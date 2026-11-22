"""Static dead-disk Referential Graph prototype (`v2_refgraph`, Step E5, OD-V2-13/16/17).

Implements:
- Strict anti-leakage guard rejecting labels, provenance, process trees, Sysmon, and timestamps.
- Path obfuscation normalizer (case, quotes, NT prefixes, env vars, 8.3 short names, ADS).
- Four-state `$MFT` reference resolver (`live_matched`, `deleted_unreused`,
  `deleted_reused_or_seq_mismatch`, `dangling`).
- Per-disk static link extractor & dual graph builder (unsplit undirected vs context-scoped
  unidirectional `EXECUTES_IMAGE` typed directed topology).
- Training-pool-only Inverse Host Frequency model (`RefGraphIDFModel`).
- Three interpretable propagation variants:
  (a) `base`       — unpropagated OOF base ranker scores,
  (b) `naive`      — undirected diffusion over unsplit merged nodes (hub-collapse baseline),
  (c) `attenuated` — context-split typed directed diffusion with training-pool IHF weights and
                     per-node edge contribution traceability.
"""
from __future__ import annotations

import json
import math
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Sequence

import numpy as np
import pandas as pd

from src import config
from src.data import features as F
from src.models.preprocess import LeakageError


ALLOWED_VARIANTS: tuple[str, ...] = ("base", "naive", "attenuated")

MFT_REF_STATES: tuple[str, ...] = (
    "live_matched",
    "deleted_unreused",
    "deleted_reused_or_seq_mismatch",
    "dangling",
)

FORBIDDEN_GRAPH_EXACT_FIELDS: frozenset[str] = frozenset({
    config.LABEL_COL,
    "label_reason",
    "split_pool",
    "dev_fold",
    "seen_run_ids",
    "seen_count",
    "technique_id",
    "variant",
    "launcher",
    "parent_name",
    "pid",
    "ppid",
    "process_guid",
    "parent_process_guid",
    "event_id",
    "event_record_id",
    "created_utc",
    "modified_utc",
    "collected_utc",
    "timestamp_utc",
    *config.ORACLE_FEATURES,
    *config.RULE_FEATURES,
    *config.V2_PROVENANCE_COLUMNS,
})

EDGE_BASE_WEIGHTS: dict[str, float] = {
    "PERSISTS_AT_LOGON": 0.90,
    "TRIGGERS_EXEC": 0.90,
    "INVOKES_COM": 0.95,
    "RESOLVES_COM_DLL": 0.95,
    "RUNS_SERVICE": 0.85,
    "HOSTS_SERVICEDLL": 0.95,
    "WMI_BINDS_FILTER": 0.90,
    "WMI_BINDS_CONSUMER": 0.90,
    "WMI_CONSUMER_EXEC": 0.90,
    "PREFETCH_MATCHES_IMAGE": 0.85,
    "LOADED_RESOURCE": 0.75,
    "REFERENCES_FILE": 0.80,
    "INVENTORIED_BINARY": 0.70,
    "EXECUTES_IMAGE": 0.50,
    "CONTAINS_CHILD": 0.05,
    "PARITY_MISMATCH": 1.00,
}

_DEVICE_VOLUME_RE = re.compile(r"^\\device\\harddiskvolume\d+\\", re.I)
_COM_GUID_RE = re.compile(r"(?i)(\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\})")
_PATH_IN_CMD_RE = re.compile(
    r"""(?i)(?:[a-z]:\\|%[a-z0-9_()]+%\\|\\\\\?\\|\\\?\?\\|\\systemroot\\|\\device\\harddiskvolume\d+\\)[^\s"'<>|;,]+?\.(?:exe|dll|ps1|psm1|psd1|bat|cmd|vbs|vbe|js|jse|wsf|hta|sys|scr|msi|lnk|cpl|py|inf)(?::[^\s"'<>|;,]+)?"""
)
_BARE_FILE_RE = re.compile(r"""(?i)\b([a-z0-9_~.-]+\.(?:exe|dll|ps1|bat|cmd|vbs|vbe|js|hta|msi|lnk|cpl|sys))\b""")
_WMI_FILTER_RE = re.compile(r'(?i)__eventfilter\s*\(\s*name\s*=\s*"([^"]+)"\s*\)')
_WMI_CONSUMER_RE = re.compile(r'(?i)(?:commandlineeventconsumer|activescripteventconsumer|[a-z0-9_]*consumer)\s*\(\s*name\s*=\s*"([^"]+)"\s*\)')


def _is_forbidden_col(col_name: str) -> bool:
    c = str(col_name).strip().lower()
    if c in FORBIDDEN_GRAPH_EXACT_FIELDS:
        return True
    if c.startswith(("sysmon_", "etw_")) or c.endswith(("_utc", "_timestamp")):
        return True
    return False


def assert_graph_inputs_clean(columns: Iterable[str]) -> None:
    """Refuse labels, provenance, process trees, Sysmon telemetry, and timestamps."""
    bad = sorted({str(c) for c in columns if _is_forbidden_col(str(c))})
    if bad:
        raise LeakageError(
            f"Forbidden non-static columns reached v2_refgraph builder (anti-leakage block): {bad}"
        )


def _str(val: Any) -> str:
    return F._str(val)


def split_ads_path(norm_path: str) -> tuple[str, str | None]:
    """Split canonical path into (base_path, ads_stream) when an NTFS ADS colon is present."""
    if not norm_path:
        return "", None
    drive_end = 2 if len(norm_path) >= 2 and norm_path[1] == ":" and norm_path[0].isalpha() else 0
    idx = norm_path.find(":", drive_end)
    if idx == -1:
        return norm_path, None
    base = norm_path[:idx].rstrip(". ")
    stream = norm_path[idx + 1 :].strip().lower() or None
    return base, stream


def normalize_windows_path(
    raw_path: object,
    short_to_long: Mapping[str, str] | None = None,
    env_map: Mapping[str, str] | None = None,
) -> tuple[str, str | None]:
    """Normalize obfuscated Windows path + return `(canonical_base_path, ads_stream)`.

    Handles mixed case, surrounding/embedded quotes, forward slashes, trailing whitespace/dots,
    NT device prefixes (`\\??\\`, `\\\\?\\`, `\\SystemRoot\\`, `\\Device\\HarddiskVolume#\\`),
    environment variables, DOS 8.3 short names (via `short_to_long`), and NTFS ADS.
    """
    if raw_path is None:
        return "", None
    try:
        if isinstance(raw_path, float) and math.isnan(raw_path):
            return "", None
    except (TypeError, ValueError):
        pass
    s = str(raw_path).strip().replace('"', "").replace("'", "").strip()
    if not s:
        return "", None

    s = s.replace("/", "\\").lower()
    merged_env = dict(F._ENV_MAP)
    if env_map:
        for k, v in env_map.items():
            merged_env[str(k).lower()] = str(v).lower().rstrip("\\")
    for var, val in merged_env.items():
        s = s.replace(var, val)

    for pref in ("\\??\\", "\\\\?\\"):
        if s.startswith(pref):
            s = s[len(pref) :]
    if _DEVICE_VOLUME_RE.match(s):
        s = "c:\\" + _DEVICE_VOLUME_RE.sub("", s, count=1)
    elif s.startswith("\\systemroot\\"):
        s = "c:\\windows\\" + s[len("\\systemroot\\") :]
    elif s.startswith("systemroot\\"):
        s = "c:\\windows\\" + s[len("systemroot\\") :]
    elif s.startswith("system32\\"):
        s = "c:\\windows\\" + s

    while "\\\\" in s:
        s = s.replace("\\\\", "\\")
    s = s.rstrip(". ")
    base, ads = split_ads_path(s)
    if ads:
        ads = ads.rstrip(". ")

    if short_to_long and base:
        parts = base.split("\\")
        rebuilt: list[str] = []
        for idx, part in enumerate(parts):
            prefix = "\\".join(rebuilt + [part])
            if prefix in short_to_long:
                mapped = short_to_long[prefix]
                rebuilt = mapped.split("\\")
            elif part in short_to_long and "~" in part:
                rebuilt.append(short_to_long[part])
            else:
                rebuilt.append(part)
        base = "\\".join(rebuilt).rstrip(". ")

    return base, ads


def resolve_mft_reference(
    ptr_index: int | None,
    ptr_seq: int | None,
    mft_records_by_index: Mapping[int, Mapping[str, Any]],
) -> str:
    """Resolve an 8-byte MFT pointer `(index, seq)` into one of 4 unambiguous structural states."""
    if ptr_index is None or ptr_seq is None:
        return "dangling"
    rec = mft_records_by_index.get(int(ptr_index))
    if rec is None:
        return "dangling"
    in_use = bool(rec.get("mft_in_use", False))
    rec_seq = int(rec.get("mft_sequence_number", -1))
    p_seq = int(ptr_seq)
    if in_use and rec_seq == p_seq:
        return "live_matched"
    if (not in_use) and rec_seq in (p_seq, p_seq + 1):
        return "deleted_unreused"
    return "deleted_reused_or_seq_mismatch"


def _extract_cmd_targets(
    cmd: str,
    short_to_long: Mapping[str, str] | None = None,
) -> list[tuple[str, str | None]]:
    if not cmd:
        return []
    out: list[tuple[str, str | None]] = []
    seen: set[tuple[str, str | None]] = set()
    for m in _PATH_IN_CMD_RE.finditer(cmd):
        b, ads = normalize_windows_path(m.group(0), short_to_long=short_to_long)
        if b and (b, ads) not in seen:
            seen.add((b, ads))
            out.append((b, ads))
    prim = F.extract_target_path(cmd)
    if prim:
        b, ads = normalize_windows_path(prim, short_to_long=short_to_long)
        if b and "." in b and (b, ads) not in seen:
            seen.add((b, ads))
            out.append((b, ads))
    for m in _BARE_FILE_RE.finditer(cmd):
        tok = m.group(1).lower().strip(". ")
        if not tok:
            continue
        if any(b == tok or b.endswith("\\" + tok) for b, _ in seen):
            continue
        if (tok, None) not in seen:
            seen.add((tok, None))
            out.append((tok, None))
    return out


@dataclass
class DiskGraph:
    """In-memory static referential graph for one single disk (`disk_id`)."""

    disk_id: str
    nodes: list[str]
    node_index: dict[str, int]
    node_types: dict[str, str]
    artifact_nodes: list[str]
    context_nodes: list[str]
    # Undirected edges across unsplit entity nodes for Variant (b) naive baseline
    naive_edges: list[tuple[str, str, str, str]] = field(default_factory=list)
    # Typed directed edges over context-split nodes: (src, dst, edge_type, canonical_target_for_ihf, structural_state)
    typed_edges: list[tuple[str, str, str, str, str]] = field(default_factory=list)
    row_links: dict[str, dict[str, Any]] = field(default_factory=dict)


def build_disk_graph(disk_df: pd.DataFrame, disk_id: str = "disk_0") -> DiskGraph:
    """Build per-disk unsplit + context-split static graphs from validated artifact records."""
    assert_graph_inputs_clean(disk_df.columns)
    df = disk_df.reset_index(drop=True)

    # 1. Build DOS 8.3 -> WIN32 long-name lookup & MFT record table
    short_to_long: dict[str, str] = {}
    mft_by_index: dict[int, dict[str, Any]] = {}
    path_to_node: dict[str, str] = {}
    basename_to_paths: dict[str, list[str]] = defaultdict(list)
    clsid_candidates: dict[tuple[str, str, bool], str] = {}  # (guid, hive, wow64) -> target_path
    wmi_filter_node: dict[str, str] = {}
    wmi_consumer_node: dict[str, str] = {}
    fileid_to_node: dict[str, str] = {}
    pf_context_by_scca: dict[tuple[str, str], str] = {}

    nodes: list[str] = []
    node_index: dict[str, int] = {}
    node_types: dict[str, str] = {}
    artifact_nodes: list[str] = []
    context_nodes: list[str] = []

    def ensure_node(nid: str, ntype: str, is_context: bool = False) -> str:
        if nid not in node_index:
            node_index[nid] = len(nodes)
            nodes.append(nid)
            node_types[nid] = ntype
            if is_context:
                context_nodes.append(nid)
        return nid

    # Pass 1: Register all static artifact nodes & MFT/8.3/CLSID/FileId lookup tables
    for _, row in df.iterrows():
        akey = _str(row.get("artifact_key")) or f"row_{len(nodes)}"
        at = _str(row.get("artifact_type")).lower() or "other"
        ensure_node(akey, at, is_context=False)
        artifact_nodes.append(akey)

        mft_idx = row.get("mft_record_number")
        mft_seq = row.get("mft_sequence_number")
        if mft_idx is not None and not pd.isna(mft_idx):
            mft_by_index[int(mft_idx)] = {
                "mft_record_number": int(mft_idx),
                "mft_sequence_number": int(mft_seq) if mft_seq is not None and not pd.isna(mft_seq) else 0,
                "mft_in_use": bool(row.get("mft_in_use", True)),
                "artifact_key": akey,
            }

        raw_fn_list = row.get("mft_file_names")
        base_dir_norm, _ = normalize_windows_path(row.get("path"))
        if "\\" in base_dir_norm:
            parent_dir = base_dir_norm.rsplit("\\", 1)[0]
        else:
            parent_dir = ""
        if isinstance(raw_fn_list, list):
            win32_names = [fn.get("name") for fn in raw_fn_list if isinstance(fn, dict) and fn.get("namespace") in ("WIN32", "WIN32_DOS", "POSIX") and fn.get("name")]
            dos_names = [fn.get("name") for fn in raw_fn_list if isinstance(fn, dict) and fn.get("namespace") == "DOS" and fn.get("name")]
            if win32_names and dos_names:
                wname = str(win32_names[0]).lower()
                for dname in dos_names:
                    dlow = str(dname).lower()
                    if parent_dir:
                        short_to_long[f"{parent_dir}\\{dlow}"] = f"{parent_dir}\\{wname}"
                    else:
                        short_to_long[dlow] = wname

    # Pass 1b: Map canonical file paths, CLSIDs, WMI, and SCCA hashes after 8.3 map is populated
    for _, row in df.iterrows():
        akey = _str(row.get("artifact_key"))
        at = _str(row.get("artifact_type")).lower()
        name = _str(row.get("name")).lower()
        raw_p = row.get("expanded_path") or row.get("path")
        norm_p, _ = normalize_windows_path(raw_p, short_to_long=short_to_long)

        if at == "file" and norm_p:
            path_to_node.setdefault(norm_p, akey)
            basename_to_paths[F.path_basename(norm_p)].append(norm_p)
            fid = _str(row.get("amcache_file_id")).lower()
            if fid:
                fileid_to_node[fid] = akey
        elif at in ("clsid", "registry"):
            guid = _str(row.get("clsid_guid")).lower()
            if not guid:
                gm = _COM_GUID_RE.search(_str(row.get("registry_key")).lower())
                guid = gm.group(1).lower() if gm else ""
            srv = _str(row.get("clsid_server_expanded") or row.get("registry_value") or row.get("command_line"))
            if guid and srv:
                hive = _str(row.get("clsid_hive") or ("HKU" if _str(row.get("registry_key")).lower().startswith(("hku", "hkcu")) else "HKLM")).upper()
                wow = bool(row.get("clsid_wow64", "wow6432node" in _str(row.get("registry_key")).lower()))
                clsid_b, _ = normalize_windows_path(srv, short_to_long=short_to_long)
                if clsid_b:
                    clsid_candidates[(guid, hive, wow)] = clsid_b
        elif at == "wmi_subscription":
            if "__eventfilter" in akey.lower() and name:
                wmi_filter_node[name] = akey
            elif "consumer" in akey.lower() and "__filtertoconsumerbinding" not in akey.lower() and name:
                wmi_consumer_node[name] = akey
        elif at == "prefetch":
            exe_nm = _str(row.get("pf_executable_name")).lower() or F.prefetch_exe_name(name)
            scca = _str(row.get("pf_scca_hash")).lower()
            if exe_nm and scca:
                pf_context_by_scca[(exe_nm, scca)] = akey

    def resolve_path_node(canon_path: str, create_dangling: bool = True) -> tuple[str | None, str]:
        if not canon_path:
            return None, "dangling"
        if canon_path in path_to_node:
            return path_to_node[canon_path], "resolved_unique"
        if "\\" not in canon_path:
            cands = basename_to_paths.get(canon_path, [])
            if len(cands) == 1:
                return path_to_node[cands[0]], "resolved_unique"
            if len(cands) > 1:
                return None, "ambiguous"
        if create_dangling:
            dn = f"dangling|path|{canon_path}"
            ensure_node(dn, "DANGLING_REF", is_context=False)
            return dn, "dangling"
        return None, "dangling"

    def resolve_clsid_path(guid: str, prefer_wow64: bool = False) -> str | None:
        g = guid.lower()
        order = [
            (g, "HKCU", prefer_wow64),
            (g, "HKU", prefer_wow64),
            (g, "HKLM", prefer_wow64),
            (g, "HKCU", not prefer_wow64),
            (g, "HKU", not prefer_wow64),
            (g, "HKLM", not prefer_wow64),
        ]
        for key in order:
            if key in clsid_candidates:
                return clsid_candidates[key]
        return None

    naive_edges: list[tuple[str, str, str, str]] = []
    typed_edges: list[tuple[str, str, str, str, str]] = []
    row_links: dict[str, dict[str, Any]] = {}

    def link_unsplit(src: str, dst: str, etype: str, canon_ihf: str) -> None:
        naive_edges.append((src, dst, etype, canon_ihf))

    def link_typed(src: str, dst: str, etype: str, canon_ihf: str, state: str = "live_matched") -> None:
        typed_edges.append((src, dst, etype, canon_ihf, state))

    # Pass 2: Extract pointers & build both unsplit undirected (naive) and context-split directed (attenuated) edges
    for _, row in df.iterrows():
        akey = _str(row.get("artifact_key"))
        at = _str(row.get("artifact_type")).lower()
        name = _str(row.get("name")).lower()
        cmd = _str(row.get("command_line") or row.get("task_exec_command") or "")
        reg_val = _str(row.get("registry_value"))
        targets_found: list[str] = []
        types_found: list[str] = []
        resolved_keys: list[str] = []

        def record_row_edge(target_str: str, etype: str, resolved_node: str | None) -> None:
            if target_str not in targets_found:
                targets_found.append(target_str)
            if etype not in types_found:
                types_found.append(etype)
            if resolved_node and not resolved_node.startswith("dangling|") and resolved_node not in resolved_keys:
                resolved_keys.append(resolved_node)

        def wire_invocation(caller_key: str, etype: str, exec_path_raw: Any, full_cmd: str) -> None:
            ctx_id = f"ctx|{caller_key}"
            ensure_node(ctx_id, "EXEC_CONTEXT", is_context=True)
            link_typed(caller_key, ctx_id, etype, caller_key)
            link_typed(ctx_id, caller_key, etype, caller_key)

            prim_b, prim_ads = normalize_windows_path(exec_path_raw, short_to_long=short_to_long)
            if not prim_b and full_cmd:
                tlist = _extract_cmd_targets(full_cmd, short_to_long=short_to_long)
                if tlist:
                    prim_b, prim_ads = tlist[0]

            if prim_b:
                img_node, st = resolve_path_node(prim_b, create_dangling=True)
                if img_node:
                    # Naive connects caller directly into shared binary node
                    link_unsplit(caller_key, img_node, etype, prim_b)
                    # Attenuated adds UNIDIRECTIONAL PE_FILE -> EXEC_CONTEXT (zero backward traversal!)
                    link_typed(img_node, ctx_id, "EXECUTES_IMAGE", prim_b, st)
                    record_row_edge(f"{prim_b}:{prim_ads}" if prim_ads else prim_b, etype, img_node)

            for tok_b, tok_ads in _extract_cmd_targets(full_cmd, short_to_long=short_to_long):
                if tok_b == prim_b and tok_ads == prim_ads:
                    continue
                dst_node, st = resolve_path_node(tok_b, create_dangling=True)
                if dst_node:
                    link_unsplit(caller_key, dst_node, etype, tok_b)
                    link_typed(ctx_id, dst_node, etype, tok_b, st)
                    link_typed(dst_node, ctx_id, etype, tok_b, st)
                    record_row_edge(f"{tok_b}:{tok_ads}" if tok_ads else tok_b, etype, dst_node)

            # Optional exact SCCA match from invocation context to Prefetch record
            ctx_scca = _str(row.get("pf_scca_hash")).lower()
            if prim_b and ctx_scca:
                pf_key = pf_context_by_scca.get((F.path_basename(prim_b), ctx_scca))
                if pf_key:
                    link_unsplit(caller_key, pf_key, "PREFETCH_MATCHES_IMAGE", pf_key)
                    link_typed(ctx_id, pf_key, "PREFETCH_MATCHES_IMAGE", pf_key)
                    link_typed(pf_key, ctx_id, "PREFETCH_MATCHES_IMAGE", pf_key)
                    record_row_edge(pf_key, "PREFETCH_MATCHES_IMAGE", pf_key)

        if at in ("run_key", "registry"):
            raw_exec = row.get("reg_value_expanded") or row.get("path") or reg_val
            wire_invocation(akey, "PERSISTS_AT_LOGON", raw_exec, cmd or reg_val)

        elif at == "task":
            # GhostTask TaskCache parity edge if xml_exists explicitly False
            if row.get("task_xml_exists") is False:
                link_typed(akey, akey, "PARITY_MISMATCH", akey, "missing_xml")
                record_row_edge("taskcache:missing_xml", "PARITY_MISMATCH", akey)
            com_guid = _str(row.get("task_com_clsid")).lower()
            if not com_guid:
                cm = _COM_GUID_RE.search(cmd)
                if cm and cmd.strip().lower().startswith("com:"):
                    com_guid = cm.group(1).lower()
            if com_guid:
                com_dll = resolve_clsid_path(com_guid, prefer_wow64=bool(row.get("prefer_wow64", False)))
                clsid_nid = f"clsid|{com_guid}"
                ensure_node(clsid_nid, "COM_CLSID", is_context=False)
                link_unsplit(akey, clsid_nid, "INVOKES_COM", com_guid)
                link_typed(akey, clsid_nid, "INVOKES_COM", com_guid)
                link_typed(clsid_nid, akey, "INVOKES_COM", com_guid)
                if com_dll:
                    dll_node, st = resolve_path_node(com_dll, create_dangling=True)
                    if dll_node:
                        link_unsplit(clsid_nid, dll_node, "RESOLVES_COM_DLL", com_dll)
                        link_typed(clsid_nid, dll_node, "RESOLVES_COM_DLL", com_dll, st)
                        link_typed(dll_node, clsid_nid, "RESOLVES_COM_DLL", com_dll, st)
                        record_row_edge(com_dll, "RESOLVES_COM_DLL", dll_node)
                else:
                    record_row_edge(com_guid, "INVOKES_COM", clsid_nid)
            else:
                exec_cmd = row.get("task_exec_command") or cmd
                if row.get("task_exec_arguments"):
                    exec_cmd = f"{exec_cmd} {row.get('task_exec_arguments')}".strip()
                wire_invocation(akey, "TRIGGERS_EXEC", row.get("path") or exec_cmd, exec_cmd)

        elif at == "service":
            wire_invocation(akey, "RUNS_SERVICE", row.get("service_image_path_expanded") or row.get("path"), cmd)
            s_dll_raw = row.get("service_dll_expanded") or row.get("service_dll_raw")
            if s_dll_raw:
                s_dll, _ = normalize_windows_path(s_dll_raw, short_to_long=short_to_long)
                if s_dll:
                    ctx_id = f"ctx|{akey}"
                    ensure_node(ctx_id, "EXEC_CONTEXT", is_context=True)
                    dll_node, st = resolve_path_node(s_dll, create_dangling=True)
                    if dll_node:
                        link_unsplit(akey, dll_node, "HOSTS_SERVICEDLL", s_dll)
                        link_typed(ctx_id, dll_node, "HOSTS_SERVICEDLL", s_dll, st)
                        link_typed(dll_node, ctx_id, "HOSTS_SERVICEDLL", s_dll, st)
                        record_row_edge(s_dll, "HOSTS_SERVICEDLL", dll_node)

        elif at == "startup":
            wire_invocation(akey, "REFERENCES_FILE", row.get("lnk_target_path_expanded") or cmd, cmd)

        elif at == "wmi_subscription":
            if "__filtertoconsumerbinding" in akey.lower():
                mf = _WMI_FILTER_RE.search(akey) or _WMI_FILTER_RE.search(name)
                mc = _WMI_CONSUMER_RE.search(akey) or _WMI_CONSUMER_RE.search(name)
                if mf:
                    fn = wmi_filter_node.get(mf.group(1).strip().lower())
                    if fn:
                        link_unsplit(akey, fn, "WMI_BINDS_FILTER", fn)
                        link_typed(akey, fn, "WMI_BINDS_FILTER", fn)
                        link_typed(fn, akey, "WMI_BINDS_FILTER", fn)
                        record_row_edge(fn, "WMI_BINDS_FILTER", fn)
                if mc:
                    cn = wmi_consumer_node.get(mc.group(1).strip().lower())
                    if cn:
                        link_unsplit(akey, cn, "WMI_BINDS_CONSUMER", cn)
                        link_typed(akey, cn, "WMI_BINDS_CONSUMER", cn)
                        link_typed(cn, akey, "WMI_BINDS_CONSUMER", cn)
                        record_row_edge(cn, "WMI_BINDS_CONSUMER", cn)
            elif "consumer" in akey.lower():
                wire_invocation(akey, "WMI_CONSUMER_EXEC", row.get("path") or cmd, cmd)

        elif at == "prefetch":
            ctx_id = f"ctx|{akey}"
            ensure_node(ctx_id, "EXEC_CONTEXT", is_context=True)
            link_typed(akey, ctx_id, "PREFETCH_MATCHES_IMAGE", akey)
            link_typed(ctx_id, akey, "PREFETCH_MATCHES_IMAGE", akey)
            metrics = row.get("pf_file_metrics")
            if isinstance(metrics, list):
                for item in metrics:
                    if not isinstance(item, dict):
                        continue
                    fp_b, _ = normalize_windows_path(item.get("file_path"), short_to_long=short_to_long)
                    if not fp_b:
                        continue
                    m_idx = item.get("mft_index")
                    m_seq = item.get("mft_sequence")
                    if m_idx is not None and m_seq is not None and mft_by_index:
                        mft_state = resolve_mft_reference(int(m_idx), int(m_seq), mft_by_index)
                    else:
                        mft_state = "live_matched" if fp_b in path_to_node else "dangling"
                    if mft_state == "deleted_reused_or_seq_mismatch":
                        # Do NOT join on reused slot; emit dangling mismatch node
                        dst_node = f"dangling|mft_reuse|{fp_b}#{m_idx}:{m_seq}"
                        ensure_node(dst_node, "DANGLING_REF", is_context=False)
                    else:
                        dst_node, _ = resolve_path_node(fp_b, create_dangling=True)
                    if dst_node:
                        link_unsplit(akey, dst_node, "LOADED_RESOURCE", fp_b)
                        link_typed(ctx_id, dst_node, "LOADED_RESOURCE", fp_b, mft_state)
                        link_typed(dst_node, ctx_id, "LOADED_RESOURCE", fp_b, mft_state)
                        record_row_edge(fp_b, "LOADED_RESOURCE", dst_node)

        elif at == "amcache":
            fid = _str(row.get("amcache_file_id")).lower()
            lp_b, _ = normalize_windows_path(row.get("amcache_lowercase_long_path") or row.get("path"), short_to_long=short_to_long)
            dst_node = fileid_to_node.get(fid) if fid else None
            st = "resolved_unique" if dst_node else "dangling"
            if dst_node is None and lp_b:
                dst_node, st = resolve_path_node(lp_b, create_dangling=True)
            if dst_node:
                link_unsplit(akey, dst_node, "INVENTORIED_BINARY", lp_b or fid)
                link_typed(akey, dst_node, "INVENTORIED_BINARY", lp_b or fid, st)
                link_typed(dst_node, akey, "INVENTORIED_BINARY", lp_b or fid, st)
                record_row_edge(lp_b or fid, "INVENTORIED_BINARY", dst_node)

        row_links[akey] = {
            "ref_targets": json.dumps(targets_found),
            "ref_type": json.dumps(types_found),
            "linked_artifact_keys": json.dumps(resolved_keys),
        }

    return DiskGraph(
        disk_id=str(disk_id),
        nodes=nodes,
        node_index=node_index,
        node_types=node_types,
        artifact_nodes=artifact_nodes,
        context_nodes=context_nodes,
        naive_edges=naive_edges,
        typed_edges=typed_edges,
        row_links=row_links,
    )


def populate_ref_edge_columns(disk_df: pd.DataFrame, disk_id: str = "disk_0") -> pd.DataFrame:
    """Populate `REFGRAPH_EDGE_COLUMNS` (`ref_targets`, `ref_type`, `linked_artifact_keys`)."""
    graph = build_disk_graph(disk_df, disk_id=disk_id)
    out = disk_df.copy()
    keys = [_str(k) for k in out["artifact_key"]]
    out["ref_targets"] = [graph.row_links[k]["ref_targets"] for k in keys]
    out["ref_type"] = [graph.row_links[k]["ref_type"] for k in keys]
    out["linked_artifact_keys"] = [graph.row_links[k]["linked_artifact_keys"] for k in keys]
    return out


class RefGraphIDFModel:
    """Inverse Host Frequency (IHF) model fitted strictly on TRAINING-pool disks only."""

    def __init__(self) -> None:
        self.doc_freq_: dict[str, int] = {}
        self.n_train_disks_: int = 0
        self.frozen_: bool = False

    def fit(self, train_graphs: Sequence[DiskGraph]) -> "RefGraphIDFModel":
        if not train_graphs:
            raise ValueError("RefGraphIDFModel requires at least one training DiskGraph")
        df_counts: dict[str, int] = defaultdict(int)
        for g in train_graphs:
            seen_targets: set[str] = set()
            for _, _, etype, canon_target, _ in g.typed_edges:
                if etype in ("LOADED_RESOURCE", "CONTAINS_CHILD") and canon_target:
                    seen_targets.add(canon_target)
            for tgt in seen_targets:
                df_counts[tgt] += 1
        self.doc_freq_ = dict(df_counts)
        self.n_train_disks_ = int(len(train_graphs))
        self.frozen_ = True
        return self

    def ihf_weight(self, canonical_target: str) -> float:
        """Compute frozen IHF weight for a target key; NEVER mutates fitted statistics."""
        if not self.frozen_:
            raise RuntimeError("RefGraphIDFModel must be fitted on training disks first")
        n = self.n_train_disks_
        df_u = min(n, self.doc_freq_.get(str(canonical_target).lower(), 0))
        denom = math.log(1.0 + n)
        if denom <= 0.0:
            return 1.0
        val = math.log((1.0 + n) / (1.0 + df_u)) / denom
        return float(max(0.0, min(1.0, val)))


def propagate_base(graph: DiskGraph, base_oof_scores: Mapping[str, float]) -> dict[str, Any]:
    """Variant (a): unpropagated OOF base ranker scores."""
    vec = np.array([float(base_oof_scores.get(nid, 0.0)) for nid in graph.nodes], dtype=float)
    return {
        "scores": {nid: float(vec[i]) for i, nid in enumerate(graph.nodes)},
        "explanations": {nid: [] for nid in graph.nodes},
    }


def propagate_naive(
    graph: DiskGraph,
    base_oof_scores: Mapping[str, float],
    alpha: float = 0.6,
    n_iter: int = 10,
) -> dict[str, Any]:
    """Variant (b): naive undirected symmetric propagation across unsplit nodes (no IHF)."""
    n = len(graph.nodes)
    s0 = np.array([float(base_oof_scores.get(nid, 0.0)) for nid in graph.nodes], dtype=float)
    if n == 0 or not graph.naive_edges:
        return {"scores": {nid: float(s0[i]) for i, nid in enumerate(graph.nodes)}, "explanations": {nid: [] for nid in graph.nodes}}

    A = np.zeros((n, n), dtype=float)
    idx = graph.node_index
    for u, v, _, _ in graph.naive_edges:
        iu, iv = idx[u], idx[v]
        A[iu, iv] += 1.0
        A[iv, iu] += 1.0
    deg = A.sum(axis=1)
    inv_sqrt = np.where(deg > 0.0, 1.0 / np.sqrt(np.maximum(deg, 1e-12)), 0.0)
    P = (A * inv_sqrt[:, None]) * inv_sqrt[None, :]

    s = s0.copy()
    for _ in range(int(n_iter)):
        s = (1.0 - float(alpha)) * s0 + float(alpha) * (P @ s)

    return {
        "scores": {nid: float(s[i]) for i, nid in enumerate(graph.nodes)},
        "explanations": {nid: [] for nid in graph.nodes},
    }


def propagate_attenuated(
    graph: DiskGraph,
    base_oof_scores: Mapping[str, float],
    idf_model: RefGraphIDFModel,
    alpha: float = 0.65,
    n_iter: int = 10,
    relation_weights: Mapping[str, float] | None = None,
) -> dict[str, Any]:
    """Variant (c): context-split unidirectional `EXECUTES_IMAGE` + training-pool IHF typed propagation."""
    n = len(graph.nodes)
    s0 = np.array([float(base_oof_scores.get(nid, 0.0)) for nid in graph.nodes], dtype=float)
    if n == 0 or not graph.typed_edges:
        return {"scores": {nid: float(s0[i]) for i, nid in enumerate(graph.nodes)}, "explanations": {nid: [] for nid in graph.nodes}}

    w_map = dict(EDGE_BASE_WEIGHTS)
    if relation_weights:
        w_map.update(relation_weights)

    W = np.zeros((n, n), dtype=float)
    edge_meta: dict[tuple[int, int], list[tuple[str, float]]] = defaultdict(list)
    idx = graph.node_index

    for src, dst, etype, canon_ihf, state in graph.typed_edges:
        base_w = float(w_map.get(etype, 0.5))
        if etype in ("LOADED_RESOURCE", "CONTAINS_CHILD"):
            eff_w = base_w * idf_model.ihf_weight(canon_ihf)
        else:
            eff_w = base_w
        if state in ("deleted_unreused", "deleted_reused_or_seq_mismatch") and etype == "LOADED_RESOURCE":
            eff_w = max(eff_w, 0.25 * base_w) if idf_model.ihf_weight(canon_ihf) > 0.0 else eff_w
        if eff_w <= 0.0:
            continue
        isrc, idst = idx[src], idx[dst]
        # Propagation pulls from src -> dst: P_in[idst, isrc] receives W[idst, isrc]
        W[idst, isrc] = max(W[idst, isrc], eff_w)
        edge_meta[(idst, isrc)].append((etype, eff_w))

    is_ctx = np.array([graph.node_types[nid] == "EXEC_CONTEXT" for nid in graph.nodes], dtype=bool)
    has_in = W.sum(axis=1) > 0.0
    if not np.any(has_in):
        return {"scores": {nid: float(s0[i]) for i, nid in enumerate(graph.nodes)}, "explanations": {nid: [] for nid in graph.nodes}}

    # Initialize virtual EXEC_CONTEXT nodes from linear neighbor average so they carry zero teleport-to-zero bias
    rsum0 = W.sum(axis=1, keepdims=True)
    P0 = np.divide(W, rsum0, out=np.zeros_like(W), where=rsum0 > 0.0)
    s = s0.copy()
    ctx_init = is_ctx & has_in
    if np.any(ctx_init):
        s[ctx_init] = (P0 @ s0)[ctx_init]

    a = float(alpha)
    P = P0
    for _ in range(int(n_iter)):
        # Salience-modulated row-stochastic transition: preserves exact constant fixed points
        # on uniform components while preventing trusted signed LOLBins from diluting high-risk contexts.
        sal = np.maximum(0.05, 0.05 + np.clip(s, 0.0, 1.0))[None, :] ** 2
        W_eff = W * sal
        rsum = W_eff.sum(axis=1, keepdims=True)
        P = np.divide(W_eff, rsum, out=np.zeros_like(W_eff), where=rsum > 0.0)
        prop = P @ s
        s = np.where(~has_in, s0, np.where(is_ctx, prop, (1.0 - a) * s0 + a * prop))

    explanations: dict[str, list[dict[str, Any]]] = {}
    for dst_id, idst in idx.items():
        if not has_in[idst]:
            explanations[dst_id] = []
            continue
        eff_alpha = 1.0 if is_ctx[idst] else a
        contribs = []
        for isrc in np.flatnonzero(P[idst] > 0.0):
            contrib_val = float(eff_alpha * P[idst, isrc] * s[isrc])
            if contrib_val <= 1e-9:
                continue
            etypes = edge_meta[(idst, int(isrc))]
            contribs.append({
                "source_node": graph.nodes[int(isrc)],
                "edge_type": etypes[0][0],
                "weight": float(P[idst, isrc]),
                "contribution": contrib_val,
            })
        contribs.sort(key=lambda d: -d["contribution"])
        explanations[dst_id] = contribs

    return {
        "scores": {nid: float(s[i]) for i, nid in enumerate(graph.nodes)},
        "explanations": explanations,
    }


class RefGraphPropagator:
    """High-level wrapper enforcing training-only IHF fit and identical scoring interface."""

    def __init__(
        self,
        variant: str = "attenuated",
        alpha: float = 0.65,
        n_iter: int = 10,
        relation_weights: Mapping[str, float] | None = None,
    ) -> None:
        if variant not in ALLOWED_VARIANTS:
            raise ValueError(f"Unsupported propagation variant {variant!r}; expected one of {ALLOWED_VARIANTS}")
        self.variant = variant
        self.alpha = float(alpha)
        self.n_iter = int(n_iter)
        self.relation_weights = dict(relation_weights) if relation_weights else None
        self.idf_model = RefGraphIDFModel()
        self.fitted = False

    def fit(self, train_df: pd.DataFrame, disk_id_col: str = "run_id") -> "RefGraphPropagator":
        assert_graph_inputs_clean(train_df.columns)
        graphs: list[DiskGraph] = []
        for d_id, grp in train_df.groupby(disk_id_col, sort=True):
            graphs.append(build_disk_graph(grp.reset_index(drop=True), disk_id=str(d_id)))
        self.idf_model.fit(graphs)
        self.fitted = True
        return self

    def propagate_disk(self, disk_df: pd.DataFrame, base_oof_scores: Mapping[str, float], disk_id: str = "eval") -> dict[str, Any]:
        if not self.fitted and self.variant == "attenuated":
            raise RuntimeError("RefGraphPropagator must be fitted on training pool disks before attenuated propagation")
        graph = build_disk_graph(disk_df, disk_id=disk_id)
        if self.variant == "base":
            return propagate_base(graph, base_oof_scores)
        if self.variant == "naive":
            return propagate_naive(graph, base_oof_scores, alpha=self.alpha, n_iter=self.n_iter)
        return propagate_attenuated(
            graph, base_oof_scores, idf_model=self.idf_model,
            alpha=self.alpha, n_iter=self.n_iter, relation_weights=self.relation_weights,
        )
