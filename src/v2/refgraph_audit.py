"""Read-only v1 DEV-only referential-graph feasibility & link-coverage audit (Step E4).

CRITICAL ISOLATION & NO-TRAINING RULES:
- Loads ONLY rows where `split_pool == "dev"`; raises ValueError if any non-dev row enters.
- NEVER inspects `split_pool == "test"` rows and NEVER trains or scores any ML/propagation model.
- Strips all labels, provenance, oracle/rule columns, process-tree columns, and timestamps before
  extracting static pointers so zero leakage can occur.
"""
from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping

import pandas as pd

from src import config
from src.data import features as F


_FORBIDDEN_IN_AUDIT = frozenset({
    config.LABEL_COL,
    "label_reason",
    "split_pool",
    "dev_fold",
    "seen_count",
    "parent_name",
    "pid",
    "ppid",
    "created_utc",
    "modified_utc",
    "collected_utc",
    *config.ORACLE_FEATURES,
    *config.RULE_FEATURES,
    *config.V1_META_COLUMNS,
    *config.V2_PROVENANCE_COLUMNS,
}) - {"run_id", "artifact_key"}

_PATH_TOKEN_RE = re.compile(
    r"""(?i)(?:[a-z]:\\|%[a-z0-9_()]+%\\|\\\\\?\\|\\\?\?\\|\\systemroot\\)[^\s"'<>|;,]+?\.(?:exe|dll|ps1|psm1|psd1|bat|cmd|vbs|vbe|js|jse|wsf|hta|sys|scr|msi|lnk|cpl|py|inf)""",
)
_BARE_TARGET_RE = re.compile(
    r"""(?i)\b([a-z0-9_.-]+\.(?:exe|dll|ps1|bat|cmd|vbs|vbe|js|hta|msi|lnk|cpl|sys))\b"""
)
_COM_GUID_RE = re.compile(r"(?i)(?:COM:|Clsid\s*=\s*)?(\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\})")
_WMI_FILTER_RE = re.compile(r'(?i)__eventfilter\s*\(\s*name\s*=\s*"([^"]+)"\s*\)')
_WMI_CONSUMER_RE = re.compile(r'(?i)(?:commandlineeventconsumer|activescripteventconsumer|[a-z0-9_]*consumer)\s*\(\s*name\s*=\s*"([^"]+)"\s*\)')
_IFEO_EXE_RE = re.compile(r"(?i)\\image file execution options\\([^\\|]+)$")


def load_v1_dev_only(parquet_path: str | Path | None = None) -> pd.DataFrame:
    """Load dataset_v1.parquet and immediately restrict to `split_pool == 'dev'` only."""
    path = Path(parquet_path) if parquet_path is not None else (config.PROCESSED_DIR / "dataset_v1.parquet")
    raw_df = pd.read_parquet(path)
    if "split_pool" not in raw_df.columns:
        raise ValueError("Dataset missing 'split_pool' column")
    dev_df = raw_df[raw_df["split_pool"].astype(str) == "dev"].copy().reset_index(drop=True)
    del raw_df
    assert set(dev_df["split_pool"].astype(str)) == {"dev"}
    return dev_df


def _validate_dev_only(df: pd.DataFrame) -> None:
    if "split_pool" not in df.columns:
        raise ValueError("Input DataFrame must contain 'split_pool' column proving dev-only scope")
    pools = set(df["split_pool"].astype(str).unique())
    if pools != {"dev"}:
        raise ValueError(f"Refusing non-dev rows in read-only v1-dev audit! Found split_pool={sorted(pools)}")


def _clean_str(val: Any) -> str:
    return F._str(val)


def _norm_ref_path(raw: str) -> str:
    s = F.normalise_path(raw)
    return s.rstrip(". ")


def _extract_command_paths(cmd: str) -> list[str]:
    if not cmd:
        return []
    out: list[str] = []
    seen: set[str] = set()
    # 1. Explicit full or env-prefixed file paths
    for m in _PATH_TOKEN_RE.finditer(cmd):
        p = _norm_ref_path(m.group(0))
        if p and p not in seen:
            seen.add(p)
            out.append(p)
    # 2. Primary command target from features.extract_target_path
    prim = _norm_ref_path(F.extract_target_path(cmd))
    if prim and "." in prim and prim not in seen:
        if "\\" not in prim:
            # Bare system executable name without path -> record explicit bare name token
            seen.add(prim)
            out.append(prim)
        else:
            seen.add(prim)
            out.append(prim)
    # 3. Any remaining bare executable/script filename tokens
    for m in _BARE_TARGET_RE.finditer(cmd):
        tok = m.group(1).lower().strip()
        if not tok:
            continue
        if any(p == tok or p.endswith("\\" + tok) for p in seen):
            continue
        seen.add(tok)
        out.append(tok)
    return out


def extract_row_static_pointers(row: Mapping[str, Any]) -> list[tuple[str, str, str]]:
    """Extract (edge_type, target_kind, normalized_target) tuples from static artifact fields ONLY."""
    at = _clean_str(row.get("artifact_type")).lower()
    akey = _clean_str(row.get("artifact_key")).lower()
    name = _clean_str(row.get("name"))
    path = _norm_ref_path(_clean_str(row.get("path")))
    cmd = _clean_str(row.get("command_line"))
    reg_key = _clean_str(row.get("registry_key"))
    reg_val = _clean_str(row.get("registry_value"))

    refs: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str, str]] = set()
    seen_full_basenames: set[tuple[str, str]] = set()

    def add(edge_type: str, target_kind: str, target: str) -> None:
        t = target.strip().lower()
        if not t:
            return
        if target_kind == "path" and "\\" in t:
            seen_full_basenames.add((edge_type, F.path_basename(t)))
        elif target_kind == "basename" and (edge_type, t) in seen_full_basenames:
            return
        item = (edge_type, target_kind, t)
        if item not in seen:
            seen.add(item)
            refs.append(item)

    if at == "task":
        m_com = _COM_GUID_RE.search(cmd)
        if m_com:
            add("INVOKES_COM", "clsid", m_com.group(1).lower())
        if path:
            add("TRIGGERS_EXEC", "path" if "\\" in path else "basename", path)
        for p in _extract_command_paths(cmd):
            add("TRIGGERS_EXEC", "path" if "\\" in p else "basename", p)

    elif at == "service":
        if path:
            add("RUNS_SERVICE", "path" if "\\" in path else "basename", path)
        for p in _extract_command_paths(cmd):
            add("RUNS_SERVICE", "path" if "\\" in p else "basename", p)

    elif at == "run_key":
        if path:
            add("PERSISTS_AT_LOGON", "path" if "\\" in path else "basename", path)
        for txt in (cmd, reg_val):
            for p in _extract_command_paths(txt):
                add("PERSISTS_AT_LOGON", "path" if "\\" in p else "basename", p)

    elif at == "startup":
        # Startup artifacts with .lnk resolve to TargetPath stored in command_line/path
        if cmd:
            for p in _extract_command_paths(cmd):
                add("REFERENCES_FILE", "path" if "\\" in p else "basename", p)
        if path and not path.endswith(".lnk"):
            add("REFERENCES_FILE", "path" if "\\" in path else "basename", path)

    elif at == "registry":
        rk_low = reg_key.lower()
        ifeo_m = _IFEO_EXE_RE.search(rk_low)
        if ifeo_m:
            add("IFEO_TARGETS_IMAGE", "basename", ifeo_m.group(1).lower())
        if path:
            add("PERSISTS_AT_LOGON", "path" if "\\" in path else "basename", path)
        for txt in (cmd, reg_val):
            if any(ext in txt.lower() for ext in (".exe", ".dll", ".ps1", ".cmd", ".bat", ".vbs", ".js", "\\")):
                for p in _extract_command_paths(txt):
                    add("PERSISTS_AT_LOGON", "path" if "\\" in p else "basename", p)

    elif at == "wmi_subscription":
        if "__filtertoconsumerbinding" in akey:
            mf = _WMI_FILTER_RE.search(akey) or _WMI_FILTER_RE.search(name)
            mc = _WMI_CONSUMER_RE.search(akey) or _WMI_CONSUMER_RE.search(name)
            if mf:
                add("WMI_BINDS_FILTER", "wmi_filter_name", mf.group(1).strip().lower())
            if mc:
                add("WMI_BINDS_CONSUMER", "wmi_consumer_name", mc.group(1).strip().lower())
        elif "consumer" in akey:
            if path:
                add("WMI_CONSUMER_EXEC", "path" if "\\" in path else "basename", path)
            for p in _extract_command_paths(cmd):
                add("WMI_CONSUMER_EXEC", "path" if "\\" in p else "basename", p)

    elif at == "prefetch":
        exe = F.prefetch_exe_name(name)
        if exe:
            add("PREFETCH_EXE_NAME", "prefetch_exe_basename", exe)

    elif at == "shimcache":
        if path:
            add("SHIMCACHE_REFERENCES_PATH", "path" if "\\" in path else "basename", path)

    elif at == "process":
        if path:
            add("LIVE_PROCESS_IMAGE", "path" if "\\" in path else "basename", path)

    # file and account have no static outbound pointers in v1 fields
    return refs


def run_v1_dev_feasibility_audit(dev_df: pd.DataFrame | None = None, include_live_process: bool = False) -> dict[str, Any]:
    """Run read-only static link-coverage audit strictly on v1 dev rows (no ML training/scoring)."""
    if dev_df is None:
        dev_df = load_v1_dev_only()
    _validate_dev_only(dev_df)

    # Drop every non-static/label/provenance/timestamp field prior to graph indexing
    static_cols = [c for c in ("run_id", "seen_run_ids", "artifact_key", "artifact_type", "name", "path", "command_line", "registry_key", "registry_value", "file_sha256") if c in dev_df.columns]
    clean_df = dev_df[static_cols].copy().reset_index(drop=True)
    if not include_live_process:
        cold_mask = clean_df["artifact_type"].astype(str) != "process"
        work_df = clean_df[cold_mask].reset_index(drop=True)
    else:
        work_df = clean_df

    # Build target lookup tables within work_df
    by_norm_path: dict[str, list[int]] = defaultdict(list)
    by_basename: dict[str, list[int]] = defaultdict(list)
    by_wmi_filter: dict[str, list[int]] = defaultdict(list)
    by_wmi_consumer: dict[str, list[int]] = defaultdict(list)

    for idx, row in work_df.iterrows():
        at = _clean_str(row.get("artifact_type")).lower()
        akey = _clean_str(row.get("artifact_key")).lower()
        p = _norm_ref_path(_clean_str(row.get("path")))
        nm = _clean_str(row.get("name")).lower()
        # Only actual file/process/service/task/shimcache/startup path-bearing nodes are resolvable path entities
        if p and at in ("file", "process"):
            by_norm_path[p].append(int(idx))
            by_basename[F.path_basename(p)].append(int(idx))
        elif at == "wmi_subscription":
            if "__eventfilter" in akey and nm:
                by_wmi_filter[nm].append(int(idx))
            elif "consumer" in akey and "__filtertoconsumerbinding" not in akey and nm:
                by_wmi_consumer[nm].append(int(idx))

    row_out_resolved: list[int] = [0] * len(work_df)
    row_in_resolved: list[int] = [0] * len(work_df)
    row_extracted: list[int] = [0] * len(work_df)
    row_dangling: list[int] = [0] * len(work_df)
    row_ambiguous: list[int] = [0] * len(work_df)

    cross_type_counts: Counter[tuple[str, str, str]] = Counter()
    edge_status_counts: Counter[tuple[str, str]] = Counter()
    dangling_examples: Counter[tuple[str, str]] = Counter()
    ambiguous_examples: Counter[tuple[str, str]] = Counter()
    total_pointers = 0

    for src_idx, row in work_df.iterrows():
        src_type = _clean_str(row.get("artifact_type")).lower()
        ptrs = extract_row_static_pointers(row)
        row_extracted[src_idx] = len(ptrs)
        for edge_type, kind, target in ptrs:
            total_pointers += 1
            if kind == "path":
                matches = [m for m in by_norm_path.get(target, []) if m != src_idx]
                if len(matches) == 1:
                    dst_idx = matches[0]
                    dst_type = _clean_str(work_df.iloc[dst_idx]["artifact_type"]).lower()
                    row_out_resolved[src_idx] += 1
                    row_in_resolved[dst_idx] += 1
                    edge_status_counts[(edge_type, "resolved_unique")] += 1
                    cross_type_counts[(src_type, dst_type, edge_type)] += 1
                elif len(matches) > 1:
                    row_ambiguous[src_idx] += 1
                    edge_status_counts[(edge_type, "ambiguous")] += 1
                    ambiguous_examples[(src_type, target)] += 1
                else:
                    row_dangling[src_idx] += 1
                    edge_status_counts[(edge_type, "dangling")] += 1
                    dangling_examples[(src_type, target)] += 1

            elif kind in ("basename", "prefetch_exe_basename"):
                # Bare basenames without directory/MFT/hash disambiguation:
                # 0 matches -> dangling; >= 1 matches -> check if all point to a single unique path or ambiguous
                matches = [m for m in by_basename.get(target, []) if m != src_idx]
                uniq_paths = {_norm_ref_path(_clean_str(work_df.iloc[m]["path"])) for m in matches}
                if len(matches) == 0:
                    row_dangling[src_idx] += 1
                    edge_status_counts[(edge_type, "dangling")] += 1
                    dangling_examples[(src_type, target)] += 1
                elif kind == "basename" and len(matches) == 1 and len(uniq_paths) == 1:
                    # Wait: bare executable token (e.g. utilman.exe) or unique file basename -> treat as resolved ONLY if unique
                    # whereas prefetch filename stem without SCCA/metrics is always ambiguous without full binary path!
                    dst_idx = matches[0]
                    dst_type = _clean_str(work_df.iloc[dst_idx]["artifact_type"]).lower()
                    row_out_resolved[src_idx] += 1
                    row_in_resolved[dst_idx] += 1
                    edge_status_counts[(edge_type, "resolved_unique")] += 1
                    cross_type_counts[(src_type, dst_type, edge_type)] += 1
                else:
                    row_ambiguous[src_idx] += 1
                    edge_status_counts[(edge_type, "ambiguous")] += 1
                    ambiguous_examples[(src_type, target)] += 1

            elif kind == "wmi_filter_name":
                matches = [m for m in by_wmi_filter.get(target, []) if m != src_idx]
                if len(matches) == 1:
                    dst_idx = matches[0]
                    dst_type = _clean_str(work_df.iloc[dst_idx]["artifact_type"]).lower()
                    row_out_resolved[src_idx] += 1
                    row_in_resolved[dst_idx] += 1
                    edge_status_counts[(edge_type, "resolved_unique")] += 1
                    cross_type_counts[(src_type, dst_type, edge_type)] += 1
                elif len(matches) > 1:
                    row_ambiguous[src_idx] += 1
                    edge_status_counts[(edge_type, "ambiguous")] += 1
                else:
                    row_dangling[src_idx] += 1
                    edge_status_counts[(edge_type, "dangling")] += 1

            elif kind == "wmi_consumer_name":
                matches = [m for m in by_wmi_consumer.get(target, []) if m != src_idx]
                if len(matches) == 1:
                    dst_idx = matches[0]
                    dst_type = _clean_str(work_df.iloc[dst_idx]["artifact_type"]).lower()
                    row_out_resolved[src_idx] += 1
                    row_in_resolved[dst_idx] += 1
                    edge_status_counts[(edge_type, "resolved_unique")] += 1
                    cross_type_counts[(src_type, dst_type, edge_type)] += 1
                elif len(matches) > 1:
                    row_ambiguous[src_idx] += 1
                    edge_status_counts[(edge_type, "ambiguous")] += 1
                else:
                    row_dangling[src_idx] += 1
                    edge_status_counts[(edge_type, "dangling")] += 1

            elif kind == "clsid":
                # v1 did not collect CLSID registry keys -> always dangling
                row_dangling[src_idx] += 1
                edge_status_counts[(edge_type, "dangling")] += 1
                dangling_examples[(src_type, f"COM:{target}")] += 1

    per_type: list[dict[str, Any]] = []
    for atype, grp in work_df.groupby("artifact_type", sort=True):
        idxs = grp.index.to_list()
        n = len(idxs)
        n_ext = sum(1 for i in idxs if row_extracted[i] > 0)
        n_out = sum(1 for i in idxs if row_out_resolved[i] > 0)
        n_in = sum(1 for i in idxs if row_in_resolved[i] > 0)
        n_out_links = sum(row_out_resolved[i] for i in idxs)
        n_in_links = sum(row_in_resolved[i] for i in idxs)
        n_any = sum(1 for i in idxs if (row_out_resolved[i] > 0 or row_in_resolved[i] > 0))
        n_dang = sum(row_dangling[i] for i in idxs)
        n_amb = sum(row_ambiguous[i] for i in idxs)
        per_type.append({
            "artifact_type": str(atype),
            "total_rows": n,
            "rows_with_extracted_pointer": n_ext,
            "rows_with_resolved_outgoing": n_out,
            "rows_with_resolved_incoming": n_in,
            "outgoing_link_count": n_out_links,
            "incoming_link_count": n_in_links,
            "rows_with_any_resolvable_link": n_any,
            "frac_resolved_outgoing": n_out / n if n else 0.0,
            "frac_any_resolvable_link": n_any / n if n else 0.0,
            "dangling_pointer_count": n_dang,
            "ambiguous_pointer_count": n_amb,
        })

    per_type.sort(key=lambda d: (-d["total_rows"], d["artifact_type"]))
    total_rows = len(work_df)
    total_any_linked = sum(1 for i in range(total_rows) if row_out_resolved[i] > 0 or row_in_resolved[i] > 0)
    total_out_linked = sum(1 for i in range(total_rows) if row_out_resolved[i] > 0)

    impossible_v1_edges = [
        ("LOADED_RESOURCE", "Prefetch File Metrics array (file_path, mft_index, mft_sequence) not collected in v1"),
        ("INVOKES_COM -> RESOLVES_COM_DLL", "CLSID InprocServer32/LocalServer32 (HKCU/HKLM/Wow6432Node) not collected in v1"),
        ("HOSTS_SERVICEDLL", "Services Parameters\\ServiceDll registry values not collected in v1"),
        ("INVENTORIED_BINARY", "Amcache.hve skipped 51/51 runs in v1 (locked_hive_no_vss)"),
        ("CONTAINS_CHILD / MFT_STATE / 8.3 / ADS", "NTFS $MFT records, sequence numbers, in-use flag, DOS 8.3 names, ADS not collected in v1"),
        ("PARITY_MISMATCH (TaskCache vs XML)", "Schedule\\TaskCache registry keys and xml_exists not collected in v1"),
        ("LNK MFT / ObjectId / VolSerial", "BEEF0004 MFT ref, TrackerDataBlock ObjectId, and VolumeSerial not collected in v1"),
    ]

    return {
        "include_live_process": bool(include_live_process),
        "n_dev_rows_audited": total_rows,
        "total_extracted_pointers": total_pointers,
        "total_resolved_links": sum(cross_type_counts.values()),
        "total_dangling_pointers": sum(row_dangling),
        "total_ambiguous_pointers": sum(row_ambiguous),
        "rows_with_resolved_outgoing": total_out_linked,
        "rows_with_any_resolvable_link": total_any_linked,
        "overall_frac_resolved_outgoing": total_out_linked / total_rows if total_rows else 0.0,
        "overall_frac_any_resolvable_link": total_any_linked / total_rows if total_rows else 0.0,
        "per_artifact_type": per_type,
        "cross_type_links": [
            {"src_type": k[0], "dst_type": k[1], "edge_type": k[2], "count": int(v)}
            for k, v in sorted(cross_type_counts.items(), key=lambda kv: (-kv[1], kv[0]))
        ],
        "edge_status_breakdown": [
            {"edge_type": k[0], "status": k[1], "count": int(v)}
            for k, v in sorted(edge_status_counts.items(), key=lambda kv: (-kv[1], kv[0]))
        ],
        "top_dangling_examples": [
            {"src_type": k[0], "target": k[1], "count": int(v)}
            for k, v in dangling_examples.most_common(12)
        ],
        "top_ambiguous_examples": [
            {"src_type": k[0], "target": k[1], "count": int(v)}
            for k, v in ambiguous_examples.most_common(12)
        ],
        "impossible_v1_edges": impossible_v1_edges,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read-only v1 DEV static referential-graph feasibility audit.")
    parser.add_argument("--parquet", type=Path, default=None, help="Optional parquet override (dev rows only).")
    parser.add_argument("--include-live-process", action="store_true", help="Include live-collected process rows separately.")
    args = parser.parse_args(argv)
    dev_df = load_v1_dev_only(args.parquet)
    rep_cold = run_v1_dev_feasibility_audit(dev_df, include_live_process=False)
    rep_all = run_v1_dev_feasibility_audit(dev_df, include_live_process=True) if args.include_live_process else None
    print(json.dumps({"cold_disk_only": rep_cold, "with_live_process": rep_all}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
