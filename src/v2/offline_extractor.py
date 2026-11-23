"""Pure user-space offline QCOW2 & NTFS artifact extractor (Step F / OD-V2-04, OD-V2-16).

Reads closed QCOW2 disk images or synthetic fixtures strictly in user space via
`dissect.target`, `dissect.ntfs`, `dissect.regf`, `dissect.cim`, `LnkParse3`, and
`signify`. Never performs host-kernel mounts (`mount`/`qemu-nbd`) and never copies
raw executable payloads onto the host workspace.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import struct
import time
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Mapping, Sequence

import pandas as pd

from src import config
from src.data import features as F
from src.utils.repro import utc_now_iso, write_json
from src.v2 import refgraph as RG


EXTRACTOR_VERSION = "2.0.0"
MIB = 1 << 20
MAX_PE_SIGNIFY_BYTES = 64 * MIB  # safety bound when decompressing / reading PEs for Authenticode hash

_SIP_EXTS: frozenset[str] = frozenset({
    ".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".msi", ".cab", ".cat",
    ".ps1", ".psm1", ".psd1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
})
_PE_EXTS: frozenset[str] = frozenset({".exe", ".dll", ".sys", ".ocx", ".cpl", ".scr", ".msi"})
_SCRIPT_EXTS: frozenset[str] = frozenset({".ps1", ".psm1", ".psd1", ".vbs", ".vbe", ".js", ".jse", ".wsf"})

_USER_SCAN_TARGET_EXTS: frozenset[str] = frozenset({
    ".exe", ".dll", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".hta", ".lnk", ".scr", ".msi",
})
_SKIP_DIR_FRAGS: tuple[str, ...] = (
    "\\programdata\\microsoft\\windows defender\\",
    "\\programdata\\package cache\\",
    "\\programdata\\ssh\\",
    "\\appdata\\local\\packages\\",
    "\\appdata\\local\\microsoft\\windows\\",
    "\\code cache\\",
    "\\gpucache\\",
    "\\crashpad\\",
)

_NS_NAMES = {0: "POSIX", 1: "WIN32", 2: "DOS", 3: "WIN32_DOS"}
_SVC_START_MAP = {0: "Boot", 1: "System", 2: "Auto", 3: "Manual", 4: "Disabled"}
_VOLUME_RE = re.compile(r"^\\(?:volume\{[^}]+\}|device\\harddiskvolume\d+)\\", re.I)
_COM_GUID_RE = re.compile(r"(?i)(\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\})")
_FORBIDDEN_PAYLOAD_KEYS = frozenset({"raw_bytes", "payload_bytes", "file_bytes", "binary_blob", "script_text", "raw_script_text"})
_PERSIST_EXEC_TYPES: tuple[str, ...] = ("task", "service", "run_key", "wmi_subscription", "prefetch")


def compute_head_histogram(data: bytes | bytearray) -> list[int]:
    """Return 256-bin byte frequency counts strictly over the leading 1 MiB."""
    head = data[:MIB]
    counts = Counter(head)
    return [int(counts.get(i, 0)) for i in range(256)]


def normalize_volume_prefix(raw_path: str | None) -> str:
    """Convert NTFS volume/device prefixes (e.g. `\\VOLUME{...}\\`) into canonical `C:\\`."""
    if not raw_path:
        return ""
    s = str(raw_path).replace("/", "\\").strip()
    if _VOLUME_RE.match(s):
        return "C:\\" + _VOLUME_RE.sub("", s, count=1)
    if s.lower().startswith("\\windows\\"):
        return "C:" + s
    if s.lower().startswith("windows\\"):
        return "C:\\" + s
    return s


def expand_win_env(raw: str | None, env_map: Mapping[str, str] | None = None) -> str:
    """Deterministically expand common Windows env vars using offline image defaults."""
    if not raw:
        return ""
    s = str(raw).strip()
    merged = {
        "%SystemRoot%": r"C:\WINDOWS",
        "%WinDir%": r"C:\WINDOWS",
        "%SystemDrive%": "C:",
        "%ProgramFiles%": r"C:\Program Files",
        "%ProgramFiles(x86)%": r"C:\Program Files (x86)",
        "%ProgramW6432%": r"C:\Program Files",
        "%CommonProgramFiles%": r"C:\Program Files\Common Files",
        "%ProgramData%": r"C:\ProgramData",
        "%AllUsersProfile%": r"C:\ProgramData",
        "%Public%": r"C:\Users\Public",
        "%ComSpec%": r"C:\WINDOWS\system32\cmd.exe",
    }
    if env_map:
        merged.update(env_map)
    for k, v in merged.items():
        s = re.sub(re.escape(k), lambda _m, rep=v: rep, s, flags=re.I)
    return s


def expand_target_like_v1(raw: str | None, c_exists_fn: Any = None, env_map: Mapping[str, str] | None = None) -> str | None:
    """Replicate v1 Collect-Artifacts.ps1 Expand-NormPath / Extract-TargetPath semantics."""
    if not raw or not str(raw).strip():
        return None
    s = expand_win_env(str(raw).strip().strip('"').strip(), env_map=env_map).replace("/", "\\")
    if s.startswith(("\\??\\", "\\\\?\\")):
        s = s[4:]
    if s.lower().startswith("\\systemroot\\"):
        s = r"C:\WINDOWS\\" + s[len("\\systemroot\\") :]
    elif s.lower().startswith("systemroot\\"):
        s = r"C:\WINDOWS\\" + s[len("systemroot\\") :]
    elif s.lower().startswith("system32\\"):
        s = r"C:\WINDOWS\\" + s
    while "\\\\" in s:
        s = s.replace("\\\\", "\\")
    if not s:
        return None
    if "\\" not in s and re.search(r"\.(exe|dll|com|msc|cpl)$", s, re.I) and c_exists_fn is not None:
        for base_dir in (r"C:\Windows\System32", r"C:\Windows\System32\WindowsPowerShell\v1.0"):
            cand = f"{base_dir}\\{s}"
            if c_exists_fn(cand):
                return cand
    return s


def decompress_wof_stream(raw_wof: bytes, uncomp_size: int, algo: int) -> bytes:
    """Decompress Windows 10/11 CompactOS `WofCompressedData` XPRESS/LZX chunks in user space."""
    if uncomp_size <= 0:
        return b""
    from dissect.util.compression import lzxpress_huffman, lzxpress  # type: ignore

    chunk_sizes = {0: 4096, 1: 32768, 2: 8192, 3: 16384}
    chunk_sz = chunk_sizes.get(int(algo), 8192)
    n_chunks = (uncomp_size + chunk_sz - 1) // chunk_sz
    if n_chunks <= 0:
        return b""
    table_sz = (n_chunks - 1) * 4
    if len(raw_wof) < table_sz:
        raise ValueError("Truncated WOF chunk offset table")
    offsets = [0] + list(struct.unpack_from(f"<{n_chunks - 1}I", raw_wof, 0)) + [len(raw_wof) - table_sz]
    out = bytearray()
    for i in range(n_chunks):
        c_start = table_sz + offsets[i]
        c_end = table_sz + offsets[i + 1]
        expected = min(chunk_sz, uncomp_size - i * chunk_sz)
        cdata = raw_wof[c_start:c_end]
        if len(cdata) == expected:
            out.extend(cdata)
        elif int(algo) == 1:
            out.extend(lzxpress.decompress(cdata)[:expected])
        else:
            out.extend(lzxpress_huffman.decompress(cdata)[:expected])
    return bytes(out[:uncomp_size])


def _read_mft_file_bytes(rec: Any, max_bytes: int = MAX_PE_SIGNIFY_BYTES) -> tuple[bytes | None, int, bool]:
    """Read file content bytes in user space (decompressing WOF CompactOS if needed)."""
    try:
        uncomp_size = int(rec.size("") or 0)
    except Exception:
        uncomp_size = 0
    is_wof = False
    try:
        is_wof = bool(rec.has_stream("WofCompressedData"))
    except Exception:
        is_wof = False

    if uncomp_size == 0:
        return b"", 0, is_wof
    if uncomp_size > max_bytes and not is_wof:
        with rec.open("") as fh:
            return fh.read(max_bytes), uncomp_size, False

    if is_wof and uncomp_size <= max_bytes:
        try:
            rp_list = rec.attributes.get(0xC0, [])
            algo = 2
            if rp_list:
                rp_attr = rp_list[0]
                rp_bytes = rp_attr.data() if callable(rp_attr.data) else bytes(rp_attr.data)
                if len(rp_bytes) >= 24 and struct.unpack_from("<I", rp_bytes, 0)[0] == 0x80000017:
                    algo = struct.unpack_from("<I", rp_bytes, 20)[0]
            raw_wof = rec.open("WofCompressedData").read()
            return decompress_wof_stream(raw_wof, uncomp_size, algo), uncomp_size, True
        except Exception:
            pass

    if not is_wof:
        try:
            with rec.open("") as fh:
                return fh.read(min(uncomp_size, max_bytes)), uncomp_size, False
        except Exception:
            return None, uncomp_size, is_wof

    # Huge WOF binary (> max_bytes): read at least partial chunks up to MIB for histogram
    try:
        rp_list = rec.attributes.get(0xC0, [])
        algo = 2
        if rp_list:
            rp_bytes = rp_list[0].data() if callable(rp_list[0].data) else bytes(rp_list[0].data)
            if len(rp_bytes) >= 24:
                algo = struct.unpack_from("<I", rp_bytes, 20)[0]
        raw_wof = rec.open("WofCompressedData").read()
        data = decompress_wof_stream(raw_wof, uncomp_size, algo)
        return data[:max_bytes], uncomp_size, True
    except Exception:
        return None, uncomp_size, is_wof


def verify_offline_signature(
    file_path: str,
    file_bytes: bytes | None,
    file_size: int,
    cat_digests: set[str] | frozenset[str] = frozenset(),
) -> str:
    """Offline `signature_status` replicating `Get-AuthenticodeSignature` + `UnknownError -> na`."""
    ext = Path(file_path).suffix.lower()
    if ext not in _SIP_EXTS or file_size <= 0 or file_bytes is None:
        return "UnknownError"

    if ext in _SCRIPT_EXTS:
        tail = file_bytes[-65536:]
        return "Valid" if b"SIG # Begin signature block" in tail else "NotSigned"

    if ext in _PE_EXTS:
        if len(file_bytes) < 64 or file_bytes[:2] != b"MZ":
            return "UnknownError"
        try:
            import signify.authenticode as sa  # type: ignore

            af = sa.AuthenticodeFile.from_stream(io.BytesIO(file_bytes))
            ver_res, err = af.explain_verify()
            vname = getattr(ver_res, "name", str(ver_res))
            if vname == "OK":
                return "Valid"
            if vname == "NOT_SIGNED":
                fp256 = af.get_fingerprint(hashlib.sha256).hex().lower()
                if fp256 in cat_digests:
                    return "Valid"
                fp1 = af.get_fingerprint(hashlib.sha1).hex().lower()
                if fp1 in cat_digests:
                    return "Valid"
                return "NotSigned"
            if "HASH" in vname.upper() or (err is not None and "digest" in str(err).lower()):
                return "HashMismatch"
            return "NotTrusted"
        except Exception:
            return "UnknownError"

    # Other SIP extensions (.cab, .cat)
    return "UnknownError"


def validate_extracted_record(rec: Mapping[str, Any]) -> dict[str, Any]:
    """Enforce zero raw executable payloads and strict schema constraints on one record."""
    bad_keys = _FORBIDDEN_PAYLOAD_KEYS & set(rec.keys())
    if bad_keys:
        raise ValueError(f"Forbidden raw payload field(s) in extracted record: {sorted(bad_keys)}")

    for k, v in rec.items():
        if isinstance(v, (bytes, bytearray, memoryview)):
            raise ValueError(f"Raw binary blob prohibited in field {k!r}")

    hist = rec.get("file_head_histogram")
    fsize = rec.get("file_size")
    if hist is not None:
        if not isinstance(hist, list) or len(hist) != 256:
            raise ValueError("file_head_histogram must be a 256-int list or None")
        total = sum(int(x) for x in hist)
        if any(int(x) < 0 for x in hist) or total > MIB:
            raise ValueError(f"file_head_histogram counts exceed 1 MiB cap ({total} > {MIB})")
        if fsize is not None and int(fsize) >= 0 and total > min(int(fsize), MIB) + 16 and total == MIB:
            pass
    if not rec.get("artifact_type") or not rec.get("artifact_key"):
        raise ValueError("Extracted record must include non-empty 'artifact_type' and 'artifact_key'")
    return dict(rec)


def _format_record_hash(rec: Mapping[str, Any]) -> str:
    payload = {k: rec.get(k) for k in sorted(rec.keys()) if k != "record_sha256"}
    raw = json.dumps(payload, sort_keys=True, default=str, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _parse_task_xml(xml_text: str) -> dict[str, Any]:
    out: dict[str, Any] = {
        "exec_actions": [],
        "com_handlers": [],
        "triggers": [],
        "command_line": None,
        "first_exec": None,
    }
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return out

    def strip_ns(tag: str) -> str:
        return tag.split("}", 1)[-1]

    trig_map = {
        "LogonTrigger": "MSFT_TaskLogonTrigger",
        "BootTrigger": "MSFT_TaskBootTrigger",
        "CalendarTrigger": "MSFT_TaskDailyTrigger",
        "TimeTrigger": "MSFT_TaskTimeTrigger",
        "RegistrationTrigger": "MSFT_TaskRegistrationTrigger",
        "EventTrigger": "MSFT_TaskEventTrigger",
        "IdleTrigger": "MSFT_TaskIdleTrigger",
        "SessionStateChangeTrigger": "MSFT_TaskSessionStateChangeTrigger",
    }
    trigs: list[str] = []
    cmd_parts: list[str] = []

    for el in root.iter():
        tname = strip_ns(el.tag)
        if tname in trig_map:
            mapped = trig_map[tname]
            if mapped not in trigs:
                trigs.append(mapped)
        elif tname == "Exec":
            cmd = ""
            args = ""
            wdir = None
            for ch in el:
                cname = strip_ns(ch.tag)
                if cname == "Command" and ch.text:
                    cmd = ch.text.strip()
                elif cname == "Arguments" and ch.text:
                    args = ch.text.strip()
                elif cname == "WorkingDirectory" and ch.text:
                    wdir = ch.text.strip()
            if cmd:
                if out["first_exec"] is None:
                    out["first_exec"] = cmd
                out["exec_actions"].append({
                    "command_raw": cmd,
                    "command_expanded": expand_win_env(cmd),
                    "arguments_raw": args or None,
                    "arguments_expanded": expand_win_env(args) if args else None,
                    "working_dir": wdir,
                })
                cmd_parts.append(f"{cmd} {args}".strip())
        elif tname == "ComHandler":
            for ch in el:
                if strip_ns(ch.tag) == "ClassId" and ch.text:
                    m = _COM_GUID_RE.search(ch.text)
                    guid = m.group(1).lower() if m else ch.text.strip().lower()
                    out["com_handlers"].append(guid)
                    cmd_parts.append(f"COM:{guid}")

    out["triggers"] = trigs
    out["command_line"] = " ; ".join(cmd_parts).strip() or None
    return out


def _read_hive_subkeys_safe(key_obj: Any, path_prefix: str = "") -> list[tuple[str, Any]]:
    results: list[tuple[str, Any]] = []
    if key_obj is None:
        return results
    try:
        subs = list(key_obj.subkeys())
    except Exception:
        return results
    for sk in subs:
        rel = f"{path_prefix}\\{sk.name}" if path_prefix else f"\\{sk.name}"
        results.append((rel, sk))
        results.extend(_read_hive_subkeys_safe(sk, rel))
    return results


def _dos_attrs_int(si: Any) -> int | None:
    if si is None:
        return None
    for attr_name in ("file_attributes", "FileAttributes", "attributes"):
        val = getattr(si, attr_name, None)
        if val is not None:
            return int(val)
    return None


def _mft_record_metadata(rec: Any, canonical_path: str) -> dict[str, Any]:
    hdr = getattr(rec, "header", None)
    seg = int(getattr(rec, "segment", 0))
    seq = int(getattr(hdr, "SequenceNumber", 0)) if hdr is not None else 0
    in_use = bool(getattr(hdr, "Flags", 1) & 0x01) if hdr is not None else True

    fns: list[dict[str, Any]] = []
    p_idx, p_seq = None, None
    for fn_wrapper in rec.attributes.get(0x30, []):
        try:
            fa = fn_wrapper.attribute.attr
            ns_id = int(getattr(fa, "Flags", 1))
            ns_str = _NS_NAMES.get(ns_id, "WIN32")
            fname = str(getattr(fa, "FileName", ""))
            pd_ref = getattr(fa, "ParentDirectory", None)
            pi = (int(pd_ref.SegmentNumberHighPart) << 32) | int(pd_ref.SegmentNumberLowPart) if pd_ref else None
            ps = int(pd_ref.SequenceNumber) if pd_ref else None
            if p_idx is None or ns_str in ("WIN32", "WIN32_DOS"):
                p_idx, p_seq = pi, ps
            fns.append({
                "namespace": ns_str,
                "name": fname,
                "parent_index": pi,
                "parent_sequence": ps,
            })
        except Exception:
            continue

    ads_list: list[dict[str, Any]] = []
    wof_compressed = False
    for d in rec.attributes.get(0x80, []):
        sname = getattr(d, "name", "") or ""
        if sname == "WofCompressedData":
            wof_compressed = True
            continue
        if sname:
            try:
                ssize = int(rec.size(sname) or 0)
            except Exception:
                ssize = 0
            ads_list.append({"stream_name": str(sname), "stream_size": ssize})

    si = rec.attributes.get(0x10, [None])[0]
    dos_attrs = _dos_attrs_int(si)
    return {
        "path": canonical_path,
        "mft_record_number": seg,
        "mft_sequence_number": seq,
        "mft_in_use": in_use,
        "mft_parent_index": p_idx,
        "mft_parent_sequence": p_seq,
        "mft_file_names": fns,
        "mft_ads_streams": ads_list,
        "attributes": dos_attrs,
        "wof_compressed": wof_compressed,
    }


def extract_from_qcow2(
    qcow2_path: str | Path,
    run_id: str = "offline_qcow2",
    max_scanned_files: int = 1500,
    resolve_catroot: bool = True,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Parse a closed QCOW2 disk image strictly in user space (zero mounts)."""
    from dissect.target import Target  # type: ignore
    from dissect.target.plugins.os.windows import prefetch as dpf  # type: ignore

    qcow2_path = Path(qcow2_path)
    t0 = time.monotonic()
    t = Target.open(str(qcow2_path))
    try:
        c_fs = t.fs.mounts.get("c:")
        ntfs = getattr(c_fs, "ntfs", None) if c_fs is not None else None

        cat_digests: set[str] = set()
        if resolve_catroot:
            try:
                for cr in t.catroot():
                    dig = getattr(cr, "digest", None)
                    if dig is not None:
                        if getattr(dig, "sha256", None):
                            cat_digests.add(str(dig.sha256).lower())
                        if getattr(dig, "sha1", None):
                            cat_digests.add(str(dig.sha1).lower())
            except Exception:
                pass

        def c_path_exists(win_path: str) -> bool:
            if not win_path:
                return False
            rel = normalize_volume_prefix(win_path)
            if rel.lower().startswith("c:\\"):
                p = t.fs.path(rel)
                return bool(p.exists() and p.is_file())
            return False

        file_meta_cache: dict[str, dict[str, Any]] = {}
        referenced_target_paths: set[str] = set()

        def inspect_target_file(win_path: str | None) -> dict[str, Any] | None:
            if not win_path:
                return None
            norm = expand_target_like_v1(normalize_volume_prefix(win_path), c_exists_fn=c_path_exists)
            if not norm or not norm.lower().startswith("c:\\"):
                return None
            low = norm.lower()
            if low in file_meta_cache:
                return file_meta_cache[low]

            rel = norm[3:].lstrip("\\")
            mft_rec = None
            if ntfs is not None:
                try:
                    mft_rec = ntfs.mft.get(rel)
                except Exception:
                    mft_rec = None

            if mft_rec is None:
                tp = t.fs.path(norm)
                if not tp.exists() or tp.is_dir():
                    return None
                fsize = int(tp.stat().st_size)
                with tp.open("rb") as fh:
                    fbytes = fh.read(min(fsize, MAX_PE_SIGNIFY_BYTES))
                info = {
                    "path": norm,
                    "file_size": fsize,
                    "attributes": None,
                    "file_head_histogram": compute_head_histogram(fbytes[:MIB]),
                    "file_sha256": hashlib.sha256(fbytes).hexdigest() if fsize <= MAX_PE_SIGNIFY_BYTES else None,
                    "signature_status": verify_offline_signature(norm, fbytes, fsize, cat_digests),
                    "mft_record_number": None,
                    "mft_sequence_number": None,
                    "mft_in_use": True,
                    "mft_parent_index": None,
                    "mft_parent_sequence": None,
                    "mft_file_names": [],
                    "mft_ads_streams": [],
                }
                file_meta_cache[low] = info
                return info

            if mft_rec.is_dir():
                return None
            mft_meta = _mft_record_metadata(mft_rec, norm)
            fbytes, full_sz, _ = _read_mft_file_bytes(mft_rec)
            hist = compute_head_histogram(fbytes[:MIB]) if fbytes is not None else None
            sha = hashlib.sha256(fbytes).hexdigest() if (fbytes is not None and full_sz <= MAX_PE_SIGNIFY_BYTES) else None
            sig = verify_offline_signature(norm, fbytes, full_sz, cat_digests)
            info = {
                **mft_meta,
                "file_size": int(full_sz),
                "file_head_histogram": hist,
                "file_sha256": sha,
                "signature_status": sig,
            }
            file_meta_cache[low] = info
            return info

        def build_record(
            artifact_type: str,
            path_or_key: str,
            name: str,
            path: str | None = None,
            command_line: str | None = None,
            registry_key: str | None = None,
            registry_value: str | None = None,
            task_name: str | None = None,
            service_name: str | None = None,
            start_mode: str | None = None,
            task_triggers: str | None = None,
            fmeta: Mapping[str, Any] | None = None,
            extra: Mapping[str, Any] | None = None,
        ) -> dict[str, Any]:
            eff_path = path or (fmeta.get("path") if fmeta else None)
            if eff_path and str(eff_path).lower().startswith("c:\\"):
                referenced_target_paths.add(str(eff_path))
            akey = f"{artifact_type.lower()}|{RG._str(path_or_key).replace('/', '\\').lower()}|{RG._str(name).replace('/', '\\').lower()}"
            rec: dict[str, Any] = {
                "run_id": run_id,
                "artifact_type": artifact_type,
                "artifact_key": akey,
                "name": name,
                "path": eff_path,
                "command_line": command_line,
                "registry_key": registry_key,
                "registry_value": registry_value,
                "task_name": task_name,
                "service_name": service_name,
                "parent_name": None,
                "start_mode": start_mode,
                "task_triggers": task_triggers,
                "attributes": fmeta.get("attributes") if fmeta else None,
                "file_size": fmeta.get("file_size") if fmeta else None,
                "file_head_histogram": fmeta.get("file_head_histogram") if fmeta else None,
                "file_sha256": fmeta.get("file_sha256") if fmeta else None,
                "signature_status": fmeta.get("signature_status") if fmeta else None,
                "mft_record_number": fmeta.get("mft_record_number") if fmeta else None,
                "mft_sequence_number": fmeta.get("mft_sequence_number") if fmeta else None,
                "mft_in_use": fmeta.get("mft_in_use") if fmeta else None,
                "mft_parent_index": fmeta.get("mft_parent_index") if fmeta else None,
                "mft_parent_sequence": fmeta.get("mft_parent_sequence") if fmeta else None,
                "mft_file_names": fmeta.get("mft_file_names") if fmeta else None,
                "mft_ads_streams": fmeta.get("mft_ads_streams") if fmeta else None,
                "schema_version": "v2",
            }
            if extra:
                rec.update(extra)
            rec["record_sha256"] = _format_record_hash(rec)
            return validate_extracted_record(rec)

        records: list[dict[str, Any]] = []
        com_guids_needed: set[str] = set()

        def reg_key_safe(reg_path: str) -> Any:
            try:
                return t.registry.key(reg_path)
            except Exception:
                return None

        def reg_subkey_safe(key_obj: Any, name: str) -> Any:
            if key_obj is None:
                return None
            try:
                return key_obj.subkey(name)
            except Exception:
                return None

        def reg_val_safe(key_obj: Any, name: str) -> Any:
            if key_obj is None:
                return None
            try:
                return key_obj.value(name)
            except Exception:
                return None

        # 1. Scheduled Tasks: XML + TaskCache reconciliation
        xml_tasks_by_uri: dict[str, tuple[str, str]] = {}
        tasks_root = t.fs.path(r"c:\Windows\System32\Tasks")
        if tasks_root.exists():
            for root_dir, _, files in tasks_root.walk():
                for fn in files:
                    fpath = root_dir / fn
                    full_str = str(fpath).replace("/", "\\")
                    if full_str.lower().startswith("c:\\"):
                        rel_uri = full_str[len("c:\\Windows\\System32\\Tasks") :]
                    else:
                        idx_t = full_str.lower().find("\\system32\\tasks")
                        rel_uri = full_str[idx_t + len("\\system32\\tasks") :] if idx_t >= 0 else f"\\{fn}"
                    try:
                        xml_txt = fpath.open("rb").read(262144).decode("utf-8", errors="replace")
                        xml_tasks_by_uri[rel_uri.lower()] = (rel_uri, xml_txt)
                    except Exception:
                        continue

        taskcache_by_uri: dict[str, dict[str, Any]] = {}
        tc_tree = reg_key_safe(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree")
        tc_tasks = reg_key_safe(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks")
        tc_guid_map: dict[str, Any] = {}
        if tc_tasks is not None:
            try:
                for sk in tc_tasks.subkeys():
                    tc_guid_map[sk.name.lower()] = sk
            except Exception:
                pass
        for rel_tree, sk in _read_hive_subkeys_safe(tc_tree):
            try:
                vals = {v.name: v.value for v in sk.values()}
            except Exception:
                continue
            tid = str(vals.get("Id") or "").lower()
            if not tid:
                continue
            has_sd = "SD" in vals and vals["SD"] is not None
            task_sk = tc_guid_map.get(tid)
            try:
                tvals = {v.name: v.value for v in task_sk.values()} if task_sk is not None else {}
            except Exception:
                tvals = {}
            has_actions = "Actions" in tvals and tvals["Actions"] is not None
            has_triggers = "Triggers" in tvals and tvals["Triggers"] is not None
            uri_norm = rel_tree if rel_tree.startswith("\\") else "\\" + rel_tree
            taskcache_by_uri[uri_norm.lower()] = {
                "tree_path": uri_norm,
                "task_guid": tid,
                "has_sd": has_sd,
                "has_actions": has_actions,
                "triggers_present": has_triggers,
            }

        all_task_uris = sorted(set(xml_tasks_by_uri.keys()) | set(taskcache_by_uri.keys()))
        for uk in all_task_uris:
            xml_entry = xml_tasks_by_uri.get(uk)
            tc_entry = taskcache_by_uri.get(uk)
            xml_exists = xml_entry is not None
            rel_uri = xml_entry[0] if xml_entry is not None else tc_entry["tree_path"]  # type: ignore[index]
            parent_dir, _, tname = rel_uri.rpartition("\\")
            tdir = parent_dir + "\\" if parent_dir else "\\"
            parsed = _parse_task_xml(xml_entry[1]) if xml_entry is not None else {
                "exec_actions": [], "com_handlers": [], "triggers": [], "command_line": None, "first_exec": None
            }
            for cg in parsed["com_handlers"]:
                com_guids_needed.add(cg)
            target = expand_target_like_v1(parsed["first_exec"], c_exists_fn=c_path_exists)
            fmeta = inspect_target_file(target) if target else None
            tc_meta = []
            if tc_entry is not None:
                tc_meta.append({
                    **tc_entry,
                    "actions_source": "xml" if xml_exists else ("registry_blob" if tc_entry["has_actions"] else "missing"),
                })
            records.append(build_record(
                artifact_type="task",
                path_or_key=tdir,
                name=tname,
                path=target,
                command_line=parsed["command_line"],
                task_name=rel_uri,
                task_triggers=",".join(parsed["triggers"]) if parsed["triggers"] else None,
                fmeta=fmeta,
                extra={
                    "task_xml_exists": xml_exists,
                    "task_xml_path": rel_uri if xml_exists else None,
                    "task_exec_actions": parsed["exec_actions"],
                    "task_com_handlers": parsed["com_handlers"],
                    "task_com_clsid": parsed["com_handlers"][0] if parsed["com_handlers"] else None,
                    "task_exec_command": parsed["exec_actions"][0]["command_expanded"] if parsed["exec_actions"] else None,
                    "task_exec_arguments": parsed["exec_actions"][0]["arguments_expanded"] if parsed["exec_actions"] else None,
                    "taskcache_entries": tc_meta,
                },
            ))

        # 2. Windows Services (SYSTEM\Select\Current -> Services, Win32 services)
        select_k = reg_key_safe(r"HKLM\SYSTEM\Select")
        cur_v = reg_val_safe(select_k, "Current")
        cur_cs = int(cur_v.value) if cur_v is not None else 1
        cs_name = f"ControlSet{cur_cs:03d}"
        svc_root = reg_key_safe(rf"HKLM\SYSTEM\{cs_name}\Services")
        if svc_root is not None:
            for sk in svc_root.subkeys():
                try:
                    vals = {v.name: v.value for v in sk.values()}
                except Exception:
                    continue
                svc_type = int(vals.get("Type") or 0)
                if (svc_type & 0x30) == 0:
                    continue  # skip kernel/FS drivers matching Win32_Service
                img_raw = str(vals.get("ImagePath") or "").strip()
                if not img_raw:
                    continue
                img_exp = expand_win_env(img_raw)
                target = expand_target_like_v1(img_exp, c_exists_fn=c_path_exists)
                fmeta = inspect_target_file(target) if target else None
                start_raw = vals.get("Start")
                start_mode = _SVC_START_MAP.get(int(start_raw), str(start_raw)) if start_raw is not None else None
                sdll_raw = None
                sdll_exp = None
                pk = reg_subkey_safe(sk, "Parameters")
                sdv = reg_val_safe(pk, "ServiceDll")
                if sdv is not None and sdv.value:
                    sdll_raw = str(sdv.value)
                    sdll_exp = expand_target_like_v1(sdll_raw, c_exists_fn=c_path_exists)
                    if sdll_exp and sdll_exp.lower().startswith("c:\\"):
                        referenced_target_paths.add(sdll_exp)
                reg_key = rf"HKLM\SYSTEM\CurrentControlSet\Services\{sk.name}"
                records.append(build_record(
                    artifact_type="service",
                    path_or_key=reg_key,
                    name=sk.name,
                    path=target,
                    command_line=img_exp,
                    registry_key=reg_key,
                    service_name=sk.name,
                    start_mode=start_mode,
                    fmeta=fmeta,
                    extra={
                        "service_image_path_raw": img_raw,
                        "service_image_path_expanded": img_exp,
                        "service_dll_raw": sdll_raw,
                        "service_dll_expanded": sdll_exp,
                    },
                ))

        # 3. Run / RunOnce + Winlogon / IFEO / Defender / UAC + CLSID COM resolution
        run_hklm_specs = [
            (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "64bit"),
            (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "64bit"),
            (r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "32bit_wow6432"),
            (r"HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "32bit_wow6432"),
            (r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "64bit"),
        ]
        run_specs: list[tuple[str, str, str, str]] = [
            (rk, rk, "HKLM", view) for rk, view in run_hklm_specs
        ]
        hku_key = reg_key_safe("HKU")
        user_sids: list[str] = []
        if hku_key is not None:
            for usk in hku_key.subkeys():
                if not usk.name.lower().endswith("_classes"):
                    user_sids.append(usk.name)
                    for sub in (
                        r"Software\Microsoft\Windows\CurrentVersion\Run",
                        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                        r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
                    ):
                        run_specs.append((rf"HKU\{usk.name}\{sub}", rf"HKU\{usk.name}\{sub}", "HKU", "64bit"))

        for reg_lookup, disp_key, hive, view in run_specs:
            rk_obj = reg_key_safe(reg_lookup)
            if rk_obj is None:
                continue
            for v in rk_obj.values():
                vname = v.name or "(Default)"
                raw_val = str(v.value or "")
                exp_val = expand_win_env(raw_val)
                target = expand_target_like_v1(exp_val, c_exists_fn=c_path_exists)
                fmeta = inspect_target_file(target) if target else None
                records.append(build_record(
                    artifact_type="run_key",
                    path_or_key=disp_key,
                    name=vname,
                    path=target,
                    command_line=raw_val,  # matches DoNotExpandEnvironmentNames in v1
                    registry_key=disp_key,
                    registry_value=raw_val,
                    fmeta=fmeta,
                    extra={
                        "reg_hive": hive,
                        "reg_wow64_view": view,
                        "reg_value_raw": raw_val,
                        "reg_value_expanded": exp_val,
                    },
                ))

        # UAC bypass, IFEO, Winlogon, Defender
        for sid in user_sids:
            for uac_sub in (r"Software\Classes\ms-settings\shell\open\command", r"Software\Classes\mscfile\shell\open\command"):
                kobj = reg_key_safe(rf"HKU\{sid}\{uac_sub}")
                if kobj is None:
                    continue
                dk = rf"HKU\{sid}\{uac_sub}"
                for v in kobj.values():
                    val = expand_win_env(str(v.value or ""))
                    target = expand_target_like_v1(val, c_exists_fn=c_path_exists)
                    fmeta = inspect_target_file(target) if target else None
                    records.append(build_record(
                        artifact_type="registry", path_or_key=dk, name=v.name or "(Default)",
                        path=target, command_line=val, registry_key=dk, registry_value=val, fmeta=fmeta,
                        extra={"reg_hive": "HKU", "reg_wow64_view": "64bit", "reg_value_raw": str(v.value or ""), "reg_value_expanded": val},
                    ))

        ifeo_root = reg_key_safe(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options")
        if ifeo_root is not None:
            for sk in ifeo_root.subkeys():
                for interesting in ("Debugger", "GlobalFlag", "VerifierDlls", "MonitorProcess"):
                    val_obj = reg_val_safe(sk, interesting)
                    if val_obj is not None:
                        val_raw = str(val_obj.value or "")
                        val_exp = expand_win_env(val_raw)
                        dk = rf"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{sk.name}"
                        target = expand_target_like_v1(val_exp, c_exists_fn=c_path_exists)
                        fmeta = inspect_target_file(target) if target else None
                        records.append(build_record(
                            artifact_type="registry", path_or_key=dk, name=interesting,
                            path=target, command_line=val_exp, registry_key=dk, registry_value=val_exp, fmeta=fmeta,
                            extra={"reg_hive": "HKLM", "reg_wow64_view": "64bit", "reg_value_raw": val_raw, "reg_value_expanded": val_exp},
                        ))

        wl_obj = reg_key_safe(r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon")
        if wl_obj is not None:
            dk = r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            for wn in ("Shell", "Userinit", "Taskman"):
                vobj = reg_val_safe(wl_obj, wn)
                if vobj is not None:
                    val_raw = str(vobj.value or "")
                    val_exp = expand_win_env(val_raw)
                    target = expand_target_like_v1(val_exp, c_exists_fn=c_path_exists)
                    fmeta = inspect_target_file(target) if target else None
                    records.append(build_record(
                        artifact_type="registry", path_or_key=dk, name=wn,
                        path=target, command_line=val_exp, registry_key=dk, registry_value=val_exp, fmeta=fmeta,
                        extra={"reg_hive": "HKLM", "reg_wow64_view": "64bit", "reg_value_raw": val_raw, "reg_value_expanded": val_exp},
                    ))

        # CLSID COM server resolution for all Task-referenced CLSIDs + HKCU Classes CLSIDs (capped if large)
        clsid_roots: list[tuple[str, str, bool]] = [
            (r"HKLM\SOFTWARE\Classes\CLSID", "HKLM", False),
            (r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID", "HKLM", True),
        ]
        if hku_key is not None:
            for usk in hku_key.subkeys():
                if usk.name.lower().endswith("_classes"):
                    clsid_roots.append((rf"HKU\{usk.name}\CLSID", "HKU", False))
                    clsid_roots.append((rf"HKU\{usk.name}\Wow6432Node\CLSID", "HKU", True))
        for rpath, chive, is_wow in clsid_roots:
            base_k = reg_key_safe(rpath)
            if base_k is None:
                continue
            target_guids = sorted(com_guids_needed) if chive == "HKLM" else [sk.name.lower() for sk in base_k.subkeys()]
            for guid in target_guids:
                gsub = reg_key_safe(rf"{rpath}\{guid}")
                if gsub is None:
                    continue
                for srv_type in ("InprocServer32", "LocalServer32"):
                    sk_srv = reg_subkey_safe(gsub, srv_type)
                    if sk_srv is None:
                        continue
                    def_v = reg_val_safe(sk_srv, "") or reg_val_safe(sk_srv, "(Default)")
                    if def_v is None or not def_v.value:
                        continue
                    s_raw = str(def_v.value)
                    s_exp = expand_target_like_v1(expand_win_env(s_raw), c_exists_fn=c_path_exists) or expand_win_env(s_raw)
                    fmeta = inspect_target_file(s_exp)
                    dk = rf"{rpath}\{guid}\{srv_type}"
                    records.append(build_record(
                        artifact_type="registry", path_or_key=dk, name=srv_type,
                        path=s_exp, command_line=s_exp, registry_key=dk, registry_value=s_exp, fmeta=fmeta,
                        extra={
                            "clsid_guid": guid.lower(),
                            "clsid_hive": chive,
                            "clsid_wow64": is_wow,
                            "clsid_server_type": srv_type,
                            "clsid_server_raw": s_raw,
                            "clsid_server_expanded": s_exp,
                        },
                    ))

        # 4. WMI OBJECTS.DATA (dissect.cim)
        try:
            from dissect.cim import cim as dcim_mod  # type: ignore

            repodir = t.fs.path(r"c:\Windows\System32\wbem\Repository")
            if repodir.exists():
                idx_p = repodir / "index.btr"
                obj_p = repodir / "objects.data"
                maps = [repodir / f"mapping{i}.map" for i in range(1, 4)]
                if idx_p.exists() and obj_p.exists() and all(m.exists() for m in maps):
                    repo = dcim_mod.CIM(idx_p.open("rb"), obj_p.open("rb"), [m.open("rb") for m in maps])
                    for ns in repo.root.namespaces:
                        raw_ns = str(getattr(ns, "name", "root\\subscription")).replace("/", "\\")
                        ns_name = raw_ns if raw_ns.lower().startswith("root\\") else f"root\\{raw_ns}"
                        try:
                            flt_cls = ns.class_("__EventFilter")
                            for flt in flt_cls.instances:
                                fname = str(flt.properties["Name"].value)
                                q = str(flt.properties["Query"].value or "")
                                records.append(build_record(
                                    artifact_type="wmi_subscription",
                                    path_or_key=rf"{ns_name}\__EventFilter",
                                    name=fname,
                                    command_line=q,
                                    extra={"wmi_namespace": ns_name, "wmi_class": "__EventFilter"},
                                ))
                        except Exception:
                            pass
                        for ccls in ("CommandLineEventConsumer", "ActiveScriptEventConsumer"):
                            try:
                                con_cls = ns.class_(ccls)
                                for con in con_cls.instances:
                                    cname = str(con.properties["Name"].value)
                                    if ccls == "CommandLineEventConsumer":
                                        ex = str(con.properties.get("ExecutablePath").value or "") if con.properties.get("ExecutablePath") else ""
                                        ct = str(con.properties.get("CommandLineTemplate").value or "") if con.properties.get("CommandLineTemplate") else ""
                                        cmd = ct or ex
                                        tgt = expand_target_like_v1(cmd, c_exists_fn=c_path_exists)
                                        fm = inspect_target_file(tgt) if tgt else None
                                        records.append(build_record(
                                            artifact_type="wmi_subscription",
                                            path_or_key=rf"{ns_name}\{ccls}",
                                            name=cname, path=tgt, command_line=cmd, fmeta=fm,
                                            extra={"wmi_namespace": ns_name, "wmi_class": ccls, "executable_path_raw": ex, "command_line_raw": cmd},
                                        ))
                                    else:
                                        stxt = str(con.properties.get("ScriptText").value or "") if con.properties.get("ScriptText") else ""
                                        sfn = str(con.properties.get("ScriptFileName").value or "") if con.properties.get("ScriptFileName") else ""
                                        records.append(build_record(
                                            artifact_type="wmi_subscription",
                                            path_or_key=rf"{ns_name}\{ccls}",
                                            name=cname, path=expand_target_like_v1(sfn) if sfn else None,
                                            command_line=sfn or None,
                                            extra={
                                                "wmi_namespace": ns_name,
                                                "wmi_class": ccls,
                                                "script_filename": sfn or None,
                                                "inline_script_len": len(stxt),
                                                "inline_script_sha256": hashlib.sha256(stxt.encode("utf-8")).hexdigest() if stxt else None,
                                            },
                                        ))
                            except Exception:
                                pass
                        try:
                            bnd_cls = ns.class_("__FilterToConsumerBinding")
                            for bnd in bnd_cls.instances:
                                fref = str(bnd.properties["Filter"].value or "")
                                cref = str(bnd.properties["Consumer"].value or "")
                                records.append(build_record(
                                    artifact_type="wmi_subscription",
                                    path_or_key=rf"{ns_name}\__FilterToConsumerBinding",
                                    name=f"{fref}->{cref}",
                                    extra={"wmi_namespace": ns_name, "wmi_class": "__FilterToConsumerBinding", "wmi_filter_ref": fref, "wmi_consumer_ref": cref},
                                ))
                        except Exception:
                            pass
        except Exception:
            pass

        # 5. Startup & Shortcut `.lnk` files
        startup_dirs: list[Path] = []
        pd_start = t.fs.path(r"c:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
        if pd_start.exists():
            startup_dirs.append(pd_start)
        users_dir = t.fs.path(r"c:\Users")
        if users_dir.exists():
            for ud in users_dir.iterdir():
                st_sub = ud / "AppData" / "Roaming" / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
                if st_sub.exists():
                    startup_dirs.append(st_sub)
        for sdir in startup_dirs:
            for item in sdir.iterdir():
                if not item.is_file() or item.name.lower() == "desktop.ini":
                    continue
                lnk_path_str = normalize_volume_prefix(str(item))
                cmd = None
                tgt_resolved = lnk_path_str
                lnk_extra: dict[str, Any] = {"lnk_source_path": lnk_path_str}
                if item.name.lower().endswith(".lnk"):
                    try:
                        import LnkParse3  # type: ignore

                        with item.open("rb") as lfh:
                            lj = LnkParse3.lnk_file(lfh).get_json()
                        linfo = lj.get("link_info") or {}
                        ldata = lj.get("data") or {}
                        lextra = lj.get("extra") or {}
                        t_raw = linfo.get("local_base_path") or ldata.get("relative_path") or ""
                        args = ldata.get("command_line_arguments") or ""
                        cmd = f"{t_raw} {args}".strip() or None
                        t_exp = expand_target_like_v1(t_raw, c_exists_fn=c_path_exists)
                        if t_exp:
                            tgt_resolved = t_exp
                        dlt = lextra.get("DISTRIBUTED_LINK_TRACKER_BLOCK") or {}
                        lnk_extra.update({
                            "lnk_target_path_raw": t_raw or None,
                            "lnk_target_path_expanded": t_exp,
                            "lnk_arguments": args or None,
                            "lnk_tracker_object_id": dlt.get("droid_file_identifier"),
                            "lnk_volume_serial": str(linfo.get("volume_id", {}).get("drive_serial_number")) if isinstance(linfo.get("volume_id"), dict) else None,
                            "lnk_target_mft_index": None,
                            "lnk_target_mft_sequence": None,
                        })
                    except Exception:
                        pass
                fmeta = inspect_target_file(tgt_resolved)
                records.append(build_record(
                    artifact_type="startup", path_or_key=lnk_path_str, name=item.name,
                    path=lnk_path_str, command_line=cmd, fmeta=fmeta, extra=lnk_extra,
                ))

        # 6. Prefetch (.pf headers + File Metrics array)
        pf_dir = t.fs.path(r"c:\Windows\Prefetch")
        if pf_dir.exists():
            for pf_path in sorted(pf_dir.iterdir(), key=lambda x: x.name.lower()):
                if not pf_path.name.lower().endswith(".pf") or not pf_path.is_file():
                    continue
                pf_str = normalize_volume_prefix(str(pf_path))
                fmeta = inspect_target_file(pf_str)
                pf_extra: dict[str, Any] = {}
                try:
                    with pf_path.open("rb") as pfh:
                        pf_obj = dpf.Prefetch(pfh)
                        pf_exe = pf_obj.header.name.decode("utf-16-le", errors="ignore").split("\x00", 1)[0]
                        pf_scca = f"{int(pf_obj.header.hash):08x}"
                        pf_ver = int(pf_obj.version)
                        pf_rc = int(getattr(pf_obj.fn, "run_count", 0))
                        _, m_struct = dpf.prefetch_version_structs[pf_ver]
                        pf_obj.fh.seek(pf_obj.fn.metrics_array_offset)
                        fm_list: list[dict[str, Any]] = []
                        for fpath_raw in (pf_obj.metrics or []):
                            ent = m_struct(pf_obj.fh)
                            ref = getattr(ent, "ntfs_reference", None)
                            idx = (int(ref) & 0xFFFFFFFFFFFF) if ref is not None else None
                            seq = ((int(ref) >> 48) & 0xFFFF) if ref is not None else None
                            if idx == 0:
                                idx, seq = None, None  # Win11 v31 empty MFT slot sentinel -> fallback to path
                            canon_m = normalize_volume_prefix(fpath_raw)
                            if canon_m and canon_m.lower().startswith("c:\\") and canon_m.lower().endswith((".exe", ".dll")):
                                referenced_target_paths.add(canon_m)
                            fm_list.append({"file_path": canon_m, "mft_index": idx, "mft_sequence": seq})
                        pf_extra = {
                            "pf_executable_name": pf_exe,
                            "pf_scca_hash": pf_scca,
                            "pf_format_version": pf_ver,
                            "pf_run_count": pf_rc,
                            "pf_file_metrics": fm_list,
                        }
                except Exception:
                    pass
                records.append(build_record(
                    artifact_type="prefetch", path_or_key=pf_str, name=pf_path.name,
                    path=pf_str, fmeta=fmeta, extra=pf_extra,
                ))

        # 7. ShimCache (AppCompatCache)
        try:
            for sc in t.shimcache():
                sp = str(getattr(sc, "path", "") or "")
                norm_p = expand_target_like_v1(sp, c_exists_fn=c_path_exists) or sp
                bname = F.path_basename(norm_p.lower())
                rk = r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
                records.append(build_record(
                    artifact_type="shimcache", path_or_key=norm_p or rk, name=bname or "AppCompatCache",
                    path=norm_p or None, registry_key=rk,
                ))
        except Exception:
            pass

        # 8. Amcache (InventoryApplicationFile from Amcache.hve)
        am_path = t.fs.path(r"c:\Windows\AppCompat\Programs\Amcache.hve")
        if am_path.exists():
            try:
                from dissect.regf import RegistryHive  # type: ignore

                with am_path.open("rb") as afh:
                    rh = RegistryHive(afh)
                    iaf = rh.open(r"Root\InventoryApplicationFile")
                    if iaf is not None:
                        for sk in iaf.subkeys():
                            vals = {v.name: v.value for v in sk.values()}
                            lp = str(vals.get("LowerCaseLongPath") or "").strip()
                            fid = str(vals.get("FileId") or "").strip() or None
                            pid_str = str(vals.get("ProgramId") or "").strip() or None
                            nm = str(vals.get("Name") or F.path_basename(lp) or sk.name)
                            norm_lp = expand_target_like_v1(lp, c_exists_fn=c_path_exists)
                            if norm_lp and norm_lp.lower().startswith("c:\\"):
                                referenced_target_paths.add(norm_lp)
                            records.append(build_record(
                                artifact_type="amcache",
                                path_or_key=norm_lp or sk.name,
                                name=nm,
                                path=norm_lp,
                                extra={
                                    "amcache_file_id": fid,
                                    "amcache_lowercase_long_path": lp.lower() or None,
                                    "amcache_program_id": pid_str,
                                },
                            ))
            except Exception:
                pass

        # 9. Local Accounts (SAM)
        try:
            seen_users: set[str] = set()
            for u in t.users():
                uname = str(getattr(u, "name", "") or "")
                sid = str(getattr(u, "sid", "") or "")
                if not uname or uname.lower() in seen_users:
                    continue
                seen_users.add(uname.lower())
                records.append(build_record(
                    artifact_type="account",
                    path_or_key=f"local_user\\{uname}",
                    name=uname,
                    extra={
                        "account_sid": sid or None,
                        "account_is_admin": uname.lower() == "administrator" or sid.endswith("-500"),
                        "account_enabled": True,
                    },
                ))
        except Exception:
            pass

        # 10. File + $MFT records: user-writable roots (v1 parity) + referenced target files (refgraph closure)
        scan_roots: list[tuple[Path, int]] = []
        for root_str, depth in (
            (r"c:\Windows\Temp", 4),
            (r"c:\Users\Public", 5),
            (r"c:\ProgramData", 4),
        ):
            rp = t.fs.path(root_str)
            if rp.exists():
                scan_roots.append((rp, depth))
        if users_dir.exists():
            for ud in users_dir.iterdir():
                if not ud.is_dir():
                    continue
                for sub_rel, depth in ((r"AppData\Local\Temp", 4), (r"AppData\Roaming", 4), (r"AppData\Local", 3)):
                    sp = ud / sub_rel
                    if sp.exists():
                        scan_roots.append((sp, depth))

        seen_file_paths: set[str] = set()
        scanned_user_files = 0

        def walk_fs(dir_obj: Any, depth_left: int) -> None:
            nonlocal scanned_user_files
            if scanned_user_files >= max_scanned_files:
                return
            d_str = normalize_volume_prefix(str(dir_obj)).lower().rstrip("\\") + "\\"
            if any(frag in d_str for frag in _SKIP_DIR_FRAGS):
                return
            try:
                entries = list(dir_obj.iterdir())
            except Exception:
                return
            subdirs = []
            for ent in entries:
                if scanned_user_files >= max_scanned_files:
                    return
                if ent.is_symlink():
                    continue
                if ent.is_file():
                    if Path(ent.name).suffix.lower() not in _USER_SCAN_TARGET_EXTS:
                        continue
                    norm_f = normalize_volume_prefix(str(ent))
                    if norm_f.lower() in seen_file_paths:
                        continue
                    seen_file_paths.add(norm_f.lower())
                    scanned_user_files += 1
                    fm = inspect_target_file(norm_f)
                    if fm:
                        records.append(build_record(
                            artifact_type="file", path_or_key=fm["path"], name=ent.name,
                            path=fm["path"], fmeta=fm,
                        ))
                elif ent.is_dir() and depth_left > 0:
                    subdirs.append(ent)
            for sd in subdirs:
                walk_fs(sd, depth_left - 1)

        for r_obj, d_lim in scan_roots:
            if scanned_user_files >= max_scanned_files:
                break
            walk_fs(r_obj, d_lim)

        # Also materialize referenced PE/script target files (System32/Program Files/etc.) so static refgraph edges close
        for ref_p in sorted(referenced_target_paths):
            norm_ref = normalize_volume_prefix(ref_p)
            if not norm_ref.lower().startswith("c:\\") or norm_ref.lower() in seen_file_paths:
                continue
            if norm_ref.lower().endswith(".pf"):
                continue
            fm = inspect_target_file(norm_ref)
            if fm is not None:
                seen_file_paths.add(norm_ref.lower())
                records.append(build_record(
                    artifact_type="file", path_or_key=fm["path"], name=Path(fm["path"]).name,
                    path=fm["path"], fmeta=fm,
                ))

        elapsed = round(time.monotonic() - t0, 3)
        df = pd.DataFrame(records)
        summary = summarize_extraction_and_refgraph(df, disk_id=run_id)
        summary.update({
            "extractor_version": EXTRACTOR_VERSION,
            "qcow2_path": str(qcow2_path),
            "elapsed_seconds": elapsed,
            "catroot_digests_loaded": len(cat_digests),
            "wof_compressed_files": int(sum(1 for r in records if r.get("wof_compressed"))),
        })
        return records, summary
    finally:
        try:
            t.target.close() if hasattr(t, "target") else None  # type: ignore[attr-defined]
        except Exception:
            pass


def extract_from_fixture(
    fixture_records: Sequence[Mapping[str, Any]],
    run_id: str = "synthetic_offline",
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Validate and enrich synthetic offline fixture records using identical user-space rules."""
    validated: list[dict[str, Any]] = []
    for raw_r in fixture_records:
        rec = dict(raw_r)
        rec.setdefault("run_id", run_id)
        raw_bytes = rec.pop("sample_head_bytes_for_test", None)
        if raw_bytes is not None:
            rec["file_head_histogram"] = compute_head_histogram(raw_bytes)
            rec.setdefault("file_size", len(raw_bytes))
            rec.setdefault("file_sha256", hashlib.sha256(raw_bytes).hexdigest())
        if "signature_status" not in rec or rec["signature_status"] is None:
            if rec.get("artifact_type") == "file" and rec.get("path"):
                ext = Path(str(rec["path"])).suffix.lower()
                if ext not in _SIP_EXTS or (rec.get("file_size") or 0) == 0:
                    rec["signature_status"] = "UnknownError"
        rec["record_sha256"] = _format_record_hash(rec)
        validated.append(validate_extracted_record(rec))

    df = pd.DataFrame(validated)
    summary = summarize_extraction_and_refgraph(df, disk_id=run_id)
    summary["extractor_version"] = EXTRACTOR_VERSION
    return validated, summary


def summarize_extraction_and_refgraph(df: pd.DataFrame, disk_id: str = "offline_disk") -> dict[str, Any]:
    """Compute per-artifact-type extraction counts and `v2_refgraph` link coverage safely."""
    if len(df) == 0:
        return {"total_records": 0, "per_type_counts": {}, "refgraph_coverage": {}}

    per_type = {str(k): int(v) for k, v in df["artifact_type"].value_counts().items()}
    # Strip any forbidden columns before passing into build_disk_graph (enforces assert_graph_inputs_clean)
    allowed_df = df[[c for c in df.columns if not RG._is_forbidden_col(c)]].copy()
    graph = RG.build_disk_graph(allowed_df, disk_id=disk_id)

    has_resolved = set()
    by_type_stats: dict[str, dict[str, Any]] = {}
    for _, row in allowed_df.iterrows():
        at = str(row.get("artifact_type", "other")).lower()
        ak = str(row.get("artifact_key", ""))
        st = by_type_stats.setdefault(at, {"rows": 0, "with_resolved_link": 0, "resolved_targets": 0})
        st["rows"] += 1
        links = json.loads(graph.row_links.get(ak, {}).get("linked_artifact_keys", "[]"))
        if links:
            st["with_resolved_link"] += 1
            st["resolved_targets"] += len(links)
            has_resolved.add(ak)
    for src, dst, _, _, _ in graph.typed_edges:
        if dst in set(allowed_df["artifact_key"].astype(str)) and src in set(allowed_df["artifact_key"].astype(str)):
            has_resolved.add(dst)

    pe_rows = sum(by_type_stats.get(t, {}).get("rows", 0) for t in _PERSIST_EXEC_TYPES)
    pe_resolved = sum(by_type_stats.get(t, {}).get("with_resolved_link", 0) for t in _PERSIST_EXEC_TYPES)

    for st in by_type_stats.values():
        st["resolved_rate_pct"] = round(100.0 * st["with_resolved_link"] / max(1, st["rows"]), 2)

    return {
        "total_records": int(len(df)),
        "per_type_counts": per_type,
        "refgraph_coverage": {
            "rows_with_resolved_outgoing": int(sum(st["with_resolved_link"] for st in by_type_stats.values())),
            "rows_with_resolved_outgoing_pct": round(100.0 * sum(st["with_resolved_link"] for st in by_type_stats.values()) / len(df), 2),
            "rows_with_any_resolved_link": int(len(has_resolved)),
            "rows_with_any_resolved_link_pct": round(100.0 * len(has_resolved) / len(df), 2),
            "persistence_exec_rows": int(pe_rows),
            "persistence_exec_resolved_rows": int(pe_resolved),
            "persistence_exec_resolved_pct": round(100.0 * pe_resolved / max(1, pe_rows), 2),
            "per_type": by_type_stats,
        },
    }


def write_outputs(records: Sequence[Mapping[str, Any]], summary: Mapping[str, Any], out_dir: str | Path) -> dict[str, Path]:
    """Write schema-validated JSONL, Parquet (complex nested cols JSON-encoded), and manifest JSON."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = out_dir / "artifacts.jsonl"
    with jsonl_path.open("w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(json.dumps(rec, separators=(",", ":"), default=str) + "\n")

    pq_rows = []
    for rec in records:
        row = {}
        for k, v in rec.items():
            if isinstance(v, (list, dict)) and k != "file_head_histogram":
                row[k] = json.dumps(v, separators=(",", ":"), default=str)
            else:
                row[k] = v
        pq_rows.append(row)
    pq_path = out_dir / "artifacts.parquet"
    pd.DataFrame(pq_rows).to_parquet(pq_path, index=False)

    manifest = {
        "generated_at_utc": utc_now_iso(),
        **summary,
    }
    man_path = write_json(manifest, out_dir / "extraction_manifest.json")
    return {"jsonl": jsonl_path, "parquet": pq_path, "manifest": man_path}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pure user-space offline QCOW2 artifact extractor (Step F).")
    parser.add_argument("--qcow2", type=Path, required=True, help="Closed QCOW2 image path (opened read-only)")
    parser.add_argument("--out-dir", type=Path, required=True, help="Output directory for JSONL/Parquet/manifest")
    parser.add_argument("--run-id", default="offline_run")
    parser.add_argument("--max-scanned-files", type=int, default=1500)
    parser.add_argument("--skip-catroot", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)

    records, summary = extract_from_qcow2(
        args.qcow2,
        run_id=args.run_id,
        max_scanned_files=args.max_scanned_files,
        resolve_catroot=not args.skip_catroot,
    )
    paths = write_outputs(records, summary, args.out_dir)
    print(json.dumps({"summary": summary, "outputs": {k: str(v) for k, v in paths.items()}}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
