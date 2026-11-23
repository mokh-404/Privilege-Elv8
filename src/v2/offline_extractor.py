"""Pure user-space offline QCOW2 & NTFS artifact extractor (Step F / OD-V2-04, OD-V2-16).

Reads closed QCOW2 disk images or synthetic fixtures strictly in user space via
`dissect.target`, `dissect.ntfs`, `dissect.regf`, `dissect.cim`, `LnkParse3`, and
`signify`. Never performs host-kernel mounts (`mount`/`qemu-nbd`) and never copies
raw executable payloads onto the host workspace.

Includes:
- Immutable Base-Image Digest & Signature Cache (`--base-cache-path` / `--build-base-cache`),
  cryptographically bound to `win11_base.qcow2` SHA-256 (`GOLDEN_BASE_IMAGE_SHA256`), reducing
  per-run extraction from `~16.9 min` to `< 1 min` while parsing new/modified files live.
- UTF-16LE/UTF-8 Scheduled Task XML parser + `TaskCache\\Tasks\\{GUID}\\Actions` binary blob decoder
  (`0x6666`/`0x7777` `ExecAction` and `0x5555`/`0x7777` `ComHandlerAction`) + `Classes\\CLSID`
  (`InprocServer32` / `LocalServer32` / `AppID -> LocalService`) target join.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import re
import struct
import time
import uuid
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import pandas as pd

from src import config
from src.data import features as F
from src.utils.repro import utc_now_iso, write_json
from src.v2 import refgraph as RG


EXTRACTOR_VERSION = "2.2.0"
PRE_BAKE_BASE_IMAGE_SHA256 = "feddb54d208174d3d1eda45e69ac831965a8572ead71f276ddf229a0ac3d0674"
GOLDEN_BASE_IMAGE_SHA256 = "d2facced4255e3ae1cb821249d5e6330e380f639cee8a5aae19ef99be690835c"
ALLOWED_BASE_IMAGE_SHA256S: frozenset[str] = frozenset({
    PRE_BAKE_BASE_IMAGE_SHA256,
    GOLDEN_BASE_IMAGE_SHA256,
})
MIB = 1 << 20
MAX_PE_SIGNIFY_BYTES = 128 * MIB  # safety bound when decompressing / reading PEs for Authenticode hash

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
_XML_DECL_RE = re.compile(r"^\s*<\?xml[^>]*\?>", re.I)
_FORBIDDEN_PAYLOAD_KEYS = frozenset({"raw_bytes", "payload_bytes", "file_bytes", "binary_blob", "script_text", "raw_script_text"})
_PERSIST_EXEC_TYPES: tuple[str, ...] = ("task", "service", "run_key", "wmi_subscription", "prefetch")

V2_HARNESS_PATH_PREFIXES: tuple[str, ...] = (
    "c:\\dfir-bootstrap",
    "c:\\collector_out_parity",
    "c:\\collector",
    "c:\\dfir_stage",
    "c:\\dfir_bake",
)
V2_HARNESS_TASK_NAMES: frozenset[str] = frozenset({
    "dfir-stagerunner",
    "\\dfir-stagerunner",
})
V2_HARNESS_SERVICE_NAMES: frozenset[str] = frozenset({
    "sysmon",
    "sysmon64",
    "sysmondrv",
})
V2_HARNESS_BINARY_BASENAMES: frozenset[str] = frozenset({
    "sysmon.exe",
    "sysmon64.exe",
    "sysmondrv.sys",
    "invoke-stagepayload.ps1",
    "install-v2basebootstrap.ps1",
    "collect-artifacts.ps1",
})


def is_v2_harness_footprint_record(rec: Mapping[str, Any]) -> str | None:
    """Return a deterministic exclusion reason if `rec` belongs to the v2 lab/collector/Sysmon harness, else None."""
    at = str(rec.get("artifact_type") or "").strip().lower()
    nm = str(rec.get("name") or "").strip().lower().replace("/", "\\")
    ak = str(rec.get("artifact_key") or "").strip().lower().replace("/", "\\")
    path = str(rec.get("path") or "").strip().lower().replace("/", "\\")
    cmd = str(rec.get("command_line") or "").strip().lower().replace("/", "\\")
    reg_k = str(rec.get("registry_key") or "").strip().lower().replace("/", "\\")
    reg_v = str(rec.get("registry_value") or "").strip().lower().replace("/", "\\")
    tname = str(rec.get("task_name") or "").strip().lower().replace("/", "\\")
    sname = str(rec.get("service_name") or "").strip().lower()
    pf_exe = str(rec.get("pf_executable_name") or "").strip().lower()

    for pref in V2_HARNESS_PATH_PREFIXES:
        if (
            path == pref
            or path.startswith(pref + "\\")
            or (pref + "\\") in cmd
            or (pref + "\\") in reg_v
            or (pref + "\\") in ak
        ):
            return f"v2_harness_path:{pref}"

    if at == "task" and (
        nm in V2_HARNESS_TASK_NAMES
        or tname in V2_HARNESS_TASK_NAMES
        or tname.endswith("\\dfir-stagerunner")
        or "dfir-stagerunner" in ak
    ):
        return "v2_harness_task:dfir-stagerunner"

    if at == "service" and (nm in V2_HARNESS_SERVICE_NAMES or sname in V2_HARNESS_SERVICE_NAMES):
        return f"v2_harness_service:{sname or nm}"

    if reg_k and any(
        reg_k.endswith(f"\\services\\{svc}") or f"\\services\\{svc}\\" in reg_k
        for svc in V2_HARNESS_SERVICE_NAMES
    ):
        return "v2_harness_service_reg:sysmon"

    base_path_nm = F.path_basename(path) if path else ""
    if (
        nm in V2_HARNESS_BINARY_BASENAMES
        or base_path_nm in V2_HARNESS_BINARY_BASENAMES
        or pf_exe in V2_HARNESS_BINARY_BASENAMES
        or (at == "prefetch" and any(nm.startswith(b + "-") for b in ("sysmon.exe", "sysmon64.exe")))
    ):
        return f"v2_harness_binary:{base_path_nm or pf_exe or nm}"

    return None


def compute_head_histogram(data: bytes | bytearray) -> list[int]:
    """Return 256-bin byte frequency counts strictly over the leading 1 MiB."""
    head = data[:MIB]
    counts = Counter(head)
    return [int(counts.get(i, 0)) for i in range(256)]


def make_base_file_cache_key(
    mft_record_number: int | None,
    mft_sequence_number: int | None,
    file_size: int | None,
    mtime_ns: int | None,
) -> str | None:
    """Build deterministic 4-tuple cache key `(mft_record_number, mft_sequence_number, file_size, mtime_ns)`."""
    if mft_record_number is None or mft_sequence_number is None or file_size is None or mtime_ns is None:
        return None
    return f"{int(mft_record_number)}:{int(mft_sequence_number)}:{int(file_size)}:{int(mtime_ns)}"


def save_base_image_cache(
    cache_path: str | Path,
    base_image_sha256: str,
    catroot_digests: Iterable[str],
    file_entries: Mapping[str, Mapping[str, Any]],
) -> Path:
    """Serialize immutable base-image `CatRoot` digests and per-file metadata cache bound to `base_image_sha256`."""
    cpath = Path(cache_path)
    cpath.parent.mkdir(parents=True, exist_ok=True)
    cat_sorted = sorted({str(d).lower() for d in catroot_digests if d})
    payload = {
        "cache_format_version": "1.0",
        "extractor_version": EXTRACTOR_VERSION,
        "created_at_utc": utc_now_iso(),
        "base_image_sha256": str(base_image_sha256).lower().strip(),
        "catroot_digests_count": len(cat_sorted),
        "file_entries_count": len(file_entries),
        "catroot_digests": cat_sorted,
        "file_entries": dict(file_entries),
    }
    raw_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if cpath.name.endswith(".gz"):
        with gzip.open(cpath, "wb", compresslevel=6) as gfh:
            gfh.write(raw_bytes)
    else:
        cpath.write_bytes(raw_bytes)
    return cpath


def load_base_image_cache(
    cache_path: str | Path,
    expected_base_sha256: str = GOLDEN_BASE_IMAGE_SHA256,
) -> dict[str, Any]:
    """Load and verify a base-image cache file against `expected_base_sha256`."""
    cpath = Path(cache_path)
    if not cpath.exists():
        raise FileNotFoundError(f"Base image cache file not found: {cpath}")
    if cpath.name.endswith(".gz"):
        with gzip.open(cpath, "rb") as gfh:
            data = json.loads(gfh.read().decode("utf-8"))
    else:
        data = json.loads(cpath.read_text(encoding="utf-8"))

    actual_sha = str(data.get("base_image_sha256") or "").lower().strip()
    exp_sha = str(expected_base_sha256 or "").lower().strip()
    if exp_sha == "auto":
        if actual_sha not in ALLOWED_BASE_IMAGE_SHA256S:
            raise ValueError(
                f"Base-image cache SHA-256 mismatch: cache bound to {actual_sha!r}, not in {sorted(ALLOWED_BASE_IMAGE_SHA256S)}"
            )
    elif exp_sha and actual_sha != exp_sha:
        raise ValueError(
            f"Base-image cache SHA-256 mismatch: cache bound to {actual_sha!r}, expected {exp_sha!r}"
        )
    return data


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
        "%CommonProgramFiles(x86)%": r"C:\Program Files (x86)\Common Files",
        "%CommonProgramW6432%": r"C:\Program Files\Common Files",
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


_TARGET_EXT_EXTRACT_RE = re.compile(
    r"^(.+?\.(?:exe|dll|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|hta|sys|scr|msi|lnk|com|msc|cpl))(?=\s|,|$)",
    re.I,
)
_LOCKED_LIVE_HIVE_NAMES: frozenset[str] = frozenset({
    "ntuser.dat",
    "ntuser.dat.log",
    "ntuser.dat.log1",
    "ntuser.dat.log2",
    "usrclass.dat",
    "usrclass.dat.log",
    "usrclass.dat.log1",
    "usrclass.dat.log2",
})


def _is_locked_live_hive_file(path_str: str | None) -> bool:
    if not path_str:
        return False
    bname = F.path_basename(str(path_str).replace("/", "\\").lower())
    return bname in _LOCKED_LIVE_HIVE_NAMES


def expand_target_like_v1(raw: str | None, c_exists_fn: Any = None, env_map: Mapping[str, str] | None = None) -> str | None:
    """Replicate v1 Collect-Artifacts.ps1 Extract-TargetPath + Expand-NormPath semantics."""
    if not raw or not str(raw).strip():
        return None
    s = str(raw).strip()
    if s.startswith('"'):
        end_q = s.find('"', 1)
        candidate = s[1:end_q] if end_q > 1 else s[1:]
    else:
        m = _TARGET_EXT_EXTRACT_RE.match(s)
        if m:
            candidate = m.group(1)
        else:
            candidate = s.split()[0]

    norm = expand_win_env(candidate.strip().strip('"').strip(), env_map=env_map).replace("/", "\\")
    if norm.startswith(("\\??\\", "\\\\?\\")):
        norm = norm[4:]
    if norm.lower().startswith("\\systemroot\\"):
        norm = r"C:\WINDOWS\\" + norm[len("\\systemroot\\") :]
    elif norm.lower().startswith("systemroot\\"):
        norm = r"C:\WINDOWS\\" + norm[len("systemroot\\") :]
    elif norm.lower().startswith("system32\\"):
        norm = r"C:\WINDOWS\\" + norm
    elif norm.lower().startswith("syswow64\\"):
        norm = r"C:\WINDOWS\\" + norm
    while "\\\\" in norm:
        norm = norm.replace("\\\\", "\\")
    norm = norm.strip().rstrip(",")
    if not norm:
        return None
    if "\\" not in norm and re.search(r"\.(exe|dll|com|msc|cpl)$", norm, re.I) and c_exists_fn is not None:
        for base_dir in (r"C:\Windows\System32", r"C:\Windows\System32\WindowsPowerShell\v1.0"):
            cand = f"{base_dir}\\{norm}"
            if c_exists_fn(cand):
                return cand
    return norm


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
            # Fast path for catalog-signed inbox PEs lacking embedded Authenticode certificates
            if not list(af.signatures):
                if cat_digests:
                    fp256 = af.get_fingerprint(hashlib.sha256).hex().lower()
                    if fp256 in cat_digests:
                        return "Valid"
                    fp1 = af.get_fingerprint(hashlib.sha1).hex().lower()
                    if fp1 in cat_digests:
                        return "Valid"
                return "NotSigned"

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


def _decode_task_xml_bytes(xml_input: str | bytes) -> str:
    """Decode UTF-16LE / UTF-16BE / UTF-8 Task XML bytes and strip encoding header for ET."""
    if isinstance(xml_input, (bytes, bytearray)):
        raw = bytes(xml_input)
        if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
            txt = raw.decode("utf-16", errors="replace")
        elif len(raw) >= 4 and raw[1] == 0 and raw[3] == 0:
            txt = raw.decode("utf-16-le", errors="replace")
        elif len(raw) >= 4 and raw[0] == 0 and raw[2] == 0:
            txt = raw.decode("utf-16-be", errors="replace")
        else:
            txt = raw.decode("utf-8-sig", errors="replace")
    else:
        txt = str(xml_input)
    return _XML_DECL_RE.sub("", txt, count=1).strip()


def _parse_task_xml(xml_text: str | bytes) -> dict[str, Any]:
    out: dict[str, Any] = {
        "exec_actions": [],
        "com_handlers": [],
        "triggers": [],
        "command_line": None,
        "first_exec": None,
    }
    clean_xml = _decode_task_xml_bytes(xml_text)
    if not clean_xml:
        return out
    try:
        root = ET.fromstring(clean_xml)
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
        "WnfStateChangeTrigger": "MSFT_TaskTrigger",
    }
    trigs: list[str] = []
    cmd_parts: list[str] = []

    for el in root.iter():
        tname = strip_ns(el.tag)
        if tname == "Triggers":
            for t_child in el:
                ctag = strip_ns(t_child.tag)
                if ctag in trig_map:
                    trigs.append(trig_map[ctag])
                elif ctag.endswith("Trigger"):
                    trigs.append("MSFT_TaskTrigger")
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
                    raw_guid = m.group(1) if m else ch.text.strip()
                    low_guid = raw_guid.lower()
                    if low_guid not in out["com_handlers"]:
                        out["com_handlers"].append(low_guid)
                    # Preserve original/uppercase brace GUID matching Get-ScheduledTask CimClass/ClassId
                    cmd_parts.append(f"COM:{raw_guid}")

    out["triggers"] = trigs
    out["command_line"] = " ; ".join(cmd_parts).strip() or None
    return out


def decode_taskcache_actions_blob(blob: bytes | bytearray | None) -> dict[str, Any]:
    """Decode `HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tasks\\{GUID}\\Actions`.

    Supports:
    - `0x6666` (`ExecAction`) and `0x7777` `ExecAction` blocks (extracting UTF-16LE command, arguments,
      and working directory strings),
    - `0x5555` and `0x7777` `ComHandlerAction` blocks (extracting 16-byte little-endian `CLSID` GUIDs
      and optional UTF-16LE handler data strings).
    """
    out: dict[str, Any] = {
        "exec_actions": [],
        "com_handlers": [],
        "command_line": None,
        "first_exec": None,
    }
    if not blob or not isinstance(blob, (bytes, bytearray)) or len(blob) < 6:
        return out
    b = bytes(blob)
    ver = struct.unpack_from("<H", b, 0)[0]
    if ver not in (1, 2, 3):
        return out
    pos = 2
    ctx_len = struct.unpack_from("<I", b, pos)[0]
    if pos + 4 + ctx_len > len(b):
        return out
    pos += 4 + ctx_len

    cmd_parts: list[str] = []

    def _looks_like_utf16_exec(buf: bytes, offset: int) -> bool:
        if offset + 4 > len(buf):
            return False
        slen = struct.unpack_from("<I", buf, offset)[0]
        if slen == 0 or slen % 2 != 0 or offset + 4 + slen > len(buf):
            return False
        s_try = buf[offset + 4 : offset + 4 + slen].decode("utf-16-le", errors="replace").rstrip("\x00")
        if not s_try or any(ord(c) < 32 for c in s_try):
            return False
        return ("\\" in s_try) or ("/" in s_try) or ("%" in s_try) or (".exe" in s_try.lower()) or (".dll" in s_try.lower()) or (".ps1" in s_try.lower()) or (".bat" in s_try.lower()) or (".cmd" in s_try.lower())

    while pos + 6 <= len(b):
        magic = struct.unpack_from("<H", b, pos)[0]
        pos += 2
        id_len = struct.unpack_from("<I", b, pos)[0]
        if pos + 4 + id_len > len(b):
            break
        pos += 4 + id_len

        is_exec = magic == 0x6666 or (magic == 0x7777 and _looks_like_utf16_exec(b, pos))
        is_com = magic == 0x5555 or (magic == 0x7777 and not is_exec)

        if is_exec:
            if pos + 4 > len(b):
                break
            cmd_len = struct.unpack_from("<I", b, pos)[0]
            pos += 4
            if pos + cmd_len > len(b):
                break
            cmd = b[pos : pos + cmd_len].decode("utf-16-le", errors="ignore").rstrip("\x00").strip()
            pos += cmd_len
            args = ""
            wdir = ""
            if pos + 4 <= len(b):
                arg_len = struct.unpack_from("<I", b, pos)[0]
                if pos + 4 + arg_len <= len(b):
                    pos += 4
                    args = b[pos : pos + arg_len].decode("utf-16-le", errors="ignore").rstrip("\x00").strip()
                    pos += arg_len
            if pos + 4 <= len(b):
                wd_len = struct.unpack_from("<I", b, pos)[0]
                if pos + 4 + wd_len <= len(b):
                    pos += 4
                    wdir = b[pos : pos + wd_len].decode("utf-16-le", errors="ignore").rstrip("\x00").strip()
                    pos += wd_len
            if ver >= 3 and pos + 2 <= len(b):
                next_u16 = struct.unpack_from("<H", b, pos)[0]
                if next_u16 not in (0x6666, 0x7777, 0x5555):
                    pos += 2
            if cmd:
                if out["first_exec"] is None:
                    out["first_exec"] = cmd
                out["exec_actions"].append({
                    "command_raw": cmd,
                    "command_expanded": expand_win_env(cmd),
                    "arguments_raw": args or None,
                    "arguments_expanded": expand_win_env(args) if args else None,
                    "working_dir": wdir or None,
                })
                cmd_parts.append(f"{cmd} {args}".strip())
        elif is_com:
            if pos + 16 > len(b):
                break
            guid = "{" + str(uuid.UUID(bytes_le=b[pos : pos + 16])).upper() + "}"
            low_guid = guid.lower()
            pos += 16
            data_str = ""
            if pos + 4 <= len(b):
                d_len = struct.unpack_from("<I", b, pos)[0]
                if pos + 4 + d_len <= len(b):
                    pos += 4
                    data_str = b[pos : pos + d_len].decode("utf-16-le", errors="ignore").rstrip("\x00").strip()
                    pos += d_len
            if low_guid not in out["com_handlers"]:
                out["com_handlers"].append(low_guid)
            cmd_parts.append(f"COM:{guid} {data_str}".strip() if data_str else f"COM:{guid}")
        else:
            break

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
    if hasattr(si, "attribute") and hasattr(si.attribute, "attr"):
        val = getattr(si.attribute.attr, "FileAttributes", None)
        if val is not None:
            return int(val)
    return None


def _si_mtime_ns(si: Any) -> int:
    if si is None:
        return 0
    val = getattr(si, "last_modification_time_ns", None)
    if val is not None:
        try:
            return int(val)
        except Exception:
            pass
    if hasattr(si, "attribute") and hasattr(si.attribute, "attr"):
        raw_ft = getattr(si.attribute.attr, "LastModificationTime", None)
        if raw_ft is not None:
            try:
                return int(raw_ft) * 100
            except Exception:
                pass
    return 0


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
    mtime_ns = _si_mtime_ns(si)
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
        "mtime_ns": mtime_ns,
    }


def _read_qcow2_backing_file_header(qcow2_path: Path) -> str | None:
    """Return the raw backing-file string embedded in a QCOW2 header, or None if absent/not QCOW2."""
    from dissect.hypervisor.disk import qcow2 as dq  # type: ignore

    with qcow2_path.open("rb") as fh:
        if fh.read(4) != dq.QCOW2_MAGIC_BYTES:
            return None
        fh.seek(0)
        hdr = dq.c_qcow2.QCowHeader(fh)
        if not hdr.backing_file_offset or not hdr.backing_file_size:
            return None
        fh.seek(hdr.backing_file_offset)
        return fh.read(hdr.backing_file_size).decode("utf-8", errors="replace")


def _open_qcow2_stream_readonly(image_path: Path, _seen: set[Path] | None = None) -> Any:
    """Recursively open a QCOW2 (or raw) image stream read-only without `Path.with_name()` crashes on `/` paths."""
    from dissect.hypervisor.disk import qcow2 as dq  # type: ignore

    resolved = image_path.resolve()
    seen = set() if _seen is None else set(_seen)
    if resolved in seen:
        raise ValueError(f"Cycle detected in QCOW2 backing chain at {resolved}")
    seen.add(resolved)

    raw_backing = _read_qcow2_backing_file_header(resolved)
    backing_stream = None
    if raw_backing:
        bpath = Path(raw_backing)
        resolved_backing = bpath.resolve() if bpath.is_absolute() else (resolved.parent / bpath).resolve()
        if not resolved_backing.exists():
            raise FileNotFoundError(
                f"QCOW2 backing file not found: {resolved_backing} (referenced by {resolved})"
            )
        backing_stream = _open_qcow2_stream_readonly(resolved_backing, _seen=seen)

    with resolved.open("rb") as fh:
        is_qcow2 = fh.read(4) == dq.QCOW2_MAGIC_BYTES
    if is_qcow2:
        return dq.QCow2(resolved, backing_file=backing_stream).open()
    return resolved.open("rb")


def _exception_chain_has_invalid_name(exc: BaseException) -> bool:
    cur: BaseException | None = exc
    visited: set[int] = set()
    while cur is not None and id(cur) not in visited:
        visited.add(id(cur))
        if isinstance(cur, ValueError) and "invalid name" in str(cur).lower():
            return True
        cur = cur.__cause__ or cur.__context__
    return False


def open_qcow2_target_readonly(qcow2_path: str | Path, *, apply: bool = True) -> Any:
    """Open a closed QCOW2 (or raw) Target read-only, resolving absolute or slash-containing backing paths."""
    from dissect.target import Target  # type: ignore
    from dissect.target.containers.qcow2 import QCow2Container  # type: ignore

    qpath = Path(qcow2_path)
    try:
        return Target.open(str(qpath), apply=apply)
    except Exception as exc:
        raw_backing = _read_qcow2_backing_file_header(qpath) if qpath.exists() and qpath.is_file() else None
        has_slash_backing = bool(raw_backing and ("/" in raw_backing or "\\" in raw_backing))
        if not (_exception_chain_has_invalid_name(exc) or has_slash_backing):
            raise
        if not raw_backing:
            raise
        bpath = Path(raw_backing)
        resolved_backing = bpath.resolve() if bpath.is_absolute() else (qpath.resolve().parent / bpath).resolve()
        if not resolved_backing.exists():
            raise FileNotFoundError(
                f"QCOW2 backing file not found: {resolved_backing} (referenced by {qpath})"
            ) from exc
        backing_stream = _open_qcow2_stream_readonly(resolved_backing)
        container = QCow2Container(qpath, backing_file=backing_stream)
        target = Target(qpath)
        target.disks.add(container)
        if apply:
            target.apply()
        return target


def close_target_safely(target: Any) -> None:
    """Safely close `Target` disks, backing streams, and underlying handles."""
    if target is None:
        return
    try:
        if hasattr(target, "target") and target.target is not None:  # type: ignore[attr-defined]
            target.target.close()
    except Exception:
        pass
    disks = getattr(target, "disks", None)
    if disks is None:
        return
    for disk in list(disks):
        for attr in ("close",):
            try:
                fn = getattr(disk, attr, None)
                if callable(fn):
                    fn()
            except Exception:
                pass
        qc_obj = getattr(disk, "qcow2", None)
        cur = qc_obj
        seen: set[int] = set()
        while cur is not None and id(cur) not in seen:
            seen.add(id(cur))
            for h_attr in ("fh", "data_file"):
                h = getattr(cur, h_attr, None)
                try:
                    if h is not None and hasattr(h, "close"):
                        h.close()
                except Exception:
                    pass
            nxt = getattr(cur, "backing_file", None)
            if nxt is None:
                break
            nxt_qcow2 = getattr(nxt, "qcow2", None)
            try:
                if hasattr(nxt, "close"):
                    nxt.close()
            except Exception:
                pass
            cur = nxt_qcow2


def extract_from_qcow2(
    qcow2_path: str | Path,
    run_id: str = "offline_qcow2",
    max_scanned_files: int = 1500,
    resolve_catroot: bool = True,
    base_cache_path: str | Path | None = None,
    build_base_cache: bool = False,
    expected_base_sha256: str = GOLDEN_BASE_IMAGE_SHA256,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Parse a closed QCOW2 disk image strictly in user space (zero mounts)."""
    from dissect.target.plugins.os.windows import prefetch as dpf  # type: ignore

    qcow2_path = Path(qcow2_path)
    t0 = time.monotonic()

    loaded_cache: dict[str, Any] | None = None
    cached_file_entries: dict[str, Mapping[str, Any]] = {}
    new_cache_file_entries: dict[str, dict[str, Any]] = {}
    base_cache_hits = 0
    base_cache_misses = 0

    if base_cache_path is not None and Path(base_cache_path).exists() and not build_base_cache:
        loaded_cache = load_base_image_cache(base_cache_path, expected_base_sha256=expected_base_sha256)
        cached_file_entries = dict(loaded_cache.get("file_entries") or {})

    t = open_qcow2_target_readonly(qcow2_path)
    try:
        c_fs = t.fs.mounts.get("c:")
        ntfs = getattr(c_fs, "ntfs", None) if c_fs is not None else None

        cat_digests: set[str] = set()
        if loaded_cache is not None and loaded_cache.get("catroot_digests"):
            cat_digests = {str(d).lower() for d in loaded_cache["catroot_digests"]}
        elif resolve_catroot:
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

        user_env_map: dict[str, str] = {}
        try:
            u_root = t.fs.path(r"c:\Users")
            if u_root.exists():
                for ud in sorted(u_root.iterdir(), key=lambda x: x.name.lower()):
                    if ud.is_dir() and ud.name.lower() not in ("public", "default", "default user", "all users"):
                        u_win = rf"C:\Users\{ud.name}"
                        user_env_map["%UserProfile%"] = u_win
                        user_env_map["%LocalAppData%"] = rf"{u_win}\AppData\Local"
                        user_env_map["%AppData%"] = rf"{u_win}\AppData\Roaming"
                        break
        except Exception:
            pass

        file_meta_cache: dict[str, dict[str, Any]] = {}
        referenced_target_paths: set[str] = set()

        def inspect_target_file(win_path: str | None) -> dict[str, Any] | None:
            nonlocal base_cache_hits, base_cache_misses
            if not win_path:
                return None
            norm = expand_target_like_v1(normalize_volume_prefix(win_path), c_exists_fn=c_path_exists, env_map=user_env_map)
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
                base_cache_misses += 1
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
                    "wof_compressed": False,
                }
                file_meta_cache[low] = info
                return info

            if mft_rec.is_dir():
                return None
            mft_meta = _mft_record_metadata(mft_rec, norm)
            try:
                fast_sz = int(mft_rec.size("") or 0)
            except Exception:
                fast_sz = 0

            ckey = make_base_file_cache_key(
                mft_meta.get("mft_record_number"),
                mft_meta.get("mft_sequence_number"),
                fast_sz,
                mft_meta.get("mtime_ns"),
            )
            c_hit_raw = cached_file_entries.get(ckey) if ckey is not None else None
            stale_large_pe_hit = bool(
                c_hit_raw is not None
                and fast_sz > 64 * MIB
                and str(c_hit_raw.get("signature_status") or "") == "NotSigned"
            )
            if c_hit_raw is not None and not stale_large_pe_hit:
                c_hit = c_hit_raw
                base_cache_hits += 1
                info = {
                    **mft_meta,
                    "file_size": int(fast_sz),
                    "file_head_histogram": list(c_hit["file_head_histogram"]) if c_hit.get("file_head_histogram") is not None else None,
                    "file_sha256": c_hit.get("file_sha256"),
                    "signature_status": c_hit.get("signature_status"),
                    "wof_compressed": bool(c_hit.get("wof_compressed", mft_meta.get("wof_compressed", False))),
                }
                file_meta_cache[low] = info
                return info

            base_cache_misses += 1
            fbytes, full_sz, is_wof = _read_mft_file_bytes(mft_rec)
            hist = compute_head_histogram(fbytes[:MIB]) if fbytes is not None else None
            sha = hashlib.sha256(fbytes).hexdigest() if (fbytes is not None and full_sz <= MAX_PE_SIGNIFY_BYTES) else None
            sig = verify_offline_signature(norm, fbytes, full_sz, cat_digests)
            wof_flag = bool(is_wof or mft_meta.get("wof_compressed", False))
            info = {
                **mft_meta,
                "file_size": int(full_sz),
                "file_head_histogram": hist,
                "file_sha256": sha,
                "signature_status": sig,
                "wof_compressed": wof_flag,
            }
            if _is_locked_live_hive_file(norm):
                # OD-V2-02 Step F0 ruling (b): align locked active hive files with v1 Win32 lock missingness
                info["file_head_histogram"] = None
                info["file_sha256"] = None
                info["signature_status"] = "UnknownError"
                info["attributes"] = None
            if ckey is not None:
                new_cache_file_entries[ckey] = {
                    "path": norm,
                    "file_size": int(full_sz),
                    "file_head_histogram": info["file_head_histogram"],
                    "file_sha256": info["file_sha256"],
                    "signature_status": info["signature_status"],
                    "wof_compressed": wof_flag,
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
            allow_fmeta_path_fallback: bool = True,
        ) -> dict[str, Any]:
            clean_name = name.replace("/", "\\").rsplit("\\", 1)[-1] if artifact_type.lower() == "task" else name
            eff_path = path if (path is not None or not allow_fmeta_path_fallback) else (fmeta.get("path") if fmeta else None)
            if eff_path and str(eff_path).lower().startswith("c:\\"):
                referenced_target_paths.add(str(eff_path))
            akey = f"{artifact_type.lower()}|{RG._str(path_or_key).replace('/', '\\').lower()}|{RG._str(clean_name).replace('/', '\\').lower()}"
            rec: dict[str, Any] = {
                "run_id": run_id,
                "artifact_type": artifact_type,
                "artifact_key": akey,
                "name": clean_name,
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
                "wof_compressed": bool(fmeta.get("wof_compressed", False)) if fmeta else False,
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

        def reg_default_value_str(key_obj: Any) -> str | None:
            if key_obj is None:
                return None
            try:
                for v in key_obj.values():
                    if v.name in ("", "(Default)", None) and v.value:
                        return str(v.value).strip()
            except Exception:
                pass
            return None

        # Pre-index Services first so AppID -> LocalService COM handlers and Service records share the map
        select_k = reg_key_safe(r"HKLM\SYSTEM\Select")
        cur_v = reg_val_safe(select_k, "Current")
        cur_cs = int(cur_v.value) if cur_v is not None else 1
        cs_name = f"ControlSet{cur_cs:03d}"
        svc_root = reg_key_safe(rf"HKLM\SYSTEM\{cs_name}\Services")
        service_target_by_name: dict[str, str] = {}
        pending_service_rows: list[dict[str, Any]] = []
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
                eff_svc_bin = sdll_exp or target
                if eff_svc_bin:
                    service_target_by_name[sk.name.lower()] = eff_svc_bin
                pending_service_rows.append({
                    "name": sk.name,
                    "target": target,
                    "img_raw": img_raw,
                    "img_exp": img_exp,
                    "start_mode": start_mode,
                    "sdll_raw": sdll_raw,
                    "sdll_exp": sdll_exp,
                })

        # 1. Scheduled Tasks: UTF-16/UTF-8 XML + TaskCache\Tasks\{GUID}\Actions binary blob + CLSID join
        xml_tasks_by_uri: dict[str, tuple[str, bytes]] = {}
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
                        xml_bytes = fpath.open("rb").read(262144)
                        xml_tasks_by_uri[rel_uri.lower()] = (rel_uri, xml_bytes)
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
            act_blob = tvals.get("Actions")
            has_actions = act_blob is not None
            blob_decoded = decode_taskcache_actions_blob(act_blob if isinstance(act_blob, (bytes, bytearray)) else None)
            has_triggers = "Triggers" in tvals and tvals["Triggers"] is not None
            uri_norm = rel_tree if rel_tree.startswith("\\") else "\\" + rel_tree
            taskcache_by_uri[uri_norm.lower()] = {
                "tree_path": uri_norm,
                "task_guid": tid,
                "has_sd": has_sd,
                "has_actions": has_actions,
                "triggers_present": has_triggers,
                "blob_decoded": blob_decoded,
            }

        all_task_uris = sorted(set(xml_tasks_by_uri.keys()) | set(taskcache_by_uri.keys()))
        staged_tasks: list[dict[str, Any]] = []
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
            blob_dec = tc_entry.get("blob_decoded") if tc_entry is not None else None
            used_blob = False
            if blob_dec:
                if not parsed["exec_actions"] and blob_dec["exec_actions"]:
                    parsed["exec_actions"] = list(blob_dec["exec_actions"])
                    parsed["first_exec"] = blob_dec["first_exec"]
                    used_blob = True
                if not parsed["com_handlers"] and blob_dec["com_handlers"]:
                    parsed["com_handlers"] = list(blob_dec["com_handlers"])
                    used_blob = True
                else:
                    for g in blob_dec["com_handlers"]:
                        if g not in parsed["com_handlers"]:
                            parsed["com_handlers"].append(g)
                            used_blob = True
                if not parsed["command_line"] and blob_dec["command_line"]:
                    parsed["command_line"] = blob_dec["command_line"]
                    used_blob = True

            for cg in parsed["com_handlers"]:
                com_guids_needed.add(cg.lower())

            staged_tasks.append({
                "rel_uri": rel_uri,
                "tdir": tdir,
                "tname": tname,
                "xml_exists": xml_exists,
                "tc_entry": tc_entry,
                "parsed": parsed,
                "used_blob": used_blob,
            })

        # Pre-resolve Task-referenced CLSIDs + HKCU Classes CLSIDs so COM tasks link directly to their DLL/EXE
        hku_key = reg_key_safe("HKU")
        user_sids: list[str] = []
        if hku_key is not None:
            for usk in hku_key.subkeys():
                if not usk.name.lower().endswith("_classes"):
                    user_sids.append(usk.name)

        clsid_roots: list[tuple[str, str, bool]] = [
            (r"HKLM\SOFTWARE\Classes\CLSID", "HKLM", False),
            (r"HKLM\SOFTWARE\Classes\WOW6432Node\CLSID", "HKLM", True),
        ]
        if hku_key is not None:
            for usk in hku_key.subkeys():
                if usk.name.lower().endswith("_classes"):
                    clsid_roots.append((rf"HKU\{usk.name}\CLSID", "HKU", False))
                    clsid_roots.append((rf"HKU\{usk.name}\Wow6432Node\CLSID", "HKU", True))

        clsid_resolved_target: dict[str, str] = {}
        pending_clsid_records: list[dict[str, Any]] = []
        for rpath, chive, is_wow in clsid_roots:
            base_k = reg_key_safe(rpath)
            if base_k is None:
                continue
            target_guids = sorted(com_guids_needed) if chive == "HKLM" else [sk.name.lower() for sk in base_k.subkeys()]
            for guid in target_guids:
                gsub = reg_key_safe(rf"{rpath}\{guid}")
                if gsub is None:
                    continue
                found_srv = False
                for srv_type in ("InprocServer32", "LocalServer32"):
                    sk_srv = reg_subkey_safe(gsub, srv_type)
                    if sk_srv is None:
                        continue
                    s_raw = reg_default_value_str(sk_srv)
                    if not s_raw:
                        continue
                    s_exp = expand_target_like_v1(expand_win_env(s_raw), c_exists_fn=c_path_exists) or expand_win_env(s_raw)
                    if s_exp and s_exp.lower().startswith("c:\\"):
                        clsid_resolved_target.setdefault(guid.lower(), s_exp)
                        referenced_target_paths.add(s_exp)
                    dk = rf"{rpath}\{guid}\{srv_type}"
                    pending_clsid_records.append({
                        "dk": dk,
                        "srv_type": srv_type,
                        "s_raw": s_raw,
                        "s_exp": s_exp,
                        "guid": guid.lower(),
                        "chive": chive,
                        "is_wow": is_wow,
                    })
                    found_srv = True

                # Fallback for COM classes hosted via AppID -> LocalService (Windows Service DCOM handler)
                if not found_srv and guid.lower() not in clsid_resolved_target:
                    try:
                        gvals = {v.name.lower(): str(v.value) for v in gsub.values() if v.value}
                    except Exception:
                        gvals = {}
                    appid = gvals.get("appid")
                    if appid:
                        ak_obj = reg_key_safe(rf"HKLM\SOFTWARE\Classes\AppID\{appid}") or reg_key_safe(
                            rf"HKLM\SOFTWARE\Classes\WOW6432Node\AppID\{appid}"
                        )
                        lsvc_v = reg_val_safe(ak_obj, "LocalService")
                        if lsvc_v is not None and lsvc_v.value:
                            svc_nm = str(lsvc_v.value).strip().lower()
                            svc_bin = service_target_by_name.get(svc_nm)
                            if svc_bin:
                                clsid_resolved_target[guid.lower()] = svc_bin
                                referenced_target_paths.add(svc_bin)
                                dk = rf"{rpath}\{guid}\LocalService"
                                pending_clsid_records.append({
                                    "dk": dk,
                                    "srv_type": "LocalService",
                                    "s_raw": svc_bin,
                                    "s_exp": svc_bin,
                                    "guid": guid.lower(),
                                    "chive": chive,
                                    "is_wow": is_wow,
                                })

        # Emit Scheduled Task records now that CLSID targets are known
        for st_item in staged_tasks:
            rel_uri = st_item["rel_uri"]
            tdir = st_item["tdir"]
            tname = st_item["tname"]
            xml_exists = st_item["xml_exists"]
            tc_entry = st_item["tc_entry"]
            parsed = st_item["parsed"]
            used_blob = st_item["used_blob"]

            target = expand_target_like_v1(parsed["first_exec"], c_exists_fn=c_path_exists, env_map=user_env_map)
            com_clsid = parsed["com_handlers"][0] if parsed["com_handlers"] else None
            com_target = clsid_resolved_target.get(com_clsid.lower()) if com_clsid else None
            # Keep v2_refgraph COM target strictly in extra + referenced_target_paths;
            # keep full_20 path/fmeta identical to v1 Collect-Artifacts.ps1 (None for COM-only tasks).
            if com_target:
                referenced_target_paths.add(com_target)
                inspect_target_file(com_target)
            fmeta = inspect_target_file(target) if target else None

            tc_meta = []
            if tc_entry is not None:
                tc_clean = {k: v for k, v in tc_entry.items() if k != "blob_decoded"}
                tc_meta.append({
                    **tc_clean,
                    "actions_source": (
                        "xml+registry_blob" if (xml_exists and used_blob)
                        else ("xml" if xml_exists else ("registry_blob" if tc_entry["has_actions"] else "missing"))
                    ),
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
                allow_fmeta_path_fallback=False,
                extra={
                    "task_xml_exists": xml_exists,
                    "task_xml_path": rel_uri if xml_exists else None,
                    "task_exec_actions": parsed["exec_actions"],
                    "task_com_handlers": parsed["com_handlers"],
                    "task_com_clsid": com_clsid,
                    "task_com_target_path": com_target,
                    "task_exec_command": parsed["exec_actions"][0]["command_expanded"] if parsed["exec_actions"] else None,
                    "task_exec_arguments": parsed["exec_actions"][0]["arguments_expanded"] if parsed["exec_actions"] else None,
                    "taskcache_entries": tc_meta,
                },
            ))

        # 2. Emit Windows Services records
        for s_item in pending_service_rows:
            fmeta = inspect_target_file(s_item["target"]) if s_item["target"] else None
            reg_key = rf"HKLM\SYSTEM\CurrentControlSet\Services\{s_item['name']}"
            records.append(build_record(
                artifact_type="service",
                path_or_key=reg_key,
                name=s_item["name"],
                path=s_item["target"],
                command_line=s_item["img_exp"],
                registry_key=reg_key,
                service_name=s_item["name"],
                start_mode=s_item["start_mode"],
                fmeta=fmeta,
                extra={
                    "service_image_path_raw": s_item["img_raw"],
                    "service_image_path_expanded": s_item["img_exp"],
                    "service_dll_raw": s_item["sdll_raw"],
                    "service_dll_expanded": s_item["sdll_exp"],
                },
            ))

        # 3. Run / RunOnce + Winlogon / IFEO / Defender / UAC + CLSID COM records
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
        for sid in user_sids:
            for sub in (
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
                r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            ):
                run_specs.append((rf"HKU\{sid}\{sub}", rf"HKU\{sid}\{sub}", "HKU", "64bit"))

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
                    command_line=raw_val,  # matches DoNotExpandEnvironmentNames in v1 (OD-V2-02 ruling)
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

        # UAC bypass, IFEO, Winlogon, Defender Policies & Exclusions
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

        for def_sub in (
            r"SOFTWARE\Policies\Microsoft\Windows Defender",
            r"SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
            r"SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths",
        ):
            def_k = reg_key_safe(rf"HKLM\{def_sub}")
            if def_k is None:
                continue
            dk = rf"HKLM\{def_sub}"
            for v in def_k.values():
                vname = "(Default)" if not v.name else str(v.name)
                vstr = str(v.value if v.value is not None else "")
                records.append(build_record(
                    artifact_type="registry", path_or_key=dk, name=vname,
                    path=None, command_line=None, registry_key=dk, registry_value=vstr,
                    allow_fmeta_path_fallback=False,
                    extra={"reg_hive": "HKLM", "reg_wow64_view": "64bit", "reg_value_raw": vstr, "reg_value_expanded": vstr},
                ))

        for c_rec in pending_clsid_records:
            fmeta = inspect_target_file(c_rec["s_exp"])
            records.append(build_record(
                artifact_type="registry",
                path_or_key=c_rec["dk"],
                name=c_rec["srv_type"],
                path=c_rec["s_exp"],
                command_line=c_rec["s_exp"],
                registry_key=c_rec["dk"],
                registry_value=c_rec["s_exp"],
                fmeta=fmeta,
                extra={
                    "clsid_guid": c_rec["guid"],
                    "clsid_hive": c_rec["chive"],
                    "clsid_wow64": c_rec["is_wow"],
                    "clsid_server_type": c_rec["srv_type"],
                    "clsid_server_raw": c_rec["s_raw"],
                    "clsid_server_expanded": c_rec["s_exp"],
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

        # Materialize referenced PE/script target files (System32/Program Files/etc.) so static refgraph edges close
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

        if build_base_cache and base_cache_path is not None:
            merged_entries = {**cached_file_entries, **new_cache_file_entries}
            save_base_image_cache(
                base_cache_path,
                base_image_sha256=expected_base_sha256,
                catroot_digests=cat_digests,
                file_entries=merged_entries,
            )

        kept_records: list[dict[str, Any]] = []
        dropped_harness: list[dict[str, Any]] = []
        for rec in records:
            drop_reason = is_v2_harness_footprint_record(rec)
            if drop_reason is not None:
                dropped_harness.append({
                    "run_id": rec.get("run_id", run_id),
                    "artifact_type": rec.get("artifact_type"),
                    "artifact_key": rec.get("artifact_key"),
                    "name": rec.get("name"),
                    "path": rec.get("path"),
                    "drop_reason": drop_reason,
                })
            else:
                kept_records.append(rec)
        records = kept_records

        elapsed = round(time.monotonic() - t0, 3)
        df = pd.DataFrame(records)
        summary = summarize_extraction_and_refgraph(df, disk_id=run_id)
        summary.update({
            "extractor_version": EXTRACTOR_VERSION,
            "qcow2_path": str(qcow2_path),
            "elapsed_seconds": elapsed,
            "catroot_digests_loaded": len(cat_digests),
            "wof_compressed_files": int(sum(1 for r in records if r.get("wof_compressed"))),
            "base_cache_used": loaded_cache is not None,
            "base_cache_built": bool(build_base_cache and base_cache_path is not None),
            "base_cache_hits": int(base_cache_hits),
            "base_cache_misses": int(base_cache_misses),
            "v2_harness_footprint_dropped_count": len(dropped_harness),
            "v2_harness_footprint_dropped": dropped_harness,
        })
        return records, summary
    finally:
        close_target_safely(t)


def extract_from_fixture(
    fixture_records: Sequence[Mapping[str, Any]],
    run_id: str = "synthetic_offline",
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Validate and enrich synthetic offline fixture records using identical user-space rules."""
    validated: list[dict[str, Any]] = []
    dropped_harness: list[dict[str, Any]] = []
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
        vrec = validate_extracted_record(rec)
        drop_reason = is_v2_harness_footprint_record(vrec)
        if drop_reason is not None:
            dropped_harness.append({
                "run_id": vrec.get("run_id", run_id),
                "artifact_type": vrec.get("artifact_type"),
                "artifact_key": vrec.get("artifact_key"),
                "name": vrec.get("name"),
                "path": vrec.get("path"),
                "drop_reason": drop_reason,
            })
        else:
            validated.append(vrec)

    df = pd.DataFrame(validated)
    summary = summarize_extraction_and_refgraph(df, disk_id=run_id)
    summary["extractor_version"] = EXTRACTOR_VERSION
    summary["v2_harness_footprint_dropped_count"] = len(dropped_harness)
    summary["v2_harness_footprint_dropped"] = dropped_harness
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
    dropped_rows = list(summary.get("v2_harness_footprint_dropped") or [])
    dropped_csv = out_dir / "v2_runner_footprint_dropped.csv"
    pd.DataFrame(
        dropped_rows,
        columns=["run_id", "artifact_type", "artifact_key", "name", "path", "drop_reason"],
    ).to_csv(dropped_csv, index=False)
    return {"jsonl": jsonl_path, "parquet": pq_path, "manifest": man_path, "dropped_csv": dropped_csv}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Pure user-space offline QCOW2 artifact extractor (Step F).")
    parser.add_argument("--qcow2", type=Path, required=True, help="Closed QCOW2 image path (opened read-only)")
    parser.add_argument("--out-dir", type=Path, required=True, help="Output directory for JSONL/Parquet/manifest")
    parser.add_argument("--run-id", default="offline_run")
    parser.add_argument("--max-scanned-files", type=int, default=1500)
    parser.add_argument("--skip-catroot", action="store_true")
    parser.add_argument("--base-cache-path", type=Path, default=None, help="Path to immutable base-image digest/signature cache")
    parser.add_argument("--build-base-cache", action="store_true", help="Build and write base-image cache to --base-cache-path")
    parser.add_argument("--expected-base-sha256", default=GOLDEN_BASE_IMAGE_SHA256)
    args = parser.parse_args(list(argv) if argv is not None else None)

    records, summary = extract_from_qcow2(
        args.qcow2,
        run_id=args.run_id,
        max_scanned_files=args.max_scanned_files,
        resolve_catroot=not args.skip_catroot,
        base_cache_path=args.base_cache_path,
        build_base_cache=args.build_base_cache,
        expected_base_sha256=args.expected_base_sha256,
    )
    paths = write_outputs(records, summary, args.out_dir)
    print(json.dumps({"summary": summary, "outputs": {k: str(v) for k, v in paths.items()}}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
