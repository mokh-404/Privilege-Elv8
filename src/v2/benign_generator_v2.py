"""Real procedural v2 benign workload generator with disjoint `dev` / `blind_test` host profiles (`IMP-06`, `OD-V2-12`).

Generates per-run PowerShell workloads (`benign_workload.ps1`), real pool asset slices from
`/var/lib/dfir-quarantine-vault/benign_pools/<split_pool>/`, procedurally varied non-template scripts
using strictly collected extractor extensions, real pool high-entropy benign installers (`.exe`/`.msi`),
and realistic Windows benign persistence (`service`, `task`, `run_key`, `registry`) — guaranteeing zero
`dev`/`blind_test` overlap, 100% extractor path/extension coverage, and zero template quantization.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import random
import struct
from typing import Any, Mapping, Sequence

import numpy as np

from src.data.features import file_head_entropy
from src.v2.offline_extractor import _SKIP_DIR_FRAGS, _USER_SCAN_TARGET_EXTS


MIB = 1 << 20
DEFAULT_BENIGN_POOLS_ROOT = Path("/var/lib/dfir-quarantine-vault/benign_pools")

# Avoid risky benign extensions (.hta/.scr) while staying strictly inside _USER_SCAN_TARGET_EXTS.
BENIGN_AVOIDED_EXTS: frozenset[str] = frozenset({".hta", ".scr"})
BENIGN_SAFE_COLLECTED_EXTS: frozenset[str] = frozenset(_USER_SCAN_TARGET_EXTS) - BENIGN_AVOIDED_EXTS
BENIGN_SCRIPT_EXTS: tuple[str, ...] = ("ps1", "psm1", "bat", "cmd", "vbs", "vbe", "js")
BENIGN_INSTALLER_EXTS: frozenset[str] = frozenset({".exe", ".msi"})
HIGH_ENTROPY_INSTALLER_THRESHOLD = 6.5

# Mirror walk_fs(root, max_depth) from src/v2/offline_extractor.py verbatim (lines 2134-2150).
EXTRACTOR_STATIC_SCAN_ROOTS: tuple[tuple[tuple[str, ...], int], ...] = (
    (("windows", "temp"), 4),
    (("users", "public"), 5),
    (("programdata",), 4),
)
EXTRACTOR_USER_SCAN_SUBROOTS: tuple[tuple[tuple[str, ...], int], ...] = (
    (("appdata", "local", "temp"), 4),
    (("appdata", "roaming"), 4),
    (("appdata", "local"), 3),
)

_INSTALLER_ENTROPY_CACHE: dict[tuple[str, int, int], float] = {}


class RealBenignPoolRequiredError(RuntimeError):
    """Raised when `require_real_pools=True` and the benign pool lacks required real PE/installer assets."""


def path_matches_extractor_scan_roots(win_path: str) -> bool:
    """Return True iff `win_path` is walked by `offline_extractor.py` scan_roots within depth & skip rules."""
    p = str(win_path or "").strip().replace("/", "\\")
    pl = p.lower()
    if not pl.startswith("c:\\"):
        return False
    parts = [seg for seg in p[3:].split("\\") if seg]
    if len(parts) < 2:
        return False
    dir_parts = tuple(seg.lower() for seg in parts[:-1])
    dir_str_norm = "c:\\" + "\\".join(dir_parts) + "\\"
    if any(frag in dir_str_norm for frag in _SKIP_DIR_FRAGS):
        return False

    roots: list[tuple[tuple[str, ...], int]] = list(EXTRACTOR_STATIC_SCAN_ROOTS)
    if len(dir_parts) >= 2 and dir_parts[0] == "users":
        user_seg = dir_parts[1]
        for sub_parts, depth_lim in EXTRACTOR_USER_SCAN_SUBROOTS:
            roots.append((("users", user_seg) + sub_parts, depth_lim))

    for root_parts, max_depth in roots:
        if dir_parts[: len(root_parts)] == root_parts:
            rel_depth = len(dir_parts) - len(root_parts)
            if 0 <= rel_depth <= max_depth:
                return True
    return False


def path_passes_extractor_file_predicate(win_path: str) -> bool:
    """Return True iff `win_path` matches BOTH `_USER_SCAN_TARGET_EXTS` and real `scan_roots`/depth rules."""
    ext = Path(str(win_path or "").replace("\\", "/")).suffix.lower()
    return (ext in _USER_SCAN_TARGET_EXTS) and path_matches_extractor_scan_roots(win_path)

WORKLOAD_PROFILES: dict[str, dict[str, Any]] = {
    "dev": {
        "profile_ids": [f"B_dev_{i:02d}" for i in range(1, 21)],
        "users": ["alice_dev", "bob_eng", "ci_runner", "dev_build", "qa_tester"],
        "software": ["Git", "Python312", "CurlCLI", "CMakeBuild", "SysinternalsDev"],
        "base_dirs": [
            r"C:\ProgramData\DevOpsTools",
            r"C:\ProgramData\BuildCache",
            r"C:\Users\Public\DevWorkspace\Tools",
            r"C:\Users\Public\DevWorkspace\Scripts",
            r"C:\Windows\Temp\DevPkgLogs",
        ],
        "svc_prefixes": ["DevBuildCache", "DevTelemetry", "DevGitGc", "DevPyEnvSync", "DevLogRotator"],
        "task_folder": r"\DevOpsTasks",
        "task_prefixes": ["RepoSync", "WheelCleanup", "BuildTrim", "PipCache", "LintCheck"],
        "run_prefixes": ["DevTray", "GitCredHelper", "PyEnvLauncher", "BuildNotifier", "CiAgentTray"],
        "ifeo_targets": ["dev_probe_a.exe", "dev_probe_b.exe", "dev_lint_cli.exe", "dev_test_runner.exe"],
        "triggers": ["ONLOGON", "DAILY", "ONSTART", "ONCE"],
        "trigger_classes": [
            "MSFT_TaskLogonTrigger",
            "MSFT_TaskDailyTrigger",
            "MSFT_TaskBootTrigger",
            "MSFT_TaskTimeTrigger",
        ],
    },
    "blind_test": {
        "profile_ids": [f"B_test_{i:02d}" for i in range(1, 11)],
        "users": ["claire_ops", "david_sec", "analyst01", "ops_auditor", "ir_lead"],
        "software": ["NotepadPlus", "SevenZipCLI", "SystemInformer", "VlcPortable", "SysinternalsOps"],
        "base_dirs": [
            r"C:\ProgramData\OpsAutomation",
            r"C:\ProgramData\EndpointHealth",
            r"C:\Users\Public\OpsWorkspace\Utilities",
            r"C:\Users\Public\OpsWorkspace\Scripts",
            r"C:\Windows\Temp\OpsAuditWork",
        ],
        "svc_prefixes": ["OpsAssetAgent", "OpsConfigWatch", "OpsPatchVerify", "OpsArchiveIdx", "OpsQuotaMon"],
        "task_folder": r"\EndpointOps",
        "task_prefixes": ["EndpointSnap", "ConfigAudit", "ArchiveSweep", "HealthCheck", "QuotaSync"],
        "run_prefixes": ["OpsTray", "NoteSession", "ArchiveQuick", "HelpDeskMon", "EndpointBar"],
        "ifeo_targets": ["ops_audit_a.exe", "ops_audit_b.exe", "ops_snap_cli.exe", "ops_health_mon.exe"],
        "triggers": ["ONLOGON", "DAILY", "ONCE", "ONIDLE"],
        "trigger_classes": [
            "MSFT_TaskLogonTrigger",
            "MSFT_TaskDailyTrigger",
            "MSFT_TaskTimeTrigger",
            "MSFT_TaskIdleTrigger",
        ],
    },
}


def _bytes_head_hist(data: bytes | bytearray) -> list[int]:
    arr = np.frombuffer(data[:MIB], dtype=np.uint8)
    return np.bincount(arr, minlength=256).astype(int).tolist()


def _deterministic_seed(split_pool: str, profile_id: str, run_id: str, run_seed: int | None) -> int:
    raw = f"{split_pool}|{profile_id}|{run_id}|{run_seed or 0}".encode("utf-8")
    return int.from_bytes(hashlib.sha256(raw).digest()[:8], "big")


def _synth_varied_script(rng: random.Random, ext: str, tag: str, user: str) -> bytes:
    """Synthesize procedurally varied non-quantized script text across multiple extensions."""
    ext = ext.lower().lstrip(".")
    n_blocks = rng.randint(2, 12)
    n_notes = rng.randint(3, 28)
    pad_len = rng.randint(120, 4800)
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-=/:.;,"

    lines: list[str] = []
    if ext in ("ps1", "psm1"):
        lines.extend([
            f"# Host admin routine {tag} operator={user}",
            "$ErrorActionPreference = 'SilentlyContinue'",
            f"$runTag = '{tag}_{rng.randint(1000, 999999)}'",
        ])
        stmts = [
            "Get-ChildItem -Path $env:TEMP -File | Select-Object -First 5 Name,Length | Out-Null",
            "Get-Service | Where-Object Status -eq 'Running' | Select-Object -First 6 Name | Out-Null",
            "[System.Environment]::ProcessorCount | Out-Null",
            "Get-Process | Select-Object -First 5 ProcessName,Id | Out-Null",
        ]
        for b in range(n_blocks):
            lines.append(f"function Invoke-BenignTask{b}_{rng.randint(100,9999)} {{")
            for _ in range(rng.randint(1, 5)):
                lines.append("    " + rng.choice(stmts))
            lines.append("}")
        if ext == "psm1":
            lines.append("Export-ModuleMember -Function Invoke-BenignTask*")
        comment_prefix = "# "
    elif ext in ("bat", "cmd"):
        lines.extend([
            "@echo off",
            f"REM Maintenance wrapper {tag} owner={user}",
            f"set BENIGN_TAG={tag}_{rng.randint(10, 9999)}",
        ])
        for b in range(n_blocks):
            lines.append(f"echo step_{b}_%BENIGN_TAG% > nul")
        comment_prefix = "REM "
    elif ext in ("vbs", "vbe"):
        lines.extend([
            f"' Host inventory helper {tag} owner={user}",
            f"Dim tagVal : tagVal = \"{tag}_{rng.randint(10, 9999)}\"",
        ])
        for b in range(n_blocks):
            lines.append(f"Dim v{b} : v{b} = Len(tagVal) + {rng.randint(1, 200)}")
        comment_prefix = "' "
    elif ext == "js":
        lines.extend([
            f"// Endpoint telemetry helper {tag} owner={user}",
            f"var runTag = \"{tag}_{rng.randint(10, 9999)}\";",
        ])
        for b in range(n_blocks):
            lines.append(f"function chk_{b}() {{ return runTag.length + {rng.randint(1, 99)}; }}")
        comment_prefix = "// "
    else:
        raise ValueError(
            f"Unsupported benign script extension {ext!r}; must be in {BENIGN_SCRIPT_EXTS}"
        )

    # Add non-uniform variable comment payload so lengths and byte distributions vary smoothly
    pos = 0
    while pos < pad_len or len(lines) < n_notes + 4:
        chunk_sz = rng.randint(24, 110)
        frag = "".join(rng.choices(alphabet, k=chunk_sz))
        lines.append(f"{comment_prefix}meta_{pos}_{rng.randint(10,99)}: {frag}")
        pos += chunk_sz

    return ("\r\n".join(lines) + "\r\n").encode("utf-8")


def _synth_unsigned_pe_bytes(
    seed: int,
    size_bytes: int,
    is_dll: bool = False,
    high_entropy: bool = False,
) -> bytes:
    """Synthesize a valid-header unsigned PE32+ executable/DLL byte buffer (fallback when pool empty)."""
    size_bytes = max(16384, int(size_bytes))
    np_rng = np.random.default_rng(seed)
    buf = bytearray(size_bytes)
    # DOS header
    buf[0:2] = b"MZ"
    pe_off = 0x80
    struct.pack_into("<I", buf, 0x3C, pe_off)
    # PE\0\0 + COFF FileHeader (AMD64, 1 section)
    buf[pe_off : pe_off + 4] = b"PE\x00\x00"
    chars = 0x2022 if is_dll else 0x0022  # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE (| DLL)
    struct.pack_into("<HHIIIHH", buf, pe_off + 4, 0x8664, 1, 0x67000000, 0, 0, 0xF0, chars)
    # OptionalHeader64 magic = 0x20B
    opt_off = pe_off + 24
    struct.pack_into("<H", buf, opt_off, 0x20B)
    struct.pack_into("<I", buf, opt_off + 16, 0x1000)  # AddressOfEntryPoint
    struct.pack_into("<Q", buf, opt_off + 24, 0x140000000)  # ImageBase
    struct.pack_into("<II", buf, opt_off + 32, 0x1000, 0x200)
    struct.pack_into("<I", buf, opt_off + 56, ((size_bytes + 0xFFF) // 0x1000) * 0x1000)
    struct.pack_into("<I", buf, opt_off + 60, 0x400)  # SizeOfHeaders
    struct.pack_into("<H", buf, opt_off + 68, 3)  # IMAGE_SUBSYSTEM_WINDOWS_CUI
    # Section .text at opt_off + 0xF0
    sec_off = opt_off + 0xF0
    buf[sec_off : sec_off + 8] = b".text\x00\x00\x00"
    raw_sz = size_bytes - 0x400
    struct.pack_into("<IIII", buf, sec_off + 8, raw_sz, 0x1000, raw_sz, 0x400)
    struct.pack_into("<I", buf, sec_off + 36, 0x60000020)

    ascii_pools = (
        np.frombuffer(
            b"kernel32.dll\x00advapi32.dll\x00GetSystemTimeAsFileTime\x00RegQueryValueExW\x00BenignCliTool\x00",
            dtype=np.uint8,
        ),
        np.frombuffer(
            b"ucrtbase.dll\x00vcruntime140.dll\x00malloc\x00free\x00memcpy\x00fprintf\x00Usage:\x00--version\x00",
            dtype=np.uint8,
        ),
        np.frombuffer(
            b"PADDING_RES_BLOCK_00\x00\x00\x00\x00CONFIG_SCHEMA_V2\x00\x00\x00\x00DEFAULT_LOCALE_EN_US\x00\x00\x00\x00",
            dtype=np.uint8,
        ),
    )
    ascii_pool = ascii_pools[int(np_rng.integers(0, len(ascii_pools)))]
    if high_entropy:
        # Packed/compressed benign installer fallback: varied high-entropy section (~6.8-7.75 bits/byte)
        frac_code = float(np_rng.uniform(0.70, 0.86))
        frac_str = float(np_rng.uniform(0.04, min(0.16, 0.99 - frac_code)))
        n_code = int(raw_sz * frac_code)
        n_str = int(raw_sz * frac_str)
        n_pad = raw_sz - n_code - n_str
        body = (
            np_rng.integers(0, 256, size=n_code, dtype=np.uint8).tobytes()
            + np_rng.choice(ascii_pool, size=n_str, replace=True).tobytes()
            + b"\x00" * n_pad
        )
    else:
        # Realistic diverse PE regimes spanning ~4.2..7.75 bits/byte (low resource/padded, native, dense packed)
        regime = int(seed % 3) if int(np_rng.random() < 0.75) else int(np_rng.integers(0, 3))
        if regime == 0:
            # Low-entropy padded / resource-heavy PE (~4.2..5.4 bits/byte)
            frac_code = float(np_rng.uniform(0.24, 0.34))
            frac_str = float(np_rng.uniform(0.26, 0.38))
        elif regime == 1:
            # Medium-entropy native .text/.rdata PE (~5.4..6.7 bits/byte)
            frac_code = float(np_rng.uniform(0.36, 0.56))
            frac_str = float(np_rng.uniform(0.18, 0.36))
        else:
            # High-entropy packed / compressed-resource PE (~6.6..7.75 bits/byte)
            frac_code = float(np_rng.uniform(0.64, 0.84))
            frac_str = float(np_rng.uniform(0.06, min(0.16, 0.99 - frac_code)))
        n_code = int(raw_sz * frac_code)
        n_str = int(raw_sz * frac_str)
        n_pad = raw_sz - n_code - n_str
        pad_byte = bytes([int(np_rng.choice([0x00, 0xCC, 0x90]))])
        body = (
            np_rng.integers(0, 256, size=n_code, dtype=np.uint8).tobytes()
            + np_rng.choice(ascii_pool, size=n_str, replace=True).tobytes()
            + (pad_byte * n_pad)
        )
    buf[0x400:] = body
    return bytes(buf)


def _cached_file_head_entropy(path: Path) -> float:
    st = path.stat()
    ckey = (str(path), int(st.st_size), int(st.st_mtime_ns))
    ent = _INSTALLER_ENTROPY_CACHE.get(ckey)
    if ent is None:
        raw = path.read_bytes()
        ent = float(file_head_entropy(raw)) if raw else 0.0
        _INSTALLER_ENTROPY_CACHE[ckey] = ent
    return ent


def _load_pool_asset_candidates(benign_pools_root: Path | None, split_pool: str) -> list[Path]:
    """Return ONLY pool assets whose suffix lies in `BENIGN_SAFE_COLLECTED_EXTS`."""
    if benign_pools_root is None:
        return []
    sdir = Path(benign_pools_root) / split_pool
    if not sdir.is_dir():
        return []
    return sorted(
        p
        for p in sdir.rglob("*")
        if p.is_file() and not p.is_symlink() and p.suffix.lower() in BENIGN_SAFE_COLLECTED_EXTS
    )


def _select_high_entropy_installer_candidates(pool_files: Sequence[Path]) -> list[Path]:
    """Return real pool `.exe`/`.msi` installer assets, prioritizing `.msi` and high-entropy `.exe`."""
    msis: list[Path] = []
    high_exes: list[Path] = []
    other_exes: list[Path] = []
    for p in pool_files:
        ext = p.suffix.lower()
        if ext not in BENIGN_INSTALLER_EXTS:
            continue
        if ext == ".msi":
            msis.append(p)
        else:
            ent = _cached_file_head_entropy(p)
            if ent >= HIGH_ENTROPY_INSTALLER_THRESHOLD:
                high_exes.append(p)
            else:
                other_exes.append(p)
    prioritized = msis + high_exes
    return prioritized if prioritized else other_exes


def generate_benign_workload_bundle(
    run_id: str,
    split_pool: str = "dev",
    benign_profile_id: str | None = None,
    run_seed: int | None = None,
    benign_pools_root: str | Path | None = None,
    n_scripts: int = 5,
    n_archives: int = 3,
    n_pool_assets: int = 3,
    create_persistence: bool = True,
    require_real_pools: bool = False,
) -> dict[str, Any]:
    """Generate a non-quantized per-run PowerShell benign workload, ISO assets, and benign attribution manifest."""
    sp = str(split_pool).strip().lower()
    if sp not in WORKLOAD_PROFILES:
        raise ValueError(f"split_pool must be 'dev' or 'blind_test', got {split_pool!r}")
    prof = WORKLOAD_PROFILES[sp]
    prof_id = benign_profile_id or prof["profile_ids"][0]
    seed = _deterministic_seed(sp, prof_id, run_id, run_seed)
    rng = random.Random(seed)

    user = prof["users"][seed % len(prof["users"])]
    base_dir = prof["base_dirs"][(seed >> 4) % len(prof["base_dirs"])]
    sw = prof["software"][(seed >> 8) % len(prof["software"])]
    safe_run = "".join(ch if ch.isalnum() or ch == "_" else "_" for ch in run_id)

    extra_iso_files: dict[str, bytes] = {}
    staged_files: list[dict[str, Any]] = []
    synthetic_fallback_counts: dict[str, int] = {"unsigned_pe": 0, "high_entropy_pe": 0}
    ps_lines: list[str] = [
        f"# Procedural v2 Benign Workload ({sp} / {prof_id} / {run_id})",
        f'param([string]$ProfileId = "{prof_id}")',
        '$ErrorActionPreference = "SilentlyContinue"',
        '$vol = Get-Volume | Where-Object { $_.FileSystemLabel -eq "DFIR_STAGE" -and $_.DriveLetter } | Select-Object -First 1',
        '$stageRoot = if ($vol) { "$($vol.DriveLetter):\\" } else { $PSScriptRoot }',
    ]

    # 1. Stage real pool assets from benign_pools/<split_pool>/ OR synthesize realistic unsigned PEs
    pool_root_path = Path(benign_pools_root) if benign_pools_root is not None else DEFAULT_BENIGN_POOLS_ROOT
    pool_files = _load_pool_asset_candidates(pool_root_path, sp)
    staged_exe_for_pers: str | None = None
    picked_section1: set[Path] = set()

    if pool_files:
        # Rotate cleanly across the pool using deterministic offset + stride
        stride = max(1, len(pool_files) // max(1, n_pool_assets))
        start_idx = seed % len(pool_files)
        picked: list[Path] = []
        for idx in range(min(n_pool_assets, len(pool_files))):
            cand = pool_files[(start_idx + idx * stride) % len(pool_files)]
            picked.append(cand)
            picked_section1.add(cand)
        for idx, pfile in enumerate(picked):
            raw_bytes = pfile.read_bytes()
            iso_rel = f"benign_assets/{sp}_{idx:02d}_{pfile.name}"
            extra_iso_files[iso_rel] = raw_bytes
            dst_dir = f"C:\\Users\\{user}\\AppData\\Local\\{sw}\\bin" if idx % 2 == 0 else base_dir
            dst_name = f"{sp}_{safe_run}_{idx:02d}_{pfile.name}"
            dst_path = f"{dst_dir}\\{dst_name}"
            if dst_name.lower().endswith(".exe") and staged_exe_for_pers is None:
                staged_exe_for_pers = dst_path
            sha = hashlib.sha256(raw_bytes).hexdigest().lower()
            sig_stat = "NotSigned"
            if pfile.suffix.lower() in (".exe", ".dll", ".msi", ".ps1", ".psm1", ".vbs", ".vbe", ".js"):
                try:
                    from src.v2.offline_extractor import verify_offline_signature
                    sig_stat = verify_offline_signature(str(pfile), raw_bytes, len(raw_bytes))
                except Exception:
                    sig_stat = "NotSigned"
            staged_files.append({
                "path": dst_path,
                "name": dst_name,
                "sha256": sha,
                "file_size": len(raw_bytes),
                "source": "benign_pool",
                "is_pe": pfile.suffix.lower() in (".exe", ".dll"),
                "signature_status": sig_stat,
            })
            ps_lines.extend([
                f'if (-not (Test-Path -LiteralPath "{dst_dir}")) {{ New-Item -ItemType Directory -Path "{dst_dir}" -Force | Out-Null }}',
                f'$srcAsset{idx} = Join-Path $stageRoot "{iso_rel.replace("/", "\\")}"',
                f'if (Test-Path -LiteralPath $srcAsset{idx}) {{ Copy-Item -LiteralPath $srcAsset{idx} -Destination "{dst_path}" -Force }}',
            ])
    else:
        if require_real_pools:
            raise RealBenignPoolRequiredError(
                f"Real benign pool required (`require_real_pools=True`), but no eligible collected assets "
                f"found for split_pool={sp!r} under {pool_root_path / sp}"
            )
        # Realistic unsigned benign developer CLI PEs (1 .exe + 1 .dll) when external pool is empty
        for pe_idx, is_dll in enumerate((False, True)):
            ext = "dll" if is_dll else "exe"
            pe_name = f"{sp}_{sw.lower()}_tool_{safe_run}_{pe_idx}_{rng.randint(100,999)}.{ext}"
            dst_dir = f"C:\\Users\\{user}\\AppData\\Local\\{sw}\\bin" if pe_idx == 0 else base_dir
            dst_path = f"{dst_dir}\\{pe_name}"
            pe_sz = rng.randint(48_000, 760_000) + pe_idx * 1319 + (seed % 4096)
            pe_bytes = _synth_unsigned_pe_bytes(seed + 101 + pe_idx, pe_sz, is_dll=is_dll)
            synthetic_fallback_counts["unsigned_pe"] += 1
            iso_rel = f"benign_assets/{pe_name}"
            extra_iso_files[iso_rel] = pe_bytes
            if not is_dll and staged_exe_for_pers is None:
                staged_exe_for_pers = dst_path
            staged_files.append({
                "path": dst_path,
                "name": pe_name,
                "sha256": hashlib.sha256(pe_bytes).hexdigest().lower(),
                "file_size": len(pe_bytes),
                "source": "synthetic_unsigned_pe",
                "is_pe": True,
                "signature_status": "NotSigned",
                "raw_bytes_preview": pe_bytes,
            })
            ps_lines.extend([
                f'if (-not (Test-Path -LiteralPath "{dst_dir}")) {{ New-Item -ItemType Directory -Path "{dst_dir}" -Force | Out-Null }}',
                f'$srcPe{pe_idx} = Join-Path $stageRoot "{iso_rel.replace("/", "\\")}"',
                f'if (Test-Path -LiteralPath $srcPe{pe_idx}) {{ Copy-Item -LiteralPath $srcPe{pe_idx} -Destination "{dst_path}" -Force }}',
            ])

    # 2. Procedurally varied non-template scripts (strictly inside collected safe extensions; zero .py)
    script_exts = BENIGN_SCRIPT_EXTS
    staged_script_for_task: str | None = None
    for s_idx in range(n_scripts):
        sext = script_exts[(seed + s_idx) % len(script_exts)]
        sname = f"{sp}_{sw.lower()}_{safe_run}_{s_idx}_{rng.randint(100,9999)}.{sext}"
        dst_dir = prof["base_dirs"][(seed + s_idx) % len(prof["base_dirs"])]
        dst_path = f"{dst_dir}\\{sname}"
        s_bytes = _synth_varied_script(rng, sext, f"{sp}_{safe_run}_{s_idx}", user)
        iso_rel = f"benign_assets/{sname}"
        extra_iso_files[iso_rel] = s_bytes
        if sext in ("ps1", "bat", "cmd") and staged_script_for_task is None:
            staged_script_for_task = dst_path
        staged_files.append({
            "path": dst_path,
            "name": sname,
            "sha256": hashlib.sha256(s_bytes).hexdigest().lower(),
            "file_size": len(s_bytes),
            "source": "procedural_script",
            "is_pe": False,
            "signature_status": "NotSigned" if sext in ("ps1", "psm1", "vbs", "vbe", "js") else "UnknownError",
            "raw_bytes_preview": s_bytes,
        })
        ps_lines.extend([
            f'if (-not (Test-Path -LiteralPath "{dst_dir}")) {{ New-Item -ItemType Directory -Path "{dst_dir}" -Force | Out-Null }}',
            f'$srcScr{s_idx} = Join-Path $stageRoot "{iso_rel.replace("/", "\\")}"',
            f'if (Test-Path -LiteralPath $srcScr{s_idx}) {{ Copy-Item -LiteralPath $srcScr{s_idx} -Destination "{dst_path}" -Force }}',
        ])

    # 3. High-entropy benign installers drawn from real pool `.exe`/`.msi` assets (fallback: high-entropy PE .exe)
    n_installers = int(n_archives)
    all_installer_cands = _select_high_entropy_installer_candidates(pool_files)
    unused_installer_cands = [p for p in all_installer_cands if p not in picked_section1]
    installer_pool = unused_installer_cands if unused_installer_cands else all_installer_cands

    if installer_pool and n_installers > 0:
        stride_i = max(1, len(installer_pool) // max(1, n_installers))
        start_i = (seed >> 3) % len(installer_pool)
        for a_idx in range(n_installers):
            pfile = installer_pool[(start_i + a_idx * stride_i) % len(installer_pool)]
            d_bytes = pfile.read_bytes()
            dname = f"{sp}_inst_{safe_run}_{a_idx}_{pfile.name}"
            dst_dir = f"C:\\Users\\{user}\\AppData\\Roaming\\{sw}\\cache"
            dst_path = f"{dst_dir}\\{dname}"
            iso_rel = f"benign_assets/{sp}_inst_{a_idx:02d}_{pfile.name}"
            extra_iso_files[iso_rel] = d_bytes
            sig_stat = "NotSigned"
            try:
                from src.v2.offline_extractor import verify_offline_signature
                sig_stat = verify_offline_signature(str(pfile), d_bytes, len(d_bytes))
            except Exception:
                sig_stat = "NotSigned"
            staged_files.append({
                "path": dst_path,
                "name": dname,
                "sha256": hashlib.sha256(d_bytes).hexdigest().lower(),
                "file_size": len(d_bytes),
                "source": "benign_pool_installer",
                "is_pe": pfile.suffix.lower() == ".exe",
                "signature_status": sig_stat,
            })
            ps_lines.extend([
                f'if (-not (Test-Path -LiteralPath "{dst_dir}")) {{ New-Item -ItemType Directory -Path "{dst_dir}" -Force | Out-Null }}',
                f'$srcDat{a_idx} = Join-Path $stageRoot "{iso_rel.replace("/", "\\")}"',
                f'if (Test-Path -LiteralPath $srcDat{a_idx}) {{ Copy-Item -LiteralPath $srcDat{a_idx} -Destination "{dst_path}" -Force }}',
            ])
    elif n_installers > 0:
        if require_real_pools:
            raise RealBenignPoolRequiredError(
                f"Real benign pool required (`require_real_pools=True`), but no real `.exe`/`.msi` "
                f"installer assets found for split_pool={sp!r} under {pool_root_path / sp}"
            )
        for a_idx in range(n_installers):
            dname = f"{sp}_inst_{safe_run}_{a_idx}_{rng.randint(100,9999)}.exe"
            dst_dir = f"C:\\Users\\{user}\\AppData\\Roaming\\{sw}\\cache"
            dst_path = f"{dst_dir}\\{dname}"
            pe_sz = rng.randint(64_000, 640_000) + a_idx * 1777 + ((seed >> 5) % 4096)
            d_bytes = _synth_unsigned_pe_bytes(
                seed + 501 + a_idx,
                pe_sz,
                is_dll=False,
                high_entropy=True,
            )
            synthetic_fallback_counts["high_entropy_pe"] += 1
            iso_rel = f"benign_assets/{dname}"
            extra_iso_files[iso_rel] = d_bytes
            staged_files.append({
                "path": dst_path,
                "name": dname,
                "sha256": hashlib.sha256(d_bytes).hexdigest().lower(),
                "file_size": len(d_bytes),
                "source": "synthetic_high_entropy_pe",
                "is_pe": True,
                "signature_status": "NotSigned",
                "raw_bytes_preview": d_bytes,
            })
            ps_lines.extend([
                f'if (-not (Test-Path -LiteralPath "{dst_dir}")) {{ New-Item -ItemType Directory -Path "{dst_dir}" -Force | Out-Null }}',
                f'$srcDat{a_idx} = Join-Path $stageRoot "{iso_rel.replace("/", "\\")}"',
                f'if (Test-Path -LiteralPath $srcDat{a_idx}) {{ Copy-Item -LiteralPath $srcDat{a_idx} -Destination "{dst_path}" -Force }}',
            ])

    # Hard invariant: 100% of emitted file paths pass the real offline_extractor predicates and avoid .hta/.scr
    for rec in staged_files:
        rec_path = str(rec["path"])
        rec_ext = Path(rec_path.replace("\\", "/")).suffix.lower()
        if rec_ext in BENIGN_AVOIDED_EXTS or not path_passes_extractor_file_predicate(rec_path):
            raise AssertionError(
                f"Generated benign path failed real extractor predicate: {rec_path!r}"
            )

    # 4. Realistic benign persistence entries (Service, varied-trigger Task, Run/RunOnce, IFEO Registry)
    services_manifest: list[dict[str, Any]] = []
    tasks_manifest: list[dict[str, Any]] = []
    run_keys_manifest: list[dict[str, Any]] = []
    reg_manifest: list[dict[str, Any]] = []

    if create_persistence:
        svc_prefix = prof["svc_prefixes"][seed % len(prof["svc_prefixes"])]
        svc_name = f"{svc_prefix}_{safe_run}"[:48]
        svc_start_flag = "auto" if (seed % 3 == 0) else "demand"
        svc_bin = staged_exe_for_pers or r"C:\Windows\System32\svchost.exe"
        svc_cmd = f'"{svc_bin}" -k {svc_prefix}Grp' if "svchost.exe" in svc_bin.lower() else f'"{svc_bin}" --service'
        services_manifest.append({
            "service_name": svc_name,
            "registry_key": rf"HKLM\SYSTEM\CurrentControlSet\Services\{svc_name}",
            "path": svc_bin,
            "command_line": svc_cmd,
            "start_mode": "Auto" if svc_start_flag == "auto" else "Manual",
        })
        ps_lines.append(f'& sc.exe create "{svc_name}" binPath= "{svc_cmd}" start= {svc_start_flag} | Out-Null')

        t_prefix = prof["task_prefixes"][(seed >> 3) % len(prof["task_prefixes"])]
        t_folder = prof["task_folder"]
        t_name = f"{t_prefix}_{safe_run}"
        t_full = f"{t_folder}\\{t_name}"
        t_trig_idx = seed % len(prof["triggers"])
        t_trig = prof["triggers"][t_trig_idx]
        t_trig_cls = prof["trigger_classes"][t_trig_idx]
        t_target = staged_script_for_task or staged_exe_for_pers or (
            staged_files[0]["path"] if staged_files else r"C:\Windows\System32\cmd.exe"
        )
        t_target_low = str(t_target).lower()
        if t_target_low.endswith(".ps1"):
            t_action = f'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "{t_target}"'
            t_exe = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
        elif t_target_low.endswith((".bat", ".cmd")):
            t_action = f'cmd.exe /c "{t_target}"'
            t_exe = r"C:\Windows\System32\cmd.exe"
        else:
            t_action = f'cmd.exe /c echo {t_name}'
            t_exe = r"C:\Windows\System32\cmd.exe"
        tasks_manifest.append({
            "task_name": t_full,
            "name": t_name,
            "task_triggers": t_trig_cls,
            "command_line": t_action,
            "path": t_exe,
        })
        if t_trig == "DAILY":
            ps_lines.append(
                f'& schtasks.exe /Create /TN "{t_full}" /TR "{t_action}" /SC DAILY /ST 03:15 /F | Out-Null'
            )
        elif t_trig == "ONCE":
            ps_lines.append(
                f'& schtasks.exe /Create /TN "{t_full}" /TR "{t_action}" /SC ONCE /ST 23:50 /F | Out-Null'
            )
        elif t_trig == "ONIDLE":
            ps_lines.append(
                f'& schtasks.exe /Create /TN "{t_full}" /TR "{t_action}" /SC ONIDLE /I 15 /F | Out-Null'
            )
        else:
            ps_lines.append(
                f'& schtasks.exe /Create /TN "{t_full}" /TR "{t_action}" /SC {t_trig} /F | Out-Null'
            )

        r_prefix = prof["run_prefixes"][(seed >> 5) % len(prof["run_prefixes"])]
        r_name = f"{r_prefix}_{safe_run}"[:48]
        is_runonce = (seed % 4 == 0)
        rk_path = (
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
            if is_runonce
            else r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
        )
        rk_target = staged_exe_for_pers or r"C:\Windows\System32\notepad.exe"
        rk_val = f'"{rk_target}" --tray'
        run_keys_manifest.append({
            "name": r_name,
            "registry_key": rk_path,
            "registry_value": rk_val,
            "path": rk_target,
        })
        ps_lines.append(f'& reg.exe ADD "{rk_path}" /v "{r_name}" /t REG_SZ /d "{rk_val}" /f | Out-Null')

        ifeo_exe = f"{sp}_{safe_run}_{prof['ifeo_targets'][seed % len(prof['ifeo_targets'])]}"
        ifeo_key = rf"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{ifeo_exe}"
        ifeo_mon = staged_exe_for_pers or r"C:\Windows\System32\cmd.exe"
        reg_manifest.append({
            "name": "MonitorProcess",
            "registry_key": ifeo_key,
            "registry_value": ifeo_mon,
            "path": ifeo_mon,
        })
        ps_lines.append(f'& reg.exe ADD "{ifeo_key}" /v "MonitorProcess" /t REG_SZ /d "{ifeo_mon}" /f | Out-Null')

    # Strip raw preview bytes from serializable manifest
    clean_files_manifest = [
        {k: v for k, v in rec.items() if k != "raw_bytes_preview"} for rec in staged_files
    ]
    synth_total = int(sum(synthetic_fallback_counts.values()))
    benign_manifest = {
        "run_id": run_id,
        "split_pool": sp,
        "benign_profile_id": prof_id,
        "seed": seed,
        "synthetic_fallback": bool(synth_total > 0),
        "synthetic_fallback_count": synth_total,
        "synthetic_fallback_counts": dict(synthetic_fallback_counts),
        "files": clean_files_manifest,
        "services": services_manifest,
        "tasks": tasks_manifest,
        "run_keys": run_keys_manifest,
        "registry_entries": reg_manifest,
    }
    return {
        "ps1_text": "\r\n".join(ps_lines) + "\r\n",
        "extra_iso_files": extra_iso_files,
        "benign_manifest": benign_manifest,
        "_staged_files_with_bytes": staged_files,
    }


def simulate_benign_generator_rows(
    split_pool: str = "dev",
    n_runs: int = 24,
    base_seed: int = 5000,
    benign_pools_root: str | Path | None = None,
    require_real_pools: bool = False,
) -> tuple[list[dict[str, Any]], set[str]]:
    """Simulate extracted cold-disk rows from `generate_benign_workload_bundle` using real extractor predicates."""
    rows: list[dict[str, Any]] = []
    keys: set[str] = set()
    sp = str(split_pool).strip().lower()
    prof_ids = WORKLOAD_PROFILES[sp]["profile_ids"]

    for idx in range(n_runs):
        rid = f"sim_{sp}_{idx:03d}"
        pid = prof_ids[idx % len(prof_ids)]
        bundle = generate_benign_workload_bundle(
            run_id=rid,
            split_pool=sp,
            benign_profile_id=pid,
            run_seed=base_seed + idx,
            benign_pools_root=benign_pools_root,
            require_real_pools=require_real_pools,
        )
        man = bundle["benign_manifest"]
        staged_bytes_by_path = {
            r["path"].lower(): r.get("raw_bytes_preview")
            for r in bundle["_staged_files_with_bytes"]
        }
        for f in man["files"]:
            p = f["path"]
            ext = Path(p.replace("\\", "/")).suffix.lower()
            if ext not in _USER_SCAN_TARGET_EXTS:
                raise AssertionError(
                    f"Simulated benign file has non-collected extension {ext!r}: {p!r}"
                )
            if ext in BENIGN_AVOIDED_EXTS:
                raise AssertionError(
                    f"Simulated benign file uses avoided extension {ext!r}: {p!r}"
                )
            if not path_matches_extractor_scan_roots(p):
                raise AssertionError(
                    f"Simulated benign file path outside real extractor scan_roots/depth: {p!r}"
                )
            nm = f["name"]
            ak = f"file|{p.lower()}|{nm.lower()}"
            keys.add(ak)
            raw_b = staged_bytes_by_path.get(p.lower())
            if raw_b is None:
                iso_rel = next((k for k in bundle["extra_iso_files"] if k.endswith(nm)), None)
                raw_b = bundle["extra_iso_files"].get(iso_rel, b"") if iso_rel else b""
            rows.append({
                "run_id": rid,
                "artifact_type": "file",
                "artifact_key": ak,
                "name": nm,
                "path": p,
                "command_line": None,
                "registry_key": None,
                "registry_value": None,
                "task_name": None,
                "service_name": None,
                "parent_name": None,
                "signature_status": f["signature_status"],
                "attributes": "Archive",
                "file_size": f["file_size"],
                "file_head_histogram": _bytes_head_hist(raw_b),
                "label": 0,
            })

        for svc in man["services"]:
            rk = svc["registry_key"]
            ak = f"service|{rk.lower()}|{svc['service_name'].lower()}"
            keys.add(ak)
            rows.append({
                "run_id": rid,
                "artifact_type": "service",
                "artifact_key": ak,
                "name": svc["service_name"],
                "path": svc["path"],
                "command_line": svc["command_line"],
                "registry_key": rk,
                "registry_value": None,
                "task_name": None,
                "service_name": svc["service_name"],
                "start_mode": svc["start_mode"],
                "parent_name": None,
                "signature_status": "NotSigned",
                "attributes": "Archive",
                "file_size": 90_000,
                "file_head_histogram": _bytes_head_hist(b"MZ" + b"\x90" * 1024),
                "label": 0,
            })

        for tsk in man["tasks"]:
            ak = f"task|{tsk['task_name'].rsplit('\\', 1)[0].lower()}\\|{tsk['name'].lower()}"
            keys.add(ak)
            rows.append({
                "run_id": rid,
                "artifact_type": "task",
                "artifact_key": ak,
                "name": tsk["name"],
                "path": tsk["path"],
                "command_line": tsk["command_line"],
                "registry_key": None,
                "registry_value": None,
                "task_name": tsk["task_name"],
                "task_triggers": tsk["task_triggers"],
                "service_name": None,
                "parent_name": None,
                "signature_status": "Valid",
                "attributes": "Archive",
                "file_size": 289_792,
                "file_head_histogram": _bytes_head_hist(b"MZ" + b"\x55" * 1024),
                "label": 0,
            })

        for rkey in man["run_keys"]:
            ak = f"run_key|{rkey['registry_key'].lower()}|{rkey['name'].lower()}"
            keys.add(ak)
            rows.append({
                "run_id": rid,
                "artifact_type": "run_key",
                "artifact_key": ak,
                "name": rkey["name"],
                "path": rkey["path"],
                "command_line": rkey["registry_value"],
                "registry_key": rkey["registry_key"],
                "registry_value": rkey["registry_value"],
                "task_name": None,
                "service_name": None,
                "parent_name": None,
                "signature_status": "NotSigned",
                "attributes": "Archive",
                "file_size": 90_000,
                "file_head_histogram": _bytes_head_hist(b"MZ" + b"\x77" * 1024),
                "label": 0,
            })

        for reg in man["registry_entries"]:
            ak = f"registry|{reg['registry_key'].lower()}|{reg['name'].lower()}"
            keys.add(ak)
            rows.append({
                "run_id": rid,
                "artifact_type": "registry",
                "artifact_key": ak,
                "name": reg["name"],
                "path": reg["path"],
                "command_line": reg["registry_value"],
                "registry_key": reg["registry_key"],
                "registry_value": reg["registry_value"],
                "task_name": None,
                "service_name": None,
                "parent_name": None,
                "signature_status": "NotSigned",
                "attributes": None,
                "file_size": None,
                "file_head_histogram": None,
                "label": 0,
            })

    return rows, keys
