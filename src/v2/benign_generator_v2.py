"""Real procedural v2 benign workload generator with disjoint `dev` / `blind_test` host profiles (`IMP-06`, `OD-V2-12`).

Generates per-run PowerShell workloads (`benign_workload.ps1`), real pool asset slices from
`/var/lib/dfir-quarantine-vault/benign_pools/<split_pool>/`, procedurally varied non-template scripts,
high-entropy benign archives/data, and realistic Windows benign persistence (`service`, `task`,
`run_key`, `registry`) — guaranteeing zero `dev`/`blind_test` overlap and zero template quantization.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import random
import struct
from typing import Any, Mapping, Sequence
import zipfile

import numpy as np

from src.data.features import row_features


MIB = 1 << 20
DEFAULT_BENIGN_POOLS_ROOT = Path("/var/lib/dfir-quarantine-vault/benign_pools")

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
    if ext == "ps1":
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
        comment_prefix = "# "
    elif ext == "py":
        lines.extend([
            f"# Diagnostic utility {tag} owner={user}",
            "import json, os, platform, sys",
            f"META = {{'tag': '{tag}', 'build': {rng.randint(100, 99999)}}}",
        ])
        for b in range(n_blocks):
            lines.append(f"def step_{b}_{rng.randint(10,999)}():")
            lines.append(f"    return len(os.getcwd()) + {rng.randint(1, 500)}")
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
    elif ext == "vbs":
        lines.extend([
            f"' Host inventory helper {tag} owner={user}",
            f"Dim tagVal : tagVal = \"{tag}_{rng.randint(10, 9999)}\"",
        ])
        for b in range(n_blocks):
            lines.append(f"Dim v{b} : v{b} = Len(tagVal) + {rng.randint(1, 200)}")
        comment_prefix = "' "
    else:  # .js
        lines.extend([
            f"// Endpoint telemetry helper {tag} owner={user}",
            f"var runTag = \"{tag}_{rng.randint(10, 9999)}\";",
        ])
        for b in range(n_blocks):
            lines.append(f"function chk_{b}() {{ return runTag.length + {rng.randint(1, 99)}; }}")
        comment_prefix = "// "

    # Add non-uniform variable comment payload so lengths and byte distributions vary smoothly
    pos = 0
    while pos < pad_len or len(lines) < n_notes + 4:
        chunk_sz = rng.randint(24, 110)
        frag = "".join(rng.choices(alphabet, k=chunk_sz))
        lines.append(f"{comment_prefix}meta_{pos}_{rng.randint(10,99)}: {frag}")
        pos += chunk_sz

    return ("\r\n".join(lines) + "\r\n").encode("utf-8")


def _synth_high_entropy_zip(rng: random.Random, tag: str) -> bytes:
    """Create a real deflate-compressed ZIP archive with high byte entropy."""
    buf = io.BytesIO()
    n_bytes = rng.randint(4096, 65536)
    seed_bytes = rng.randbytes(n_bytes)
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.writestr(f"{tag}_metrics.bin", seed_bytes)
        zf.writestr(f"{tag}_manifest.json", json.dumps({"tag": tag, "bytes": n_bytes}).encode("utf-8"))
    return buf.getvalue()


def _synth_json_or_log(rng: random.Random, ext: str, tag: str) -> bytes:
    n_recs = rng.randint(12, 120)
    if ext == "json":
        payload = {
            "tag": tag,
            "events": [
                {
                    "seq": i,
                    "metric": rng.randint(10, 10000),
                    "token": "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=rng.randint(12, 36))),
                }
                for i in range(n_recs)
            ],
        }
        return json.dumps(payload, indent=2).encode("utf-8")
    lines = [
        f"2026-11-25T00:{i % 60:02d}:00Z INFO {tag} chk={rng.randint(1000,99999)} tok="
        + "".join(rng.choices("abcdef0123456789", k=rng.randint(16, 48)))
        for i in range(n_recs)
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _synth_unsigned_pe_bytes(seed: int, size_bytes: int, is_dll: bool = False) -> bytes:
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

    # Realistic non-uniform .text/.rdata byte body
    n_code = int(raw_sz * 0.55)
    n_str = int(raw_sz * 0.25)
    n_pad = raw_sz - n_code - n_str
    ascii_pool = np.frombuffer(
        b"kernel32.dll\x00advapi32.dll\x00GetSystemTimeAsFileTime\x00RegQueryValueExW\x00BenignCliTool\x00",
        dtype=np.uint8,
    )
    body = (
        np_rng.integers(0, 256, size=n_code, dtype=np.uint8).tobytes()
        + np_rng.choice(ascii_pool, size=n_str, replace=True).tobytes()
        + b"\x00" * n_pad
    )
    buf[0x400:] = body
    return bytes(buf)


def _load_pool_asset_candidates(benign_pools_root: Path | None, split_pool: str) -> list[Path]:
    if benign_pools_root is None:
        return []
    sdir = Path(benign_pools_root) / split_pool
    if not sdir.is_dir():
        return []
    return sorted(p for p in sdir.rglob("*") if p.is_file() and not p.is_symlink())


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

    if pool_files:
        # Rotate cleanly across the pool using deterministic offset + stride
        stride = max(1, len(pool_files) // max(1, n_pool_assets))
        start_idx = seed % len(pool_files)
        picked: list[Path] = []
        for idx in range(min(n_pool_assets, len(pool_files))):
            picked.append(pool_files[(start_idx + idx * stride) % len(pool_files)])
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
            if pfile.suffix.lower() in (".exe", ".dll", ".ps1"):
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
        # Realistic unsigned benign developer CLI PEs (1 .exe + 1 .dll) when external pool is empty
        for pe_idx, is_dll in enumerate((False, True)):
            ext = "dll" if is_dll else "exe"
            pe_name = f"{sp}_{sw.lower()}_tool_{safe_run}_{pe_idx}_{rng.randint(100,999)}.{ext}"
            dst_dir = f"C:\\Users\\{user}\\AppData\\Local\\{sw}\\bin" if pe_idx == 0 else base_dir
            dst_path = f"{dst_dir}\\{pe_name}"
            pe_sz = rng.randint(48_000, 760_000) + pe_idx * 1319 + (seed % 4096)
            pe_bytes = _synth_unsigned_pe_bytes(seed + 101 + pe_idx, pe_sz, is_dll=is_dll)
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

    # 2. Procedurally varied non-template scripts (all extensions covered by offline_extractor user-scan + .py)
    script_exts = ("ps1", "bat", "cmd", "vbs", "js", "ps1", "py")
    staged_py_path: str | None = None
    for s_idx in range(n_scripts):
        sext = script_exts[(seed + s_idx) % len(script_exts)]
        sname = f"{sp}_{sw.lower()}_{safe_run}_{s_idx}_{rng.randint(100,9999)}.{sext}"
        dst_dir = prof["base_dirs"][(seed + s_idx) % len(prof["base_dirs"])]
        dst_path = f"{dst_dir}\\{sname}"
        s_bytes = _synth_varied_script(rng, sext, f"{sp}_{safe_run}_{s_idx}", user)
        iso_rel = f"benign_assets/{sname}"
        extra_iso_files[iso_rel] = s_bytes
        if sext == "py" and staged_py_path is None:
            staged_py_path = dst_path
        staged_files.append({
            "path": dst_path,
            "name": sname,
            "sha256": hashlib.sha256(s_bytes).hexdigest().lower(),
            "file_size": len(s_bytes),
            "source": "procedural_script",
            "is_pe": False,
            "signature_status": "NotSigned" if sext in ("ps1", "vbs", "js") else "UnknownError",
            "raw_bytes_preview": s_bytes,
        })
        ps_lines.extend([
            f'if (-not (Test-Path -LiteralPath "{dst_dir}")) {{ New-Item -ItemType Directory -Path "{dst_dir}" -Force | Out-Null }}',
            f'$srcScr{s_idx} = Join-Path $stageRoot "{iso_rel.replace("/", "\\")}"',
            f'if (Test-Path -LiteralPath $srcScr{s_idx}) {{ Copy-Item -LiteralPath $srcScr{s_idx} -Destination "{dst_path}" -Force }}',
        ])

    # 3. High-entropy benign archives & structured data (.zip / .json / .log)
    data_exts = ("zip", "json", "log")
    for a_idx in range(n_archives):
        dext = data_exts[(seed + a_idx) % len(data_exts)]
        dname = f"{sp}_bundle_{safe_run}_{a_idx}_{rng.randint(100,9999)}.{dext}"
        dst_dir = f"C:\\Users\\{user}\\AppData\\Roaming\\{sw}\\cache"
        dst_path = f"{dst_dir}\\{dname}"
        d_bytes = (
            _synth_high_entropy_zip(rng, f"{sp}_{safe_run}_{a_idx}")
            if dext == "zip"
            else _synth_json_or_log(rng, dext, f"{sp}_{safe_run}_{a_idx}")
        )
        iso_rel = f"benign_assets/{dname}"
        extra_iso_files[iso_rel] = d_bytes
        staged_files.append({
            "path": dst_path,
            "name": dname,
            "sha256": hashlib.sha256(d_bytes).hexdigest().lower(),
            "file_size": len(d_bytes),
            "source": "benign_data",
            "is_pe": False,
            "signature_status": "UnknownError",
            "raw_bytes_preview": d_bytes,
        })
        ps_lines.extend([
            f'if (-not (Test-Path -LiteralPath "{dst_dir}")) {{ New-Item -ItemType Directory -Path "{dst_dir}" -Force | Out-Null }}',
            f'$srcDat{a_idx} = Join-Path $stageRoot "{iso_rel.replace("/", "\\")}"',
            f'if (Test-Path -LiteralPath $srcDat{a_idx}) {{ Copy-Item -LiteralPath $srcDat{a_idx} -Destination "{dst_path}" -Force }}',
        ])

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
        t_target = staged_py_path or (staged_files[0]["path"] if staged_files else r"C:\Windows\System32\cmd.exe")
        t_action = (
            f'cmd.exe /c python.exe "{t_target}"'
            if str(t_target).lower().endswith(".py")
            else f'cmd.exe /c echo {t_name}'
        )
        tasks_manifest.append({
            "task_name": t_full,
            "name": t_name,
            "task_triggers": t_trig_cls,
            "command_line": t_action,
            "path": r"C:\Windows\System32\cmd.exe",
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
    benign_manifest = {
        "run_id": run_id,
        "split_pool": sp,
        "benign_profile_id": prof_id,
        "seed": seed,
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
) -> tuple[list[dict[str, Any]], set[str]]:
    """Simulate extracted cold-disk rows from `generate_benign_workload_bundle` for shortcut & disjoint audits."""
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
        )
        man = bundle["benign_manifest"]
        staged_bytes_by_path = {
            r["path"].lower(): r.get("raw_bytes_preview")
            for r in bundle["_staged_files_with_bytes"]
        }
        for f in man["files"]:
            p = f["path"]
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
