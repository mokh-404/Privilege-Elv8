"""Stratified shortcut & template-quantization audit (v2 IMP-06 upgrade + legacy v1 audit mode)."""
from __future__ import annotations

import argparse
import hashlib
import math
import random
import re
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score
import yaml

from src import config
from src.data.features import row_features, shannon_entropy


MIB = 1 << 20

HOST_PROFILES: dict[str, dict[str, Any]] = {
    "dev": {
        "users": ["alice_dev", "bob_eng", "ci_runner"],
        "software": ["Git", "Python312", "Sysinternals", "7-Zip"],
        "base_dirs": [
            r"C:\ProgramData\DevOpsTools",
            r"C:\ProgramData\BuildCache",
            r"C:\Users\alice_dev\AppData\Local\Programs\Tools",
            r"C:\Users\bob_eng\Workspace\Scripts",
            r"C:\Windows\Temp\PkgLogs",
        ],
        "svc_prefixes": ["BuildCache", "DevTelemetry", "GitGc", "PyEnvSync", "LogRotator"],
        "task_prefixes": ["RepoSync", "WheelCleanup", "SysmonHealth", "DiskTrim", "PipCache"],
        "run_prefixes": ["DevTray", "GitCredential", "PyLauncher", "SevenZipAssoc", "ProcMonHelper"],
        "triggers": ["MSFT_TaskLogonTrigger", "MSFT_TaskDailyTrigger", "MSFT_TaskBootTrigger", "MSFT_TaskTimeTrigger"],
    },
    "blind_test": {
        "users": ["claire_ops", "david_sec", "analyst01"],
        "software": ["Notepad++", "7-Zip", "Git", "Python312", "Sysinternals"],
        "base_dirs": [
            r"C:\ProgramData\OpsAutomation",
            r"C:\ProgramData\EndpointHealth",
            r"C:\Users\claire_ops\AppData\Roaming\Utilities",
            r"C:\Users\david_sec\Documents\OpsScripts",
            r"C:\Windows\Temp\AuditWork",
        ],
        "svc_prefixes": ["AssetAgent", "ConfigWatch", "PatchVerify", "ArchiveIdx", "QuotaMon"],
        "task_prefixes": ["EndpointSnap", "ConfigAudit", "NotepadBackup", "SysClean", "HourlyCheck"],
        "run_prefixes": ["OpsTray", "NoteSession", "ArchiveQuick", "HelpDesk", "StatusBar"],
        "triggers": ["MSFT_TaskLogonTrigger", "MSFT_TaskDailyTrigger", "MSFT_TaskRegistrationTrigger", "MSFT_TaskIdleTrigger"],
    },
}


def bytes_to_head_histogram(data: bytes | bytearray) -> list[int]:
    """Compute real 256-bin byte frequency counts over the leading 1 MiB."""
    arr = np.frombuffer(data[:MIB], dtype=np.uint8)
    return np.bincount(arr, minlength=256).astype(int).tolist()


def _synthetic_script_bytes(seed: int, body_hint: str, rng: random.Random) -> bytes:
    """Synthesize non-quantized realistic UTF-8 script/config text of varied length and entropy."""
    n_comments = rng.randint(2, 18)
    n_funcs = rng.randint(1, 5)
    lines = [
        f"# Host maintenance script: {body_hint}",
        f"# SeedTag={seed} Build={rng.randint(1000, 99999)}",
        "$ErrorActionPreference = 'SilentlyContinue'",
    ]
    cmds = [
        "Get-ChildItem -Path $env:TEMP -File | Where-Object Length -gt 0 | Measure-Object",
        "Get-Service | Where-Object Status -eq 'Running' | Select-Object -First 8 Name,StartType",
        "python -c \"import json, os, sys; print(len(os.listdir('.'))) \"",
        "git status --short --branch 2>&1 | Out-Null",
        "7z l C:\\ProgramData\\archive_meta.7z > $null",
        "sigcheck.exe -nobanner -q C:\\Windows\\System32\\notepad.exe | Out-Null",
    ]
    for fidx in range(n_funcs):
        fn_id = rng.randint(100, 9999)
        lines.append(f"function Invoke-Step{fidx}_{fn_id} {{")
        for _ in range(rng.randint(2, 7)):
            lines.append("    " + rng.choice(cmds))
        lines.append("}")
    for cidx in range(n_comments):
        pad = "".join(rng.choices("abcdefghijklmnopqrstuvwxyz0123456789_-=/:", k=rng.randint(14, 72)))
        lines.append(f"# note_{cidx}: {pad}")
    return ("\r\n".join(lines) + "\r\n").encode("utf-8")


def _synthetic_pe_bytes(seed: int, size_bytes: int, packed_like: bool = False) -> bytes:
    """Generate realistic unsigned PE-shaped byte buffer with real DOS/PE header + varied payload."""
    size_bytes = max(4096, int(size_bytes))
    rng = np.random.default_rng(seed)
    hdr = bytearray(1024)
    hdr[0:2] = b"MZ"
    struct_pe_off = 0x80
    hdr[0x3C:0x40] = int(struct_pe_off).to_bytes(4, "little")
    hdr[struct_pe_off : struct_pe_off + 4] = b"PE\x00\x00"
    rem = size_bytes - len(hdr)
    if packed_like:
        body = rng.integers(0, 256, size=rem, dtype=np.uint8).tobytes()
    else:
        # Realistic .text/.rdata mix: opcodes + ASCII strings + zero padding
        ascii_pool = np.frombuffer(
            b"kernel32.dll\x00GetProcAddress\x00VirtualAlloc\x00ntdll.dll\x00ConfigValue\x00Usage: tool.exe\x00",
            dtype=np.uint8,
        )
        n_code = int(0.45 * rem)
        n_str = int(0.30 * rem)
        n_zero = rem - n_code - n_str
        body = (
            rng.integers(0, 256, size=n_code, dtype=np.uint8).tobytes()
            + rng.choice(ascii_pool, size=n_str, replace=True).tobytes()
            + b"\x00" * n_zero
        )
    return bytes(hdr) + body


def load_attack_rows(
    techniques_yaml_path: str = "lab_automation/techniques.yaml",
    real_bytes: bool = True,
) -> list[dict[str, Any]]:
    """Build synthetic attack rows; uses realistic byte sizes & histograms by default."""
    with open(techniques_yaml_path, encoding="utf-8") as f:
        catalog = yaml.safe_load(f)

    attack_rows: list[dict[str, Any]] = []
    idx = 0
    for t in catalog["techniques"]:
        for v in t.get("variants", []):
            for a in v.get("expected_artifact_keys", []):
                idx += 1
                rng = random.Random(7000 + idx)
                parts = a.split("|")
                atype = parts[0]
                if atype not in ("file", "task", "run_key"):
                    continue
                steps_text = " ".join([s.get("cmd", "") for s in v.get("steps", [])])
                if atype == "file":
                    fname = parts[2]
                    if real_bytes:
                        is_exe = fname.lower().endswith((".exe", ".dll"))
                        payload = (
                            _synthetic_pe_bytes(7000 + idx, rng.randint(36_000, 520_000), packed_like=rng.random() < 0.4)
                            if is_exe
                            else _synthetic_script_bytes(7000 + idx, fname, rng)
                        )
                        fsize = len(payload)
                        fhist = bytes_to_head_histogram(payload)
                    else:
                        fsize, fhist = 2048, [1] * 256
                    row = {
                        "artifact_type": "file", "artifact_key": a, "name": fname, "path": parts[1],
                        "command_line": None, "registry_key": None, "registry_value": None,
                        "task_name": None, "service_name": None, "parent_name": None,
                        "signature_status": "Valid" if fname.endswith(".exe") else "NotSigned",
                        "attributes": "Archive", "file_size": fsize, "file_head_histogram": fhist, "label": 1,
                    }
                elif atype == "task":
                    tn_match = re.search(r"/TN\s+[\"']?([^\s\"']+)", steps_text)
                    tname = tn_match.group(1) if tn_match else parts[2]
                    if "cachemaintenance" in tname.lower():
                        cmd_line = r"powershell.exe -NoProfile -WindowStyle Hidden -File C:\ProgramData\Maint\cache_sync_v1.ps1"
                    elif "telemetryindex" in tname.lower():
                        cmd_line = r"cmd.exe /c C:\Users\Public\idx_refresh_v2.cmd"
                    else:
                        cmd_line = "powershell.exe -NoProfile -EncodedCommand JABlAG4AdgA6AEMATwBNAFAAVQBUAEUAUgBOAEEATQBFACAAfAAgAE8AdQB0AC0ARgBpAGwAZQAgAEMAOgBcAFcAaQBuAGQAbwB3AHMAXABUAGUAbQBwAFwAdABhAHMAawBfAGkAbgBkAHgALgB0AHgAdAA="
                    tpath = (
                        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
                        if "powershell" in cmd_line.lower()
                        else r"C:\Windows\System32\cmd.exe"
                    )
                    if real_bytes:
                        payload = _synthetic_pe_bytes(8000 + idx, 450_000 if "powershell" in cmd_line.lower() else 320_000)
                        fsize, fhist = len(payload), bytes_to_head_histogram(payload)
                    else:
                        fsize, fhist = 450000, [1] * 256
                    row = {
                        "artifact_type": "task", "artifact_key": a, "name": tname, "path": tpath,
                        "command_line": cmd_line, "registry_key": None, "registry_value": None,
                        "task_name": "\\" + tname, "task_triggers": "MSFT_TaskDailyTrigger",
                        "service_name": None, "parent_name": None, "signature_status": "Valid",
                        "attributes": "Archive", "file_size": fsize, "file_head_histogram": fhist, "label": 1,
                    }
                else:  # run_key
                    rn_match = re.search(r"/v\s+[\"']?([^\s\"']+)", steps_text)
                    rk_name = rn_match.group(1) if rn_match else parts[2]
                    reg_key = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run" if parts[1] == "hku" else parts[1]
                    if "desktopsyncagent" in rk_name.lower():
                        cmd_line = r"powershell.exe -NoProfile -WindowStyle Hidden -File C:\Users\Public\desktop_sync_v1.ps1"
                        target = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
                    elif "printerspoolfix" in rk_name.lower():
                        cmd_line = r"C:\ProgramData\SpoolFix\spool_v2.bat"
                        target = cmd_line
                    elif "syshealthmon" in rk_name.lower():
                        cmd_line = r"C:\ProgramData\svchost.exe"
                        target = cmd_line
                    else:
                        cmd_line = r"C:\ProgramData\app.cmd"
                        target = cmd_line
                    sig = "Valid" if "powershell" in target.lower() else "NotSigned"
                    if real_bytes:
                        payload = (
                            _synthetic_pe_bytes(9000 + idx, 450_000)
                            if sig == "Valid"
                            else _synthetic_script_bytes(9000 + idx, rk_name, rng)
                        )
                        fsize, fhist = len(payload), bytes_to_head_histogram(payload)
                    else:
                        fsize = 450000 if sig == "Valid" else 1024
                        fhist = [1] * 256
                    row = {
                        "artifact_type": "run_key", "artifact_key": a, "name": rk_name, "path": target,
                        "command_line": cmd_line, "registry_key": reg_key, "registry_value": cmd_line,
                        "task_name": None, "service_name": None, "parent_name": None, "signature_status": sig,
                        "attributes": "Archive", "file_size": fsize, "file_head_histogram": fhist, "label": 1,
                    }
                attack_rows.append(row)
    return attack_rows


def simulate_benign_rows(n_seeds: int = 48, base_seed: int = 46) -> tuple[list[dict[str, Any]], set[str]]:
    """Legacy v1 6-template generator retained solely for `--mode v1` comparison."""
    FilePrefixes = ["sys", "net", "host", "acct", "cfg", "disk", "user", "svc", "diag", "log", "sync", "data", "cache", "task", "file", "env", "mon", "perf"]
    FileStems = ["audit", "probe", "scan", "sweep", "check", "helper", "monitor", "worker", "agent", "status", "report", "clean", "maint", "sync", "update", "refresh", "backup", "review"]
    FileExts = ["ps1", "ps1", "cmd", "cmd", "bat", "vbs"]
    Dirs = [r"C:\ProgramData\Diagnostics", r"C:\Users\Public", r"C:\Windows\Temp"]
    benign_rows = []
    unique_keys = set()
    for s_idx in range(n_seeds):
        rng = random.Random(base_seed + s_idx)
        for ext in ("cmd", "ps1"):
            d = rng.choice(Dirs)
            fn = f"{rng.choice(FilePrefixes)}_{rng.choice(FileStems)}.{ext}"
            p = f"{d}\\{fn}"
            k = f"file|{p.lower()}|{fn.lower()}"
            unique_keys.add(k)
            benign_rows.append({
                "artifact_type": "file", "artifact_key": k, "name": fn, "path": p,
                "command_line": None, "registry_key": None, "registry_value": None, "task_name": None,
                "service_name": None, "parent_name": None, "signature_status": "NotSigned",
                "attributes": "Archive", "file_size": 2048, "file_head_histogram": [1] * 256, "label": 0,
            })
    return benign_rows, unique_keys


def simulate_v2_benign_rows(
    profile: str = "dev",
    n_runs: int = 48,
    base_seed: int = 1000,
) -> tuple[list[dict[str, Any]], set[str]]:
    """Diverse v2 benign workload generator with real sizes, real histograms & disjoint host profiles."""
    if profile not in HOST_PROFILES:
        raise ValueError(f"Unknown host profile {profile!r}; expected one of {sorted(HOST_PROFILES)}")
    prof = HOST_PROFILES[profile]
    benign_rows: list[dict[str, Any]] = []
    unique_keys: set[str] = set()

    for r_idx in range(n_runs):
        seed = base_seed + r_idx
        rng = random.Random(seed)
        user = prof["users"][r_idx % len(prof["users"])]
        base_dir = prof["base_dirs"][r_idx % len(prof["base_dirs"])]

        # 1. Varied procedural / dev scripts (Git / Python / Admin) with real unique content bytes
        for ext in ("ps1", "py", "cmd", "bat"):
            tag = f"{profile}_{r_idx:03d}_{rng.randint(10, 9999)}"
            fn = f"{prof['software'][r_idx % len(prof['software'])].lower().replace('+', 'p')}_{tag}.{ext}"
            fpath = f"{base_dir}\\{fn}"
            payload = _synthetic_script_bytes(seed * 31 + len(fn), f"{user}:{fn}", rng)
            akey = f"file|{fpath.lower()}|{fn.lower()}"
            unique_keys.add(akey)
            benign_rows.append({
                "artifact_type": "file", "artifact_key": akey, "name": fn, "path": fpath,
                "command_line": None, "registry_key": None, "registry_value": None,
                "task_name": None, "service_name": None, "parent_name": None,
                "signature_status": "NotSigned", "attributes": "Archive",
                "file_size": len(payload), "file_head_histogram": bytes_to_head_histogram(payload), "label": 0,
            })

        # 2. Legitimate unsigned open-source / developer PE utilities (unique sizes & real PE histograms)
        if r_idx % 2 == 0:
            pe_name = f"{profile}_helper_cli_{r_idx:03d}_{rng.randint(100, 999)}.exe"
            pe_path = f"C:\\Users\\{user}\\Tools\\{pe_name}"
            pe_size = rng.randint(42_000, 880_000) + r_idx * 137
            pe_bytes = _synthetic_pe_bytes(seed * 97 + 7, pe_size, packed_like=False)
            pe_key = f"file|{pe_path.lower()}|{pe_name.lower()}"
            unique_keys.add(pe_key)
            benign_rows.append({
                "artifact_type": "file", "artifact_key": pe_key, "name": pe_name, "path": pe_path,
                "command_line": None, "registry_key": None, "registry_value": None,
                "task_name": None, "service_name": None, "parent_name": None,
                "signature_status": "NotSigned", "attributes": "Archive",
                "file_size": len(pe_bytes), "file_head_histogram": bytes_to_head_histogram(pe_bytes), "label": 0,
            })

        # 3. Benign Windows service (hosts svchost DLL or standalone unsigned/signed utility)
        svc_name = f"{prof['svc_prefixes'][r_idx % len(prof['svc_prefixes'])]}_{profile}_{r_idx:02d}"
        svc_reg = f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\{svc_name}"
        svc_exe = (
            r"C:\Windows\System32\svchost.exe"
            if r_idx % 2 == 0
            else f"C:\\Program Files\\{prof['software'][0]}\\{svc_name.lower()}.exe"
        )
        svc_cmd = f"{svc_exe} -k {svc_name}Group" if r_idx % 2 == 0 else f"\"{svc_exe}\" --service"
        svc_bytes = _synthetic_pe_bytes(seed * 53, 88_232 if r_idx % 2 == 0 else rng.randint(95_000, 410_000))
        svc_key = f"service|{svc_reg.lower()}|{svc_name.lower()}"
        unique_keys.add(svc_key)
        benign_rows.append({
            "artifact_type": "service", "artifact_key": svc_key, "name": svc_name,
            "path": svc_exe, "command_line": svc_cmd, "registry_key": svc_reg,
            "registry_value": None, "task_name": None, "service_name": svc_name,
            "start_mode": "Auto" if r_idx % 3 == 0 else "Manual",
            "parent_name": None, "signature_status": "Valid" if r_idx % 2 == 0 else "NotSigned",
            "attributes": "Archive", "file_size": len(svc_bytes),
            "file_head_histogram": bytes_to_head_histogram(svc_bytes), "label": 0,
        })

        # 4. Varied-trigger scheduled task
        tname = f"{prof['task_prefixes'][r_idx % len(prof['task_prefixes'])]}_{profile}_{r_idx:03d}"
        trig = prof["triggers"][r_idx % len(prof["triggers"])]
        t_host = r"C:\Program Files\Python312\python.exe" if r_idx % 2 == 0 else r"C:\Program Files\Git\cmd\git.exe"
        t_cmd = f"\"{t_host}\" \"{base_dir}\\task_job_{r_idx}.py\""
        t_bytes = _synthetic_pe_bytes(seed * 61, rng.randint(102_000, 460_000))
        t_key = f"task|\\{profile}|{tname.lower()}"
        unique_keys.add(t_key)
        benign_rows.append({
            "artifact_type": "task", "artifact_key": t_key, "name": tname, "path": t_host,
            "command_line": t_cmd, "registry_key": None, "registry_value": None,
            "task_name": f"\\{profile}\\{tname}", "task_triggers": trig,
            "service_name": None, "parent_name": None, "signature_status": "Valid",
            "attributes": "Archive", "file_size": len(t_bytes),
            "file_head_histogram": bytes_to_head_histogram(t_bytes), "label": 0,
        })

        # 5. Benign Run/RunOnce & Registry software config edits
        rname = f"{prof['run_prefixes'][r_idx % len(prof['run_prefixes'])]}_{profile}_{r_idx:02d}"
        rcmd = f"\"C:\\Program Files\\7-Zip\\7zFM.exe\" /bg_{r_idx}" if r_idx % 2 == 0 else f"\"C:\\Users\\{user}\\Tools\\{rname}.exe\""
        rk_path = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run" if r_idx % 4 != 0 else r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
        r_bytes = _synthetic_pe_bytes(seed * 79, rng.randint(85_000, 520_000))
        r_key = f"run_key|hku_{profile}|{rname.lower()}"
        unique_keys.add(r_key)
        benign_rows.append({
            "artifact_type": "run_key", "artifact_key": r_key, "name": rname,
            "path": rcmd.split('"')[1] if '"' in rcmd else rcmd, "command_line": rcmd,
            "registry_key": rk_path, "registry_value": rcmd,
            "task_name": None, "service_name": None, "parent_name": None,
            "signature_status": "Valid" if r_idx % 2 == 0 else "NotSigned",
            "attributes": "Archive", "file_size": len(r_bytes),
            "file_head_histogram": bytes_to_head_histogram(r_bytes), "label": 0,
        })

        reg_key = f"registry|hklm\\software\\vendor_{profile}\\{r_idx:02d}|config_{r_idx:02d}"
        unique_keys.add(reg_key)
        benign_rows.append({
            "artifact_type": "registry", "artifact_key": reg_key, "name": f"config_{r_idx:02d}",
            "path": None, "command_line": f"\"C:\\Program Files\\Notepad++\\notepad++.exe\" -multiInst -n{r_idx}",
            "registry_key": f"HKLM\\SOFTWARE\\Vendor_{profile}\\{r_idx:02d}",
            "registry_value": f"mode={rng.choice(['fast', 'full', 'quiet'])}",
            "task_name": None, "service_name": None, "parent_name": None,
            "signature_status": None, "attributes": None, "file_size": None,
            "file_head_histogram": None, "label": 0,
        })

    return benign_rows, unique_keys


def check_template_quantization(
    benign_df: pd.DataFrame,
    min_unique_size_ratio: float = 0.60,
    min_unique_pair_ratio: float = 0.75,
    max_single_size_share: float = 0.10,
) -> dict[str, Any]:
    """Pass/fail realism gate detecting fixed-template benign file quantization (IMP-06)."""
    files = benign_df[benign_df["artifact_type"] == "file"].copy() if "artifact_type" in benign_df.columns else pd.DataFrame()
    n_files = int(len(files))
    failures: list[str] = []

    if n_files == 0:
        return {
            "passed": False,
            "n_files": 0,
            "unique_size_ratio": 0.0,
            "unique_size_entropy_pair_ratio": 0.0,
            "max_single_size_share": 1.0,
            "benign_services": 0,
            "benign_registry": 0,
            "benign_unsigned_pes": 0,
            "failures": ["Zero benign file rows found"],
        }

    sizes = files["file_size_log"].round(6)
    ents = files["file_entropy"].round(4) if "file_entropy" in files.columns else pd.Series(0.0, index=files.index)
    n_uniq_sizes = int(sizes.nunique(dropna=True))
    pairs = pd.DataFrame({"s": sizes, "e": ents}).dropna()
    n_uniq_pairs = int(len(pairs.drop_duplicates()))
    top_share = float(sizes.value_counts(normalize=True).iloc[0]) if n_uniq_sizes > 0 else 1.0

    size_ratio = n_uniq_sizes / n_files
    pair_ratio = n_uniq_pairs / n_files

    ben_svcs = int((benign_df["artifact_type"] == "service").sum())
    ben_regs = int((benign_df["artifact_type"] == "registry").sum())
    ben_uns_pes = int(((files["ext_class"] == "exe") & (files["signature_state"] == "unsigned")).sum())

    if size_ratio < min_unique_size_ratio:
        failures.append(f"unique_size_ratio={size_ratio:.3f} < {min_unique_size_ratio:.2f}")
    if pair_ratio < min_unique_pair_ratio:
        failures.append(f"unique_size_entropy_pair_ratio={pair_ratio:.3f} < {min_unique_pair_ratio:.2f}")
    if top_share > max_single_size_share:
        failures.append(f"max_single_size_share={top_share:.3f} > {max_single_size_share:.2f}")
    if ben_svcs == 0:
        failures.append("Zero benign service drift rows (IMP-06)")
    if ben_regs == 0:
        failures.append("Zero benign registry drift rows (IMP-06)")
    if ben_uns_pes == 0:
        failures.append("Zero legitimate unsigned benign PE binaries (IMP-06)")

    return {
        "passed": len(failures) == 0,
        "n_files": n_files,
        "n_unique_sizes": n_uniq_sizes,
        "unique_size_ratio": round(size_ratio, 4),
        "n_unique_pairs": n_uniq_pairs,
        "unique_size_entropy_pair_ratio": round(pair_ratio, 4),
        "max_single_size_share": round(top_share, 4),
        "benign_services": ben_svcs,
        "benign_registry": ben_regs,
        "benign_unsigned_pes": ben_uns_pes,
        "failures": failures,
    }


def run_audit(mode: str = "v2", profile: str = "dev") -> bool:
    """Execute stratified shortcut & template-quantization audit."""
    use_real = mode == "v2"
    attack_rows = load_attack_rows(real_bytes=use_real)
    if mode == "v2":
        benign_rows, unique_keys = simulate_v2_benign_rows(profile=profile)
    else:
        benign_rows, unique_keys = simulate_benign_rows()

    all_rows = attack_rows + benign_rows
    feats = [row_features(r) for r in all_rows]
    df = pd.DataFrame(feats)
    df["label"] = [r["label"] for r in all_rows]

    q_res = check_template_quantization(df[df["label"] == 0])
    print("================================================================================")
    print(f"STRATIFIED SHORTCUT & QUANTIZATION AUDIT (mode={mode}, profile={profile})")
    print("================================================================================")
    print(f"Total Attack Rows: {len(attack_rows)} | Benign Rows: {len(benign_rows)} | Distinct Benign Keys: {len(unique_keys)}")
    print(f"Template Quantization Gate: {'PASS' if q_res['passed'] else 'FAIL'} -> {q_res}")
    print("================================================================================\n")

    overall_pass = bool(q_res["passed"])
    numeric_to_check = config.NUMERIC_FEATURES + [
        "has_double_extension", "has_encoded_flag", "has_url_or_ip",
        "has_lolbin", "has_hidden_attr", "autostart_flag",
    ]
    cat_to_check = ["path_class", "ext_class", "registry_location_class", "parent_process_class", "signature_state"]

    for atype in ["file", "task", "run_key"]:
        sub = df[df["artifact_type"] == atype]
        y = sub["label"]
        if len(sub) == 0 or (y == 1).sum() == 0 or (y == 0).sum() == 0:
            continue
        print(f"### Artifact Type: `{atype}` (Attack N={(y == 1).sum()}, Benign N={(y == 0).sum()})")
        for num_col in numeric_to_check:
            vals = sub[num_col].fillna(sub[num_col].median() if not sub[num_col].isna().all() else 0)
            if len(vals.unique()) <= 1:
                auc = 0.5
            else:
                auc = roc_auc_score(y, vals)
                if auc < 0.5:
                    auc = 1.0 - auc
            print(f"  - `{num_col}`: Attack={sub[y == 1][num_col].mean():.2f} vs Benign={sub[y == 0][num_col].mean():.2f} | AUC={auc:.4f}")
        for cat_col in cat_to_check:
            att_dist = sub[y == 1][cat_col].value_counts(normalize=True).to_dict()
            ben_dist = sub[y == 0][cat_col].value_counts(normalize=True).to_dict()
            max_gap = max(abs(att_dist.get(lv, 0.0) - ben_dist.get(lv, 0.0)) * 100 for lv in (set(att_dist) | set(ben_dist)))
            print(f"  - `{cat_col}` max level gap: {max_gap:.1f}pp")
        print()

    return overall_pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Stratified shortcut & template-quantization audit.")
    parser.add_argument("--mode", choices=("v2", "v1"), default="v2")
    parser.add_argument("--profile", choices=tuple(sorted(HOST_PROFILES)), default="dev")
    args = parser.parse_args()
    return 0 if run_audit(mode=args.mode, profile=args.profile) else 1


if __name__ == "__main__":
    raise SystemExit(main())
