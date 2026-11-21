"""Stratified shortcut audit within artifact_type comparing benign_noise.ps1 vs techniques.yaml."""
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


def load_attack_rows(techniques_yaml_path: str = "lab_automation/techniques.yaml") -> list[dict[str, Any]]:
    with open(techniques_yaml_path) as f:
        catalog = yaml.safe_load(f)

    attack_rows = []
    for t in catalog["techniques"]:
        for v in t.get("variants", []):
            for a in v.get("expected_artifact_keys", []):
                parts = a.split("|")
                atype = parts[0]
                if atype not in ("file", "task", "run_key"):
                    continue
                steps_text = " ".join([s.get("cmd", "") for s in v.get("steps", [])])
                if atype == "file":
                    fname = parts[2]
                    row = {
                        "artifact_type": "file",
                        "artifact_key": a,
                        "name": fname,
                        "path": parts[1],
                        "command_line": None,
                        "registry_key": None,
                        "registry_value": None,
                        "task_name": None,
                        "service_name": None,
                        "parent_name": None,
                        "signature_status": "Valid" if fname.endswith(".exe") else "NotSigned",
                        "attributes": "Archive",
                        "file_size": 2048,
                        "file_head_histogram": [1] * 256,
                        "label": 1,
                    }
                elif atype == "task":
                    tn_match = re.search(r"/TN\s+[\"']?([^\s\"']+)", steps_text)
                    tname = tn_match.group(1) if tn_match else parts[2]
                    if "cachemaintenance" in tname.lower():
                        cmd_line = "powershell.exe -NoProfile -WindowStyle Hidden -File C:\\ProgramData\\Maint\\cache_sync_v1.ps1"
                    elif "telemetryindex" in tname.lower():
                        cmd_line = "cmd.exe /c C:\\Users\\Public\\idx_refresh_v2.cmd"
                    else:
                        cmd_line = "powershell.exe -NoProfile -EncodedCommand JABlAG4AdgA6AEMATwBNAFAAVQBUAEUAUgBOAEEATQBFACAAfAAgAE8AdQB0AC0ARgBpAGwAZQAgAEMAOgBcAFcAaQBuAGQAbwB3AHMAXABUAGUAbQBwAFwAdABhAHMAawBfAGkAbgBkAHgALgB0AHgAdAA="
                    row = {
                        "artifact_type": "task",
                        "artifact_key": a,
                        "name": tname,
                        "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" if "powershell" in cmd_line.lower() else "C:\\Windows\\System32\\cmd.exe",
                        "command_line": cmd_line,
                        "registry_key": None,
                        "registry_value": None,
                        "task_name": "\\" + tname,
                        "service_name": None,
                        "parent_name": None,
                        "signature_status": "Valid",
                        "attributes": "Archive",
                        "file_size": 450000,
                        "file_head_histogram": [1] * 256,
                        "label": 1,
                    }
                elif atype == "run_key":
                    rn_match = re.search(r"/v\s+[\"']?([^\s\"']+)", steps_text)
                    rk_name = rn_match.group(1) if rn_match else parts[2]
                    reg_key = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" if parts[1] == "hku" else parts[1]
                    if "desktopsyncagent" in rk_name.lower():
                        cmd_line = "powershell.exe -NoProfile -WindowStyle Hidden -File C:\\Users\\Public\\desktop_sync_v1.ps1"
                        target = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                    elif "printerspoolfix" in rk_name.lower():
                        cmd_line = "C:\\ProgramData\\SpoolFix\\spool_v2.bat"
                        target = cmd_line
                    elif "syshealthmon" in rk_name.lower():
                        cmd_line = "C:\\ProgramData\\svchost.exe"
                        target = cmd_line
                    elif "certsync" in rk_name.lower():
                        cmd_line = "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\\Users\\Public\\payload_v1.ps1"
                        target = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                    elif "sysauditonce" in rk_name.lower():
                        cmd_line = "C:\\ProgramData\\sys_audit_wrap_v1.cmd"
                        target = cmd_line
                    elif "acctscan" in rk_name.lower():
                        cmd_line = "C:\\ProgramData\\acct_scan_v1.cmd"
                        target = cmd_line
                    elif "acctaudit" in rk_name.lower():
                        cmd_line = "powershell.exe -NoProfile -File C:\\Users\\Public\\enum_users_v2.ps1"
                        target = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                    elif "cfgindexer" in rk_name.lower():
                        cmd_line = "powershell.exe -NoProfile -File C:\\Windows\\Temp\\ksearch_v3.ps1"
                        target = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
                    else:
                        cmd_line = "C:\\ProgramData\\app.cmd"
                        target = cmd_line
                    sig = "Valid" if "powershell" in target.lower() else "NotSigned"
                    row = {
                        "artifact_type": "run_key",
                        "artifact_key": a,
                        "name": rk_name,
                        "path": target,
                        "command_line": cmd_line,
                        "registry_key": reg_key,
                        "registry_value": cmd_line,
                        "task_name": None,
                        "service_name": None,
                        "parent_name": None,
                        "signature_status": sig,
                        "attributes": "Archive",
                        "file_size": 450000 if sig == "Valid" else 1024,
                        "file_head_histogram": [1] * 256,
                        "label": 1,
                    }
                attack_rows.append(row)
    return attack_rows


def simulate_benign_rows(n_seeds: int = 48, base_seed: int = 46) -> tuple[list[dict[str, Any]], set[str]]:
    FilePrefixes = ["sys", "net", "host", "acct", "cfg", "disk", "user", "svc", "diag", "log", "sync", "data", "cache", "task", "file", "env", "mon", "perf"]
    FileStems = ["audit", "probe", "scan", "sweep", "check", "helper", "monitor", "worker", "agent", "status", "report", "clean", "maint", "sync", "update", "refresh", "backup", "review"]
    FileExts = ["ps1", "ps1", "cmd", "cmd", "bat", "vbs"]

    TaskPrefixes = ["Cache", "Telemetry", "Font", "System", "Index", "Network", "Health", "Service", "Data", "Disk"]
    TaskStems = ["MaintenanceHelper", "IndexRefresh", "CacheUpdater", "StatusMonitor", "HealthCheck", "UpdateHelper"]

    RunPrefixes = ["Desktop", "Printer", "SysHealth", "Cert", "SysAudit", "Acct", "Cfg", "Health", "Sync", "Net"]
    RunStems = ["SyncAgent", "SpoolFix", "Mon", "Sync", "Once", "Scan", "Audit", "Indexer", "Agent", "Fix"]

    Dirs = [
        "C:\\ProgramData\\Diagnostics",
        "C:\\ProgramData\\Support",
        "C:\\ProgramData\\Maintenance",
        "C:\\Users\\Public",
        "C:\\Users\\Public\\Reports",
        "C:\\Windows\\Temp",
        "C:\\Windows\\Temp\\Maint",
    ]

    def get_file_name(rng: random.Random, forced_ext: str = "") -> str:
        p = rng.choice(FilePrefixes)
        s = rng.choice(FileStems)
        suf = f"_v{rng.choice([1, 2, 3])}" if rng.random() < 0.56 else ""
        ext = forced_ext if forced_ext else rng.choice(FileExts)
        return f"{p}_{s}{suf}.{ext}"

    benign_rows = []
    unique_keys = set()

    for s_idx in range(n_seeds):
        seed = base_seed + s_idx
        rng = random.Random(seed)

        # 1. workspace_doc (cmd and ps1)
        d1 = rng.choice(Dirs)
        fn1 = get_file_name(rng, "cmd")
        p1 = f"{d1}\\{fn1}"
        k1 = f"file|{p1.lower()}|{fn1.lower()}"
        unique_keys.add(k1)
        benign_rows.append({
            "artifact_type": "file", "artifact_key": k1, "name": fn1, "path": p1,
            "command_line": None, "registry_key": None, "registry_value": None, "task_name": None, "service_name": None,
            "parent_name": None, "signature_status": "NotSigned", "attributes": "Archive", "file_size": 2048,
            "file_head_histogram": [1] * 256, "label": 0,
        })

        fn2 = get_file_name(rng, "ps1")
        p2 = f"{d1}\\{fn2}"
        k2 = f"file|{p2.lower()}|{fn2.lower()}"
        unique_keys.add(k2)
        benign_rows.append({
            "artifact_type": "file", "artifact_key": k2, "name": fn2, "path": p2,
            "command_line": None, "registry_key": None, "registry_value": None, "task_name": None, "service_name": None,
            "parent_name": None, "signature_status": "NotSigned", "attributes": "Archive", "file_size": 2048,
            "file_head_histogram": [1] * 256, "label": 0,
        })

        # 2. ps_diag (ps1)
        d2 = rng.choice(Dirs)
        fn3 = get_file_name(rng, "ps1")
        p3 = f"{d2}\\{fn3}"
        k3 = f"file|{p3.lower()}|{fn3.lower()}"
        unique_keys.add(k3)
        benign_rows.append({
            "artifact_type": "file", "artifact_key": k3, "name": fn3, "path": p3,
            "command_line": None, "registry_key": None, "registry_value": None, "task_name": None, "service_name": None,
            "parent_name": None, "signature_status": "NotSigned", "attributes": "Archive", "file_size": 2048,
            "file_head_histogram": [1] * 256, "label": 0,
        })

        # 3. cmd_archive (cmd)
        d3 = rng.choice(Dirs)
        fn4 = get_file_name(rng, "cmd")
        p4 = f"{d3}\\{fn4}"
        k4 = f"file|{p4.lower()}|{fn4.lower()}"
        unique_keys.add(k4)
        benign_rows.append({
            "artifact_type": "file", "artifact_key": k4, "name": fn4, "path": p4,
            "command_line": None, "registry_key": None, "registry_value": None, "task_name": None, "service_name": None,
            "parent_name": None, "signature_status": "NotSigned", "attributes": "Archive", "file_size": 2048,
            "file_head_histogram": [1] * 256, "label": 0,
        })

        # 4. backup_task (task + target script)
        tp = rng.choice(TaskPrefixes)
        ts = rng.choice(TaskStems)
        tname = f"{tp}{ts}"
        td = rng.choice(Dirs)
        tscript_fn = get_file_name(rng, "ps1")
        tscript = f"{td}\\{tscript_fn}"
        k_tfile = f"file|{tscript.lower()}|{tscript_fn.lower()}"
        unique_keys.add(k_tfile)
        benign_rows.append({
            "artifact_type": "file", "artifact_key": k_tfile, "name": tscript_fn, "path": tscript,
            "command_line": None, "registry_key": None, "registry_value": None, "task_name": None, "service_name": None,
            "parent_name": None, "signature_status": "NotSigned", "attributes": "Archive", "file_size": 2048,
            "file_head_histogram": [1] * 256, "label": 0,
        })

        if rng.random() < 0.67:
            if rng.random() < 0.33:
                tcmd = "powershell.exe -NoProfile -EncodedCommand JABlAG4AdgA6AEMATwBNAFAAVQBUAEUAUgBOAEEATQBFACAAfAAgAE8AdQB0AC0ARgBpAGwAZQAgAEMAOgBcAFcAaQBuAGQAbwB3AHMAXABUAGUAbQBwAFwAdABhAHMAawBfAGkAbgBkAHgALgB0AHgAdAA="
            else:
                tcmd = f"powershell.exe -NoProfile -WindowStyle Hidden -File {tscript}"
            tpath = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
        else:
            tcmd = f"cmd.exe /c {tscript}"
            tpath = "C:\\Windows\\System32\\cmd.exe"

        ktask = f"task|\\|{tname.lower()}"
        unique_keys.add(ktask)
        benign_rows.append({
            "artifact_type": "task", "artifact_key": ktask, "name": tname,
            "path": tpath, "command_line": tcmd,
            "registry_key": None, "registry_value": None, "task_name": f"\\{tname}", "service_name": None,
            "parent_name": None, "signature_status": "Valid", "attributes": "Archive", "file_size": 450000,
            "file_head_histogram": [1] * 256, "label": 0,
        })

        # 5. run_note (run_key + target script)
        rp = rng.choice(RunPrefixes)
        rs = rng.choice(RunStems)
        rsuf = f"V{rng.choice([1, 2, 3])}" if rng.random() < 0.60 else ""
        rname = f"{rp}{rs}{rsuf}"
        rd = rng.choice(Dirs)
        rscript_fn = get_file_name(rng, "ps1")
        rscript = f"{rd}\\{rscript_fn}"
        k_rfile = f"file|{rscript.lower()}|{rscript_fn.lower()}"
        unique_keys.add(k_rfile)
        benign_rows.append({
            "artifact_type": "file", "artifact_key": k_rfile, "name": rscript_fn, "path": rscript,
            "command_line": None, "registry_key": None, "registry_value": None, "task_name": None, "service_name": None,
            "parent_name": None, "signature_status": "NotSigned", "attributes": "Archive", "file_size": 2048,
            "file_head_histogram": [1] * 256, "label": 0,
        })

        if rng.random() < 0.50:
            if rng.random() < 0.5:
                rcmd = f"powershell.exe -NoProfile -WindowStyle Hidden -File {rscript}"
            else:
                rcmd = f"powershell.exe -NoProfile -File {rscript}"
            rpath = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            rsig = "Valid"
        else:
            rcmd = rscript
            rpath = rscript
            rsig = "NotSigned"

        rreg = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" if rng.random() < 0.875 else "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
        krun = f"run_key|hku|{rname.lower()}"
        unique_keys.add(krun)
        benign_rows.append({
            "artifact_type": "run_key", "artifact_key": krun, "name": rname,
            "path": rpath, "command_line": rcmd,
            "registry_key": rreg, "registry_value": rcmd,
            "task_name": None, "service_name": None, "parent_name": None, "signature_status": rsig,
            "attributes": "Archive", "file_size": 450000 if rsig == "Valid" else 1024,
            "file_head_histogram": [1] * 256, "label": 0,
        })

    return benign_rows, unique_keys


def run_audit():
    attack_rows = load_attack_rows()
    benign_rows, unique_keys = simulate_benign_rows()

    all_rows = attack_rows + benign_rows
    feats = [row_features(r) for r in all_rows]
    df = pd.DataFrame(feats)
    df["label"] = [r["label"] for r in all_rows]

    print("================================================================================")
    print("STRATIFIED SHORTCUT AUDIT WITHIN ARTIFACT_TYPE (REAL FEATURES EXTRACTOR)")
    print("================================================================================")
    print(f"Total Attack Rows evaluated: {len(attack_rows)}")
    print(f"Total Benign Rows evaluated: {len(benign_rows)}")
    print(f"Total Distinct Benign Keys after cross-run dedup: {len(unique_keys)} (Target: >= 100)")
    print("================================================================================\n")

    overall_pass = True
    numeric_to_check = config.NUMERIC_FEATURES + [
        "has_double_extension", "has_encoded_flag", "has_url_or_ip",
        "has_lolbin", "has_hidden_attr", "autostart_flag"
    ]
    cat_to_check = [
        "path_class", "ext_class", "registry_location_class",
        "parent_process_class", "signature_state"
    ]

    for atype in ["file", "task", "run_key"]:
        sub = df[df["artifact_type"] == atype]
        y = sub["label"]
        n_att = int((y == 1).sum())
        n_ben = int((y == 0).sum())

        print(f"### Artifact Type: `{atype}` (Attack N={n_att}, Benign N={n_ben})")

        # Name length distribution
        att_len = sub[y == 1]["name_length"]
        ben_len = sub[y == 0]["name_length"]
        print(f"**Name Length Distributions:**")
        print(f"  - Attack: Mean={att_len.mean():.2f}, Median={att_len.median():.1f}, Std={att_len.std():.2f}, Min={att_len.min():.0f}, Max={att_len.max():.0f}")
        print(f"  - Benign: Mean={ben_len.mean():.2f}, Median={ben_len.median():.1f}, Std={ben_len.std():.2f}, Min={ben_len.min():.0f}, Max={ben_len.max():.0f}\n")

        # Numeric features table
        print(f"| Numeric Feature | Attack Mean | Benign Mean | Single-Feature ROC-AUC | Status (<= 0.70) |")
        print(f"| :--- | :---: | :---: | :---: | :---: |")
        for num_col in numeric_to_check:
            vals = sub[num_col].fillna(sub[num_col].median() if not sub[num_col].isna().all() else 0)
            if len(vals.unique()) <= 1:
                auc = 0.5
            else:
                try:
                    auc = roc_auc_score(y, vals)
                    if auc < 0.5:
                        auc = 1.0 - auc
                except Exception:
                    auc = 0.5
            status = "PASS" if auc <= 0.70 else "FAIL (> 0.70)"
            if auc > 0.70:
                overall_pass = False
            att_m = sub[y == 1][num_col].mean()
            ben_m = sub[y == 0][num_col].mean()
            print(f"| `{num_col}` | {att_m:.2f} | {ben_m:.2f} | **{auc:.4f}** | {status} |")
        print()

        # Categorical features table
        print(f"| Categorical Feature | Level | Attack Share | Benign Share | Gap (pp) | Status (<= 25pp) |")
        print(f"| :--- | :--- | :---: | :---: | :---: | :---: |")
        for cat_col in cat_to_check:
            att_dist = sub[y == 1][cat_col].value_counts(normalize=True).to_dict()
            ben_dist = sub[y == 0][cat_col].value_counts(normalize=True).to_dict()
            all_levels = sorted(set(att_dist.keys()) | set(ben_dist.keys()))
            for lvl in all_levels:
                a_sh = att_dist.get(lvl, 0.0) * 100
                b_sh = ben_dist.get(lvl, 0.0) * 100
                gap = abs(a_sh - b_sh)
                status = "PASS" if gap <= 25.0 else "FAIL (> 25pp)"
                if gap > 25.0:
                    overall_pass = False
                print(f"| `{cat_col}` | `{lvl}` | {a_sh:5.1f}% | {b_sh:5.1f}% | {gap:5.1f}pp | {status} |")
        print("\n" + "-" * 80 + "\n")

    print(f"ALL STOPPING CRITERIA SATISFIED: {overall_pass}")
    return overall_pass


if __name__ == "__main__":
    success = run_audit()
    exit(0 if success else 1)
