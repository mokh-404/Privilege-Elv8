"""Small synthetic normalised-artifact fixtures (no real data, no VM)."""
from __future__ import annotations

import pandas as pd


def synthetic_rows() -> pd.DataFrame:
    rows = [
        {   # benign system service
            "run_id": "run_000", "technique_id": None, "variant": None, "launcher": None,
            "artifact_key": "service|c:\\windows\\system32\\svchost.exe|wuauserv",
            "artifact_type": "service", "name": "wuauserv", "path": None,
            "command_line": "C:\\Windows\\system32\\svchost.exe -k netsvcs -p",
            "registry_key": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\wuauserv", "registry_value": None,
            "task_name": None, "service_name": "wuauserv", "parent_name": None,
            "signature_status": "Valid", "attributes": "Archive", "file_size": 55320,
            "start_mode": "Manual", "task_triggers": None,
            "created_utc": "2026-01-01T00:00:00Z", "modified_utc": "2026-01-01T00:00:00Z",
            "label": "baseline",
        },
        {   # suspicious HKU run key to a user-writable script
            "run_id": "run_001", "technique_id": "TX", "variant": 1, "launcher": "attack",
            "artifact_key": "run_key|hku\\s-1-5-21-1\\software\\microsoft\\windows\\currentversion\\run|updater",
            "artifact_type": "run_key", "name": "updater", "path": None,
            "command_line": "powershell.exe -w hidden -enc SQBFAFgA",
            "registry_key": "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "registry_value": "powershell.exe -w hidden -enc SQBFAFgA",
            "task_name": None, "service_name": None, "parent_name": None,
            "signature_status": None, "attributes": None, "file_size": None,
            "start_mode": None, "task_triggers": None,
            "created_utc": None, "modified_utc": "2026-11-21T11:58:10Z",
            "label": "attacker_induced",
        },
        {   # dropped double-extension binary in Public, hidden
            "run_id": "run_001", "technique_id": "TX", "variant": 1, "launcher": "attack",
            "artifact_key": "file|c:\\users\\public\\report.pdf.exe|report.pdf.exe",
            "artifact_type": "file", "name": "report.pdf.exe", "path": "C:\\Users\\Public\\report.pdf.exe",
            "command_line": None, "registry_key": None, "registry_value": None,
            "task_name": None, "service_name": None, "parent_name": None,
            "signature_status": "NotSigned", "attributes": "Hidden, Archive", "file_size": 1023,
            "file_head_histogram": [4] * 256,
            "start_mode": None, "task_triggers": None,
            "created_utc": "2026-11-21T11:58:20Z", "modified_utc": "2026-11-21T11:58:20Z",
            "label": "attacker_induced",
        },
        {   # benign drift scheduled task (backup) at logon
            "run_id": "run_001", "technique_id": None, "variant": None, "launcher": "benign",
            "artifact_key": "task|\\backup|nightly backup",
            "artifact_type": "task", "name": "Nightly Backup", "path": None,
            "command_line": "\"C:\\Program Files\\7-Zip\\7z.exe\" a C:\\Users\\Public\\Documents\\b.7z",
            "registry_key": None, "registry_value": None,
            "task_name": "\\Backup\\Nightly Backup", "service_name": None, "parent_name": None,
            "signature_status": "Valid", "attributes": None, "file_size": 560000,
            "start_mode": None, "task_triggers": "MSFT_TaskLogonTrigger",
            "created_utc": "2026-11-21T11:58:30Z", "modified_utc": None,
            "label": "benign_drift",
        },
        {   # process launched via cmd with a lolbin
            "run_id": "run_001", "technique_id": "TX", "variant": 1, "launcher": "attack",
            "artifact_key": "process|c:\\windows\\system32\\rundll32.exe|rundll32.exe",
            "artifact_type": "process", "name": "rundll32.exe", "path": "C:\\Windows\\System32\\rundll32.exe",
            "command_line": "rundll32.exe C:\\Users\\Public\\hlp.dll,Start http://10.0.0.5/x",
            "registry_key": None, "registry_value": None, "task_name": None, "service_name": None,
            "parent_name": "cmd.exe", "signature_status": "Valid", "attributes": "Archive", "file_size": 71680,
            "start_mode": None, "task_triggers": None,
            "created_utc": "2019-12-07T09:09:00Z", "modified_utc": "2019-12-07T09:09:00Z",
            "label": "attacker_induced",
        },
        {   # prefetch entry
            "run_id": "run_001", "technique_id": None, "variant": None, "launcher": None,
            "artifact_key": "prefetch|c:\\windows\\prefetch\\notepad.exe-d8414f97.pf|notepad.exe-d8414f97.pf",
            "artifact_type": "prefetch", "name": "NOTEPAD.EXE-D8414F97.pf",
            "path": "C:\\Windows\\Prefetch\\NOTEPAD.EXE-D8414F97.pf",
            "command_line": None, "registry_key": None, "registry_value": None, "task_name": None,
            "service_name": None, "parent_name": None, "signature_status": None, "attributes": "Archive",
            "file_size": 4096, "start_mode": None, "task_triggers": None,
            "created_utc": "2026-11-21T11:59:00Z", "modified_utc": None, "label": "benign_drift",
        },
    ]
    return pd.DataFrame(rows)
