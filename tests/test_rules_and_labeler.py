"""Unit tests for Step 7: 15 deterministic rules and provenance/diff labeler."""
import json
import math
from pathlib import Path

import pandas as pd
import pytest
import yaml

from src import config
from src.data import labeler
from src.data.sanitize import SanitizationError
from src.rules import deterministic_rules as R


# ---------------- Deterministic rules (RULE-001..RULE-015) ----------------
def test_exactly_15_rules_defined():
    assert len(R.RULES) == 15
    assert [r.rule_id for r in R.RULES] == [f"RULE-{i:03d}" for i in range(1, 16)]


def test_rules_never_read_label_or_ground_truth_technique():
    row = {
        "artifact_type": "file",
        "name": "notes.txt",
        "path": "C:\\Users\\Public\\notes.txt",
        "signature_status": "NotSigned",
        "attributes": "Archive",
        "label": "attacker_induced",
        "technique_id": "T1547.001",
        "launcher": "attack",
    }
    assert R.evaluate_row(row) == []


@pytest.mark.parametrize("rule_id,pos_row,neg_row", [
    ("RULE-001",
     {"artifact_type": "run_key", "name": "Updater", "registry_key": "HKU\\S-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "command_line": "C:\\Users\\Public\\u.ps1", "signature_status": "NotSigned"},
     {"artifact_type": "run_key", "name": "OneDrive", "registry_key": "HKU\\S-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
      "command_line": "C:\\Program Files\\OneDrive\\OneDrive.exe", "signature_status": "Valid"}),
    ("RULE-002",
     {"artifact_type": "task", "name": "Sync", "task_name": "\\Sync", "command_line": "powershell.exe -enc SQBFAFgA"},
     {"artifact_type": "task", "name": "WinUpdate", "task_name": "\\Microsoft\\Windows\\Update\\Run", "command_line": "C:\\Windows\\System32\\sc.exe start wuauserv"}),
    ("RULE-003",
     {"artifact_type": "service", "name": "BadSvc", "command_line": "C:\\ProgramData\\svc.exe", "signature_status": "NotSigned"},
     {"artifact_type": "service", "name": "wuauserv", "command_line": "C:\\Windows\\System32\\svchost.exe -k netsvcs", "signature_status": "Valid"}),
    ("RULE-004",
     {"artifact_type": "startup", "name": "helper.lnk", "path": "C:\\Users\\a\\Startup\\helper.lnk", "command_line": "wscript.exe C:\\Windows\\Temp\\x.vbs"},
     {"artifact_type": "startup", "name": "app.lnk", "path": "C:\\ProgramData\\Start\\app.lnk", "command_line": "C:\\Program Files\\App\\app.exe", "signature_status": "Valid"}),
    ("RULE-005",
     {"artifact_type": "wmi_subscription", "name": "DiskQuotaConsumerV1", "command_line": "cmd.exe /c x.cmd"},
     {"artifact_type": "wmi_subscription", "name": "SCM Event Log Consumer", "command_line": ""}),
    ("RULE-006",
     {"artifact_type": "process", "name": "certutil.exe", "path": "C:\\Windows\\System32\\certutil.exe",
      "command_line": "certutil.exe -f -decode a.b64 a.ps1", "signature_status": "Valid"},
     {"artifact_type": "process", "name": "certutil.exe", "path": "C:\\Windows\\System32\\certutil.exe",
      "command_line": "certutil.exe -store My", "signature_status": "Valid"}),
    ("RULE-007",
     {"artifact_type": "process", "name": "powershell.exe", "path": "C:\\Windows\\System32\\powershell.exe",
      "command_line": "powershell.exe -NoProfile -enc SQBFAFgA", "signature_status": "Valid"},
     {"artifact_type": "process", "name": "powershell.exe", "path": "C:\\Windows\\System32\\powershell.exe",
      "command_line": "powershell.exe -NoProfile -Command Get-Date", "signature_status": "Valid"}),
    ("RULE-008",
     {"artifact_type": "file", "name": "version.dll", "path": "C:\\Users\\Public\\side\\version.dll", "signature_status": "NotSigned"},
     {"artifact_type": "file", "name": "7z.exe", "path": "C:\\Program Files\\7-Zip\\7z.exe", "signature_status": "Valid"}),
    ("RULE-009",
     {"artifact_type": "file", "name": "svchost.exe", "path": "C:\\ProgramData\\svchost.exe", "attributes": "Hidden, Archive"},
     {"artifact_type": "file", "name": "desktop.ini", "path": "C:\\Users\\Public\\desktop.ini", "attributes": "Hidden, System"}),
    ("RULE-010",
     {"artifact_type": "file", "name": "svchost.exe", "path": "C:\\ProgramData\\svchost.exe", "signature_status": "Valid"},
     {"artifact_type": "file", "name": "svchost.exe", "path": "C:\\Windows\\System32\\svchost.exe", "signature_status": "Valid"}),
    ("RULE-011",
     {"artifact_type": "registry", "name": "(Default)", "registry_key": "HKU\\S-1\\Software\\Classes\\ms-settings\\shell\\open\\command", "registry_value": "x.cmd"},
     {"artifact_type": "registry", "name": "Shell", "registry_key": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "registry_value": "explorer.exe"}),
    ("RULE-012",
     {"artifact_type": "registry", "name": "Debugger", "registry_key": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\utilman.exe", "registry_value": "x.cmd"},
     {"artifact_type": "registry", "name": "Userinit", "registry_key": "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "registry_value": "C:\\Windows\\system32\\userinit.exe,"}),
    ("RULE-013",
     {"artifact_type": "account", "name": "svc_maint_v1", "raw": {"is_admin": True, "enabled": True}},
     {"artifact_type": "account", "name": "Administrator", "raw": {"is_admin": True, "enabled": True}}),
    ("RULE-014",
     {"artifact_type": "registry", "name": "DisableRealtimeMonitoring", "registry_key": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "registry_value": "1"},
     {"artifact_type": "registry", "name": "DisableRealtimeMonitoring", "registry_key": "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection", "registry_value": "0"}),
    ("RULE-015",
     {"artifact_type": "file", "name": "sweep.ps1", "path": "C:\\Users\\Public\\sweep.ps1", "signature_status": "NotSigned"},
     {"artifact_type": "file", "name": "readme.txt", "path": "C:\\Users\\Public\\readme.txt"}),
])
def test_each_deterministic_rule_positive_and_negative(rule_id, pos_row, neg_row):
    pos_ids = {m.rule_id for m in R.evaluate_row(pos_row)}
    neg_ids = {m.rule_id for m in R.evaluate_row(neg_row)}
    assert rule_id in pos_ids, f"{rule_id} failed to fire on {pos_row}"
    assert rule_id not in neg_ids, f"{rule_id} falsely fired on {neg_row}"


# ---------------- Labeler, baseline diff, deduplication, split assignment ----------------
def _write_run(raw_dir: Path, prov_dir: Path, run_id: str, artifacts: list[dict], prov: list[dict]) -> None:
    rdir = raw_dir / run_id
    rdir.mkdir(parents=True, exist_ok=True)
    (rdir / "artifacts.json").write_text(json.dumps(artifacts), encoding="utf-8")
    (rdir / "manifest.json").write_text(json.dumps({"run_id": run_id, "total_records": len(artifacts)}), encoding="utf-8")
    prov_dir.mkdir(parents=True, exist_ok=True)
    (prov_dir / f"{run_id}.jsonl").write_text("\n".join(json.dumps(p) for p in prov) + "\n", encoding="utf-8")


def _base_service(collected_utc: str = "2026-11-21T00:00:00Z") -> dict:
    return {
        "artifact_type": "service",
        "artifact_key": "service|hklm\\system\\currentcontrolset\\services\\wuauserv|wuauserv",
        "name": "wuauserv",
        "path": "C:\\Windows\\System32\\svchost.exe",
        "command_line": "C:\\Windows\\system32\\svchost.exe -k netsvcs",
        "registry_key": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\wuauserv",
        "signature_status": "Valid",
        "attributes": "Archive",
        "file_size": 50000,
        "start_mode": "Manual",
        "collected_utc": collected_utc,
        "pid": 100,
    }


def test_labeler_end_to_end_diff_dedupe_and_no_leakage(tmp_path):
    raw_dir = tmp_path / "raw"
    prov_dir = tmp_path / "prov"
    proc_dir = tmp_path / "processed"
    splits_dir = tmp_path / "splits"

    # Two control boots (with different collected_utc & pid, same content -> must dedupe to baseline)
    _write_run(raw_dir, prov_dir, "ctrl_01", [_base_service("2026-11-21T01:00:00Z")],
               [{"run_id": "ctrl_01", "launcher": "control", "timestamp_utc": "2026-11-21T01:00:00Z"}])
    _write_run(raw_dir, prov_dir, "ctrl_02", [_base_service("2026-11-21T01:05:00Z")],
               [{"run_id": "ctrl_02", "launcher": "control", "timestamp_utc": "2026-11-21T01:05:00Z"}])

    # Dev run (T1547.001) with baseline, benign_drift, sshd + wrapper PID footprint, and attack row
    run_dev_arts = [
        _base_service("2026-11-21T02:00:00Z"),
        {"artifact_type": "process", "artifact_key": "process|c:\\programdata\\ssh\\sshd.exe|sshd.exe",
         "name": "sshd.exe", "path": "C:\\ProgramData\\ssh\\sshd.exe", "pid": 500},
        {"artifact_type": "process", "artifact_key": "process|pid#999|powershell.exe",
         "name": "powershell.exe", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "pid": 999},
        {"artifact_type": "file", "artifact_key": "file|c:\\users\\public\\documents\\notes_01.txt|notes_01.txt",
         "name": "notes_01.txt", "path": "C:\\Users\\Public\\Documents\\notes_01.txt", "file_size": 40,
         "created_utc": "2026-11-21T02:00:05Z", "modified_utc": "2026-11-21T02:00:05Z"},
        {"artifact_type": "run_key", "artifact_key": "run_key|hku\\s-1-5-21-9\\software\\microsoft\\windows\\currentversion\\run|desktopsyncagent",
         "name": "DesktopSyncAgent", "registry_key": "HKU\\S-1-5-21-9\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
         "command_line": "powershell.exe -NoProfile -File C:\\Users\\Public\\desktop_sync_v1.ps1",
         "registry_value": "powershell.exe -NoProfile -File C:\\Users\\Public\\desktop_sync_v1.ps1",
         "created_utc": "2026-11-21T02:00:06Z"},
    ]
    run_dev_prov = [
        {"run_id": "run_004_T1547_001_v1", "launcher": "benign", "wrapper_pid": 999,
         "timestamp_utc": "2026-11-21T02:00:00Z", "action": "workspace_doc",
         "expected_artifact_keys": ["file|c:\\users\\public\\documents\\notes_01.txt|notes_01.txt"]},
        {"run_id": "run_004_T1547_001_v1", "launcher": "attack", "wrapper_pid": 998,
         "technique_id": "T1547.001", "variant": 1, "timestamp_utc": "2026-11-21T02:00:10Z",
         "action": "stage_payload_and_run_key",
         "expected_artifact_keys": ["run_key|hku|desktopsyncagent"]},
    ]
    _write_run(raw_dir, prov_dir, "run_004_T1547_001_v1", run_dev_arts, run_dev_prov)

    # Holdout run (T1036.005)
    run_hold_arts = [
        _base_service("2026-11-21T03:00:00Z"),
        {"artifact_type": "file", "artifact_key": "file|c:\\users\\public\\report.pdf.exe|report.pdf.exe",
         "name": "report.pdf.exe", "path": "C:\\Users\\Public\\report.pdf.exe",
         "signature_status": "NotSigned", "attributes": "Hidden, Archive", "file_size": 1024,
         "created_utc": "2026-11-21T03:00:05Z"},
    ]
    run_hold_prov = [
        {"run_id": "run_005_T1036_005_v2", "launcher": "attack", "wrapper_pid": 888,
         "technique_id": "T1036.005", "variant": 2, "timestamp_utc": "2026-11-21T03:00:10Z",
         "action": "masquerade_double_ext_v2",
         "expected_artifact_keys": ["file|c:\\users\\public\\report.pdf.exe|report.pdf.exe"]},
    ]
    _write_run(raw_dir, prov_dir, "run_005_T1036_005_v2", run_hold_arts, run_hold_prov)

    run_table = tmp_path / "run_table.csv"
    pd.DataFrame([
        {"run_id": "ctrl_01", "technique": "CONTROL", "variant": 0, "status": "success"},
        {"run_id": "ctrl_02", "technique": "CONTROL", "variant": 0, "status": "success"},
        {"run_id": "run_004_T1547_001_v1", "technique": "T1547.001", "variant": 1, "status": "success"},
        {"run_id": "run_005_T1036_005_v2", "technique": "T1036.005", "variant": 2, "status": "success"},
    ]).to_csv(run_table, index=False)

    res = labeler.build_dataset(
        raw_runs_dir=raw_dir,
        provenance_dir=prov_dir,
        techniques_yaml=config.TECHNIQUES_YAML,
        run_table_csv=run_table,
        processed_dir=proc_dir,
        splits_dir=splits_dir,
        baseline_snapshot_utc="2026-11-21T01:10:00Z",
    )
    ds = res["dataset"]
    # Runner footprint dropped (sshd.exe & pid=999 gone)
    assert "sshd.exe" not in set(ds["name"])
    assert "process|pid#999|powershell.exe" not in set(ds["artifact_key"])
    # Baseline deduplicated across 4 runs to 1 row
    base_rows = ds[ds["label"] == "baseline"]
    assert len(base_rows) == 1
    assert base_rows.iloc[0]["seen_count"] == 4
    # 1 benign_drift + 2 attacker_induced (1 dev, 1 test)
    assert len(ds[ds["label"] == "benign_drift"]) == 1
    pos = ds[ds["label"] == "attacker_induced"]
    assert len(pos) == 2
    assert set(pos["split_pool"]) == {"dev", "test"}
    # Oracle + rule columns stored but separate from FEATURES
    for col in config.FEATURES + config.ORACLE_FEATURES + config.RULE_FEATURES:
        assert col in ds.columns
    # Parquet + manifest + review sample exist
    assert res["parquet_path"].exists()
    assert res["review_path"].exists()
    assert len(pd.read_parquet(res["parquet_path"])) == len(ds)
    assert res["manifest"]["test_positives"] == 1
    rev = pd.read_csv(res["review_path"])
    assert len(rev) == 2   # ceil(0.1 * 2) = 1 attack + 1 drift


def test_labeler_rejects_forbidden_tokens(tmp_path):
    df = pd.DataFrame([{"artifact_key": "file|x|Atomic_Test_1.exe", "artifact_type": "file", "name": "Atomic_Test_1.exe"}])
    with pytest.raises(SanitizationError):
        labeler.label_run(df, {}, [], run_id="r1", sanitization_report=tmp_path / "fail.csv")


def test_label_does_not_depend_on_timestamps_or_rules():
    # A clean harmless row inside the attack time window without attack provenance -> benign_drift, NOT attacker_induced
    df = pd.DataFrame([{
        "artifact_type": "file",
        "artifact_key": "file|c:\\users\\public\\harmless.ps1|harmless.ps1",
        "name": "harmless.ps1",
        "path": "C:\\Users\\Public\\harmless.ps1",
        "signature_status": "NotSigned",
        "created_utc": "2026-11-21T02:00:05Z",
    }])
    out = labeler.label_run(
        df, baseline_index={}, provenance_rows=[{
            "launcher": "attack", "timestamp_utc": "2026-11-21T02:00:00Z", "expected_artifact_keys": ["file|other|other"],
        }],
        run_id="r1",
    )
    # Even though RULE-015 would fire on a .ps1 in C:\Users\Public and timestamp is in window, label must be benign_drift
    assert R.evaluate_row(df.iloc[0])
    assert out.iloc[0]["label"] == "benign_drift"
