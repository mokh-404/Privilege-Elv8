"""Tests for read-only v1 DEV referential-graph feasibility audit (Step E4)."""
from __future__ import annotations

import pandas as pd
import pytest

from src.v2.refgraph_audit import extract_row_static_pointers, load_v1_dev_only, run_v1_dev_feasibility_audit


def test_audit_refuses_non_dev_rows():
    df = pd.DataFrame([
        {"split_pool": "dev", "artifact_type": "file", "artifact_key": "file|a|a", "name": "a", "path": "C:\\a.exe"},
        {"split_pool": "test", "artifact_type": "file", "artifact_key": "file|b|b", "name": "b", "path": "C:\\b.exe"},
    ])
    with pytest.raises(ValueError, match="non-dev"):
        run_v1_dev_feasibility_audit(df)


def test_synthetic_dev_pointer_resolution_counts_unique_ambiguous_dangling():
    df = pd.DataFrame([
        {
            "split_pool": "dev", "run_id": "r1", "artifact_type": "file",
            "artifact_key": "file|c:\\users\\public\\u.ps1|u.ps1",
            "name": "u.ps1", "path": "C:\\Users\\Public\\u.ps1",
            "command_line": "", "registry_key": "", "registry_value": "", "file_sha256": "abc",
        },
        {
            "split_pool": "dev", "run_id": "r1", "artifact_type": "run_key",
            "artifact_key": "run_key|hku\\run|updater",
            "name": "Updater", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": "powershell.exe -File C:\\Users\\Public\\u.ps1",
            "registry_key": "HKU\\Run", "registry_value": "powershell.exe -File C:\\Users\\Public\\u.ps1", "file_sha256": "ps",
        },
        {
            "split_pool": "dev", "run_id": "r1", "artifact_type": "task",
            "artifact_key": "task|\\ms\\comtask|comtask",
            "name": "ComTask", "path": None, "command_line": "COM:{11111111-2222-3333-4444-555555555555}",
            "registry_key": "", "registry_value": "", "file_sha256": None,
        },
        {
            "split_pool": "dev", "run_id": "r1", "artifact_type": "prefetch",
            "artifact_key": "prefetch|c:\\windows\\prefetch\\tool.exe-1234abcd.pf|tool.exe-1234abcd.pf",
            "name": "TOOL.EXE-1234ABCD.pf", "path": "C:\\Windows\\Prefetch\\TOOL.EXE-1234ABCD.pf",
            "command_line": "", "registry_key": "", "registry_value": "", "file_sha256": "pfh",
        },
        {
            "split_pool": "dev", "run_id": "r1", "artifact_type": "wmi_subscription",
            "artifact_key": 'wmi_subscription|root\\subscription\\__eventfilter|flt1',
            "name": "Flt1", "path": None, "command_line": "SELECT * FROM Win32_Process",
            "registry_key": "", "registry_value": "", "file_sha256": None,
        },
        {
            "split_pool": "dev", "run_id": "r1", "artifact_type": "wmi_subscription",
            "artifact_key": 'wmi_subscription|root\\subscription\\commandlineeventconsumer|con1',
            "name": "Con1", "path": "C:\\Users\\Public\\u.ps1", "command_line": "C:\\Users\\Public\\u.ps1",
            "registry_key": "", "registry_value": "", "file_sha256": None,
        },
        {
            "split_pool": "dev", "run_id": "r1", "artifact_type": "wmi_subscription",
            "artifact_key": 'wmi_subscription|root\\subscription\\__filtertoconsumerbinding|__eventfilter (name = "flt1")->commandlineeventconsumer (name = "con1")',
            "name": '__EventFilter (Name = "Flt1")->CommandLineEventConsumer (Name = "Con1")',
            "path": None, "command_line": "", "registry_key": "", "registry_value": "", "file_sha256": None,
        },
    ])
    rep = run_v1_dev_feasibility_audit(df, include_live_process=False)
    assert rep["n_dev_rows_audited"] == 7
    assert rep["total_resolved_links"] == 4  # run_key->u.ps1, con1->u.ps1, binding->flt1, binding->con1
    by_t = {r["artifact_type"]: r for r in rep["per_artifact_type"]}
    assert by_t["run_key"]["rows_with_resolved_outgoing"] == 1
    assert by_t["file"]["rows_with_resolved_incoming"] == 1
    assert by_t["file"]["incoming_link_count"] == 2
    assert by_t["task"]["dangling_pointer_count"] == 1
    assert by_t["prefetch"]["dangling_pointer_count"] == 1


def test_real_v1_dev_loader_never_exposes_test_pool():
    dev_df = load_v1_dev_only()
    assert len(dev_df) == 1179
    assert set(dev_df["split_pool"].astype(str)) == {"dev"}
    rep = run_v1_dev_feasibility_audit(dev_df, include_live_process=False)
    assert rep["n_dev_rows_audited"] == 1104  # 1179 dev rows - 75 live process rows
