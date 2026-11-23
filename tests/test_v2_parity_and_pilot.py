"""Unit tests for clean-image feature parity comparator (`scripts/compare_v1_v2_parity.py`),
Stage A pilot orchestrator (`src/v2/run_stage_a_pilot.py`), and base-image bake artifacts (`00_bake_v2_base_image.sh`).
"""
from __future__ import annotations

import hashlib
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from scripts.compare_v1_v2_parity import compare_v1_v2_feature_parity, format_parity_markdown
from src import config
from src.v2.pilot_staging import PilotStagingError, StageRunSpec
from src.v2.run_stage_a_pilot import (
    compute_od_v2_20_pilot_gate,
    evaluate_stage_a_pilot_runs,
    write_stage_a_pilot_report,
)


def test_clean_image_parity_comparator_pass_and_fail():
    v1_live = [
        {
            "artifact_type": "process",
            "artifact_key": "process|svchost.exe|1234",
            "name": "svchost.exe",
            "parent_name": "services.exe",
            "path": r"C:\Windows\System32\svchost.exe",
        },
        {
            "artifact_type": "service",
            "artifact_key": r"service|hklm\system\currentcontrolset\services\bits|bits",
            "name": "BITS",
            "path": r"C:\Windows\System32\svchost.exe",
            "command_line": r"C:\Windows\System32\svchost.exe -k netsvcs",
            "registry_key": r"HKLM\SYSTEM\CurrentControlSet\Services\BITS",
            "start_mode": "Auto",
            "signature_status": "Valid",
            "file_size": 88232,
            "file_head_histogram": [344] * 256,
        },
        {
            "artifact_type": "run_key",
            "artifact_key": r"run_key|hklm\software\microsoft\windows\currentversion\run|securityhealth",
            "name": "SecurityHealth",
            "path": r"C:\Windows\system32\SecurityHealthSystray.exe",
            "command_line": r"%windir%\system32\SecurityHealthSystray.exe",
            "registry_key": r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "registry_value": r"%windir%\system32\SecurityHealthSystray.exe",
            "signature_status": "Valid",
            "file_size": 102400,
            "file_head_histogram": [400] * 256,
        },
    ]
    v2_offline = [dict(r) for r in v1_live if r["artifact_type"] != "process"]
    rep = compare_v1_v2_feature_parity(v1_live, v2_offline)
    assert rep["overall_status"] == "PASS"
    assert rep["v2_process_rows"] == 0
    assert rep["v2_parent_process_all_na"] is True
    md = format_parity_markdown(rep)
    assert "Overall Verdict:** **`PASS`**" in md

    # Inject a process row into v2_offline -> parent_process_class check must FAIL
    bad_v2 = v2_offline + [dict(v1_live[0])]
    bad_rep = compare_v1_v2_feature_parity(v1_live, bad_v2)
    assert bad_rep["overall_status"] == "FAIL"


def test_bake_scripts_exist_and_have_valid_syntax():
    repo = Path(__file__).resolve().parent.parent
    sh_path = repo / "docs" / "v2" / "hardening" / "00_bake_v2_base_image.sh"
    ps_path = repo / "docs" / "v2" / "hardening" / "Install-V2BaseBootstrap.ps1"
    assert sh_path.exists() and ps_path.exists()
    ps_txt = ps_path.read_text(encoding="utf-8")
    assert "Microsoft-Windows-Sysmon/Operational" in ps_txt
    assert "67108864" in ps_txt
    assert "\\DFIR-StageRunner" in ps_txt
    assert 'Set-Service -Name "sshd" -StartupType Disabled' in ps_txt


def test_stage_a_pilot_orchestrator_gate0_od_v2_20_and_power_calibration(tmp_path):
    ctrl_rows = [
        {
            "run_id": "ctrl_01",
            "artifact_type": "file",
            "artifact_key": r"file|c:\windows\system32\svchost.exe|svchost.exe",
            "name": "svchost.exe",
            "path": r"C:\Windows\System32\svchost.exe",
            "signature_status": "Valid",
            "file_size": 88232,
            "file_head_histogram": [344] * 256,
        },
        {
            "run_id": "ctrl_01",
            "artifact_type": "service",
            "artifact_key": r"service|hklm\system\currentcontrolset\services\bits|bits",
            "name": "BITS",
            "path": r"C:\Windows\System32\svchost.exe",
            "command_line": r"C:\Windows\System32\svchost.exe -k netsvcs",
            "registry_key": r"HKLM\SYSTEM\CurrentControlSet\Services\BITS",
            "start_mode": "Auto",
            "signature_status": "Valid",
            "file_size": 88232,
            "file_head_histogram": [344] * 256,
        },
    ]
    ctrl_df = pd.DataFrame(ctrl_rows)

    pilot_runs = []
    families = ["fam_one", "fam_two", "fam_three", "fam_four"]
    for idx, fam in enumerate(families):
        sha = hashlib.sha256(f"sample_{fam}".encode()).hexdigest()
        pair_id = f"pair_{fam}"
        staged_path = rf"C:\Users\Public\Downloads\{fam}_agent.exe"

        for st in ("dormant", "executed"):
            spec = StageRunSpec(
                run_id=f"pilot_{fam}_{st}",
                stratum=st,
                benign_profile_id=f"dev_prof_{idx}",
                dwell_seconds=60,
                staging_target_path=staged_path,
                sample_sha256=sha,
                sample_family=fam,
                pair_group_id=pair_id,
                execute_payload=(st == "executed"),
                gate0_signed_off=True,
                dedicated_host_user_verified=True,
            )
            run_rows = [dict(r, run_id=spec.run_id) for r in ctrl_rows]
            # Staged binary row
            run_rows.append({
                "run_id": spec.run_id,
                "artifact_type": "file",
                "artifact_key": f"file|{staged_path.lower()}|{fam}_agent.exe",
                "name": f"{fam}_agent.exe",
                "path": staged_path,
                "signature_status": "NotSigned",
                "file_size": 245760 + idx * 4096,
                "file_head_histogram": [960] * 256,
                "file_sha256": sha,
                "attributes": 2,
            })
            sysmon_evs = []
            if st == "executed":
                # Persistence service created by executed binary
                run_rows.append({
                    "run_id": spec.run_id,
                    "artifact_type": "service",
                    "artifact_key": f"service|hklm\\system\\currentcontrolset\\services\\{fam}svc|{fam}svc",
                    "name": f"{fam}svc",
                    "path": staged_path,
                    "command_line": f"{staged_path} --daemon -enc AAAA",
                    "registry_key": rf"HKLM\SYSTEM\CurrentControlSet\Services\{fam}svc",
                    "service_name": f"{fam}svc",
                    "start_mode": "Auto",
                    "signature_status": "NotSigned",
                    "file_size": 245760 + idx * 4096,
                    "file_head_histogram": [960] * 256,
                    "file_sha256": sha,
                })
                sysmon_evs = [
                    {
                        "event_id": 1,
                        "process_guid": f"{{guid-{fam}-root}}",
                        "pid": 4000 + idx,
                        "image": staged_path,
                        "hashes": f"SHA256={sha}",
                    },
                    {
                        "event_id": 13,
                        "process_guid": f"{{guid-{fam}-root}}",
                        "pid": 4000 + idx,
                        "target_object": rf"HKLM\SYSTEM\CurrentControlSet\Services\{fam}svc\ImagePath",
                    },
                ]
            pilot_runs.append({
                "spec": spec,
                "df": pd.DataFrame(run_rows),
                "sysmon_events": sysmon_evs,
                "malware_root_guids": [f"{{guid-{fam}-root}}"] if st == "executed" else [],
            })

    summary = evaluate_stage_a_pilot_runs(
        control_runs=[ctrl_df],
        pilot_runs=pilot_runs,
        arms=("rf", "iforest"),
        n_outer=2,
        n_inner=2,
        n_trials=2,
        seed=42,
    )
    assert summary["od_v2_20_gate"]["computed_before_model_scoring"] is True
    assert summary["od_v2_20_gate"]["gate_passed"] is True
    assert summary["od_v2_20_gate"]["v2_refgraph_status"] == "confirmatory_secondary"
    assert summary["executed_detonation_success_rate_pct"] == 100.0
    assert summary["statistical_power_calibration"]["n_pilot_families"] == 4
    assert set(summary["statistical_power_calibration"]["mde_by_f_test"].keys()) == {10, 12, 15}

    rep_path = write_stage_a_pilot_report(summary, tmp_path / "STAGE_A_PILOT_REPORT.md")
    assert rep_path.exists()
    assert "OD-V2-20" in rep_path.read_text()

    # Unsigned Gate 0 run must raise PilotStagingError before any evaluation proceeds
    unsigned_run = dict(pilot_runs[0])
    unsigned_run["spec"] = StageRunSpec(
        run_id="unsigned_01",
        stratum="executed",
        benign_profile_id="dev_prof_0",
        staging_target_path=r"C:\Users\Public\Downloads\bad.exe",
        sample_sha256="a" * 64,
        pair_group_id="pair_bad",
        execute_payload=True,
        gate0_signed_off=False,
        dedicated_host_user_verified=True,
    )
    with pytest.raises(PilotStagingError, match="Gate 0 .* is NOT signed off"):
        evaluate_stage_a_pilot_runs([ctrl_df], [unsigned_run])
