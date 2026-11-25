"""Unit tests for clean-image feature parity comparator (`scripts/compare_v1_v2_parity.py`),
Stage A pilot orchestrator (`src/v2/run_stage_a_pilot.py`), and base-image bake artifacts (`00_bake_v2_base_image.sh`).
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import shutil
import subprocess

import numpy as np
import pandas as pd
import pytest

from scripts.compare_v1_v2_parity import compare_v1_v2_feature_parity, format_parity_markdown
from src import config
from src.v2.benign_generator_v2 import _synth_unsigned_pe_bytes
from src.v2.labeler_v2 import drop_v2_harness_footprint
from src.v2.offline_extractor import (
    expand_target_like_v1,
    extract_from_fixture,
    is_v2_harness_footprint_record,
    write_outputs,
)
from src.v2.pilot_staging import (
    PilotStagingError,
    StageRunSpec,
    assert_allowed_malware_policy,
    build_clean_parity_stage_iso,
    build_dormant_batch_bundle,
    validate_stage_run_spec,
)
from src.v2.run_stage_a_pilot import (
    _select_canary_subset,
    build_container_extraction_command,
    build_create_overlay_command,
    compute_od_v2_20_pilot_gate,
    evaluate_egress_delta,
    evaluate_stage_a_pilot_runs,
    execute_stage_a_pilot_batch,
    verify_canary_run_outputs,
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
    sh_txt = sh_path.read_text(encoding="utf-8")
    assert "prepare-overlay)" in sh_txt
    assert "qemu-img commit" in sh_txt
    assert "chown 956:956" in sh_txt
    assert "rel_base" in sh_txt
    assert "open_qcow2_target_readonly" in sh_txt
    assert "build_stage_iso" in sh_txt
    ps_txt = ps_path.read_text(encoding="utf-8")
    assert "Microsoft-Windows-Sysmon/Operational" in ps_txt
    assert "67108864" in ps_txt
    assert "\\DFIR-StageRunner" in ps_txt
    assert 'Set-Service -Name "sshd" -StartupType Disabled' in ps_txt

    cmd = build_create_overlay_command(
        "/var/lib/libvirt/images/win11_base.qcow2",
        "/var/lib/libvirt/images/win11_overlay.qcow2",
    )
    assert cmd[:7] == ["qemu-img", "create", "-f", "qcow2", "-F", "qcow2", "-b"]
    assert cmd[7] == "win11_base.qcow2"
    assert cmd[8] == "/var/lib/libvirt/images/win11_overlay.qcow2"


def test_zero_ssh_parity_iso_builder_and_v2_harness_footprint_filtering(tmp_path):
    # 1. Verify zero-SSH parity ISO packages Collect-Artifacts.ps1 into DFIR_STAGE ISO with full long filenames
    bundle = build_clean_parity_stage_iso(tmp_path / "parity_iso_dir")
    assert bundle["iso"].exists() and bundle["collector_ps1"].exists()
    iso_bytes = bundle["iso"].read_bytes()
    assert b"CD001" in iso_bytes
    assert b"COLLECT.PS1" in iso_bytes
    assert "C:\\collector_out_parity" in bundle["benign_workload"].read_text(encoding="utf-8")

    xorriso_bin = shutil.which("xorriso")
    assert xorriso_bin is not None
    cp = subprocess.run([xorriso_bin, "-indev", str(bundle["iso"]), "-ls", "/"], capture_output=True, text=True, check=True)
    for expected in ("run_manifest.json", "benign_workload.ps1", "Invoke-StagePayload.ps1", "COLLECT.PS1"):
        assert expected in cp.stdout

    # 2. Verify v2 harness footprint filtering in both offline_extractor and labeler_v2
    harness_and_real = [
        {
            "artifact_type": "file",
            "artifact_key": r"file|c:\windows\system32\svchost.exe|svchost.exe",
            "name": "svchost.exe",
            "path": r"C:\Windows\System32\svchost.exe",
        },
        {
            "artifact_type": "task",
            "artifact_key": r"task|\|dfir-stagerunner",
            "name": "DFIR-StageRunner",
            "task_name": r"\DFIR-StageRunner",
            "command_line": r"powershell.exe -File C:\DFIR-Bootstrap\Invoke-StagePayload.ps1",
        },
        {
            "artifact_type": "file",
            "artifact_key": r"file|c:\dfir-bootstrap\invoke-stagepayload.ps1|invoke-stagepayload.ps1",
            "name": "Invoke-StagePayload.ps1",
            "path": r"C:\DFIR-Bootstrap\Invoke-StagePayload.ps1",
        },
        {
            "artifact_type": "file",
            "artifact_key": r"file|c:\collector_out_parity\artifacts.json|artifacts.json",
            "name": "artifacts.json",
            "path": r"C:\collector_out_parity\artifacts.json",
        },
        {
            "artifact_type": "service",
            "artifact_key": r"service|hklm\system\currentcontrolset\services\sysmon64|sysmon64",
            "name": "Sysmon64",
            "service_name": "Sysmon64",
            "path": r"C:\Windows\Sysmon64.exe",
            "registry_key": r"HKLM\SYSTEM\CurrentControlSet\Services\Sysmon64",
        },
        {
            "artifact_type": "file",
            "artifact_key": r"file|c:\windows\sysmon64.exe|sysmon64.exe",
            "name": "Sysmon64.exe",
            "path": r"C:\Windows\Sysmon64.exe",
        },
        {
            "artifact_type": "file",
            "artifact_key": r"file|c:\windows\system32\drivers\sysmondrv.sys|sysmondrv.sys",
            "name": "SysmonDrv.sys",
            "path": r"C:\Windows\System32\drivers\SysmonDrv.sys",
        },
        {
            "artifact_type": "prefetch",
            "artifact_key": r"prefetch|c:\windows\prefetch\sysmon64.exe-12345678.pf|sysmon64.exe-12345678.pf",
            "name": "SYSMON64.EXE-12345678.pf",
            "path": r"C:\Windows\Prefetch\SYSMON64.EXE-12345678.pf",
            "pf_executable_name": "SYSMON64.EXE",
        },
    ]
    kept, summary = extract_from_fixture(harness_and_real, run_id="harness_filter_test")
    assert len(kept) == 1
    assert kept[0]["name"] == "svchost.exe"
    assert summary["v2_harness_footprint_dropped_count"] == 7
    out_paths = write_outputs(kept, summary, tmp_path / "ext_out")
    assert out_paths["dropped_csv"].exists()
    dropped_df = pd.read_csv(out_paths["dropped_csv"])
    assert len(dropped_df) == 7

    # Also verify labeler_v2 drop_v2_harness_footprint filters all 7 and writes to a v2 audit CSV
    v2_log = tmp_path / "v2_runner_footprint_dropped.csv"
    kept_l, dropped_l = drop_v2_harness_footprint(pd.DataFrame(harness_and_real), log_path=v2_log)
    assert len(kept_l) == 1
    assert len(dropped_l) == 7
    assert v2_log.exists()

    # Refuses to overwrite frozen v1 RUNNER_FOOTPRINT_LOG_CSV
    with pytest.raises(ValueError, match="Refusing to overwrite frozen v1"):
        drop_v2_harness_footprint(pd.DataFrame(harness_and_real), log_path=config.RUNNER_FOOTPRINT_LOG_CSV)

    # 3. Verify v1 Extract-TargetPath semantics on quoted args and comma-terminated Winlogon Userinit
    assert expand_target_like_v1(r'"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe" /svc') == r"C:\Program Files (x86)\Microsoft\EdgeUpdate\MicrosoftEdgeUpdate.exe"
    assert expand_target_like_v1(r'"C:\Users\mokh\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background') == r"C:\Users\mokh\AppData\Local\Microsoft\OneDrive\OneDrive.exe"
    assert expand_target_like_v1(r"C:\WINDOWS\system32\userinit.exe,") == r"C:\WINDOWS\system32\userinit.exe"


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
    assert set(summary["statistical_power_calibration"]["mde_by_f_test"].keys()) == {10, 15, 22, 25}

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


def test_parity_workload_cli_matches_frozen_collect_artifacts_params(tmp_path):
    import re

    repo = Path(__file__).resolve().parent.parent
    collector_ps1 = (repo / "collector" / "Collect-Artifacts.ps1").read_text(encoding="utf-8")
    m_param = re.search(r"(?is)param\s*\((.*?)\n\)", collector_ps1)
    assert m_param is not None
    param_body = m_param.group(1)

    declared_params = {name.lower() for name in re.findall(r"\$([A-Za-z_][A-Za-z0-9_]*)", param_body)}
    declared_aliases = {alias.lower() for alias in re.findall(r'\[Alias\("([^"]+)"\)\]', param_body)}
    valid_flags = declared_params | declared_aliases
    assert "outdir" in valid_flags
    assert "runid" not in valid_flags

    bundle = build_clean_parity_stage_iso(tmp_path / "parity_cli_check")
    workload_txt = bundle["benign_workload"].read_text(encoding="utf-8")
    assert "parity_stdout.log" in workload_txt

    invoked_lines = [ln for ln in workload_txt.splitlines() if "$collectorScript" in ln and "powershell.exe" in ln]
    assert len(invoked_lines) == 1
    passed_flags = re.findall(r"(?<=\s)-([A-Za-z_][A-Za-z0-9_]*)\b", invoked_lines[0].split("$collectorScript", 1)[1])
    assert "OutDir" in passed_flags
    assert "RunId" not in passed_flags
    for flag in passed_flags:
        assert flag.lower() in valid_flags, f"Undeclared Collect-Artifacts.ps1 parameter -{flag}"

    cmd, env = build_container_extraction_command(
        "/var/lib/libvirt/images/win11_overlay.qcow2",
        "/tmp/pilot_out/run_01",
        "run_01",
    )
    assert cmd[0].endswith("06_unprivileged_container_runner.sh")
    assert cmd[1:] == [
        "/var/lib/libvirt/images/win11_overlay.qcow2",
        "/tmp/pilot_out/run_01",
        "run_01",
        "/var/lib/dfir-quarantine-vault/win11_base_cache.json.gz",
    ]
    assert env == {"BASE_CACHE_PATH": "/var/lib/dfir-quarantine-vault/win11_base_cache.json.gz"}


def test_unattended_pilot_batch_inetsim_lifecycle_and_vault_curator(tmp_path, monkeypatch):
    import json
    import os
    import subprocess
    from scripts.v2_curate_vault_manifest import curate_pilot_vault_and_batch

    repo = Path(__file__).resolve().parent.parent
    setup_script = repo / "docs" / "v2" / "hardening" / "05_quarantine_vault_setup.sh"
    bsdtar_bin = shutil.which("bsdtar")
    assert bsdtar_bin is not None

    vault_dir = tmp_path / "vault"
    subprocess.run(["bash", str(setup_script), "init"], env=dict(os.environ, VAULT_ROOT=str(vault_dir)), check=True)

    # Gate 0 must block curation until GATE0_SIGNED_OFF exists with 0400 mode & required fields
    with pytest.raises(PilotStagingError, match="Gate 0 sign-off marker missing"):
        curate_pilot_vault_and_batch(vault_root=vault_dir, setup_script=setup_script, target_families=6)

    marker = vault_dir / "GATE0_SIGNED_OFF"
    marker.write_text("SIGNED_BY_TEST\n", encoding="utf-8")
    with pytest.raises(PilotStagingError, match="Vault preflight check failed"):
        curate_pilot_vault_and_batch(vault_root=vault_dir, setup_script=setup_script, target_families=6)

    marker.write_text(
        "SIGNED_BY=Mokh\n"
        "DATE=2026-11-25\n"
        "SUPERVISOR_APPROVAL=Supervisor Marawan (AASTMT) 2026-11-25\n"
        "CONTAINMENT_CHECKS=NEG-01..NEG-10 PASS\n"
        "DEDICATED_USER_VERIFIED=true\n",
        encoding="utf-8",
    )
    os.chmod(marker, 0o400)

    # Missing ABUSECH_AUTH_KEY must fail cleanly when no client is injected
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    with pytest.raises(RuntimeError, match="ABUSECH_AUTH_KEY"):
        curate_pilot_vault_and_batch(vault_root=vault_dir, setup_script=setup_script, target_families=6)

    # Create 6 distinct valid PE32+ .exe AES-256 zip payloads (all allowed non-destructive families)
    families = [
        ("redline", "stealer", "exe", "RedLine"),
        ("lummac2", "stealer", "exe", "LummaC2"),
        ("smokeloader", "loader", "exe", "smokeloader"),
        ("asyncrat", "rat", "exe", "asyncrat"),
        ("xmrig", "miner", "exe", "xmrig"),
        ("amadey", "trojan", "exe", "persistence"),
    ]
    zips_by_sha: dict[str, bytes] = {}
    records_by_tag: dict[str, list[dict[str, object]]] = {}
    for idx, (fam, cat, ftype, query_tag) in enumerate(families):
        raw = _synth_unsigned_pe_bytes(seed=500 + idx, size_bytes=16384 + idx * 512, is_dll=False)
        sha = hashlib.sha256(raw).hexdigest()
        src_p = tmp_path / f"{fam}.exe"
        src_p.write_bytes(raw)
        zpath = tmp_path / f"{fam}.zip"
        subprocess.run(
            [
                bsdtar_bin,
                "--format",
                "zip",
                "--options",
                "zip:encryption=aes256",
                "--passphrase",
                "infected",
                "-cf",
                str(zpath),
                "-C",
                str(tmp_path),
                src_p.name,
            ],
            check=True,
            capture_output=True,
        )
        src_p.unlink()
        zips_by_sha[sha] = zpath.read_bytes()
        entry = {
            "sha256_hash": sha,
            "signature": fam,
            "file_name": f"{fam}.exe",
            "file_type": ftype,
            "file_size": len(raw),
            "imphash": f"{idx + 1:032x}",
            "tags": [fam, "persist", cat],
        }
        records_by_tag[query_tag] = [entry]
    # Add an Android APK, duplicate imphash, and forbidden lockbit ransomware candidate that must ALL be filtered out
    first_sha = next(iter(zips_by_sha))
    dup_raw = _synth_unsigned_pe_bytes(seed=999, size_bytes=18432, is_dll=False)
    dup_sha = hashlib.sha256(dup_raw).hexdigest()
    ransom_sha = hashlib.sha256(b"forbidden_lockbit").hexdigest()
    records_by_tag["stealer"] = [
        {
            "sha256_hash": hashlib.sha256(b"apk_skip").hexdigest(),
            "signature": "AndroidBad",
            "file_name": "app.apk",
            "file_type": "apk",
            "file_size": 50000,
        },
        {
            "sha256_hash": ransom_sha,
            "signature": "LockBit",
            "file_name": "lockbit.exe",
            "file_type": "exe",
            "file_size": 90000,
            "tags": ["ransomware"],
        },
        {
            "sha256_hash": dup_sha,
            "signature": "OtherDup",
            "file_name": "dup.exe",
            "file_type": "exe",
            "file_size": len(dup_raw),
            "imphash": f"{1:032x}",
        },
        *records_by_tag["RedLine"],
    ]

    class _FakeFeedClient:
        def query_tag(self, tag: str, limit: int = 50) -> list[dict[str, object]]:
            return list(records_by_tag.get(tag, records_by_tag.get(tag.lower(), [])))

        def download_sample_zip(self, sha256_hash: str) -> bytes:
            return zips_by_sha[sha256_hash.lower()]

    cur = curate_pilot_vault_and_batch(
        vault_root=vault_dir,
        setup_script=setup_script,
        target_families=6,
        min_families=6,
        n_control_boots=3,
        dwell_seconds=45,
        client=_FakeFeedClient(),
    )
    assert cur["n_families"] == 6
    assert cur["n_total_runs"] == 15  # 3 controls + 6 * (executed + dormant)
    assert "lockbit" not in set(cur["families"])
    batch_payload = json.loads(Path(cur["batch_path"]).read_text(encoding="utf-8"))
    runs = batch_payload["runs"]

    # Pick 1 control + 1 dormant + 1 executed run and exercise unattended execution + inetsim-vm lifecycle
    subset = [
        runs[0],
        next(r for r in runs if r["spec"]["stratum"] == "dormant"),
        next(r for r in runs if r["spec"]["stratum"] == "executed"),
    ]
    recorded: list[list[str]] = []

    def _mock_cmd(cmd: list[str], env_over=None) -> int:
        recorded.append(list(cmd))
        return 0

    res = execute_stage_a_pilot_batch(
        batch_runs=subset,
        runs_out_dir=tmp_path / "pilot_runs_out",
        vault_root=vault_dir,
        inetsim_wait_seconds=0,
        run_cmd=_mock_cmd,
        sleep_fn=lambda _s: None,
    )
    assert [r["inetsim_booted"] for r in res] == [False, False, True]
    inetsim_starts = [i for i, c in enumerate(recorded) if c == ["sudo", "virsh", "-c", "qemu:///system", "start", "inetsim-vm"]]
    inetsim_destroys = [i for i, c in enumerate(recorded) if c == ["sudo", "virsh", "-c", "qemu:///system", "destroy", "inetsim-vm"]]
    win_starts = [i for i, c in enumerate(recorded) if c == ["sudo", "virsh", "-c", "qemu:///system", "start", "win11"]]
    assert len(inetsim_starts) == 1 and len(inetsim_destroys) == 1
    assert inetsim_starts[0] < win_starts[2] < inetsim_destroys[0]

    # Verify abort cleanup destroys inetsim-vm and disarms watchdog even if watchdog aborts win11
    recorded_abort: list[list[str]] = []

    def _abort_cmd(cmd: list[str], env_over=None) -> int:
        recorded_abort.append(list(cmd))
        if "watchdog" in cmd:
            return 2
        return 0

    with pytest.raises(RuntimeError, match="Watchdog aborted"):
        execute_stage_a_pilot_batch(
            batch_runs=[subset[2]],
            runs_out_dir=tmp_path / "pilot_abort_out",
            vault_root=vault_dir,
            inetsim_wait_seconds=0,
            run_cmd=_abort_cmd,
            sleep_fn=lambda _s: None,
        )
    assert ["sudo", "virsh", "-c", "qemu:///system", "destroy", "inetsim-vm"] in recorded_abort
    assert any("disarm-watchdog" in c for c in recorded_abort)
    assert (vault_dir / "archives" / f"{first_sha}.zip").exists()


def _make_aes256_zip(tmp_path: Path, name: str, raw: bytes) -> Path:
    bsdtar_bin = shutil.which("bsdtar")
    assert bsdtar_bin is not None
    src = tmp_path / f"{name}.bin"
    src.write_bytes(raw)
    zpath = tmp_path / f"{name}.zip"
    subprocess.run(
        [
            bsdtar_bin,
            "--format",
            "zip",
            "--options",
            "zip:encryption=aes256",
            "--passphrase",
            "infected",
            "-cf",
            str(zpath),
            "-C",
            str(tmp_path),
            src.name,
        ],
        check=True,
        capture_output=True,
    )
    src.unlink()
    return zpath


def test_forbidden_malware_policy_and_dll_pe_rejection(tmp_path):
    from scripts.v2_curate_vault_manifest import curate_pilot_vault_and_batch, validate_standalone_runnable_exe_pe

    # Hard blocklist covers ransomware, wipers, and worms
    for bad_fam, bad_cat, bad_tags in (
        ("lockbit", "stealer", ()),
        ("stop", "stealer", ()),
        ("hermeticwiper", "loader", ()),
        ("conficker", "rat", ()),
        ("benign_slug", "ransomware", ()),
        ("benign_slug", "stealer", ("usb_worm",)),
    ):
        with pytest.raises(PilotStagingError, match="BLOCKED"):
            assert_allowed_malware_policy(sample_family=bad_fam, sample_category=bad_cat, tags=bad_tags)
        with pytest.raises(PilotStagingError, match="BLOCKED"):
            validate_stage_run_spec(
                StageRunSpec(
                    run_id="bad_policy",
                    stratum="executed",
                    benign_profile_id="B_dev_01",
                    staging_target_path=r"C:\Users\Public\x.exe",
                    sample_sha256="a" * 64,
                    sample_family=bad_fam,
                    sample_category=bad_cat,
                    sample_tags=tuple(bad_tags),
                    pair_group_id="p_bad",
                    execute_payload=True,
                    gate0_signed_off=True,
                    dedicated_host_user_verified=True,
                )
            )

    # Allowed families and "desktop" substring MUST pass cleanly
    assert_allowed_malware_policy(sample_family="redline", sample_category="stealer", tags=("desktop_stealer",))
    assert_allowed_malware_policy(sample_family="asyncrat", sample_category="rat", tags=("persist",))

    # pefile standalone runnable .exe gate rejects DLLs and non-PE bytes
    exe_bytes = _synth_unsigned_pe_bytes(11, 16384, is_dll=False)
    dll_bytes = _synth_unsigned_pe_bytes(12, 16384, is_dll=True)
    meta_ok = validate_standalone_runnable_exe_pe(exe_bytes)
    assert meta_ok["is_exe"] is True and meta_ok["is_dll"] is False

    with pytest.raises(PilotStagingError, match="IMAGE_FILE_DLL"):
        validate_standalone_runnable_exe_pe(dll_bytes)
    with pytest.raises(PilotStagingError, match="MZ"):
        validate_standalone_runnable_exe_pe(b"\x7fELF" + b"\x00" * 128)

    # Curator must reject a DLL pretending to have .exe extension BEFORE saving to vault
    import os

    repo = Path(__file__).resolve().parent.parent
    setup_script = repo / "docs" / "v2" / "hardening" / "05_quarantine_vault_setup.sh"
    vault_dir = tmp_path / "vault_dll"
    subprocess.run(["bash", str(setup_script), "init"], env=dict(os.environ, VAULT_ROOT=str(vault_dir)), check=True)
    marker = vault_dir / "GATE0_SIGNED_OFF"
    marker.write_text(
        "SIGNED_BY=Mokh\nDATE=2026-11-25\nSUPERVISOR_APPROVAL=Supervisor Marawan (AASTMT) 2026-11-25\n"
        "CONTAINMENT_CHECKS=NEG-01..NEG-10 PASS\nDEDICATED_USER_VERIFIED=true\n",
        encoding="utf-8",
    )
    os.chmod(marker, 0o400)

    dll_sha = hashlib.sha256(dll_bytes).hexdigest()
    dll_zip = _make_aes256_zip(tmp_path, "dll_disguised", dll_bytes).read_bytes()

    class _DllFeed:
        def query_tag(self, tag: str, limit: int = 50):
            if tag.lower() == "redline":
                return [{
                    "sha256_hash": dll_sha,
                    "signature": "RedLine",
                    "file_name": "fake.exe",
                    "file_type": "exe",
                    "file_size": len(dll_bytes),
                    "tags": ["redline"],
                }]
            return []

        def download_sample_zip(self, sha256_hash: str) -> bytes:
            return dll_zip

    with pytest.raises(PilotStagingError, match="IMAGE_FILE_DLL"):
        curate_pilot_vault_and_batch(
            vault_root=vault_dir,
            setup_script=setup_script,
            target_families=1,
            min_families=1,
            client=_DllFeed(),
        )
    assert not (vault_dir / "archives" / f"{dll_sha}.zip").exists()


def test_dormant_batch_staging_dev_only_and_zero_rebake_iso(tmp_path):
    xorriso_bin = shutil.which("xorriso")
    assert xorriso_bin is not None

    pe0 = _synth_unsigned_pe_bytes(201, 16384, is_dll=False)
    pe1 = _synth_unsigned_pe_bytes(202, 16896, is_dll=False)
    sha0 = hashlib.sha256(pe0).hexdigest()
    sha1 = hashlib.sha256(pe1).hexdigest()
    z0 = _make_aes256_zip(tmp_path, "db0", pe0)
    z1 = _make_aes256_zip(tmp_path, "db1", pe1)

    batch_items = (
        {"sample_sha256": sha0, "staging_target_path": r"C:\Users\Public\db_a.exe", "pair_group_id": "p0", "sample_family": "redline"},
        {"sample_sha256": sha1, "staging_target_path": r"C:\Users\Public\db_b.exe", "pair_group_id": "p1", "sample_family": "asyncrat"},
    )

    with pytest.raises(PilotStagingError, match="strictly restricted to split_pool='dev'"):
        validate_stage_run_spec(
            StageRunSpec(
                run_id="db_bad_test",
                stratum="dormant_batch",
                benign_profile_id="B_test_01",
                split_pool="blind_test",
                execute_payload=False,
                gate0_signed_off=True,
                dedicated_host_user_verified=True,
                batch_samples=batch_items,
            )
        )

    spec_dev = StageRunSpec(
        run_id="db_dev_01",
        stratum="dormant_batch",
        benign_profile_id="B_dev_01",
        split_pool="dev",
        dwell_seconds=50,
        execute_payload=False,
        gate0_signed_off=True,
        dedicated_host_user_verified=True,
        batch_samples=batch_items,
    )
    out = build_dormant_batch_bundle(
        spec=spec_dev,
        out_dir=tmp_path / "db_bundle",
        sample_vault_files={sha0: z0, sha1: z1},
        benign_script_text="Write-Host 'benign_dev'\n",
    )
    ext_dir = tmp_path / "db_iso_ext"
    ext_dir.mkdir()
    subprocess.run(
        [xorriso_bin, "-osirrox", "on", "-indev", str(out["iso"]), "-extract", "/", str(ext_dir)],
        check=True,
        capture_output=True,
    )
    assert (ext_dir / "batch_payloads" / "sample_00.bin").read_bytes() == pe0
    assert (ext_dir / "batch_payloads" / "sample_01.bin").read_bytes() == pe1
    ps1_txt = (ext_dir / "benign_workload.ps1").read_text(encoding="utf-8")
    assert "Start-Process" not in ps1_txt
    assert "batch_samples" in ps1_txt
    assert not (tmp_path / "db_bundle" / "batch_payloads").exists()


def test_pilot_safety_watchdog_canary_egress_pipelining_and_resume(tmp_path):
    import json
    import os

    repo = Path(__file__).resolve().parent.parent
    setup_script = repo / "docs" / "v2" / "hardening" / "05_quarantine_vault_setup.sh"
    vault_dir = tmp_path / "vault_safety"
    subprocess.run(["bash", str(setup_script), "init"], env=dict(os.environ, VAULT_ROOT=str(vault_dir)), check=True)
    marker = vault_dir / "GATE0_SIGNED_OFF"
    marker.write_text(
        "SIGNED_BY=Mokh\nDATE=2026-11-25\nSUPERVISOR_APPROVAL=Supervisor Marawan (AASTMT) 2026-11-25\n"
        "CONTAINMENT_CHECKS=NEG-01..NEG-10 PASS\nDEDICATED_USER_VERIFIED=true\n",
        encoding="utf-8",
    )
    os.chmod(marker, 0o400)

    pe_bytes = _synth_unsigned_pe_bytes(303, 16384, is_dll=False)
    pe_sha = hashlib.sha256(pe_bytes).hexdigest()
    zpath = _make_aes256_zip(tmp_path, "canary_sample", pe_bytes)

    canary_batch = [
        {"spec": StageRunSpec(run_id="c_ctrl", stratum="control", benign_profile_id="B_dev_01", dwell_seconds=30).__dict__, "vault_file": None},
        {
            "spec": StageRunSpec(
                run_id="c_dorm",
                stratum="dormant",
                benign_profile_id="B_dev_02",
                dwell_seconds=30,
                staging_target_path=r"C:\Users\Public\c.exe",
                sample_sha256=pe_sha,
                sample_family="redline",
                pair_group_id="p_can",
                execute_payload=False,
                gate0_signed_off=True,
                dedicated_host_user_verified=True,
            ).__dict__,
            "vault_file": str(zpath),
        },
        {
            "spec": StageRunSpec(
                run_id="c_exec",
                stratum="executed",
                benign_profile_id="B_dev_03",
                dwell_seconds=30,
                staging_target_path=r"C:\Users\Public\c.exe",
                sample_sha256=pe_sha,
                sample_family="redline",
                pair_group_id="p_can",
                execute_payload=True,
                gate0_signed_off=True,
                dedicated_host_user_verified=True,
            ).__dict__,
            "vault_file": str(zpath),
        },
    ]

    # 1. require_canary_stamp=True blocks before canary stamp exists
    runs_dir = tmp_path / "canary_runs"
    stamp_file = runs_dir / "CANARY_PASSED"
    with pytest.raises(PilotStagingError, match="CANARY"):
        execute_stage_a_pilot_batch(
            batch_runs=[canary_batch[2]],
            runs_out_dir=runs_dir,
            vault_root=vault_dir,
            inetsim_wait_seconds=0,
            require_canary_stamp=True,
            canary_stamp_path=stamp_file,
            run_cmd=lambda _c, _e=None: 0,
            sleep_fn=lambda _s: None,
        )

    # 2. Canary run executes with arm-watchdog < start, verify-base-fast, and writes CANARY_PASSED
    canary_cmds: list[list[str]] = []

    def _canary_cmd(cmd: list[str], _env=None) -> int:
        canary_cmds.append(list(cmd))
        if cmd and cmd[0].endswith("06_unprivileged_container_runner.sh"):
            rdir = Path(cmd[2])
            rid = cmd[3]
            rdir.mkdir(parents=True, exist_ok=True)
            (rdir / "extraction_manifest.json").write_text(
                json.dumps({
                    "run_id": rid,
                    "total_records": 4414,
                    "sysmon_evtx_present": (rid == "c_exec"),
                    "sysmon_events_count": 12 if rid == "c_exec" else 0,
                }),
                encoding="utf-8",
            )
        return 0

    execute_stage_a_pilot_batch(
        batch_runs=canary_batch,
        runs_out_dir=runs_dir,
        vault_root=vault_dir,
        inetsim_wait_seconds=0,
        canary_mode=True,
        canary_stamp_path=stamp_file,
        full_base_hash_every=25,
        run_cmd=_canary_cmd,
        sleep_fn=lambda _s: None,
    )
    assert stamp_file.is_file()
    assert json.loads(stamp_file.read_text(encoding="utf-8"))["status"] == "PASS"
    arm_idx = next(i for i, c in enumerate(canary_cmds) if "arm-watchdog" in c)
    start_idx = next(i for i, c in enumerate(canary_cmds) if c[-2:] == ["start", "win11"])
    assert arm_idx < start_idx
    assert any("verify-base-fast" in c for c in canary_cmds)

    # 3. After CANARY_PASSED, require_canary_stamp=True allows execution & resume skips completed runs
    pipe_cmds: list[list[str]] = []
    batch_b = [
        {"spec": StageRunSpec(run_id="pipe_01", stratum="control", benign_profile_id="B_dev_04", dwell_seconds=30).__dict__, "vault_file": None},
    ]

    def _pipe_cmd(cmd: list[str], _env=None) -> int:
        pipe_cmds.append(list(cmd))
        return 0

    out_dir_pipe = tmp_path / "pipe_runs"
    res_pipe = execute_stage_a_pilot_batch(
        batch_runs=batch_b,
        runs_out_dir=out_dir_pipe,
        overlay_qcow2=tmp_path / "imgs" / "win11_overlay.qcow2",
        vault_root=vault_dir,
        inetsim_wait_seconds=0,
        require_canary_stamp=True,
        canary_stamp_path=stamp_file,
        enable_pipelining=True,
        run_cmd=_pipe_cmd,
        sleep_fn=lambda _s: None,
    )
    assert len(res_pipe) == 1
    assert any(
        len(c) >= 4 and c[:3] == ["sudo", "mv", "-f"] and c[4].endswith("win11_overlay_pipe_01.qcow2")
        for c in pipe_cmds
    )
    assert any(
        c[0].endswith("06_unprivileged_container_runner.sh") and c[1].endswith("win11_overlay_pipe_01.qcow2")
        for c in pipe_cmds
    )

    # Resume must skip already-completed pipe_01
    re_cmds: list[list[str]] = []
    res_resume = execute_stage_a_pilot_batch(
        batch_runs=batch_b,
        runs_out_dir=out_dir_pipe,
        vault_root=vault_dir,
        inetsim_wait_seconds=0,
        require_canary_stamp=True,
        canary_stamp_path=stamp_file,
        resume=True,
        run_cmd=lambda c, _e=None: re_cmds.append(list(c)) or 0,
        sleep_fn=lambda _s: None,
    )
    assert res_resume == [] and re_cmds == []

    # 4. Egress packet-counter delta > 0 MUST fail loudly and log egress_audit.jsonl
    snap_calls = {"n": 0}

    def _egress_leak_output(cmd: list[str], _env=None) -> tuple[int, str]:
        if "check-egress" in cmd:
            snap_calls["n"] += 1
            pkts = 0 if snap_calls["n"] == 1 else 2
            return 0, json.dumps({
                "bridge": "virbr1",
                "firewall_rules_valid": True,
                "fwd_drop_pkts": pkts,
                "fwd_drop_bytes": pkts * 60,
                "in_drop_pkts": 0,
                "in_drop_bytes": 0,
            })
        return 0, ""

    eg_dir = tmp_path / "eg_fail_runs"
    with pytest.raises(RuntimeError, match="Unauthorized virbr1 egress"):
        execute_stage_a_pilot_batch(
            batch_runs=[batch_b[0]],
            runs_out_dir=eg_dir,
            vault_root=vault_dir,
            inetsim_wait_seconds=0,
            run_cmd=lambda _c, _e=None: 0,
            cmd_output_fn=_egress_leak_output,
            sleep_fn=lambda _s: None,
        )
    assert (eg_dir / "egress_audit.jsonl").exists()

    # 5. _select_canary_subset slices a 15-run batch down to [control, executed, paired_dormant]
    large_batch = [
        {"spec": StageRunSpec(run_id=f"ctrl_{i}", stratum="control", benign_profile_id="B_dev_01").__dict__}
        for i in range(3)
    ]
    for i, fam in enumerate(("redline", "asyncrat", "smokeloader", "xmrig", "amadey", "lummac2")):
        for st in ("executed", "dormant"):
            large_batch.append({
                "spec": StageRunSpec(
                    run_id=f"p_{i}_{fam}_{st}",
                    stratum=st,
                    benign_profile_id="B_dev_01",
                    staging_target_path=r"C:\Users\Public\x.exe",
                    sample_sha256="f" * 64,
                    sample_family=fam,
                    pair_group_id=f"pg_{i}_{fam}",
                    execute_payload=(st == "executed"),
                    gate0_signed_off=True,
                    dedicated_host_user_verified=True,
                ).__dict__
            })
    assert len(large_batch) == 15
    canary_slice = _select_canary_subset(large_batch)
    assert len(canary_slice) == 3
    assert [r["spec"]["stratum"] for r in canary_slice] == ["control", "executed", "dormant"]
    assert canary_slice[1]["spec"]["pair_group_id"] == canary_slice[2]["spec"]["pair_group_id"]
