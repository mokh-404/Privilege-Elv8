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
from src.v2.labeler_v2 import drop_v2_harness_footprint
from src.v2.offline_extractor import (
    expand_target_like_v1,
    extract_from_fixture,
    is_v2_harness_footprint_record,
    write_outputs,
)
from src.v2.pilot_staging import PilotStagingError, StageRunSpec, build_clean_parity_stage_iso
from src.v2.run_stage_a_pilot import (
    build_container_extraction_command,
    build_create_overlay_command,
    compute_od_v2_20_pilot_gate,
    evaluate_stage_a_pilot_runs,
    execute_stage_a_pilot_batch,
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

    # Gate 0 must block curation until GATE0_SIGNED_OFF exists
    with pytest.raises(PilotStagingError, match="Gate 0 sign-off marker missing"):
        curate_pilot_vault_and_batch(vault_root=vault_dir, setup_script=setup_script, target_families=6)

    (vault_dir / "GATE0_SIGNED_OFF").write_text("SIGNED_BY_TEST\n", encoding="utf-8")

    # Missing ABUSECH_AUTH_KEY must fail cleanly when no client is injected
    monkeypatch.delenv("ABUSECH_AUTH_KEY", raising=False)
    with pytest.raises(RuntimeError, match="ABUSECH_AUTH_KEY"):
        curate_pilot_vault_and_batch(vault_root=vault_dir, setup_script=setup_script, target_families=6)

    # Create 6 distinct synthetic AES-256 zip payloads (plus 1 near-duplicate imphash + 1 non-Windows APK)
    families = [
        ("lockbit", "ransomware", "exe", "lockbit"),
        ("redline", "stealer", "exe", "RedLine"),
        ("smokeloader", "loader", "exe", "smokeloader"),
        ("asyncrat", "rat", "exe", "asyncrat"),
        ("xmrig", "miner", "exe", "xmrig"),
        ("amadey", "trojan", "exe", "persistence"),
    ]
    zips_by_sha: dict[str, bytes] = {}
    records_by_tag: dict[str, list[dict[str, object]]] = {}
    for idx, (fam, cat, ftype, query_tag) in enumerate(families):
        raw = f"MZ_PILOT_SAMPLE_{fam}_{idx}".encode("utf-8")
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
            "file_size": 65536 + idx * 1024,
            "imphash": f"{idx + 1:032x}",
            "tags": [fam, "persist", cat],
        }
        records_by_tag[query_tag] = [entry]
    # Add an Android APK that must be filtered out and a duplicate imphash that must be deduplicated
    first_sha = next(iter(zips_by_sha))
    dup_raw = b"MZ_DUPLICATE_FAMILY_BYTES"
    dup_sha = hashlib.sha256(dup_raw).hexdigest()
    records_by_tag["ransomware"] = [
        {
            "sha256_hash": hashlib.sha256(b"apk_skip").hexdigest(),
            "signature": "AndroidBad",
            "file_name": "app.apk",
            "file_type": "apk",
            "file_size": 50000,
        },
        {
            "sha256_hash": dup_sha,
            "signature": "OtherDup",
            "file_name": "dup.exe",
            "file_type": "exe",
            "file_size": 70000,
            "imphash": f"{1:032x}",
        },
        *records_by_tag["lockbit"],
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
        n_control_boots=3,
        dwell_seconds=45,
        client=_FakeFeedClient(),
    )
    assert cur["n_families"] == 6
    assert cur["n_total_runs"] == 15  # 3 controls + 6 * (dormant + executed)
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

    # Verify abort cleanup destroys inetsim-vm even if watchdog aborts win11
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
    assert (vault_dir / "archives" / f"{first_sha}.zip").exists()
