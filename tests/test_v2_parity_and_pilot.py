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
    ALLOWED_FAMILIES,
    CANONICAL_ALLOWED_FAMILIES,
    DORMANT_BATCH_MAX,
    FAMILY_ALIAS_TO_CANONICAL,
    FORBIDDEN_MALWARE_FAMILIES_AND_TAGS,
    FORBIDDEN_SUBSTRING_STEMS,
    PilotStagingError,
    StageRunSpec,
    assert_allowed_malware_policy,
    build_clean_parity_stage_iso,
    build_dormant_batch_bundle,
    build_stage_bundle,
    canonicalize_family_name,
    check_forbidden_malware_policy,
    normalize_family_slug,
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
    assert "prepare-inetsim-overlay)" in sh_txt
    assert "qemu-img commit" in sh_txt
    assert "chown 956:956" in sh_txt
    assert 'chmod 0664 "$overlay"' in sh_txt
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
    families = ["redline", "asyncrat", "smokeloader", "xmrig"]
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

    # Allowlist invariants: disjoint from blocklist, zero forbidden stems, excludes pending grey-zone families
    assert ALLOWED_FAMILIES.isdisjoint(FORBIDDEN_MALWARE_FAMILIES_AND_TAGS)
    assert all(stem not in fam for fam in ALLOWED_FAMILIES for stem in FORBIDDEN_SUBSTRING_STEMS)
    pending_decision = {"njrat", "bladabindi", "qakbot", "emotet", "trickbot"}
    assert pending_decision.isdisjoint(ALLOWED_FAMILIES | FORBIDDEN_MALWARE_FAMILIES_AND_TAGS)
    for grey_fam in pending_decision:
        assert check_forbidden_malware_policy(sample_family=grey_fam) is not None

    # Fail-closed on empty/blank metadata and unknown non-allowlisted families
    assert check_forbidden_malware_policy() is not None
    assert check_forbidden_malware_policy(sample_family=None, sample_category="stealer", tags=()) is not None
    assert check_forbidden_malware_policy(sample_family="   ", sample_category=None, tags=("persist",)) is not None
    assert check_forbidden_malware_policy(sample_family="unknown_custom_rat", sample_category="rat") is not None
    with pytest.raises(PilotStagingError, match="fail-closed"):
        assert_allowed_malware_policy(sample_family=None, sample_category=None, tags=())

    # 'Ransom.Win32.X' rejected across signature, family, or tags
    for sig_val in ("Ransom.Win32.X", "Ransom.Win32.LockBit"):
        assert check_forbidden_malware_policy(raw_signature=sig_val) is not None
        assert check_forbidden_malware_policy(sample_family="redline", tags=(sig_val,)) is not None

    # Whole-token ransomware + worm additions blocked (as tokens) without false substring matches
    new_whole_tokens = (
        "play", "lynx", "chaos", "cuba", "mimic", "blackbyte", "hellokitty", "lorenz",
        "nokoyawa", "xorist", "locky", "filecoder", "thanos", "trigona", "ransomhub",
        "phorpiex", "dorkbot", "raspberryrobin", "blackshades", "lemonduck", "tofsee", "bondat",
    )
    for tok in new_whole_tokens:
        with pytest.raises(PilotStagingError, match="BLOCKED"):
            assert_allowed_malware_policy(sample_family=tok, sample_category="loader", tags=())
        with pytest.raises(PilotStagingError, match="BLOCKED"):
            assert_allowed_malware_policy(sample_family="redline", sample_category="stealer", tags=(tok,))

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

    # Allowlisted families + benign words containing whole-token blocks as substrings ("desktop", "display", "replay") pass cleanly
    assert_allowed_malware_policy(
        sample_family="redline",
        sample_category="stealer",
        tags=("desktop_stealer", "display_helper", "replay_log"),
    )
    assert_allowed_malware_policy(sample_family="asyncrat", sample_category="rat", tags=("persist",))
    assert normalize_family_slug("Lumma-C2") == "lummac2"
    assert_allowed_malware_policy(sample_family="Lumma-C2", sample_category="stealer", tags=("persist",))

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

    # 2. Canary run executes with DETONATE prompt (executed only), arm-watchdog < start, verify-base-fast, and writes bound CANARY_PASSED
    canary_cmds: list[list[str]] = []
    prompts_seen: list[str] = []

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

    clean_git = lambda _r: {"git_head": "a" * 40, "git_dirty": False}

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
        git_state_fn=clean_git,
        confirm_input_fn=lambda p: prompts_seen.append(p) or "DETONATE",
    )
    assert len(prompts_seen) == 1 and "c_exec" in prompts_seen[0]
    assert stamp_file.is_file()
    stamp_obj = json.loads(stamp_file.read_text(encoding="utf-8"))
    assert stamp_obj["status"] == "PASS"
    assert stamp_obj["git_head"] == "a" * 40 and stamp_obj["git_dirty"] is False
    assert stamp_obj["ttl_seconds"] == 86400
    assert len(stamp_obj["batch_json_sha256"]) == 64 and len(stamp_obj["base_image_sha256"]) == 64
    arm_idx = next(i for i, c in enumerate(canary_cmds) if "arm-watchdog" in c)
    start_idx = next(i for i, c in enumerate(canary_cmds) if c[-2:] == ["start", "win11"])
    assert arm_idx < start_idx
    assert any("verify-base-fast" in c for c in canary_cmds)

    # 3. After CANARY_PASSED, require_canary_stamp=True allows execution on matching batch & resume skips completed runs
    pipe_cmds: list[list[str]] = []

    def _pipe_cmd(cmd: list[str], _env=None) -> int:
        pipe_cmds.append(list(cmd))
        return 0

    out_dir_pipe = tmp_path / "pipe_runs"
    res_pipe = execute_stage_a_pilot_batch(
        batch_runs=canary_batch[:1],
        runs_out_dir=out_dir_pipe,
        overlay_qcow2=tmp_path / "imgs" / "win11_overlay.qcow2",
        vault_root=vault_dir,
        inetsim_wait_seconds=0,
        require_canary_stamp=True,
        canary_stamp_path=stamp_file,
        batch_json_sha256=stamp_obj["batch_json_sha256"],
        enable_pipelining=True,
        run_cmd=_pipe_cmd,
        sleep_fn=lambda _s: None,
        git_state_fn=clean_git,
    )
    assert len(res_pipe) == 1
    assert any(
        len(c) >= 4 and c[:3] == ["sudo", "mv", "-f"] and c[4].endswith("win11_overlay_c_ctrl.qcow2")
        for c in pipe_cmds
    )
    assert any(
        c[0].endswith("06_unprivileged_container_runner.sh") and c[1].endswith("win11_overlay_c_ctrl.qcow2")
        for c in pipe_cmds
    )

    # Resume must skip already-completed c_ctrl
    re_cmds: list[list[str]] = []
    res_resume = execute_stage_a_pilot_batch(
        batch_runs=canary_batch[:1],
        runs_out_dir=out_dir_pipe,
        vault_root=vault_dir,
        inetsim_wait_seconds=0,
        require_canary_stamp=True,
        canary_stamp_path=stamp_file,
        batch_json_sha256=stamp_obj["batch_json_sha256"],
        resume=True,
        run_cmd=lambda c, _e=None: re_cmds.append(list(c)) or 0,
        sleep_fn=lambda _s: None,
        git_state_fn=clean_git,
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
            batch_runs=canary_batch[:1],
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


def test_canary_stamp_full_binding_expiry_and_detonate_prompt(tmp_path):
    from datetime import datetime, timedelta, timezone
    import json
    import os

    repo = Path(__file__).resolve().parent.parent
    setup_script = repo / "docs" / "v2" / "hardening" / "05_quarantine_vault_setup.sh"
    vault_dir = tmp_path / "vault_canary_bind"
    subprocess.run(["bash", str(setup_script), "init"], env=dict(os.environ, VAULT_ROOT=str(vault_dir)), check=True)
    marker = vault_dir / "GATE0_SIGNED_OFF"
    marker.write_text(
        "SIGNED_BY=Mokh\nDATE=2026-11-25\nSUPERVISOR_APPROVAL=Supervisor Marawan (AASTMT) 2026-11-25\n"
        "CONTAINMENT_CHECKS=NEG-01..NEG-10 PASS\nDEDICATED_USER_VERIFIED=true\n",
        encoding="utf-8",
    )
    os.chmod(marker, 0o400)

    pe_bytes = _synth_unsigned_pe_bytes(404, 16384, is_dll=False)
    pe_sha = hashlib.sha256(pe_bytes).hexdigest()
    zpath = _make_aes256_zip(tmp_path, "bind_sample", pe_bytes)
    batch_file = tmp_path / "batch.json"

    batch = [
        {"spec": StageRunSpec(run_id="cb_ctrl", stratum="control", benign_profile_id="B_dev_01", dwell_seconds=30).__dict__, "vault_file": None},
        {
            "spec": StageRunSpec(
                run_id="cb_exec",
                stratum="executed",
                benign_profile_id="B_dev_02",
                dwell_seconds=30,
                staging_target_path=r"C:\Users\Public\b.exe",
                sample_sha256=pe_sha,
                sample_family="redline",
                pair_group_id="p_bind",
                execute_payload=True,
                gate0_signed_off=True,
                dedicated_host_user_verified=True,
            ).__dict__,
            "vault_file": str(zpath),
        },
        {
            "spec": StageRunSpec(
                run_id="cb_dorm",
                stratum="dormant",
                benign_profile_id="B_dev_03",
                dwell_seconds=30,
                staging_target_path=r"C:\Users\Public\b.exe",
                sample_sha256=pe_sha,
                sample_family="redline",
                pair_group_id="p_bind",
                execute_payload=False,
                gate0_signed_off=True,
                dedicated_host_user_verified=True,
            ).__dict__,
            "vault_file": str(zpath),
        },
    ]
    batch_file.write_text(json.dumps({"runs": batch}, indent=2), encoding="utf-8")

    # 1. Non-'DETONATE' responses MUST abort BEFORE first executed canary boot starts inetsim-vm or win11
    for bad_reply in ("yes", "detonate", ""):
        cmds_abort: list[list[str]] = []
        with pytest.raises(PilotStagingError, match="DETONATE"):
            execute_stage_a_pilot_batch(
                batch_runs=batch,
                runs_out_dir=tmp_path / f"abort_{bad_reply or 'empty'}",
                vault_root=vault_dir,
                batch_json_path=batch_file,
                inetsim_wait_seconds=0,
                canary_mode=True,
                run_cmd=lambda c, _e=None: cmds_abort.append(list(c)) or 0,
                sleep_fn=lambda _s: None,
                git_state_fn=lambda _r: {"git_head": "b" * 40, "git_dirty": False},
                confirm_input_fn=lambda _p: bad_reply,
            )
        # Only cb_ctrl (control) could boot win11; cb_exec never started inetsim-vm or a second win11
        assert not any(len(c) >= 2 and c[-2:] == ["start", "inetsim-vm"] for c in cmds_abort)
        assert sum(1 for c in cmds_abort if len(c) >= 2 and c[-2:] == ["start", "win11"]) == 1

    # 2. Successful canary writes bound stamp
    t0 = datetime(2026, 11, 26, 1, 0, 0, tzinfo=timezone.utc)
    runs_dir = tmp_path / "bind_runs"
    stamp_file = runs_dir / "CANARY_PASSED"

    def _run_ok(cmd: list[str], _env=None) -> int:
        if cmd and cmd[0].endswith("06_unprivileged_container_runner.sh"):
            rdir = Path(cmd[2])
            rid = cmd[3]
            rdir.mkdir(parents=True, exist_ok=True)
            (rdir / "extraction_manifest.json").write_text(
                json.dumps({
                    "run_id": rid,
                    "total_records": 4414,
                    "sysmon_evtx_present": (rid == "cb_exec"),
                    "sysmon_events_count": 7 if rid == "cb_exec" else 0,
                }),
                encoding="utf-8",
            )
        return 0

    execute_stage_a_pilot_batch(
        batch_runs=batch,
        runs_out_dir=runs_dir,
        vault_root=vault_dir,
        batch_json_path=batch_file,
        base_image_sha256="1" * 64,
        inetsim_wait_seconds=0,
        canary_mode=True,
        canary_stamp_path=stamp_file,
        run_cmd=_run_ok,
        sleep_fn=lambda _s: None,
        git_state_fn=lambda _r: {"git_head": "b" * 40, "git_dirty": False},
        now_fn=lambda: t0,
        confirm_input_fn=lambda _p: "DETONATE",
    )

    unattended_batch = [batch[1]]
    common_kw = dict(
        batch_runs=unattended_batch,
        runs_out_dir=tmp_path / "unattended_out",
        vault_root=vault_dir,
        batch_json_path=batch_file,
        base_image_sha256="1" * 64,
        inetsim_wait_seconds=0,
        require_canary_stamp=True,
        canary_stamp_path=stamp_file,
        run_cmd=_run_ok,
        sleep_fn=lambda _s: None,
        git_state_fn=lambda _r: {"git_head": "b" * 40, "git_dirty": False},
        now_fn=lambda: t0 + timedelta(hours=1),
    )

    # 3. Mismatched batch JSON rejected
    other_batch = tmp_path / "other_batch.json"
    other_batch.write_text('{"runs": []}', encoding="utf-8")
    with pytest.raises(PilotStagingError, match="batch_json_sha256 mismatch"):
        execute_stage_a_pilot_batch(**{**common_kw, "batch_json_path": other_batch})

    # 4. Mismatched base image hash rejected
    with pytest.raises(PilotStagingError, match="base_image_sha256 mismatch"):
        execute_stage_a_pilot_batch(**{**common_kw, "base_image_sha256": "2" * 64})

    # 5. Mismatched git HEAD rejected
    with pytest.raises(PilotStagingError, match="git_head mismatch"):
        execute_stage_a_pilot_batch(**{**common_kw, "git_state_fn": lambda _r: {"git_head": "c" * 40, "git_dirty": False}})

    # 6. Dirty working tree rejected
    with pytest.raises(PilotStagingError, match="dirty"):
        execute_stage_a_pilot_batch(**{**common_kw, "git_state_fn": lambda _r: {"git_head": "b" * 40, "git_dirty": True}})

    # 7. Expired stamp (> 24h) rejected
    with pytest.raises(PilotStagingError, match="EXPIRED"):
        execute_stage_a_pilot_batch(**{**common_kw, "now_fn": lambda: t0 + timedelta(hours=24, seconds=1)})

    # 8. Valid fresh clean matching stamp succeeds cleanly
    ok_res = execute_stage_a_pilot_batch(**common_kw)
    assert len(ok_res) == 1 and ok_res[0]["run_id"] == "cb_exec"


def test_dormant_batch_cap_16_and_evaluate_stage_a_wires_batch_and_raises_on_unknown(tmp_path):
    from src.v2.labeler_v2 import build_multi_control_baseline, label_dormant_batch_run
    from src.v2.pilot_staging import _DORMANT_BATCH_PS1_LOOP

    assert DORMANT_BATCH_MAX == 16
    assert "$maxBatch = 16" in _DORMANT_BATCH_PS1_LOOP
    assert "16" in (build_dormant_batch_bundle.__doc__ or "")
    assert "20" not in (build_dormant_batch_bundle.__doc__ or "")

    def _mk_batch_items(count: int):
        return tuple(
            {
                "sample_sha256": f"{i + 1:064x}",
                "staging_target_path": rf"C:\Users\Public\db_{i:02d}.exe",
                "pair_group_id": f"pg_batch_{i:02d}",
                "sample_family": "redline" if i % 2 == 0 else "asyncrat",
            }
            for i in range(count)
        )

    # Exactly 16 succeeds; 17 fails both validate_stage_run_spec and label_dormant_batch_run
    spec_16 = StageRunSpec(
        run_id="db_16",
        stratum="dormant_batch",
        benign_profile_id="B_dev_01",
        split_pool="dev",
        dwell_seconds=50,
        execute_payload=False,
        gate0_signed_off=True,
        dedicated_host_user_verified=True,
        batch_samples=_mk_batch_items(16),
    )
    validate_stage_run_spec(spec_16)

    spec_17 = StageRunSpec(
        run_id="db_17",
        stratum="dormant_batch",
        benign_profile_id="B_dev_01",
        split_pool="dev",
        dwell_seconds=50,
        execute_payload=False,
        gate0_signed_off=True,
        dedicated_host_user_verified=True,
        batch_samples=_mk_batch_items(17),
    )
    with pytest.raises(PilotStagingError, match="1\\.\\.16"):
        validate_stage_run_spec(spec_17)

    ctrl_df = pd.DataFrame([
        {
            "run_id": "ctrl_01",
            "artifact_type": "file",
            "artifact_key": r"file|c:\windows\system32\notepad.exe|notepad.exe",
            "name": "notepad.exe",
            "path": r"C:\Windows\System32\notepad.exe",
            "signature_status": "Valid",
            "file_size": 204800,
            "file_head_histogram": [800] * 256,
            "file_sha256": "e" * 64,
        }
    ])
    base_idx = build_multi_control_baseline([ctrl_df])
    with pytest.raises(ValueError, match="at most 16"):
        label_dormant_batch_run(ctrl_df, base_idx, list(_mk_batch_items(17)), run_id="db_17", split_pool="dev")

    # Wire dormant_batch into evaluate_stage_a_pilot_runs (MUST NOT drop batch run)
    ctrl_rows = ctrl_df.to_dict(orient="records")
    # Need >= 3 distinct family clusters (2 positives + benign) for 2-fold outer CV
    exec_families = ("redline", "asyncrat", "smokeloader", "xmrig")
    pilot_runs = []
    batch_items = []
    for idx, fam in enumerate(exec_families):
        sha = hashlib.sha256(f"db_eval_{fam}".encode()).hexdigest()
        staged_p = rf"C:\Users\Public\db_{fam}.exe"
        pair_id = f"pair_db_{fam}"
        if idx < 2:
            batch_items.append({
                "staging_target_path": staged_p,
                "sample_sha256": sha,
                "sample_family": fam,
                "pair_group_id": pair_id,
            })
        exec_rows = [dict(r, run_id=f"ex_{fam}") for r in ctrl_rows]
        exec_rows.append({
            "run_id": f"ex_{fam}",
            "artifact_type": "file",
            "artifact_key": f"file|{staged_p.lower()}|db_{fam}.exe",
            "name": f"db_{fam}.exe",
            "path": staged_p,
            "signature_status": "NotSigned",
            "file_size": 220000 + idx * 4096,
            "file_head_histogram": [850] * 256,
            "file_sha256": sha,
            "attributes": 2,
        })
        pilot_runs.append({
            "spec": StageRunSpec(
                run_id=f"ex_{fam}",
                stratum="executed",
                benign_profile_id="B_dev_01",
                dwell_seconds=60,
                staging_target_path=staged_p,
                sample_sha256=sha,
                sample_family=fam,
                pair_group_id=pair_id,
                execute_payload=True,
                gate0_signed_off=True,
                dedicated_host_user_verified=True,
            ),
            "df": pd.DataFrame(exec_rows),
            "sysmon_events": [{"event_id": 1, "process_guid": f"{{g-{fam}}}", "pid": 3000 + idx, "image": staged_p, "hashes": f"SHA256={sha}"}],
            "malware_root_guids": [f"{{g-{fam}}}"],
        })

    db_rows = [dict(r, run_id="db_batch_01") for r in ctrl_rows]
    for bm in batch_items:
        db_rows.append({
            "run_id": "db_batch_01",
            "artifact_type": "file",
            "artifact_key": f"file|{bm['staging_target_path'].lower()}|{Path(bm['staging_target_path']).name}",
            "name": Path(bm["staging_target_path"]).name,
            "path": bm["staging_target_path"],
            "signature_status": "NotSigned",
            "file_size": 190000,
            "file_head_histogram": [740] * 256,
            "file_sha256": bm["sample_sha256"],
            "attributes": 2,
        })
    pilot_runs.append({
        "spec": StageRunSpec(
            run_id="db_batch_01",
            stratum="dormant_batch",
            benign_profile_id="B_dev_02",
            split_pool="dev",
            dwell_seconds=60,
            execute_payload=False,
            gate0_signed_off=True,
            dedicated_host_user_verified=True,
            batch_samples=tuple(batch_items),
        ),
        "df": pd.DataFrame(db_rows),
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
    by_rid = {row["run_id"]: row for row in summary["yield_table"]}
    assert "db_batch_01" in by_rid
    assert by_rid["db_batch_01"]["stratum"] == "dormant_batch"
    assert by_rid["db_batch_01"]["attacker_induced"] == 2
    assert summary["dormant_mean_positives_per_run"] == 2.0

    # Unknown or non-malware strata inside pilot_runs MUST raise rather than silently continuing
    with pytest.raises(PilotStagingError):
        evaluate_stage_a_pilot_runs(
            control_runs=[ctrl_df],
            pilot_runs=[{"spec": {"run_id": "bogus", "stratum": "unknown_stratum", "benign_profile_id": "B_dev_01"}, "df": ctrl_df}],
        )
    with pytest.raises(PilotStagingError, match="Unsupported stratum"):
        evaluate_stage_a_pilot_runs(
            control_runs=[ctrl_df],
            pilot_runs=[{"spec": StageRunSpec(run_id="ctrl_in_pilot", stratum="control", benign_profile_id="B_dev_01"), "df": ctrl_df}],
        )


def test_allowlist_removes_lime_and_canonical_aliases_enforce_split_and_caps(tmp_path):
    from scripts.v2_curate_vault_manifest import canonical_family_slug, select_pilot_families

    # lime / limerat removed from allowlist & blocked
    assert "lime" not in ALLOWED_FAMILIES and "limerat" not in ALLOWED_FAMILIES
    assert "lime" not in CANONICAL_ALLOWED_FAMILIES and "limerat" not in CANONICAL_ALLOWED_FAMILIES
    for lime_name in ("lime", "limerat", "LimeRAT"):
        with pytest.raises(PilotStagingError, match="BLOCKED"):
            assert_allowed_malware_policy(sample_family=lime_name, sample_category="rat")

    # All 13 canonical alias mappings resolve to one key per group
    alias_groups = [
        ("lumma", ("lumma", "lummac2", "lummastealer", "Lumma-C2")),
        ("warzone", ("warzone", "warzonerat", "avemaria", "AveMaria")),
        ("redline", ("redline", "redlinestealer")),
        ("raccoon", ("raccoon", "raccoonstealer")),
        ("remcos", ("remcos", "remcosrat")),
        ("quasar", ("quasar", "quasarrat")),
        ("orcus", ("orcus", "orcusrat")),
        ("nanocore", ("nanocore", "nanocorerat")),
        ("buer", ("buer", "buerloader")),
        ("aurora", ("aurora", "aurorastealer")),
        ("revenge", ("revenge", "revengerat")),
        ("gh0st", ("gh0st", "ghostrat")),
        ("formbook", ("formbook", "xloader")),
        ("vidar", ("vidar", "arkei")),
        ("raccoon", ("raccoon", "raccoonstealer", "recordbreaker")),
    ]
    for expected_canon, variants in alias_groups:
        for v in variants:
            assert canonicalize_family_name(v) == expected_canon
            assert expected_canon in CANONICAL_ALLOWED_FAMILIES
            assert FAMILY_ALIAS_TO_CANONICAL[normalize_family_slug(v)] == expected_canon

    assert canonical_family_slug("AveMaria", ()) == "warzone"
    assert canonical_family_slug("LummaC2", ()) == "lumma"
    assert canonical_family_slug("XLoader", ()) == "formbook"

    # Per-family caps treat alias variants as ONE canonical family
    cands = {
        "stealer": [
            {"sha256_hash": "1" * 64, "signature": "Lumma", "file_name": "a.exe", "file_type": "exe", "file_size": 32768, "tags": ["lumma"]},
            {"sha256_hash": "2" * 64, "signature": "LummaC2", "file_name": "b.exe", "file_type": "exe", "file_size": 36864, "tags": ["lummac2"]},
            {"sha256_hash": "3" * 64, "signature": "LummaStealer", "file_name": "c.exe", "file_type": "exe", "file_size": 40960, "tags": ["lummastealer"]},
            {"sha256_hash": "4" * 64, "signature": "Formbook", "file_name": "d.exe", "file_type": "exe", "file_size": 45056, "tags": ["formbook"]},
            {"sha256_hash": "5" * 64, "signature": "XLoader", "file_name": "e.exe", "file_type": "exe", "file_size": 49152, "tags": ["xloader"]},
        ],
        "rat": [
            {"sha256_hash": "6" * 64, "signature": "WarzoneRAT", "file_name": "f.exe", "file_type": "exe", "file_size": 32768, "tags": ["warzonerat"]},
            {"sha256_hash": "7" * 64, "signature": "AveMaria", "file_name": "g.exe", "file_type": "exe", "file_size": 36864, "tags": ["avemaria"]},
            {"sha256_hash": "8" * 64, "signature": "LimeRAT", "file_name": "h.exe", "file_type": "exe", "file_size": 36864, "tags": ["limerat"]},
        ],
    }
    picked = select_pilot_families(cands, target_families=10, max_per_family=1, target_samples=10)
    picked_fams = [r["_family"] for r in picked]
    assert sorted(picked_fams) == ["formbook", "lumma", "warzone"]
    assert len(picked) == 3  # LimeRAT excluded and aliases collapsed to 1 per canonical key


def test_stage_b_requires_real_pools_while_stage_a_allows_synthetic_fallback(tmp_path):
    import json
    from src.v2.benign_generator_v2 import RealBenignPoolRequiredError
    from src.v2.run_stage_a_pilot import main as pilot_main

    empty_pools = tmp_path / "empty_pools"
    ctrl_only = [
        {
            "spec": StageRunSpec(
                run_id="pool_ctrl_01",
                stratum="control",
                benign_profile_id="B_dev_01",
                dwell_seconds=30,
            ).__dict__,
            "vault_file": None,
        }
    ]
    out_a = tmp_path / "out_stage_a"
    execute_stage_a_pilot_batch(
        batch_runs=ctrl_only,
        runs_out_dir=out_a,
        inetsim_wait_seconds=0,
        benign_pools_root=empty_pools,
        stage="a",
        run_cmd=lambda _c, _e=None: 0,
        sleep_fn=lambda _s: None,
    )
    # Build directly via build_stage_bundle to check manifest fields written
    bun = build_stage_bundle(
        StageRunSpec(run_id="chk_fb", stratum="control", benign_profile_id="B_dev_01", dwell_seconds=30),
        tmp_path / "chk_fb_dir",
        benign_pools_root=empty_pools,
        require_real_pools=False,
    )
    man = json.loads(bun["benign_manifest"].read_text(encoding="utf-8"))
    assert man["synthetic_fallback"] is True
    assert man["synthetic_fallback_counts"] == {"unsigned_pe": 2, "high_entropy_pe": 3}

    with pytest.raises(RealBenignPoolRequiredError):
        execute_stage_a_pilot_batch(
            batch_runs=ctrl_only,
            runs_out_dir=tmp_path / "out_stage_b",
            inetsim_wait_seconds=0,
            benign_pools_root=empty_pools,
            stage="b",
            run_cmd=lambda _c, _e=None: 0,
            sleep_fn=lambda _s: None,
        )

    with pytest.raises(RealBenignPoolRequiredError):
        execute_stage_a_pilot_batch(
            batch_runs=ctrl_only,
            runs_out_dir=tmp_path / "out_stage_a_strict",
            inetsim_wait_seconds=0,
            benign_pools_root=empty_pools,
            stage="a",
            require_real_pools=True,
            run_cmd=lambda _c, _e=None: 0,
            sleep_fn=lambda _s: None,
        )

    batch_json = tmp_path / "cli_ctrl_batch.json"
    batch_json.write_text(json.dumps({"runs": ctrl_only}), encoding="utf-8")
    with pytest.raises(RealBenignPoolRequiredError):
        pilot_main([
            "--batch-json", str(batch_json),
            "--runs-out-dir", str(tmp_path / "cli_stage_b"),
            "--benign-pools-root", str(empty_pools),
            "--stage", "b",
            "--dry-run",
        ])
    assert pilot_main([
        "--batch-json", str(batch_json),
        "--runs-out-dir", str(tmp_path / "cli_stage_b_override"),
        "--benign-pools-root", str(empty_pools),
        "--stage", "b",
        "--no-require-real-pools",
        "--dry-run",
    ]) == 0


def test_warm_inetsim_reuse_and_per_stratum_dwell_defaults(tmp_path, monkeypatch):
    import json
    import os
    from scripts import v2_curate_vault_manifest as v2_cur
    from scripts.v2_curate_vault_manifest import build_pilot_batch_specs, main as curate_main
    from src.v2.run_stage_a_pilot import main as pilot_main

    # 1. Verify curator CLI & build_pilot_batch_specs per-stratum dwell defaults (45s exec / 15s dormant / 15s ctrl)
    samples = []
    vault_dir = tmp_path / "vault_warm"
    setup_script = Path(__file__).resolve().parent.parent / "docs" / "v2" / "hardening" / "05_quarantine_vault_setup.sh"
    subprocess.run(["bash", str(setup_script), "init"], env=dict(os.environ, VAULT_ROOT=str(vault_dir)), check=True)
    marker = vault_dir / "GATE0_SIGNED_OFF"
    marker.write_text(
        "SIGNED_BY=Mokh\nDATE=2026-11-26\nSUPERVISOR_APPROVAL=Supervisor Marawan (AASTMT) 2026-11-25\n"
        "CONTAINMENT_CHECKS=NEG-01..NEG-10 PASS\nDEDICATED_USER_VERIFIED=true\n",
        encoding="utf-8",
    )
    os.chmod(marker, 0o400)

    for idx, fam in enumerate(("redline", "asyncrat", "smokeloader")):
        pe_bytes = _synth_unsigned_pe_bytes(600 + idx, 16384, is_dll=False)
        sha = hashlib.sha256(pe_bytes).hexdigest()
        zpath = _make_aes256_zip(tmp_path, f"warm_{fam}", pe_bytes)
        samples.append({
            "sample_sha256": sha,
            "sample_family": fam,
            "category": "stealer",
            "vault_archive_path": str(zpath),
            "near_dup_cluster_id": f"clu_{idx}",
        })

    default_batch = build_pilot_batch_specs(samples, n_control_boots=2)
    strata_seq = [r["spec"]["stratum"] for r in default_batch]
    dwell_seq = [r["spec"]["dwell_seconds"] for r in default_batch]
    assert strata_seq == ["control", "control", "executed", "executed", "executed", "dormant", "dormant", "dormant"]
    assert dwell_seq == [15, 15, 45, 45, 45, 15, 15, 15]

    packed_batch = build_pilot_batch_specs(samples, n_control_boots=1, dormant_batch_size=16)
    assert [r["spec"]["stratum"] for r in packed_batch] == ["control", "executed", "executed", "executed", "dormant_batch"]
    assert [r["spec"]["dwell_seconds"] for r in packed_batch] == [15, 45, 45, 45, 15]
    assert len(packed_batch[-1]["spec"]["batch_samples"]) == 3

    with pytest.raises(PilotStagingError, match="blind_test"):
        build_pilot_batch_specs(samples, dormant_batch_size=2, split_pool="blind_test")

    # 2. Warm inetsim-vm skips redundant start + wait across consecutive executed runs and tears down before dormant/exit
    warm_cmds: list[list[str]] = []
    sleeps: list[float] = []
    res_warm = execute_stage_a_pilot_batch(
        batch_runs=default_batch,
        runs_out_dir=tmp_path / "warm_runs_out",
        vault_root=vault_dir,
        inetsim_wait_seconds=8,
        keep_inetsim_warm=True,
        run_cmd=lambda cmd, _e=None: warm_cmds.append(list(cmd)) or 0,
        sleep_fn=lambda s: sleeps.append(float(s)),
    )
    assert [r["inetsim_booted"] for r in res_warm] == [False, False, True, True, True, False, False, False]
    inetsim_preps = [i for i, c in enumerate(warm_cmds) if len(c) >= 3 and c[2] == "prepare-inetsim-overlay"]
    inetsim_starts = [i for i, c in enumerate(warm_cmds) if c == ["sudo", "virsh", "-c", "qemu:///system", "start", "inetsim-vm"]]
    inetsim_destroys = [i for i, c in enumerate(warm_cmds) if c == ["sudo", "virsh", "-c", "qemu:///system", "destroy", "inetsim-vm"]]
    win_starts = [i for i, c in enumerate(warm_cmds) if c == ["sudo", "virsh", "-c", "qemu:///system", "start", "win11"]]
    assert len(inetsim_preps) == 1
    assert len(inetsim_starts) == 1
    assert len(inetsim_destroys) == 1
    assert sleeps == [8.0]
    # Prepare overlay -> start inetsim -> 1st executed win11 -> ... -> destroy inetsim before 1st dormant win11
    assert inetsim_preps[0] < inetsim_starts[0] < win_starts[2] < win_starts[4] < inetsim_destroys[0] < win_starts[5]

    # Executed-only tail cleans up warm inetsim-vm in outer finally:
    tail_cmds: list[list[str]] = []
    tail_sleeps: list[float] = []
    execute_stage_a_pilot_batch(
        batch_runs=default_batch[2:4],
        runs_out_dir=tmp_path / "warm_tail_out",
        vault_root=vault_dir,
        inetsim_wait_seconds=8,
        keep_inetsim_warm=True,
        run_cmd=lambda cmd, _e=None: tail_cmds.append(list(cmd)) or 0,
        sleep_fn=lambda s: tail_sleeps.append(float(s)),
    )
    assert sum(1 for c in tail_cmds if len(c) >= 3 and c[2] == "prepare-inetsim-overlay") == 1
    assert sum(1 for c in tail_cmds if c[-2:] == ["start", "inetsim-vm"]) == 1
    assert sum(1 for c in tail_cmds if c[-2:] == ["destroy", "inetsim-vm"]) == 1
    assert tail_sleeps == [8.0]

    # keep_inetsim_warm=False restores per-run prepare/start/sleep/destroy
    cold_cmds: list[list[str]] = []
    cold_sleeps: list[float] = []
    execute_stage_a_pilot_batch(
        batch_runs=default_batch[2:4],
        runs_out_dir=tmp_path / "cold_runs_out",
        vault_root=vault_dir,
        inetsim_wait_seconds=8,
        keep_inetsim_warm=False,
        run_cmd=lambda cmd, _e=None: cold_cmds.append(list(cmd)) or 0,
        sleep_fn=lambda s: cold_sleeps.append(float(s)),
    )
    assert sum(1 for c in cold_cmds if len(c) >= 3 and c[2] == "prepare-inetsim-overlay") == 2
    assert sum(1 for c in cold_cmds if c[-2:] == ["start", "inetsim-vm"]) == 2
    assert sum(1 for c in cold_cmds if c[-2:] == ["destroy", "inetsim-vm"]) == 2
    assert cold_sleeps == [8.0, 8.0]

    # Abort on 2nd executed run MUST immediately destroy warm inetsim-vm (never leak across failures)
    abort_cmds: list[list[str]] = []

    def _fail_second_wd(cmd: list[str], _e=None) -> int:
        abort_cmds.append(list(cmd))
        if "watchdog" in cmd and sum(1 for c in abort_cmds if "watchdog" in c) == 2:
            return 2
        return 0

    with pytest.raises(RuntimeError, match="Watchdog aborted"):
        execute_stage_a_pilot_batch(
            batch_runs=default_batch[2:5],
            runs_out_dir=tmp_path / "warm_abort_out",
            vault_root=vault_dir,
            inetsim_wait_seconds=0,
            keep_inetsim_warm=True,
            run_cmd=_fail_second_wd,
            sleep_fn=lambda _s: None,
        )
    assert sum(1 for c in abort_cmds if c[-2:] == ["destroy", "inetsim-vm"]) == 1

    # CLI flags smoke check for --keep-inetsim-warm / --no-keep-inetsim-warm & curate CLI per-stratum dwell defaults
    bfile = tmp_path / "warm_cli_batch.json"
    bfile.write_text(json.dumps({"runs": default_batch[:1]}), encoding="utf-8")
    assert pilot_main([
        "--batch-json", str(bfile),
        "--runs-out-dir", str(tmp_path / "warm_cli_out"),
        "--keep-inetsim-warm",
        "--dry-run",
    ]) == 0
    assert pilot_main([
        "--batch-json", str(bfile),
        "--runs-out-dir", str(tmp_path / "warm_cli_cold_out"),
        "--no-keep-inetsim-warm",
        "--dry-run",
    ]) == 0

    cli_vault = tmp_path / "cli_cur_vault"
    subprocess.run(["bash", str(setup_script), "init"], env=dict(os.environ, VAULT_ROOT=str(cli_vault)), check=True)
    cli_marker = cli_vault / "GATE0_SIGNED_OFF"
    cli_marker.write_text(
        "SIGNED_BY=Mokh\nDATE=2026-11-26\nSUPERVISOR_APPROVAL=Supervisor Marawan (AASTMT) 2026-11-25\n"
        "CONTAINMENT_CHECKS=NEG-01..NEG-10 PASS\nDEDICATED_USER_VERIFIED=true\n",
        encoding="utf-8",
    )
    os.chmod(cli_marker, 0o400)
    zbytes_by_sha = {s["sample_sha256"]: Path(s["vault_archive_path"]).read_bytes() for s in samples}
    fake_rows = [
        {
            "sha256_hash": s["sample_sha256"],
            "signature": s["sample_family"],
            "file_name": f"{s['sample_family']}.exe",
            "file_type": "exe",
            "file_size": 16384,
            "imphash": f"{idx + 10:032x}",
            "tags": [s["sample_family"], "stealer"],
        }
        for idx, s in enumerate(samples)
    ]

    class _CliFakeMB:
        def __init__(self, api_key: str) -> None:
            assert api_key == "dummy_test_key"

        def query_tag(self, tag: str, limit: int = 40):
            return fake_rows if tag.lower() == "redline" else []

        def download_sample_zip(self, sha256_hash: str) -> bytes:
            return zbytes_by_sha[sha256_hash.lower()]

    monkeypatch.setenv("ABUSECH_AUTH_KEY", "dummy_test_key")
    monkeypatch.setattr(v2_cur, "MalwareBazaarClient", _CliFakeMB)
    assert curate_main([
        "--vault-root", str(cli_vault),
        "--setup-script", str(setup_script),
        "--target-families", "3",
        "--min-families", "3",
        "--n-control-boots", "2",
    ]) == 0
    cli_batch = json.loads((cli_vault / "stage_a_pilot_batch.json").read_text(encoding="utf-8"))
    assert cli_batch["dwell_seconds_executed"] == 45
    assert cli_batch["dwell_seconds_dormant"] == 15
    assert cli_batch["dwell_seconds_control"] == 15
    assert cli_batch["dormant_batch_size"] == 1
    assert [r["spec"]["dwell_seconds"] for r in cli_batch["runs"]] == [15, 15, 45, 45, 45, 15, 15, 15]


def test_resilient_query_tag_siginfo_fallback_and_soft_statuses(capsys):
    import json
    import urllib.error
    from scripts.v2_curate_vault_manifest import MalwareBazaarClient

    # 1. get_taginfo returns {"query_status": "error"} -> falls back once to get_siginfo and returns data
    calls_1: list[dict[str, object]] = []
    mb1 = MalwareBazaarClient(api_key="test_key")

    def _post_1(fields):
        calls_1.append(dict(fields))
        if fields.get("query") == "get_taginfo":
            return json.dumps({"query_status": "error"}).encode("utf-8")
        assert fields == {"query": "get_siginfo", "signature": "AgentTesla", "limit": 50}
        return json.dumps({"query_status": "ok", "data": [{"sha256_hash": "a" * 64}]}).encode("utf-8")

    mb1._post = _post_1  # type: ignore[method-assign]
    rows_1 = mb1.query_tag("AgentTesla", limit=50)
    assert len(rows_1) == 1 and rows_1[0]["sha256_hash"] == "a" * 64
    assert [c["query"] for c in calls_1] == ["get_taginfo", "get_siginfo"]

    # 2. Transient URLError on get_taginfo -> falls back once to get_siginfo
    calls_2: list[dict[str, object]] = []
    mb2 = MalwareBazaarClient(api_key="test_key")

    def _post_2(fields):
        calls_2.append(dict(fields))
        if fields.get("query") == "get_taginfo":
            raise urllib.error.URLError("timed out")
        return json.dumps({"query_status": "ok", "data": [{"sha256_hash": "b" * 64}]}).encode("utf-8")

    mb2._post = _post_2  # type: ignore[method-assign]
    rows_2 = mb2.query_tag("LummaC2", limit=40)
    assert len(rows_2) == 1 and rows_2[0]["sha256_hash"] == "b" * 64
    assert [c["query"] for c in calls_2] == ["get_taginfo", "get_siginfo"]

    # 3. Both get_taginfo and get_siginfo return soft failure statuses or network errors -> warn & return []
    mb3 = MalwareBazaarClient(api_key="test_key")
    mb3._post = lambda _f: json.dumps({"query_status": "error"}).encode("utf-8")  # type: ignore[method-assign]
    assert mb3.query_tag("AgentTesla") == []
    assert "get_siginfo" in capsys.readouterr().err

    mb3._post = lambda f: json.dumps(  # type: ignore[method-assign]
        {"query_status": "error" if f.get("query") == "get_taginfo" else "sig_not_found"}
    ).encode("utf-8")
    assert mb3.query_tag("UnknownSig") == []
    assert "sig_not_found" in capsys.readouterr().err

    def _post_both_fail(fields):
        raise TimeoutError("network timeout")

    mb3._post = _post_both_fail  # type: ignore[method-assign]
    assert mb3.query_tag("TimeoutSig") == []
    assert "TimeoutSig" in capsys.readouterr().err


def test_curator_skips_disguised_dll_curates_backup_and_uses_stage_a_fast_query(tmp_path, capsys):
    import json
    import os
    from scripts.v2_curate_vault_manifest import CATEGORY_SEARCH_TAGS, curate_pilot_vault_and_batch

    repo = Path(__file__).resolve().parent.parent
    setup_script = repo / "docs" / "v2" / "hardening" / "05_quarantine_vault_setup.sh"
    vault_dir = tmp_path / "vault_dll_backup"
    subprocess.run(["bash", str(setup_script), "init"], env=dict(os.environ, VAULT_ROOT=str(vault_dir)), check=True)
    marker = vault_dir / "GATE0_SIGNED_OFF"
    marker.write_text(
        "SIGNED_BY=Mokh\nDATE=2026-11-27\nSUPERVISOR_APPROVAL=Supervisor Marawan (AASTMT) 2026-11-25\n"
        "CONTAINMENT_CHECKS=NEG-01..NEG-10 PASS\nDEDICATED_USER_VERIFIED=true\n",
        encoding="utf-8",
    )
    os.chmod(marker, 0o400)

    # Top-ranked redline candidate is a DLL disguised as .exe (higher persistence score via multiple hint tokens)
    dll_bytes = _synth_unsigned_pe_bytes(701, 16384, is_dll=True)
    dll_sha = hashlib.sha256(dll_bytes).hexdigest()
    dll_zip = _make_aes256_zip(tmp_path, "redline_bad", dll_bytes).read_bytes()

    exe_bytes = _synth_unsigned_pe_bytes(702, 16896, is_dll=False)
    exe_sha = hashlib.sha256(exe_bytes).hexdigest()
    exe_zip = _make_aes256_zip(tmp_path, "redline_good", exe_bytes).read_bytes()

    class _BackupFeed:
        def query_tag(self, tag: str, limit: int = 50):
            if tag == "RedLine":
                return [
                    {
                        "sha256_hash": dll_sha,
                        "signature": "RedLine",
                        "file_name": "redline_bad.exe",
                        "file_type": "exe",
                        "file_size": len(dll_bytes),
                        "imphash": "1" * 32,
                        "tags": ["redline", "persist", "startup", "run", "scheduled"],
                    },
                    {
                        "sha256_hash": exe_sha,
                        "signature": "RedLine",
                        "file_name": "redline_good.exe",
                        "file_type": "exe",
                        "file_size": len(exe_bytes),
                        "imphash": "2" * 32,
                        "tags": ["redline"],
                    },
                ]
            return []

        def download_sample_zip(self, sha256_hash: str) -> bytes:
            return {"dl": dll_zip, "ex": exe_zip}[
                "dl" if sha256_hash.lower() == dll_sha else "ex"
            ]

    out = curate_pilot_vault_and_batch(
        vault_root=vault_dir,
        setup_script=setup_script,
        target_families=1,
        min_families=1,
        n_control_boots=1,
        client=_BackupFeed(),
        plan_only=False,
    )
    err_txt = capsys.readouterr().err
    assert "Skipping candidate" in err_txt and "IMAGE_FILE_DLL" in err_txt
    assert out["families"] == ["redline"]
    assert not (vault_dir / "archives" / f"{dll_sha}.zip").exists()
    assert not list((vault_dir / "archives").glob(".tmp_*.zip"))
    assert (vault_dir / "archives" / f"{exe_sha}.zip").exists()
    manifest_obj = json.loads(Path(out["vault_manifest_path"]).read_text(encoding="utf-8"))
    assert manifest_obj["samples"][0]["sample_sha256"] == exe_sha

    # Fast tag-query mode for Stage A: stops querying extra tags in stealer once >= 3 canonical families
    # have >= 3 candidates each, and only queries remaining tags if downloads exhaust initial candidates.
    vault_fast = tmp_path / "vault_fast"
    subprocess.run(["bash", str(setup_script), "init"], env=dict(os.environ, VAULT_ROOT=str(vault_fast)), check=True)
    m_fast = vault_fast / "GATE0_SIGNED_OFF"
    m_fast.write_text(marker.read_text(encoding="utf-8"), encoding="utf-8")
    os.chmod(m_fast, 0o400)

    fast_zips: dict[str, bytes] = {}
    rows_by_tag: dict[str, list[dict[str, object]]] = {}
    for f_idx, (fam, tag_name) in enumerate((("redline", "RedLine"), ("lumma", "LummaC2"), ("vidar", "Vidar"))):
        rows_by_tag[tag_name] = []
        for c_idx in range(3):
            raw_b = _synth_unsigned_pe_bytes(800 + f_idx * 10 + c_idx, 16384 + c_idx * 512, is_dll=False)
            sha_b = hashlib.sha256(raw_b).hexdigest()
            fast_zips[sha_b] = _make_aes256_zip(tmp_path, f"f_{fam}_{c_idx}", raw_b).read_bytes()
            rows_by_tag[tag_name].append({
                "sha256_hash": sha_b,
                "signature": fam,
                "file_name": f"{fam}_{c_idx}.exe",
                "file_type": "exe",
                "file_size": len(raw_b),
                "imphash": f"{f_idx + 1}{c_idx + 1:031x}",
                "tags": [fam],
            })

    # Also test lazy fallback when initial stealer families all fail download/validation:
    # RedLine hits only appear on tag "Vidar" as >=3 families if AgentTesla isn't queried initially!
    # Wait: let's add a later tag "SnakeKeylogger" that must NOT be queried when Vidar already satisfies >=3 families with >=3 cands.
    queried_tags: list[str] = []

    class _FastModeFeed:
        def query_tag(self, tag: str, limit: int = 50):
            queried_tags.append(tag)
            return list(rows_by_tag.get(tag, []))

        def download_sample_zip(self, sha256_hash: str) -> bytes:
            return fast_zips[sha256_hash.lower()]

    stealer_tags = dict(CATEGORY_SEARCH_TAGS)["stealer"]
    curate_pilot_vault_and_batch(
        vault_root=vault_fast,
        setup_script=setup_script,
        target_families=3,
        min_families=3,
        n_control_boots=1,
        client=_FastModeFeed(),
        plan_only=False,
    )
    # "RedLine" (idx 0), "LummaC2" (idx 1), "AgentTesla" (idx 3), "Vidar" (idx 4) -> 3 ready families => stopped before "Raccoon" / "SnakeKeylogger"!
    assert "Vidar" in queried_tags
    assert "SnakeKeylogger" not in queried_tags
    assert "Lokibot" not in queried_tags
    assert len(queried_tags) < sum(len(t) for _, t in CATEGORY_SEARCH_TAGS)

    # When downloads exhaust initial candidates in fast mode, remaining tags in that category ARE queried lazily
    vault_exhaust = tmp_path / "vault_exhaust"
    subprocess.run(["bash", str(setup_script), "init"], env=dict(os.environ, VAULT_ROOT=str(vault_exhaust)), check=True)
    m_exh = vault_exhaust / "GATE0_SIGNED_OFF"
    m_exh.write_text(marker.read_text(encoding="utf-8"), encoding="utf-8")
    os.chmod(m_exh, 0o400)

    snake_raw = _synth_unsigned_pe_bytes(899, 16384, is_dll=False)
    snake_sha = hashlib.sha256(snake_raw).hexdigest()
    snake_zip = _make_aes256_zip(tmp_path, "snake_ok", snake_raw).read_bytes()
    rows_exhaust = {
        **rows_by_tag,
        "SnakeKeylogger": [{
            "sha256_hash": snake_sha,
            "signature": "SnakeKeylogger",
            "file_name": "snake.exe",
            "file_type": "exe",
            "file_size": len(snake_raw),
            "imphash": "9" * 32,
            "tags": ["snakekeylogger"],
        }],
    }
    queried_exh: list[str] = []

    class _ExhaustThenRecoverFeed:
        def query_tag(self, tag: str, limit: int = 50):
            queried_exh.append(tag)
            return list(rows_exhaust.get(tag, []))

        def download_sample_zip(self, sha256_hash: str) -> bytes:
            if sha256_hash.lower() == snake_sha:
                return snake_zip
            raise RuntimeError("transient download failure")

    out_exh = curate_pilot_vault_and_batch(
        vault_root=vault_exhaust,
        setup_script=setup_script,
        target_families=1,
        min_families=1,
        n_control_boots=1,
        client=_ExhaustThenRecoverFeed(),
        plan_only=False,
    )
    assert "SnakeKeylogger" in queried_exh
    assert out_exh["families"] == ["snakekeylogger"]


def test_verify_canary_requires_positive_sysmon_delta_over_control(tmp_path):
    import json
    from src.v2.run_stage_a_pilot import verify_canary_run_outputs

    def _mk_runs(ctrl_cnt: int, dorm_cnt: int, exec_cnt: int, tag: str):
        base = tmp_path / tag
        specs = [("c_ctrl", "control", ctrl_cnt, False), ("c_dorm", "dormant", dorm_cnt, False), ("c_exec", "executed", exec_cnt, True)]
        rlog = []
        for rid, strat, cnt, evtx_ok in specs:
            rdir = base / rid
            rdir.mkdir(parents=True, exist_ok=True)
            (rdir / "extraction_manifest.json").write_text(
                json.dumps({
                    "run_id": rid,
                    "total_records": 4413,
                    "sysmon_evtx_present": evtx_ok,
                    "sysmon_events_count": cnt,
                }),
                encoding="utf-8",
            )
            rlog.append({"run_id": rid, "stratum": strat, "out_dir": str(rdir)})
        return rlog, base

    common = dict(
        batch_json_sha256="a" * 64,
        base_image_sha256="b" * 64,
        git_head="c" * 40,
        git_dirty=False,
    )

    # Equal to 7306 control baseline -> MUST fail
    logs_eq, dir_eq = _mk_runs(7306, 7306, 7306, "eq")
    with pytest.raises(PilotStagingError, match="did not exceed control baseline"):
        verify_canary_run_outputs(logs_eq, dir_eq, dir_eq / "CANARY_PASSED", **common)

    # Below 7306 control baseline -> MUST fail
    logs_lt, dir_lt = _mk_runs(7306, 7306, 7300, "lt")
    with pytest.raises(PilotStagingError, match="did not exceed control baseline"):
        verify_canary_run_outputs(logs_lt, dir_lt, dir_lt / "CANARY_PASSED", **common)

    # Strictly above 7306 control baseline -> PASSES
    logs_gt, dir_gt = _mk_runs(7306, 7306, 7342, "gt")
    stamp = verify_canary_run_outputs(logs_gt, dir_gt, dir_gt / "CANARY_PASSED", **common)
    assert stamp["status"] == "PASS"
    assert stamp["max_control_sysmon_events"] == 7306
    assert stamp["executed_sysmon_events_total"] == 7342


def test_relative_runs_out_dir_resolves_absolute_iso_and_dac_modes(tmp_path, monkeypatch):
    import stat

    monkeypatch.chdir(tmp_path)
    rel_runs_dir = Path("runs/stage_a_pilot")
    expected_root = (tmp_path / rel_runs_dir).resolve()
    ctrl_batch = [
        {
            "spec": StageRunSpec(
                run_id="pilot_ctrl_01",
                stratum="control",
                benign_profile_id="B_dev_01",
                dwell_seconds=15,
            ).__dict__,
            "vault_file": None,
        }
    ]

    observed_cmds: list[list[str]] = []
    observed_attach_iso: list[str] = []
    observed_extract_out: list[str] = []
    observed_modes: dict[str, int] = {}

    def _inspect_cmd(cmd: list[str], _env=None) -> int:
        observed_cmds.append(list(cmd))
        if len(cmd) >= 6 and cmd[:4] == ["sudo", "virsh", "-c", "qemu:///system"] and cmd[4] == "attach-disk":
            iso_arg = cmd[6]
            observed_attach_iso.append(iso_arg)
            iso_file = Path(iso_arg)
            stage_dir = iso_file.parent
            stage_root = stage_dir.parent
            out_dir = stage_root.parent
            assert iso_file.is_file()
            observed_modes["out_root"] = stat.S_IMODE(out_dir.stat().st_mode)
            observed_modes["stage_root"] = stat.S_IMODE(stage_root.stat().st_mode)
            observed_modes["stage_dir"] = stat.S_IMODE(stage_dir.stat().st_mode)
            observed_modes["iso_file"] = stat.S_IMODE(iso_file.stat().st_mode)
        elif cmd and cmd[0].endswith("06_unprivileged_container_runner.sh"):
            observed_extract_out.append(cmd[2])
        return 0

    res = execute_stage_a_pilot_batch(
        batch_runs=ctrl_batch,
        runs_out_dir=rel_runs_dir,
        inetsim_wait_seconds=0,
        run_cmd=_inspect_cmd,
        sleep_fn=lambda _s: None,
    )
    assert len(res) == 1
    assert len(observed_attach_iso) == 1
    assert observed_attach_iso[0].startswith("/")
    assert observed_attach_iso[0] == str(expected_root / "_staging_iso" / "pilot_ctrl_01" / "run_stage_pilot_ctrl_01.iso")
    attach_idx = next(i for i, c in enumerate(observed_cmds) if len(c) >= 5 and c[4] == "attach-disk")
    tb_idx = observed_cmds[attach_idx].index("--targetbus")
    assert observed_cmds[attach_idx][tb_idx + 1] == "sata"
    chmod_idx = next(i for i, c in enumerate(observed_cmds) if c[:3] == ["sudo", "chmod", "a+r"])
    ext_idx = next(i for i, c in enumerate(observed_cmds) if c and c[0].endswith("06_unprivileged_container_runner.sh"))
    assert chmod_idx < ext_idx
    assert observed_cmds[chmod_idx][3].endswith("win11_overlay.qcow2")
    assert len(observed_extract_out) == 1 and observed_extract_out[0].startswith("/")
    assert observed_extract_out[0] == str(expected_root / "pilot_ctrl_01")
    assert res[0]["out_dir"] == str(expected_root / "pilot_ctrl_01")
    assert observed_modes == {
        "out_root": 0o755,
        "stage_root": 0o755,
        "stage_dir": 0o755,
        "iso_file": 0o644,
    }
