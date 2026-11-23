"""Unit tests for Step C.4: synthetic v2 causal/dormant labeler and blinded two-reviewer workflow."""
from __future__ import annotations

import pandas as pd
import pytest

from src import config
from src.v2.labeler_v2 import (
    AMBIGUOUS_LABEL,
    assign_v2_splits,
    build_multi_control_baseline,
    label_dormant_run,
    label_executed_run,
    trace_sysmon_process_tree,
)
from src.v2.review_v2 import (
    BLINDED_STRIP_COLS,
    compute_inter_rater_kappa,
    export_blinded_review_sample,
    merge_label_corrections,
)


def _baseline_df(run_id: str, extra_rows=()):
    rows = [
        {"artifact_type": "file", "artifact_key": "file|c:\\windows\\notepad.exe|notepad.exe",
         "name": "notepad.exe", "path": "C:\\Windows\\notepad.exe", "file_sha256": "aaa111"},
        {"artifact_type": "service", "artifact_key": "service|svc1|svc1",
         "name": "Svc1", "path": "C:\\Windows\\System32\\svchost.exe", "file_sha256": "bbb222"},
    ] + list(extra_rows)
    return pd.DataFrame(rows)


def test_sysmon_process_tree_and_ambiguous_quarantine():
    base = build_multi_control_baseline([_baseline_df("ctrl_01"), _baseline_df("ctrl_02")])
    assert base["n_control_boots"] == 2

    sysmon = [
        {"event_id": 1, "process_guid": "{mal-root}", "parent_process_guid": "{exp}", "pid": 400, "ppid": 100,
         "image": r"C:\Users\Public\dropper.exe", "hashes": "sha256=deadbeef01"},
        {"event_id": 1, "process_guid": "{mal-child}", "parent_process_guid": "{mal-root}", "pid": 401, "ppid": 400,
         "image": r"C:\Windows\System32\cmd.exe"},
        {"event_id": 11, "process_guid": "{mal-child}", "pid": 401,
         "target_filename": r"C:\ProgramData\beacon_cfg.dat"},
        {"event_id": 13, "process_guid": "{mal-child}", "pid": 401,
         "target_object": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\EvilPers"},
        {"event_id": 1, "process_guid": "{ben-root}", "parent_process_guid": "{exp}", "pid": 500, "ppid": 100,
         "image": r"C:\Program Files\Git\cmd\git.exe"},
        {"event_id": 11, "process_guid": "{ben-root}", "pid": 500,
         "target_filename": r"C:\Users\alice\git_status.tmp"},
    ]
    tr = trace_sysmon_process_tree(sysmon, root_guids=["{mal-root}"])
    assert "{mal-child}" in tr["tree_guids"]
    assert r"c:\programdata\beacon_cfg.dat" in tr["attributed_paths"]

    run_df = pd.DataFrame([
        {"artifact_type": "file", "artifact_key": "file|c:\\windows\\notepad.exe|notepad.exe",
         "name": "notepad.exe", "path": "C:\\Windows\\notepad.exe", "file_sha256": "aaa111"},
        {"artifact_type": "file", "artifact_key": r"file|c:\programdata\beacon_cfg.dat|beacon_cfg.dat",
         "name": "beacon_cfg.dat", "path": r"C:\ProgramData\beacon_cfg.dat", "file_sha256": "cc99"},
        {"artifact_type": "run_key", "artifact_key": r"run_key|hku\evilpers|evilpers",
         "name": "EvilPers", "path": r"C:\ProgramData\beacon_cfg.dat",
         "registry_key": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", "file_sha256": "dd00"},
        {"artifact_type": "file", "artifact_key": r"file|c:\users\alice\git_status.tmp|git_status.tmp",
         "name": "git_status.tmp", "path": r"C:\Users\alice\git_status.tmp", "file_sha256": "ee11"},
        {"artifact_type": "file", "artifact_key": r"file|c:\windows\temp\mystery_drop.dll|mystery_drop.dll",
         "name": "mystery_drop.dll", "path": r"C:\Windows\Temp\mystery_drop.dll", "file_sha256": "ff22"},
    ])
    labeled = label_executed_run(
        run_df, base, sysmon, run_id="exec_01",
        malware_root_guids=["{mal-root}"], benign_scheduler_guids=["{ben-root}"],
        sample_meta={"sample_sha256": "deadbeef01", "sample_family": "asyncrat", "pair_group_id": "deadbeef01"},
    )
    by_name = dict(zip(labeled["name"], labeled[config.LABEL_COL]))
    assert by_name["notepad.exe"] == "baseline"
    assert by_name["beacon_cfg.dat"] == config.POSITIVE_LABEL
    assert by_name["EvilPers"] == config.POSITIVE_LABEL  # unknown/arbitrary persistence key still caught via reg_key prefix!
    assert by_name["git_status.tmp"] == "benign_drift"
    # Residual unattributed diff MUST be ambiguous_unattributed (never silently benign_drift)
    assert by_name["mystery_drop.dll"] == AMBIGUOUS_LABEL


def test_dormant_labeling_and_paired_binary_split_isolation():
    base = build_multi_control_baseline([_baseline_df("ctrl_01")])
    dorm_df = pd.DataFrame([
        {"artifact_type": "file", "artifact_key": r"file|c:\users\public\stage\sample.exe|sample.exe",
         "name": "sample.exe", "path": r"C:\Users\Public\stage\sample.exe", "file_sha256": "deadbeef01"},
        {"artifact_type": "file", "artifact_key": "file|c:\\windows\\notepad.exe|notepad.exe",
         "name": "notepad.exe", "path": "C:\\Windows\\notepad.exe", "file_sha256": "aaa111"},
    ])
    dorm_labeled = label_dormant_run(
        dorm_df, base,
        staged_manifest=[{"staged_path": r"C:\Users\Public\stage\sample.exe", "sample_sha256": "deadbeef01"}],
        run_id="dorm_01",
        sample_meta={"sample_sha256": "deadbeef01", "sample_family": "asyncrat", "packer_cluster": "clu_1", "pair_group_id": "deadbeef01"},
    )
    assert dorm_labeled.loc[0, config.LABEL_COL] == config.POSITIVE_LABEL
    assert dorm_labeled.loc[0, "stratum"] == "dormant"

    # Combine executed + dormant + emulated and verify paired closure keeps executed & dormant in test together
    exec_df = pd.DataFrame([{
        "run_id": "exec_01", "artifact_type": "file", "artifact_key": r"file|c:\users\public\stage\sample.exe|sample.exe",
        "name": "sample.exe", "path": r"C:\Users\Public\stage\sample.exe",
        config.LABEL_COL: config.POSITIVE_LABEL, "sample_sha256": "deadbeef01", "sample_family": "asyncrat",
        "packer_cluster": "clu_1", "pair_group_id": "deadbeef01", "stratum": "executed",
    }, {
        "run_id": "emu_01", "artifact_type": "file", "artifact_key": "file|c:\\emu\\v1.ps1|v1.ps1",
        "name": "v1.ps1", "path": "C:\\emu\\v1.ps1", config.LABEL_COL: config.POSITIVE_LABEL,
        "sample_sha256": None, "sample_family": None, "packer_cluster": None, "pair_group_id": None, "stratum": "emulated",
    }])
    combined = pd.concat([dorm_labeled, exec_df], ignore_index=True)
    split_df = assign_v2_splits(combined, blind_test_families=["asyncrat"])
    async_pools = set(split_df[split_df["sample_family"] == "asyncrat"]["split_pool"])
    assert async_pools == {"test"}  # BOTH dormant and executed moved to test together
    assert set(split_df[split_df["stratum"] == "emulated"]["split_pool"]) == {"dev"}


def test_blinded_two_reviewer_workflow_and_non_overwrite_guard(tmp_path):
    rows = []
    for i in range(15):
        rows.append({
            "run_id": f"r_{i//3}", "stratum": "executed", "execution_state": "executed",
            "artifact_type": "file", "artifact_key": f"file|c:\\p\\a{i}.exe|a{i}.exe",
            "name": f"a{i}.exe", "path": f"C:\\p\\a{i}.exe", "command_line": "",
            "registry_key": "", "signature_status": "NotSigned", "file_size": 1000 + i,
            config.LABEL_COL: config.POSITIVE_LABEL if i < 6 else ("benign_drift" if i < 12 else AMBIGUOUS_LABEL),
            "label_reason": "sysmon_process_tree_attribution",
            "launcher": "attack",
            "sample_family": "test_fam",
            "pair_group_id": "pair_1",
        })
    df = pd.DataFrame(rows)

    p_csv = tmp_path / "primary_review.csv"
    o_csv = tmp_path / "overlap_review.csv"
    k_json = tmp_path / "sealed_keys.json"
    info = export_blinded_review_sample(df, p_csv, o_csv, k_json, overlap_frac=0.20, seed=42)
    assert info["n_primary"] == 15 and info["n_overlap"] >= 3

    # Must refuse to overwrite existing populated/exported review files
    with pytest.raises(FileExistsError):
        export_blinded_review_sample(df, p_csv, o_csv, k_json)

    # Assert strict blinding
    prim = pd.read_csv(p_csv, keep_default_na=False)
    for col in BLINDED_STRIP_COLS:
        assert col not in prim.columns

    # Populate primary (friend) and overlap (mokh) with distinct rationales
    prim["reviewer_id"] = "friend_primary"
    prim["reviewed_at_utc"] = "2026-11-23T02:00:00Z"
    prim["human_label"] = [config.POSITIVE_LABEL if i < 6 else "benign_drift" for i in range(len(prim))]
    prim["human_notes"] = [f"Verified tree parent & path index check item {i}" for i in range(len(prim))]
    prim.to_csv(p_csv, index=False)

    ov = pd.read_csv(o_csv, keep_default_na=False)
    ov["reviewer_id"] = "mokh_overlap"
    ov["reviewed_at_utc"] = "2026-11-23T02:05:00Z"
    # Match primary reviewer labels cleanly to test kappa calculation
    p_map = dict(zip(prim["review_id"], prim["human_label"]))
    ov["human_label"] = [p_map[rid] for rid in ov["review_id"]]
    ov["human_notes"] = [f"Independent overlap check rationale row {i}" for i in range(len(ov))]
    ov.to_csv(o_csv, index=False)

    k_res = compute_inter_rater_kappa(p_csv, o_csv)
    assert k_res["cohen_kappa"] == pytest.approx(1.0)
    assert k_res["primary_reviewers"] == ["friend_primary"]
    assert k_res["overlap_reviewers"] == ["mokh_overlap"]

    # Reject same reviewer scoring both primary & overlap
    ov["reviewer_id"] = "friend_primary"
    ov.to_csv(o_csv, index=False)
    with pytest.raises(ValueError, match="distinct individuals"):
        compute_inter_rater_kappa(p_csv, o_csv)

    merged = merge_label_corrections(df, prim)
    assert (merged["label_review_status"] == "human_reviewed").all()
