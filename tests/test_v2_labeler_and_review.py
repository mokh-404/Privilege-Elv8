"""Unit tests for Step C.4: synthetic v2 causal/dormant labeler and blinded two-reviewer workflow."""
from __future__ import annotations

import pandas as pd
import pytest

from src import config
from src.v2.labeler_v2 import (
    AMBIGUOUS_LABEL,
    assign_v2_splits,
    build_multi_control_baseline,
    deduplicate_dev_os_baseline,
    label_dormant_batch_run,
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


def test_review_v2_caps_large_dataset_to_400_and_80_overlap_stratified(tmp_path):
    import json

    rows = []
    fams = ["redline", "asyncrat", "smokeloader", "xmrig"]
    for i in range(5600):
        st = "executed" if i < 2800 else "dormant"
        fam = fams[i % len(fams)]
        rows.append({
            "run_id": f"r_{i // 10}",
            "stratum": st,
            "execution_state": st,
            "artifact_type": "file",
            "artifact_key": f"file|c:\\u\\{fam}_{i}.exe|{fam}_{i}.exe",
            "name": f"{fam}_{i}.exe",
            "path": f"C:\\u\\{fam}_{i}.exe",
            "command_line": "",
            "registry_key": "",
            "signature_status": "NotSigned",
            "file_size": 10000 + i,
            config.LABEL_COL: config.POSITIVE_LABEL,
            "label_reason": "sysmon_process_tree_attribution",
            "launcher": "attack",
            "sample_family": fam,
            "pair_group_id": f"pair_{i}",
        })
    for i in range(300):
        rows.append({
            "run_id": f"b_{i // 5}",
            "stratum": "benign",
            "execution_state": "benign",
            "artifact_type": "file",
            "artifact_key": f"file|c:\\ben\\b_{i}.ps1|b_{i}.ps1",
            "name": f"b_{i}.ps1",
            "path": f"C:\\ben\\b_{i}.ps1",
            "command_line": "",
            "registry_key": "",
            "signature_status": "NotSigned",
            "file_size": 500 + i,
            config.LABEL_COL: "benign_drift",
            "label_reason": "benign_staging_manifest_match",
            "launcher": "benign",
            "sample_family": None,
            "pair_group_id": None,
        })
    for i in range(300):
        rows.append({
            "run_id": f"a_{i // 5}",
            "stratum": "executed",
            "execution_state": "executed",
            "artifact_type": "file",
            "artifact_key": f"file|c:\\tmp\\u_{i}.dat|u_{i}.dat",
            "name": f"u_{i}.dat",
            "path": f"C:\\tmp\\u_{i}.dat",
            "command_line": "",
            "registry_key": "",
            "signature_status": "NotSigned",
            "file_size": 700 + i,
            config.LABEL_COL: AMBIGUOUS_LABEL,
            "label_reason": "unattributed_diff_quarantined",
            "launcher": "unattributed",
            "sample_family": None,
            "pair_group_id": None,
        })

    big_df = pd.DataFrame(rows)
    p_csv = tmp_path / "primary_400.csv"
    o_csv = tmp_path / "overlap_80.csv"
    k_json = tmp_path / "key_400.json"
    info = export_blinded_review_sample(big_df, p_csv, o_csv, k_json, overlap_frac=0.20, seed=42)
    assert info["n_primary"] == 400
    assert info["n_overlap"] == 80

    key_data = json.loads(k_json.read_text(encoding="utf-8"))
    labels = [v["auto_label"] for v in key_data["keys"].values()]
    assert labels.count(config.POSITIVE_LABEL) == 200
    assert labels.count("benign_drift") == 100
    assert labels.count(AMBIGUOUS_LABEL) == 100
    pos_fams = {v["sample_family"] for v in key_data["keys"].values() if v["auto_label"] == config.POSITIVE_LABEL}
    assert pos_fams == set(fams)


def test_label_dormant_batch_run_dev_only_and_deduplicate_dev_os_baseline():
    base = build_multi_control_baseline([_baseline_df("ctrl_01")])
    batch_manifest = [
        {"staging_target_path": r"C:\Users\Public\s0.exe", "sample_sha256": "aa" * 32, "sample_family": "redline", "pair_group_id": "p0"},
        {"staging_target_path": r"C:\Users\Public\s1.exe", "sample_sha256": "bb" * 32, "sample_family": "asyncrat", "pair_group_id": "p1"},
    ]
    run_df = pd.DataFrame([
        {"artifact_type": "file", "artifact_key": "file|c:\\windows\\notepad.exe|notepad.exe",
         "name": "notepad.exe", "path": "C:\\Windows\\notepad.exe", "file_sha256": "aaa111"},
        {"artifact_type": "file", "artifact_key": r"file|c:\users\public\s0.exe|s0.exe",
         "name": "s0.exe", "path": r"C:\Users\Public\s0.exe", "file_sha256": "aa" * 32},
        {"artifact_type": "file", "artifact_key": r"file|c:\users\public\s1.exe|s1.exe",
         "name": "s1.exe", "path": r"C:\Users\Public\s1.exe", "file_sha256": "bb" * 32},
        {"artifact_type": "file", "artifact_key": r"file|c:\programdata\ben_tool.ps1|ben_tool.ps1",
         "name": "ben_tool.ps1", "path": r"C:\ProgramData\ben_tool.ps1", "file_sha256": "cc" * 32},
    ])

    with pytest.raises(ValueError, match="strictly dev-only"):
        label_dormant_batch_run(run_df, base, batch_manifest, run_id="db_bad", split_pool="blind_test")

    # Mark s1 as unexpectedly executed via Sysmon EID 1 to verify quarantine guard
    labeled = label_dormant_batch_run(
        run_df,
        base,
        batch_manifest,
        run_id="db_dev_01",
        sysmon_events=[{"event_id": 1, "image": r"C:\Users\Public\s1.exe", "hashes": f"SHA256={'bb' * 32}"}],
        benign_manifest={"files": [{"path": r"C:\ProgramData\ben_tool.ps1", "file_sha256": "cc" * 32}]},
        split_pool="dev",
    )
    by_name = dict(zip(labeled["name"], labeled[config.LABEL_COL]))
    assert by_name["notepad.exe"] == "baseline"
    assert by_name["s0.exe"] == config.POSITIVE_LABEL
    assert by_name["s1.exe"] == AMBIGUOUS_LABEL
    assert by_name["ben_tool.ps1"] == "benign_drift"

    # Cross-run OS-baseline deduplication works on dev and blocks test
    dup_dev = pd.DataFrame([
        {"run_id": "r1", "split_pool": "dev", "artifact_type": "file", "artifact_key": "k_os", "name": "n.exe", "path": "C:\\Windows\\n.exe", "file_sha256": "111", config.LABEL_COL: "baseline"},
        {"run_id": "r2", "split_pool": "dev", "artifact_type": "file", "artifact_key": "k_os", "name": "n.exe", "path": "C:\\Windows\\n.exe", "file_sha256": "111", config.LABEL_COL: "baseline"},
        {"run_id": "r1", "split_pool": "dev", "artifact_type": "file", "artifact_key": "k_dr1", "name": "d1.ps1", "path": "C:\\tmp\\d1.ps1", "file_sha256": "222", config.LABEL_COL: "benign_drift"},
        {"run_id": "r2", "split_pool": "dev", "artifact_type": "file", "artifact_key": "k_dr2", "name": "d1.ps1", "path": "C:\\tmp\\d1.ps1", "file_sha256": "222", config.LABEL_COL: "benign_drift"},
    ])
    ded = deduplicate_dev_os_baseline(dup_dev)
    assert len(ded) == 3  # 1 baseline + 2 benign_drift retained

    bad_test = dup_dev.copy()
    bad_test.loc[0, "split_pool"] = "test"
    with pytest.raises(ValueError, match="Blind test must NEVER be deduplicated"):
        deduplicate_dev_os_baseline(bad_test)


def test_assign_v2_splits_and_training_groups_keep_canonical_aliases_together():
    from src.v2.training import build_family_cluster_groups

    df = pd.DataFrame([
        {
            "run_id": "r_lumma_1",
            "artifact_type": "file",
            "artifact_key": r"file|c:\users\public\l1.exe|l1.exe",
            "name": "l1.exe",
            "path": r"C:\Users\Public\l1.exe",
            config.LABEL_COL: config.POSITIVE_LABEL,
            "sample_sha256": "11" * 32,
            "sample_family": "Lumma",
            "packer_cluster": "p_1",
            "pair_group_id": "pg_1",
            "stratum": "executed",
        },
        {
            "run_id": "r_lumma_2",
            "artifact_type": "file",
            "artifact_key": r"file|c:\users\public\l2.exe|l2.exe",
            "name": "l2.exe",
            "path": r"C:\Users\Public\l2.exe",
            config.LABEL_COL: config.POSITIVE_LABEL,
            "sample_sha256": "22" * 32,
            "sample_family": "LummaC2",
            "packer_cluster": "p_2",
            "pair_group_id": "pg_2",
            "stratum": "executed",
        },
        {
            "run_id": "r_warzone_1",
            "artifact_type": "file",
            "artifact_key": r"file|c:\users\public\w1.exe|w1.exe",
            "name": "w1.exe",
            "path": r"C:\Users\Public\w1.exe",
            config.LABEL_COL: config.POSITIVE_LABEL,
            "sample_sha256": "33" * 32,
            "sample_family": "AveMaria",
            "packer_cluster": "p_3",
            "pair_group_id": "pg_3",
            "stratum": "dormant",
        },
        {
            "run_id": "r_warzone_2",
            "artifact_type": "file",
            "artifact_key": r"file|c:\users\public\w2.exe|w2.exe",
            "name": "w2.exe",
            "path": r"C:\Users\Public\w2.exe",
            config.LABEL_COL: config.POSITIVE_LABEL,
            "sample_sha256": "44" * 32,
            "sample_family": "WarzoneRAT",
            "packer_cluster": "p_4",
            "pair_group_id": "pg_4",
            "stratum": "dormant",
        },
    ])

    split_df = assign_v2_splits(df, blind_test_families=["LummaStealer"])
    assert set(split_df.loc[[0, 1], "split_pool"]) == {"test"}
    assert set(split_df.loc[[2, 3], "split_pool"]) == {"dev"}

    # Canonical aliases share ONE CV cluster group even with distinct hashes/clusters
    groups = build_family_cluster_groups(df)
    assert groups[0] == groups[1]
    assert groups[2] == groups[3]
    assert groups[0] != groups[2]
