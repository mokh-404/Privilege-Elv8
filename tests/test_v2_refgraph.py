"""Unit tests for Step E5: static refgraph resolver, 3 propagation variants, hub-collapse, and anti-leakage."""
from __future__ import annotations

import pandas as pd
import pytest

from src import config
from src.models.preprocess import LeakageError, SharedPreprocessor
from src.v2.refgraph import (
    RefGraphIDFModel,
    RefGraphPropagator,
    assert_graph_inputs_clean,
    build_disk_graph,
    normalize_windows_path,
    populate_ref_edge_columns,
    propagate_attenuated,
    propagate_base,
    propagate_naive,
    resolve_mft_reference,
)


def test_path_obfuscation_83_env_prefixes_and_ads():
    short_map = {
        r"c:\users\public\progra~1": r"c:\users\public\program_payload",
        r"c:\users\public\program_payload\bad~1.dll": r"c:\users\public\program_payload\bad_sideload.dll",
    }
    p1, ads1 = normalize_windows_path(r'  "\??\%SystemRoot%/System32/RUNDLL32.EXE " ', short_to_long=short_map)
    assert p1 == r"c:\windows\system32\rundll32.exe" and ads1 is None

    p2, ads2 = normalize_windows_path(r"\\?\C:\Users\Public\PROGRA~1\BAD~1.DLL", short_to_long=short_map)
    assert p2 == r"c:\users\public\program_payload\bad_sideload.dll" and ads2 is None

    p3, ads3 = normalize_windows_path(r"\Device\HarddiskVolume3\Windows\System32\notepad.exe:evil.exe")
    assert p3 == r"c:\windows\system32\notepad.exe"
    assert ads3 == "evil.exe"


def test_four_mft_reference_states():
    mft = {
        100: {"mft_record_number": 100, "mft_sequence_number": 5, "mft_in_use": True},
        101: {"mft_record_number": 101, "mft_sequence_number": 3, "mft_in_use": False},
        102: {"mft_record_number": 102, "mft_sequence_number": 9, "mft_in_use": True},
    }
    assert resolve_mft_reference(100, 5, mft) == "live_matched"
    assert resolve_mft_reference(101, 2, mft) == "deleted_unreused"
    assert resolve_mft_reference(102, 4, mft) == "deleted_reused_or_seq_mismatch"
    assert resolve_mft_reference(999, 1, mft) == "dangling"


def test_com_hijack_hkcu_precedence_servicedll_wmi_and_ghosttask_parity():
    df = pd.DataFrame([
        {
            "run_id": "d1", "artifact_type": "task", "artifact_key": "task|\\evilcom|evilcom",
            "name": "EvilCom", "path": None, "command_line": "COM:{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}",
            "task_com_clsid": "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}",
            "task_xml_exists": False,
        },
        {
            "run_id": "d1", "artifact_type": "clsid", "artifact_key": "clsid|hklm|aaa",
            "name": "InprocServer32", "path": r"C:\Windows\System32\legit.dll",
            "clsid_guid": "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}", "clsid_hive": "HKLM", "clsid_wow64": False,
            "clsid_server_expanded": r"C:\Windows\System32\legit.dll",
        },
        {
            "run_id": "d1", "artifact_type": "clsid", "artifact_key": "clsid|hkcu|aaa",
            "name": "InprocServer32", "path": r"C:\Users\Public\evil_com.dll",
            "clsid_guid": "{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}", "clsid_hive": "HKCU", "clsid_wow64": False,
            "clsid_server_expanded": r"C:\Users\Public\evil_com.dll",
        },
        {
            "run_id": "d1", "artifact_type": "file", "artifact_key": r"file|c:\users\public\evil_com.dll|evil_com.dll",
            "name": "evil_com.dll", "path": r"C:\Users\Public\evil_com.dll",
        },
        {
            "run_id": "d1", "artifact_type": "file", "artifact_key": r"file|c:\windows\system32\legit.dll|legit.dll",
            "name": "legit.dll", "path": r"C:\Windows\System32\legit.dll",
        },
        {
            "run_id": "d1", "artifact_type": "service", "artifact_key": "service|hklm\\services\\badsvc|badsvc",
            "name": "BadSvc", "path": r"C:\Windows\System32\svchost.exe",
            "command_line": r"C:\Windows\System32\svchost.exe -k netsvcs",
            "service_dll_expanded": r"%ProgramData%\svcdll.dll",
        },
        {
            "run_id": "d1", "artifact_type": "file", "artifact_key": r"file|c:\programdata\svcdll.dll|svcdll.dll",
            "name": "svcdll.dll", "path": r"C:\ProgramData\svcdll.dll",
        },
    ])
    g = build_disk_graph(df, disk_id="d1")
    edge_pairs = {(u, v, et) for u, v, et, _, _ in g.typed_edges}
    assert ("task|\\evilcom|evilcom", "task|\\evilcom|evilcom", "PARITY_MISMATCH") in edge_pairs
    # HKCU takes precedence over HKLM for {GUID} resolution -> resolves to evil_com.dll, NOT legit.dll
    assert ("clsid|{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}", r"file|c:\users\public\evil_com.dll|evil_com.dll", "RESOLVES_COM_DLL") in edge_pairs
    assert ("clsid|{aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee}", r"file|c:\windows\system32\legit.dll|legit.dll", "RESOLVES_COM_DLL") not in edge_pairs
    assert ("ctx|service|hklm\\services\\badsvc|badsvc", r"file|c:\programdata\svcdll.dll|svcdll.dll", "HOSTS_SERVICEDLL") in edge_pairs

    enriched = populate_ref_edge_columns(df, disk_id="d1")
    for col in config.REFGRAPH_EDGE_COLUMNS:
        assert col in enriched.columns


def _make_training_hub_disk(disk_id: str) -> pd.DataFrame:
    """Clean training disk containing universal hubs rundll32.exe and ntdll.dll."""
    return pd.DataFrame([
        {"run_id": disk_id, "artifact_type": "file", "artifact_key": r"file|c:\windows\system32\rundll32.exe|rundll32.exe",
         "name": "rundll32.exe", "path": r"C:\Windows\System32\rundll32.exe", "mft_record_number": 10, "mft_sequence_number": 1, "mft_in_use": True},
        {"run_id": disk_id, "artifact_type": "file", "artifact_key": r"file|c:\windows\system32\ntdll.dll|ntdll.dll",
         "name": "ntdll.dll", "path": r"C:\Windows\System32\ntdll.dll", "mft_record_number": 11, "mft_sequence_number": 1, "mft_in_use": True},
        {"run_id": disk_id, "artifact_type": "prefetch", "artifact_key": f"prefetch|rundll_{disk_id}|rundll32.exe-11111111.pf",
         "name": "RUNDLL32.EXE-11111111.pf", "path": r"C:\Windows\Prefetch\RUNDLL32.EXE-11111111.pf",
         "pf_executable_name": "rundll32.exe", "pf_scca_hash": "11111111",
         "pf_file_metrics": [{"file_path": r"C:\Windows\System32\ntdll.dll", "mft_index": 11, "mft_sequence": 1}]},
    ])


def test_synthetic_hub_collapse_naive_smears_while_attenuated_isolates_rare_sideload():
    # 1. Fit IDF strictly on 10 training disks where ntdll.dll appears on 10/10 disks (IHF = 0.0)
    train_df = pd.concat([_make_training_hub_disk(f"train_{i:02d}") for i in range(10)], ignore_index=True)
    prop_att = RefGraphPropagator(variant="attenuated", alpha=0.70, n_iter=12).fit(train_df)
    assert prop_att.idf_model.ihf_weight(r"c:\windows\system32\ntdll.dll") == pytest.approx(0.0)
    assert prop_att.idf_model.ihf_weight(r"c:\programdata\side.dll") == pytest.approx(1.0)

    # 2. Construct evaluation disk:
    #    - EvilTask (base OOF = 0.95) launches rundll32.exe with SCCA=aaaa1111 matching EvilPrefetch
    #    - EvilPrefetch loads BOTH ntdll.dll (universal hub) AND rare C:\ProgramData\side.dll (base=0.05)
    #    - BenignApp1..4 (base OOF = 0.05) ALSO launch rundll32.exe with SCCA=bbbb2222 matching BenignPrefetch
    eval_rows = [
        {"run_id": "eval_0", "artifact_type": "file", "artifact_key": r"file|c:\windows\system32\rundll32.exe|rundll32.exe",
         "name": "rundll32.exe", "path": r"C:\Windows\System32\rundll32.exe", "mft_record_number": 10, "mft_sequence_number": 1, "mft_in_use": True},
        {"run_id": "eval_0", "artifact_type": "file", "artifact_key": r"file|c:\windows\system32\ntdll.dll|ntdll.dll",
         "name": "ntdll.dll", "path": r"C:\Windows\System32\ntdll.dll", "mft_record_number": 11, "mft_sequence_number": 1, "mft_in_use": True},
        {"run_id": "eval_0", "artifact_type": "file", "artifact_key": r"file|c:\programdata\side.dll|side.dll",
         "name": "side.dll", "path": r"C:\ProgramData\side.dll", "mft_record_number": 12, "mft_sequence_number": 1, "mft_in_use": True},
        {"run_id": "eval_0", "artifact_type": "task", "artifact_key": r"task|\eviltask|eviltask",
         "name": "EvilTask", "path": r"C:\Windows\System32\rundll32.exe",
         "command_line": r"C:\Windows\System32\rundll32.exe C:\ProgramData\side.dll,Run",
         "pf_scca_hash": "aaaa1111"},
        {"run_id": "eval_0", "artifact_type": "prefetch", "artifact_key": r"prefetch|evil_pf|rundll32.exe-aaaa1111.pf",
         "name": "RUNDLL32.EXE-AAAA1111.pf", "path": r"C:\Windows\Prefetch\RUNDLL32.EXE-AAAA1111.pf",
         "pf_executable_name": "rundll32.exe", "pf_scca_hash": "aaaa1111",
         "pf_file_metrics": [
             {"file_path": r"C:\Windows\System32\ntdll.dll", "mft_index": 11, "mft_sequence": 1},
             {"file_path": r"C:\ProgramData\side.dll", "mft_index": 12, "mft_sequence": 1},
         ]},
    ]
    base_scores = {
        r"file|c:\windows\system32\rundll32.exe|rundll32.exe": 0.05,
        r"file|c:\windows\system32\ntdll.dll|ntdll.dll": 0.05,
        r"file|c:\programdata\side.dll|side.dll": 0.05,
        r"task|\eviltask|eviltask": 0.95,
        r"prefetch|evil_pf|rundll32.exe-aaaa1111.pf": 0.10,
    }
    for i in range(1, 5):
        tk = f"task|\\benignapp_{i}|benignapp_{i}"
        pk = f"prefetch|ben_{i}|rundll32.exe-bbbb000{i}.pf"
        bk = f"file|c:\\program files\\ben_{i}.dll|ben_{i}.dll"
        eval_rows.extend([
            {"run_id": "eval_0", "artifact_type": "file", "artifact_key": bk, "name": f"ben_{i}.dll",
             "path": f"C:\\Program Files\\ben_{i}.dll", "mft_record_number": 20 + i, "mft_sequence_number": 1, "mft_in_use": True},
            {"run_id": "eval_0", "artifact_type": "task", "artifact_key": tk, "name": f"BenignApp_{i}",
             "path": r"C:\Windows\System32\rundll32.exe", "command_line": r"C:\Windows\System32\rundll32.exe",
             "pf_scca_hash": f"bbbb000{i}"},
            {"run_id": "eval_0", "artifact_type": "prefetch", "artifact_key": pk, "name": f"RUNDLL32.EXE-BBBB000{i}.pf",
             "path": f"C:\\Windows\\Prefetch\\RUNDLL32.EXE-BBBB000{i}.pf",
             "pf_executable_name": "rundll32.exe", "pf_scca_hash": f"bbbb000{i}",
             "pf_file_metrics": [
                 {"file_path": r"C:\Windows\System32\ntdll.dll", "mft_index": 11, "mft_sequence": 1},
                 {"file_path": f"C:\\Program Files\\ben_{i}.dll", "mft_index": 20 + i, "mft_sequence": 1},
             ]},
        ])
        base_scores[tk] = 0.05
        base_scores[pk] = 0.05
        base_scores[bk] = 0.05

    eval_df = pd.DataFrame(eval_rows)
    res_base = RefGraphPropagator(variant="base").propagate_disk(eval_df, base_scores, disk_id="eval_0")
    res_naive = RefGraphPropagator(variant="naive", alpha=0.70, n_iter=12).propagate_disk(eval_df, base_scores, disk_id="eval_0")
    res_att = prop_att.propagate_disk(eval_df, base_scores, disk_id="eval_0")

    # (a) Base returns unchanged OOF scores
    assert res_base["scores"][r"file|c:\programdata\side.dll|side.dll"] == pytest.approx(0.05)

    # (b) Naive smears risk through universal hubs (rundll32.exe / ntdll.dll) onto BenignApp, ntdll & rundll32
    naive_ben_max = max(res_naive["scores"][f"task|\\benignapp_{i}|benignapp_{i}"] for i in range(1, 5))
    assert res_naive["scores"][r"file|c:\windows\system32\rundll32.exe|rundll32.exe"] > 0.12
    assert res_naive["scores"][r"file|c:\windows\system32\ntdll.dll|ntdll.dll"] > 0.08
    assert naive_ben_max > 0.065

    # (c) Hub-attenuated context-split boosts rare side.dll and keeps BenignApp & ntdll uncontaminated
    att_side = res_att["scores"][r"file|c:\programdata\side.dll|side.dll"]
    att_ntdll = res_att["scores"][r"file|c:\windows\system32\ntdll.dll|ntdll.dll"]
    att_ben_max = max(res_att["scores"][f"task|\\benignapp_{i}|benignapp_{i}"] for i in range(1, 5))
    assert att_side > 0.30
    assert att_ben_max == pytest.approx(0.05, abs=1e-9)
    assert att_ntdll == pytest.approx(0.05, abs=1e-9)
    assert res_att["scores"][r"file|c:\windows\system32\rundll32.exe|rundll32.exe"] == pytest.approx(0.05, abs=1e-9)
    assert att_side > res_naive["scores"][r"file|c:\programdata\side.dll|side.dll"]
    assert att_side > naive_ben_max
    assert att_side > att_ben_max
    # Explainability trace explicitly cites EvilTask context
    exps = res_att["explanations"][r"file|c:\programdata\side.dll|side.dll"]
    assert len(exps) >= 1
    assert any(e["source_node"] == r"ctx|task|\eviltask|eviltask" for e in exps)


@pytest.mark.parametrize(
    "forbidden_col",
    [
        "label",
        "label_reason",
        "sample_family",
        "pair_group_id",
        "attribution_method",
        "parent_name",
        "pid",
        "ppid",
        "sysmon_event_id",
        "created_utc",
        "modified_utc",
        "file_age_minutes",
        "rule_hit_count",
    ],
)
def test_leakage_guards_reject_label_provenance_process_sysmon_timestamps(forbidden_col):
    df = pd.DataFrame([
        {"artifact_key": "file|a|a", "artifact_type": "file", "name": "a", "path": "C:\\a.exe", forbidden_col: "X"}
    ])
    with pytest.raises(LeakageError):
        build_disk_graph(df)
    with pytest.raises(LeakageError):
        assert_graph_inputs_clean(["artifact_key", forbidden_col])
    if forbidden_col in config.FORBIDDEN_MODEL_INPUTS:
        with pytest.raises(LeakageError):
            SharedPreprocessor(categorical=config.CATEGORICAL_FEATURES + [forbidden_col])


def test_idf_statistics_strictly_from_training_pool_only():
    train_df = pd.concat([_make_training_hub_disk(f"tr_{i}") for i in range(4)], ignore_index=True)
    # Test disk introduces 20 new references to rare_xyz.dll
    test_rows = [
        {"run_id": f"te_{j}", "artifact_type": "prefetch", "artifact_key": f"pf|{j}|x.pf",
         "name": "X.EXE-12345678.pf", "path": r"C:\Windows\Prefetch\X.EXE-12345678.pf",
         "pf_file_metrics": [{"file_path": r"C:\Users\Public\rare_xyz.dll", "mft_index": 500, "mft_sequence": 1}]}
        for j in range(5)
    ]
    test_df = pd.DataFrame(test_rows)

    prop = RefGraphPropagator(variant="attenuated").fit(train_df)
    before_df_map = dict(prop.idf_model.doc_freq_)
    before_n = prop.idf_model.n_train_disks_
    before_rare_w = prop.idf_model.ihf_weight(r"c:\users\public\rare_xyz.dll")

    # Scoring unseen test disks NEVER alters frozen training IDF counts or weights
    for j in range(5):
        sub = test_df[test_df["run_id"] == f"te_{j}"].reset_index(drop=True)
        prop.propagate_disk(sub, {"pf|" + str(j) + "|x.pf": 0.8}, disk_id=f"te_{j}")

    assert prop.idf_model.doc_freq_ == before_df_map
    assert prop.idf_model.n_train_disks_ == before_n
    assert prop.idf_model.ihf_weight(r"c:\users\public\rare_xyz.dll") == before_rare_w == pytest.approx(1.0)
