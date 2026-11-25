"""Tests for Step C.6: real byte histograms, template-quantization gate, and disjoint profiles."""
from __future__ import annotations

import pandas as pd
import pytest

from scripts.verify_stratified_shortcuts import (
    check_template_quantization,
    load_attack_rows,
    simulate_benign_rows,
    simulate_v2_benign_rows,
)
from scripts.v2_prepare_benign_pools import index_and_validate_benign_pools, ingest_package_dir
from src.data.features import row_features
from src.v2.benign_generator_v2 import _synth_unsigned_pe_bytes, simulate_benign_generator_rows


def test_real_histograms_and_no_uniform_placeholders():
    att = load_attack_rows(real_bytes=True)
    ben, _ = simulate_v2_benign_rows(profile="dev", n_runs=24)
    assert att and ben
    for r in att + ben:
        hist = r.get("file_head_histogram")
        if hist is not None:
            assert hist != [1] * 256
            assert len(hist) == 256
            assert sum(hist) == min(r["file_size"], 1 << 20)


def test_quantization_gate_passes_v2_and_fails_v1_templates():
    # Legacy v1 6-template simulation uses constant size=2048 -> MUST FAIL quantization check
    v1_rows, _ = simulate_benign_rows(n_seeds=24)
    v1_feats = pd.DataFrame([row_features(r) for r in v1_rows])
    v1_res = check_template_quantization(v1_feats)
    assert v1_res["passed"] is False
    assert v1_res["unique_size_ratio"] < 0.60

    # Upgraded v2 generator MUST PASS all quantization & diversity gates
    v2_rows, _ = simulate_v2_benign_rows(profile="dev", n_runs=24)
    v2_feats = pd.DataFrame([row_features(r) for r in v2_rows])
    v2_res = check_template_quantization(v2_feats)
    assert v2_res["passed"] is True
    assert v2_res["unique_size_ratio"] >= 0.60
    assert v2_res["unique_size_entropy_pair_ratio"] >= 0.75
    assert v2_res["max_single_size_share"] <= 0.10
    assert v2_res["benign_services"] > 0
    assert v2_res["benign_registry"] > 0
    assert v2_res["benign_unsigned_pes"] > 0


def test_disjoint_dev_and_blind_test_host_profiles():
    dev_rows, dev_keys = simulate_v2_benign_rows(profile="dev", n_runs=30, base_seed=1000)
    test_rows, test_keys = simulate_v2_benign_rows(profile="blind_test", n_runs=30, base_seed=2000)
    assert dev_keys.isdisjoint(test_keys)
    # Varied task triggers present in both
    dev_trigs = {r["task_triggers"] for r in dev_rows if r.get("task_triggers")}
    test_trigs = {r["task_triggers"] for r in test_rows if r.get("task_triggers")}
    assert len(dev_trigs) >= 3 and len(test_trigs) >= 3


def test_benign_generator_v2_passes_quantization_and_pool_disjointness(tmp_path):
    src_dev = tmp_path / "src_dev_pkg"
    src_test = tmp_path / "src_test_pkg"
    src_dev.mkdir()
    src_test.mkdir()
    (src_dev / "dev_cli.exe").write_bytes(_synth_unsigned_pe_bytes(11, 20480, is_dll=False))
    (src_dev / "dev_sync.ps1").write_text("Write-Output 'dev sync ok'\n", encoding="utf-8")
    (src_test / "test_agent.exe").write_bytes(_synth_unsigned_pe_bytes(22, 24576, is_dll=False))
    (src_test / "test_audit.py").write_text("print('test audit')\n", encoding="utf-8")

    pools = tmp_path / "benign_pools"
    ingest_package_dir(src_dev, pools, split_pool="dev", package_name="devpkg")
    ingest_package_dir(src_test, pools, split_pool="blind_test", package_name="testpkg")
    summary = index_and_validate_benign_pools(pools, write_manifest=True)
    assert summary["disjointness_verified"] is True
    assert summary["dev"]["total_files"] == 2 and summary["blind_test"]["total_files"] == 2

    # Same filename across splits MUST be blocked
    coll_dir = tmp_path / "src_collide"
    coll_dir.mkdir()
    (coll_dir / "dev_cli.exe").write_bytes(b"different_bytes_same_name")
    with pytest.raises(ValueError, match="Cross-split"):
        ingest_package_dir(coll_dir, pools, split_pool="blind_test", package_name="otherpkg")

    dev_rows, dev_keys = simulate_benign_generator_rows("dev", n_runs=24, base_seed=7000, benign_pools_root=pools)
    test_rows, test_keys = simulate_benign_generator_rows("blind_test", n_runs=24, base_seed=8000, benign_pools_root=pools)
    assert dev_keys.isdisjoint(test_keys)
    assert len({tuple(r["file_head_histogram"]) for r in dev_rows if r.get("file_head_histogram")}) >= 20

    feats = pd.DataFrame([row_features(r) for r in dev_rows])
    qres = check_template_quantization(feats)
    assert qres["passed"] is True
    assert qres["benign_unsigned_pes"] > 0 and qres["benign_services"] > 0 and qres["benign_registry"] > 0
