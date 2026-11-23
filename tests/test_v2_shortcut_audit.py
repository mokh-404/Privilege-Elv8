"""Tests for Step C.6: real byte histograms, template-quantization gate, and disjoint profiles."""
from __future__ import annotations

import pandas as pd

from scripts.verify_stratified_shortcuts import (
    check_template_quantization,
    load_attack_rows,
    simulate_benign_rows,
    simulate_v2_benign_rows,
)
from src.data.features import row_features


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
