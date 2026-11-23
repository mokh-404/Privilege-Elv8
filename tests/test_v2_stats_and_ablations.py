"""Unit tests for Step C.3 v2 statistical inference, tail-risk/effort metrics, LOFO, and dev-guarded ablations."""
from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from src import config
from src.v2.ablations_v2 import (
    AblationGuardError,
    V2_ABLATION_CONFIGS,
    assert_dev_only_ablation_guard,
    run_dev_ablations_v2,
)
from src.v2.stats_v2 import (
    FIXED_V2_COMPARISONS,
    calibrate_dev_threshold,
    compute_lofo_table,
    cross_stratum_execution_delta,
    evaluate_fixed_comparisons_dual_config,
    evaluate_frozen_threshold,
    family_clustered_paired_bootstrap_p,
    holm_bonferroni_adjust,
    monte_carlo_random_pr_auc,
    tail_audit_upper_bound,
    tail_risk_and_effort_metrics,
)


def _make_synthetic_v2_dev_df(seed: int = 42) -> pd.DataFrame:
    rng = np.random.default_rng(seed)
    rows: list[dict] = []
    families = ["fam_alpha", "fam_beta", "fam_gamma", "fam_delta"]

    for f_idx, fam in enumerate(families):
        pair_id = f"pair_{fam}"
        sha = f"{f_idx + 1:064x}"
        for st in ("dormant", "executed"):
            run_id = f"run_{fam}_{st}"
            n_pos = 1 if st == "dormant" else 3
            for p in range(n_pos):
                rows.append(
                    {
                        "run_id": run_id,
                        "split_pool": "dev",
                        "stratum": st,
                        "execution_state": st,
                        "sample_family": fam,
                        "technique_id": f"T10{f_idx}0",
                        "sample_sha256": sha,
                        "pair_group_id": pair_id,
                        "packer_cluster": f"pkr_{f_idx}",
                        "benign_session_id": None,
                        "artifact_key": f"pos_{fam}_{st}_{p}",
                        config.LABEL_COL: config.POSITIVE_LABEL,
                        "artifact_type": "file" if p == 0 else "service",
                        "path_class": "temp" if st == "dormant" else "appdata",
                        "ext_class": "exe",
                        "signature_state": "not_signed",
                        "parent_process_class": "na",
                        "registry_location_class": "na" if p == 0 else "services",
                        "path_depth": 4.0 + p,
                        "name_length": 14.0 + f_idx,
                        "name_entropy": 3.7,
                        "file_size_log": 11.5 + 0.2 * f_idx,
                        "file_entropy": 7.4 if st == "dormant" else 6.8,
                        "cmdline_length": 0.0 if st == "dormant" else 85.0,
                        "cmdline_entropy": 0.0 if st == "dormant" else 4.3,
                        "cmdline_nonalnum_ratio": 0.0 if st == "dormant" else 0.28,
                        "has_double_extension": 0,
                        "has_encoded_flag": 0 if st == "dormant" else 1,
                        "has_url_or_ip": 0 if st == "dormant" else 1,
                        "has_lolbin": 0 if st == "dormant" else 1,
                        "has_hidden_attr": 1,
                        "autostart_flag": 0 if p == 0 else 1,
                    }
                )
            for b in range(8):
                rows.append(
                    {
                        "run_id": run_id,
                        "split_pool": "dev",
                        "stratum": st,
                        "execution_state": st,
                        "sample_family": None,
                        "technique_id": "BENIGN",
                        "sample_sha256": None,
                        "pair_group_id": None,
                        "packer_cluster": None,
                        "benign_session_id": f"bsess_{f_idx}_{st}",
                        "artifact_key": f"ben_{fam}_{st}_{b}",
                        config.LABEL_COL: "benign_baseline" if b < 6 else "benign_drift",
                        "artifact_type": "file" if b % 2 == 0 else "registry",
                        "path_class": "system32",
                        "ext_class": "dll" if b % 2 == 0 else "none",
                        "signature_state": "valid",
                        "parent_process_class": "na",
                        "registry_location_class": "na" if b % 2 == 0 else "other",
                        "path_depth": float(rng.integers(2, 5)),
                        "name_length": float(rng.integers(6, 12)),
                        "name_entropy": float(rng.uniform(2.5, 3.2)),
                        "file_size_log": float(rng.uniform(8.0, 10.5)),
                        "file_entropy": float(rng.uniform(4.5, 5.8)),
                        "cmdline_length": float(rng.uniform(0.0, 20.0)),
                        "cmdline_entropy": float(rng.uniform(0.0, 2.5)),
                        "cmdline_nonalnum_ratio": float(rng.uniform(0.0, 0.12)),
                        "has_double_extension": 0,
                        "has_encoded_flag": 0,
                        "has_url_or_ip": 0,
                        "has_lolbin": 0,
                        "has_hidden_attr": 0,
                        "autostart_flag": 0,
                    }
                )
    return pd.DataFrame(rows)


def test_monte_carlo_random_pr_auc_10k_permutations():
    y = np.array([1] * 10 + [0] * 190, dtype=int)
    res1 = monte_carlo_random_pr_auc(y, n_perm=10_000, seed=42)
    res2 = monte_carlo_random_pr_auc(y, n_perm=10_000, seed=42)
    assert res1 == res2
    assert res1["n_perm"] == 10_000
    assert res1["p05"] <= res1["p50"] <= res1["p95"]
    assert abs(res1["prevalence"] - 0.05) < 1e-9
    # Finite-sample random AP expectation is close to prevalence (slightly above due to 1/r convexity)
    assert 0.045 <= res1["mean"] <= 0.075


def test_tail_risk_and_effort_metrics_and_tail_audit_calculator():
    # 10 items, 4 positives at scores [0.95 (rank 1), 0.80 (rank 2), 0.50 tied w/ neg (worst rank 5), 0.05 (rank 10)]
    y = np.array([1, 1, 0, 1, 0, 0, 0, 0, 0, 1], dtype=int)
    scores = np.array([0.95, 0.80, 0.70, 0.50, 0.50, 0.40, 0.30, 0.20, 0.10, 0.05], dtype=float)
    m = tail_risk_and_effort_metrics(y, scores, budgets=(2, 5), recall_targets=(0.50, 0.75, 1.00))

    assert m["worst_positive_rank"] == 10
    assert abs(m["worst_positive_percentile"] - 1.0) < 1e-9
    # Positives have worst ranks [1, 2, 5, 10]; bottom 50% (rank > 5) has 1 positive (rank 10)
    assert m["pos_in_bottom_50pct"] == 1
    # Bottom 90% (rank > 1) has 3 positives (ranks 2, 5, 10)
    assert m["pos_in_bottom_90pct"] == 3
    # 50% recall (2 positives) reached at rank 2; 75% recall (3 positives) at worst rank 5; 100% at rank 10
    assert m["effort_at_recall_50_count"] == 2
    assert m["effort_at_recall_75_count"] == 5
    assert m["effort_at_recall_100_count"] == 10

    assert abs(tail_audit_upper_bound(5, alpha=0.05) - (1.0 - 0.05 ** (1.0 / 5.0))) < 1e-12
    assert abs(tail_audit_upper_bound(59, alpha=0.05) - 0.05) < 0.001
    assert abs(tail_audit_upper_bound(300, alpha=0.05) - 0.01) < 0.0005


def test_holm_bonferroni_and_dual_config_winner_rule():
    raw_p = np.array([0.001, 0.020, 0.015, 0.500], dtype=float)
    adj_p = holm_bonferroni_adjust(raw_p)
    # Sorted order: [0.001 (*4=0.004), 0.015 (*3=0.045), 0.020 (*2=0.040 -> max(0.045, 0.040)=0.045), 0.500 (*1=0.500)]
    np.testing.assert_allclose(adj_p, np.array([0.004, 0.045, 0.045, 0.500]), atol=1e-12)

    df = _make_synthetic_v2_dev_df(seed=7)
    y = (df[config.LABEL_COL] == config.POSITIVE_LABEL).astype(int).to_numpy()
    rng = np.random.default_rng(11)
    strong = y * 2.0 + rng.normal(0.0, 0.1, size=len(y))
    weak = rng.normal(0.0, 1.0, size=len(y))
    medium = y * 0.15 + rng.normal(0.0, 1.0, size=len(y))

    scores_full = {"xgb": strong, "rf": weak, "mlp": medium}
    scores_no = {"xgb": strong, "rf": weak, "mlp": weak}

    comp_df = evaluate_fixed_comparisons_dual_config(
        df_full=df,
        scores_full=scores_full,
        df_nocontent=df,
        scores_nocontent=scores_no,
        comparisons=(("xgb", "rf"), ("rf", "xgb"), ("mlp", "rf")),
        n_boot=300,
        seed=42,
    )
    verdicts = dict(zip(zip(comp_df["arm_a"], comp_df["arm_b"]), comp_df["verdict"]))
    assert verdicts[("xgb", "rf")] == "a_better"
    assert verdicts[("rf", "xgb")] == "b_better"
    assert verdicts[("mlp", "rf")] in ("not distinguishable", "configuration-dependent")
    # Unadjusted CIs must not be mutated by Holm adjustment
    assert (comp_df["full_20_ci_lo"] <= comp_df["full_20_ci_hi"]).all()
    assert len(FIXED_V2_COMPARISONS) == 9


def test_dev_threshold_calibration_and_lofo_and_execution_delta():
    df = _make_synthetic_v2_dev_df(seed=19)
    y = (df[config.LABEL_COL] == config.POSITIVE_LABEL).astype(int).to_numpy()
    st = df["execution_state"].astype(str).to_numpy()
    # Executed positives rank at the top (with distinct scores); dormant positives rank behind several benign rows
    idx_arr = np.arange(len(df), dtype=float)
    scores = np.where(
        (y == 1) & (st == "executed"),
        0.95 - (idx_arr % 3) * 0.03,
        np.where((y == 1) & (st == "dormant"), 0.31, 0.20 + (idx_arr % 7) * 0.06),
    )
    df["score_model"] = scores

    cal = calibrate_dev_threshold(y, scores, target_fpr=0.05)
    frozen_eval = evaluate_frozen_threshold(y, scores, cal["threshold"])
    assert cal["n_benign_oof"] == int(np.sum(y == 0))
    assert frozen_eval["fpr"] <= 0.15
    assert 0.0 <= frozen_eval["recall"] <= 1.0

    lofo = compute_lofo_table(df, score_cols=["score_model"])
    assert set(lofo["family"]) == {"fam_alpha", "fam_beta", "fam_gamma", "fam_delta"}
    assert (lofo["pr_auc"] > 0.3).all()

    delta = cross_stratum_execution_delta(df, score_col="score_model", n_boot=200, seed=42)
    assert delta["n_paired_samples"] == 4
    assert delta["pr_auc_executed"] > delta["pr_auc_dormant"]
    assert delta["delta_exec_pr_auc"] > 0.0
    assert delta["delta_first_hit_median"] > 0.0
    assert delta["intrusion_recall_at_5_executed"] >= delta["intrusion_recall_at_5_dormant"]


def test_dev_only_ablation_guard_and_config_matched_ablations(tmp_path: Path):
    df = _make_synthetic_v2_dev_df(seed=23)
    leaked_df = df.copy()
    leaked_df.loc[0, "split_pool"] = "test"

    with pytest.raises(AblationGuardError, match="Refusing to run ablations on non-dev"):
        assert_dev_only_ablation_guard(leaked_df)

    with pytest.raises(AblationGuardError):
        run_dev_ablations_v2(leaked_df, arms=("rf",), configs=("full_20",), n_outer=2, n_inner=2, n_trials=2)

    out_csv = tmp_path / "dev_ablations_v2.csv"
    ab_df = run_dev_ablations_v2(
        dev_df=df,
        arms=("rf", "iforest"),
        configs=("full_20", "no_content", "unsup_baseline_only"),
        n_outer=2,
        n_inner=2,
        n_trials=2,
        seed=42,
        out_csv=out_csv,
    )
    assert out_csv.exists()
    assert (ab_df["config_matched_tuning"] == True).all()
    feat_counts = dict(zip(ab_df["config"], ab_df["n_features"]))
    assert feat_counts["full_20"] == 20
    assert feat_counts["no_content"] == 18
    assert len(V2_ABLATION_CONFIGS["no_content_no_sig"]["features"]) == 17
    unsup_rows = ab_df[ab_df["config"] == "unsup_baseline_only"]
    assert list(unsup_rows["arm"]) == ["iforest"]
    assert set(V2_ABLATION_CONFIGS).issuperset(
        {"full_20", "no_content", "drop_signature", "no_content_no_sig", "unsup_baseline_only"}
    )
