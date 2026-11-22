"""Unit tests for post-hoc supplementary analyses (`src/eval/supp_posthoc.py`)."""
from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from src import config
from src.eval import metrics as M
from src.eval import supp_posthoc


def test_verify_frozen_test_hash_matches_and_guards():
    sha = supp_posthoc.verify_frozen_test_hash()
    assert sha == supp_posthoc.EXPECTED_TEST_SHA256
    with pytest.raises(RuntimeError, match="mismatch"):
        supp_posthoc.verify_frozen_test_hash(expected_sha256="0" * 64)


def test_extract_score_map_detects_missing_or_nan():
    df = pd.DataFrame({"score_rf": [0.9, 0.1], "score_xgb": [0.8, np.nan]})
    with pytest.raises(KeyError, match="mlp"):
        supp_posthoc.extract_score_map(df, ["rf", "mlp"])
    with pytest.raises(ValueError, match="xgb"):
        supp_posthoc.extract_score_map(df, ["rf", "xgb"])


def test_verdict_helper_reproduces_existing_rules_binary_table():
    df_full = pd.read_parquet(config.TABLES_DIR / "track_a_test_predictions.parquet")
    df_nc = pd.read_parquet(config.TABLES_DIR / "no_content" / "track_a_test_predictions.parquet")
    expected = pd.read_csv(config.TABLES_DIR / "track_a_test_dual_config_verdict.csv")

    pairs = [tuple(x) for x in expected[["arm_a", "arm_b"]].drop_duplicates().to_numpy()]
    actual = supp_posthoc.compute_dual_config_verdicts_from_predictions(
        df_full, df_nc, pairs=pairs, group_by="run_id",
        n_boot=config.N_BOOTSTRAP, seed=config.BOOTSTRAP_SEED,
    )

    assert len(actual) == len(expected)
    assert (actual["analysis_status"] == supp_posthoc.POSTHOC_STATUS).all()

    key_cols = ["artifact_slice", "arm_a", "arm_b"]
    merged = expected.merge(actual, on=key_cols, suffixes=("_exp", "_act"))
    assert len(merged) == len(expected)
    for col in ("verdict_full_20", "verdict_no_content", "dual_verdict"):
        assert (merged[f"{col}_exp"] == merged[f"{col}_act"]).all()
    for col in ("excludes_zero_full_20", "excludes_zero_no_content"):
        assert (merged[f"{col}_exp"].astype(bool) == merged[f"{col}_act"].astype(bool)).all()
    for col in (
        "pr_auc_a_full_20", "pr_auc_b_full_20", "diff_full_20", "ci_lo_full_20", "ci_hi_full_20",
        "pr_auc_a_no_content", "pr_auc_b_no_content", "diff_no_content", "ci_lo_no_content", "ci_hi_no_content",
    ):
        assert np.allclose(merged[f"{col}_exp"], merged[f"{col}_act"], atol=1e-12)


def test_operating_points_synthetic_with_ties():
    # 10 rows: 4 positives (indices 0,1,2,3), 6 negatives (indices 4..9).
    # rules_count >= 2 flags {0, 4} -> 2 flagged, 1 TP, P=0.5, R=0.25.
    # rules_count >= 1 (== rules_binary >= 1) flags {0,1,2,4,5,6} -> 6 flagged, 3 TP, P=0.5, R=0.75.
    # rf scores have a tie block at score 0.6 across rows {1,2,5,6} (2 pos, 2 neg), right across TP=3 (R=0.75):
    #   sorted scores: row 0 (pos, 0.9), tie block {1,2,5,6} (2 pos, 2 neg, score 0.6),
    #                  row 4 (neg, 0.4), row 3 (pos, 0.2), rows {7,8,9} (neg, 0.1).
    #   at target TP = 3 (R=0.75): prev_n=1, prev_pos=1, rem_pos=2, counts[b]=4, pos_counts[b]=2
    #   -> expected_n_flagged = 1 + 2 * (4/2) = 5.0; tie_expected_precision = 3/5 = 0.60;
    #   -> inclusive threshold >= 0.6 flags 5 items -> n_flagged_at_threshold=5, precision_at_threshold=0.60.
    # Now add a partial tie test on xgb where tie block has 3 pos + 1 neg at the boundary and we only need 2 pos:
    #   row 0 (pos, 0.9), tie block {1,2,3,4} = (2 pos, 2 neg at 0.5)? Better: 4 positives total:
    #   xgb: {0: (pos, 0.9), 1: (pos, 0.5), 2: (pos, 0.5), 3: (neg, 0.5), 4: (pos, 0.2), 5..9: neg <=0.4}
    #   at target TP = 3 (R=0.75): prev_n=1, prev_pos=1, rem_pos=2, block {1,2,3} has counts=3, pos=2 -> expected_n_flagged=4, P=0.75.
    #   at target TP = 2 (R=0.50): prev_n=1, prev_pos=1, rem_pos=1, block {1,2,3} has counts=3, pos=2 -> expected_n_flagged=1 + 1*(3/2)=2.5, P=2/2.5=0.80!
    df_synth = pd.DataFrame({
        "artifact_key": [f"k{i}" for i in range(10)],
        "y":                  [1,   1,   1,   1,   0,   0,   0,   0,   0,   0],
        "score_rules_binary": [1.0, 1.0, 1.0, 0.0, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0],
        "score_rules_count":  [2.0, 1.0, 1.0, 0.0, 2.0, 1.0, 1.0, 0.0, 0.0, 0.0],
        "score_random":       [0.1, 0.9, 0.2, 0.8, 0.3, 0.7, 0.4, 0.6, 0.5, 0.0],
        "score_rf":           [0.9, 0.6, 0.6, 0.2, 0.4, 0.6, 0.6, 0.1, 0.1, 0.1],
        "score_xgb":          [0.9, 0.5, 0.5, 0.2, 0.5, 0.4, 0.3, 0.1, 0.1, 0.1],
        "score_mlp":          [0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0],
        "score_lr":           [0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0],
        "score_ae":           [0.9, 0.8, 0.7, 0.6, 0.5, 0.4, 0.3, 0.2, 0.1, 0.0],
        "score_iforest":      [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
    })
    # Direct helper check on partial tie (xgb at target_recall = 0.50 -> target_tp = 2)
    res_xgb = supp_posthoc.tie_expected_precision_at_recall(df_synth["y"], df_synth["score_xgb"], 0.50)
    assert res_xgb["target_tp"] == 2
    assert res_xgb["expected_n_flagged"] == pytest.approx(2.5)
    assert res_xgb["tie_expected_precision"] == pytest.approx(0.80)
    assert res_xgb["n_flagged_at_threshold"] == 4
    assert res_xgb["precision_at_threshold"] == pytest.approx(0.75)

    # Full table check + permutation invariance
    op_df = supp_posthoc.compute_operating_points_table(df_synth, df_synth, ks=(5, 10))
    perm = df_synth.sample(frac=1.0, random_state=7).reset_index(drop=True)
    op_perm = supp_posthoc.compute_operating_points_table(perm, perm, ks=(5, 10))

    assert (op_df["analysis_status"] == supp_posthoc.POSTHOC_STATUS).all()
    thresh_rows = op_df[op_df["evaluation_type"] != "top_k"]
    assert (thresh_rows["threshold_caveat"] == supp_posthoc.THRESHOLD_CAVEAT).all()

    # Rules operating points
    r1 = op_df[(op_df["evaluation_type"] == "rules_operating_point") & (op_df["operating_point"] == "rules_count >= 1")].iloc[0]
    assert r1["n_flagged"] == 6.0 and r1["expected_tp"] == 3.0
    assert r1["precision"] == pytest.approx(0.5) and r1["recall"] == pytest.approx(0.75)

    r2 = op_df[(op_df["evaluation_type"] == "rules_operating_point") & (op_df["operating_point"] == "rules_count >= 2")].iloc[0]
    assert r2["n_flagged"] == 2.0 and r2["expected_tp"] == 1.0
    assert r2["precision"] == pytest.approx(0.5) and r2["recall"] == pytest.approx(0.25)

    # RF matched at rules >= 1 (target recall 0.75) and matched at 6 flagged items
    rf_rec = op_df[
        (op_df["evaluation_type"] == "matched_at_rules_recall")
        & (op_df["config"] == "full_20")
        & (op_df["arm"] == "rf")
        & (op_df["target_n_flagged"] == 6)
    ].iloc[0]
    assert rf_rec["n_flagged"] == pytest.approx(5.0)
    assert rf_rec["precision"] == pytest.approx(0.6)

    # RF matched at flagged=2 -> row 0 (pos, 0.9) + 1 draw from {1,2,5,6} (0.5 pos expected) -> E[TP]=1.5, R=1.5/4=0.375
    rf_flg2 = op_df[
        (op_df["evaluation_type"] == "matched_at_rules_flagged")
        & (op_df["config"] == "full_20")
        & (op_df["arm"] == "rf")
        & (op_df["target_n_flagged"] == 2)
    ].iloc[0]
    assert rf_flg2["expected_tp"] == pytest.approx(1.5)
    assert rf_flg2["recall"] == pytest.approx(0.375)
    assert rf_flg2["precision"] == pytest.approx(0.75)

    # Top-k matches metrics.py tie_expected helpers
    rf_top5 = op_df[
        (op_df["evaluation_type"] == "top_k")
        & (op_df["config"] == "full_20")
        & (op_df["arm"] == "rf")
        & (op_df["target_n_flagged"] == 5)
    ].iloc[0]
    assert rf_top5["precision"] == pytest.approx(M.tie_expected_precision_at_k(df_synth["y"], df_synth["score_rf"], 5))
    assert rf_top5["recall"] == pytest.approx(M.tie_expected_recall_at_k(df_synth["y"], df_synth["score_rf"], 5))

    # Row-order permutation invariance
    assert np.allclose(
        op_df.sort_values(["evaluation_type", "operating_point", "config", "arm"])["precision"].to_numpy(),
        op_perm.sort_values(["evaluation_type", "operating_point", "config", "arm"])["precision"].to_numpy(),
    )


def test_shap_ranks_and_spearman_synthetic():
    feats = [f"f{i:02d}" for i in range(12)]
    rf_vals = [float(12 - i) for i in range(10)] + [0.0, 0.0]
    xgb_vals = [v * 10.0 for v in rf_vals]  # identical rank order on 10x log-odds scale
    mlp_vals = [float(i + 1) * 100.0 for i in range(12)]  # reversed order on 100x logit scale
    mlp_vals[0] = 0.0

    rows = []
    for arm, vals in (("rf", rf_vals), ("xgb", xgb_vals), ("mlp", mlp_vals)):
        for f, v in zip(feats, vals):
            rows.append({"arm": arm, "feature": f, "mean_abs_shap": v, "explainer": "Test", "commit": "abc"})
    df_shap = pd.DataFrame(rows)

    ranks_df, spear_df = supp_posthoc.compute_shap_ranks_and_spearman({"full_20": df_shap})
    assert (ranks_df["analysis_status"] == supp_posthoc.POSTHOC_STATUS).all()
    assert (ranks_df["scale_note"] == supp_posthoc.SHAP_SCALE_NOTE).all()

    # Normalized shares sum to 1.0 per arm and are scale-invariant between rf and xgb
    for arm in ("rf", "xgb", "mlp"):
        sub = ranks_df[ranks_df["arm"] == arm]
        assert sub["normalized_share"].sum() == pytest.approx(1.0)
    rf_s = ranks_df[ranks_df["arm"] == "rf"].sort_values("feature")["normalized_share"].to_numpy()
    xgb_s = ranks_df[ranks_df["arm"] == "xgb"].sort_values("feature")["normalized_share"].to_numpy()
    assert np.allclose(rf_s, xgb_s)

    # All-features Spearman: n=12, rf-xgb == 1.0
    rf_xgb_all = spear_df[
        (spear_df["feature_subset"] == "all_features")
        & (spear_df["arm_1"] == "rf")
        & (spear_df["arm_2"] == "xgb")
    ].iloc[0]
    assert rf_xgb_all["n_features_compared"] == 12
    assert rf_xgb_all["spearman_rho"] == pytest.approx(1.0)

    # Top-10 union includes both all top-10 of rf/xgb (f00..f09) AND all top-10 of mlp (which puts high weight on reversed indices -> all 12)
    top_u = spear_df[
        (spear_df["feature_subset"] == "top10_union")
        & (spear_df["arm_1"] == "rf")
        & (spear_df["arm_2"] == "xgb")
    ].iloc[0]
    assert top_u["n_features_compared"] == 12
    assert top_u["spearman_rho"] == pytest.approx(1.0)
