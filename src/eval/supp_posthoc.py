"""Post-hoc supplementary analyses on frozen Track A test outputs.

IMPORTANT: Every analysis in this module is POST-HOC SUPPLEMENTARY (not part of the
pre-registered FINAL_EVAL_PLAN.md). This script is strictly read-only with respect to
the dataset, splits, trained models, and pre-existing result files: it never refits,
retrains, or re-runs --final, and never writes to final_eval_audit.jsonl.

All outputs carry the `supp_posthoc_` prefix and execution is logged to
`results/logs/supp_posthoc_log.jsonl`.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Sequence

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from scipy.stats import spearmanr

from src import config
from src.data import labeler
from src.eval import metrics as M
from src.eval import run_track_a
from src.utils.repro import get_commit_hash, utc_now_iso

EXPECTED_TEST_SHA256 = "0f1ff3ec054bf00c66875fb5d2466e3b8d35685d69c2f0203d6787b71852ffa8"
POSTHOC_STATUS = "POST-HOC SUPPLEMENTARY (not in pre-registered FINAL_EVAL_PLAN)"
THRESHOLD_CAVEAT = "descriptive, thresholds chosen on test, not a deployable operating point"
TOPK_CAVEAT = (
    "descriptive, evaluated on frozen test (fixed top-k ranking budget, not a deployable operating point)"
)
SHAP_SCALE_NOTE = (
    "Raw SHAP magnitudes are on different scales across models "
    "(RF probability scale, XGBoost log-odds, MLP logit) and must not be compared directly."
)
MODEL_SHAP_SCALES: dict[str, str] = {
    "rf": "RF probability scale",
    "xgb": "XGBoost log-odds",
    "mlp": "MLP logit",
}
BASELINE_ARMS: tuple[str, ...] = ("rules_binary", "rules_count", "random")
ML_ARMS_ALL: tuple[str, ...] = ("rf", "xgb", "mlp", "lr", "ae", "iforest")
RULES_COUNT_PAIRS: tuple[tuple[str, str], ...] = (
    ("rf", "rules_count"),
    ("xgb", "rules_count"),
    ("mlp", "rules_count"),
)
TOP_KS: tuple[int, ...] = (5, 10, 20, 50)
ARM_COLORS: dict[str, str] = {
    "rf": "#0072B2",
    "xgb": "#D55E00",
    "mlp": "#009E73",
}


def verify_frozen_test_hash(
    dataset_path: str | Path = config.PROCESSED_DIR / "dataset_v1.parquet",
    manifest_path: str | Path = config.SPLITS_DIR / "dataset_v1_manifest.json",
    expected_sha256: str = EXPECTED_TEST_SHA256,
) -> str:
    """Verify frozen test SHA-256 matches both manifest and expected hash."""
    ds_p = Path(dataset_path)
    mf_p = Path(manifest_path)
    df = pd.read_parquet(ds_p)
    actual_sha = labeler.compute_frozen_test_hash(df)
    manifest = json.loads(mf_p.read_text(encoding="utf-8"))
    manifest_sha = str(manifest.get("test_sha256", ""))
    if actual_sha != expected_sha256:
        raise RuntimeError(
            f"Frozen test SHA-256 mismatch: computed {actual_sha!r} != expected {expected_sha256!r}"
        )
    if manifest_sha != expected_sha256:
        raise RuntimeError(
            f"Manifest test_sha256 mismatch: {manifest_sha!r} != expected {expected_sha256!r}"
        )
    return actual_sha


def extract_score_map(
    df_preds: pd.DataFrame,
    required_arms: Sequence[str],
    label: str = "predictions",
) -> dict[str, np.ndarray]:
    """Extract score_<arm> arrays; raise explicitly if any arm is missing or contains NaNs."""
    missing = [arm for arm in required_arms if f"score_{arm}" not in df_preds.columns]
    if missing:
        raise KeyError(f"Missing per-row score columns in {label}: {missing}")
    nan_arms = [arm for arm in required_arms if df_preds[f"score_{arm}"].isna().any()]
    if nan_arms:
        raise ValueError(f"NaN values found in per-row score columns in {label}: {nan_arms}")
    return {arm: df_preds[f"score_{arm}"].to_numpy(dtype=float) for arm in required_arms}


def _validate_aligned_predictions(df_full: pd.DataFrame, df_no_content: pd.DataFrame) -> None:
    if len(df_full) != len(df_no_content):
        raise ValueError(
            f"Row count mismatch between full_20 ({len(df_full)}) and no_content ({len(df_no_content)})"
        )
    if not np.array_equal(df_full["y"].to_numpy(dtype=int), df_no_content["y"].to_numpy(dtype=int)):
        raise ValueError("Target label vector y differs between full_20 and no_content predictions")
    if "artifact_key" in df_full.columns and "artifact_key" in df_no_content.columns:
        if not np.array_equal(
            df_full["artifact_key"].astype(str).to_numpy(),
            df_no_content["artifact_key"].astype(str).to_numpy(),
        ):
            raise ValueError("artifact_key alignment differs between full_20 and no_content predictions")


def compute_dual_config_verdicts_from_predictions(
    df_full: pd.DataFrame,
    df_no_content: pd.DataFrame,
    pairs: Sequence[tuple[str, str]] = RULES_COUNT_PAIRS,
    group_by: str = "run_id",
    n_boot: int = config.N_BOOTSTRAP,
    seed: int = config.BOOTSTRAP_SEED,
) -> pd.DataFrame:
    """Run paired run_id bootstrap & dual-config verdict logic directly on saved test scores."""
    _validate_aligned_predictions(df_full, df_no_content)
    needed_arms = tuple(dict.fromkeys([arm for pair in pairs for arm in pair]))
    y = df_full["y"].to_numpy(dtype=int)
    score_map_full = extract_score_map(df_full, needed_arms, label="full_20")
    score_map_nc = extract_score_map(df_no_content, needed_arms, label="no_content")
    arm_names = {**config.ARM_DISPLAY, **run_track_a.BASELINE_DISPLAY}

    paired_full = run_track_a.compute_paired_comparisons(
        df_full,
        y,
        score_map_full,
        arm_names=arm_names,
        pairs=pairs,
        group_by=group_by,
        n_boot=n_boot,
        seed=seed,
    )
    paired_nc = run_track_a.compute_paired_comparisons(
        df_no_content,
        y,
        score_map_nc,
        arm_names=arm_names,
        pairs=pairs,
        group_by=group_by,
        n_boot=n_boot,
        seed=seed,
    )
    merged = run_track_a.combine_dual_config_verdicts(paired_full, paired_nc)
    merged.insert(0, "analysis_status", POSTHOC_STATUS)
    return merged


def tie_expected_precision_at_recall(
    y: Sequence[int] | np.ndarray,
    scores: Sequence[float] | np.ndarray,
    target_recall: float,
) -> dict[str, float | int]:
    """Compute tie-expected & inclusive-threshold precision at target recall.

    Let `E[positives(k)]` be the piecewise-linear tie-expected positive count computed by
    `src.eval.metrics._expected_positives_in_top_k`. Solving `E[positives(k)] == target_tp`
    yields `expected_n_flagged = prev_n + rem_pos * (counts[b] / pos_counts[b])`, so
    `tie_expected_precision = target_tp / expected_n_flagged` is the exact inverse of
    `tie_expected_recall_at_k`. Inclusive-threshold metrics (`score >= threshold`) are also
    returned for full transparency when boundary ties occur.
    """
    y_arr = np.asarray(y, dtype=int).ravel()
    s_arr = np.asarray(scores, dtype=float).ravel()
    if len(y_arr) != len(s_arr):
        raise ValueError("y and scores must have the same length")
    n_pos = int(y_arr.sum())
    if len(y_arr) == 0 or n_pos == 0:
        raise ValueError("Cannot compute operating point on empty or zero-positive array")
    if not (0.0 < float(target_recall) <= 1.0):
        raise ValueError(f"target_recall must lie in (0, 1], got {target_recall}")

    target_tp = min(max(int(np.ceil(float(target_recall) * n_pos - 1e-12)), 1), n_pos)
    neg_vals, inv, counts = np.unique(-s_arr, return_inverse=True, return_counts=True)
    vals = -neg_vals
    pos_counts = np.bincount(inv, weights=y_arr, minlength=len(counts))
    cum_n = np.cumsum(counts)
    cum_pos = np.cumsum(pos_counts)

    b = int(np.searchsorted(cum_pos, target_tp, side="left"))
    prev_n = int(cum_n[b - 1]) if b > 0 else 0
    prev_pos = float(cum_pos[b - 1]) if b > 0 else 0.0
    rem_pos = float(target_tp) - prev_pos

    expected_n_flagged = float(prev_n + rem_pos * (counts[b] / pos_counts[b]))
    tie_expected_precision = float(target_tp / expected_n_flagged)
    achieved_recall = float(target_tp / n_pos)

    return {
        "target_tp": target_tp,
        "achieved_recall": achieved_recall,
        "expected_n_flagged": expected_n_flagged,
        "tie_expected_precision": tie_expected_precision,
        "threshold": float(vals[b]),
        "n_flagged_at_threshold": int(cum_n[b]),
        "tp_at_threshold": int(cum_pos[b]),
        "precision_at_threshold": float(cum_pos[b] / cum_n[b]),
        "recall_at_threshold": float(cum_pos[b] / n_pos),
    }


def _arm_display_name(arm: str) -> str:
    return {**config.ARM_DISPLAY, **run_track_a.BASELINE_DISPLAY}.get(arm, arm)


def compute_operating_points_table(
    df_full: pd.DataFrame,
    df_no_content: pd.DataFrame,
    ml_arms: Sequence[str] = ML_ARMS_ALL,
    ks: Sequence[int] = TOP_KS,
) -> pd.DataFrame:
    """Build Analysis 2 operating-point and P@k/R@k comparison table."""
    _validate_aligned_predictions(df_full, df_no_content)
    all_required = tuple(dict.fromkeys([*ml_arms, *BASELINE_ARMS]))
    scores_full = extract_score_map(df_full, all_required, label="full_20")
    scores_nc = extract_score_map(df_no_content, all_required, label="no_content")
    y = df_full["y"].to_numpy(dtype=int)
    n_pos = int(y.sum())
    commit = get_commit_hash()

    rows: list[dict[str, Any]] = []

    def _base_row(
        eval_type: str,
        op_point: str,
        cfg: str,
        arm: str,
        target_recall: float | None,
        target_n_flagged: int | None,
        n_flagged: float,
        n_flagged_thresh: int | None,
        threshold: float | None,
        expected_tp: float,
        precision: float,
        precision_thresh: float | None,
        recall: float,
        tie_handling: str,
        caveat: str,
    ) -> dict[str, Any]:
        return {
            "analysis_status": POSTHOC_STATUS,
            "evaluation_type": eval_type,
            "operating_point": op_point,
            "config": cfg,
            "arm": arm,
            "arm_name": _arm_display_name(arm),
            "target_recall": target_recall,
            "target_n_flagged": target_n_flagged,
            "n_flagged": float(n_flagged),
            "n_flagged_at_threshold": n_flagged_thresh,
            "threshold": threshold,
            "expected_tp": float(expected_tp),
            "n_pos_total": n_pos,
            "precision": float(precision),
            "precision_at_threshold": precision_thresh,
            "recall": float(recall),
            "tie_handling": tie_handling,
            "threshold_caveat": caveat,
            "commit": commit,
        }

    # Rules operating points (identical in full_20 and no_content)
    rules_bin_scores = scores_full["rules_binary"]
    rules_cnt_scores = scores_full["rules_count"]

    rules_specs: list[tuple[str, str, float, np.ndarray]] = []
    bin_mask = rules_bin_scores >= 1.0
    rules_specs.append(("rules_binary >= 1", "rules_binary", 1.0, bin_mask))

    pos_thresholds = sorted({int(round(v)) for v in rules_cnt_scores if v >= 1.0})
    for c in pos_thresholds:
        cnt_mask = rules_cnt_scores >= float(c)
        rules_specs.append((f"rules_count >= {c}", "rules_count", float(c), cnt_mask))

    unique_matched_ops: list[tuple[str, int, float]] = []
    seen_targets: set[tuple[int, int]] = set()
    for op_label, arm, thresh, mask in rules_specs:
        n_flag = int(mask.sum())
        tp = int((y[mask] == 1).sum())
        prec = float(tp / n_flag) if n_flag > 0 else float("nan")
        rec = float(tp / n_pos) if n_pos > 0 else float("nan")
        rows.append(
            _base_row(
                eval_type="rules_operating_point",
                op_point=op_label,
                cfg="config_invariant",
                arm=arm,
                target_recall=rec,
                target_n_flagged=n_flag,
                n_flagged=float(n_flag),
                n_flagged_thresh=n_flag,
                threshold=thresh,
                expected_tp=float(tp),
                precision=prec,
                precision_thresh=prec,
                recall=rec,
                tie_handling="exact_threshold",
                caveat=THRESHOLD_CAVEAT,
            )
        )
        sig = (tp, n_flag)
        if sig not in seen_targets:
            seen_targets.add(sig)
            matched_label = (
                "rules_binary >= 1 / rules_count >= 1"
                if abs(thresh - 1.0) < 1e-12
                else op_label
            )
            unique_matched_ops.append((matched_label, n_flag, rec))

    # Matched recall & matched flagged counts across both feature configs
    for op_label, target_n_flagged, target_rec in unique_matched_ops:
        for cfg_name, score_map in (("full_20", scores_full), ("no_content", scores_nc)):
            for arm in ml_arms:
                s = score_map[arm]
                res_r = tie_expected_precision_at_recall(y, s, target_rec)
                rows.append(
                    _base_row(
                        eval_type="matched_at_rules_recall",
                        op_point=op_label,
                        cfg=cfg_name,
                        arm=arm,
                        target_recall=target_rec,
                        target_n_flagged=target_n_flagged,
                        n_flagged=float(res_r["expected_n_flagged"]),
                        n_flagged_thresh=int(res_r["n_flagged_at_threshold"]),
                        threshold=float(res_r["threshold"]),
                        expected_tp=float(res_r["target_tp"]),
                        precision=float(res_r["tie_expected_precision"]),
                        precision_thresh=float(res_r["precision_at_threshold"]),
                        recall=float(res_r["achieved_recall"]),
                        tie_handling="tie_expected",
                        caveat=THRESHOLD_CAVEAT,
                    )
                )

                p_at_m = M.tie_expected_precision_at_k(y, s, target_n_flagged)
                r_at_m = M.tie_expected_recall_at_k(y, s, target_n_flagged)
                rows.append(
                    _base_row(
                        eval_type="matched_at_rules_flagged",
                        op_point=op_label,
                        cfg=cfg_name,
                        arm=arm,
                        target_recall=target_rec,
                        target_n_flagged=target_n_flagged,
                        n_flagged=float(target_n_flagged),
                        n_flagged_thresh=None,
                        threshold=None,
                        expected_tp=float(r_at_m * n_pos),
                        precision=float(p_at_m),
                        precision_thresh=None,
                        recall=float(r_at_m),
                        tie_handling="tie_expected",
                        caveat=THRESHOLD_CAVEAT,
                    )
                )

    # P@k and R@k for k in {5, 10, 20, 50}
    for k in ks:
        for arm in BASELINE_ARMS:
            s = scores_full[arm]
            p_k = M.tie_expected_precision_at_k(y, s, k)
            r_k = M.tie_expected_recall_at_k(y, s, k)
            rows.append(
                _base_row(
                    eval_type="top_k",
                    op_point=f"top_{k}",
                    cfg="config_invariant",
                    arm=arm,
                    target_recall=None,
                    target_n_flagged=int(k),
                    n_flagged=float(k),
                    n_flagged_thresh=None,
                    threshold=None,
                    expected_tp=float(r_k * n_pos),
                    precision=float(p_k),
                    precision_thresh=None,
                    recall=float(r_k),
                    tie_handling="tie_expected",
                    caveat=TOPK_CAVEAT,
                )
            )
        for cfg_name, score_map in (("full_20", scores_full), ("no_content", scores_nc)):
            for arm in ml_arms:
                s = score_map[arm]
                p_k = M.tie_expected_precision_at_k(y, s, k)
                r_k = M.tie_expected_recall_at_k(y, s, k)
                rows.append(
                    _base_row(
                        eval_type="top_k",
                        op_point=f"top_{k}",
                        cfg=cfg_name,
                        arm=arm,
                        target_recall=None,
                        target_n_flagged=int(k),
                        n_flagged=float(k),
                        n_flagged_thresh=None,
                        threshold=None,
                        expected_tp=float(r_k * n_pos),
                        precision=float(p_k),
                        precision_thresh=None,
                        recall=float(r_k),
                        tie_handling="tie_expected",
                        caveat=TOPK_CAVEAT,
                    )
                )

    return pd.DataFrame(rows)


def compute_shap_ranks_and_spearman(
    shap_by_config: dict[str, pd.DataFrame],
    arms: Sequence[str] = ("rf", "xgb", "mlp"),
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Compute per-model SHAP feature ranks, normalized shares, and Spearman correlations."""
    commit = get_commit_hash()
    rank_rows: list[dict[str, Any]] = []
    spearman_rows: list[dict[str, Any]] = []

    for cfg_name, df_shap in shap_by_config.items():
        present_arms = [a for a in arms if a in set(df_shap["arm"])]
        summaries: dict[str, pd.DataFrame] = {}
        all_features: list[str] = []
        top10_union: list[str] = []

        for arm in present_arms:
            sub = (
                df_shap[df_shap["arm"] == arm]
                .sort_values(["mean_abs_shap", "feature"], ascending=[False, True])
                .reset_index(drop=True)
            )
            summaries[arm] = sub
            total = float(sub["mean_abs_shap"].sum())
            denom = total if total > 0.0 else 1.0
            shares = sub["mean_abs_shap"] / denom
            ranks_min = sub["mean_abs_shap"].rank(ascending=False, method="min").astype(int)
            ranks_avg = sub["mean_abs_shap"].rank(ascending=False, method="average")
            n_feats = len(sub)

            for feat in sub["feature"]:
                if feat not in all_features:
                    all_features.append(str(feat))
            for feat in sub["feature"].head(10):
                if feat not in top10_union:
                    top10_union.append(str(feat))

            for idx, r in sub.iterrows():
                rank_rows.append({
                    "analysis_status": POSTHOC_STATUS,
                    "config": cfg_name,
                    "arm": arm,
                    "arm_name": _arm_display_name(arm),
                    "n_features_in_config": n_feats,
                    "feature": str(r["feature"]),
                    "rank": int(ranks_min.iloc[idx]),
                    "rank_avg": float(ranks_avg.iloc[idx]),
                    "normalized_share": float(shares.iloc[idx]),
                    "mean_abs_shap": float(r["mean_abs_shap"]),
                    "explainer": str(r.get("explainer", "")),
                    "model_scale": MODEL_SHAP_SCALES.get(arm, "unknown"),
                    "scale_note": SHAP_SCALE_NOTE,
                    "commit": commit,
                })

        vec_by_arm = {
            arm: summaries[arm].set_index("feature")["mean_abs_shap"] for arm in present_arms
        }
        for subset_name, feat_list in (
            ("all_features", all_features),
            ("top10_union", top10_union),
        ):
            for i, a1 in enumerate(present_arms):
                for a2 in present_arms[i + 1 :]:
                    v1 = vec_by_arm[a1].reindex(feat_list).fillna(0.0).to_numpy()
                    v2 = vec_by_arm[a2].reindex(feat_list).fillna(0.0).to_numpy()
                    rho, pval = spearmanr(v1, v2)
                    spearman_rows.append({
                        "analysis_status": POSTHOC_STATUS,
                        "config": cfg_name,
                        "feature_subset": subset_name,
                        "arm_1": a1,
                        "arm_2": a2,
                        "n_features_compared": len(feat_list),
                        "spearman_rho": float(rho) if not np.isnan(rho) else 0.0,
                        "p_value": float(pval) if not np.isnan(pval) else 1.0,
                        "scale_note": SHAP_SCALE_NOTE,
                        "commit": commit,
                    })

    return pd.DataFrame(rank_rows), pd.DataFrame(spearman_rows)


def plot_shap_normalized_shares(
    ranks_df: pd.DataFrame,
    out_dir: Path = config.FIGURES_DIR,
    stem: str = "supp_posthoc_shap_normalized_shares",
) -> list[Path]:
    """Generate 300-DPI PNG + PDF of per-model normalized SHAP shares across both configs.

    Does NOT modify existing figures_manifest.json files.
    """
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.size": 8.0,
        "axes.labelsize": 8.5,
        "xtick.labelsize": 7.5,
        "ytick.labelsize": 7.5,
        "legend.fontsize": 7.5,
        "axes.spines.top": False,
        "axes.spines.right": False,
    })

    configs = [c for c in ("full_20", "no_content") if c in set(ranks_df["config"])]
    fig, axes = plt.subplots(1, len(configs), figsize=(11.5, 5.6), sharey=False)
    if len(configs) == 1:
        axes = [axes]

    arms = [a for a in ("rf", "xgb", "mlp") if a in set(ranks_df["arm"])]
    h = 0.25

    for ax, cfg in zip(axes, configs):
        sub_cfg = ranks_df[ranks_df["config"] == cfg]
        feat_order = (
            sub_cfg.groupby("feature")["normalized_share"]
            .mean()
            .sort_values(ascending=True)
            .index.tolist()
        )
        y_pos = np.arange(len(feat_order))
        for i, arm in enumerate(arms):
            s_arm = (
                sub_cfg[sub_cfg["arm"] == arm]
                .set_index("feature")["normalized_share"]
                .reindex(feat_order)
                .fillna(0.0)
            )
            ax.barh(
                y_pos + (i - (len(arms) - 1) / 2) * h,
                s_arm.to_numpy() * 100.0,
                height=h,
                label=_arm_display_name(arm),
                color=ARM_COLORS.get(arm, "#333333"),
                edgecolor="black",
                linewidth=0.3,
            )
        n_feats = len(feat_order)
        ax.set_yticks(y_pos)
        ax.set_yticklabels(feat_order)
        ax.set_xlabel("Normalized mean |SHAP| share (%)")
        ax.set_title(f"{cfg} (n = {n_feats} features)", fontsize=9.0, fontweight="bold")
        ax.grid(axis="x", linestyle=":", alpha=0.45)

    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", bbox_to_anchor=(0.5, 0.94), ncol=len(arms), frameon=False)
    fig.suptitle(
        "Post-Hoc Supplementary: Normalized SHAP Feature Importance Shares (RF, XGBoost, MLP)",
        fontsize=10.0,
        fontweight="bold",
        y=0.985,
    )
    fig.text(
        0.5,
        0.008,
        "Post-hoc supplementary (not in FINAL_EVAL_PLAN). Raw SHAP magnitudes differ in scale (RF prob, XGB log-odds, MLP logit); normalized share = mean|SHAP| / sum(mean|SHAP|).",
        ha="center",
        fontsize=7.0,
        color="#444444",
    )
    fig.tight_layout(rect=[0.0, 0.03, 1.0, 0.90])

    saved: list[Path] = []
    for ext in ("png", "pdf"):
        out_p = out_dir / f"{stem}.{ext}"
        fig.savefig(out_p, dpi=300, bbox_inches="tight")
        saved.append(out_p)
    plt.close(fig)
    return saved


def append_supp_posthoc_log(
    log_path: str | Path,
    test_sha256: str,
    inputs: Sequence[str],
    outputs: Sequence[str],
    script: str = "src/eval/supp_posthoc.py",
) -> dict[str, Any]:
    """Append a structured run record to results/logs/supp_posthoc_log.jsonl."""
    p = Path(log_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp_utc": utc_now_iso(),
        "analysis_status": "post_hoc_supplementary",
        "commit": get_commit_hash(),
        "script": script,
        "test_sha256": test_sha256,
        "inputs": list(inputs),
        "outputs": list(outputs),
    }
    with p.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, sort_keys=True) + "\n")
    return record


def run_all(
    dataset_path: Path = config.PROCESSED_DIR / "dataset_v1.parquet",
    manifest_path: Path = config.SPLITS_DIR / "dataset_v1_manifest.json",
    tables_dir: Path = config.TABLES_DIR,
    figures_dir: Path = config.FIGURES_DIR,
    log_path: Path = config.LOGS_DIR / "supp_posthoc_log.jsonl",
) -> dict[str, Any]:
    """Verify frozen test hash and run all three read-only post-hoc supplementary analyses."""
    test_sha = verify_frozen_test_hash(dataset_path=dataset_path, manifest_path=manifest_path)

    full_pred_p = tables_dir / "track_a_test_predictions.parquet"
    nc_pred_p = tables_dir / "no_content" / "track_a_test_predictions.parquet"
    full_shap_p = tables_dir / "shap_summary_all.csv"
    nc_shap_p = tables_dir / "no_content" / "shap_summary_all.csv"

    df_full = pd.read_parquet(full_pred_p)
    df_nc = pd.read_parquet(nc_pred_p)
    shap_full = pd.read_csv(full_shap_p)
    shap_nc = pd.read_csv(nc_shap_p)

    # Analysis 1: rf, xgb, mlp vs rules_count
    verdicts_df = compute_dual_config_verdicts_from_predictions(df_full, df_nc)
    out_verdicts = tables_dir / "supp_posthoc_dual_config_vs_rules_count.csv"
    verdicts_df.to_csv(out_verdicts, index=False)

    # Analysis 2: Operating-point comparison & P@k / R@k
    op_df = compute_operating_points_table(df_full, df_nc)
    out_op = tables_dir / "supp_posthoc_operating_points.csv"
    op_df.to_csv(out_op, index=False)

    # Analysis 3: SHAP ranks, normalized shares, Spearman, and 300-DPI figure
    ranks_df, spearman_df = compute_shap_ranks_and_spearman(
        {"full_20": shap_full, "no_content": shap_nc}
    )
    out_ranks = tables_dir / "supp_posthoc_shap_ranks.csv"
    out_spear = tables_dir / "supp_posthoc_shap_spearman.csv"
    ranks_df.to_csv(out_ranks, index=False)
    spearman_df.to_csv(out_spear, index=False)

    fig_paths = plot_shap_normalized_shares(ranks_df, out_dir=figures_dir)

    inputs = [
        str(dataset_path),
        str(manifest_path),
        str(full_pred_p),
        str(nc_pred_p),
        str(full_shap_p),
        str(nc_shap_p),
    ]
    outputs = [
        str(out_verdicts),
        str(out_op),
        str(out_ranks),
        str(out_spear),
        *[str(p) for p in fig_paths],
    ]
    log_rec = append_supp_posthoc_log(
        log_path=log_path,
        test_sha256=test_sha,
        inputs=[_rel_to_repo(p) for p in inputs],
        outputs=[_rel_to_repo(p) for p in outputs],
    )
    return {
        "test_sha256": test_sha,
        "verdicts": verdicts_df,
        "operating_points": op_df,
        "shap_ranks": ranks_df,
        "shap_spearman": spearman_df,
        "figure_paths": fig_paths,
        "log_record": log_rec,
    }


def _rel_to_repo(path_str: str) -> str:
    p = Path(path_str).resolve()
    try:
        return str(p.relative_to(config.REPO_ROOT.resolve()))
    except ValueError:
        return str(path_str)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run post-hoc supplementary analyses purely from frozen --final outputs."
    )
    parser.add_argument("--tables-dir", type=Path, default=config.TABLES_DIR)
    parser.add_argument("--figures-dir", type=Path, default=config.FIGURES_DIR)
    parser.add_argument("--log-path", type=Path, default=config.LOGS_DIR / "supp_posthoc_log.jsonl")
    args = parser.parse_args()
    res = run_all(tables_dir=args.tables_dir, figures_dir=args.figures_dir, log_path=args.log_path)
    print(f"Verified test_sha256: {res['test_sha256']}")
    print(f"Wrote {len(res['verdicts'])} verdict rows -> supp_posthoc_dual_config_vs_rules_count.csv")
    print(f"Wrote {len(res['operating_points'])} operating-point rows -> supp_posthoc_operating_points.csv")
    print(f"Wrote {len(res['shap_ranks'])} SHAP rank rows -> supp_posthoc_shap_ranks.csv")
    print(f"Wrote {len(res['shap_spearman'])} SHAP Spearman rows -> supp_posthoc_shap_spearman.csv")
    print(f"Saved figures: {[p.name for p in res['figure_paths']]}")


if __name__ == "__main__":
    main()
