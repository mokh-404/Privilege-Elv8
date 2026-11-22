"""Explainability suite (Prompt D, doc 07 section 7):

  - XGBoost & Random Forest: SHAP TreeExplainer (stratified sample <= 2000 test rows).
  - PyTorch MLP: SHAP GradientExplainer (100-row background, <= 500 test rows),
    with automatic KernelExplainer fallback (logged).
  - Maps one-hot and missing-indicator columns back to the 20 original features by summing |SHAP|.
  - Spearman rank correlation across RF, XGBoost, and MLP top-10 features.
  - PyTorch Autoencoder: per-feature mean reconstruction MSE (attack vs benign).
  - Isolation Forest: permutation importance on PR-AUC grouped by original feature.
  - Error analysis: top-20 false positives and top-20 false negatives.
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Sequence

import joblib
import numpy as np
import pandas as pd
import shap
import torch
from scipy.stats import spearmanr

from src import config
from src.eval import metrics as M
from src.models.autoencoder import DeepAutoencoderArm
from src.models.mlp import TabularMLPArm
from src.models.preprocess import SharedPreprocessor
from src.models.sklearn_models import IsolationForestArm
from src.utils.repro import get_commit_hash, set_global_seed


def _stratified_sample_indices(y: np.ndarray, max_rows: int, seed: int = config.SEED) -> np.ndarray:
    y = np.asarray(y).astype(int).ravel()
    if len(y) <= max_rows:
        return np.arange(len(y))
    rng = np.random.default_rng(seed)
    pos_idx = np.flatnonzero(y == 1)
    neg_idx = np.flatnonzero(y == 0)
    # Keep all positives up to max_rows // 2 so attacker_induced rows are represented
    n_pos = min(len(pos_idx), max(1, max_rows // 2)) if len(pos_idx) else 0
    n_neg = min(len(neg_idx), max_rows - n_pos)
    pick_p = rng.choice(pos_idx, size=n_pos, replace=False) if n_pos else np.empty(0, dtype=int)
    pick_n = rng.choice(neg_idx, size=n_neg, replace=False) if n_neg else np.empty(0, dtype=int)
    return np.sort(np.concatenate([pick_p, pick_n]))


def _normalize_shap_2d(sv: Any) -> np.ndarray:
    if isinstance(sv, list):
        sv = sv[1] if len(sv) >= 2 else sv[0]
    arr = np.asarray(sv, dtype=float)
    if arr.ndim == 3:
        arr = arr[:, :, 1] if arr.shape[2] >= 2 else arr[:, :, 0]
    if arr.ndim != 2:
        raise ValueError(f"Expected 2D SHAP array after normalization, got shape {arr.shape}")
    return arr


def aggregate_shap_to_original_features(
    shap_values_2d: np.ndarray,
    feature_origin: Sequence[str],
    orig_features: Sequence[str] = config.FEATURES,
) -> tuple[np.ndarray, np.ndarray]:
    """Sum signed and absolute SHAP values from encoded columns back to original features."""
    sv = np.asarray(shap_values_2d, dtype=float)
    if sv.shape[1] != len(feature_origin):
        raise ValueError(f"SHAP width {sv.shape[1]} != feature_origin length {len(feature_origin)}")
    n = sv.shape[0]
    d_orig = len(orig_features)
    signed_out = np.zeros((n, d_orig), dtype=float)
    abs_out = np.zeros((n, d_orig), dtype=float)
    col_map: dict[str, list[int]] = {}
    for idx, orig in enumerate(feature_origin):
        col_map.setdefault(orig, []).append(idx)
    for j, feat in enumerate(orig_features):
        idxs = col_map.get(feat, [])
        if idxs:
            signed_out[:, j] = sv[:, idxs].sum(axis=1)
            abs_out[:, j] = np.abs(sv[:, idxs]).sum(axis=1)
    return signed_out, abs_out


def explain_tree_arm(
    arm,
    pre: SharedPreprocessor,
    eval_df: pd.DataFrame,
    y_eval: np.ndarray,
    max_rows: int = 2000,
    seed: int = config.SEED,
    orig_features: Sequence[str] = config.FEATURES,
) -> dict[str, Any]:
    """Compute SHAP TreeExplainer values aggregated to `orig_features`."""
    idx = _stratified_sample_indices(y_eval, max_rows=max_rows, seed=seed)
    X_enc = pre.transform(eval_df.iloc[idx])
    explainer = shap.TreeExplainer(arm.model)
    raw_sv = explainer.shap_values(X_enc)
    sv_2d = _normalize_shap_2d(raw_sv)
    signed_orig, abs_orig = aggregate_shap_to_original_features(sv_2d, pre.feature_origin_, orig_features)
    mean_abs = abs_orig.mean(axis=0)
    summary = pd.DataFrame({
        "arm": arm.name,
        "feature": list(orig_features),
        "mean_abs_shap": mean_abs,
        "explainer": "TreeExplainer",
    }).sort_values("mean_abs_shap", ascending=False).reset_index(drop=True)
    return {
        "summary": summary,
        "signed_df": pd.DataFrame(signed_orig, columns=list(orig_features)),
        "sample_indices": idx,
        "explainer": "TreeExplainer",
    }


def explain_mlp_arm(
    arm: TabularMLPArm,
    pre: SharedPreprocessor,
    train_df: pd.DataFrame,
    eval_df: pd.DataFrame,
    y_eval: np.ndarray,
    bg_size: int = 100,
    max_rows: int = 500,
    seed: int = config.SEED,
    orig_features: Sequence[str] = config.FEATURES,
) -> dict[str, Any]:
    """Compute SHAP GradientExplainer on CPU, falling back cleanly to KernelExplainer if needed."""
    set_global_seed(seed)
    rng = np.random.default_rng(seed)
    X_bg_all = pre.transform(train_df)
    bg_pick = rng.choice(len(X_bg_all), size=min(bg_size, len(X_bg_all)), replace=False)
    X_bg = X_bg_all[np.sort(bg_pick)]

    idx = _stratified_sample_indices(y_eval, max_rows=max_rows, seed=seed)
    X_ev = pre.transform(eval_df.iloc[idx])

    # Run GradientExplainer on a CPU copy so device alignment is guaranteed
    assert arm.net is not None
    orig_device = next(arm.net.parameters()).device
    explainer_used = "GradientExplainer"
    try:
        arm.net.to("cpu").eval()
        exp = shap.GradientExplainer(arm.net, torch.from_numpy(X_bg))
        raw_sv = exp.shap_values(torch.from_numpy(X_ev))
        sv_2d = _normalize_shap_2d(raw_sv)
    except Exception as exc:
        explainer_used = "KernelExplainer_fallback"
        print(f"[INFO] GradientExplainer failed ({exc}); falling back to KernelExplainer.")
        arm.net.to(orig_device).eval()
        kexp = shap.KernelExplainer(lambda x: arm.predict_scores(x), X_bg[:min(50, len(X_bg))])
        raw_sv = kexp.shap_values(X_ev, nsamples=100, silent=True)
        sv_2d = _normalize_shap_2d(raw_sv)
    finally:
        arm.net.to(orig_device).eval()

    signed_orig, abs_orig = aggregate_shap_to_original_features(sv_2d, pre.feature_origin_, orig_features)
    summary = pd.DataFrame({
        "arm": arm.name,
        "feature": list(orig_features),
        "mean_abs_shap": abs_orig.mean(axis=0),
        "explainer": explainer_used,
    }).sort_values("mean_abs_shap", ascending=False).reset_index(drop=True)
    return {
        "summary": summary,
        "signed_df": pd.DataFrame(signed_orig, columns=list(orig_features)),
        "sample_indices": idx,
        "explainer": explainer_used,
    }


def compute_spearman_top10(summaries: dict[str, pd.DataFrame]) -> pd.DataFrame:
    """Pairwise Spearman rank correlation on top-10 features across RF, XGBoost, and MLP."""
    arms = [a for a in ("rf", "xgb", "mlp") if a in summaries]
    top_union: list[str] = []
    vec_by_arm: dict[str, pd.Series] = {}
    for a in arms:
        df = summaries[a].sort_values("mean_abs_shap", ascending=False)
        vec_by_arm[a] = df.set_index("feature")["mean_abs_shap"]
        for f in df["feature"].head(10):
            if f not in top_union:
                top_union.append(f)

    rows = []
    for i, a1 in enumerate(arms):
        for a2 in arms[i + 1 :]:
            v1 = vec_by_arm[a1].reindex(top_union).fillna(0.0).to_numpy()
            v2 = vec_by_arm[a2].reindex(top_union).fillna(0.0).to_numpy()
            rho, pval = spearmanr(v1, v2)
            rows.append({
                "arm_1": a1,
                "arm_2": a2,
                "n_features_compared": len(top_union),
                "spearman_rho": float(rho) if not np.isnan(rho) else 0.0,
                "p_value": float(pval) if not np.isnan(pval) else 1.0,
                "commit": get_commit_hash(),
            })
    return pd.DataFrame(rows)


def explain_autoencoder(
    arm: DeepAutoencoderArm,
    pre: SharedPreprocessor,
    eval_df: pd.DataFrame,
    y_eval: np.ndarray,
    orig_features: Sequence[str] = config.FEATURES,
) -> pd.DataFrame:
    """Per-feature mean reconstruction MSE on attacker_induced vs benign test rows."""
    X_enc = pre.transform(eval_df)
    pf_mse = arm.per_feature_mse(X_enc)
    _, agg = aggregate_shap_to_original_features(pf_mse, pre.feature_origin_, orig_features)
    y = np.asarray(y_eval).astype(int).ravel()
    att = agg[y == 1].mean(axis=0) if (y == 1).any() else np.zeros(len(orig_features))
    ben = agg[y == 0].mean(axis=0) if (y == 0).any() else np.zeros(len(orig_features))
    return pd.DataFrame({
        "feature": list(orig_features),
        "mean_mse_attack": att,
        "mean_mse_benign": ben,
        "mse_diff_attack_minus_benign": att - ben,
        "commit": get_commit_hash(),
    }).sort_values("mse_diff_attack_minus_benign", ascending=False).reset_index(drop=True)


def explain_iforest_permutation(
    arm: IsolationForestArm,
    pre: SharedPreprocessor,
    eval_df: pd.DataFrame,
    y_eval: np.ndarray,
    n_repeats: int = 5,
    seed: int = config.SEED,
    orig_features: Sequence[str] = config.FEATURES,
) -> pd.DataFrame:
    """Permutation importance on PR-AUC grouped by original feature (for Isolation Forest)."""
    rng = np.random.default_rng(seed)
    X_enc = pre.transform(eval_df)
    base_pr = M.pr_auc(y_eval, arm.predict_scores(X_enc))

    col_map: dict[str, list[int]] = {}
    for idx, orig in enumerate(pre.feature_origin_):
        col_map.setdefault(orig, []).append(idx)

    rows = []
    for feat in orig_features:
        idxs = col_map.get(feat, [])
        if not idxs:
            rows.append({"feature": feat, "pr_auc_drop_mean": 0.0, "pr_auc_drop_std": 0.0})
            continue
        drops = []
        for _ in range(n_repeats):
            X_perm = X_enc.copy()
            perm = rng.permutation(len(X_perm))
            X_perm[:, idxs] = X_perm[perm][:, idxs]
            drops.append(base_pr - M.pr_auc(y_eval, arm.predict_scores(X_perm)))
        rows.append({
            "feature": feat,
            "pr_auc_drop_mean": float(np.mean(drops)),
            "pr_auc_drop_std": float(np.std(drops)),
            "commit": get_commit_hash(),
        })
    return pd.DataFrame(rows).sort_values("pr_auc_drop_mean", ascending=False).reset_index(drop=True)


def export_error_analysis(
    eval_df: pd.DataFrame,
    scores: Sequence[float],
    y_eval: Sequence[int],
    out_csv: str | Path,
    top_n: int = 20,
) -> pd.DataFrame:
    """Export top-N highest-scoring false positives and lowest-scoring false negatives."""
    df = eval_df.copy().reset_index(drop=True)
    df["score"] = np.asarray(scores, dtype=float)
    df["y"] = np.asarray(y_eval, dtype=int)
    fp = df[df["y"] == 0].sort_values("score", ascending=False).head(top_n).assign(error_type="false_positive")
    fn = df[df["y"] == 1].sort_values("score", ascending=True).head(top_n).assign(error_type="false_negative")
    cols = [c for c in ("error_type", "score", "y", "run_id", "technique_id", "artifact_type",
                        "artifact_key", "name", "path", "command_line", "label_reason") if c in df.columns]
    out = pd.concat([fp, fn], ignore_index=True)[cols]
    out["analyst_note"] = ""
    Path(out_csv).parent.mkdir(parents=True, exist_ok=True)
    out.to_csv(out_csv, index=False)
    return out


def run_all_explanations(
    dataset_df: pd.DataFrame,
    models_dir: Path = config.MODELS_DIR,
    out_tables_dir: Path = config.TABLES_DIR,
    max_tree_rows: int = 2000,
    max_mlp_rows: int = 500,
    mlp_bg_size: int = 100,
    seed: int = config.SEED,
    features: Sequence[str] | None = None,
) -> dict[str, pd.DataFrame]:
    """Run SHAP (RF, XGB, MLP), AE reconstruction error, IF permutation importance, and error analysis."""
    orig_features = list(features) if features is not None else list(config.FEATURES)
    dev_df = dataset_df[dataset_df["split_pool"] == "dev"].reset_index(drop=True)
    test_df = dataset_df[dataset_df["split_pool"] == "test"].reset_index(drop=True)
    y_test = (test_df[config.LABEL_COL] == config.POSITIVE_LABEL).astype(int).to_numpy()
    out_tables_dir = Path(out_tables_dir)
    out_tables_dir.mkdir(parents=True, exist_ok=True)
    models_dir = Path(models_dir)

    from src.models.sklearn_models import RandomForestArm, XGBoostArm
    summaries: dict[str, pd.DataFrame] = {}
    outputs: dict[str, pd.DataFrame] = {}

    for arm_key, loader in (("rf", RandomForestArm.load), ("xgb", XGBoostArm.load)):
        mp = models_dir / f"track_a_final_{arm_key}.bin"
        pp = models_dir / f"track_a_final_{arm_key}_pre.joblib"
        if mp.exists() and pp.exists():
            arm, pre = loader(mp), joblib.load(pp)
            res = explain_tree_arm(
                arm, pre, test_df, y_test, max_rows=max_tree_rows, seed=seed, orig_features=orig_features,
            )
            summaries[arm_key] = res["summary"]
            res["signed_df"].to_parquet(out_tables_dir / f"shap_{arm_key}_rows.parquet", index=False)
            if arm_key == "xgb":
                test_df.iloc[res["sample_indices"]][orig_features].reset_index(drop=True).to_parquet(
                    out_tables_dir / "shap_xgb_features.parquet", index=False
                )

    mp_mlp = models_dir / "track_a_final_mlp.bin"
    pp_mlp = models_dir / "track_a_final_mlp_pre.joblib"
    if mp_mlp.exists() and pp_mlp.exists():
        arm_mlp, pre_mlp = TabularMLPArm.load(mp_mlp), joblib.load(pp_mlp)
        res_mlp = explain_mlp_arm(
            arm_mlp, pre_mlp, dev_df, test_df, y_test,
            bg_size=mlp_bg_size, max_rows=max_mlp_rows, seed=seed, orig_features=orig_features,
        )
        summaries["mlp"] = res_mlp["summary"]

    if summaries:
        comb = pd.concat(summaries.values(), ignore_index=True)
        comb["commit"] = get_commit_hash()
        comb.to_csv(out_tables_dir / "shap_summary_all.csv", index=False)
        outputs["shap_summary"] = comb
        sp_df = compute_spearman_top10(summaries)
        sp_df.to_csv(out_tables_dir / "shap_spearman_top10.csv", index=False)
        outputs["spearman"] = sp_df

    mp_ae = models_dir / "track_a_final_ae.bin"
    pp_ae = models_dir / "track_a_final_ae_pre.joblib"
    if mp_ae.exists() and pp_ae.exists():
        ae_df = explain_autoencoder(
            DeepAutoencoderArm.load(mp_ae), joblib.load(pp_ae), test_df, y_test, orig_features=orig_features,
        )
        ae_df.to_csv(out_tables_dir / "ae_recon_error.csv", index=False)
        outputs["ae_recon_error"] = ae_df

    mp_if = models_dir / "track_a_final_iforest.bin"
    pp_if = models_dir / "track_a_final_iforest_pre.joblib"
    if mp_if.exists() and pp_if.exists():
        if_df = explain_iforest_permutation(
            IsolationForestArm.load(mp_if), joblib.load(pp_if), test_df, y_test, seed=seed, orig_features=orig_features,
        )
        if_df.to_csv(out_tables_dir / "iforest_perm_importance.csv", index=False)
        outputs["iforest_perm"] = if_df

    preds_p = out_tables_dir / "track_a_test_predictions.parquet"
    t1_p = out_tables_dir / "track_a_test_results.csv"
    if preds_p.exists() and t1_p.exists():
        t1 = pd.read_csv(t1_p).sort_values("pr_auc", ascending=False)
        best_arm = str(t1.iloc[0]["arm"])
        preds = pd.read_parquet(preds_p)
        if f"score_{best_arm}" in preds.columns:
            err_df = export_error_analysis(test_df, preds[f"score_{best_arm}"], y_test,
                                           out_tables_dir / f"error_analysis_{best_arm}.csv")
            outputs["error_analysis"] = err_df

    return outputs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate SHAP, AE error, IF permutation, and error analysis tables.")
    parser.add_argument("--dataset", type=Path, default=config.PROCESSED_DIR / "dataset_v1.parquet")
    parser.add_argument("--models-dir", type=Path, default=config.MODELS_DIR)
    parser.add_argument("--out-dir", type=Path, default=config.TABLES_DIR)
    parser.add_argument("--config", choices=["full_20", "no_content"], default="full_20")
    args = parser.parse_args(argv)
    df = pd.read_parquet(args.dataset)
    feats = list(config.FEATURES) if args.config == "full_20" else [
        f for f in config.FEATURES if f not in ("file_size_log", "file_entropy")
    ]
    run_all_explanations(df, models_dir=args.models_dir, out_tables_dir=args.out_dir, features=feats)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
