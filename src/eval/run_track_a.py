"""Track A five-arm evaluation: grouped dev CV, hyperparameter search, probes, and one-time final eval.

Rules (doc 07 & doc 10 section 3):
  - X uses config.FEATURES only (ORACLE_FEATURES, RULE_FEATURES, META_COLUMNS, LABEL_COL excluded),
    except explicitly tagged probe/ablation runs.
  - Grouping: attacker_induced by technique_id; benign keys by hash bucket (75/25 dev/test,
    dev fold = bucket % 5). Zero key or technique overlap across folds or dev/test.
  - Unsupervised arms (iforest, ae) fit preprocessor & model on benign training rows ONLY.
  - Final evaluation verifies frozen test hash and refuses a second --final without --force,
    logging every attempt (including refused ones) to results/logs/final_eval_audit.jsonl.
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Sequence

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import precision_recall_curve
from sklearn.model_selection import GroupShuffleSplit, StratifiedGroupKFold

from src import config
from src.data import labeler, splits
from src.eval import metrics as M
from src.models.autoencoder import DeepAutoencoderArm
from src.models.mlp import TabularMLPArm
from src.models.preprocess import SharedPreprocessor, assert_no_forbidden_inputs
from src.models.sklearn_models import (
    IsolationForestArm,
    RandomForestArm,
    XGBoostArm,
    build_logistic_regression_arm,
)
from src.utils.repro import get_commit_hash, run_metadata, set_global_seed, utc_now_iso, write_json

BASELINE_DISPLAY: dict[str, str] = {
    "rules_binary": "Rules only (rule_hit_count > 0)",
    "rules_count": "Rules only (rank by rule_hit_count)",
    "random": "Random baseline",
}
HARD_NEG_ARTIFACT_TYPES: tuple[str, ...] = ("file", "run_key", "task")
PROBE_FEATURE_SETS: dict[str, list[str]] = {
    "full_20": list(config.FEATURES),
    "probe_name_path": [
        "path_class", "path_depth", "ext_class",
        "has_double_extension", "name_length", "name_entropy",
    ],
    "probe_content": ["file_size_log", "file_entropy", "signature_state"],
    "probe_artifact_type": ["artifact_type"],
}
NO_CONTENT_FEATURES: list[str] = [
    f for f in config.FEATURES if f not in ("file_size_log", "file_entropy")
]
assert len(NO_CONTENT_FEATURES) == 18
EVAL_CONFIGS: dict[str, list[str]] = {
    "full_20": list(config.FEATURES),
    "no_content": list(NO_CONTENT_FEATURES),
}


def _build_arm(arm_key: str, seed: int = config.SEED, params: dict[str, Any] | None = None,
               max_epochs_override: int | None = None):
    p = dict(params or {})
    if arm_key == "rf":
        return RandomForestArm(seed=seed, **p)
    if arm_key == "xgb":
        return XGBoostArm(seed=seed, **p)
    if arm_key == "iforest":
        return IsolationForestArm(seed=seed, **p)
    if arm_key == "mlp":
        if max_epochs_override is not None:
            p["max_epochs"] = max_epochs_override
        return TabularMLPArm(seed=seed, **p)
    if arm_key == "ae":
        if max_epochs_override is not None:
            p["max_epochs"] = max_epochs_override
        return DeepAutoencoderArm(seed=seed, **p)
    if arm_key == "lr":
        return build_logistic_regression_arm(seed=seed, **p)
    raise ValueError(f"Unknown model arm: {arm_key!r}")


def _split_inner_grouped_val(
    df: pd.DataFrame,
    y: np.ndarray,
    seed: int = config.SEED,
) -> tuple[np.ndarray, np.ndarray]:
    """Grouped inner validation split for MLP/AE early stopping (no random row mixing)."""
    pos_idx = np.flatnonzero(y == 1)
    ben_idx = np.flatnonzero(y == 0)

    if len(pos_idx) > 0:
        pos_groups = df.iloc[pos_idx]["technique_id"].astype(str).to_numpy()
        uniq_t = np.unique(pos_groups)
        if len(uniq_t) >= 2:
            gss = GroupShuffleSplit(n_splits=1, test_size=max(1, len(uniq_t) // 5), random_state=seed)
            tr_p_rel, va_p_rel = next(gss.split(pos_idx, groups=pos_groups))
            tr_pos, va_pos = pos_idx[tr_p_rel], pos_idx[va_p_rel]
        else:
            tr_pos, va_pos = pos_idx, pos_idx
    else:
        tr_pos, va_pos = np.empty(0, dtype=int), np.empty(0, dtype=int)

    if "dev_fold" in df.columns and len(ben_idx) > 0:
        ben_folds = df.iloc[ben_idx]["dev_fold"].to_numpy()
        valid_folds = sorted({int(f) for f in ben_folds if f >= 0})
        if len(valid_folds) >= 2:
            pick = valid_folds[-1]
            va_ben = ben_idx[ben_folds == pick]
            tr_ben = ben_idx[ben_folds != pick]
        else:
            split_pt = max(1, (4 * len(ben_idx)) // 5)
            tr_ben, va_ben = ben_idx[:split_pt], ben_idx[split_pt:]
    else:
        split_pt = max(1, (4 * len(ben_idx)) // 5)
        tr_ben, va_ben = ben_idx[:split_pt], ben_idx[split_pt:]
        if len(va_ben) == 0:
            va_ben = tr_ben

    tr_idx = np.sort(np.concatenate([tr_pos, tr_ben]))
    va_idx = np.sort(np.concatenate([va_pos, va_ben]))
    return tr_idx, va_idx


def make_dev_folds(
    dev_df: pd.DataFrame,
    n_splits: int = config.N_DEV_FOLDS,
    seed: int = config.SEED,
) -> list[tuple[np.ndarray, np.ndarray]]:
    """Technique-grouped folds for positives + hash-bucket folds for benign dev rows."""
    dev_df = dev_df.reset_index(drop=True)
    y = (dev_df[config.LABEL_COL] == config.POSITIVE_LABEL).astype(int).to_numpy()
    pos_idx = np.flatnonzero(y == 1)
    ben_idx = np.flatnonzero(y == 0)

    if len(pos_idx) == 0:
        raise ValueError("Development split has zero attacker_induced rows")
    pos_groups = dev_df.iloc[pos_idx]["technique_id"].astype(str).to_numpy()
    n_tech = len(np.unique(pos_groups))
    if n_tech < 2:
        raise ValueError(f"Need at least 2 dev techniques for grouped CV, found {n_tech}")

    k = min(int(n_splits), n_tech)
    sgkf = StratifiedGroupKFold(n_splits=k, shuffle=True, random_state=seed)
    pos_fold_assign = np.zeros(len(pos_idx), dtype=int)
    for f_id, (_, va_rel) in enumerate(sgkf.split(pos_idx, np.ones(len(pos_idx)), groups=pos_groups)):
        pos_fold_assign[va_rel] = f_id

    if "dev_fold" in dev_df.columns and (dev_df.iloc[ben_idx]["dev_fold"] >= 0).all():
        ben_fold_assign = (dev_df.iloc[ben_idx]["dev_fold"].to_numpy() % k).astype(int)
    else:
        ben_fold_assign = np.array([
            splits.benign_dev_fold(str(key)) % k for key in dev_df.iloc[ben_idx]["artifact_key"]
        ], dtype=int)

    folds: list[tuple[np.ndarray, np.ndarray]] = []
    for f_id in range(k):
        va_pos = pos_idx[pos_fold_assign == f_id]
        tr_pos = pos_idx[pos_fold_assign != f_id]
        va_ben = ben_idx[ben_fold_assign == f_id]
        tr_ben = ben_idx[ben_fold_assign != f_id]
        tr_idx = np.sort(np.concatenate([tr_pos, tr_ben]))
        va_idx = np.sort(np.concatenate([va_pos, va_ben]))

        # Hard leakage assertions per fold
        assert set(dev_df.iloc[tr_pos]["technique_id"]).isdisjoint(set(dev_df.iloc[va_pos]["technique_id"]))
        assert set(dev_df.iloc[tr_ben]["artifact_key"]).isdisjoint(set(dev_df.iloc[va_ben]["artifact_key"]))
        folds.append((tr_idx, va_idx))
    return folds


def _sample_param_configs(arm_key: str, n_trials: int, seed: int = config.SEED) -> list[dict[str, Any]]:
    space = config.SEARCH_SPACES[arm_key]
    keys = sorted(space)
    rng = np.random.default_rng(seed)
    total_combos = 1
    for k in keys:
        total_combos *= len(space[k])
    target = min(int(n_trials), config.MAX_SEARCH_TRIALS, total_combos)
    seen: set[tuple] = set()
    configs: list[dict[str, Any]] = []
    attempts = 0
    while len(configs) < target and attempts < target * 20:
        attempts += 1
        pick = {k: space[k][int(rng.integers(0, len(space[k])))] for k in keys}
        sig = tuple((k, pick[k]) for k in keys)
        if sig not in seen:
            seen.add(sig)
            configs.append(pick)
    return configs


def _fit_arm_on_split(
    arm_key: str,
    tr_df: pd.DataFrame,
    y_tr: np.ndarray,
    va_df: pd.DataFrame | None,
    y_va: np.ndarray | None,
    cat_cols: Sequence[str],
    num_cols: Sequence[str],
    bin_cols: Sequence[str],
    allowed_extra: Sequence[str],
    seed: int,
    params: dict[str, Any] | None = None,
    max_epochs_override: int | None = None,
    inner_val_seed: int | None = None,
):
    arm = _build_arm(arm_key, seed=seed, params=params, max_epochs_override=max_epochs_override)
    if arm.is_unsupervised:
        tr_ben = tr_df[y_tr == 0]
        pre = SharedPreprocessor(cat_cols, num_cols, bin_cols, allowed_extra=allowed_extra).fit(tr_ben)
        X_tr_ben = pre.transform(tr_ben)
        y_tr_ben = np.zeros(len(tr_ben), dtype=int)
        if va_df is not None and y_va is not None and (y_va == 0).any():
            X_va_ben = pre.transform(va_df[y_va == 0])
            y_va_ben = np.zeros(len(X_va_ben), dtype=int)
        else:
            in_tr, in_va = _split_inner_grouped_val(tr_df, y_tr, seed=inner_val_seed or seed)
            in_tr_b = in_tr[y_tr[in_tr] == 0]
            in_va_b = in_va[y_tr[in_va] == 0]
            if len(in_tr_b) > 0 and len(in_va_b) > 0:
                pre = SharedPreprocessor(cat_cols, num_cols, bin_cols, allowed_extra=allowed_extra).fit(tr_df.iloc[in_tr_b])
                X_tr_ben = pre.transform(tr_df.iloc[in_tr_b])
                y_tr_ben = np.zeros(len(in_tr_b), dtype=int)
                X_va_ben = pre.transform(tr_df.iloc[in_va_b])
                y_va_ben = np.zeros(len(in_va_b), dtype=int)
            else:
                X_va_ben, y_va_ben = X_tr_ben, y_tr_ben
        arm.fit(X_tr_ben, y_tr_ben, X_val=X_va_ben, y_val=y_va_ben)
        return arm, pre

    # Supervised arms
    if arm_key == "mlp" and inner_val_seed is not None:
        in_tr, in_va = _split_inner_grouped_val(tr_df, y_tr, seed=inner_val_seed)
        pre = SharedPreprocessor(cat_cols, num_cols, bin_cols, allowed_extra=allowed_extra).fit(tr_df.iloc[in_tr])
        arm.fit(pre.transform(tr_df.iloc[in_tr]), y_tr[in_tr],
                X_val=pre.transform(tr_df.iloc[in_va]), y_val=y_tr[in_va])
        return arm, pre

    pre = SharedPreprocessor(cat_cols, num_cols, bin_cols, allowed_extra=allowed_extra).fit(tr_df)
    X_tr = pre.transform(tr_df)
    X_va = pre.transform(va_df) if va_df is not None else X_tr
    y_va_use = y_va if y_va is not None else y_tr
    arm.fit(X_tr, y_tr, X_val=X_va, y_val=y_va_use)
    return arm, pre


def _resolve_feature_lists(
    features_override: Sequence[str] | None = None,
    allowed_extra: Sequence[str] = (),
) -> tuple[list[str], list[str], list[str]]:
    base = list(features_override) if features_override is not None else list(config.FEATURES)
    assert_no_forbidden_inputs(base + list(allowed_extra), allowed_extra=allowed_extra)
    cat_cols = [c for c in config.CATEGORICAL_FEATURES if c in base]
    num_cols = [c for c in config.NUMERIC_FEATURES if c in base] + [
        c for c in allowed_extra if c not in config.CATEGORICAL_FEATURES + config.BINARY_FEATURES
    ]
    bin_cols = [c for c in config.BINARY_FEATURES if c in base]
    return cat_cols, num_cols, bin_cols


def compute_baseline_scores(df: pd.DataFrame, seed: int = config.SEED) -> dict[str, np.ndarray]:
    """Deterministic score vectors for non-ML baselines (rules + random)."""
    scores: dict[str, np.ndarray] = {}
    if "rule_hit_count" in df.columns:
        rh = df["rule_hit_count"].fillna(0.0).to_numpy(dtype=float)
        scores["rules_binary"] = (rh > 0).astype(float)
        scores["rules_count"] = rh
    scores["random"] = np.random.default_rng(seed).random(len(df))
    return scores


def evaluate_score_vector(
    arm_key: str,
    arm_name: str,
    df: pd.DataFrame,
    y: np.ndarray,
    scores: np.ndarray,
    n_boot: int = config.N_BOOTSTRAP,
) -> dict[str, Any]:
    """Compute ranking metrics, tie-expected @k, and run+technique bootstrap CIs on one slice."""
    n_pos = int((y == 1).sum())
    n_neg = int((y == 0).sum())
    has_label = config.LABEL_COL in df.columns
    clean_baseline_mask = (df[config.LABEL_COL].astype(str) == "baseline").to_numpy() if has_label else np.zeros(len(df), dtype=bool)
    drift_mask = (df[config.LABEL_COL].astype(str) == "benign_drift").to_numpy() if has_label else np.zeros(len(df), dtype=bool)

    if n_pos > 0 and n_neg > 0:
        pr = M.pr_auc(y, scores)
        roc = M.roc_auc(y, scores)
        boot_run = M.bootstrap_track_a(M.pr_auc, y, scores, df, group_by="run_id", n_boot=n_boot, seed=config.BOOTSTRAP_SEED)
        boot_tech = M.bootstrap_track_a(M.pr_auc, y, scores, df, group_by="technique_id", n_boot=n_boot, seed=config.BOOTSTRAP_SEED)
        fpr_all = M.fpr_at_recall(y, scores, config.FIXED_RECALL)
        fpr_base = M.fpr_at_recall(y, scores, config.FIXED_RECALL, negative_mask=clean_baseline_mask) if clean_baseline_mask.any() else float("nan")
        fpr_drift = M.fpr_at_recall(y, scores, config.FIXED_RECALL, negative_mask=drift_mask) if drift_mask.any() else float("nan")
    else:
        pr = float("nan")
        roc = float("nan")
        boot_run = {"lo": float("nan"), "hi": float("nan")}
        boot_tech = {"lo": float("nan"), "hi": float("nan")}
        fpr_all = float("nan")
        fpr_base = float("nan")
        fpr_drift = float("nan")

    row: dict[str, Any] = {
        "arm": arm_key,
        "arm_name": arm_name,
        "n_rows": int(len(df)),
        "n_pos": n_pos,
        "n_neg": n_neg,
        "n_baseline": int(clean_baseline_mask.sum()),
        "n_benign_drift": int(drift_mask.sum()),
        "pr_auc": float(pr),
        "pr_auc_ci_lo": float(boot_run["lo"]),
        "pr_auc_ci_hi": float(boot_run["hi"]),
        "pr_auc_run_ci_lo": float(boot_run["lo"]),
        "pr_auc_run_ci_hi": float(boot_run["hi"]),
        "pr_auc_tech_ci_lo": float(boot_tech["lo"]),
        "pr_auc_tech_ci_hi": float(boot_tech["hi"]),
        "roc_auc": float(roc),
        "fpr_at_recall_0.9_all_benign": float(fpr_all),
        "fpr_at_recall_0.9_clean_baseline": float(fpr_base),
        "fpr_at_recall_0.9_benign_drift": float(fpr_drift),
    }
    for k in config.K_VALUES:
        row[f"precision_at_{k}"] = M.tie_expected_precision_at_k(y, scores, k)
        row[f"recall_at_{k}"] = M.tie_expected_recall_at_k(y, scores, k)
    return row


def _default_paired_pairs(score_map: dict[str, np.ndarray], y: np.ndarray) -> list[tuple[str, str]]:
    """Build ordered unique paired comparison list for one score map."""
    ml_keys = [k for k in score_map if k not in BASELINE_DISPLAY]
    best_ml = max(ml_keys, key=lambda k: M.pr_auc(y, score_map[k])) if ml_keys else None
    raw_pairs: list[tuple[str, str]] = [("xgb", "rf")]
    if best_ml is not None:
        raw_pairs.append((best_ml, "rules_binary"))
    if best_ml != "rf":
        raw_pairs.append(("rf", "rules_binary"))
    if best_ml != "xgb":
        raw_pairs.append(("xgb", "rules_binary"))
    raw_pairs.extend([("rf", "mlp"), ("xgb", "mlp")])
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for a, b in raw_pairs:
        if (a, b) not in seen and a != b and a in score_map and b in score_map:
            seen.add((a, b))
            out.append((a, b))
    return out


def combine_dual_config_verdicts(paired_full: pd.DataFrame, paired_no_content: pd.DataFrame) -> pd.DataFrame:
    """Apply pre-registered dual-configuration winner rule across full_20 & no_content."""
    keep_cols = [
        "artifact_slice", "arm_a", "arm_b",
        "pr_auc_a", "pr_auc_b", "diff", "ci_lo", "ci_hi", "excludes_zero", "verdict",
    ]
    a_df = paired_full[keep_cols + [c for c in ("arm_a_name", "arm_b_name", "n_rows", "n_pos", "n_neg") if c in paired_full.columns]]
    b_df = paired_no_content[keep_cols]
    merged = a_df.merge(
        b_df,
        on=["artifact_slice", "arm_a", "arm_b"],
        how="inner",
        suffixes=("_full_20", "_no_content"),
    )
    verdicts: list[str] = []
    for _, r in merged.iterrows():
        vf = str(r["verdict_full_20"])
        vn = str(r["verdict_no_content"])
        if vf == "a_better" and vn == "a_better":
            verdicts.append("a_better")
        elif vf == "b_better" and vn == "b_better":
            verdicts.append("b_better")
        elif vf == "not distinguishable" and vn == "not distinguishable":
            verdicts.append("not distinguishable")
        else:
            verdicts.append("configuration-dependent")
    merged["dual_verdict"] = verdicts
    if "commit" in paired_full.columns and len(paired_full):
        merged["commit"] = str(paired_full["commit"].iloc[0])
    return merged


def compute_paired_comparisons(
    df: pd.DataFrame,
    y: np.ndarray,
    score_map: dict[str, np.ndarray],
    arm_names: dict[str, str] | None = None,
    pairs: Sequence[tuple[str, str]] | None = None,
    group_by: str = "run_id",
    n_boot: int = config.N_BOOTSTRAP,
    seed: int = config.BOOTSTRAP_SEED,
) -> pd.DataFrame:
    """Paired cluster bootstrap PR-AUC comparisons across all / hard-negative views."""
    names = arm_names or {**config.ARM_DISPLAY, **BASELINE_DISPLAY}
    if pairs is None:
        use_pairs = _default_paired_pairs(score_map, y)
    else:
        use_pairs = [(a, b) for a, b in pairs if a in score_map and b in score_map]

    slices: list[tuple[str, np.ndarray]] = [("all", np.ones(len(df), dtype=bool))]
    if "artifact_type" in df.columns:
        at = df["artifact_type"].astype(str)
        hn_mask = at.isin(HARD_NEG_ARTIFACT_TYPES).to_numpy()
        if hn_mask.any():
            slices.append(("file+run_key+task", hn_mask))
            if config.LABEL_COL in df.columns:
                hn_drift = hn_mask & (df[config.LABEL_COL].astype(str) != "baseline").to_numpy()
                if hn_drift.any():
                    slices.append(("file+run_key+task_drift_only", hn_drift))

    commit = get_commit_hash()
    rows: list[dict[str, Any]] = []
    for slice_name, mask in slices:
        sub_df = df.iloc[mask].reset_index(drop=True)
        y_sub = y[mask]
        n_pos = int((y_sub == 1).sum())
        n_neg = int((y_sub == 0).sum())
        for arm_a, arm_b in use_pairs:
            res = M.paired_bootstrap_track_a(
                M.pr_auc,
                y_sub,
                score_map[arm_a][mask],
                score_map[arm_b][mask],
                sub_df,
                group_by=group_by,
                n_boot=n_boot,
                seed=seed,
            )
            rows.append({
                "artifact_slice": slice_name,
                "arm_a": arm_a,
                "arm_a_name": names.get(arm_a, arm_a),
                "arm_b": arm_b,
                "arm_b_name": names.get(arm_b, arm_b),
                "n_rows": int(len(sub_df)),
                "n_pos": n_pos,
                "n_neg": n_neg,
                "pr_auc_a": float(res["point_a"]),
                "pr_auc_b": float(res["point_b"]),
                "diff": float(res["diff"]),
                "ci_lo": float(res["ci_lo"]),
                "ci_hi": float(res["ci_hi"]),
                "excludes_zero": bool(res["excludes_zero"]),
                "verdict": str(res["verdict"]),
                "group_by": str(res["group_by"]),
                "n_boot_valid": int(res["n_boot_valid"]),
                "seed": int(seed),
                "commit": commit,
            })
    return pd.DataFrame(rows)


def evaluate_by_artifact_type(
    df: pd.DataFrame,
    y: np.ndarray,
    score_map: dict[str, np.ndarray],
    arm_names: dict[str, str],
    n_boot: int = config.N_BOOTSTRAP,
) -> pd.DataFrame:
    """Evaluate all arms/baselines overall, on file+run_key+task hard negatives, and per artifact_type."""
    slices: list[tuple[str, np.ndarray]] = [("all", np.ones(len(df), dtype=bool))]
    if "artifact_type" in df.columns:
        at = df["artifact_type"].astype(str)
        hn_mask = at.isin(HARD_NEG_ARTIFACT_TYPES).to_numpy()
        if hn_mask.any():
            slices.append(("file+run_key+task", hn_mask))
            if config.LABEL_COL in df.columns:
                hn_drift = hn_mask & (df[config.LABEL_COL].astype(str) != "baseline").to_numpy()
                if hn_drift.any():
                    slices.append(("file+run_key+task_drift_only", hn_drift))
        pos_types = (
            df.loc[y == 1, "artifact_type"].astype(str).value_counts()
        )
        for atype in sorted(pos_types.index, key=lambda k: (-int(pos_types[k]), k)):
            slices.append((atype, (at == atype).to_numpy()))

    rows: list[dict[str, Any]] = []
    commit = get_commit_hash()
    for slice_name, mask in slices:
        sub_df = df.iloc[mask].reset_index(drop=True)
        y_sub = y[mask]
        for key, scores in score_map.items():
            rec = evaluate_score_vector(
                key,
                arm_names.get(key, key),
                sub_df,
                y_sub,
                scores[mask],
                n_boot=n_boot,
            )
            rec["artifact_slice"] = slice_name
            rec["commit"] = commit
            rows.append(rec)
    return pd.DataFrame(rows)


def _run_dev_oof(
    dev_df: pd.DataFrame,
    y_dev: np.ndarray,
    arm_key: str,
    cat_cols: Sequence[str],
    num_cols: Sequence[str],
    bin_cols: Sequence[str],
    allowed_extra: Sequence[str],
    seeds: Sequence[int],
    n_splits: int,
    params: dict[str, Any],
    max_epochs_override: int | None = None,
    unsup_baseline_only: bool = False,
) -> tuple[list[np.ndarray], list[float]]:
    """Run grouped dev CV across `seeds` for one arm/config; returns OOF vectors & per-seed PR-AUCs."""
    seed_oof_list: list[np.ndarray] = []
    seed_scores: list[float] = []
    for cv_seed in seeds:
        folds = make_dev_folds(dev_df, n_splits=n_splits, seed=cv_seed)
        oof_scores = np.zeros(len(dev_df), dtype=float)
        seen_val = np.zeros(len(dev_df), dtype=bool)
        for tr_idx, va_idx in folds:
            tr_sub = dev_df.iloc[tr_idx]
            y_tr_sub = y_dev[tr_idx]
            va_fit = dev_df.iloc[va_idx]
            y_va_fit = y_dev[va_idx]

            if unsup_baseline_only and arm_key in config.UNSUPERVISED_ARMS and config.LABEL_COL in dev_df.columns:
                tr_bmask = (tr_sub[config.LABEL_COL].astype(str) == "baseline").to_numpy()
                if tr_bmask.any():
                    tr_sub = tr_sub.iloc[tr_bmask].reset_index(drop=True)
                    y_tr_sub = np.zeros(len(tr_sub), dtype=int)
                va_bmask = (va_fit[config.LABEL_COL].astype(str) == "baseline").to_numpy()
                if va_bmask.any():
                    va_fit = va_fit.iloc[va_bmask].reset_index(drop=True)
                    y_va_fit = np.zeros(len(va_fit), dtype=int)

            arm, pre = _fit_arm_on_split(
                arm_key,
                tr_sub, y_tr_sub,
                va_fit, y_va_fit,
                cat_cols, num_cols, bin_cols, allowed_extra,
                seed=cv_seed, params=params, max_epochs_override=max_epochs_override,
                inner_val_seed=cv_seed,
            )
            oof_scores[va_idx] = arm.predict_scores(pre.transform(dev_df.iloc[va_idx]))
            seen_val[va_idx] = True
        assert seen_val.all()
        seed_oof_list.append(oof_scores)
        seed_scores.append(M.pr_auc(y_dev, oof_scores))
    return seed_oof_list, seed_scores


def run_dev_cv(
    df: pd.DataFrame,
    arms: Sequence[str] = config.ARMS,
    n_trials: int = config.MAX_SEARCH_TRIALS,
    seeds: Sequence[int] = config.DEV_CV_SEEDS,
    n_splits: int = config.N_DEV_FOLDS,
    allowed_extra: Sequence[str] = (),
    features_override: Sequence[str] | None = None,
    max_epochs_override: int | None = None,
    out_tables_dir: Path = config.TABLES_DIR,
    n_boot: int = config.N_BOOTSTRAP,
) -> tuple[pd.DataFrame, dict[str, dict[str, Any]]]:
    """Repeated grouped CV random search + full OOF dev evaluation on the development split ONLY."""
    dev_df = df[df["split_pool"] == "dev"].reset_index(drop=True)
    y_dev = (dev_df[config.LABEL_COL] == config.POSITIVE_LABEL).astype(int).to_numpy()
    cat_cols, num_cols, bin_cols = _resolve_feature_lists(features_override, allowed_extra)
    out_tables_dir = Path(out_tables_dir)
    out_tables_dir.mkdir(parents=True, exist_ok=True)
    commit = get_commit_hash()

    trial_rows: list[dict[str, Any]] = []
    best_params: dict[str, dict[str, Any]] = {}
    best_oof_mean: dict[str, np.ndarray] = {}
    best_seed_stats: dict[str, tuple[float, float]] = {}

    for arm_key in arms:
        param_cands = _sample_param_configs(arm_key, n_trials=n_trials, seed=config.SEED)
        best_score = -float("inf")
        best_cfg = param_cands[0]
        best_oof_list: list[np.ndarray] = []
        best_seeds_arr: list[float] = []

        for t_idx, p_cfg in enumerate(param_cands):
            seed_oof_list, seed_scores = _run_dev_oof(
                dev_df, y_dev, arm_key,
                cat_cols, num_cols, bin_cols, allowed_extra,
                seeds=seeds, n_splits=n_splits, params=p_cfg,
                max_epochs_override=max_epochs_override,
            )
            mean_pr = float(np.mean(seed_scores))
            std_pr = float(np.std(seed_scores))
            trial_rows.append({
                "arm": arm_key,
                "trial": t_idx,
                "params_json": json.dumps(p_cfg, sort_keys=True),
                "mean_pr_auc": mean_pr,
                "std_pr_auc": std_pr,
                "seed_scores_json": json.dumps([round(x, 6) for x in seed_scores]),
                "commit": commit,
            })
            if mean_pr > best_score:
                best_score = mean_pr
                best_cfg = p_cfg
                best_oof_list = seed_oof_list
                best_seeds_arr = seed_scores
        best_params[arm_key] = dict(best_cfg)
        best_oof_mean[arm_key] = np.mean(np.vstack(best_oof_list), axis=0)
        best_seed_stats[arm_key] = (float(np.mean(best_seeds_arr)), float(np.std(best_seeds_arr)))

    trials_df = pd.DataFrame(trial_rows)
    trials_df.to_csv(out_tables_dir / "track_a_dev_trials.csv", index=False)
    write_json(best_params, out_tables_dir / "track_a_best_params.json")

    # Combine tuned ML OOF scores + non-ML baselines strictly on dev_df
    baseline_scores = compute_baseline_scores(dev_df, seed=config.SEED)
    score_map: dict[str, np.ndarray] = dict(best_oof_mean)
    score_map.update(baseline_scores)
    arm_names = {**config.ARM_DISPLAY, **BASELINE_DISPLAY}

    meta_cols = [
        c for c in ("run_id", "technique_id", "variant", "artifact_type", "artifact_key", config.LABEL_COL, "rule_hit_count")
        if c in dev_df.columns
    ]
    oof_df = dev_df[meta_cols].copy()
    oof_df["y"] = y_dev
    for key, vec in score_map.items():
        oof_df[f"score_{key}"] = vec
    oof_df.to_parquet(out_tables_dir / "track_a_dev_oof_predictions.parquet", index=False)

    summary_rows: list[dict[str, Any]] = []
    for key, scores in score_map.items():
        rec = evaluate_score_vector(key, arm_names.get(key, key), dev_df, y_dev, scores, n_boot=n_boot)
        s_mean, s_std = best_seed_stats.get(key, (float(rec["pr_auc"]), 0.0))
        rec["cv_seed_pr_auc_mean"] = s_mean
        rec["cv_seed_pr_auc_std"] = s_std
        rec["params_json"] = json.dumps(best_params.get(key, {}), sort_keys=True)
        rec["commit"] = commit
        summary_rows.append(rec)
    pd.DataFrame(summary_rows).to_csv(out_tables_dir / "track_a_dev_summary.csv", index=False)

    by_type_df = evaluate_by_artifact_type(dev_df, y_dev, score_map, arm_names, n_boot=n_boot)
    by_type_df.to_csv(out_tables_dir / "track_a_dev_by_artifact_type.csv", index=False)

    paired_df = compute_paired_comparisons(
        dev_df, y_dev, score_map, arm_names, group_by="run_id", n_boot=n_boot, seed=config.BOOTSTRAP_SEED,
    )
    paired_df.to_csv(out_tables_dir / "track_a_dev_paired_bootstrap.csv", index=False)

    # Per-technique dev OOF breakdown against all dev benign rows
    dev_techniques = sorted(dev_df.loc[y_dev == 1, "technique_id"].astype(str).unique())
    ben_mask = y_dev == 0
    tech_rows: list[dict[str, Any]] = []
    for key, scores in score_map.items():
        for tid in dev_techniques:
            t_pos = (y_dev == 1) & (dev_df["technique_id"].astype(str).to_numpy() == tid)
            t_mask = ben_mask | t_pos
            tech_rows.append({
                "arm": key,
                "arm_name": arm_names.get(key, key),
                "technique_id": tid,
                "n_positives": int(t_pos.sum()),
                "pr_auc": M.pr_auc(y_dev[t_mask], scores[t_mask]),
                "roc_auc": M.roc_auc(y_dev[t_mask], scores[t_mask]),
                "precision_at_10": M.tie_expected_precision_at_k(y_dev[t_mask], scores[t_mask], 10),
                "recall_at_50": M.tie_expected_recall_at_k(y_dev[t_mask], scores[t_mask], 50),
                "commit": commit,
            })
    pd.DataFrame(tech_rows).to_csv(out_tables_dir / "track_a_dev_per_technique.csv", index=False)
    return trials_df, best_params


def _eval_feature_probes(
    probe_df: pd.DataFrame,
    y: np.ndarray,
    arm_key: str,
    probe_name: str,
    feat_cols: Sequence[str],
    scores: np.ndarray,
    n_boot: int,
    seed_mean: float,
    seed_std: float,
    commit: str,
) -> dict[str, Any]:
    rec = evaluate_score_vector(arm_key, config.ARM_DISPLAY.get(arm_key, arm_key), probe_df, y, scores, n_boot=n_boot)
    hn_pr, hn_drift_pr = float("nan"), float("nan")
    if "artifact_type" in probe_df.columns:
        at = probe_df["artifact_type"].astype(str)
        hn_mask = at.isin(HARD_NEG_ARTIFACT_TYPES).to_numpy()
        if hn_mask.any() and (y[hn_mask] == 1).any() and (y[hn_mask] == 0).any():
            hn_pr = M.pr_auc(y[hn_mask], scores[hn_mask])
        if config.LABEL_COL in probe_df.columns:
            hn_drift = hn_mask & (probe_df[config.LABEL_COL].astype(str) != "baseline").to_numpy()
            if hn_drift.any() and (y[hn_drift] == 1).any() and (y[hn_drift] == 0).any():
                hn_drift_pr = M.pr_auc(y[hn_drift], scores[hn_drift])
    rec["probe"] = probe_name
    rec["n_features"] = int(len(feat_cols))
    rec["features_json"] = json.dumps(list(feat_cols))
    rec["cv_seed_pr_auc_mean"] = seed_mean
    rec["cv_seed_pr_auc_std"] = seed_std
    rec["hard_neg_pr_auc"] = float(hn_pr)
    rec["hard_neg_drift_only_pr_auc"] = float(hn_drift_pr)
    rec["commit"] = commit
    return rec


def run_dev_probes(
    df: pd.DataFrame,
    best_params: dict[str, dict[str, Any]] | None = None,
    arms: Sequence[str] = config.ARMS,
    seeds: Sequence[int] = config.DEV_CV_SEEDS,
    n_splits: int = config.N_DEV_FOLDS,
    max_epochs_override: int | None = None,
    out_tables_dir: Path = config.TABLES_DIR,
    n_boot: int = config.N_BOOTSTRAP,
    probe_sets: dict[str, list[str]] | None = None,
) -> pd.DataFrame:
    """Feature-subset probe models trained & evaluated strictly via grouped CV on split_pool == 'dev'."""
    dev_df = df[df["split_pool"] == "dev"].reset_index(drop=True)
    y_dev = (dev_df[config.LABEL_COL] == config.POSITIVE_LABEL).astype(int).to_numpy()
    best_params = best_params or {}
    probe_sets = probe_sets or PROBE_FEATURE_SETS
    out_tables_dir = Path(out_tables_dir)
    out_tables_dir.mkdir(parents=True, exist_ok=True)
    commit = get_commit_hash()

    rows: list[dict[str, Any]] = []
    for probe_name, feat_cols in probe_sets.items():
        cat_cols, num_cols, bin_cols = _resolve_feature_lists(feat_cols, ())
        for arm_key in arms:
            seed_oof_list, seed_scores = _run_dev_oof(
                dev_df, y_dev, arm_key,
                cat_cols, num_cols, bin_cols, (),
                seeds=seeds, n_splits=n_splits,
                params=best_params.get(arm_key, {}),
                max_epochs_override=max_epochs_override,
            )
            oof_mean = np.mean(np.vstack(seed_oof_list), axis=0)
            rows.append(_eval_feature_probes(
                dev_df, y_dev, arm_key, probe_name, feat_cols, oof_mean,
                n_boot=n_boot,
                seed_mean=float(np.mean(seed_scores)),
                seed_std=float(np.std(seed_scores)),
                commit=commit,
            ))

    probe_df = pd.DataFrame(rows)
    probe_df.to_csv(out_tables_dir / "track_a_dev_probes.csv", index=False)
    return probe_df


def run_dev_ablations(
    df: pd.DataFrame,
    best_params: dict[str, dict[str, Any]] | None = None,
    arms: Sequence[str] = config.ARMS,
    seeds: Sequence[int] = config.DEV_CV_SEEDS,
    n_splits: int = config.N_DEV_FOLDS,
    max_epochs_override: int | None = None,
    out_tables_dir: Path = config.TABLES_DIR,
    n_boot: int = config.N_BOOTSTRAP,
) -> pd.DataFrame:
    """Dev-only OOF ablations (rule_hit_count, oracle upper bound, drop feature groups, unsup baseline scope)."""
    dev_df = df[df["split_pool"] == "dev"].reset_index(drop=True)
    y_dev = (dev_df[config.LABEL_COL] == config.POSITIVE_LABEL).astype(int).to_numpy()
    best_params = best_params or {}
    out_tables_dir = Path(out_tables_dir)
    out_tables_dir.mkdir(parents=True, exist_ok=True)
    commit = get_commit_hash()

    specs: list[tuple[str, str, Sequence[str] | None, Sequence[str], Sequence[str], bool]] = [
        ("primary_20", "standard", None, (), arms, False),
    ]
    if all(c in dev_df.columns for c in config.RULE_FEATURES):
        specs.append(("plus_rule_hit_count", "rule_ablation", None, config.RULE_FEATURES, arms, False))
    if all(c in dev_df.columns for c in config.ORACLE_FEATURES):
        specs.append(("oracle_upper_bound", "ORACLE UPPER BOUND, NOT A RESULT", None, config.ORACLE_FEATURES, arms, False))
    for grp_name, drop_cols in config.FEATURE_GROUPS.items():
        kept = [f for f in config.FEATURES if f not in set(drop_cols)]
        specs.append((f"drop_{grp_name}", "feature_group_ablation", kept, (), arms, False))
    unsup_arms = [a for a in arms if a in config.UNSUPERVISED_ARMS]
    if unsup_arms:
        specs.append(("unsup_baseline_only", "benign_scope_ablation", None, (), unsup_arms, True))
        specs.append(("unsup_baseline_plus_drift", "benign_scope_ablation", None, (), unsup_arms, False))

    rows: list[dict[str, Any]] = []
    for ab_name, tag, feat_ovr, extra_cols, target_arms, unsup_only in specs:
        cat_cols, num_cols, bin_cols = _resolve_feature_lists(feat_ovr, extra_cols)
        for arm_key in target_arms:
            seed_oof_list, seed_scores = _run_dev_oof(
                dev_df, y_dev, arm_key,
                cat_cols, num_cols, bin_cols, extra_cols,
                seeds=seeds, n_splits=n_splits,
                params=best_params.get(arm_key, {}),
                max_epochs_override=max_epochs_override,
                unsup_baseline_only=unsup_only,
            )
            oof_mean = np.mean(np.vstack(seed_oof_list), axis=0)
            rec = _eval_feature_probes(
                dev_df, y_dev, arm_key, ab_name,
                list(feat_ovr) if feat_ovr is not None else list(config.FEATURES) + list(extra_cols),
                oof_mean, n_boot=n_boot,
                seed_mean=float(np.mean(seed_scores)),
                seed_std=float(np.std(seed_scores)),
                commit=commit,
            )
            rec["ablation"] = ab_name
            rec["ablation_tag"] = tag
            rows.append(rec)

    ab_df = pd.DataFrame(rows)
    ab_df.to_csv(out_tables_dir / "track_a_dev_ablations.csv", index=False)
    return ab_df


def _append_audit(audit_path: Path, entry: dict[str, Any]) -> None:
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with open(audit_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")


def _eval_single_config_on_test(
    dev_df: pd.DataFrame,
    test_df: pd.DataFrame,
    y_dev: np.ndarray,
    y_test: np.ndarray,
    arms: Sequence[str],
    best_params: dict[str, dict[str, Any]],
    features_override: Sequence[str] | None,
    allowed_extra: Sequence[str],
    out_tables_dir: Path,
    models_dir: Path,
    actual_hash: str,
    commit: str,
    max_epochs_override: int | None = None,
    n_boot: int = config.N_BOOTSTRAP,
    run_probes: bool = True,
) -> dict[str, Any]:
    """Fit all arms for one feature configuration on dev_df and score frozen test_df."""
    out_tables_dir = Path(out_tables_dir)
    models_dir = Path(models_dir)
    out_tables_dir.mkdir(parents=True, exist_ok=True)
    models_dir.mkdir(parents=True, exist_ok=True)

    cat_cols, num_cols, bin_cols = _resolve_feature_lists(features_override, allowed_extra)
    set_global_seed(config.SEED)

    test_meta_cols = [
        c for c in (
            "run_id", "technique_id", "variant", "artifact_type", "artifact_key",
            "name", "path", "command_line", "registry_key", "registry_value",
            "signature_status", "attributes", "file_sha256", "record_sha256",
            config.LABEL_COL, "rule_hit_count",
        )
        if c in test_df.columns
    ]
    preds_df = test_df[test_meta_cols].copy()
    preds_df["y"] = y_test

    t1_rows: list[dict[str, Any]] = []
    t5_rows: list[dict[str, Any]] = []
    pr_rows: list[dict[str, Any]] = []
    score_map: dict[str, np.ndarray] = {}

    ben_mask = y_test == 0
    test_techniques = sorted(test_df.loc[y_test == 1, "technique_id"].astype(str).unique())

    for arm_key in arms:
        p_cfg = best_params.get(arm_key, {})
        t0 = time.perf_counter()
        arm, pre = _fit_arm_on_split(
            arm_key, dev_df, y_dev, None, None,
            cat_cols, num_cols, bin_cols, allowed_extra,
            seed=config.SEED, params=p_cfg, max_epochs_override=max_epochs_override,
            inner_val_seed=config.SEED,
        )
        train_time_s = time.perf_counter() - t0

        X_te = pre.transform(test_df)
        t1 = time.perf_counter()
        scores = arm.predict_scores(X_te)
        infer_per_1k = ((time.perf_counter() - t1) / max(1, len(test_df))) * 1000.0
        preds_df[f"score_{arm_key}"] = scores
        score_map[arm_key] = scores

        arm.save(models_dir / f"track_a_final_{arm_key}.bin")
        joblib.dump(pre, models_dir / f"track_a_final_{arm_key}_pre.joblib")

        row_t1 = evaluate_score_vector(arm_key, config.ARM_DISPLAY[arm_key], test_df, y_test, scores, n_boot=n_boot)
        if row_t1["pr_auc"] > 0.98:
            print(f"[WARNING] Track A arm {arm_key} reached PR-AUC={row_t1['pr_auc']:.4f} (> 0.98); inspect for leakage!")
        row_t1.update({
            "train_time_s": float(train_time_s),
            "infer_time_per_1k_s": float(infer_per_1k),
            "n_dev": int(len(dev_df)),
            "n_test": int(len(test_df)),
            "n_test_pos": int(y_test.sum()),
            "test_sha256": actual_hash,
            "seed": config.SEED,
            "bootstrap_seed": config.BOOTSTRAP_SEED,
            "commit": commit,
        })
        t1_rows.append(row_t1)

        for tid in test_techniques:
            t_pos = (y_test == 1) & (test_df["technique_id"].astype(str).to_numpy() == tid)
            t_mask = ben_mask | t_pos
            t5_rows.append({
                "arm": arm_key,
                "arm_name": config.ARM_DISPLAY[arm_key],
                "technique_id": tid,
                "n_positives": int(t_pos.sum()),
                "pr_auc": M.pr_auc(y_test[t_mask], scores[t_mask]),
                "roc_auc": M.roc_auc(y_test[t_mask], scores[t_mask]),
                "precision_at_10": M.tie_expected_precision_at_k(y_test[t_mask], scores[t_mask], 10),
                "recall_at_50": M.tie_expected_recall_at_k(y_test[t_mask], scores[t_mask], 50),
                "commit": commit,
            })

        prec, rec, _ = precision_recall_curve(y_test, scores)
        if len(prec) > 200:
            idx = np.linspace(0, len(prec) - 1, 200, dtype=int)
            prec, rec = prec[idx], rec[idx]
        for p_v, r_v in zip(prec, rec):
            pr_rows.append({"arm": arm_key, "arm_name": config.ARM_DISPLAY[arm_key],
                            "recall": float(r_v), "precision": float(p_v)})

    baseline_scores = compute_baseline_scores(test_df, seed=config.SEED)
    for b_key, b_scores in baseline_scores.items():
        preds_df[f"score_{b_key}"] = b_scores
        score_map[b_key] = b_scores

    arm_names = {**config.ARM_DISPLAY, **BASELINE_DISPLAY}
    baseline_rows = []
    for b_key, b_scores in baseline_scores.items():
        rec = evaluate_score_vector(b_key, BASELINE_DISPLAY[b_key], test_df, y_test, b_scores, n_boot=n_boot)
        rec.update({
            "n_dev": int(len(dev_df)),
            "n_test": int(len(test_df)),
            "n_test_pos": int(y_test.sum()),
            "test_sha256": actual_hash,
            "seed": config.SEED,
            "bootstrap_seed": config.BOOTSTRAP_SEED,
            "commit": commit,
        })
        baseline_rows.append(rec)

    t1_df = pd.DataFrame(t1_rows)
    t5_df = pd.DataFrame(t5_rows)
    pr_df = pd.DataFrame(pr_rows)
    baselines_df = pd.DataFrame(baseline_rows)
    by_type_df = evaluate_by_artifact_type(test_df, y_test, score_map, arm_names, n_boot=n_boot)
    paired_df = compute_paired_comparisons(
        test_df, y_test, score_map, arm_names, group_by="run_id", n_boot=n_boot, seed=config.BOOTSTRAP_SEED,
    )

    if run_probes:
        probe_rows: list[dict[str, Any]] = []
        for probe_name, feat_cols in PROBE_FEATURE_SETS.items():
            p_cat, p_num, p_bin = _resolve_feature_lists(feat_cols, ())
            for arm_key in arms:
                arm_p, pre_p = _fit_arm_on_split(
                    arm_key, dev_df, y_dev, None, None,
                    p_cat, p_num, p_bin, (),
                    seed=config.SEED, params=best_params.get(arm_key, {}),
                    max_epochs_override=max_epochs_override, inner_val_seed=config.SEED,
                )
                p_scores = arm_p.predict_scores(pre_p.transform(test_df))
                probe_rows.append(_eval_feature_probes(
                    test_df, y_test, arm_key, probe_name, feat_cols, p_scores,
                    n_boot=n_boot, seed_mean=float("nan"), seed_std=float("nan"), commit=commit,
                ))
        probes_df = pd.DataFrame(probe_rows)
        probes_df.to_csv(out_tables_dir / "track_a_test_probes.csv", index=False)
    else:
        probes_df = pd.DataFrame()

    t1_df.to_csv(out_tables_dir / "track_a_test_results.csv", index=False)
    t5_df.to_csv(out_tables_dir / "track_a_per_technique.csv", index=False)
    pr_df.to_csv(out_tables_dir / "track_a_pr_curves.csv", index=False)
    baselines_df.to_csv(out_tables_dir / "track_a_test_baselines.csv", index=False)
    by_type_df.to_csv(out_tables_dir / "track_a_test_by_artifact_type.csv", index=False)
    paired_df.to_csv(out_tables_dir / "track_a_test_paired_bootstrap.csv", index=False)
    preds_df.to_parquet(out_tables_dir / "track_a_test_predictions.parquet", index=False)

    return {
        "t1": t1_df,
        "t5": t5_df,
        "pr_curves": pr_df,
        "predictions": preds_df,
        "baselines": baselines_df,
        "by_artifact_type": by_type_df,
        "paired_bootstrap": paired_df,
        "probes": probes_df,
        "score_map": score_map,
    }


def run_final_eval(
    df: pd.DataFrame,
    manifest: dict[str, Any],
    best_params: dict[str, dict[str, Any]] | None = None,
    arms: Sequence[str] = config.ARMS,
    force: bool = False,
    out_tables_dir: Path = config.TABLES_DIR,
    models_dir: Path = config.MODELS_DIR,
    logs_dir: Path = config.LOGS_DIR,
    allowed_extra: Sequence[str] = (),
    features_override: Sequence[str] | None = None,
    max_epochs_override: int | None = None,
    n_boot: int = config.N_BOOTSTRAP,
    secondary_configs: dict[str, Sequence[str]] | None = None,
    secondary_best_params: dict[str, dict[str, dict[str, Any]]] | None = None,
) -> dict[str, Any]:
    """Refit on ALL dev data with chosen params and evaluate ONCE on the frozen test set."""
    out_tables_dir = Path(out_tables_dir)
    models_dir = Path(models_dir)
    logs_dir = Path(logs_dir)
    out_tables_dir.mkdir(parents=True, exist_ok=True)
    models_dir.mkdir(parents=True, exist_ok=True)
    audit_path = logs_dir / "final_eval_audit.jsonl"
    commit = get_commit_hash()

    # Verify frozen test-set hash before evaluating
    actual_hash = labeler.compute_frozen_test_hash(df)
    expected_hash = manifest.get("test_sha256")
    if expected_hash and actual_hash != expected_hash:
        raise AssertionError(
            f"Frozen test-set hash mismatch! expected={expected_hash}, actual={actual_hash}"
        )

    prior_executed = False
    if audit_path.exists():
        for line in audit_path.read_text(encoding="utf-8").splitlines():
            if line.strip() and json.loads(line).get("status") == "executed":
                prior_executed = True
                break

    if prior_executed and not force:
        _append_audit(audit_path, {
            "timestamp_utc": utc_now_iso(),
            "commit": commit,
            "status": "refused_duplicate_final",
            "test_sha256": actual_hash,
        })
        raise RuntimeError(
            "Final evaluation has already run on this frozen test set (audit guard). "
            "Pass --force to run again."
        )

    dev_df = df[df["split_pool"] == "dev"].reset_index(drop=True)
    test_df = df[df["split_pool"] == "test"].reset_index(drop=True)
    y_dev = (dev_df[config.LABEL_COL] == config.POSITIVE_LABEL).astype(int).to_numpy()
    y_test = (test_df[config.LABEL_COL] == config.POSITIVE_LABEL).astype(int).to_numpy()
    best_params = best_params or {}

    primary = _eval_single_config_on_test(
        dev_df, test_df, y_dev, y_test, arms, best_params,
        features_override, allowed_extra, out_tables_dir, models_dir,
        actual_hash, commit, max_epochs_override=max_epochs_override, n_boot=n_boot, run_probes=True,
    )

    sec_out: dict[str, dict[str, Any]] = {}
    evaluated_configs = ["full_20" if features_override is None else "primary"]
    if secondary_configs:
        sec_params_map = secondary_best_params or {}
        arm_names = {**config.ARM_DISPLAY, **BASELINE_DISPLAY}
        for cfg_name, cfg_feats in secondary_configs.items():
            cfg_params = sec_params_map.get(cfg_name, best_params)
            res_s = _eval_single_config_on_test(
                dev_df, test_df, y_dev, y_test, arms, cfg_params,
                cfg_feats, (), out_tables_dir / cfg_name, models_dir / cfg_name,
                actual_hash, commit, max_epochs_override=max_epochs_override, n_boot=n_boot, run_probes=False,
            )
            sec_out[cfg_name] = res_s
            evaluated_configs.append(cfg_name)

        if "no_content" in sec_out:
            # Ensure paired comparisons include the union of best-vs-rules pairs across both configs
            union_pairs = list(dict.fromkeys(
                _default_paired_pairs(primary["score_map"], y_test)
                + _default_paired_pairs(sec_out["no_content"]["score_map"], y_test)
            ))
            pf = compute_paired_comparisons(
                test_df, y_test, primary["score_map"], arm_names, pairs=union_pairs,
                group_by="run_id", n_boot=n_boot, seed=config.BOOTSTRAP_SEED,
            )
            pnc = compute_paired_comparisons(
                test_df, y_test, sec_out["no_content"]["score_map"], arm_names, pairs=union_pairs,
                group_by="run_id", n_boot=n_boot, seed=config.BOOTSTRAP_SEED,
            )
            pf.to_csv(out_tables_dir / "track_a_test_paired_bootstrap.csv", index=False)
            pnc.to_csv(out_tables_dir / "no_content" / "track_a_test_paired_bootstrap.csv", index=False)
            primary["paired_bootstrap"] = pf
            sec_out["no_content"]["paired_bootstrap"] = pnc
            dual_df = combine_dual_config_verdicts(pf, pnc)
            dual_df.to_csv(out_tables_dir / "track_a_test_dual_config_verdict.csv", index=False)
            primary["dual_config_verdict"] = dual_df

    primary.pop("score_map", None)
    for v in sec_out.values():
        v.pop("score_map", None)
    if sec_out:
        primary["secondary"] = sec_out

    _append_audit(audit_path, {
        "timestamp_utc": utc_now_iso(),
        "commit": commit,
        "status": "executed",
        "forced": bool(force and prior_executed),
        "arms": list(arms),
        "configs": evaluated_configs,
        "test_sha256": actual_hash,
    })
    write_json(run_metadata({
        "track": "A_final",
        "arms": list(arms),
        "configs": evaluated_configs,
        "test_sha256": actual_hash,
        "forced": bool(force),
        "best_params": best_params,
        "secondary_best_params": secondary_best_params or {},
    }), logs_dir / "track_a_final_meta.json")

    return primary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Track A grouped CV & frozen-test evaluation.")
    parser.add_argument("--dataset", type=Path, default=config.PROCESSED_DIR / "dataset_v1.parquet")
    parser.add_argument("--manifest", type=Path, default=config.SPLITS_DIR / "dataset_v1_manifest.json")
    parser.add_argument("--dev", action="store_true", help="Run dev grouped CV random search.")
    parser.add_argument("--final", action="store_true", help="Run one-time frozen test evaluation.")
    parser.add_argument("--force", action="store_true", help="Allow re-running --final (logged to audit).")
    parser.add_argument("--dual-config", action="store_true", help="Evaluate both full_20 and no_content configurations.")
    parser.add_argument("--n-trials", type=int, default=config.MAX_SEARCH_TRIALS)
    parser.add_argument("--arms", nargs="+", default=list(config.ARMS), choices=config.ARMS + config.OPTIONAL_ARMS)
    parser.add_argument("--include-lr", action="store_true")
    parser.add_argument("--skip-probes", action="store_true")
    parser.add_argument("--skip-dev-ablations", action="store_true")
    args = parser.parse_args(argv)

    df = pd.read_parquet(args.dataset)
    arms = list(args.arms) + (["lr"] if args.include_lr and "lr" not in args.arms else [])

    if not args.dev and not args.final:
        args.dev = True

    best_params: dict[str, dict[str, Any]] = {}
    secondary_best: dict[str, dict[str, dict[str, Any]]] = {}
    if args.dev:
        _, best_params = run_dev_cv(df, arms=arms, n_trials=args.n_trials)
        if not args.skip_probes:
            run_dev_probes(df, best_params=best_params, arms=arms)
        if not args.skip_dev_ablations:
            run_dev_ablations(df, best_params=best_params, arms=arms)
        if args.dual_config:
            _, nc_best = run_dev_cv(
                df,
                arms=arms,
                n_trials=args.n_trials,
                features_override=NO_CONTENT_FEATURES,
                out_tables_dir=config.TABLES_DIR / "no_content",
            )
            secondary_best["no_content"] = nc_best
            oof_f = pd.read_parquet(config.TABLES_DIR / "track_a_dev_oof_predictions.parquet")
            oof_n = pd.read_parquet(config.TABLES_DIR / "no_content" / "track_a_dev_oof_predictions.parquet")
            y_dev_oof = oof_f["y"].to_numpy()
            s_f = {c[len("score_"):]: oof_f[c].to_numpy() for c in oof_f.columns if c.startswith("score_")}
            s_n = {c[len("score_"):]: oof_n[c].to_numpy() for c in oof_n.columns if c.startswith("score_")}
            union_pairs = list(dict.fromkeys(
                _default_paired_pairs(s_f, y_dev_oof) + _default_paired_pairs(s_n, y_dev_oof)
            ))
            arm_names = {**config.ARM_DISPLAY, **BASELINE_DISPLAY}
            pf = compute_paired_comparisons(oof_f, y_dev_oof, s_f, arm_names, pairs=union_pairs)
            pn = compute_paired_comparisons(oof_n, y_dev_oof, s_n, arm_names, pairs=union_pairs)
            pf.to_csv(config.TABLES_DIR / "track_a_dev_paired_bootstrap.csv", index=False)
            pn.to_csv(config.TABLES_DIR / "no_content" / "track_a_dev_paired_bootstrap.csv", index=False)
            combine_dual_config_verdicts(pf, pn).to_csv(
                config.TABLES_DIR / "track_a_dev_dual_config_verdict.csv", index=False
            )
    else:
        if (config.TABLES_DIR / "track_a_best_params.json").exists():
            best_params = json.loads((config.TABLES_DIR / "track_a_best_params.json").read_text(encoding="utf-8"))
        if args.dual_config and (config.TABLES_DIR / "no_content" / "track_a_best_params.json").exists():
            secondary_best["no_content"] = json.loads(
                (config.TABLES_DIR / "no_content" / "track_a_best_params.json").read_text(encoding="utf-8")
            )

    if args.final:
        manifest = json.loads(args.manifest.read_text(encoding="utf-8")) if args.manifest.exists() else {}
        sec_cfgs = {"no_content": NO_CONTENT_FEATURES} if args.dual_config else None
        run_final_eval(
            df,
            manifest,
            best_params=best_params,
            arms=arms,
            force=args.force,
            secondary_configs=sec_cfgs,
            secondary_best_params=secondary_best if sec_cfgs else None,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
