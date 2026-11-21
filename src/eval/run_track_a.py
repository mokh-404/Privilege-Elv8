"""Track A five-arm evaluation: grouped dev CV, hyperparameter search, and one-time final eval.

Rules (doc 07 & doc 10 section 3):
  - X uses config.FEATURES only (ORACLE_FEATURES, RULE_FEATURES, META_COLUMNS, LABEL_COL excluded).
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
    num_cols = [c for c in config.NUMERIC_FEATURES if c in base] + [c for c in allowed_extra if c not in config.CATEGORICAL_FEATURES + config.BINARY_FEATURES]
    bin_cols = [c for c in config.BINARY_FEATURES if c in base]
    return cat_cols, num_cols, bin_cols


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
) -> tuple[pd.DataFrame, dict[str, dict[str, Any]]]:
    """Repeated grouped CV random search on the development split ONLY."""
    dev_df = df[df["split_pool"] == "dev"].reset_index(drop=True)
    y_dev = (dev_df[config.LABEL_COL] == config.POSITIVE_LABEL).astype(int).to_numpy()
    cat_cols, num_cols, bin_cols = _resolve_feature_lists(features_override, allowed_extra)
    out_tables_dir = Path(out_tables_dir)
    out_tables_dir.mkdir(parents=True, exist_ok=True)
    commit = get_commit_hash()

    trial_rows: list[dict[str, Any]] = []
    best_params: dict[str, dict[str, Any]] = {}

    for arm_key in arms:
        param_cands = _sample_param_configs(arm_key, n_trials=n_trials, seed=config.SEED)
        best_score = -float("inf")
        best_cfg = param_cands[0]

        for t_idx, p_cfg in enumerate(param_cands):
            seed_scores = []
            for cv_seed in seeds:
                folds = make_dev_folds(dev_df, n_splits=n_splits, seed=cv_seed)
                oof_scores = np.zeros(len(dev_df), dtype=float)
                seen_val = np.zeros(len(dev_df), dtype=bool)
                for tr_idx, va_idx in folds:
                    arm, pre = _fit_arm_on_split(
                        arm_key,
                        dev_df.iloc[tr_idx], y_dev[tr_idx],
                        dev_df.iloc[va_idx], y_dev[va_idx],
                        cat_cols, num_cols, bin_cols, allowed_extra,
                        seed=cv_seed, params=p_cfg, max_epochs_override=max_epochs_override,
                        inner_val_seed=cv_seed,
                    )
                    oof_scores[va_idx] = arm.predict_scores(pre.transform(dev_df.iloc[va_idx]))
                    seen_val[va_idx] = True
                assert seen_val.all()
                seed_scores.append(M.pr_auc(y_dev, oof_scores))

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
        best_params[arm_key] = dict(best_cfg)

    trials_df = pd.DataFrame(trial_rows)
    trials_df.to_csv(out_tables_dir / "track_a_dev_trials.csv", index=False)
    write_json(best_params, out_tables_dir / "track_a_best_params.json")
    return trials_df, best_params


def _append_audit(audit_path: Path, entry: dict[str, Any]) -> None:
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    with open(audit_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")


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
) -> dict[str, pd.DataFrame]:
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
    cat_cols, num_cols, bin_cols = _resolve_feature_lists(features_override, allowed_extra)
    best_params = best_params or {}

    set_global_seed(config.SEED)
    test_meta_cols = [c for c in ("run_id", "technique_id", "variant", "artifact_key", config.LABEL_COL) if c in test_df.columns]
    preds_df = test_df[test_meta_cols].copy()
    preds_df["y"] = y_test

    t1_rows: list[dict[str, Any]] = []
    t5_rows: list[dict[str, Any]] = []
    pr_rows: list[dict[str, Any]] = []

    clean_baseline_mask = (test_df[config.LABEL_COL] == "baseline").to_numpy()
    run_groups = test_df["run_id"].astype(str).to_numpy()
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

        arm.save(models_dir / f"track_a_final_{arm_key}.bin")
        joblib.dump(pre, models_dir / f"track_a_final_{arm_key}_pre.joblib")

        pr = M.pr_auc(y_test, scores)
        if pr > 0.98:
            print(f"[WARNING] Track A arm {arm_key} reached PR-AUC={pr:.4f} (> 0.98); inspect for leakage!")

        boot = M.bootstrap_by_group(M.pr_auc, y_test, scores, run_groups, n_boot=n_boot, seed=config.BOOTSTRAP_SEED)
        row_t1 = {
            "arm": arm_key,
            "arm_name": config.ARM_DISPLAY[arm_key],
            "pr_auc": pr,
            "pr_auc_ci_lo": boot["lo"],
            "pr_auc_ci_hi": boot["hi"],
            "roc_auc": M.roc_auc(y_test, scores),
            "fpr_at_recall_0.9_all_benign": M.fpr_at_recall(y_test, scores, config.FIXED_RECALL),
            "fpr_at_recall_0.9_clean_baseline": M.fpr_at_recall(y_test, scores, config.FIXED_RECALL, negative_mask=clean_baseline_mask),
            "train_time_s": float(train_time_s),
            "infer_time_per_1k_s": float(infer_per_1k),
            "n_dev": int(len(dev_df)),
            "n_test": int(len(test_df)),
            "n_test_pos": int(y_test.sum()),
            "test_sha256": actual_hash,
            "seed": config.SEED,
            "bootstrap_seed": config.BOOTSTRAP_SEED,
            "commit": commit,
        }
        for k in config.K_VALUES:
            row_t1[f"precision_at_{k}"] = M.precision_at_k(y_test, scores, k)
            row_t1[f"recall_at_{k}"] = M.recall_at_k(y_test, scores, k)
        t1_rows.append(row_t1)

        # T5: per-technique performance against all test benign rows
        ben_mask = y_test == 0
        for tid in test_techniques:
            t_mask = ben_mask | ((y_test == 1) & (test_df["technique_id"].astype(str).to_numpy() == tid))
            t5_rows.append({
                "arm": arm_key,
                "arm_name": config.ARM_DISPLAY[arm_key],
                "technique_id": tid,
                "n_positives": int(((y_test == 1) & (test_df["technique_id"].astype(str).to_numpy() == tid)).sum()),
                "pr_auc": M.pr_auc(y_test[t_mask], scores[t_mask]),
                "roc_auc": M.roc_auc(y_test[t_mask], scores[t_mask]),
                "precision_at_10": M.precision_at_k(y_test[t_mask], scores[t_mask], 10),
                "recall_at_50": M.recall_at_k(y_test[t_mask], scores[t_mask], 50),
                "commit": commit,
            })

        # PR curve points (subsampled cleanly to <= 200 points)
        prec, rec, _ = precision_recall_curve(y_test, scores)
        if len(prec) > 200:
            idx = np.linspace(0, len(prec) - 1, 200, dtype=int)
            prec, rec = prec[idx], rec[idx]
        for p_v, r_v in zip(prec, rec):
            pr_rows.append({"arm": arm_key, "arm_name": config.ARM_DISPLAY[arm_key],
                            "recall": float(r_v), "precision": float(p_v)})

    t1_df = pd.DataFrame(t1_rows)
    t5_df = pd.DataFrame(t5_rows)
    pr_df = pd.DataFrame(pr_rows)

    t1_df.to_csv(out_tables_dir / "track_a_test_results.csv", index=False)
    t5_df.to_csv(out_tables_dir / "track_a_per_technique.csv", index=False)
    pr_df.to_csv(out_tables_dir / "track_a_pr_curves.csv", index=False)
    preds_df.to_parquet(out_tables_dir / "track_a_test_predictions.parquet", index=False)

    _append_audit(audit_path, {
        "timestamp_utc": utc_now_iso(),
        "commit": commit,
        "status": "executed",
        "forced": bool(force and prior_executed),
        "arms": list(arms),
        "test_sha256": actual_hash,
    })
    write_json(run_metadata({
        "track": "A_final",
        "arms": list(arms),
        "test_sha256": actual_hash,
        "forced": bool(force),
        "best_params": best_params,
    }), logs_dir / "track_a_final_meta.json")

    return {"t1": t1_df, "t5": t5_df, "pr_curves": pr_df, "predictions": preds_df}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Track A grouped CV & frozen-test evaluation.")
    parser.add_argument("--dataset", type=Path, default=config.PROCESSED_DIR / "dataset_v1.parquet")
    parser.add_argument("--manifest", type=Path, default=config.SPLITS_DIR / "dataset_v1_manifest.json")
    parser.add_argument("--dev", action="store_true", help="Run dev grouped CV random search.")
    parser.add_argument("--final", action="store_true", help="Run one-time frozen test evaluation.")
    parser.add_argument("--force", action="store_true", help="Allow re-running --final (logged to audit).")
    parser.add_argument("--n-trials", type=int, default=config.MAX_SEARCH_TRIALS)
    parser.add_argument("--arms", nargs="+", default=list(config.ARMS), choices=config.ARMS + config.OPTIONAL_ARMS)
    parser.add_argument("--include-lr", action="store_true")
    args = parser.parse_args(argv)

    df = pd.read_parquet(args.dataset)
    manifest = json.loads(args.manifest.read_text(encoding="utf-8")) if args.manifest.exists() else {}
    arms = list(args.arms) + (["lr"] if args.include_lr and "lr" not in args.arms else [])

    if not args.dev and not args.final:
        args.dev = True

    best_params: dict[str, dict[str, Any]] = {}
    if args.dev:
        _, best_params = run_dev_cv(df, arms=arms, n_trials=args.n_trials)
    elif (config.TABLES_DIR / "track_a_best_params.json").exists():
        best_params = json.loads((config.TABLES_DIR / "track_a_best_params.json").read_text(encoding="utf-8"))

    if args.final:
        run_final_eval(df, manifest, best_params=best_params, arms=arms, force=args.force)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
