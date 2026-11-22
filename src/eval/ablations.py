"""Track A ablations (doc 07 section 6 & Prompt C).

Ablations:
  1. primary_20                (baseline 20-feature benchmark reference)
  2. plus_rule_hit_count       (adds RULE_FEATURES)
  3. oracle_upper_bound        (adds ORACLE_FEATURES; tagged "ORACLE UPPER BOUND, NOT A RESULT")
  4. drop_<group>              (drops path, cmdline, signature, or registry group)
  5. unsup_baseline_only       vs unsup_baseline_plus_drift (unsupervised arms)
  6. train_fraction            (25%, 50%, 100% of dev data, grouped by technique + benign keys)
"""
from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any, Sequence

import numpy as np
import pandas as pd

from src import config
from src.eval import metrics as M
from src.eval.run_track_a import _fit_arm_on_split, _resolve_feature_lists
from src.utils.repro import get_commit_hash, set_global_seed


ORACLE_TAG = "ORACLE UPPER BOUND, NOT A RESULT"


def _eval_ablation_case(
    name: str,
    tag: str,
    dev_df: pd.DataFrame,
    test_df: pd.DataFrame,
    arms: Sequence[str],
    features_override: Sequence[str] | None = None,
    allowed_extra: Sequence[str] = (),
    best_params: dict[str, dict[str, Any]] | None = None,
    max_epochs_override: int | None = None,
    unsup_baseline_only: bool = False,
) -> list[dict[str, Any]]:
    y_dev = (dev_df[config.LABEL_COL] == config.POSITIVE_LABEL).astype(int).to_numpy()
    y_test = (test_df[config.LABEL_COL] == config.POSITIVE_LABEL).astype(int).to_numpy()
    cat_cols, num_cols, bin_cols = _resolve_feature_lists(features_override, allowed_extra)
    best_params = best_params or {}
    commit = get_commit_hash()
    rows = []

    for arm_key in arms:
        use_dev = dev_df
        use_y = y_dev
        if unsup_baseline_only and arm_key in config.UNSUPERVISED_ARMS:
            mask = dev_df[config.LABEL_COL] == "baseline"
            if mask.any():
                use_dev = dev_df[mask].reset_index(drop=True)
                use_y = np.zeros(len(use_dev), dtype=int)

        arm, pre = _fit_arm_on_split(
            arm_key, use_dev, use_y, None, None,
            cat_cols, num_cols, bin_cols, allowed_extra,
            seed=config.SEED, params=best_params.get(arm_key, {}),
            max_epochs_override=max_epochs_override, inner_val_seed=config.SEED,
        )
        scores = arm.predict_scores(pre.transform(test_df))
        rows.append({
            "ablation": name,
            "ablation_tag": tag,
            "arm": arm_key,
            "arm_name": config.ARM_DISPLAY[arm_key],
            "pr_auc": M.pr_auc(y_test, scores),
            "roc_auc": M.roc_auc(y_test, scores),
            "precision_at_10": M.precision_at_k(y_test, scores, 10),
            "precision_at_50": M.precision_at_k(y_test, scores, 50),
            "n_dev_rows": int(len(use_dev)),
            "seed": config.SEED,
            "commit": commit,
        })
    return rows


def _grouped_subsample_dev(dev_df: pd.DataFrame, frac: float, seed: int = config.SEED) -> pd.DataFrame:
    if frac >= 0.999:
        return dev_df.reset_index(drop=True)
    rng = np.random.default_rng(seed)
    pos = dev_df[dev_df[config.LABEL_COL] == config.POSITIVE_LABEL]
    ben = dev_df[dev_df[config.LABEL_COL] != config.POSITIVE_LABEL]

    techs = sorted(pos["technique_id"].astype(str).unique())
    n_t = max(2, int(round(frac * len(techs))))
    keep_techs = set(rng.choice(techs, size=min(len(techs), n_t), replace=False))
    sub_pos = pos[pos["technique_id"].astype(str).isin(keep_techs)]

    n_b = max(4, int(round(frac * len(ben))))
    keep_b_idx = rng.choice(ben.index.to_numpy(), size=min(len(ben), n_b), replace=False)
    sub_ben = ben.loc[np.sort(keep_b_idx)]
    return pd.concat([sub_pos, sub_ben], ignore_index=True)


def run_all_ablations(
    df: pd.DataFrame,
    arms: Sequence[str] = config.ARMS,
    best_params: dict[str, dict[str, Any]] | None = None,
    fractions: Sequence[float] = (0.25, 0.50, 1.00),
    out_tables_dir: Path = config.TABLES_DIR,
    max_epochs_override: int | None = None,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Run all Track A ablations and training-fraction curves; save CSVs and return them."""
    set_global_seed(config.SEED)
    out_tables_dir = Path(out_tables_dir)
    out_tables_dir.mkdir(parents=True, exist_ok=True)
    dev_df = df[df["split_pool"] == "dev"].reset_index(drop=True)
    test_df = df[df["split_pool"] == "test"].reset_index(drop=True)

    ab_rows: list[dict[str, Any]] = []
    ab_rows.extend(_eval_ablation_case(
        "primary_20", "standard", dev_df, test_df, arms,
        best_params=best_params, max_epochs_override=max_epochs_override,
    ))
    if all(c in df.columns for c in config.RULE_FEATURES):
        ab_rows.extend(_eval_ablation_case(
            "plus_rule_hit_count", "rule_ablation", dev_df, test_df, arms,
            allowed_extra=config.RULE_FEATURES, best_params=best_params,
            max_epochs_override=max_epochs_override,
        ))
    if all(c in df.columns for c in config.ORACLE_FEATURES):
        ab_rows.extend(_eval_ablation_case(
            "oracle_upper_bound", ORACLE_TAG, dev_df, test_df, arms,
            allowed_extra=config.ORACLE_FEATURES, best_params=best_params,
            max_epochs_override=max_epochs_override,
        ))
    for grp_name, drop_cols in config.FEATURE_GROUPS.items():
        kept = [f for f in config.FEATURES if f not in set(drop_cols)]
        specs = kept
        ab_rows.extend(_eval_ablation_case(
            f"drop_{grp_name}", "feature_group_ablation", dev_df, test_df, arms,
            features_override=specs, best_params=best_params,
            max_epochs_override=max_epochs_override,
        ))
    no_content_cols = [f for f in config.FEATURES if f not in ("file_size_log", "file_entropy")]
    ab_rows.extend(_eval_ablation_case(
        "no_content", "feature_group_ablation", dev_df, test_df, arms,
        features_override=no_content_cols, best_params=best_params,
        max_epochs_override=max_epochs_override,
    ))

    unsup_present = [a for a in arms if a in config.UNSUPERVISED_ARMS]
    if unsup_present:
        ab_rows.extend(_eval_ablation_case(
            "unsup_baseline_only", "benign_scope_ablation", dev_df, test_df, unsup_present,
            best_params=best_params, max_epochs_override=max_epochs_override,
            unsup_baseline_only=True,
        ))
        ab_rows.extend(_eval_ablation_case(
            "unsup_baseline_plus_drift", "benign_scope_ablation", dev_df, test_df, unsup_present,
            best_params=best_params, max_epochs_override=max_epochs_override,
            unsup_baseline_only=False,
        ))

    ab_df = pd.DataFrame(ab_rows)
    ab_df.to_csv(out_tables_dir / "track_a_ablations.csv", index=False)

    # Training-fraction curve
    frac_rows: list[dict[str, Any]] = []
    for frac in fractions:
        sub_dev = _grouped_subsample_dev(dev_df, frac=frac, seed=config.SEED)
        for rec in _eval_ablation_case(
            f"frac_{frac:.2f}", "train_fraction", sub_dev, test_df, arms,
            best_params=best_params, max_epochs_override=max_epochs_override,
        ):
            rec["train_fraction"] = float(frac)
            frac_rows.append(rec)

    frac_df = pd.DataFrame(frac_rows)
    frac_df.to_csv(out_tables_dir / "track_a_train_size.csv", index=False)
    return ab_df, frac_df


def main(argv: list[str] | None = None) -> int:
    import json
    parser = argparse.ArgumentParser(description="Run Track A ablations and training-size curves.")
    parser.add_argument("--dataset", type=Path, default=config.PROCESSED_DIR / "dataset_v1.parquet")
    parser.add_argument("--out-dir", type=Path, default=config.TABLES_DIR)
    parser.add_argument("--best-params", type=Path, default=config.TABLES_DIR / "track_a_best_params.json")
    parser.add_argument("--arms", nargs="+", default=list(config.ARMS), choices=config.ARMS + config.OPTIONAL_ARMS)
    args = parser.parse_args(argv)

    df = pd.read_parquet(args.dataset)
    best_params = json.loads(args.best_params.read_text(encoding="utf-8")) if args.best_params and args.best_params.exists() else None
    run_all_ablations(df, arms=args.arms, best_params=best_params, out_tables_dir=args.out_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
