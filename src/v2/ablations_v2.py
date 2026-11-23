"""Dev-only, config-matched feature ablations for Phase v2 (`IMP-14`, `OD-V2-14`, `OD-V2-15`).

Enforces two hard invariants:
1. **Dev-Only Guard (`assert_dev_only_ablation_guard`)**: Refuses any DataFrame containing rows with
   `split_pool != "dev"` unless `allow_final_audit=True` AND an explicit `audit_log_path` is supplied.
   Blind-test rows must never be touched during development ablation sweeps.
2. **Config-Matched Hyperparameter Search**: Each feature configuration (`full_20`, `no_content`,
   `drop_signature`, `no_content_no_sig`, `drop_path`, `drop_cmdline`, `drop_signature_group`,
   `drop_registry`, `unsup_baseline_only`) tunes its own hyperparameters independently via nested
   family-grouped CV rather than reusing `full_20` `--best-params`.
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Sequence

import numpy as np
import pandas as pd

from src import config
from src.eval.metrics import pr_auc, roc_auc
from src.v2 import config_v2
from src.v2.stats_v2 import tail_risk_and_effort_metrics
from src.v2.training import (
    _make_grouped_folds,
    build_family_cluster_groups,
    fit_arm_v2,
    run_nested_family_cv,
    sample_param_trials,
    score_unsupervised_label_free,
)


class AblationGuardError(RuntimeError):
    """Raised when an ablation run receives non-`dev` (`test` / `blind_test`) rows without a final audit log."""


def _build_ablation_configs() -> dict[str, dict[str, Any]]:
    full = list(config.FEATURES)
    no_content = [f for f in full if f not in ("file_size_log", "file_entropy")]
    drop_sig_single = [f for f in full if f != "signature_state"]
    no_content_no_sig = [f for f in no_content if f != "signature_state"]

    cfgs: dict[str, dict[str, Any]] = {
        "full_20": {
            "features": full,
            "allowed_extra": (),
            "unsup_baseline_only": False,
            "tag": "primary",
        },
        "no_content": {
            "features": no_content,
            "allowed_extra": (),
            "unsup_baseline_only": False,
            "tag": "primary",
        },
        "drop_signature": {
            "features": drop_sig_single,
            "allowed_extra": (),
            "unsup_baseline_only": False,
            "tag": "concept_c_evasion",
        },
        "no_content_no_sig": {
            "features": no_content_no_sig,
            "allowed_extra": (),
            "unsup_baseline_only": False,
            "tag": "concept_c_evasion",
        },
        "unsup_baseline_only": {
            "features": full,
            "allowed_extra": (),
            "unsup_baseline_only": True,
            "tag": "benign_scope_ablation",
        },
    }
    for grp_name, drop_cols in config.FEATURE_GROUPS.items():
        kept = [f for f in full if f not in set(drop_cols)]
        key = "drop_signature_group" if grp_name == "signature" else f"drop_{grp_name}"
        cfgs[key] = {
            "features": kept,
            "allowed_extra": (),
            "unsup_baseline_only": False,
            "tag": "feature_group_ablation",
        }
    return cfgs


V2_ABLATION_CONFIGS: dict[str, dict[str, Any]] = _build_ablation_configs()


def split_feature_types(feature_list: Sequence[str]) -> tuple[list[str], list[str], list[str]]:
    """Partition `feature_list` into `(cat_cols, num_cols, bin_cols)` preserving canonical order."""
    fset = set(feature_list)
    cat_cols = [c for c in config.CATEGORICAL_FEATURES if c in fset]
    num_cols = [c for c in config.NUMERIC_FEATURES if c in fset]
    bin_cols = [c for c in config.BINARY_FEATURES if c in fset]
    return cat_cols, num_cols, bin_cols


def assert_dev_only_ablation_guard(
    df: pd.DataFrame,
    allow_final_audit: bool = False,
    audit_log_path: Path | None = None,
) -> None:
    """Refuse to run ablations if `df` contains any non-`dev` row unless explicitly audited."""
    if "split_pool" not in df.columns:
        raise AblationGuardError("DataFrame is missing required 'split_pool' column for dev-only ablation guard")

    pools = df["split_pool"].astype(str).str.strip().unique().tolist()
    non_dev = [p for p in pools if p != "dev"]
    if not non_dev:
        return

    if not allow_final_audit or audit_log_path is None:
        raise AblationGuardError(
            f"Refusing to run ablations on non-dev split_pool values {non_dev!r}. "
            "Ablations are restricted strictly to split_pool == 'dev' (or require allow_final_audit=True "
            "with an explicit audit_log_path)."
        )

    log_path = Path(audit_log_path)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    entry = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "action": "ablation_final_audit_override",
        "n_rows": int(len(df)),
        "split_pools": pools,
    }
    with log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")


def _run_unsup_baseline_only_nested_cv(
    dev_df: pd.DataFrame,
    y_dev: np.ndarray,
    unsup_arms: Sequence[str],
    cat_cols: Sequence[str],
    num_cols: Sequence[str],
    bin_cols: Sequence[str],
    n_outer: int,
    n_inner: int,
    n_trials: int,
    seed: int,
    unsup_selection: str,
    max_epochs_override: int | None,
    device: str | None,
) -> dict[str, np.ndarray]:
    """Run nested family-grouped CV for unsupervised arms trained strictly on `benign_baseline` rows."""
    groups = build_family_cluster_groups(dev_df)
    outer_folds = _make_grouped_folds(y_dev, groups, n_splits=n_outer, seed=seed)
    outer_oof: dict[str, np.ndarray] = {a: np.zeros(len(dev_df), dtype=float) for a in unsup_arms}

    for arm_name in unsup_arms:
        for o_idx, (tr_idx, va_idx) in enumerate(outer_folds):
            tr_sub_all = dev_df.iloc[tr_idx].reset_index(drop=True)
            va_sub = dev_df.iloc[va_idx].reset_index(drop=True)
            y_tr_all = y_dev[tr_idx]
            g_tr_all = groups[tr_idx]

            keep_tr = tr_sub_all[config.LABEL_COL].astype(str) != "benign_drift"
            if int(np.sum((y_tr_all == 0) & keep_tr.to_numpy())) < 2:
                tr_sub = tr_sub_all
                y_tr_sub = y_tr_all
                g_tr_sub = g_tr_all
            else:
                tr_sub = tr_sub_all.loc[keep_tr].reset_index(drop=True)
                y_tr_sub = y_tr_all[keep_tr.to_numpy()]
                g_tr_sub = g_tr_all[keep_tr.to_numpy()]

            inner_folds = _make_grouped_folds(y_tr_sub, g_tr_sub, n_splits=n_inner, seed=seed + 200 + o_idx)
            cands = sample_param_trials(arm_name, n_trials=n_trials, seed=seed + 2000 + o_idx)
            best_crit = -float("inf")
            best_cfg = dict(cands[0])

            for t_idx, raw_cfg in enumerate(cands):
                cfg = dict(raw_cfg)
                if max_epochs_override is not None and arm_name in ("mlp", "ae"):
                    cfg["max_epochs"] = int(max_epochs_override)
                inner_oof = np.zeros(len(tr_sub), dtype=float)
                for i_idx, (itr_idx, iva_idx) in enumerate(inner_folds):
                    art = fit_arm_v2(
                        arm_name=arm_name,
                        tr_df=tr_sub.iloc[itr_idx].reset_index(drop=True),
                        y_tr=y_tr_sub[itr_idx],
                        groups_tr=g_tr_sub[itr_idx],
                        cat_cols=cat_cols,
                        num_cols=num_cols,
                        bin_cols=bin_cols,
                        seed=seed + 3000 + o_idx * 31 + t_idx * 7 + i_idx,
                        params=cfg,
                        device=device,
                    )
                    X_iva = art.preprocessor.transform(tr_sub.iloc[iva_idx].reset_index(drop=True))
                    inner_oof[iva_idx] = art.arm.predict_scores(X_iva)

                if unsup_selection == "label_selected":
                    crit = float(pr_auc(y_tr_sub, inner_oof))
                else:
                    crit = float(score_unsupervised_label_free(arm_name, inner_oof, y_tr_sub))
                if crit > best_crit:
                    best_crit = crit
                    best_cfg = dict(cfg)

            outer_art = fit_arm_v2(
                arm_name=arm_name,
                tr_df=tr_sub,
                y_tr=y_tr_sub,
                groups_tr=g_tr_sub,
                cat_cols=cat_cols,
                num_cols=num_cols,
                bin_cols=bin_cols,
                seed=seed + 4000 + o_idx,
                params=best_cfg,
                device=device,
            )
            X_va = outer_art.preprocessor.transform(va_sub)
            outer_oof[arm_name][va_idx] = outer_art.arm.predict_scores(X_va)

    return outer_oof


def run_dev_ablations_v2(
    dev_df: pd.DataFrame,
    arms: Sequence[str] = config.ARMS,
    configs: Sequence[str] = ("full_20", "no_content"),
    n_outer: int = 3,
    n_inner: int = 2,
    n_trials: int = 4,
    seed: int = config.SEED,
    unsup_selection: str = "label_free",
    max_epochs_override: int | None = None,
    device: str | None = None,
    out_csv: Path | None = None,
    allow_final_audit: bool = False,
    audit_log_path: Path | None = None,
) -> pd.DataFrame:
    """Run dev-only ablations with independent config-matched nested CV hyperparameter search per config."""
    assert_dev_only_ablation_guard(
        dev_df,
        allow_final_audit=allow_final_audit,
        audit_log_path=audit_log_path,
    )

    df_clean = dev_df.reset_index(drop=True)
    y_dev = (df_clean[config.LABEL_COL].astype(str) == config.POSITIVE_LABEL).astype(int).to_numpy()
    rows: list[dict[str, Any]] = []

    for c_idx, cfg_name in enumerate(configs):
        if cfg_name not in V2_ABLATION_CONFIGS:
            raise KeyError(f"Unknown v2 ablation config {cfg_name!r}. Valid: {sorted(V2_ABLATION_CONFIGS)}")
        spec = V2_ABLATION_CONFIGS[cfg_name]
        feats = list(spec["features"])
        cat_cols, num_cols, bin_cols = split_feature_types(feats)
        n_features = len(cat_cols) + len(num_cols) + len(bin_cols)

        if spec["unsup_baseline_only"]:
            unsup_arms = [a for a in arms if a in config.UNSUPERVISED_ARMS]
            if not unsup_arms:
                continue
            oof_scores = _run_unsup_baseline_only_nested_cv(
                dev_df=df_clean,
                y_dev=y_dev,
                unsup_arms=unsup_arms,
                cat_cols=cat_cols,
                num_cols=num_cols,
                bin_cols=bin_cols,
                n_outer=n_outer,
                n_inner=n_inner,
                n_trials=n_trials,
                seed=int(seed) + c_idx * 101,
                unsup_selection=unsup_selection,
                max_epochs_override=max_epochs_override,
                device=device,
            )
            eval_arms = unsup_arms
        else:
            cv_res = run_nested_family_cv(
                dev_df=df_clean,
                y_dev=y_dev,
                arms=arms,
                cat_cols=cat_cols,
                num_cols=num_cols,
                bin_cols=bin_cols,
                n_outer=n_outer,
                n_inner=n_inner,
                n_trials=n_trials,
                seed=int(seed) + c_idx * 101,
                unsup_selection=unsup_selection,
                allowed_extra=spec["allowed_extra"],
                max_epochs_override=max_epochs_override,
                device=device,
            )
            oof_scores = cv_res["outer_oof_scores"]
            eval_arms = list(arms)

        for arm_name in eval_arms:
            s_oof = np.asarray(oof_scores[arm_name], dtype=float)
            tail = tail_risk_and_effort_metrics(
                y_dev,
                s_oof,
                budgets=(10, 20, 50, 100),
                recall_targets=(0.50, 0.80, 0.90),
            )
            rows.append(
                {
                    "config": cfg_name,
                    "tag": spec["tag"],
                    "arm": arm_name,
                    "n_features": int(n_features),
                    "config_matched_tuning": True,
                    "n_trials": int(n_trials),
                    "pr_auc": float(pr_auc(y_dev, s_oof)),
                    "roc_auc": float(roc_auc(y_dev, s_oof)),
                    "tie_expected_precision_at_10": float(tail["tie_expected_precision_at_10"]),
                    "tie_expected_precision_at_50": float(tail["tie_expected_precision_at_50"]),
                    "recall_at_10": float(tail["recall_at_10"]),
                    "recall_at_50": float(tail["recall_at_50"]),
                    "worst_positive_rank": int(tail["worst_positive_rank"]),
                    "pos_in_bottom_50pct": int(tail["pos_in_bottom_50pct"]),
                    "pos_in_bottom_90pct": int(tail["pos_in_bottom_90pct"]),
                    "effort_at_recall_50_count": int(tail["effort_at_recall_50_count"]),
                    "effort_at_recall_80_count": int(tail["effort_at_recall_80_count"]),
                    "effort_at_recall_90_count": int(tail["effort_at_recall_90_count"]),
                }
            )

    out_df = pd.DataFrame(rows)
    if out_csv is not None:
        out_path = Path(out_csv)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_df.to_csv(out_path, index=False)
    return out_df
