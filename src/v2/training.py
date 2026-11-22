"""v2 training integrity pipeline (IMP-08, IMP-09, OD-V2-06, OD-V2-09).

Enforces:
- Non-early-stopped arms (rf, xgb, lr, iforest) fit on 100% of eligible training/dev rows.
- Early-stopped arms (mlp, ae) stop strictly on disjoint inner grouped validation splits
  (fit_arm_v2 does NOT accept outer va_df).
- Split-local SharedPreprocessor fitting inside each fold / sub_tr split only.
- Union-find family + packer_cluster + sample_sha256 + pair_group_id positive grouping.
- Nested family-grouped CV with equal N_trials across all tuned arms.
- Label-free unsupervised model selection by default; any labeled-val selection explicitly
  stamped "label-selected".
- Multi-seed --final (K = 5) reporting per-seed mean/std and the K-seed ensemble score.
"""
from __future__ import annotations

import itertools
import json
import math
from dataclasses import dataclass
from typing import Any, Sequence

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedGroupKFold

from src import config
from src.eval.metrics import pr_auc
from src.models.preprocess import SharedPreprocessor
from src.v2 import config_v2
from src.v2.models_v2 import make_arm_v2


@dataclass
class FitArtifactV2:
    arm: Any
    preprocessor: SharedPreprocessor
    fit_meta: dict[str, Any]


def _clean_opt_str(val: Any) -> str | None:
    if val is None:
        return None
    try:
        if pd.isna(val):
            return None
    except (TypeError, ValueError):
        pass
    s = str(val).strip()
    if not s or s.lower() in ("none", "nan", "unknown", ""):
        return None
    return s


def build_family_cluster_groups(df: pd.DataFrame) -> np.ndarray:
    """Assign leakage-proof group IDs keeping family/packer/binary/pair clusters together.

    Positive rows (y == 1) are transitively grouped via union-find across any shared
    `sample_family` (fallback `technique_id`), `packer_cluster`, `sample_sha256`, and
    `pair_group_id`. Benign rows (y == 0) are grouped separately by `benign_session_id`,
    `run_id`, or `artifact_key`.
    """
    n = len(df)
    y = (df[config.LABEL_COL].astype(str) == config.POSITIVE_LABEL).to_numpy()
    pos_indices = np.flatnonzero(y)
    ben_indices = np.flatnonzero(~y)

    groups = np.empty(n, dtype=object)

    # Disjoint-set union over positive row indices
    if len(pos_indices):
        parent = {int(i): int(i) for i in pos_indices}

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(a: int, b: int) -> None:
            ra, rb = find(a), find(b)
            if ra != rb:
                if ra < rb:
                    parent[rb] = ra
                else:
                    parent[ra] = rb

        extra_cols = [c for c in ("packer_cluster", "sample_sha256", "pair_group_id") if c in df.columns]
        buckets: dict[tuple[str, str], list[int]] = {}
        for idx in pos_indices:
            row = df.iloc[int(idx)]
            has_any = False
            eff_family = _clean_opt_str(row.get("sample_family")) or _clean_opt_str(row.get("technique_id"))
            if eff_family is not None:
                has_any = True
                buckets.setdefault(("family", eff_family.lower()), []).append(int(idx))
            for col in extra_cols:
                v = _clean_opt_str(row[col])
                if v is not None:
                    has_any = True
                    buckets.setdefault((col, v.lower()), []).append(int(idx))
            if not has_any:
                ak = _clean_opt_str(row.get("artifact_key")) or f"row_{idx}"
                buckets.setdefault(("fallback", ak.lower()), []).append(int(idx))

        for idxs in buckets.values():
            first = idxs[0]
            for other in idxs[1:]:
                union(first, other)

        for idx in pos_indices:
            groups[int(idx)] = f"pos_grp_{find(int(idx))}"

    for idx in ben_indices:
        row = df.iloc[int(idx)]
        b_id = (
            _clean_opt_str(row.get("benign_session_id"))
            or _clean_opt_str(row.get("run_id"))
            or _clean_opt_str(row.get("artifact_key"))
            or f"row_{idx}"
        )
        groups[int(idx)] = f"ben_grp_{b_id.lower()}"

    return groups


def make_inner_val_split(
    tr_df: pd.DataFrame,
    y_tr: np.ndarray,
    groups_tr: np.ndarray,
    seed: int = config.SEED,
    val_fraction: float = 0.2,
) -> tuple[np.ndarray, np.ndarray]:
    """Carve a strictly disjoint grouped validation slice inside `tr_df` (0 group overlap)."""
    y_arr = np.asarray(y_tr).astype(int).ravel()
    g_arr = np.asarray(groups_tr).astype(str).ravel()
    if len(tr_df) != len(y_arr) or len(tr_df) != len(g_arr):
        raise ValueError("tr_df, y_tr, and groups_tr must have identical lengths")

    pos_groups = sorted({g for g, yi in zip(g_arr, y_arr) if yi == 1})
    ben_groups = sorted({g for g, yi in zip(g_arr, y_arr) if yi == 0 and g not in pos_groups})

    rng = np.random.default_rng(seed)
    rng.shuffle(pos_groups)
    rng.shuffle(ben_groups)

    val_groups: set[str] = set()
    if len(pos_groups) >= 2:
        n_pos_val = min(len(pos_groups) - 1, max(1, int(round(val_fraction * len(pos_groups)))))
        val_groups.update(pos_groups[:n_pos_val])

    if len(ben_groups) >= 2:
        n_ben_val = min(len(ben_groups) - 1, max(1, int(round(val_fraction * len(ben_groups)))))
        val_groups.update(ben_groups[:n_ben_val])
    elif len(ben_groups) == 1 and len(val_groups) == 0:
        raise ValueError("Cannot carve disjoint inner validation split from a single benign group")

    val_mask = np.isin(g_arr, list(val_groups))
    sub_tr_idx = np.flatnonzero(~val_mask)
    es_val_idx = np.flatnonzero(val_mask)

    if len(sub_tr_idx) == 0 or len(es_val_idx) == 0:
        raise ValueError("Inner validation split failed to produce non-empty train and val partitions")
    assert set(g_arr[sub_tr_idx]).isdisjoint(set(g_arr[es_val_idx])), "Inner ES split leaked group across train/val!"
    return sub_tr_idx, es_val_idx


def _eligible_mask(arm_name: str, y: np.ndarray) -> np.ndarray:
    y_arr = np.asarray(y).astype(int).ravel()
    if arm_name in config.UNSUPERVISED_ARMS:
        return y_arr == 0
    return np.ones(len(y_arr), dtype=bool)


def fit_arm_v2(
    arm_name: str,
    tr_df: pd.DataFrame,
    y_tr: np.ndarray,
    groups_tr: np.ndarray,
    cat_cols: Sequence[str],
    num_cols: Sequence[str],
    bin_cols: Sequence[str],
    allowed_extra: Sequence[str] = (),
    seed: int = config.SEED,
    params: dict[str, Any] | None = None,
    fixed_epochs: int | None = None,
    device: str | None = None,
) -> FitArtifactV2:
    """Fit one v2 model arm cleanly using ONLY `tr_df` (no outer `va_df` parameter accepted)."""
    y_arr = np.asarray(y_tr).astype(int).ravel()
    g_arr = np.asarray(groups_tr).astype(str).ravel()
    arm = make_arm_v2(arm_name, seed=seed, device=device, fixed_epochs=fixed_epochs, params=params)

    elig_all = _eligible_mask(arm_name, y_arr)
    n_eligible = int(elig_all.sum())

    if not getattr(arm, "uses_early_stopping", False) or fixed_epochs is not None:
        tr_elig_df = tr_df.iloc[elig_all]
        y_elig = y_arr[elig_all]
        pre = SharedPreprocessor(cat_cols, num_cols, bin_cols, allowed_extra=allowed_extra).fit(tr_elig_df)
        X_elig = pre.transform(tr_elig_df)
        arm.fit(X_elig, y_elig)
        meta = {
            "arm": arm_name,
            "seed": int(seed),
            "n_train_total": int(len(tr_df)),
            "n_eligible_rows": n_eligible,
            "n_fit_rows": int(len(tr_elig_df)),
            "n_pre_fit_rows": int(len(tr_elig_df)),
            "sub_tr_indices": np.flatnonzero(elig_all).tolist(),
            "es_val_indices": [],
            "best_epoch": int(getattr(arm, "best_epoch_", 0)),
            "fit_mode": getattr(arm, "fit_mode_", "full_eligible_fit"),
        }
        return FitArtifactV2(arm=arm, preprocessor=pre, fit_meta=meta)

    sub_tr_idx, es_val_idx = make_inner_val_split(tr_df, y_arr, g_arr, seed=seed)
    assert set(g_arr[sub_tr_idx]).isdisjoint(set(g_arr[es_val_idx]))

    if arm.is_unsupervised:
        sub_mask = y_arr[sub_tr_idx] == 0
        val_mask = y_arr[es_val_idx] == 0
        fit_idx = sub_tr_idx[sub_mask]
        val_idx = es_val_idx[val_mask]
    else:
        fit_idx = sub_tr_idx
        val_idx = es_val_idx

    pre = SharedPreprocessor(cat_cols, num_cols, bin_cols, allowed_extra=allowed_extra).fit(tr_df.iloc[fit_idx])
    X_fit = pre.transform(tr_df.iloc[fit_idx])
    X_es = pre.transform(tr_df.iloc[val_idx])
    arm.fit(X_fit, y_arr[fit_idx], X_val=X_es, y_val=y_arr[val_idx])
    meta = {
        "arm": arm_name,
        "seed": int(seed),
        "n_train_total": int(len(tr_df)),
        "n_eligible_rows": n_eligible,
        "n_fit_rows": int(len(fit_idx)),
        "n_pre_fit_rows": int(len(fit_idx)),
        "sub_tr_indices": sub_tr_idx.tolist(),
        "es_val_indices": es_val_idx.tolist(),
        "sub_tr_groups": sorted(set(g_arr[sub_tr_idx])),
        "es_val_groups": sorted(set(g_arr[es_val_idx])),
        "best_epoch": int(getattr(arm, "best_epoch_", 0)),
        "fit_mode": getattr(arm, "fit_mode_", "inner_val_early_stop"),
    }
    return FitArtifactV2(arm=arm, preprocessor=pre, fit_meta=meta)


def sample_param_trials(arm_name: str, n_trials: int, seed: int = config.SEED) -> list[dict[str, Any]]:
    """Deterministically sample `n_trials` unique configurations for one arm."""
    space = config_v2.V2_SEARCH_SPACES[arm_name]
    keys = sorted(space)
    total = 1
    for k in keys:
        total *= len(space[k])
    if total < int(n_trials):
        raise ValueError(f"Search space for {arm_name!r} has only {total} combos (< requested {n_trials})")

    rng = np.random.default_rng(seed)
    all_combos = [dict(zip(keys, vals)) for vals in itertools.product(*(space[k] for k in keys))]
    pick_idx = rng.choice(len(all_combos), size=int(n_trials), replace=False)
    return [all_combos[int(i)] for i in pick_idx]


def score_unsupervised_label_free(arm_name: str, inner_oof_scores: np.ndarray, y_tr: np.ndarray) -> float:
    """Label-free unsupervised validation criterion computed strictly from benign rows.

    Lower benign anomaly score + tighter benign tail spread -> higher score (never touches y == 1).
    """
    ben_scores = np.asarray(inner_oof_scores, dtype=float)[np.asarray(y_tr).astype(int) == 0]
    if len(ben_scores) == 0:
        return -float("inf")
    if arm_name == "ae":
        return -float(np.mean(ben_scores))
    return -(float(np.mean(ben_scores)) + 0.5 * float(np.std(ben_scores)))


def _make_grouped_folds(y: np.ndarray, groups: np.ndarray, n_splits: int, seed: int) -> list[tuple[np.ndarray, np.ndarray]]:
    pos_groups = len({g for g, yi in zip(groups, y) if yi == 1})
    ben_groups = len({g for g, yi in zip(groups, y) if yi == 0})
    k = min(int(n_splits), max(2, pos_groups), max(2, ben_groups))
    if pos_groups < 2 or ben_groups < 2:
        raise ValueError(f"Need >= 2 positive groups and >= 2 benign groups, got pos={pos_groups}, ben={ben_groups}")
    sgkf = StratifiedGroupKFold(n_splits=k, shuffle=True, random_state=seed)
    folds = []
    for tr_idx, va_idx in sgkf.split(np.zeros(len(y)), y, groups=groups):
        assert set(groups[tr_idx]).isdisjoint(set(groups[va_idx])), "CV fold leaked group!"
        folds.append((np.asarray(tr_idx, dtype=int), np.asarray(va_idx, dtype=int)))
    return folds


def run_nested_family_cv(
    dev_df: pd.DataFrame,
    y_dev: np.ndarray,
    arms: Sequence[str],
    cat_cols: Sequence[str],
    num_cols: Sequence[str],
    bin_cols: Sequence[str],
    n_outer: int = config_v2.V2_OUTER_FOLDS,
    n_inner: int = config_v2.V2_INNER_FOLDS,
    n_trials: int = config_v2.V2_N_SEARCH_TRIALS,
    seed: int = config.SEED,
    unsup_selection: str = "label_free",
    allowed_extra: Sequence[str] = (),
    max_epochs_override: int | None = None,
    device: str | None = None,
) -> dict[str, Any]:
    """Nested family-grouped CV on dev data with equal trial budgets and leak-free tuning."""
    if unsup_selection not in config_v2.V2_UNSUP_SELECTION_MODES:
        raise ValueError(f"Invalid unsup_selection {unsup_selection!r}")

    dev_df = dev_df.reset_index(drop=True)
    y_arr = np.asarray(y_dev).astype(int).ravel()
    groups = build_family_cluster_groups(dev_df)
    outer_folds = _make_grouped_folds(y_arr, groups, n_splits=n_outer, seed=seed)

    outer_oof: dict[str, np.ndarray] = {a: np.zeros(len(dev_df), dtype=float) for a in arms}
    outer_pr: dict[str, float] = {}
    fold_records: list[dict[str, Any]] = []
    trial_records: list[dict[str, Any]] = []
    best_params_per_fold: dict[str, list[dict[str, Any]]] = {a: [] for a in arms}
    best_epochs_per_arm: dict[str, list[int]] = {a: [] for a in arms}
    selection_tags: dict[str, str] = {}

    for arm_name in arms:
        sel_tag = (
            "label-selected" if (arm_name in config.UNSUPERVISED_ARMS and unsup_selection == "label_selected")
            else ("label_free" if arm_name in config.UNSUPERVISED_ARMS else "supervised_pr_auc")
        )
        selection_tags[arm_name] = sel_tag
        seen_outer = np.zeros(len(dev_df), dtype=bool)

        for o_idx, (tr_idx, va_idx) in enumerate(outer_folds):
            tr_sub = dev_df.iloc[tr_idx].reset_index(drop=True)
            va_sub = dev_df.iloc[va_idx].reset_index(drop=True)
            y_tr_sub = y_arr[tr_idx]
            y_va_sub = y_arr[va_idx]
            g_tr_sub = groups[tr_idx]

            inner_folds = _make_grouped_folds(y_tr_sub, g_tr_sub, n_splits=n_inner, seed=seed + 100 + o_idx)
            cands = sample_param_trials(arm_name, n_trials=n_trials, seed=seed + 1000 + o_idx)

            best_crit = -float("inf")
            best_cfg = dict(cands[0])
            for t_idx, raw_cfg in enumerate(cands):
                cfg = dict(raw_cfg)
                if max_epochs_override is not None and arm_name in ("mlp", "ae"):
                    cfg["max_epochs"] = int(max_epochs_override)
                inner_oof = np.zeros(len(tr_sub), dtype=float)
                inner_seen = np.zeros(len(tr_sub), dtype=bool)
                for i_idx, (itr, iva) in enumerate(inner_folds):
                    art_in = fit_arm_v2(
                        arm_name,
                        tr_sub.iloc[itr].reset_index(drop=True),
                        y_tr_sub[itr],
                        g_tr_sub[itr],
                        cat_cols,
                        num_cols,
                        bin_cols,
                        allowed_extra=allowed_extra,
                        seed=seed + o_idx * 10 + i_idx,
                        params=cfg,
                        device=device,
                    )
                    inner_oof[iva] = art_in.arm.predict_scores(art_in.preprocessor.transform(tr_sub.iloc[iva]))
                    inner_seen[iva] = True
                assert inner_seen.all()

                if sel_tag == "label_free":
                    crit = score_unsupervised_label_free(arm_name, inner_oof, y_tr_sub)
                else:
                    crit = float(pr_auc(y_tr_sub, inner_oof))

                trial_records.append({
                    "arm": arm_name,
                    "outer_fold": o_idx,
                    "trial": t_idx,
                    "selection_tag": sel_tag,
                    "criterion_score": float(crit),
                    "params_json": json.dumps(raw_cfg, sort_keys=True, default=str),
                })
                if crit > best_crit:
                    best_crit = crit
                    best_cfg = dict(cfg)

            art_out = fit_arm_v2(
                arm_name,
                tr_sub,
                y_tr_sub,
                g_tr_sub,
                cat_cols,
                num_cols,
                bin_cols,
                allowed_extra=allowed_extra,
                seed=seed + o_idx,
                params=best_cfg,
                device=device,
            )
            va_scores = art_out.arm.predict_scores(art_out.preprocessor.transform(va_sub))
            outer_oof[arm_name][va_idx] = va_scores
            seen_outer[va_idx] = True

            if art_out.fit_meta["best_epoch"] > 0:
                best_epochs_per_arm[arm_name].append(int(art_out.fit_meta["best_epoch"]))
            best_params_per_fold[arm_name].append(dict(best_cfg))
            fold_records.append({
                "arm": arm_name,
                "outer_fold": o_idx,
                "selection_tag": sel_tag,
                "trials_evaluated": len(cands),
                "outer_fold_pr_auc": float(pr_auc(y_va_sub, va_scores)),
                "n_train_rows": int(len(tr_sub)),
                "n_fit_rows": int(art_out.fit_meta["n_fit_rows"]),
                "n_eligible_rows": int(art_out.fit_meta["n_eligible_rows"]),
                "best_epoch": int(art_out.fit_meta["best_epoch"]),
                "fit_mode": art_out.fit_meta["fit_mode"],
            })

        assert seen_outer.all()
        outer_pr[arm_name] = float(pr_auc(y_arr, outer_oof[arm_name]))

    median_best_epoch = {
        a: (int(math.ceil(float(np.median(best_epochs_per_arm[a])))) if best_epochs_per_arm[a] else None)
        for a in arms
    }
    return {
        "outer_oof_scores": outer_oof,
        "outer_oof_pr_auc": outer_pr,
        "fold_records": pd.DataFrame(fold_records),
        "trials_df": pd.DataFrame(trial_records),
        "best_params_per_fold": best_params_per_fold,
        "median_best_epoch": median_best_epoch,
        "selection_tags": selection_tags,
    }


def run_multiseed_final(
    dev_df: pd.DataFrame,
    y_dev: np.ndarray,
    test_df: pd.DataFrame,
    y_test: np.ndarray,
    arm_name: str,
    params: dict[str, Any] | None,
    cat_cols: Sequence[str],
    num_cols: Sequence[str],
    bin_cols: Sequence[str],
    seeds: Sequence[int] = config_v2.V2_FINAL_SEEDS,
    refit_policy: str = "full_dev_median_epoch",
    fixed_epochs: int | None = None,
    n_folds: int = config_v2.V2_OUTER_FOLDS,
    allowed_extra: Sequence[str] = (),
    device: str | None = None,
) -> dict[str, Any]:
    """Run K-seed `--final` evaluation returning per-seed mean/std and the K-seed ensemble score."""
    if refit_policy not in config_v2.V2_REFIT_POLICIES:
        raise ValueError(f"Unsupported refit_policy {refit_policy!r}")

    dev_df = dev_df.reset_index(drop=True)
    y_dev_arr = np.asarray(y_dev).astype(int).ravel()
    y_test_arr = np.asarray(y_test).astype(int).ravel()
    groups_dev = build_family_cluster_groups(dev_df)

    per_seed_scores: list[np.ndarray] = []
    per_seed_pr_auc: list[float] = []
    fit_metas: list[dict[str, Any]] = []

    use_fixed_epochs = fixed_epochs
    if use_fixed_epochs is None and arm_name in ("mlp", "ae") and refit_policy == "full_dev_median_epoch":
        use_fixed_epochs = int((params or {}).get("fixed_epochs") or 20)

    for s in seeds:
        if refit_policy == "full_dev_median_epoch":
            art = fit_arm_v2(
                arm_name,
                dev_df,
                y_dev_arr,
                groups_dev,
                cat_cols,
                num_cols,
                bin_cols,
                allowed_extra=allowed_extra,
                seed=int(s),
                params=params,
                fixed_epochs=use_fixed_epochs if arm_name in ("mlp", "ae") else None,
                device=device,
            )
            te_scores = art.arm.predict_scores(art.preprocessor.transform(test_df))
            fit_metas.append(art.fit_meta)
        else:
            folds = _make_grouped_folds(y_dev_arr, groups_dev, n_splits=n_folds, seed=int(s))
            fold_preds = []
            fold_metas = []
            for f_i, (tr_idx, _) in enumerate(folds):
                art = fit_arm_v2(
                    arm_name,
                    dev_df.iloc[tr_idx].reset_index(drop=True),
                    y_dev_arr[tr_idx],
                    groups_dev[tr_idx],
                    cat_cols,
                    num_cols,
                    bin_cols,
                    allowed_extra=allowed_extra,
                    seed=int(s) + f_i,
                    params=params,
                    fixed_epochs=fixed_epochs if arm_name in ("mlp", "ae") else None,
                    device=device,
                )
                fold_preds.append(art.arm.predict_scores(art.preprocessor.transform(test_df)))
                fold_metas.append(art.fit_meta)
            te_scores = np.mean(np.vstack(fold_preds), axis=0)
            fit_metas.append({"seed": int(s), "fold_ensemble_metas": fold_metas})

        per_seed_scores.append(te_scores)
        per_seed_pr_auc.append(float(pr_auc(y_test_arr, te_scores)))

    ensemble_scores = np.mean(np.vstack(per_seed_scores), axis=0)
    return {
        "arm": arm_name,
        "seeds": [int(s) for s in seeds],
        "refit_policy": refit_policy,
        "per_seed_scores": per_seed_scores,
        "per_seed_pr_auc": per_seed_pr_auc,
        "mean_pr_auc": float(np.mean(per_seed_pr_auc)),
        "std_pr_auc": float(np.std(per_seed_pr_auc)),
        "ensemble_scores": ensemble_scores,
        "ensemble_pr_auc": float(pr_auc(y_test_arr, ensemble_scores)),
        "fit_metas": fit_metas,
    }
