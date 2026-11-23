"""Phase v2 statistical inference, tail-risk/effort metrics, LOFO, and execution-delta helpers.

Implements:
- `monte_carlo_random_pr_auc`: 10,000-permutation Monte Carlo finite-sample random PR-AUC baseline (`IMP-14`).
- `tail_risk_and_effort_metrics` & `tail_audit_upper_bound`: conservative tie-aware tail-risk and analyst
  `effort@recall` metrics (`OD-V2-14`).
- `family_clustered_paired_bootstrap_p`: paired bootstrap p-values and unadjusted 95% CIs resampling whole
  malware family/packer/binary/pair clusters and benign sessions (`IMP-10`).
- `holm_bonferroni_adjust` & `evaluate_fixed_comparisons_dual_config`: step-down Holm-Bonferroni adjustment
  strictly on p-values (never CIs) over the fixed pre-registered comparison family and dual-config winner rule.
- `calibrate_dev_threshold` & `evaluate_frozen_threshold`: nested dev OOF threshold calibration (`IMP-11`).
- `compute_lofo_table`: leave-one-family-out per-family PR-AUC evaluation table.
- `cross_stratum_execution_delta`: Concept C (`OD-V2-15`) paired `executed` vs `dormant` ranking contrast.
"""
from __future__ import annotations

import math
from typing import Any, Callable, Sequence

import numpy as np
import pandas as pd

from src import config
from src.eval.metrics import (
    accuracy_at_threshold,
    f1_at_threshold,
    fpr_at_threshold,
    pr_auc,
    recall_at_threshold,
    roc_auc,
    threshold_at_fpr,
    tie_expected_precision_at_k,
    tie_expected_recall_at_k,
)
from src.v2.training import build_family_cluster_groups

__all__ = [
    "FIXED_V2_COMPARISONS",
    "tie_expected_precision_at_k",
    "tie_expected_recall_at_k",
    "monte_carlo_random_pr_auc",
    "tail_risk_and_effort_metrics",
    "tail_audit_upper_bound",
    "family_clustered_paired_bootstrap_p",
    "holm_bonferroni_adjust",
    "evaluate_fixed_comparisons_dual_config",
    "calibrate_dev_threshold",
    "evaluate_frozen_threshold",
    "compute_lofo_table",
    "cross_stratum_execution_delta",
]

# Fixed pre-registered comparison list (zero post-hoc `best_ml` selection).
FIXED_V2_COMPARISONS: tuple[tuple[str, str], ...] = (
    ("xgb", "rf"),
    ("rf", "mlp"),
    ("xgb", "mlp"),
    ("rf", "rules_count"),
    ("rf", "rules_binary"),
    ("xgb", "rules_count"),
    ("xgb", "rules_binary"),
    ("mlp", "rules_count"),
    ("mlp", "rules_binary"),
)


def _worst_case_descending_ranks(scores: np.ndarray) -> np.ndarray:
    """Return 1-indexed worst-case descending rank for each score (ties assigned max rank in tie block)."""
    s = np.asarray(scores, dtype=float).ravel()
    if len(s) == 0:
        return np.empty(0, dtype=int)
    _, inv, counts = np.unique(-s, return_inverse=True, return_counts=True)
    cum_counts = np.cumsum(counts)
    return cum_counts[inv].astype(int)


def monte_carlo_random_pr_auc(
    y: Sequence[int] | np.ndarray,
    n_perm: int = 10_000,
    seed: int = config.SEED,
) -> dict[str, float]:
    """Compute finite-sample random-ranking PR-AUC distribution over `n_perm` permutations (`IMP-14`).

    Under continuous uniform random scores (a uniform random permutation of `N` items with `P` positives),
    average precision equals `(1 / P) * sum_{j=1}^P (j / r_j)` where `r_1 < ... < r_P` are the sorted
    1-indexed positions of the `P` positives.
    """
    y_arr = np.asarray(y, dtype=int).ravel()
    n = int(len(y_arr))
    n_pos = int(np.sum(y_arr == 1))
    n_neg = n - n_pos
    if n == 0 or n_pos == 0 or n_neg == 0:
        raise ValueError(f"y must contain both positives and negatives (got n={n}, n_pos={n_pos})")
    if int(n_perm) < 1:
        raise ValueError(f"n_perm must be >= 1, got {n_perm}")

    rng = np.random.default_rng(int(seed))
    numerators = np.arange(1, n_pos + 1, dtype=float)
    ap_vals = np.empty(int(n_perm), dtype=float)

    for b in range(int(n_perm)):
        pos_ranks = np.sort(rng.choice(n, size=n_pos, replace=False)) + 1.0
        ap_vals[b] = float(np.sum(numerators / pos_ranks) / float(n_pos))

    return {
        "mean": float(np.mean(ap_vals)),
        "std": float(np.std(ap_vals, ddof=1)) if int(n_perm) > 1 else 0.0,
        "p05": float(np.percentile(ap_vals, 5.0)),
        "p50": float(np.percentile(ap_vals, 50.0)),
        "p95": float(np.percentile(ap_vals, 95.0)),
        "prevalence": float(n_pos / float(n)),
        "n_perm": int(n_perm),
    }


def tail_risk_and_effort_metrics(
    y: Sequence[int] | np.ndarray,
    scores: Sequence[float] | np.ndarray,
    budgets: Sequence[int] = (10, 20, 50, 100),
    recall_targets: Sequence[float] = (0.50, 0.80, 0.90),
) -> dict[str, float]:
    """Compute pre-registered secondary tail-risk and analyst-effort metrics (`OD-V2-14`).

    Rank definitions use conservative (tie-pessimistic) 1-indexed descending ranks:
    - `worst_positive_rank`: maximum 1-indexed worst-case rank across all positives (`y == 1`).
    - `pos_in_bottom_50pct`: count of positives with `worst_rank > 0.50 * N` (lower 50% of scores).
    - `pos_in_bottom_90pct`: count of positives with `worst_rank > 0.10 * N` (outside top 10%, i.e., lower 90%).
    - `effort_at_recall_{50,80,90}_count` & `_frac`: minimum artifacts reviewed under worst-case tie ordering
      to recover at least `ceil(target * n_pos)` positives.
    """
    y_arr = np.asarray(y, dtype=int).ravel()
    s_arr = np.asarray(scores, dtype=float).ravel()
    if len(y_arr) != len(s_arr):
        raise ValueError(f"y and scores length mismatch: {len(y_arr)} != {len(s_arr)}")
    n = int(len(y_arr))
    pos_mask = y_arr == 1
    n_pos = int(np.sum(pos_mask))
    if n == 0 or n_pos == 0:
        raise ValueError(f"tail_risk_and_effort_metrics requires >= 1 positive row (n={n}, n_pos={n_pos})")

    worst_ranks = _worst_case_descending_ranks(s_arr)
    pos_worst_ranks = np.sort(worst_ranks[pos_mask])

    worst_pos_rank = int(pos_worst_ranks[-1])
    bottom_50_cutoff = 0.50 * float(n)
    bottom_90_cutoff = 0.10 * float(n)  # bottom 90% = outside top 10%
    pos_bottom_50 = int(np.sum(pos_worst_ranks > bottom_50_cutoff))
    pos_bottom_90 = int(np.sum(pos_worst_ranks > bottom_90_cutoff))

    out: dict[str, float] = {
        "n_total": int(n),
        "n_pos": int(n_pos),
        "worst_positive_rank": int(worst_pos_rank),
        "worst_positive_percentile": float(worst_pos_rank / float(n)),
        "pos_in_bottom_50pct": int(pos_bottom_50),
        "pos_in_bottom_50pct_frac": float(pos_bottom_50 / float(n_pos)),
        "pos_in_bottom_90pct": int(pos_bottom_90),
        "pos_in_bottom_90pct_frac": float(pos_bottom_90 / float(n_pos)),
    }

    for k in budgets:
        k_int = int(k)
        out[f"recall_at_{k_int}"] = float(tie_expected_recall_at_k(y_arr, s_arr, k_int))
        out[f"tie_expected_precision_at_{k_int}"] = float(tie_expected_precision_at_k(y_arr, s_arr, k_int))

    for target in recall_targets:
        t_val = float(target)
        if not (0.0 < t_val <= 1.0):
            raise ValueError(f"recall target must be in (0, 1], got {t_val}")
        pct = int(round(t_val * 100))
        req_pos = max(1, min(n_pos, int(math.ceil(t_val * float(n_pos) - 1e-12))))
        effort_count = int(pos_worst_ranks[req_pos - 1])
        out[f"effort_at_recall_{pct}_count"] = int(effort_count)
        out[f"effort_at_recall_{pct}_frac"] = float(effort_count / float(n))

    return out


def tail_audit_upper_bound(n_draws: int, alpha: float = 0.05) -> float:
    """Return `(1 - alpha)` upper bound on missed-positive rate after 0 positives in `n_draws` random tail draws.

    Formula (`OD-V2-14`, future-work sample-size calculator): `p_upper(n) = 1 - alpha**(1 / n)`.
    """
    if int(n_draws) < 1:
        raise ValueError(f"n_draws must be >= 1, got {n_draws}")
    if not (0.0 < float(alpha) < 1.0):
        raise ValueError(f"alpha must be in (0, 1), got {alpha}")
    return float(1.0 - (float(alpha) ** (1.0 / float(n_draws))))


def family_clustered_paired_bootstrap_p(
    metric_fn: Callable[[np.ndarray, np.ndarray], float],
    y: Sequence[int] | np.ndarray,
    scores_a: Sequence[float] | np.ndarray,
    scores_b: Sequence[float] | np.ndarray,
    df: pd.DataFrame,
    n_boot: int = 2000,
    seed: int = config.BOOTSTRAP_SEED,
    alpha: float = 0.05,
) -> dict[str, float]:
    """Paired cluster bootstrap comparing `scores_a` vs `scores_b` over family/pair & session clusters (`IMP-10`).

    Resamples positive clusters (transitively merged across `sample_family`/`technique_id`,
    `packer_cluster`, `sample_sha256`, and `pair_group_id`) and benign session clusters
    independently with replacement. Returns unadjusted `(1 - alpha)` percentile CIs on
    `metric(A) - metric(B)` alongside the two-sided paired bootstrap p-value `p_raw`.
    """
    y_arr = np.asarray(y, dtype=int).ravel()
    a_arr = np.asarray(scores_a, dtype=float).ravel()
    b_arr = np.asarray(scores_b, dtype=float).ravel()
    if not (len(y_arr) == len(a_arr) == len(b_arr) == len(df)):
        raise ValueError("y, scores_a, scores_b, and df must have identical length")
    if int(n_boot) < 1:
        raise ValueError(f"n_boot must be >= 1, got {n_boot}")

    df_local = df.copy()
    if config.LABEL_COL not in df_local.columns:
        df_local[config.LABEL_COL] = np.where(y_arr == 1, config.POSITIVE_LABEL, "benign_baseline")
    groups = build_family_cluster_groups(df_local)

    pos_clusters: dict[str, np.ndarray] = {}
    ben_clusters: dict[str, np.ndarray] = {}
    for idx, (g, yi) in enumerate(zip(groups, y_arr)):
        g_str = str(g)
        if int(yi) == 1:
            pos_clusters.setdefault(g_str, []).append(idx)
        else:
            ben_clusters.setdefault(g_str, []).append(idx)

    if not pos_clusters or not ben_clusters:
        raise ValueError(
            f"Need >= 1 positive cluster and >= 1 benign cluster (pos={len(pos_clusters)}, ben={len(ben_clusters)})"
        )

    pos_keys = sorted(pos_clusters.keys())
    ben_keys = sorted(ben_clusters.keys())
    pos_idx_list = [np.asarray(pos_clusters[k], dtype=int) for k in pos_keys]
    ben_idx_list = [np.asarray(ben_clusters[k], dtype=int) for k in ben_keys]
    n_pos_c = len(pos_idx_list)
    n_ben_c = len(ben_idx_list)

    point_a = float(metric_fn(y_arr, a_arr))
    point_b = float(metric_fn(y_arr, b_arr))
    point_diff = float(point_a - point_b)

    rng = np.random.default_rng(int(seed))
    diffs = np.empty(int(n_boot), dtype=float)
    for b in range(int(n_boot)):
        p_draw = rng.integers(0, n_pos_c, size=n_pos_c)
        n_draw = rng.integers(0, n_ben_c, size=n_ben_c)
        boot_idx = np.concatenate(
            [pos_idx_list[i] for i in p_draw] + [ben_idx_list[j] for j in n_draw]
        )
        yb = y_arr[boot_idx]
        ab = a_arr[boot_idx]
        bb = b_arr[boot_idx]
        diffs[b] = float(metric_fn(yb, ab) - metric_fn(yb, bb))

    lo_q = 100.0 * (float(alpha) / 2.0)
    hi_q = 100.0 * (1.0 - float(alpha) / 2.0)
    ci_lo = float(np.percentile(diffs, lo_q))
    ci_hi = float(np.percentile(diffs, hi_q))

    n_le_zero = int(np.sum(diffs <= 0.0))
    n_ge_zero = int(np.sum(diffs >= 0.0))
    b_tot = float(int(n_boot))
    p_one_side = min((1.0 + n_le_zero) / (1.0 + b_tot), (1.0 + n_ge_zero) / (1.0 + b_tot))
    p_raw = float(min(1.0, 2.0 * p_one_side))

    return {
        "point_a": point_a,
        "point_b": point_b,
        "point_diff": point_diff,
        "ci_lo": ci_lo,
        "ci_hi": ci_hi,
        "p_raw": p_raw,
        "n_boot": int(n_boot),
        "n_pos_clusters": int(n_pos_c),
        "n_ben_clusters": int(n_ben_c),
    }


def holm_bonferroni_adjust(p_values: Sequence[float] | np.ndarray) -> np.ndarray:
    """Apply step-down Holm-Bonferroni adjustment to p-values ONLY (never confidence intervals)."""
    p_arr = np.asarray(p_values, dtype=float).ravel()
    m = len(p_arr)
    if m == 0:
        return np.empty(0, dtype=float)
    if np.any((p_arr < 0.0) | (p_arr > 1.0) | np.isnan(p_arr)):
        raise ValueError("All p_values must be finite floats in [0, 1]")

    order = np.argsort(p_arr, kind="mergesort")
    p_sorted = p_arr[order]
    adj_sorted = np.empty(m, dtype=float)
    running_max = 0.0
    for i in range(m):
        scaled = float(m - i) * float(p_sorted[i])
        running_max = max(running_max, scaled)
        adj_sorted[i] = min(1.0, running_max)

    out = np.empty(m, dtype=float)
    out[order] = adj_sorted
    return out


def _dual_config_verdict(
    diff_full: float,
    p_adj_full: float,
    diff_nocontent: float,
    p_adj_nocontent: float,
    alpha: float = 0.05,
) -> str:
    """Apply pre-registered dual-configuration winner rule (`FINAL_EVAL_PLAN_v2_SKELETON` §6)."""
    sig_full = float(p_adj_full) < float(alpha)
    sig_no = float(p_adj_nocontent) < float(alpha)
    if sig_full and sig_no:
        if diff_full > 0.0 and diff_nocontent > 0.0:
            return "a_better"
        if diff_full < 0.0 and diff_nocontent < 0.0:
            return "b_better"
        return "configuration-dependent"
    if (not sig_full) and (not sig_no):
        return "not distinguishable"
    return "configuration-dependent"


def evaluate_fixed_comparisons_dual_config(
    df_full: pd.DataFrame,
    scores_full: dict[str, Sequence[float] | np.ndarray],
    df_nocontent: pd.DataFrame,
    scores_nocontent: dict[str, Sequence[float] | np.ndarray],
    comparisons: Sequence[tuple[str, str]] = FIXED_V2_COMPARISONS,
    metric_fn: Callable[[np.ndarray, np.ndarray], float] = pr_auc,
    n_boot: int = 2000,
    seed: int = config.BOOTSTRAP_SEED,
    alpha: float = 0.05,
) -> pd.DataFrame:
    """Evaluate fixed pre-registered model pairs across `full_20` and `no_content` without `best_ml` selection.

    Holm-Bonferroni adjusts `p_raw` across the comparison family within each config while leaving
    95% cluster-bootstrap percentile confidence intervals (`ci_lo`, `ci_hi`) unadjusted.
    """
    y_full = (df_full[config.LABEL_COL].astype(str) == config.POSITIVE_LABEL).astype(int).to_numpy()
    y_no = (df_nocontent[config.LABEL_COL].astype(str) == config.POSITIVE_LABEL).astype(int).to_numpy()

    rows: list[dict[str, Any]] = []
    for idx, (arm_a, arm_b) in enumerate(comparisons):
        if arm_a not in scores_full or arm_b not in scores_full:
            raise KeyError(f"Comparison ({arm_a!r}, {arm_b!r}) missing from scores_full")
        if arm_a not in scores_nocontent or arm_b not in scores_nocontent:
            raise KeyError(f"Comparison ({arm_a!r}, {arm_b!r}) missing from scores_nocontent")

        res_full = family_clustered_paired_bootstrap_p(
            metric_fn=metric_fn,
            y=y_full,
            scores_a=scores_full[arm_a],
            scores_b=scores_full[arm_b],
            df=df_full,
            n_boot=n_boot,
            seed=int(seed) + idx * 17,
            alpha=alpha,
        )
        res_no = family_clustered_paired_bootstrap_p(
            metric_fn=metric_fn,
            y=y_no,
            scores_a=scores_nocontent[arm_a],
            scores_b=scores_nocontent[arm_b],
            df=df_nocontent,
            n_boot=n_boot,
            seed=int(seed) + 10_000 + idx * 17,
            alpha=alpha,
        )
        rows.append(
            {
                "arm_a": arm_a,
                "arm_b": arm_b,
                "full_20_point_a": res_full["point_a"],
                "full_20_point_b": res_full["point_b"],
                "full_20_diff": res_full["point_diff"],
                "full_20_ci_lo": res_full["ci_lo"],
                "full_20_ci_hi": res_full["ci_hi"],
                "full_20_p_raw": res_full["p_raw"],
                "no_content_point_a": res_no["point_a"],
                "no_content_point_b": res_no["point_b"],
                "no_content_diff": res_no["point_diff"],
                "no_content_ci_lo": res_no["ci_lo"],
                "no_content_ci_hi": res_no["ci_hi"],
                "no_content_p_raw": res_no["p_raw"],
                "n_pos_clusters_full": res_full["n_pos_clusters"],
                "n_ben_clusters_full": res_full["n_ben_clusters"],
            }
        )

    out_df = pd.DataFrame(rows)
    if len(out_df) == 0:
        return out_df

    out_df["full_20_p_adj"] = holm_bonferroni_adjust(out_df["full_20_p_raw"].to_numpy())
    out_df["no_content_p_adj"] = holm_bonferroni_adjust(out_df["no_content_p_raw"].to_numpy())
    out_df["verdict"] = [
        _dual_config_verdict(
            diff_full=float(r["full_20_diff"]),
            p_adj_full=float(r["full_20_p_adj"]),
            diff_nocontent=float(r["no_content_diff"]),
            p_adj_nocontent=float(r["no_content_p_adj"]),
            alpha=alpha,
        )
        for _, r in out_df.iterrows()
    ]
    return out_df


def calibrate_dev_threshold(
    y_dev_oof: Sequence[int] | np.ndarray,
    scores_dev_oof: Sequence[float] | np.ndarray,
    target_fpr: float = 0.01,
) -> dict[str, float]:
    """Select a deployable decision threshold strictly from benign nested dev OOF scores (`IMP-11`)."""
    y_arr = np.asarray(y_dev_oof, dtype=int).ravel()
    s_arr = np.asarray(scores_dev_oof, dtype=float).ravel()
    if len(y_arr) != len(s_arr):
        raise ValueError("y_dev_oof and scores_dev_oof length mismatch")
    ben_scores = s_arr[y_arr == 0]
    if len(ben_scores) == 0:
        raise ValueError("calibrate_dev_threshold requires >= 1 benign dev OOF row")

    thr = float(threshold_at_fpr(ben_scores, float(target_fpr)))
    return {
        "threshold": thr,
        "target_fpr": float(target_fpr),
        "achieved_dev_oof_fpr": float(fpr_at_threshold(y_arr, s_arr, thr)),
        "achieved_dev_oof_recall": float(recall_at_threshold(y_arr, s_arr, thr)),
        "n_benign_oof": int(len(ben_scores)),
    }


def evaluate_frozen_threshold(
    y_eval: Sequence[int] | np.ndarray,
    scores_eval: Sequence[float] | np.ndarray,
    threshold: float,
) -> dict[str, float]:
    """Evaluate a dev-frozen decision threshold once on an evaluation set (`IMP-11`)."""
    y_arr = np.asarray(y_eval, dtype=int).ravel()
    s_arr = np.asarray(scores_eval, dtype=float).ravel()
    thr = float(threshold)
    return {
        "threshold": thr,
        "recall": float(recall_at_threshold(y_arr, s_arr, thr)),
        "fpr": float(fpr_at_threshold(y_arr, s_arr, thr)),
        "accuracy": float(accuracy_at_threshold(y_arr, s_arr, thr)),
        "f1": float(f1_at_threshold(y_arr, s_arr, thr)),
    }


def compute_lofo_table(
    oof_df: pd.DataFrame,
    score_cols: Sequence[str],
    family_col: str = "sample_family",
    label_col: str = config.LABEL_COL,
) -> pd.DataFrame:
    """Compute per-family leave-one-family-out (LOFO) ranking metrics against the full benign OOF pool."""
    if label_col not in oof_df.columns:
        raise KeyError(f"Missing label_col {label_col!r} in oof_df")

    y_all = (oof_df[label_col].astype(str) == config.POSITIVE_LABEL).to_numpy()
    ben_mask = ~y_all
    if int(np.sum(ben_mask)) == 0 or int(np.sum(y_all)) == 0:
        raise ValueError("compute_lofo_table requires both positive and benign rows in oof_df")

    eff_families = pd.Series(index=oof_df.index, dtype=object)
    for idx in oof_df.index[y_all]:
        row = oof_df.loc[idx]
        fam = row.get(family_col) if family_col in oof_df.columns else None
        if fam is None or (isinstance(fam, float) and math.isnan(fam)) or str(fam).strip() in ("", "nan", "None"):
            fam = row.get("technique_id", "unknown_family")
        eff_families.loc[idx] = str(fam).strip()

    unique_fams = sorted(eff_families.dropna().unique())
    records: list[dict[str, Any]] = []
    for fam in unique_fams:
        fam_pos_mask = y_all & (eff_families == fam).to_numpy()
        eval_mask = ben_mask | fam_pos_mask
        sub_df = oof_df.loc[eval_mask]
        y_sub = (sub_df[label_col].astype(str) == config.POSITIVE_LABEL).astype(int).to_numpy()
        n_pos = int(np.sum(y_sub == 1))
        n_ben = int(np.sum(y_sub == 0))

        for sc in score_cols:
            if sc not in sub_df.columns:
                raise KeyError(f"Score column {sc!r} not found in oof_df")
            s_sub = sub_df[sc].astype(float).to_numpy()
            tail = tail_risk_and_effort_metrics(y_sub, s_sub, budgets=(10, 50), recall_targets=(0.50, 0.90))
            records.append(
                {
                    "family": fam,
                    "model": sc,
                    "n_pos": n_pos,
                    "n_benign": n_ben,
                    "pr_auc": float(pr_auc(y_sub, s_sub)),
                    "roc_auc": float(roc_auc(y_sub, s_sub)),
                    "tie_expected_precision_at_10": float(tail["tie_expected_precision_at_10"]),
                    "worst_positive_rank": int(tail["worst_positive_rank"]),
                    "effort_at_recall_50_count": int(tail["effort_at_recall_50_count"]),
                }
            )

    return pd.DataFrame(records)


def cross_stratum_execution_delta(
    paired_df: pd.DataFrame,
    score_col: str,
    pair_col: str = "pair_group_id",
    stratum_col: str = "execution_state",
    run_col: str = "run_id",
    budgets: Sequence[int] = (5, 10, 20, 50),
    n_boot: int = 1000,
    seed: int = config.BOOTSTRAP_SEED,
) -> dict[str, Any]:
    """Compute Concept C (`OD-V2-15`) Cross-Stratum Execution Delta (`executed` vs `dormant`) on paired binaries.

    Evaluates:
    1. Stratum-conditional `PR-AUC` delta (`Delta_exec = PR-AUC(executed) - PR-AUC(dormant)`) with
       family-clustered paired bootstrap 95% CIs and two-sided `p_raw`.
    2. Sample-level first-detection rank `Rank_min(s, stratum)` inside each sample's host run, plus
       median and IQR of `Delta_first_hit(s) = Rank_min(s, dormant) - Rank_min(s, executed)`.
    3. Intrusion-Detection Recall@k (`k in {5, 10, 20, 50}`): fraction of paired samples with at least
       one `attacker_induced` artifact inside the top `k` ranked leads of its host run.
    """
    for req in (score_col, stratum_col, config.LABEL_COL):
        if req not in paired_df.columns:
            raise KeyError(f"Required column {req!r} missing from paired_df")

    eff_pair_col = pair_col if pair_col in paired_df.columns else "sample_sha256"
    if eff_pair_col not in paired_df.columns:
        raise KeyError(f"Neither {pair_col!r} nor 'sample_sha256' found in paired_df")

    df_loc = paired_df.copy().reset_index(drop=True)
    y_all = (df_loc[config.LABEL_COL].astype(str) == config.POSITIVE_LABEL).astype(int).to_numpy()
    strata = df_loc[stratum_col].astype(str).str.lower().to_numpy()

    pos_df = df_loc[y_all == 1]
    dorm_pairs = set(pos_df.loc[pos_df[stratum_col].astype(str).str.lower() == "dormant", eff_pair_col].dropna().astype(str))
    exec_pairs = set(pos_df.loc[pos_df[stratum_col].astype(str).str.lower() == "executed", eff_pair_col].dropna().astype(str))
    common_pairs = sorted(dorm_pairs & exec_pairs)
    if not common_pairs:
        raise ValueError("No paired sample_sha256/pair_group_id found with positives in both dormant and executed strata")

    exec_mask = strata == "executed"
    dorm_mask = strata == "dormant"
    y_exec = y_all[exec_mask]
    s_exec = df_loc.loc[exec_mask, score_col].astype(float).to_numpy()
    y_dorm = y_all[dorm_mask]
    s_dorm = df_loc.loc[dorm_mask, score_col].astype(float).to_numpy()

    pr_exec = float(pr_auc(y_exec, s_exec))
    pr_dorm = float(pr_auc(y_dorm, s_dorm))
    delta_exec = float(pr_exec - pr_dorm)

    # Family-clustered bootstrap over whole clusters so paired dormant & executed runs resample together
    groups = build_family_cluster_groups(df_loc)
    pos_clusters: dict[str, np.ndarray] = {}
    ben_clusters: dict[str, np.ndarray] = {}
    for idx, (g, yi) in enumerate(zip(groups, y_all)):
        if int(yi) == 1:
            pos_clusters.setdefault(str(g), []).append(idx)
        else:
            ben_clusters.setdefault(str(g), []).append(idx)

    pos_list = [np.asarray(pos_clusters[k], dtype=int) for k in sorted(pos_clusters)]
    ben_list = [np.asarray(ben_clusters[k], dtype=int) for k in sorted(ben_clusters)]
    rng = np.random.default_rng(int(seed))
    boot_deltas: list[float] = []
    scores_all = df_loc[score_col].astype(float).to_numpy()

    for _ in range(int(n_boot)):
        p_draw = rng.integers(0, len(pos_list), size=len(pos_list))
        n_draw = rng.integers(0, len(ben_list), size=len(ben_list))
        b_idx = np.concatenate([pos_list[i] for i in p_draw] + [ben_list[j] for j in n_draw])
        b_strata = strata[b_idx]
        b_y = y_all[b_idx]
        b_s = scores_all[b_idx]
        e_m = b_strata == "executed"
        d_m = b_strata == "dormant"
        if np.sum(b_y[e_m] == 1) > 0 and np.sum(b_y[e_m] == 0) > 0 and np.sum(b_y[d_m] == 1) > 0 and np.sum(b_y[d_m] == 0) > 0:
            boot_deltas.append(float(pr_auc(b_y[e_m], b_s[e_m]) - pr_auc(b_y[d_m], b_s[d_m])))

    boot_arr = np.asarray(boot_deltas, dtype=float) if boot_deltas else np.array([delta_exec], dtype=float)
    ci_lo = float(np.percentile(boot_arr, 2.5))
    ci_hi = float(np.percentile(boot_arr, 97.5))
    b_len = float(len(boot_arr))
    p_raw = float(
        min(
            1.0,
            2.0 * min((1.0 + np.sum(boot_arr <= 0.0)) / (1.0 + b_len), (1.0 + np.sum(boot_arr >= 0.0)) / (1.0 + b_len)),
        )
    )

    # Per-sample Rank_min(s, stratum) inside each host run
    sample_records: list[dict[str, Any]] = []
    for pid in common_pairs:
        ranks_by_stratum: dict[str, int] = {}
        pct_by_stratum: dict[str, float] = {}
        for st in ("dormant", "executed"):
            st_pos = df_loc[(y_all == 1) & (strata == st) & (df_loc[eff_pair_col].astype(str) == pid)]
            if run_col in df_loc.columns and st_pos[run_col].notna().any():
                run_ids = st_pos[run_col].dropna().astype(str).unique()
                run_sub = df_loc[df_loc[run_col].astype(str).isin(run_ids)]
            else:
                run_sub = df_loc[strata == st]
            w_ranks = _worst_case_descending_ranks(run_sub[score_col].astype(float).to_numpy())
            is_target_pos = (
                (run_sub[config.LABEL_COL].astype(str) == config.POSITIVE_LABEL)
                & (run_sub[eff_pair_col].astype(str) == pid)
            ).to_numpy()
            r_min = int(np.min(w_ranks[is_target_pos]))
            ranks_by_stratum[st] = r_min
            pct_by_stratum[st] = float(r_min / float(len(run_sub)))

        sample_records.append(
            {
                "pair_id": pid,
                "rank_min_dormant": ranks_by_stratum["dormant"],
                "rank_min_executed": ranks_by_stratum["executed"],
                "pct_min_dormant": pct_by_stratum["dormant"],
                "pct_min_executed": pct_by_stratum["executed"],
                "delta_first_hit": int(ranks_by_stratum["dormant"] - ranks_by_stratum["executed"]),
            }
        )

    sample_df = pd.DataFrame(sample_records)
    deltas_fh = sample_df["delta_first_hit"].to_numpy(dtype=float)
    q75, q25 = np.percentile(deltas_fh, [75.0, 25.0])

    out: dict[str, Any] = {
        "n_paired_samples": int(len(common_pairs)),
        "pr_auc_executed": pr_exec,
        "pr_auc_dormant": pr_dorm,
        "delta_exec_pr_auc": delta_exec,
        "delta_exec_ci_lo": ci_lo,
        "delta_exec_ci_hi": ci_hi,
        "delta_exec_p_raw": p_raw,
        "delta_first_hit_median": float(np.median(deltas_fh)),
        "delta_first_hit_iqr": float(q75 - q25),
        "per_sample_df": sample_df,
    }
    for k in budgets:
        k_int = int(k)
        out[f"intrusion_recall_at_{k_int}_executed"] = float(np.mean(sample_df["rank_min_executed"] <= k_int))
        out[f"intrusion_recall_at_{k_int}_dormant"] = float(np.mean(sample_df["rank_min_dormant"] <= k_int))

    return out
