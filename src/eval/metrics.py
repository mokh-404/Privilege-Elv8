"""Ranking metrics (doc 07 section 4). Scores: higher = ranked as more attacker-like.

All functions are deterministic. Ties in ranking are broken by original row order
(stable sort on -score), so results never depend on hidden randomness.
Accuracy is provided only as a secondary metric for Track B split 1 (literature comparison).
"""
from __future__ import annotations

from typing import Callable, Sequence

import numpy as np
from sklearn.metrics import accuracy_score, average_precision_score, f1_score, roc_auc_score


def _arr(y, s=None):
    y = np.asarray(y).astype(int).ravel()
    if s is None:
        return y
    s = np.asarray(s, dtype=float).ravel()
    if y.shape != s.shape:
        raise ValueError(f"y and scores differ in shape: {y.shape} vs {s.shape}")
    return y, s


def rank_order(scores) -> np.ndarray:
    """Indices sorted by descending score; ties keep original order (stable)."""
    s = np.asarray(scores, dtype=float).ravel()
    return np.argsort(-s, kind="stable")


def pr_auc(y, scores) -> float:
    """Average precision (PR-AUC). NaN if there are no positives."""
    y, s = _arr(y, scores)
    if y.sum() == 0:
        return float("nan")
    return float(average_precision_score(y, s))


def roc_auc(y, scores) -> float:
    y, s = _arr(y, scores)
    if y.sum() == 0 or y.sum() == len(y):
        return float("nan")
    return float(roc_auc_score(y, s))


def precision_at_k(y, scores, k: int) -> float:
    """Fraction of positives among the top-k ranked rows. If k > n, uses k_eff = n."""
    y, s = _arr(y, scores)
    if len(y) == 0 or k <= 0:
        return float("nan")
    k_eff = min(k, len(y))
    top = rank_order(s)[:k_eff]
    return float(y[top].sum() / k_eff)


def recall_at_k(y, scores, k: int) -> float:
    """Fraction of all positives that appear in the top-k ranked rows. NaN if no positives."""
    y, s = _arr(y, scores)
    n_pos = y.sum()
    if n_pos == 0 or k <= 0:
        return float("nan")
    top = rank_order(s)[: min(k, len(y))]
    return float(y[top].sum() / n_pos)


def _expected_positives_in_top_k(y: np.ndarray, s: np.ndarray, k: int) -> float:
    """Expected number of positives in top-k under uniform random tie breaking."""
    k_eff = min(int(k), len(y))
    _, inv, counts = np.unique(-s, return_inverse=True, return_counts=True)
    pos_counts = np.bincount(inv, weights=y, minlength=len(counts))
    cum_n = np.cumsum(counts)
    cum_pos = np.cumsum(pos_counts)
    boundary = int(np.searchsorted(cum_n, k_eff, side="left"))
    prev_n = int(cum_n[boundary - 1]) if boundary > 0 else 0
    prev_pos = float(cum_pos[boundary - 1]) if boundary > 0 else 0.0
    rem = k_eff - prev_n
    return float(prev_pos + rem * (pos_counts[boundary] / counts[boundary]))


def tie_expected_precision_at_k(y, scores, k: int) -> float:
    """Order-invariant Precision@k computing exact expectation across tied score groups."""
    y, s = _arr(y, scores)
    if len(y) == 0 or k <= 0:
        return float("nan")
    k_eff = min(int(k), len(y))
    return float(_expected_positives_in_top_k(y, s, k_eff) / k_eff)


def tie_expected_recall_at_k(y, scores, k: int) -> float:
    """Order-invariant Recall@k computing exact expectation across tied score groups."""
    y, s = _arr(y, scores)
    n_pos = int(y.sum())
    if len(y) == 0 or n_pos == 0 or k <= 0:
        return float("nan")
    return float(_expected_positives_in_top_k(y, s, k) / n_pos)


def grouped_at_k(fn: Callable, y, scores, groups, k: int) -> float:
    """Mean of a per-group @k metric (e.g. per host / run_id), ignoring NaN groups."""
    y, s = _arr(y, scores)
    g = np.asarray(groups).ravel()
    vals = []
    for gv in np.unique(g):
        m = g == gv
        v = fn(y[m], s[m], k)
        if not np.isnan(v):
            vals.append(v)
    return float(np.mean(vals)) if vals else float("nan")


def threshold_at_recall(y, scores, recall: float = 0.9) -> float:
    """Highest score threshold t such that recall(score >= t) >= target. NaN if no positives."""
    y, s = _arr(y, scores)
    pos = np.sort(s[y == 1])[::-1]
    if len(pos) == 0:
        return float("nan")
    n_needed = int(np.ceil(recall * len(pos) - 1e-12))
    n_needed = min(max(n_needed, 1), len(pos))
    return float(pos[n_needed - 1])


def fpr_at_recall(y, scores, recall: float = 0.9, negative_mask=None) -> float:
    """FPR among negatives (optionally restricted by negative_mask, e.g. clean baseline rows)
    at the highest threshold that reaches the target recall on positives."""
    y, s = _arr(y, scores)
    t = threshold_at_recall(y, s, recall)
    if np.isnan(t):
        return float("nan")
    neg = y == 0
    if negative_mask is not None:
        neg = neg & np.asarray(negative_mask, dtype=bool).ravel()
    if neg.sum() == 0:
        return float("nan")
    return float((s[neg] >= t).sum() / neg.sum())


def threshold_at_fpr(benign_val_scores, fpr: float) -> float:
    """Threshold from a benign validation portion so that about `fpr` of benign scores are >= it.
    Uses the (1 - fpr) empirical quantile with 'higher' interpolation (conservative)."""
    b = np.asarray(benign_val_scores, dtype=float).ravel()
    if len(b) == 0:
        return float("nan")
    return float(np.quantile(b, 1.0 - fpr, method="higher"))


def recall_at_threshold(y, scores, threshold: float) -> float:
    """Recall on positives at score > threshold (strict, matching threshold_at_fpr)."""
    y, s = _arr(y, scores)
    if y.sum() == 0 or np.isnan(threshold):
        return float("nan")
    return float((s[y == 1] > threshold).sum() / y.sum())


def fpr_at_threshold(y, scores, threshold: float) -> float:
    y, s = _arr(y, scores)
    neg = y == 0
    if neg.sum() == 0 or np.isnan(threshold):
        return float("nan")
    return float((s[neg] > threshold).sum() / neg.sum())


def accuracy_at_threshold(y, scores, threshold: float) -> float:
    """SECONDARY metric only (Track B split 1 literature comparison)."""
    y, s = _arr(y, scores)
    return float(accuracy_score(y, (s > threshold).astype(int)))


def f1_at_threshold(y, scores, threshold: float) -> float:
    y, s = _arr(y, scores)
    return float(f1_score(y, (s > threshold).astype(int), zero_division=0))


def bootstrap_by_group(
    metric: Callable[[np.ndarray, np.ndarray], float],
    y, scores, groups,
    n_boot: int = 1000, seed: int = 42, alpha: float = 0.05,
) -> dict:
    """Percentile CI by resampling GROUPS (e.g. run_id) with replacement.

    The interval covers group-to-group (run-to-run) variation, not generalisation to new techniques.
    """
    y, s = _arr(y, scores)
    g = np.asarray(groups).ravel()
    uniq = np.unique(g)
    idx_by_g = {gv: np.flatnonzero(g == gv) for gv in uniq}
    rng = np.random.default_rng(seed)
    vals = []
    for _ in range(n_boot):
        pick = rng.choice(uniq, size=len(uniq), replace=True)
        idx = np.concatenate([idx_by_g[p] for p in pick])
        v = metric(y[idx], s[idx])
        if not np.isnan(v):
            vals.append(v)
    point = metric(y, s)
    if not vals:
        return {"point": point, "lo": float("nan"), "hi": float("nan"), "n_boot_valid": 0}
    lo, hi = np.quantile(vals, [alpha / 2, 1 - alpha / 2])
    return {"point": point, "lo": float(lo), "hi": float(hi), "n_boot_valid": len(vals)}


def _build_group_map(indices: np.ndarray, keys: np.ndarray) -> tuple[np.ndarray, dict[str, np.ndarray]]:
    sub_keys = keys[indices].astype(str)
    uniq = np.unique(sub_keys)
    return uniq, {k: indices[sub_keys == k] for k in uniq}


def _prepare_track_a_strata(y: np.ndarray, df, group_by: str) -> dict:
    """Build stratification/cluster index structures for Track A bootstrap."""
    if group_by not in ("run_id", "technique_id"):
        raise ValueError(f"group_by must be 'run_id' or 'technique_id', got {group_by!r}")
    if len(y) != len(df):
        raise ValueError(f"df length ({len(df)}) != y length ({len(y)})")

    has_label = "label" in df.columns
    has_run = "run_id" in df.columns
    has_tech = "technique_id" in df.columns

    if has_label:
        lbl = df["label"].astype(str).to_numpy()
        base_idx = np.flatnonzero(lbl == "baseline")
        drift_idx = np.flatnonzero((lbl != "baseline") & (y == 0))
        non_base_idx = np.flatnonzero(lbl != "baseline")
    else:
        base_idx = np.flatnonzero(y == 0)
        drift_idx = np.empty(0, dtype=int)
        non_base_idx = np.flatnonzero(y == 1)

    pos_idx = np.flatnonzero(y == 1)
    run_vals = df["run_id"].fillna("UNKNOWN").astype(str).to_numpy() if has_run else np.empty(0, dtype=str)
    tech_vals = df["technique_id"].fillna("UNKNOWN").astype(str).to_numpy() if has_tech else np.empty(0, dtype=str)

    if group_by == "run_id":
        nb_uniq, nb_map = _build_group_map(non_base_idx, run_vals) if (has_run and len(non_base_idx)) else (np.empty(0, dtype=str), {})
        pos_uniq, pos_map = np.empty(0, dtype=str), {}
        dr_uniq, dr_map = np.empty(0, dtype=str), {}
    else:
        nb_uniq, nb_map = np.empty(0, dtype=str), {}
        pos_uniq, pos_map = _build_group_map(pos_idx, tech_vals) if (has_tech and len(pos_idx)) else (np.empty(0, dtype=str), {})
        dr_uniq, dr_map = _build_group_map(drift_idx, run_vals) if (has_run and len(drift_idx)) else (np.empty(0, dtype=str), {})

    return {
        "base_idx": base_idx,
        "drift_idx": drift_idx,
        "non_base_idx": non_base_idx,
        "pos_idx": pos_idx,
        "nb_uniq": nb_uniq,
        "nb_map": nb_map,
        "pos_uniq": pos_uniq,
        "pos_map": pos_map,
        "dr_uniq": dr_uniq,
        "dr_map": dr_map,
    }


def _sample_track_a_indices(strata: dict, group_by: str, rng: np.random.Generator) -> np.ndarray | None:
    """Draw one stratified/clustered bootstrap index vector (exact RNG draw order)."""
    parts: list[np.ndarray] = []
    if group_by == "run_id":
        nb_uniq = strata["nb_uniq"]
        if len(nb_uniq):
            pick = rng.choice(nb_uniq, size=len(nb_uniq), replace=True)
            nb_map = strata["nb_map"]
            parts.extend(nb_map[p] for p in pick)
        elif len(strata["non_base_idx"]):
            nb_i = strata["non_base_idx"]
            parts.append(rng.choice(nb_i, size=len(nb_i), replace=True))
        if len(strata["base_idx"]):
            b_i = strata["base_idx"]
            parts.append(rng.choice(b_i, size=len(b_i), replace=True))
    else:
        pos_uniq = strata["pos_uniq"]
        if len(pos_uniq):
            pick_t = rng.choice(pos_uniq, size=len(pos_uniq), replace=True)
            pos_map = strata["pos_map"]
            parts.extend(pos_map[p] for p in pick_t)
        elif len(strata["pos_idx"]):
            p_i = strata["pos_idx"]
            parts.append(rng.choice(p_i, size=len(p_i), replace=True))
        dr_uniq = strata["dr_uniq"]
        if len(dr_uniq):
            pick_d = rng.choice(dr_uniq, size=len(dr_uniq), replace=True)
            dr_map = strata["dr_map"]
            parts.extend(dr_map[p] for p in pick_d)
        elif len(strata["drift_idx"]):
            d_i = strata["drift_idx"]
            parts.append(rng.choice(d_i, size=len(d_i), replace=True))
        if len(strata["base_idx"]):
            b_i = strata["base_idx"]
            parts.append(rng.choice(b_i, size=len(b_i), replace=True))
    return np.concatenate(parts) if parts else None


def bootstrap_track_a(
    metric: Callable[[np.ndarray, np.ndarray], float],
    y,
    scores,
    df,
    group_by: str = "run_id",
    n_boot: int = 1000,
    seed: int = 42,
    alpha: float = 0.05,
) -> dict:
    """Stratified percentile bootstrap CI for Track A by 'run_id' or 'technique_id'.

    Because deduplicated `baseline` rows are anchored largely to ctrl_01 and benign rows
    have no technique_id:
      - group_by='run_id': cluster non-baseline rows (label != 'baseline') by `run_id`
        and resample baseline rows independently with replacement.
      - group_by='technique_id': cluster positive rows (y == 1) by `technique_id`,
        cluster `benign_drift` rows by `run_id`, and resample `baseline` rows by row.
    """
    y, s = _arr(y, scores)
    strata = _prepare_track_a_strata(y, df, group_by)
    point = float(metric(y, s))

    rng = np.random.default_rng(seed)
    vals: list[float] = []
    for _ in range(int(n_boot)):
        idx = _sample_track_a_indices(strata, group_by, rng)
        if idx is None:
            continue
        y_b = y[idx]
        if (y_b == 1).sum() == 0 or (y_b == 0).sum() == 0:
            continue
        v = float(metric(y_b, s[idx]))
        if not np.isnan(v):
            vals.append(v)

    if not vals or np.isnan(point):
        return {"point": point, "lo": float("nan"), "hi": float("nan"), "n_boot_valid": 0, "group_by": group_by}
    lo, hi = np.quantile(vals, [alpha / 2, 1 - alpha / 2])
    return {"point": point, "lo": float(lo), "hi": float(hi), "n_boot_valid": len(vals), "group_by": group_by}


def paired_bootstrap_track_a(
    metric: Callable[[np.ndarray, np.ndarray], float],
    y,
    scores_a,
    scores_b,
    df,
    group_by: str = "run_id",
    n_boot: int = 1000,
    seed: int = 42,
    alpha: float = 0.05,
) -> dict:
    """Paired stratified percentile bootstrap for metric(A) - metric(B) on shared clusters."""
    y_a, sa = _arr(y, scores_a)
    y_b_chk, sb = _arr(y, scores_b)
    if sa.shape != sb.shape:
        raise ValueError(f"scores_a and scores_b differ in shape: {sa.shape} vs {sb.shape}")
    strata = _prepare_track_a_strata(y_a, df, group_by)

    point_a = float(metric(y_a, sa))
    point_b = float(metric(y_b_chk, sb))
    diff = point_a - point_b

    rng = np.random.default_rng(seed)
    diffs: list[float] = []
    for _ in range(int(n_boot)):
        idx = _sample_track_a_indices(strata, group_by, rng)
        if idx is None:
            continue
        y_sub = y_a[idx]
        if (y_sub == 1).sum() == 0 or (y_sub == 0).sum() == 0:
            continue
        va = float(metric(y_sub, sa[idx]))
        vb = float(metric(y_sub, sb[idx]))
        if not (np.isnan(va) or np.isnan(vb)):
            diffs.append(va - vb)

    if not diffs or np.isnan(diff):
        return {
            "point_a": point_a,
            "point_b": point_b,
            "diff": diff,
            "ci_lo": float("nan"),
            "ci_hi": float("nan"),
            "excludes_zero": False,
            "verdict": "not distinguishable",
            "n_boot_valid": 0,
            "group_by": group_by,
        }
    lo, hi = np.quantile(diffs, [alpha / 2, 1 - alpha / 2])
    lo_f, hi_f = float(lo), float(hi)
    excludes_zero = bool(lo_f > 0.0 or hi_f < 0.0)
    if excludes_zero:
        verdict = "a_better" if lo_f > 0.0 else "b_better"
    else:
        verdict = "not distinguishable"
    return {
        "point_a": point_a,
        "point_b": point_b,
        "diff": float(diff),
        "ci_lo": lo_f,
        "ci_hi": hi_f,
        "excludes_zero": excludes_zero,
        "verdict": verdict,
        "n_boot_valid": len(diffs),
        "group_by": group_by,
    }


def ranking_report(y, scores, ks: Sequence[int] = (10, 50, 100), recall: float = 0.9,
                   negative_mask=None, groups=None) -> dict:
    """Standard Track A metric bundle for one arm."""
    out = {"pr_auc": pr_auc(y, scores), "roc_auc": roc_auc(y, scores),
           f"fpr_at_recall_{recall}": fpr_at_recall(y, scores, recall, negative_mask)}
    for k in ks:
        if groups is None:
            out[f"precision_at_{k}"] = precision_at_k(y, scores, k)
            out[f"recall_at_{k}"] = recall_at_k(y, scores, k)
        else:
            out[f"precision_at_{k}"] = grouped_at_k(precision_at_k, y, scores, groups, k)
            out[f"recall_at_{k}"] = grouped_at_k(recall_at_k, y, scores, groups, k)
    return out
