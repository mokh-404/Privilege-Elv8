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
