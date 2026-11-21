"""Leakage-proof splitting helpers for Track A (key hash buckets) and Track B.

Track A:
    - Benign rows (`baseline` and `benign_drift`) are hashed by `artifact_key` so one key
      never appears in both train and test.
    - `attacker_induced` rows are NEVER bucketed by hash; they stay grouped by `technique_id`.

Track B (CIC-MalMem-2022):
    - Split 1: stratified 80/20 reproduction split (marked LEAKY everywhere).
    - Split 2: family-grouped holdout of 1 family per malware category (3 held out) plus
      k-means cluster grouping of benign rows into disjoint train / val / test pools.
    - 5-rotation generator: holds out every one of the 15 families exactly once.
"""
from __future__ import annotations

import hashlib
from typing import Sequence

import numpy as np
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from src import config


# --------------------------------------------------------------------------------------
# Track A benign hash-bucket assignment (Prompt B step 3, doc 07 section 2)
# --------------------------------------------------------------------------------------

def artifact_key_bucket(key: str) -> int:
    """Deterministic bucket in [0, 99] from sha256(artifact_key)."""
    if not isinstance(key, str) or not key:
        raise ValueError(f"artifact_key must be a non-empty string, got {key!r}")
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()
    return int(digest[:8], 16) % config.BENIGN_BUCKET_MOD


def benign_pool(key: str) -> str:
    """'test' if bucket >= 75, else 'dev'."""
    return "test" if artifact_key_bucket(key) >= config.BENIGN_TEST_BUCKET_MIN else "dev"


def benign_dev_fold(key: str) -> int:
    """Development fold in [0, N_DEV_FOLDS - 1] for dev-pool keys."""
    b = artifact_key_bucket(key)
    if b >= config.BENIGN_TEST_BUCKET_MIN:
        raise ValueError(f"Key {key!r} belongs to the test pool (bucket={b}), not a dev fold")
    return b % config.N_DEV_FOLDS


# --------------------------------------------------------------------------------------
# Track B Split 1: stratified 80/20 (LEAKY reproduction split)
# --------------------------------------------------------------------------------------

def track_b_split1_leaky(
    y: np.ndarray,
    test_size: float = config.TRACK_B_SPLIT1_TEST_SIZE,
    val_fraction_of_train: float = 0.15,
    seed: int = config.SEED,
) -> dict:
    """Stratified 80/20 split (LEAKY by construction due to 15s sibling dumps + SMOTE)."""
    y_arr = np.asarray(y).astype(int).ravel()
    idx = np.arange(len(y_arr))
    train_all_idx, test_idx = train_test_split(
        idx, test_size=test_size, stratify=y_arr, random_state=seed,
    )
    train_idx, val_idx = train_test_split(
        train_all_idx, test_size=val_fraction_of_train, stratify=y_arr[train_all_idx], random_state=seed,
    )
    train_idx = np.sort(train_idx)
    val_idx = np.sort(val_idx)
    train_all_idx = np.sort(train_all_idx)
    test_idx = np.sort(test_idx)
    benign_val_idx = val_idx[y_arr[val_idx] == 0]
    assert set(train_all_idx).isdisjoint(test_idx)
    assert set(train_idx).isdisjoint(val_idx)
    return {
        "split_name": "split1_stratified_leaky",
        "split_note": config.TRACK_B_SPLIT1_TAG,
        "seed": int(seed),
        "train_idx": train_idx,
        "val_idx": val_idx,
        "train_all_idx": train_all_idx,
        "benign_val_idx": benign_val_idx,
        "test_idx": test_idx,
    }


# --------------------------------------------------------------------------------------
# Track B Split 2: family-grouped holdout + benign k-means cluster grouping
# --------------------------------------------------------------------------------------

def _assign_benign_clusters(
    X_benign: pd.DataFrame,
    benign_indices: np.ndarray,
    n_clusters: int,
    test_frac: float,
    val_frac: float,
    seed: int,
) -> tuple[np.ndarray, np.ndarray, np.ndarray, dict[str, int]]:
    if len(benign_indices) < 3:
        raise ValueError("Need at least 3 benign rows to partition into train/val/test clusters")
    k = min(int(n_clusters), max(3, len(benign_indices) // 2))
    prep = Pipeline([
        ("imp", SimpleImputer(strategy="constant", fill_value=0.0)),
        ("scale", StandardScaler()),
    ])
    X_scaled = prep.fit_transform(X_benign)
    km = KMeans(n_clusters=k, random_state=seed, n_init="auto")
    labels = km.fit_predict(X_scaled)

    uniq_cids = np.unique(labels)
    if len(uniq_cids) < 3:
        raise ValueError(f"KMeans produced only {len(uniq_cids)} unique cluster(s); need >= 3")

    rng = np.random.default_rng(seed)
    order = rng.permutation(uniq_cids)
    total = len(benign_indices)
    target_test = max(1, int(round(test_frac * total)))
    target_val = max(1, int(round(val_frac * total)))

    test_cids, val_cids, train_cids = [], [], []
    n_test = 0
    n_val = 0
    for i, cid in enumerate(order):
        rem_clusters = len(order) - i
        csize = int((labels == cid).sum())
        # Always reserve at least 2 clusters for val + train while filling test,
        # and at least 1 cluster for train while filling val.
        if n_test < target_test and rem_clusters > 2:
            test_cids.append(cid)
            n_test += csize
        elif n_val < target_val and rem_clusters > 1:
            val_cids.append(cid)
            n_val += csize
        else:
            train_cids.append(cid)

    assert test_cids and val_cids and train_cids
    assert set(test_cids).isdisjoint(val_cids)
    assert set(test_cids).isdisjoint(train_cids)
    assert set(val_cids).isdisjoint(train_cids)

    test_idx = np.sort(benign_indices[np.isin(labels, test_cids)])
    val_idx = np.sort(benign_indices[np.isin(labels, val_cids)])
    train_idx = np.sort(benign_indices[np.isin(labels, train_cids)])
    counts = {
        "n_clusters_total": int(len(uniq_cids)),
        "n_clusters_train": len(train_cids),
        "n_clusters_val": len(val_cids),
        "n_clusters_test": len(test_cids),
    }
    return train_idx, val_idx, test_idx, counts


def track_b_split2_family_grouped(
    X_df: pd.DataFrame,
    y: np.ndarray,
    categories: pd.Series,
    families: pd.Series,
    held_out_families: Sequence[str] | None = None,
    draw_seed: int = config.TRACK_B_HOLDOUT_DRAW_SEED,
    kmeans_seed: int = config.TRACK_B_KMEANS_SEED,
    n_clusters: int = config.TRACK_B_N_BENIGN_CLUSTERS,
    benign_test_frac: float = config.TRACK_B_BENIGN_TEST_FRACTION,
    benign_val_frac: float = config.TRACK_B_BENIGN_VAL_FRACTION,
) -> dict:
    """Family-grouped holdout (3 unseen families: 1 per malware category) + clustered benign."""
    y_arr = np.asarray(y).astype(int).ravel()
    cats = pd.Series(categories).reset_index(drop=True)
    fams = pd.Series(families).reset_index(drop=True)
    if not (len(X_df) == len(y_arr) == len(cats) == len(fams)):
        raise ValueError("X_df, y, categories, families must have identical length")

    mal_mask = y_arr == 1
    benign_idx = np.flatnonzero(y_arr == 0)
    mal_cats = sorted(cats[mal_mask].unique())
    if not mal_cats:
        raise ValueError("No malware rows present")

    rng = np.random.default_rng(draw_seed)
    if held_out_families is None:
        chosen = []
        for c in mal_cats:
            c_fams = sorted(fams[mal_mask & (cats == c)].unique())
            chosen.append(str(rng.choice(c_fams)))
        held_out = tuple(chosen)
    else:
        held_out = tuple(str(f) for f in held_out_families)

    held_set = set(held_out)
    all_mal_fams = set(fams[mal_mask].unique())
    unknown = held_set - all_mal_fams
    if unknown:
        raise ValueError(f"Unknown held_out_families: {sorted(unknown)}")

    # Group-stratified inner validation family (1 per category from remaining families)
    val_fams = []
    for c in mal_cats:
        rem = sorted(set(fams[mal_mask & (cats == c)].unique()) - held_set)
        if len(rem) >= 2:
            val_fams.append(str(rng.choice(rem)))
    val_fam_set = set(val_fams)

    mal_test_idx = np.flatnonzero(mal_mask & fams.isin(held_set))
    mal_val_idx = np.flatnonzero(mal_mask & fams.isin(val_fam_set))
    mal_train_idx = np.flatnonzero(mal_mask & ~fams.isin(held_set | val_fam_set))
    if len(mal_val_idx) == 0:
        # Fallback if a category had <2 remaining families: still keep held_out untouched
        mal_val_idx = mal_train_idx

    benign_train_idx, benign_val_idx, benign_test_idx, cluster_counts = _assign_benign_clusters(
        X_benign=X_df.iloc[benign_idx],
        benign_indices=benign_idx,
        n_clusters=n_clusters,
        test_frac=benign_test_frac,
        val_frac=benign_val_frac,
        seed=kmeans_seed,
    )

    train_idx = np.sort(np.concatenate([mal_train_idx, benign_train_idx]))
    val_idx = np.sort(np.concatenate([mal_val_idx, benign_val_idx]))
    train_all_malware_idx = np.sort(np.unique(np.concatenate([mal_train_idx, mal_val_idx, benign_train_idx])))
    test_idx = np.sort(np.concatenate([mal_test_idx, benign_test_idx]))

    # Hard anti-leakage assertions
    assert set(train_all_malware_idx).isdisjoint(test_idx)
    assert set(benign_val_idx).isdisjoint(train_all_malware_idx)
    assert set(benign_val_idx).isdisjoint(test_idx)
    train_mal_fams = set(fams.iloc[np.concatenate([mal_train_idx, mal_val_idx])].unique())
    assert train_mal_fams.isdisjoint(held_set)

    return {
        "split_name": "split2_family_grouped",
        "held_out_families": held_out,
        "val_families": tuple(sorted(val_fam_set)),
        "draw_seed": int(draw_seed),
        "kmeans_seed": int(kmeans_seed),
        "train_idx": train_idx,
        "val_idx": val_idx,
        "train_all_malware_idx": train_all_malware_idx,
        "benign_train_idx": benign_train_idx,
        "benign_val_idx": benign_val_idx,
        "benign_test_idx": benign_test_idx,
        "test_idx": test_idx,
        "cluster_counts": cluster_counts,
        "caveat": config.TRACK_B_CAVEAT,
    }


def track_b_rotations(categories: pd.Series, families: pd.Series, y: np.ndarray) -> list[tuple[str, ...]]:
    """Generate 5 rotations where rotation i holds out the i-th sorted family of each category."""
    y_arr = np.asarray(y).astype(int).ravel()
    cats = pd.Series(categories).reset_index(drop=True)
    fams = pd.Series(families).reset_index(drop=True)
    mal_mask = y_arr == 1
    mal_cats = sorted(cats[mal_mask].unique())
    fams_by_cat = [sorted(fams[mal_mask & (cats == c)].unique()) for c in mal_cats]
    counts = {len(fs) for fs in fams_by_cat}
    if len(counts) != 1:
        raise ValueError(f"Expected equal family counts per category for rotation, got {counts}")
    n_rot = next(iter(counts))
    rotations = [tuple(fs[i] for fs in fams_by_cat) for i in range(n_rot)]
    flat = [f for rot in rotations for f in rot]
    assert len(flat) == len(set(flat)), "Family repeated across rotations"
    return rotations
