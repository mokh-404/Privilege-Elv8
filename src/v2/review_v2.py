"""Decoupled blinded two-reviewer workflow for v2 (Step C.4 / IMP-04, OD-V2-10).

Enforces:
- Completely separate from dataset build (`export_blinded_review_sample` never overwrites existing populated files).
- Strictly blinded exports (strips labels, reasons, family names, launcher, pair/attribution provenance).
- Stratified 400-row primary export cap (200 positives stratified by stratum+family, 100 benign_drift, 100 ambiguous)
  and proportional 20% (80-row) overlap slice for Mokh Cohen's kappa (`OD-V2-10`).
- Validates distinct `reviewer_id`s, valid UTC timestamps, non-empty non-boilerplate `human_notes`.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import cohen_kappa_score

from src import config
from src.utils.repro import write_json
from src.v2.labeler_v2 import AMBIGUOUS_LABEL, V2_LABEL_VALUES


BLINDED_STRIP_COLS: tuple[str, ...] = (
    config.LABEL_COL,
    "label_reason",
    "launcher",
    "technique_id",
    "sample_family",
    "sample_category",
    "sample_source",
    "attribution_method",
    "attribution_confidence",
    "process_tree_root_guid",
    "packer_cluster",
    "pair_group_id",
)

REVIEW_VISIBLE_COLS: tuple[str, ...] = (
    "review_id",
    "run_id",
    "stratum",
    "execution_state",
    "artifact_type",
    "artifact_key",
    "name",
    "path",
    "command_line",
    "registry_key",
    "signature_status",
    "file_size",
)

REQUIRED_REVIEWER_COLS: tuple[str, ...] = ("reviewer_id", "reviewed_at_utc", "human_label", "human_notes")


def _stratified_positive_indices(
    pos_df: pd.DataFrame,
    max_positives: int,
    rng: np.random.Generator,
) -> np.ndarray:
    """Select up to `max_positives` positives balanced across stratum (`executed`/`dormant`) and `sample_family`."""
    if len(pos_df) <= max_positives:
        return np.sort(pos_df.index.to_numpy())

    strata_col = "stratum" if "stratum" in pos_df.columns else ("execution_state" if "execution_state" in pos_df.columns else None)
    fam_col = "sample_family" if "sample_family" in pos_df.columns else None

    if strata_col is None:
        strata_groups: list[pd.DataFrame] = [pos_df]
    else:
        strata_vals = pos_df[strata_col].fillna("unknown").astype(str).str.strip().str.lower()
        ordered_strata = sorted(strata_vals.unique())
        strata_groups = [pos_df[strata_vals == s] for s in ordered_strata]

    # Allocate quota across strata proportionally with exact remainder distribution
    n_strata = len(strata_groups)
    base_q = max_positives // n_strata
    rem_q = max_positives % n_strata
    stratum_quotas: list[int] = []
    # First pass: cap each stratum at its available rows and track leftover capacity
    avail = [len(g) for g in strata_groups]
    raw_alloc = [min(avail[i], base_q + (1 if i < rem_q else 0)) for i in range(n_strata)]
    deficit = max_positives - sum(raw_alloc)
    if deficit > 0:
        for i in range(n_strata):
            extra = min(deficit, avail[i] - raw_alloc[i])
            raw_alloc[i] += extra
            deficit -= extra
            if deficit == 0:
                break
    stratum_quotas = raw_alloc

    chosen: list[Any] = []
    for sub_df, quota in zip(strata_groups, stratum_quotas):
        if quota <= 0 or len(sub_df) == 0:
            continue
        if fam_col is None:
            pick = rng.choice(sub_df.index.to_numpy(), size=quota, replace=False)
            chosen.extend(pick.tolist())
            continue

        fams = sub_df[fam_col].fillna("unknown").astype(str).str.strip().str.lower()
        fam_pools: dict[str, list[Any]] = {}
        for fam in sorted(fams.unique()):
            idxs = sub_df.index[fams == fam].to_numpy().copy()
            rng.shuffle(idxs)
            fam_pools[fam] = idxs.tolist()

        fam_order = sorted(fam_pools.keys())
        rng.shuffle(fam_order)
        picked_in_stratum: list[Any] = []
        while len(picked_in_stratum) < quota and any(fam_pools.values()):
            for fam in fam_order:
                if len(picked_in_stratum) >= quota:
                    break
                if fam_pools[fam]:
                    picked_in_stratum.append(fam_pools[fam].pop())
        chosen.extend(picked_in_stratum)

    return np.sort(np.asarray(chosen))


def _proportional_overlap_indices(
    labels: np.ndarray,
    overlap_frac: float,
    rng: np.random.Generator,
) -> list[int]:
    """Allocate `round(overlap_frac * len(labels))` stratified overlap indices via largest-remainder."""
    n_total = len(labels)
    target_total = max(1, int(round(float(overlap_frac) * n_total))) if n_total > 0 else 0
    target_total = min(n_total, target_total)

    unique_lbls = list(dict.fromkeys(labels.tolist()))
    pools: dict[Any, np.ndarray] = {lbl: np.flatnonzero(labels == lbl) for lbl in unique_lbls}

    exact_shares = {lbl: float(overlap_frac) * len(idxs) for lbl, idxs in pools.items()}
    counts = {lbl: min(len(pools[lbl]), int(np.floor(exact_shares[lbl]))) for lbl in unique_lbls}

    # Ensure every non-empty stratum gets >= 1 row if target_total allows
    for lbl in unique_lbls:
        if counts[lbl] == 0 and len(pools[lbl]) > 0 and sum(counts.values()) < target_total:
            counts[lbl] = 1

    remaining = target_total - sum(counts.values())
    if remaining > 0:
        remainders = sorted(
            unique_lbls,
            key=lambda l: (exact_shares[l] - counts[l], len(pools[l])),
            reverse=True,
        )
        for lbl in remainders:
            if remaining <= 0:
                break
            if counts[lbl] < len(pools[lbl]):
                counts[lbl] += 1
                remaining -= 1

    ov_indices: list[int] = []
    for lbl in unique_lbls:
        n_ov = counts[lbl]
        if n_ov > 0:
            ov_pick = rng.choice(pools[lbl], size=n_ov, replace=False)
            ov_indices.extend(int(i) for i in ov_pick)
    return sorted(set(ov_indices))


def export_blinded_review_sample(
    df: pd.DataFrame,
    primary_out_csv: str | Path,
    overlap_out_csv: str | Path,
    sealed_key_json: str | Path,
    overlap_frac: float = 0.20,
    seed: int = config.SEED,
    max_per_stratum: int = 100,
    max_positives: int = 200,
    max_drift: int | None = None,
    max_ambiguous: int | None = None,
) -> dict[str, Any]:
    """Export blinded primary review CSV (friend, capped at 400 default) + 20% overlap CSV (Mokh) + answer key."""
    primary_out_csv = Path(primary_out_csv)
    overlap_out_csv = Path(overlap_out_csv)
    sealed_key_json = Path(sealed_key_json)

    for p in (primary_out_csv, overlap_out_csv, sealed_key_json):
        if p.exists():
            raise FileExistsError(
                f"Refusing to overwrite existing review file {p}. Move or rename before re-exporting (IMP-04)."
            )

    eff_max_drift = int(max_per_stratum if max_drift is None else max_drift)
    eff_max_ambig = int(max_per_stratum if max_ambiguous is None else max_ambiguous)
    eff_max_pos = int(max_positives)

    rng = np.random.default_rng(seed)
    picked_parts: list[pd.DataFrame] = []
    for target_lbl, cap in (
        (config.POSITIVE_LABEL, eff_max_pos),
        ("benign_drift", eff_max_drift),
        (AMBIGUOUS_LABEL, eff_max_ambig),
    ):
        sub = df[df[config.LABEL_COL] == target_lbl]
        if len(sub) == 0 or cap <= 0:
            continue
        if target_lbl == config.POSITIVE_LABEL:
            chosen = _stratified_positive_indices(sub, max_positives=cap, rng=rng)
        else:
            n_pick = min(len(sub), cap)
            chosen = np.sort(rng.choice(sub.index.to_numpy(), size=n_pick, replace=False))
        picked_parts.append(sub.loc[chosen])

    if not picked_parts:
        raise ValueError("No eligible rows (attacker_induced / benign_drift / ambiguous_unattributed) to review")

    full_pick = pd.concat(picked_parts, ignore_index=True)
    # Shuffle deterministically so automated classes aren't grouped trivially
    perm = rng.permutation(len(full_pick))
    full_pick = full_pick.iloc[perm].reset_index(drop=True)
    full_pick["review_id"] = [f"rev_{i:05d}" for i in range(len(full_pick))]

    vis_cols = [c for c in REVIEW_VISIBLE_COLS if c in full_pick.columns]
    blinded = full_pick[vis_cols].copy()
    for c in BLINDED_STRIP_COLS:
        assert c not in blinded.columns, f"Blinding violation: {c} remained in review export"
    for rc in REQUIRED_REVIEWER_COLS:
        blinded[rc] = ""

    # Stratified 20% overlap draw across original labels (sealed for inter-rater kappa)
    ov_indices = _proportional_overlap_indices(full_pick[config.LABEL_COL].to_numpy(), overlap_frac=overlap_frac, rng=rng)
    overlap_blinded = blinded.iloc[ov_indices].reset_index(drop=True)

    for p in (primary_out_csv, overlap_out_csv, sealed_key_json):
        p.parent.mkdir(parents=True, exist_ok=True)
    blinded.to_csv(primary_out_csv, index=False)
    overlap_blinded.to_csv(overlap_out_csv, index=False)

    key_records = {
        str(r["review_id"]): {
            "artifact_key": str(r.get("artifact_key", "")),
            "auto_label": str(r.get(config.LABEL_COL, "")),
            "label_reason": str(r.get("label_reason", "")),
            "sample_family": r.get("sample_family"),
        }
        for _, r in full_pick.iterrows()
    }
    write_json({
        "seed": int(seed),
        "overlap_frac": float(overlap_frac),
        "max_positives": eff_max_pos,
        "max_drift": eff_max_drift,
        "max_ambiguous": eff_max_ambig,
        "n_primary": int(len(blinded)),
        "n_overlap": int(len(overlap_blinded)),
        "overlap_review_ids": overlap_blinded["review_id"].tolist(),
        "keys": key_records,
    }, sealed_key_json)

    return {
        "primary_csv": primary_out_csv,
        "overlap_csv": overlap_out_csv,
        "sealed_key_json": sealed_key_json,
        "n_primary": int(len(blinded)),
        "n_overlap": int(len(overlap_blinded)),
    }


def validate_completed_review(
    review_csv: str | Path,
    min_note_chars: int = 8,
    min_unique_note_ratio: float = 0.5,
) -> pd.DataFrame:
    """Validate reviewer metadata, ISO-8601 UTC timestamps, labels, and non-boilerplate notes."""
    df = pd.read_csv(review_csv, keep_default_na=False)
    missing = [c for c in ("review_id", *REQUIRED_REVIEWER_COLS) if c not in df.columns]
    if missing:
        raise ValueError(f"Review CSV missing required columns: {missing}")
    if len(df) == 0:
        raise ValueError("Review CSV is empty")

    for i, row in df.iterrows():
        rid = str(row["reviewer_id"]).strip()
        ts = str(row["reviewed_at_utc"]).strip()
        hl = str(row["human_label"]).strip()
        notes = str(row["human_notes"]).strip()
        if not rid:
            raise ValueError(f"Row {i}: empty reviewer_id")
        try:
            datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError(f"Row {i}: invalid reviewed_at_utc {ts!r}") from exc
        if hl not in V2_LABEL_VALUES:
            raise ValueError(f"Row {i}: invalid human_label {hl!r}; expected one of {V2_LABEL_VALUES}")
        if len(notes) < min_note_chars:
            raise ValueError(f"Row {i}: human_notes too short ({len(notes)} < {min_note_chars} chars)")

    notes_list = [str(n).strip().lower() for n in df["human_notes"]]
    if len(notes_list) >= 3 and len(set(notes_list)) / len(notes_list) < min_unique_note_ratio:
        raise ValueError(
            f"Boilerplate review notes detected: only {len(set(notes_list))}/{len(notes_list)} unique rationales"
        )
    return df


def compute_inter_rater_kappa(
    primary_csv: str | Path,
    overlap_csv: str | Path,
) -> dict[str, Any]:
    """Validate distinct reviewers and compute Cohen's kappa over the stratified 20% overlap."""
    p_df = validate_completed_review(primary_csv)
    o_df = validate_completed_review(overlap_csv)

    p_reviewers = {str(x).strip() for x in p_df["reviewer_id"]}
    o_reviewers = {str(x).strip() for x in o_df["reviewer_id"]}
    if not p_reviewers.isdisjoint(o_reviewers):
        raise ValueError(
            f"Primary reviewer and overlap scorer must be distinct individuals (OD-V2-10); overlap={p_reviewers & o_reviewers}"
        )

    merged = pd.merge(
        p_df[["review_id", "human_label"]],
        o_df[["review_id", "human_label"]],
        on="review_id",
        suffixes=("_primary", "_overlap"),
    )
    if len(merged) == 0:
        raise ValueError("Zero overlapping review_id rows between primary and overlap CSVs")

    y1 = merged["human_label_primary"].tolist()
    y2 = merged["human_label_overlap"].tolist()
    agree = sum(a == b for a, b in zip(y1, y2)) / len(y1)
    if len(set(y1) | set(y2)) <= 1:
        kappa = 1.0 if agree == 1.0 else 0.0
    else:
        kappa = float(cohen_kappa_score(y1, y2))
    return {
        "n_overlap": int(len(merged)),
        "agreement_rate": float(agree),
        "cohen_kappa": float(kappa),
        "primary_reviewers": sorted(p_reviewers),
        "overlap_reviewers": sorted(o_reviewers),
    }


def merge_label_corrections(dataset_df: pd.DataFrame, reviewed_df: pd.DataFrame) -> pd.DataFrame:
    """Apply validated primary human review adjudications onto dataset without dropping provenance."""
    out = dataset_df.copy()
    if "label_review_status" not in out.columns:
        out["label_review_status"] = "pending"
    by_key = {
        (str(r["run_id"]), str(r["artifact_key"])): str(r["human_label"])
        for _, r in reviewed_df.iterrows()
    }
    for idx, row in out.iterrows():
        k = (str(row.get("run_id", "")), str(row.get("artifact_key", "")))
        if k in by_key:
            out.at[idx, config.LABEL_COL] = by_key[k]
            out.at[idx, "label_review_status"] = "human_reviewed"
    return out
