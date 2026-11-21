"""REVENANT Phase 2 `findings.json` exporter (operator-approved schema).

Non-negotiable layering rules (docs/12_operator_decisions.md & doc 10 section 3):
  - Only artifacts with >= 1 deterministic rule hit (`src/rules/deterministic_rules.py`)
    become `F-xxxx` entries under `"findings"`, ordered descending by `ml_anomaly_score`.
  - Top-K model-ranked artifacts with 0 rule hits go into `"leads"` (`L-xxxx`) with
    `rule_ids_triggered: []` and `technique_id: null`.
  - `technique_id` in `"findings"` comes STRICTLY from the triggered deterministic rule's
    ATT&CK mapping — NEVER from the simulation ground-truth `technique_id` column.
  - Canonical `|` separator (`ARTIFACT_KEY_SEP = "|"`) is kept in `artifact_key`.
  - Both `file_sha256` (str | null) and `record_sha256` (str) are emitted.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np
import pandas as pd

from src import config
from src.data import features as F
from src.rules import deterministic_rules
from src.utils.repro import utc_now_iso


_WIN_PATH_RE = re.compile(r"[A-Za-z]:\\[^\s\"';<>|]+")
_URL_IP_EXTRACT_RE = re.compile(
    r"(?i)\b(?:https?|ftp)://[^\s\"'<>]+|(?<![\d.])(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}(?![\d.])"
)
_SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1}


def _clean_str(val: Any) -> str | None:
    if val is None or (isinstance(val, float) and math.isnan(val)):
        return None
    s = str(val).strip()
    return s if s else None


def _record_sha256(row: Mapping[str, Any]) -> str:
    existing = _clean_str(row.get("record_sha256"))
    if existing:
        return existing
    canon = {
        k: (None if row.get(k) is None or (isinstance(row.get(k), float) and math.isnan(row.get(k))) else row.get(k))
        for k in ("artifact_type", "artifact_key", "name", "path", "command_line", "registry_key", "registry_value")
    }
    blob = json.dumps(canon, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()


def _extract_iocs(row: Mapping[str, Any], file_sha256: str | None) -> dict[str, list[str]]:
    paths: list[str] = []
    urls_ips: list[str] = []
    for col in ("path", "command_line", "registry_value"):
        txt = _clean_str(row.get(col))
        if not txt:
            continue
        for m in _WIN_PATH_RE.findall(txt):
            if m not in paths:
                paths.append(m)
        for u in _URL_IP_EXTRACT_RE.findall(txt):
            if u not in urls_ips:
                urls_ips.append(u)
    p0 = _clean_str(row.get("path"))
    if p0 and p0 not in paths:
        paths.insert(0, p0)
    hashes = [file_sha256] if file_sha256 else []
    return {
        "file_paths": paths,
        "sha256_hashes": hashes,
        "urls_or_ips": urls_ips,
    }


def _artifact_ref(row: Mapping[str, Any]) -> dict[str, Any]:
    file_hash = _clean_str(row.get("file_sha256"))
    ts = _clean_str(row.get("modified_utc")) or _clean_str(row.get("created_utc")) or _clean_str(row.get("collected_utc")) or utc_now_iso()
    return {
        "artifact_key": str(row["artifact_key"]),
        "artifact_type": str(row.get("artifact_type") or "other"),
        "timestamp_utc": ts,
        "file_sha256": file_hash,
        "record_sha256": _record_sha256(row),
        "excluded_or_invalid": False,
    }


def _top_shap_list(
    row: Mapping[str, Any],
    shap_row: Mapping[str, float] | None,
    top_n: int = 3,
) -> list[dict[str, Any]]:
    if not shap_row:
        return []
    ordered = sorted(shap_row.items(), key=lambda kv: abs(float(kv[1])), reverse=True)[:top_n]
    out = []
    for feat, sv in ordered:
        fval = row.get(feat)
        if isinstance(fval, (np.floating, float)) and math.isnan(float(fval)):
            fval = None
        elif isinstance(fval, (np.integer, np.floating)):
            fval = fval.item()
        out.append({"feature": str(feat), "shap_value": round(float(sv), 6), "feature_value": fval})
    return out


def export_findings(
    df: pd.DataFrame,
    scores: Sequence[float],
    ml_model_name: str,
    run_id: str,
    case_id: str = "CASE-2026-0001",
    manifest_sha256: str = "",
    per_row_shap: Sequence[Mapping[str, float]] | None = None,
    top_k_leads: int = 20,
    out_path: str | Path | None = None,
) -> dict[str, Any]:
    """Build REVENANT `findings.json` payload (findings = rule hits only; leads = top-K unruled)."""
    scores_arr = np.asarray(scores, dtype=float).ravel()
    if len(scores_arr) != len(df):
        raise ValueError(f"scores length {len(scores_arr)} != DataFrame length {len(df)}")

    # Strip ground-truth simulation metadata BEFORE evaluating rules or formatting outputs
    # so ground-truth technique_id / label can never leak into exported findings.
    safe_df = df.drop(columns=[c for c in ("technique_id", "label", "label_reason", "launcher") if c in df.columns]).reset_index(drop=True)
    order = np.argsort(-scores_arr, kind="stable")

    findings: list[dict[str, Any]] = []
    leads: list[dict[str, Any]] = []

    for ml_rank, idx in enumerate(order, start=1):
        row = safe_df.iloc[int(idx)].to_dict()
        score = round(float(scores_arr[int(idx)]), 6)
        shap_map = per_row_shap[int(idx)] if per_row_shap is not None else None
        shap_top = _top_shap_list(row, shap_map, top_n=3)
        aref = _artifact_ref(row)
        matches = deterministic_rules.evaluate_row(row)

        if matches:
            primary = max(matches, key=lambda m: (_SEVERITY_RANK.get(m.severity, 0), m.confidence))
            findings.append({
                "finding_id": f"F-{len(findings) + 1:04d}",
                "category": primary.category,
                "severity": primary.severity,
                "confidence": float(primary.confidence),
                "technique_id": primary.technique_id,     # strictly from deterministic rule match
                "rule_ids_triggered": [m.rule_id for m in matches],
                "ml_anomaly_score": score,
                "ml_rank": ml_rank,
                "shap_top_features": shap_top,
                "artifact_refs": [aref],
                "extracted_iocs": _extract_iocs(row, aref["file_sha256"]),
            })
        elif len(leads) < int(top_k_leads):
            leads.append({
                "lead_id": f"L-{len(leads) + 1:04d}",
                "ml_anomaly_score": score,
                "ml_rank": ml_rank,
                "rule_ids_triggered": [],
                "technique_id": None,
                "shap_top_features": shap_top,
                "artifact_ref": aref,
            })

    payload = {
        "case_id": case_id,
        "run_id": run_id,
        "generated_at_utc": utc_now_iso(),
        "manifest_sha256": manifest_sha256,
        "ml_model_name": ml_model_name,
        "findings": findings,
        "leads": leads,
    }
    if out_path is not None:
        p = Path(out_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export ranked artifacts + rule hits to REVENANT findings.json.")
    parser.add_argument("--predictions", type=Path, required=True, help="Parquet with artifact metadata and score_<arm>.")
    parser.add_argument("--arm", default="xgb")
    parser.add_argument("--run-id", default="frozen_test")
    parser.add_argument("--case-id", default="CASE-2026-0001")
    parser.add_argument("--manifest-sha256", default="")
    parser.add_argument("--top-k-leads", type=int, default=20)
    parser.add_argument("--out", type=Path, default=config.RESULTS_DIR / "findings.json")
    args = parser.parse_args(argv)

    df = pd.read_parquet(args.predictions)
    score_col = f"score_{args.arm}"
    if score_col not in df.columns:
        raise KeyError(f"Column {score_col!r} missing from {args.predictions}")
    export_findings(
        df, scores=df[score_col].to_numpy(), ml_model_name=args.arm,
        run_id=args.run_id, case_id=args.case_id,
        manifest_sha256=args.manifest_sha256, top_k_leads=args.top_k_leads,
        out_path=args.out,
    )
    print(f"Exported findings.json -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
