"""Clean-Image Live-v1 vs. Offline-v2 Feature Parity Comparator (`docs/v2/FEATURE_PARITY_AUDIT.md` §4).

Compares `/tmp/parity_v1_live.json` (collected inside a clean control guest via `Collect-Artifacts.ps1`)
against `/tmp/parity_v2_offline/artifacts.jsonl` (extracted offline from the exact same closed overlay via
`src/v2/offline_extractor.py`) across all 19 cold-disk `full_20` features and verifies `parent_process_class`.
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np
import pandas as pd

from src import config
from src.data import features as F

EXACT_MATCH_FEATURES: tuple[str, ...] = (
    "artifact_type",
    "ext_class",
    "registry_location_class",
    "name_length",
    "name_entropy",
    "file_size_log",
    "has_double_extension",
    "has_encoded_flag",
    "has_url_or_ip",
    "has_lolbin",
    "has_hidden_attr",
    "autostart_flag",
)


def _load_records(path: str | Path) -> list[dict[str, Any]]:
    p = Path(path)
    txt = p.read_text(encoding="utf-8-sig").strip()
    if not txt:
        return []
    if p.suffix.lower() == ".jsonl" or (txt.startswith("{") and "\n" in txt):
        return [json.loads(line) for line in txt.splitlines() if line.strip()]
    data = json.loads(txt)
    if isinstance(data, dict) and "artifacts" in data:
        return list(data["artifacts"])
    if isinstance(data, list):
        return list(data)
    raise ValueError(f"Unsupported artifact container format in {p}")


def _is_parity_collector_scratch(rec: Mapping[str, Any], scratch_prefix: str = r"c:\collector_out_parity") -> bool:
    p = str(rec.get("path") or "").replace("/", "\\").lower()
    ak = str(rec.get("artifact_key") or "").replace("/", "\\").lower()
    pref = scratch_prefix.lower().rstrip("\\")
    return bool(pref and (p.startswith(pref) or pref in ak))


def compare_v1_v2_feature_parity(
    v1_records: Sequence[Mapping[str, Any]],
    v2_records: Sequence[Mapping[str, Any]],
    scratch_prefix: str = r"c:\collector_out_parity",
) -> dict[str, Any]:
    """Compare matched cold-disk records across all 20 `full_20` features and evaluate §4 acceptance gates."""
    v1_cold = [
        dict(r)
        for r in v1_records
        if str(r.get("artifact_type") or "").lower() != "process"
        and not _is_parity_collector_scratch(r, scratch_prefix=scratch_prefix)
    ]
    v2_list = [dict(r) for r in v2_records if not _is_parity_collector_scratch(r, scratch_prefix=scratch_prefix)]

    v2_process_rows = sum(1 for r in v2_list if str(r.get("artifact_type") or "").lower() == "process")
    v2_feats_all = [F.row_features(r) for r in v2_list]
    v2_parent_all_na = all(str(f.get("parent_process_class")) == "na" for f in v2_feats_all)

    v1_by_key = {str(r.get("artifact_key") or "").replace("/", "\\").lower(): r for r in v1_cold if r.get("artifact_key")}
    v2_by_key = {str(r.get("artifact_key") or "").replace("/", "\\").lower(): r for r in v2_list if r.get("artifact_key")}
    shared_keys = sorted(set(v1_by_key.keys()) & set(v2_by_key.keys()))
    if not shared_keys:
        raise ValueError("No shared artifact_key records found between v1_records and v2_records")

    feature_rows: list[dict[str, Any]] = []
    discrepancies: list[dict[str, Any]] = []

    v1_feat_map = {k: F.row_features(v1_by_key[k]) for k in shared_keys}
    v2_feat_map = {k: F.row_features(v2_by_key[k]) for k in shared_keys}

    for feat in config.FEATURES:
        if feat == "parent_process_class":
            passed = (v2_process_rows == 0) and v2_parent_all_na
            feature_rows.append({
                "feature": feat,
                "category": "cold_disk_constant_na",
                "n_compared": len(v2_list),
                "agreement_rate": 1.0 if passed else 0.0,
                "max_abs_diff": 0.0,
                "threshold": "0 process rows & 100% 'na' offline",
                "status": "PASS" if passed else "FAIL",
            })
            continue

        n_comp = 0
        n_agree = 0
        max_diff = 0.0

        for k in shared_keys:
            val1 = v1_feat_map[k].get(feat)
            val2 = v2_feat_map[k].get(feat)
            is_nan1 = val1 is None or (isinstance(val1, float) and math.isnan(val1))
            is_nan2 = val2 is None or (isinstance(val2, float) and math.isnan(val2))

            if feat in ("file_entropy", "file_size_log") and (is_nan1 or is_nan2):
                # Compare non-missing shared rows (v1 had 27 Win32-locked files with missing file_entropy)
                continue

            n_comp += 1
            if isinstance(val1, (int, float)) and isinstance(val2, (int, float)) and not (is_nan1 or is_nan2):
                diff = abs(float(val1) - float(val2))
                max_diff = max(max_diff, diff)
                if feat in EXACT_MATCH_FEATURES or feat == "file_entropy":
                    ok = diff <= 1e-6
                elif feat == "path_depth":
                    ok = diff <= 1e-6
                elif feat == "cmdline_length":
                    ok = diff <= 2.0
                elif feat == "cmdline_entropy":
                    ok = diff <= 0.05
                elif feat == "cmdline_nonalnum_ratio":
                    ok = diff <= 0.02
                else:
                    ok = diff <= 1e-6
            else:
                ok = str(val1) == str(val2)

            if ok:
                n_agree += 1
            elif len(discrepancies) < 50:
                discrepancies.append({"artifact_key": k, "feature": feat, "v1": val1, "v2": val2})

        rate = float(n_agree / max(1, n_comp))
        if feat in EXACT_MATCH_FEATURES or feat == "file_entropy":
            req_rate = 1.0
            cat = "exact_or_1e-6"
            thr_str = "100.0% (|diff| <= 1e-6)"
        elif feat == "signature_state":
            req_rate = 0.98
            cat = "catalog_and_pe_sig"
            thr_str = ">= 98.0% exact agreement"
        elif feat in ("path_class", "path_depth"):
            req_rate = 0.99
            cat = "target_path_resolution"
            thr_str = ">= 99.0% exact agreement"
        elif feat in ("cmdline_length", "cmdline_entropy", "cmdline_nonalnum_ratio"):
            req_rate = 0.98
            cat = "cmdline_tolerance"
            thr_str = ">= 98.0% within (|dl|<=2, |de|<=0.05, |dr|<=0.02)"
        else:
            req_rate = 1.0
            cat = "exact"
            thr_str = "100.0%"

        passed = rate + 1e-12 >= req_rate
        feature_rows.append({
            "feature": feat,
            "category": cat,
            "n_compared": n_comp,
            "agreement_rate": round(rate, 6),
            "max_abs_diff": round(max_diff, 8),
            "threshold": thr_str,
            "status": "PASS" if passed else "FAIL",
        })

    overall_pass = all(r["status"] == "PASS" for r in feature_rows)
    return {
        "overall_status": "PASS" if overall_pass else "FAIL",
        "n_v1_cold_records": len(v1_cold),
        "n_v2_offline_records": len(v2_list),
        "n_shared_keys": len(shared_keys),
        "v2_process_rows": int(v2_process_rows),
        "v2_parent_process_all_na": bool(v2_parent_all_na),
        "feature_table": feature_rows,
        "sample_discrepancies": discrepancies,
    }


def format_parity_markdown(report: Mapping[str, Any]) -> str:
    """Format the parity comparison result as a Markdown report table."""
    lines = [
        "# Clean-Image Feature Parity Report (Live v1 vs. Offline v2)",
        "",
        f"- **Overall Verdict:** **`{report['overall_status']}`**",
        f"- **Shared Matched `artifact_key`s:** `{report['n_shared_keys']}` "
        f"(v1 cold-disk rows: `{report['n_v1_cold_records']}`, v2 offline rows: `{report['n_v2_offline_records']}`)",
        f"- **Offline `process` Rows:** `{report['v2_process_rows']}` | **`parent_process_class == 'na'` on 100% of offline rows:** `{report['v2_parent_process_all_na']}`",
        "",
        "| Feature | Category | Compared Rows | Agreement Rate | Max `|v2 - v1|` | Acceptance Threshold | Status |",
        "| :--- | :--- | ---: | ---: | ---: | :--- | :---: |",
    ]
    for r in report["feature_table"]:
        lines.append(
            f"| `{r['feature']}` | `{r['category']}` | `{r['n_compared']}` | `{100.0 * r['agreement_rate']:.2f}%` | "
            f"`{r['max_abs_diff']}` | {r['threshold']} | **`{r['status']}`** |"
        )
    return "\n".join(lines) + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compare live v1 vs offline v2 clean-image feature parity.")
    parser.add_argument("--v1-live-json", type=Path, required=True)
    parser.add_argument("--v2-offline-jsonl", type=Path, required=True)
    parser.add_argument("--out-md", type=Path, default=None)
    parser.add_argument("--out-json", type=Path, default=None)
    args = parser.parse_args(list(argv) if argv is not None else None)

    v1_recs = _load_records(args.v1_live_json)
    v2_recs = _load_records(args.v2_offline_jsonl)
    rep = compare_v1_v2_feature_parity(v1_recs, v2_recs)
    md = format_parity_markdown(rep)
    print(md)
    if args.out_md is not None:
        args.out_md.parent.mkdir(parents=True, exist_ok=True)
        args.out_md.write_text(md, encoding="utf-8")
    if args.out_json is not None:
        args.out_json.parent.mkdir(parents=True, exist_ok=True)
        args.out_json.write_text(json.dumps(rep, indent=2), encoding="utf-8")
    return 0 if rep["overall_status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
