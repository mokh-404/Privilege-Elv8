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
from src.v2.offline_extractor import extract_from_qcow2, is_v2_harness_footprint_record, write_outputs
from src.v2.pilot_staging import build_clean_parity_stage_iso

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
    if is_v2_harness_footprint_record(rec) is not None:
        return True
    p = str(rec.get("path") or "").replace("/", "\\").lower()
    ak = str(rec.get("artifact_key") or "").replace("/", "\\").lower()
    pref = scratch_prefix.lower().rstrip("\\")
    return bool(pref and (p.startswith(pref) or pref in ak))


def extract_v1_live_json_from_qcow2(
    qcow2_path: str | Path,
    guest_json_path: str = r"c:\collector_out_parity\artifacts.json",
    out_json_path: str | Path | None = None,
) -> list[dict[str, Any]]:
    """Read `C:\\collector_out_parity\\artifacts.json` directly from a closed QCOW2 overlay in user space (zero SSH)."""
    from dissect.target import Target  # type: ignore

    qpath = Path(qcow2_path)
    t = Target.open(str(qpath))
    try:
        gp = t.fs.path(guest_json_path)
        if not gp.exists():
            raise FileNotFoundError(
                f"Guest v1 collector output {guest_json_path!r} not found inside {qpath}. "
                "Ensure the clean parity boot ran with the DFIR_STAGE parity ISO (--build-parity-iso) and shut down cleanly."
            )
        raw_bytes = gp.open("rb").read()
    finally:
        try:
            t.target.close() if hasattr(t, "target") else None  # type: ignore[attr-defined]
        except Exception:
            pass

    if raw_bytes.startswith((b"\xff\xfe", b"\xfe\xff")):
        txt = raw_bytes.decode("utf-16")
    else:
        txt = raw_bytes.decode("utf-8-sig")

    if out_json_path is not None:
        op = Path(out_json_path)
        op.parent.mkdir(parents=True, exist_ok=True)
        op.write_text(txt, encoding="utf-8")

    data = json.loads(txt)
    if isinstance(data, dict) and "artifacts" in data:
        return list(data["artifacts"])
    if isinstance(data, list):
        return list(data)
    raise ValueError(f"Unexpected JSON structure in guest file {guest_json_path!r}")


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
    parser = argparse.ArgumentParser(description="Zero-SSH Clean-Image Live-v1 vs Offline-v2 Feature Parity Comparator.")
    parser.add_argument("--build-parity-iso", type=Path, default=None, help="Build zero-SSH DFIR_STAGE parity ISO in this directory and exit")
    parser.add_argument("--extract-v1-json-from-qcow2", type=Path, default=None, help="Closed QCOW2 overlay from which to extract C:\\collector_out_parity\\artifacts.json in user space")
    parser.add_argument("--guest-json-path", default=r"c:\collector_out_parity\artifacts.json")
    parser.add_argument("--base-cache-path", type=Path, default=None, help="Optional base-image cache path when running v2 offline extractor on --extract-v1-json-from-qcow2")
    parser.add_argument("--v1-live-json", type=Path, default=Path("/tmp/parity_v1_live.json"))
    parser.add_argument("--v2-offline-jsonl", type=Path, default=Path("/tmp/parity_v2_offline/artifacts.jsonl"))
    parser.add_argument("--out-md", type=Path, default=None)
    parser.add_argument("--out-json", type=Path, default=None)
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.build_parity_iso is not None:
        bundle = build_clean_parity_stage_iso(args.build_parity_iso)
        print(json.dumps({k: str(v) for k, v in bundle.items()}, indent=2))
        return 0

    if args.extract_v1_json_from_qcow2 is not None:
        v1_recs = extract_v1_live_json_from_qcow2(
            args.extract_v1_json_from_qcow2,
            guest_json_path=args.guest_json_path,
            out_json_path=args.v1_live_json,
        )
        if not args.v2_offline_jsonl.exists():
            v2_recs, v2_summary = extract_from_qcow2(
                args.extract_v1_json_from_qcow2,
                run_id="clean_parity_test",
                base_cache_path=args.base_cache_path,
            )
            write_outputs(v2_recs, v2_summary, args.v2_offline_jsonl.parent)
        else:
            v2_recs = _load_records(args.v2_offline_jsonl)
    else:
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
