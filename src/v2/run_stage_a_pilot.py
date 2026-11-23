"""Stage A Pilot Orchestrator & Pre-Scoring `OD-V2-20` / Statistical-Power Evaluator (`OD-V2-05`, `OD-V2-07`, `OD-V2-20`).

Automates and evaluates the Stage A Pilot batch (`~3` clean control boots + `6-8` non-test pilot families
x paired `dormant` + `executed` runs per `sample_sha256` / `pair_group_id`):
1. Enforces hard Gate 0 (`OD-V2-07`) and paired-stratum staging validation via `src.v2.pilot_staging.validate_stage_run_spec`.
2. Labels `dormant` and `executed` runs against the multi-control baseline via `src.v2.labeler_v2`.
3. Evaluates the **pre-scoring `OD-V2-20` 50% persistence/execution static-link go/no-go gate** (`task`,
   `service`, `run_key`, `wmi_subscription`, `prefetch`) **before** any model training or scoring.
4. Verifies `check_template_quantization` on pilot benign files (`IMP-06`).
5. Computes nested family-grouped dev CV, per-family LOFO PR-AUC, Cross-Stratum Execution Delta (`OD-V2-15`),
   and the **empirical between-family paired-difference standard deviation `sigma_delta_family`** +
   80%-power Minimum Detectable Effect (`MDE`) table for `FINAL_EVAL_PLAN_v2_SKELETON.md` §6.
6. Writes `docs/v2/STAGE_A_PILOT_REPORT.md`.
"""
from __future__ import annotations

import argparse
import json
import math
import os
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np
import pandas as pd

from scripts.verify_stratified_shortcuts import check_template_quantization
from src import config
from src.data import features as F
from src.utils.repro import utc_now_iso
from src.v2.ablations_v2 import split_feature_types
from src.v2.labeler_v2 import (
    AMBIGUOUS_LABEL,
    build_multi_control_baseline,
    label_dormant_run,
    label_executed_run,
)
from src.v2.offline_extractor import summarize_extraction_and_refgraph
from src.v2.pilot_staging import StageRunSpec, validate_stage_run_spec
from src.v2.stats_v2 import compute_lofo_table, cross_stratum_execution_delta
from src.v2.training import run_nested_family_cv


def build_create_overlay_command(base_qcow2: str | Path, overlay_qcow2: str | Path) -> list[str]:
    """Return a `qemu-img create` command using a relative `-b` backing filename so dissect resolves it cleanly."""
    base_resolved = Path(base_qcow2).resolve()
    overlay_dir = Path(overlay_qcow2).resolve().parent
    rel_backing = os.path.relpath(base_resolved, overlay_dir)
    return [
        "qemu-img",
        "create",
        "-f",
        "qcow2",
        "-F",
        "qcow2",
        "-b",
        rel_backing,
        str(overlay_qcow2),
    ]


def compute_od_v2_20_pilot_gate(df: pd.DataFrame, threshold_pct: float = 50.0) -> dict[str, Any]:
    """Compute the pre-scoring `OD-V2-20` go/no-go gate on pilot persistence/execution artifacts."""
    summary = summarize_extraction_and_refgraph(df, disk_id="stage_a_pilot")
    cov = summary.get("refgraph_coverage", {})
    pe_rows = int(cov.get("persistence_exec_rows", 0))
    pe_res = int(cov.get("persistence_exec_resolved_rows", 0))
    pe_pct = float(cov.get("persistence_exec_resolved_pct", 0.0))
    passed = pe_pct >= float(threshold_pct)
    return {
        "gate_id": "OD-V2-20",
        "computed_before_model_scoring": True,
        "threshold_pct": float(threshold_pct),
        "persistence_exec_rows": pe_rows,
        "persistence_exec_resolved_rows": pe_res,
        "persistence_exec_resolved_pct": pe_pct,
        "gate_passed": bool(passed),
        "v2_refgraph_status": "confirmatory_secondary" if passed else "exploratory_only",
        "per_type": cov.get("per_type", {}),
    }


def compute_empirical_family_power_table(
    lofo_df: pd.DataFrame,
    arm_a: str = "xgb",
    arm_b: str = "rf",
    f_test_candidates: Sequence[int] = (10, 12, 15),
) -> dict[str, Any]:
    """Compute empirical between-family paired PR-AUC difference SD `sigma_delta_family` and 80%-power MDE."""
    piv = lofo_df.pivot(index="family", columns="model", values="pr_auc")
    if arm_a not in piv.columns or arm_b not in piv.columns:
        cols = list(piv.columns)
        if len(cols) >= 2:
            arm_a, arm_b = str(cols[0]), str(cols[1])
        else:
            return {
                "arm_a": arm_a,
                "arm_b": arm_b,
                "n_pilot_families": int(len(piv)),
                "sigma_delta_family": 0.0,
                "mde_by_f_test": {},
            }

    diffs = (piv[arm_a] - piv[arm_b]).dropna().to_numpy(dtype=float)
    sigma_f = float(np.std(diffs, ddof=1)) if len(diffs) > 1 else 0.0
    # Step-1 Holm-Bonferroni over m=9 fixed comparisons at two-sided alpha=0.05 -> alpha/18 = 0.002778 -> z=2.773
    # z_{0.80} = 0.8416 -> z_sum = 3.615
    z_step1 = 3.615
    # Step-9 Holm-Bonferroni (unadjusted alpha=0.05 -> z_{0.975} + z_{0.80} = 1.96 + 0.8416 = 2.802)
    z_step9 = 2.802

    mde_map: dict[int, dict[str, float]] = {}
    for f_test in f_test_candidates:
        ft = int(f_test)
        mde_map[ft] = {
            "mde_80pct_holm_step1": round(float(z_step1 * sigma_f / math.sqrt(ft)), 4),
            "mde_80pct_holm_step9": round(float(z_step9 * sigma_f / math.sqrt(ft)), 4),
        }

    return {
        "arm_a": arm_a,
        "arm_b": arm_b,
        "n_pilot_families": int(len(diffs)),
        "mean_paired_diff": round(float(np.mean(diffs)) if len(diffs) else 0.0, 4),
        "sigma_delta_family": round(sigma_f, 4),
        "mde_by_f_test": mde_map,
    }


def _ensure_feature_columns(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    missing = [f for f in config.FEATURES if f not in out.columns]
    if not missing:
        return out
    feat_rows = [F.row_features(rec) for rec in out.to_dict(orient="records")]
    feat_df = pd.DataFrame(feat_rows, index=out.index)
    for col in missing:
        out[col] = feat_df[col]
    return out


def evaluate_stage_a_pilot_runs(
    control_runs: Sequence[pd.DataFrame],
    pilot_runs: Sequence[Mapping[str, Any]],
    arms: Sequence[str] = ("rf", "xgb", "iforest"),
    n_outer: int = 3,
    n_inner: int = 2,
    n_trials: int = 2,
    seed: int = config.SEED,
) -> dict[str, Any]:
    """Run the full Stage A Pilot evaluation pipeline over control boots + paired dormant/executed runs.

    Each item in `pilot_runs` is a dict containing:
    - `spec`: a `StageRunSpec` (validated via `validate_stage_run_spec` enforcing Gate 0)
    - `df`: extracted raw/feature DataFrame for that run
    - `sysmon_events`: list of Sysmon event dicts (for `executed` runs)
    """
    if len(control_runs) < 1:
        raise ValueError("Stage A pilot requires >= 1 clean control run to build multi-control baseline")

    for item in pilot_runs:
        spec = item["spec"]
        if not isinstance(spec, StageRunSpec):
            spec = StageRunSpec(**dict(spec))
        validate_stage_run_spec(spec)

    baseline_idx = build_multi_control_baseline(control_runs)

    labeled_dfs: list[pd.DataFrame] = []
    run_yield_rows: list[dict[str, Any]] = []

    for item in pilot_runs:
        spec: StageRunSpec = item["spec"] if isinstance(item["spec"], StageRunSpec) else StageRunSpec(**dict(item["spec"]))
        raw_df = item["df"].copy()
        sysmon_evs = list(item.get("sysmon_events") or [])
        sample_meta = {
            "sample_sha256": spec.sample_sha256,
            "sample_family": spec.sample_family,
            "pair_group_id": spec.pair_group_id,
            "run_duration_s": spec.dwell_seconds,
            "detonation_exit_status": item.get("detonation_exit_status", "clean_exit"),
            "packer_cluster": item.get("packer_cluster", f"pkr_{spec.sample_family}"),
        }

        if spec.stratum == "dormant":
            ldf = label_dormant_run(
                run_df=raw_df,
                baseline_index=baseline_idx,
                staged_manifest=[{"staged_path": spec.staging_target_path, "sample_sha256": spec.sample_sha256}],
                run_id=spec.run_id,
                sysmon_events=sysmon_evs,
                sample_meta=sample_meta,
            )
        elif spec.stratum == "executed":
            ldf = label_executed_run(
                run_df=raw_df,
                baseline_index=baseline_idx,
                sysmon_events=sysmon_evs,
                run_id=spec.run_id,
                malware_root_hashes=[spec.sample_sha256] if spec.sample_sha256 else (),
                malware_root_guids=list(item.get("malware_root_guids") or ()),
                benign_scheduler_guids=list(item.get("benign_scheduler_guids") or ()),
                sample_meta=sample_meta,
            )
        else:
            continue

        ldf["split_pool"] = "dev"
        ldf = _ensure_feature_columns(ldf)
        labeled_dfs.append(ldf)

        vc = ldf[config.LABEL_COL].value_counts().to_dict()
        n_pos = int(vc.get(config.POSITIVE_LABEL, 0))
        n_amb = int(vc.get(AMBIGUOUS_LABEL, 0))
        n_drift = int(vc.get("benign_drift", 0))
        run_yield_rows.append({
            "run_id": spec.run_id,
            "stratum": spec.stratum,
            "sample_family": spec.sample_family,
            "pair_group_id": spec.pair_group_id,
            "total_rows": len(ldf),
            "attacker_induced": n_pos,
            "benign_drift": n_drift,
            "ambiguous_unattributed": n_amb,
            "detonation_success": bool(n_pos >= 1),
        })

    full_pilot_df = pd.concat(labeled_dfs, ignore_index=True)

    # 1. Pre-Scoring OD-V2-20 Go/No-Go Gate (computed BEFORE any model training or scoring!)
    od_v2_20_gate = compute_od_v2_20_pilot_gate(full_pilot_df, threshold_pct=50.0)

    # 2. Check benign template quantization gate
    ben_files = full_pilot_df[
        (full_pilot_df[config.LABEL_COL].isin(["benign_drift", "baseline", "benign_baseline"]))
        & (full_pilot_df["artifact_type"] == "file")
    ]
    quant_check = (
        check_template_quantization(ben_files)
        if len(ben_files) >= 5
        else {"passed": True, "note": "insufficient_benign_files_in_fixture"}
    )

    # 3. Filter out ambiguous_unattributed rows before model scoring (per V2_PLAN §8)
    eval_df = full_pilot_df[full_pilot_df[config.LABEL_COL] != AMBIGUOUS_LABEL].reset_index(drop=True)
    y_eval = (eval_df[config.LABEL_COL].astype(str) == config.POSITIVE_LABEL).astype(int).to_numpy()
    cat_cols, num_cols, bin_cols = split_feature_types(config.FEATURES)

    cv_res = run_nested_family_cv(
        dev_df=eval_df,
        y_dev=y_eval,
        arms=arms,
        cat_cols=cat_cols,
        num_cols=num_cols,
        bin_cols=bin_cols,
        n_outer=n_outer,
        n_inner=n_inner,
        n_trials=n_trials,
        seed=seed,
    )
    for arm_name, oof_arr in cv_res["outer_oof_scores"].items():
        eval_df[f"oof_{arm_name}"] = oof_arr

    score_cols = [f"oof_{a}" for a in arms]
    lofo_df = compute_lofo_table(eval_df, score_cols=score_cols)
    primary_arm = f"oof_{arms[0]}"
    exec_delta = cross_stratum_execution_delta(eval_df, score_col=primary_arm, n_boot=200, seed=seed)
    power_note = compute_empirical_family_power_table(
        lofo_df,
        arm_a=f"oof_{arms[1]}" if len(arms) > 1 else primary_arm,
        arm_b=primary_arm,
    )

    yield_df = pd.DataFrame(run_yield_rows)
    exec_yield = yield_df[yield_df["stratum"] == "executed"]
    dorm_yield = yield_df[yield_df["stratum"] == "dormant"]

    return {
        "generated_at_utc": utc_now_iso(),
        "n_control_boots": len(control_runs),
        "n_pilot_runs": len(pilot_runs),
        "n_total_labeled_rows": len(full_pilot_df),
        "n_eval_rows_excluding_ambiguous": len(eval_df),
        "ambiguous_rate_pct": round(100.0 * float((full_pilot_df[config.LABEL_COL] == AMBIGUOUS_LABEL).mean()), 2),
        "executed_detonation_success_rate_pct": round(100.0 * float(exec_yield["detonation_success"].mean()), 2) if len(exec_yield) else 0.0,
        "executed_mean_positives_per_run": round(float(exec_yield["attacker_induced"].mean()), 2) if len(exec_yield) else 0.0,
        "dormant_mean_positives_per_run": round(float(dorm_yield["attacker_induced"].mean()), 2) if len(dorm_yield) else 0.0,
        "od_v2_20_gate": od_v2_20_gate,
        "template_quantization_gate": quant_check,
        "outer_oof_pr_auc": cv_res["outer_oof_pr_auc"],
        "cross_stratum_execution_delta": {k: v for k, v in exec_delta.items() if k != "per_sample_df"},
        "statistical_power_calibration": power_note,
        "yield_table": run_yield_rows,
    }


def write_stage_a_pilot_report(summary: Mapping[str, Any], out_md: str | Path) -> Path:
    """Format and write `STAGE_A_PILOT_REPORT.md` from `evaluate_stage_a_pilot_runs` output."""
    gate = summary["od_v2_20_gate"]
    pwr = summary["statistical_power_calibration"]
    delta = summary["cross_stratum_execution_delta"]
    lines = [
        "# Stage A Pilot Report (`OD-V2-05`, `OD-V2-20` Gate & Power Calibration)",
        "",
        f"**Generated UTC:** `{summary['generated_at_utc']}`  ",
        f"**Control Boots:** `{summary['n_control_boots']}` | **Paired Pilot Runs:** `{summary['n_pilot_runs']}` | "
        f"**Total Labeled Rows:** `{summary['n_total_labeled_rows']}`",
        "",
        "## 1. Pre-Scoring `OD-V2-20` Referential-Graph Go/No-Go Gate",
        f"- **Computed Before Model Scoring:** `{gate['computed_before_model_scoring']}`",
        f"- **Persistence/Execution Artifacts (`task`, `service`, `run_key`, `wmi_subscription`, `prefetch`):** "
        f"`{gate['persistence_exec_resolved_rows']} / {gate['persistence_exec_rows']}` (**`{gate['persistence_exec_resolved_pct']:.2f}%`** vs `{gate['threshold_pct']:.1f}%` threshold)",
        f"- **Gate Decision:** **`{gate['v2_refgraph_status']}`** (`gate_passed = {gate['gate_passed']}`)",
        "",
        "## 2. Empirical Yield & Quarantine Summary",
        f"- **Executed Detonation Success Rate:** `{summary['executed_detonation_success_rate_pct']:.2f}%`",
        f"- **Mean `attacker_induced` Positives / Run:** Executed = `{summary['executed_mean_positives_per_run']}`, Dormant = `{summary['dormant_mean_positives_per_run']}`",
        f"- **`ambiguous_unattributed` Quarantine Rate:** `{summary['ambiguous_rate_pct']:.2f}%`",
        "",
        "## 3. Cross-Stratum Execution Delta (`OD-V2-15`) & Nested Dev OOF PR-AUC",
        f"- **Nested OOF PR-AUC:** `{json.dumps(summary['outer_oof_pr_auc'], sort_keys=True)}`",
        f"- **`PR-AUC(executed)` vs `PR-AUC(dormant)`:** `{delta['pr_auc_executed']:.4f}` vs `{delta['pr_auc_dormant']:.4f}` "
        f"(`Delta_exec = {delta['delta_exec_pr_auc']:+.4f}`, median `Delta_first_hit = {delta['delta_first_hit_median']:+.1f}` ranks)",
        "",
        "## 4. Empirical Statistical-Power Calibration (`FINAL_EVAL_PLAN_v2_SKELETON.md` §6)",
        f"- **Pilot Families Evaluated:** `{pwr['n_pilot_families']}` (`{pwr['arm_a']}` vs `{pwr['arm_b']}`)",
        f"- **Empirical Between-Family Paired-Difference SD (`sigma_delta_family`):** **`{pwr['sigma_delta_family']:.4f}`**",
        f"- **80%-Power Minimum Detectable Effect (`MDE`) by Blind-Test Family Count `F_test`:** `{json.dumps(pwr['mde_by_f_test'], sort_keys=True)}`",
    ]
    out_p = Path(out_md)
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_p
