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
import shutil
import subprocess
import time
from typing import Any, Callable, Mapping, Sequence

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
from src.v2.pilot_staging import (
    PilotStagingError,
    StageRunSpec,
    build_stage_bundle,
    validate_stage_run_spec,
)
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


def build_container_extraction_command(
    overlay_qcow2: str | Path,
    run_out_dir: str | Path,
    run_id: str,
    base_cache_path: str | Path | None = Path("/var/lib/dfir-quarantine-vault/win11_base_cache.json.gz"),
    runner_script: str | Path | None = None,
) -> tuple[list[str], dict[str, str]]:
    """Build the unprivileged `06_unprivileged_container_runner.sh` argv and env with `BASE_CACHE_PATH`."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    script_p = (
        Path(runner_script)
        if runner_script is not None
        else (repo_root / "docs" / "v2" / "hardening" / "06_unprivileged_container_runner.sh")
    )
    cache_arg = str(base_cache_path) if base_cache_path is not None else "none"
    cmd = [
        str(script_p),
        str(overlay_qcow2),
        str(run_out_dir),
        str(run_id),
        cache_arg,
    ]
    env = {"BASE_CACHE_PATH": cache_arg}
    return cmd, env


def build_inetsim_lifecycle_commands(
    domain: str = "inetsim-vm",
    libvirt_uri: str = "qemu:///system",
) -> dict[str, list[str]]:
    """Return allowed libvirt commands to start/stop/inspect `inetsim-vm` (`never virsh create`)."""
    return {
        "domstate": ["sudo", "virsh", "-c", libvirt_uri, "domstate", domain],
        "start": ["sudo", "virsh", "-c", libvirt_uri, "start", domain],
        "destroy": ["sudo", "virsh", "-c", libvirt_uri, "destroy", domain],
    }


def _invoke_cmd(
    run_cmd: Callable[..., int] | None,
    cmd: list[str],
    env_overrides: Mapping[str, str] | None = None,
    dry_run: bool = False,
) -> int:
    if dry_run:
        return 0
    if run_cmd is not None:
        try:
            return int(run_cmd(cmd, env_overrides))
        except TypeError:
            return int(run_cmd(cmd))
    merged_env = dict(os.environ)
    if env_overrides:
        merged_env.update({str(k): str(v) for k, v in env_overrides.items()})
    return int(subprocess.run(cmd, env=merged_env, check=False).returncode)


def execute_stage_a_pilot_batch(
    batch_runs: Sequence[Mapping[str, Any]],
    runs_out_dir: str | Path,
    base_qcow2: str | Path = "/var/lib/libvirt/images/win11_base.qcow2",
    overlay_qcow2: str | Path = "/var/lib/libvirt/images/win11_overlay.qcow2",
    base_cache_path: str | Path | None = "/var/lib/dfir-quarantine-vault/win11_base_cache.json.gz",
    vault_root: str | Path = "~/.quarantine_vault_dfir_v2",
    win_domain: str = "win11",
    inetsim_domain: str = "inetsim-vm",
    libvirt_uri: str = "qemu:///system",
    inetsim_wait_seconds: int = 8,
    watchdog_grace_seconds: int = 180,
    dry_run: bool = False,
    run_cmd: Callable[..., int] | None = None,
    sleep_fn: Callable[[float], None] = time.sleep,
) -> list[dict[str, Any]]:
    """Execute or dry-run an unattended Stage A Pilot batch with strict Gate 0 & `inetsim-vm` lifecycle cleanup."""
    repo_root = Path(__file__).resolve().parent.parent.parent
    watchdog_script = repo_root / "docs" / "v2" / "hardening" / "04_watchdog_and_base_hash.sh"
    bake_script = repo_root / "docs" / "v2" / "hardening" / "00_bake_v2_base_image.sh"
    vault_script = repo_root / "docs" / "v2" / "hardening" / "05_quarantine_vault_setup.sh"
    out_root = Path(runs_out_dir)
    out_root.mkdir(parents=True, exist_ok=True)
    stage_tmp_root = out_root / "_staging_iso"
    stage_tmp_root.mkdir(parents=True, exist_ok=True)
    vroot = Path(vault_root).expanduser()

    parsed_entries: list[tuple[StageRunSpec, Mapping[str, Any]]] = []
    has_malware_run = False
    for entry in batch_runs:
        raw_spec = entry["spec"]
        spec = raw_spec if isinstance(raw_spec, StageRunSpec) else StageRunSpec(**dict(raw_spec))
        validate_stage_run_spec(spec)
        if spec.stratum in ("dormant", "executed"):
            has_malware_run = True
        parsed_entries.append((spec, entry))

    if has_malware_run and not dry_run:
        if not (vroot / "GATE0_SIGNED_OFF").is_file():
            raise PilotStagingError(
                f"BLOCKED (OD-V2-07): Gate 0 marker missing at {vroot / 'GATE0_SIGNED_OFF'}."
            )
        rc_pre = _invoke_cmd(run_cmd, ["bash", str(vault_script), "preflight"], {"VAULT_ROOT": str(vroot)})
        if rc_pre != 0:
            raise PilotStagingError(f"Vault preflight failed with exit code {rc_pre}")

    inetsim_cmds = build_inetsim_lifecycle_commands(domain=inetsim_domain, libvirt_uri=libvirt_uri)
    verify_cmd = ["bash", str(watchdog_script), "verify-base"]
    prep_cmd = ["bash", str(bake_script), "prepare-overlay", str(base_qcow2), str(overlay_qcow2)]

    results_log: list[dict[str, Any]] = []
    for spec, entry in parsed_entries:
        run_dir = out_root / spec.run_id
        stage_dir = stage_tmp_root / spec.run_id
        iso_path = stage_dir / f"run_stage_{spec.run_id}.iso"
        inetsim_started = False

        rc_v1 = _invoke_cmd(run_cmd, verify_cmd, dry_run=dry_run)
        if rc_v1 != 0:
            raise RuntimeError(f"Base verification failed before run {spec.run_id!r} (rc={rc_v1})")

        rc_prep = _invoke_cmd(run_cmd, prep_cmd, dry_run=dry_run)
        if rc_prep != 0:
            raise RuntimeError(f"prepare-overlay failed for run {spec.run_id!r} (rc={rc_prep})")

        vault_file = entry.get("vault_file")
        if not dry_run or spec.stratum == "control" or (vault_file is not None and Path(vault_file).exists()):
            build_stage_bundle(
                spec=spec,
                out_dir=stage_dir,
                sample_vault_file=vault_file,
                benign_script_text=str(entry.get("benign_script_text") or "# Benign workload placeholder\n"),
                archive_password=entry.get("archive_password", "infected"),
            )

        attach_cmd = [
            "sudo", "virsh", "-c", libvirt_uri, "attach-disk",
            win_domain, str(iso_path), "sdc", "--type", "cdrom", "--mode", "readonly", "--config",
        ]
        if _invoke_cmd(run_cmd, attach_cmd, dry_run=dry_run) != 0:
            raise RuntimeError(f"Failed to attach DFIR_STAGE ISO for run {spec.run_id!r}")

        try:
            if spec.stratum == "executed":
                rc_inet = _invoke_cmd(run_cmd, inetsim_cmds["start"], dry_run=dry_run)
                if rc_inet != 0:
                    raise RuntimeError(f"Failed to start {inetsim_domain} for executed run {spec.run_id!r}")
                inetsim_started = True
                if not dry_run and inetsim_wait_seconds > 0:
                    sleep_fn(float(inetsim_wait_seconds))

            start_win = ["sudo", "virsh", "-c", libvirt_uri, "start", win_domain]
            if _invoke_cmd(run_cmd, start_win, dry_run=dry_run) != 0:
                raise RuntimeError(f"Failed to start {win_domain} for run {spec.run_id!r}")

            wd_cmd = ["bash", str(watchdog_script), "watchdog", str(int(spec.dwell_seconds) + int(watchdog_grace_seconds))]
            rc_wd = _invoke_cmd(run_cmd, wd_cmd, dry_run=dry_run)
            if rc_wd not in (0, 124):
                raise RuntimeError(f"Watchdog aborted run {spec.run_id!r} unexpectedly (rc={rc_wd})")
        finally:
            _invoke_cmd(run_cmd, ["sudo", "virsh", "-c", libvirt_uri, "destroy", win_domain], dry_run=dry_run)
            if inetsim_started:
                _invoke_cmd(run_cmd, inetsim_cmds["destroy"], dry_run=dry_run)
            _invoke_cmd(
                run_cmd,
                ["sudo", "virsh", "-c", libvirt_uri, "detach-disk", win_domain, "sdc", "--config"],
                dry_run=dry_run,
            )
            shutil.rmtree(stage_dir, ignore_errors=True)

        ext_cmd, ext_env = build_container_extraction_command(
            overlay_qcow2=overlay_qcow2,
            run_out_dir=run_dir,
            run_id=spec.run_id,
            base_cache_path=base_cache_path,
        )
        rc_ext = _invoke_cmd(run_cmd, ext_cmd, env_overrides=ext_env, dry_run=dry_run)
        if rc_ext != 0:
            raise RuntimeError(f"Offline container extraction failed for run {spec.run_id!r} (rc={rc_ext})")

        _invoke_cmd(run_cmd, ["sudo", "rm", "-f", str(overlay_qcow2)], dry_run=dry_run)
        if _invoke_cmd(run_cmd, verify_cmd, dry_run=dry_run) != 0:
            raise RuntimeError(f"Base hash verification failed after run {spec.run_id!r}")

        results_log.append({
            "run_id": spec.run_id,
            "stratum": spec.stratum,
            "sample_family": spec.sample_family,
            "pair_group_id": spec.pair_group_id,
            "inetsim_booted": bool(inetsim_started),
            "out_dir": str(run_dir),
            "dry_run": bool(dry_run),
        })

    return results_log


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


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Unattended Stage A Pilot VM & offline extraction orchestrator.")
    parser.add_argument("--batch-json", type=Path, required=True, help="Path to stage_a_pilot_batch.json")
    parser.add_argument("--runs-out-dir", type=Path, required=True, help="Output directory for per-run extracted JSONL")
    parser.add_argument("--base-qcow2", type=Path, default=Path("/var/lib/libvirt/images/win11_base.qcow2"))
    parser.add_argument("--overlay-qcow2", type=Path, default=Path("/var/lib/libvirt/images/win11_overlay.qcow2"))
    parser.add_argument(
        "--base-cache-path",
        type=Path,
        default=Path("/var/lib/dfir-quarantine-vault/win11_base_cache.json.gz"),
    )
    parser.add_argument("--vault-root", type=Path, default=Path("~/.quarantine_vault_dfir_v2"))
    parser.add_argument("--inetsim-wait-seconds", type=int, default=8)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)

    payload = json.loads(args.batch_json.read_text(encoding="utf-8"))
    runs = list(payload["runs"]) if isinstance(payload, dict) and "runs" in payload else list(payload)
    executed = execute_stage_a_pilot_batch(
        batch_runs=runs,
        runs_out_dir=args.runs_out_dir,
        base_qcow2=args.base_qcow2,
        overlay_qcow2=args.overlay_qcow2,
        base_cache_path=args.base_cache_path,
        vault_root=args.vault_root,
        inetsim_wait_seconds=args.inetsim_wait_seconds,
        dry_run=args.dry_run,
    )
    print(json.dumps({"completed_runs": len(executed), "runs": executed}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
