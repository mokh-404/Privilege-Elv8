"""Batch runner (51 runs: 3 controls + 48 technique variants), --dry-run, --resume, disk guard."""
from __future__ import annotations

import argparse
import shutil
from pathlib import Path
from typing import Any, Callable

import numpy as np
import pandas as pd
import yaml

from lab_automation.run_one import LabConfig, run_single
from src import config
from src.utils.repro import get_commit_hash, utc_now_iso


def propose_holdout_split(
    techniques: list[dict[str, Any]],
    seed: int = config.HOLDOUT_TECHNIQUE_DRAW_SEED,
    n_holdout: int = config.N_HOLDOUT_TECHNIQUES,
) -> dict[str, str]:
    """Deterministic stratified draw of `n_holdout` techniques across distinct tactics."""
    by_tactic: dict[str, list[str]] = {}
    for t in techniques:
        by_tactic.setdefault(str(t["tactic"]), []).append(str(t["technique_id"]))

    eligible_tactics = sorted(tac for tac, tids in by_tactic.items() if len(tids) >= 2)
    if len(eligible_tactics) < n_holdout:
        eligible_tactics = sorted(by_tactic)

    rng = np.random.default_rng(seed)
    holdout_tids = {str(rng.choice(sorted(by_tactic[tac]))) for tac in eligible_tactics[:n_holdout]}
    return {str(t["technique_id"]): ("holdout" if str(t["technique_id"]) in holdout_tids else "dev")
            for t in techniques}


def build_run_list(
    catalog: dict[str, Any],
    dry_run: bool = False,
    n_controls: int = 3,
    base_seed: int = config.SEED,
) -> list[dict[str, Any]]:
    """Build deterministic list of runs (full: 3 controls + 48 attacks; dry-run: 3 runs)."""
    techniques = list(catalog["techniques"])
    if dry_run:
        first_dev = next(t for t in techniques if t["split"] == "dev")
        first_hold = next(t for t in techniques if t["split"] == "holdout")
        return [
            {"run_id": "dry_ctrl_01", "mode": "control", "technique": None, "variant_spec": None,
             "technique_id": "CONTROL", "variant": 0, "split": "control", "seed": base_seed},
            {"run_id": f"dry_{first_dev['technique_id'].replace('.', '_')}_v1", "mode": "attack",
             "technique": first_dev, "variant_spec": first_dev["variants"][0],
             "technique_id": first_dev["technique_id"], "variant": 1, "split": "dev", "seed": base_seed + 1},
            {"run_id": f"dry_{first_hold['technique_id'].replace('.', '_')}_v1", "mode": "attack",
             "technique": first_hold, "variant_spec": first_hold["variants"][0],
             "technique_id": first_hold["technique_id"], "variant": 1, "split": "holdout", "seed": base_seed + 2},
        ]

    runs: list[dict[str, Any]] = []
    idx = 0
    for c in range(1, n_controls + 1):
        idx += 1
        runs.append({
            "run_id": f"ctrl_{c:02d}",
            "mode": "control",
            "technique": None,
            "variant_spec": None,
            "technique_id": "CONTROL",
            "variant": 0,
            "split": "control",
            "seed": base_seed + idx,
        })
    for t in techniques:
        for v in t["variants"]:
            idx += 1
            tid_slug = str(t["technique_id"]).replace(".", "_")
            vnum = int(v["variant"])
            runs.append({
                "run_id": f"run_{idx:03d}_{tid_slug}_v{vnum}",
                "mode": "attack",
                "technique": t,
                "variant_spec": v,
                "technique_id": t["technique_id"],
                "variant": vnum,
                "split": t["split"],
                "seed": base_seed + idx,
            })
    return runs


def check_free_disk_gb(path: Path, disk_usage_fn: Callable = shutil.disk_usage) -> float:
    path = Path(path)
    probe = path if path.exists() else path.parent
    while not probe.exists() and probe != probe.parent:
        probe = probe.parent
    usage = disk_usage_fn(probe)
    return float(usage.free / (1024 ** 3))


def run_batch(
    cfg: LabConfig,
    catalog: dict[str, Any],
    dry_run: bool = False,
    resume: bool = False,
    n_controls: int = 3,
    run_table_path: Path = config.LOGS_DIR / "run_table.csv",
    single_runner: Callable[..., dict[str, Any]] = run_single,
    disk_usage_fn: Callable = shutil.disk_usage,
) -> pd.DataFrame:
    """Execute planned runs with --resume, retry-once on failure, disk guard, and run_table.csv."""
    run_list = build_run_list(catalog, dry_run=dry_run, n_controls=n_controls)
    run_table_path = Path(run_table_path)
    run_table_path.parent.mkdir(parents=True, exist_ok=True)
    commit = get_commit_hash()

    completed_map: dict[str, dict[str, Any]] = {}
    if resume and run_table_path.exists():
        prev = pd.read_csv(run_table_path)
        for _, row in prev.iterrows():
            rid = str(row["run_id"])
            manifest_ok = (Path(cfg.run_output_dir) / rid / "manifest.json").exists()
            if row.get("status") == "success" and manifest_ok:
                completed_map[rid] = row.to_dict()

    records: list[dict[str, Any]] = []
    for item in run_list:
        rid = item["run_id"]
        if resume and rid in completed_map:
            rec = dict(completed_map[rid])
            records.append(rec)
            continue

        free_gb = check_free_disk_gb(Path(cfg.run_output_dir), disk_usage_fn=disk_usage_fn)
        if free_gb < cfg.min_free_disk_gb:
            raise RuntimeError(
                f"Aborting before {rid}: free disk {free_gb:.1f} GB < guard {cfg.min_free_disk_gb} GB"
            )

        last_err = ""
        status = "failed"
        duration_s = 0.0
        attempts = 0
        for attempt in (1, 2):   # retry once on failure (Prompt E spec)
            attempts = attempt
            try:
                res = single_runner(
                    cfg,
                    run_id=rid,
                    mode=item["mode"],
                    technique=item["technique"],
                    variant_spec=item["variant_spec"],
                    seed=item["seed"],
                )
                status = str(res.get("status", "success"))
                duration_s = float(res.get("duration_s", 0.0))
                last_err = ""
                break
            except Exception as exc:
                last_err = str(exc)

        records.append({
            "run_id": rid,
            "technique": item["technique_id"],
            "variant": item["variant"],
            "split": item["split"],
            "status": status,
            "attempts": attempts,
            "duration_s": duration_s,
            "seed": item["seed"],
            "error": last_err,
            "finished_utc": utc_now_iso(),
            "commit": commit,
        })
        pd.DataFrame(records).to_csv(run_table_path, index=False)

    df = pd.DataFrame(records)
    df.to_csv(run_table_path, index=False)
    return df


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Batch Win11 libvirt data-generation runner.")
    parser.add_argument("--config", type=Path, default=config.LAB_DIR / "lab_config.yaml")
    parser.add_argument("--techniques", type=Path, default=config.TECHNIQUES_YAML)
    parser.add_argument("--dry-run", action="store_true", help="Run 3 runs (1 control, 1 dev, 1 holdout).")
    parser.add_argument("--resume", action="store_true", help="Skip runs already succeeded with manifest.json.")
    parser.add_argument("--propose-holdout", action="store_true", help="Print seeded holdout split and exit.")
    parser.add_argument("--run-table", type=Path, default=config.LOGS_DIR / "run_table.csv")
    args = parser.parse_args(argv)

    catalog = yaml.safe_load(args.techniques.read_text(encoding="utf-8"))
    if args.propose_holdout:
        split = propose_holdout_split(catalog["techniques"])
        print(f"Proposed split (seed={config.HOLDOUT_TECHNIQUE_DRAW_SEED}):")
        for tid, sp in split.items():
            print(f"  {tid}: {sp}")
        return 0

    cfg = LabConfig.from_yaml(args.config)
    df = run_batch(cfg, catalog, dry_run=args.dry_run, resume=args.resume, run_table_path=args.run_table)
    print(df[["run_id", "technique", "variant", "status", "duration_s"]].to_string(index=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
