"""Diff labeler, baseline/drift hash-deduplication, split assignment, and review export (Step 7).

Implements LB-01..LB-04 and Prompt B steps 2-5:
  1. Drops DS-10 runner footprint (sshd.exe, wrapper PIDs, collector output paths).
  2. Runs FE-08 sanitization assertion BEFORE any string feature or labeling work.
  3. Labels strictly from baseline diff + host-side provenance + technique expected keys
     (NEVER from timestamps, NEVER from deterministic rules or a model).
  4. Deduplicates baseline and benign_drift rows across runs by `artifact_key`, retaining
     `seen_run_ids`, and assigns benign keys by SHA-256 hash bucket (75/25 dev/test).
     `attacker_induced` rows stay grouped by `technique_id` (dev vs holdout).
  5. Computes the 20 locked features (+ isolated oracle & rule_hit_count columns), exports
     dataset_v1.parquet, data_dictionary.md, dataset_stats.csv, review_sample.csv, and
     dataset_v1_manifest.json (with frozen test-set hash).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
from typing import Any, Mapping, Sequence

import numpy as np
import pandas as pd
import yaml

from src import config
from src.data import features, sanitize, splits
from src.rules import deterministic_rules
from src.utils.repro import get_commit_hash, utc_now_iso, write_json


_HASH_CONTENT_FIELDS = (
    "artifact_type", "artifact_key", "name", "path", "command_line",
    "registry_key", "registry_value", "task_name", "service_name",
    "file_sha256", "start_mode", "task_triggers", "attributes",
)


def stable_content_hash(row: Mapping[str, Any]) -> str:
    """Hash invariant artifact content fields (excludes volatile pids/collection timestamps)."""
    payload = {}
    for k in _HASH_CONTENT_FIELDS:
        v = row.get(k)
        if v is None or (isinstance(v, float) and math.isnan(v)):
            payload[k] = None
        else:
            payload[k] = str(v)
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def load_collector_run(run_dir: str | Path) -> tuple[pd.DataFrame, dict[str, Any]]:
    """Load `artifacts.json` (or `*.jsonl`) and `manifest.json` from one raw run folder."""
    run_dir = Path(run_dir)
    manifest_path = run_dir / "manifest.json"
    manifest: dict[str, Any] = {}
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    art_json = run_dir / "artifacts.json"
    records: list[dict[str, Any]] = []
    if art_json.exists():
        loaded = json.loads(art_json.read_text(encoding="utf-8"))
        records = loaded if isinstance(loaded, list) else [loaded]
    else:
        for jp in sorted(run_dir.glob("*.jsonl")):
            for line in jp.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    records.append(json.loads(line))

    df = pd.DataFrame(records)
    if len(df) and "run_id" not in df.columns:
        df["run_id"] = run_dir.name
    return df, manifest


def load_provenance_jsonl(path: str | Path) -> list[dict[str, Any]]:
    path = Path(path)
    if not path.exists():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def build_baseline_index(control_dfs: Sequence[pd.DataFrame]) -> dict[str, set[str]]:
    """Union of (artifact_key -> set of stable_content_hash) across all control boots."""
    index: dict[str, set[str]] = {}
    for df in control_dfs:
        if df is None or len(df) == 0:
            continue
        for _, row in df.iterrows():
            key = str(row["artifact_key"]).lower()
            index.setdefault(key, set()).add(stable_content_hash(row))
    return index


def _key_matches_expected(artifact_key: str, pattern: str) -> bool:
    """Match an observed collector `artifact_key` against a provenance/technique expected key."""
    ak = str(artifact_key).strip().lower()
    pk = str(pattern).strip().lower()
    if not ak or not pk:
        return False
    if ak == pk:
        return True

    aparts = ak.split(config.ARTIFACT_KEY_SEP)
    pparts = pk.split(config.ARTIFACT_KEY_SEP)
    if len(aparts) < 2 or len(pparts) < 2 or aparts[0] != pparts[0]:
        return False
    atype = aparts[0]
    apath = aparts[1]
    aname = aparts[2] if len(aparts) > 2 else ""
    ppath = pparts[1]
    pname = pparts[2] if len(pparts) > 2 else ""

    if atype in ("run_key", "registry"):
        if ppath == "hku" and apath.startswith("hku\\"):
            return aname == pname or pname in apath
        return apath == ppath and (not pname or aname == pname)
    if atype == "task":
        return aname == pname and (ppath in ("\\", "") or apath == ppath)
    if atype == "startup":
        return aname == pname
    if atype == "process":
        return aname == ppath or aname == pname
    if atype == "prefetch":
        return bool(pname) and aname.startswith(f"{pname}-") and aname.endswith(".pf")
    return False


def _matches_any(artifact_key: str, patterns: Sequence[str]) -> bool:
    return any(_key_matches_expected(artifact_key, p) for p in patterns)


def _provenance_summary(provenance_rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    attack_keys: list[str] = []
    benign_keys: list[str] = []
    wrapper_pids: set[int] = set()
    exclude_pids: set[int] = set()
    technique_id: str | None = None
    variant: Any = None
    timestamps: list[str] = []

    def _add_pid_list(val: Any, target: set[int]) -> None:
        if isinstance(val, (list, tuple, set)):
            for p in val:
                if p is not None and not pd.isna(p):
                    target.add(int(p))

    for rec in provenance_rows:
        wpid = rec.get("wrapper_pid")
        if wpid is not None and not pd.isna(wpid):
            wrapper_pids.add(int(wpid))
            exclude_pids.add(int(wpid))
        _add_pid_list(rec.get("wrapper_pids"), wrapper_pids)
        _add_pid_list(rec.get("wrapper_pids"), exclude_pids)
        _add_pid_list(rec.get("sshd_pids"), exclude_pids)
        _add_pid_list(rec.get("exclude_pids"), exclude_pids)

        launcher = str(rec.get("launcher") or "").lower()
        ts = rec.get("timestamp_utc") or rec.get("timestamp")
        if ts and launcher in ("attack", "benign", "control"):
            timestamps.append(str(ts))
        raw_exp = rec.get("expected_artifact_keys") or []
        if isinstance(raw_exp, str):
            raw_exp = [raw_exp]
        exp = [str(k) for k in raw_exp if isinstance(k, (str, bytes)) or not isinstance(k, dict)]
        if launcher == "attack":
            attack_keys.extend(exp)
            if rec.get("technique_id") and technique_id is None:
                technique_id = str(rec["technique_id"])
            if rec.get("variant") is not None and variant is None:
                variant = rec["variant"]
        elif launcher == "benign":
            benign_keys.extend(exp)

    window = (min(timestamps), max(timestamps)) if timestamps else None
    return {
        "attack_keys": attack_keys,
        "benign_keys": benign_keys,
        "wrapper_pids": sorted(wrapper_pids),
        "exclude_pids": sorted(exclude_pids),
        "technique_id": technique_id,
        "variant": variant,
        "window": window,
    }


def label_run(
    run_df: pd.DataFrame,
    baseline_index: Mapping[str, set[str]],
    provenance_rows: Sequence[Mapping[str, Any]],
    run_id: str,
    technique_spec: Mapping[str, Any] | None = None,
    variant_spec: Mapping[str, Any] | None = None,
    is_control: bool = False,
    runner_log_path: str | Path | None = config.RUNNER_FOOTPRINT_LOG_CSV,
    sanitization_report: str | Path | None = config.SANITIZATION_FAILURES_CSV,
) -> pd.DataFrame:
    """Drop runner footprint, assert FE-08 clean, and assign deterministic diff/provenance labels."""
    if len(run_df) == 0:
        return run_df.copy()

    df = run_df.copy()
    df["run_id"] = run_id
    prov = _provenance_summary(provenance_rows)

    # DS-10: drop runner footprint (sshd.exe, launcher wrapper PIDs, collector paths) BEFORE sanitize
    df, _ = sanitize.drop_runner_footprint(
        df,
        exclude_pids=prov["exclude_pids"],
        log_path=runner_log_path,
    )
    # FE-08: hard assertion on all feature-input strings
    sanitize.assert_clean(df, report_path=sanitization_report)

    tech_id = (
        str(technique_spec["technique_id"]) if technique_spec is not None
        else prov["technique_id"]
    )
    var_val = (
        int(variant_spec["variant"]) if variant_spec is not None
        else prov["variant"]
    )
    tech_expected = list((variant_spec or {}).get("expected_artifact_keys", []))

    labels: list[str] = []
    reasons: list[str] = []
    row_tech_ids: list[str | None] = []
    row_variants: list[int | None] = []
    row_launchers: list[str] = []

    for _, row in df.iterrows():
        akey = str(row["artifact_key"]).lower()
        chash = stable_content_hash(row)
        base_hashes = baseline_index.get(akey)
        in_baseline_unchanged = base_hashes is not None and chash in base_hashes

        if is_control:
            labels.append("baseline")
            reasons.append("control_boot_baseline")
            row_tech_ids.append(None)
            row_variants.append(None)
            row_launchers.append("control")
            continue

        if in_baseline_unchanged:
            labels.append("baseline")
            reasons.append("in_baseline_unchanged")
            row_tech_ids.append(None)
            row_variants.append(None)
            row_launchers.append("baseline")
            continue

        # Candidate row (not in baseline or content hash changed): label strictly by provenance/technique spec
        if _matches_any(akey, prov["attack_keys"]):
            labels.append(config.POSITIVE_LABEL)
            reasons.append("provenance_attack_match")
            row_tech_ids.append(tech_id)
            row_variants.append(int(var_val) if var_val is not None else None)
            row_launchers.append("attack")
        elif _matches_any(akey, tech_expected):
            labels.append(config.POSITIVE_LABEL)
            reasons.append("technique_expected_match")
            row_tech_ids.append(tech_id)
            row_variants.append(int(var_val) if var_val is not None else None)
            row_launchers.append("attack")
        elif _matches_any(akey, prov["benign_keys"]):
            labels.append("benign_drift")
            reasons.append("provenance_benign_match")
            row_tech_ids.append(None)
            row_variants.append(None)
            row_launchers.append("benign")
        else:
            labels.append("benign_drift")
            reasons.append("os_or_background_drift")
            row_tech_ids.append(None)
            row_variants.append(None)
            row_launchers.append("os_drift")

    df[config.LABEL_COL] = labels
    df["label_reason"] = reasons
    df["technique_id"] = row_tech_ids
    df["variant"] = row_variants
    df["launcher"] = row_launchers
    return df


def deduplicate_and_assign_splits(
    labelled_df: pd.DataFrame,
    techniques_catalog: Mapping[str, Any],
) -> pd.DataFrame:
    """Deduplicate baseline and benign_drift keys across runs and assign group/hash splits."""
    holdout_tids = {
        str(t["technique_id"]) for t in techniques_catalog["techniques"] if t.get("split") == "holdout"
    }
    dev_tids = {
        str(t["technique_id"]) for t in techniques_catalog["techniques"] if t.get("split") == "dev"
    }

    pos_df = labelled_df[labelled_df[config.LABEL_COL] == config.POSITIVE_LABEL].copy()
    ben_df = labelled_df[labelled_df[config.LABEL_COL] != config.POSITIVE_LABEL].copy()

    # Track seen_run_ids per benign key; prefer benign_drift over baseline if a key drifted
    rank_prio = {"benign_drift": 0, "baseline": 1}
    dedup_rows = []
    if len(ben_df):
        ben_df = ben_df.assign(_prio=ben_df[config.LABEL_COL].map(rank_prio).fillna(2))
        ben_df = ben_df.sort_values(["artifact_key", "_prio", "run_id"], kind="mergesort")
        for akey, grp in ben_df.groupby("artifact_key", sort=False):
            first = grp.iloc[0].drop(labels=["_prio"]).to_dict()
            run_ids = sorted({str(r) for r in grp["run_id"]})
            first["seen_run_ids"] = json.dumps(run_ids)
            first["seen_count"] = len(run_ids)
            pool = splits.benign_pool(str(akey))
            first["split_pool"] = pool
            first["dev_fold"] = splits.benign_dev_fold(str(akey)) if pool == "dev" else -1
            dedup_rows.append(first)
    ben_dedup = pd.DataFrame(dedup_rows) if dedup_rows else pd.DataFrame(columns=list(ben_df.columns))

    if len(pos_df):
        pos_df["seen_run_ids"] = pos_df["run_id"].apply(lambda r: json.dumps([str(r)]))
        pos_df["seen_count"] = 1
        pos_df["split_pool"] = pos_df["technique_id"].apply(
            lambda tid: "test" if str(tid) in holdout_tids else "dev"
        )
        pos_df["dev_fold"] = -1   # assigned via StratifiedGroupKFold(n_splits=5) in run_track_a.py

    out = pd.concat([pos_df, ben_dedup], ignore_index=True)

    # Anti-leakage assertions (D11 / C-04)
    ben_out = out[out[config.LABEL_COL] != config.POSITIVE_LABEL]
    dev_ben_keys = set(ben_out[ben_out["split_pool"] == "dev"]["artifact_key"])
    test_ben_keys = set(ben_out[ben_out["split_pool"] == "test"]["artifact_key"])
    assert dev_ben_keys.isdisjoint(test_ben_keys), "Benign artifact_key leaked between dev and test!"

    pos_out = out[out[config.LABEL_COL] == config.POSITIVE_LABEL]
    if len(pos_out):
        pos_dev_tids = set(pos_out[pos_out["split_pool"] == "dev"]["technique_id"].astype(str))
        pos_test_tids = set(pos_out[pos_out["split_pool"] == "test"]["technique_id"].astype(str))
        assert pos_dev_tids.isdisjoint(pos_test_tids), "Technique leaked between dev and test!"
        assert pos_test_tids <= holdout_tids or not holdout_tids
        assert pos_dev_tids <= dev_tids or not dev_tids

    return out


def export_review_sample(
    df: pd.DataFrame,
    out_csv: str | Path,
    seed: int = config.SEED,
) -> pd.DataFrame:
    """Export >= 10% of attacker_induced and up to 100 benign_drift rows for LB-02 review."""
    rng = np.random.default_rng(seed)
    pos = df[df[config.LABEL_COL] == config.POSITIVE_LABEL]
    drift = df[df[config.LABEL_COL] == "benign_drift"]

    n_pos_pick = min(len(pos), max(1, math.ceil(0.10 * len(pos)))) if len(pos) else 0
    n_drift_pick = min(len(drift), 100)

    parts = []
    if n_pos_pick:
        pick_idx = rng.choice(pos.index.to_numpy(), size=n_pos_pick, replace=False)
        parts.append(pos.loc[np.sort(pick_idx)])
    if n_drift_pick:
        pick_idx = rng.choice(drift.index.to_numpy(), size=n_drift_pick, replace=False)
        parts.append(drift.loc[np.sort(pick_idx)])

    review_cols = [c for c in (
        "run_id", "technique_id", "variant", "artifact_type", "artifact_key",
        "name", "path", "command_line", "registry_key", config.LABEL_COL, "label_reason",
    ) if c in df.columns]
    sample = pd.concat(parts, ignore_index=True)[review_cols] if parts else pd.DataFrame(columns=review_cols)
    sample["human_label"] = ""
    sample["human_notes"] = ""
    out_csv = Path(out_csv)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    sample.to_csv(out_csv, index=False)
    return sample


def compute_frozen_test_hash(df: pd.DataFrame) -> str:
    """Deterministic SHA-256 over the frozen test pool (`split_pool == 'test'`)."""
    test_df = df[df["split_pool"] == "test"].copy()
    cols = [c for c in ("run_id", "technique_id", "artifact_key", config.LABEL_COL, *config.FEATURES)
            if c in test_df.columns]
    test_df = test_df.sort_values(["artifact_key", "run_id"]).reset_index(drop=True)[cols]
    csv_bytes = test_df.to_csv(index=False).encode("utf-8")
    return hashlib.sha256(csv_bytes).hexdigest()


def write_data_dictionary(out_path: str | Path) -> Path:
    """Generate `data/processed/data_dictionary.md` documenting all dataset_v1 columns."""
    lines = [
        "# DFIR-Triage Track A Dataset (`dataset_v1.parquet`) Data Dictionary",
        "",
        "## Model Input Features (`config.FEATURES`, 20 columns)",
        "| Column | Kind | Description |",
        "|---|---|---|",
    ]
    for f in config.CATEGORICAL_FEATURES:
        lines.append(f"| `{f}` | categorical | Levels: {', '.join(config.CATEGORICAL_LEVELS[f])} |")
    for f in config.NUMERIC_FEATURES:
        lines.append(f"| `{f}` | numeric | Computed by `src/data/features.py` |")
    for f in config.BINARY_FEATURES:
        lines.append(f"| `{f}` | binary (0/1) | Computed by `src/data/features.py` |")
    lines += [
        "",
        "## Excluded From Primary Benchmark (Leakage / Metadata / Ablation Only)",
        "| Column | Group | Purpose |",
        "|---|---|---|",
        "| `file_age_minutes`, `created_in_window` | `ORACLE_FEATURES` | Oracle upper-bound ablation only |",
        "| `rule_hit_count` | `RULE_FEATURES` | Rule-hit ablation & `export_findings.py` only |",
        "| `run_id`, `technique_id`, `variant`, `launcher`, `artifact_key` | `META_COLUMNS` | Grouping, provenance, deduplication |",
        "| `label`, `label_reason`, `split_pool`, `dev_fold`, `seen_run_ids`, `seen_count` | Label / split | Supervision & leakage-proof split metadata |",
    ]
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path


def build_dataset(
    raw_runs_dir: str | Path = config.RAW_RUNS_DIR,
    provenance_dir: str | Path = config.PROVENANCE_DIR,
    techniques_yaml: str | Path = config.TECHNIQUES_YAML,
    run_table_csv: str | Path = config.LOGS_DIR / "run_table.csv",
    processed_dir: str | Path = config.PROCESSED_DIR,
    splits_dir: str | Path = config.SPLITS_DIR,
    baseline_snapshot_utc: object = None,
    seed: int = config.SEED,
    exclude_dry_runs: bool = True,
    runner_log_path: str | Path | None = config.RUNNER_FOOTPRINT_LOG_CSV,
) -> dict[str, Any]:
    """End-to-end Step 7 builder: baseline index -> label -> dedupe -> features -> parquet + manifest."""
    raw_runs_dir = Path(raw_runs_dir)
    provenance_dir = Path(provenance_dir)
    processed_dir = Path(processed_dir)
    splits_dir = Path(splits_dir)
    processed_dir.mkdir(parents=True, exist_ok=True)
    splits_dir.mkdir(parents=True, exist_ok=True)

    catalog = yaml.safe_load(Path(techniques_yaml).read_text(encoding="utf-8"))
    tech_by_id = {str(t["technique_id"]): t for t in catalog["techniques"]}

    run_table = pd.read_csv(run_table_csv) if Path(run_table_csv).exists() else None
    run_dirs = sorted(
        p for p in raw_runs_dir.iterdir()
        if p.is_dir()
        and (p / "manifest.json").exists()
        and not (exclude_dry_runs and p.name.startswith("dry_"))
    )
    if not run_dirs:
        raise FileNotFoundError(f"No completed run directories with manifest.json found under {raw_runs_dir}")

    # 1. Identify control boots & build baseline index B
    control_raw: list[tuple[str, pd.DataFrame, list[dict]]] = []
    attack_runs: list[tuple[str, pd.DataFrame, list[dict], str | None, int | None]] = []

    run_info_map: dict[str, dict] = {}
    if run_table is not None:
        for _, r in run_table.iterrows():
            run_info_map[str(r["run_id"])] = r.to_dict()

    for rdir in run_dirs:
        rid = rdir.name
        df_r, _ = load_collector_run(rdir)
        prov_r = load_provenance_jsonl(provenance_dir / f"{rid}.jsonl")
        info = run_info_map.get(rid, {})
        tech_id = info.get("technique")
        if tech_id is None and prov_r:
            tech_id = next((p.get("technique_id") for p in prov_r if p.get("technique_id")), None)
        is_ctrl = (
            rid.startswith(("ctrl_", "dry_ctrl_"))
            or str(tech_id).upper() == "CONTROL"
            or (
                bool(prov_r)
                and any(p.get("launcher") == "control" for p in prov_r)
                and all(p.get("launcher") in ("control", "runner_meta") for p in prov_r)
            )
        )
        if is_ctrl:
            control_raw.append((rid, df_r, prov_r))
        else:
            var_num = int(info["variant"]) if info.get("variant") is not None and not pd.isna(info["variant"]) else None
            if var_num is None and prov_r:
                var_num = next((int(p["variant"]) for p in prov_r if p.get("variant") is not None), None)
            attack_runs.append((rid, df_r, prov_r, str(tech_id) if tech_id else None, var_num))

    if not control_raw:
        raise ValueError("No control runs found; at least 1 (target >= 3) control boot is required for baseline B")

    baseline_dfs_clean = []
    for rid, cdf, prov_r in control_raw:
        ps = _provenance_summary(prov_r)
        kept, _ = sanitize.drop_runner_footprint(
            cdf,
            exclude_pids=ps["exclude_pids"],
            log_path=runner_log_path,
        )
        sanitize.assert_clean(kept)
        baseline_dfs_clean.append(kept)
    baseline_index = build_baseline_index(baseline_dfs_clean)

    # 2. Label every control and attack run
    labelled_parts: list[pd.DataFrame] = []
    windows_by_run: dict[str, tuple[str, str] | None] = {}

    for rid, cdf, prov_r in control_raw:
        windows_by_run[rid] = _provenance_summary(prov_r)["window"]
        labelled_parts.append(label_run(
            cdf, baseline_index, prov_r, run_id=rid, is_control=True,
            runner_log_path=runner_log_path,
        ))

    for rid, adf, prov_r, tid, var_num in attack_runs:
        windows_by_run[rid] = _provenance_summary(prov_r)["window"]
        tspec = tech_by_id.get(tid) if tid else None
        vspec = None
        if tspec and var_num is not None:
            vspec = next((v for v in tspec["variants"] if int(v["variant"]) == var_num), None)
        labelled_parts.append(label_run(
            adf, baseline_index, prov_r, run_id=rid,
            technique_spec=tspec, variant_spec=vspec, is_control=False,
            runner_log_path=runner_log_path,
        ))

    all_labelled = pd.concat(labelled_parts, ignore_index=True)
    dedup = deduplicate_and_assign_splits(all_labelled, catalog)

    # 3. Deterministic rule counts + 20 locked features + isolated oracle columns
    _, rule_counts = deterministic_rules.evaluate_dataframe(dedup)
    # Compute features row-by-row with per-run window for oracle_features only
    feat_rows = []
    oracle_rows = []
    sanitize.assert_clean(dedup)
    for _, r in dedup.iterrows():
        feat_rows.append(features.row_features(r))
        oracle_rows.append(features.oracle_features(r, baseline_snapshot_utc, windows_by_run.get(str(r["run_id"]))))

    feat_df = pd.DataFrame(feat_rows, columns=config.FEATURES)
    oracle_df = pd.DataFrame(oracle_rows, columns=config.ORACLE_FEATURES)
    meta_extra = ["run_id", "technique_id", "variant", "launcher", "artifact_key",
                  "name", "path", "command_line", "registry_key", "registry_value",
                  "signature_status", "attributes", "file_sha256", "record_sha256",
                  "label", "label_reason", "split_pool", "dev_fold", "seen_run_ids", "seen_count"]
    keep_meta = [c for c in meta_extra if c in dedup.columns]
    dataset = pd.concat([
        dedup[keep_meta].reset_index(drop=True),
        feat_df.reset_index(drop=True),
        oracle_df.reset_index(drop=True),
        pd.DataFrame({"rule_hit_count": rule_counts.astype(float)}),
    ], axis=1)
    for c in config.CATEGORICAL_FEATURES:
        dataset[c] = dataset[c].astype(str)
    for c in config.BINARY_FEATURES:
        dataset[c] = dataset[c].astype(int)

    parquet_path = processed_dir / "dataset_v1.parquet"
    dataset.to_parquet(parquet_path, index=False)
    dict_path = write_data_dictionary(processed_dir / "data_dictionary.md")
    review_path = processed_dir / "review_sample.csv"
    export_review_sample(dataset, review_path, seed=seed)

    stats = (
        dataset.groupby([config.LABEL_COL, "split_pool"], dropna=False)
        .size()
        .reset_index(name="row_count")
    )
    stats.to_csv(processed_dir / "dataset_stats.csv", index=False)

    test_hash = compute_frozen_test_hash(dataset)
    holdout_tids = sorted(t["technique_id"] for t in catalog["techniques"] if t.get("split") == "holdout")
    manifest = {
        "dataset_path": str(parquet_path),
        "generated_at_utc": utc_now_iso(),
        "commit": get_commit_hash(),
        "seed": seed,
        "holdout_draw_seed": int(catalog.get("holdout_draw_seed", config.HOLDOUT_TECHNIQUE_DRAW_SEED)),
        "holdout_techniques": holdout_tids,
        "n_runs": len(run_dirs),
        "n_control_runs": len(control_raw),
        "n_attack_runs": len(attack_runs),
        "total_rows": int(len(dataset)),
        "label_counts": {str(k): int(v) for k, v in dataset[config.LABEL_COL].value_counts().items()},
        "split_counts": {str(k): int(v) for k, v in dataset["split_pool"].value_counts().items()},
        "test_positives": int(((dataset["split_pool"] == "test") & (dataset[config.LABEL_COL] == config.POSITIVE_LABEL)).sum()),
        "test_sha256": test_hash,
    }
    manifest_path = write_json(manifest, splits_dir / "dataset_v1_manifest.json")
    return {
        "dataset": dataset,
        "parquet_path": parquet_path,
        "manifest_path": manifest_path,
        "review_path": review_path,
        "data_dictionary_path": dict_path,
        "manifest": manifest,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build frozen Track A dataset_v1.parquet from collected runs.")
    parser.add_argument("--raw-dir", type=Path, default=config.RAW_RUNS_DIR)
    parser.add_argument("--prov-dir", type=Path, default=config.PROVENANCE_DIR)
    parser.add_argument("--techniques", type=Path, default=config.TECHNIQUES_YAML)
    parser.add_argument("--run-table", type=Path, default=config.LOGS_DIR / "run_table.csv")
    parser.add_argument("--out-dir", type=Path, default=config.PROCESSED_DIR)
    parser.add_argument("--splits-dir", type=Path, default=config.SPLITS_DIR)
    parser.add_argument("--runner-log", type=Path, default=config.RUNNER_FOOTPRINT_LOG_CSV)
    parser.add_argument("--include-dry-runs", action="store_true", help="Include dry_* run directories.")
    parser.add_argument("--baseline-utc", default=None)
    args = parser.parse_args(argv)

    res = build_dataset(
        raw_runs_dir=args.raw_dir,
        provenance_dir=args.prov_dir,
        techniques_yaml=args.techniques,
        run_table_csv=args.run_table,
        processed_dir=args.out_dir,
        splits_dir=args.splits_dir,
        baseline_snapshot_utc=args.baseline_utc,
        exclude_dry_runs=not args.include_dry_runs,
        runner_log_path=args.runner_log,
    )
    print(json.dumps(res["manifest"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
