"""Tests for v2 schema additions (IMP-07, IMP-13, OD-V2-13)."""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import pytest

from src import config
from src.data import labeler
from src.models.preprocess import LeakageError, SharedPreprocessor, assert_no_forbidden_inputs
from src.rules import deterministic_rules as R


def test_v2_features_remain_exact_20_and_disjoint_from_forbidden():
    assert len(config.FEATURES) == 20
    assert len(config.V2_PROVENANCE_COLUMNS) == 15
    assert "pair_group_id" in config.V2_PROVENANCE_COLUMNS
    assert "pair_group_id" in config.FORBIDDEN_MODEL_INPUTS
    assert len(config.REFGRAPH_EDGE_COLUMNS) == 3
    assert len(config.RULE_EXPORT_COLUMNS) == 6
    assert set(config.V2_PROVENANCE_COLUMNS) <= set(config.META_COLUMNS)
    assert set(config.V2_PROVENANCE_COLUMNS) <= set(config.FORBIDDEN_MODEL_INPUTS)
    assert set(config.REFGRAPH_EDGE_COLUMNS) <= set(config.FORBIDDEN_MODEL_INPUTS)
    assert set(config.FEATURES).isdisjoint(config.FORBIDDEN_MODEL_INPUTS)


@pytest.mark.parametrize(
    "col",
    config.META_COLUMNS
    + config.REFGRAPH_EDGE_COLUMNS
    + config.ORACLE_FEATURES
    + config.RULE_FEATURES
    + [config.LABEL_COL],
)
def test_every_forbidden_column_rejected_from_x(col):
    with pytest.raises(LeakageError):
        assert_no_forbidden_inputs(config.FEATURES + [col])
    with pytest.raises(LeakageError):
        SharedPreprocessor(numeric=config.NUMERIC_FEATURES + [col])


@pytest.mark.parametrize(
    "never_col",
    config.V1_META_COLUMNS
    + config.V2_PROVENANCE_COLUMNS
    + config.REFGRAPH_EDGE_COLUMNS
    + [config.LABEL_COL],
)
def test_meta_provenance_refgraph_and_label_never_allowed_even_with_allowed_extra(never_col):
    with pytest.raises(LeakageError):
        assert_no_forbidden_inputs(config.FEATURES + [never_col], allowed_extra=[never_col])
    with pytest.raises(LeakageError):
        SharedPreprocessor(
            categorical=config.CATEGORICAL_FEATURES + [never_col],
            allowed_extra=[never_col],
        )


def _write_run(raw_dir: Path, prov_dir: Path, run_id: str, artifacts: list[dict], prov: list[dict]) -> None:
    rdir = raw_dir / run_id
    rdir.mkdir(parents=True, exist_ok=True)
    (rdir / "artifacts.json").write_text(json.dumps(artifacts), encoding="utf-8")
    (rdir / "manifest.json").write_text(
        json.dumps({"run_id": run_id, "total_records": len(artifacts)}), encoding="utf-8"
    )
    prov_dir.mkdir(parents=True, exist_ok=True)
    (prov_dir / f"{run_id}.jsonl").write_text("\n".join(json.dumps(p) for p in prov) + "\n", encoding="utf-8")


def test_rule_export_columns_and_parquet_roundtrip_parity(tmp_path):
    raw_dir = tmp_path / "raw"
    prov_dir = tmp_path / "prov"
    proc_dir = tmp_path / "processed"
    splits_dir = tmp_path / "splits"

    base_svc = {
        "artifact_type": "service",
        "artifact_key": "service|hklm\\system\\currentcontrolset\\services\\wuauserv|wuauserv",
        "name": "wuauserv",
        "service_name": "wuauserv",
        "start_mode": "Manual",
        "path": "C:\\Windows\\System32\\svchost.exe",
        "command_line": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
        "registry_key": "HKLM\\SYSTEM\\CurrentControlSet\\Services\\wuauserv",
        "signature_status": "Valid",
        "attributes": "Archive",
        "file_size": 50000,
    }
    _write_run(
        raw_dir,
        prov_dir,
        "ctrl_01",
        [base_svc],
        [{"run_id": "ctrl_01", "launcher": "control", "timestamp_utc": "2026-11-21T01:00:00Z"}],
    )

    # Include: (1) Microsoft task calling sc.exe -> RULE-002 MUST NOT fire when task_name preserved
    #          (2) Custom task calling C:\Users\Public\sync.ps1 -> RULE-002 MUST fire
    #          (3) Enabled non-default local admin -> RULE-013 MUST fire
    #          (4) Disabled non-default local admin -> RULE-013 MUST NOT fire
    attack_arts = [
        base_svc,
        {
            "artifact_type": "task",
            "artifact_key": "task|\\microsoft\\windows\\update\\run|run",
            "name": "Run",
            "task_name": "\\Microsoft\\Windows\\Update\\Run",
            "task_triggers": "MSFT_TaskDailyTrigger",
            "path": "C:\\Windows\\System32\\sc.exe",
            "command_line": "C:\\Windows\\System32\\sc.exe start wuauserv",
            "signature_status": "Valid",
        },
        {
            "artifact_type": "task",
            "artifact_key": "task|\\customsync|customsync",
            "name": "CustomSync",
            "task_name": "\\CustomSync",
            "task_triggers": "MSFT_TaskLogonTrigger",
            "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "command_line": "powershell.exe -NoProfile -File C:\\Users\\Public\\sync.ps1",
            "signature_status": "Valid",
        },
        {
            "artifact_type": "account",
            "artifact_key": "account|local_user\\maint_enabled|maint_enabled",
            "name": "maint_enabled",
            "raw": {"is_admin": True, "enabled": True},
        },
        {
            "artifact_type": "account",
            "artifact_key": "account|local_user\\maint_disabled|maint_disabled",
            "name": "maint_disabled",
            "raw": {"is_admin": True, "enabled": False},
        },
    ]
    attack_prov = [
        {
            "run_id": "run_001_T1053_005_v1",
            "launcher": "attack",
            "technique_id": "T1053.005",
            "variant": 1,
            "timestamp_utc": "2026-11-21T02:00:00Z",
            "expected_artifact_keys": ["task|\\customsync|customsync"],
        }
    ]
    _write_run(raw_dir, prov_dir, "run_001_T1053_005_v1", attack_arts, attack_prov)

    res = labeler.build_dataset(
        raw_runs_dir=raw_dir,
        provenance_dir=prov_dir,
        techniques_yaml=config.TECHNIQUES_YAML,
        run_table_csv=tmp_path / "missing_rt.csv",
        processed_dir=proc_dir,
        splits_dir=splits_dir,
        runner_log_path=tmp_path / "dropped.csv",
        sanitization_report=tmp_path / "san_fail.csv",
    )
    ds_mem = res["dataset"]
    for col in config.RULE_EXPORT_COLUMNS:
        assert col in ds_mem.columns

    ds_pq = pd.read_parquet(res["parquet_path"])
    for col in config.RULE_EXPORT_COLUMNS:
        assert col in ds_pq.columns

    matches_pq, counts_pq = R.evaluate_dataframe(ds_pq)
    assert list(counts_pq) == [int(x) for x in ds_mem["rule_hit_count"].tolist()]

    by_key = {
        row["artifact_key"]: {m.rule_id for m in m_list}
        for (_, row), m_list in zip(ds_pq.iterrows(), matches_pq)
    }
    assert "RULE-002" not in by_key["task|\\microsoft\\windows\\update\\run|run"]
    assert "RULE-002" in by_key["task|\\customsync|customsync"]
    assert "RULE-013" in by_key["account|local_user\\maint_enabled|maint_enabled"]
    assert "RULE-013" not in by_key["account|local_user\\maint_disabled|maint_disabled"]
