"""Synthetic end-to-end tests for Step 8 (Track A eval, ablations, SHAP, figures, export_findings).

All artifacts and outputs stay strictly inside `tmp_path` (never writes real results/tables/).
"""
import json
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from src import config
from src.data import features as F
from src.data import labeler, splits
from src.eval import ablations, export_findings, figures, run_track_a, shap_explain


def _make_synthetic_dataset(n_per_tech: int = 8, n_benign: int = 120, seed: int = 42) -> tuple[pd.DataFrame, dict]:
    """Synthetic 16-technique (11 dev + 5 holdout) + baseline + benign_drift dataset."""
    rng = np.random.default_rng(seed)
    import yaml
    cat = yaml.safe_load(config.TECHNIQUES_YAML.read_text(encoding="utf-8"))
    raw_rows = []
    idx = 0

    for t in cat["techniques"]:
        tid = t["technique_id"]
        is_hold = t["split"] == "holdout"
        for k in range(n_per_tech):
            idx += 1
            raw_rows.append({
                "run_id": f"run_{tid}_{k % 3}",
                "technique_id": tid,
                "variant": (k % 3) + 1,
                "launcher": "attack",
                "artifact_key": f"file|c:\\programdata\\t_{idx}.ps1|t_{idx}.ps1",
                "artifact_type": "file" if k % 2 == 0 else "run_key",
                "name": f"mod_{idx}_{rng.integers(100, 999)}.ps1",
                "path": f"C:\\ProgramData\\mod_{idx}.ps1",
                "command_line": f"powershell.exe -NoProfile -enc SQBFAFgA_{idx}" if k % 2 == 0 else "cmd.exe /c x.cmd",
                "registry_key": None if k % 2 == 0 else "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                "registry_value": None if k % 2 == 0 else f"C:\\Users\\Public\\u_{idx}.ps1",
                "signature_status": "NotSigned",
                "attributes": "Hidden, Archive" if k % 3 == 0 else "Archive",
                "file_size": int(rng.integers(200, 8000)),
                "file_head_histogram": [4] * 256,
                "created_utc": "2026-11-21T10:00:05Z",
                "modified_utc": "2026-11-21T10:00:05Z",
                "label": "attacker_induced",
                "split_pool": "test" if is_hold else "dev",
                "dev_fold": -1,
            })

    for b in range(n_benign):
        idx += 1
        is_drift = b % 3 == 0
        akey = f"service|c:\\windows\\system32\\svc_{b}.exe|svc_{b}" if not is_drift else f"file|c:\\users\\public\\doc_{b}.txt|doc_{b}.txt"
        pool = splits.benign_pool(akey)
        fold = splits.benign_dev_fold(akey) if pool == "dev" else -1
        raw_rows.append({
            "run_id": f"run_b_{b % 6}",
            "technique_id": None,
            "variant": None,
            "launcher": "benign" if is_drift else "baseline",
            "artifact_key": akey,
            "artifact_type": "file" if is_drift else "service",
            "name": f"doc_{b}.txt" if is_drift else f"svc_{b}",
            "path": f"C:\\Users\\Public\\doc_{b}.txt" if is_drift else "C:\\Windows\\System32\\svchost.exe",
            "command_line": "C:\\Windows\\System32\\svchost.exe -k netsvcs" if not is_drift else None,
            "registry_key": None if is_drift else f"HKLM\\SYSTEM\\CurrentControlSet\\Services\\svc_{b}",
            "registry_value": None,
            "signature_status": "Valid" if not is_drift else None,
            "attributes": "Archive",
            "file_size": int(rng.integers(1000, 90000)),
            "start_mode": "Manual",
            "created_utc": "2026-11-21T10:00:05Z" if is_drift else "2025-01-01T00:00:00Z",
            "modified_utc": "2026-11-21T10:00:05Z" if is_drift else "2025-01-01T00:00:00Z",
            "label": "benign_drift" if is_drift else "baseline",
            "split_pool": pool,
            "dev_fold": fold,
        })

    raw_df = pd.DataFrame(raw_rows)
    feats = F.compute_features(
        raw_df,
        baseline_snapshot_utc="2026-11-21T00:00:00Z",
        window=("2026-11-21T09:59:00Z", "2026-11-21T10:05:00Z"),
        rule_hit_count=np.where(raw_df["label"] == "attacker_induced", 2, 0),
        sanitization_report=None,
    )
    for col in ("name", "path", "command_line", "registry_key", "registry_value",
                "signature_status", "attributes", "split_pool", "dev_fold"):
        feats[col] = raw_df[col].values
    manifest = {"test_sha256": labeler.compute_frozen_test_hash(feats)}
    return feats, manifest


def test_dev_folds_grouped_with_zero_leakage():
    ds, _ = _make_synthetic_dataset()
    dev_df = ds[ds["split_pool"] == "dev"].reset_index(drop=True)
    folds = run_track_a.make_dev_folds(dev_df, n_splits=5, seed=0)
    assert len(folds) == 5
    for tr, va in folds:
        tr_df, va_df = dev_df.iloc[tr], dev_df.iloc[va]
        tr_pos = tr_df[tr_df["label"] == "attacker_induced"]
        va_pos = va_df[va_df["label"] == "attacker_induced"]
        assert set(tr_pos["technique_id"]).isdisjoint(set(va_pos["technique_id"]))
        tr_ben = tr_df[tr_df["label"] != "attacker_induced"]
        va_ben = va_df[va_df["label"] != "attacker_induced"]
        assert set(tr_ben["artifact_key"]).isdisjoint(set(va_ben["artifact_key"]))


def test_track_a_end_to_end_final_guard_ablations_shap_and_figures(tmp_path):
    ds, manifest = _make_synthetic_dataset(n_per_tech=6, n_benign=120)
    tables_dir = tmp_path / "tables"
    models_dir = tmp_path / "models"
    logs_dir = tmp_path / "logs"
    figs_dir = tmp_path / "figures"

    # 1. Dev CV (1 trial, 1 seed, 2 epochs)
    trials, best = run_track_a.run_dev_cv(
        ds, arms=config.ARMS, n_trials=1, seeds=[0], n_splits=3,
        max_epochs_override=2, out_tables_dir=tables_dir,
    )
    assert set(trials["arm"]) == set(config.ARMS)
    assert set(best) == set(config.ARMS)

    # 2. Tampered test hash must fail
    tampered = ds.copy()
    idx_test = tampered.index[tampered["split_pool"] == "test"][0]
    tampered.loc[idx_test, "name_length"] = 999.0
    with pytest.raises(AssertionError, match="hash mismatch"):
        run_track_a.run_final_eval(
            tampered, manifest, best, arms=config.ARMS,
            out_tables_dir=tables_dir, models_dir=models_dir, logs_dir=logs_dir,
            max_epochs_override=2, n_boot=20,
        )

    # 3. First --final succeeds; second without --force is refused and logged; --force succeeds
    res = run_track_a.run_final_eval(
        ds, manifest, best, arms=config.ARMS, force=False,
        out_tables_dir=tables_dir, models_dir=models_dir, logs_dir=logs_dir,
        max_epochs_override=2, n_boot=20,
    )
    assert set(res["t1"]["arm"]) == set(config.ARMS)
    assert len(res["t5"]) == 5 * 5   # 5 holdout techniques x 5 arms

    with pytest.raises(RuntimeError, match="--force"):
        run_track_a.run_final_eval(
            ds, manifest, best, arms=config.ARMS, force=False,
            out_tables_dir=tables_dir, models_dir=models_dir, logs_dir=logs_dir,
            max_epochs_override=2, n_boot=20,
        )
    audit_lines = [json.loads(l) for l in (logs_dir / "final_eval_audit.jsonl").read_text().splitlines()]
    assert [a["status"] for a in audit_lines] == ["executed", "refused_duplicate_final"]

    # 4. Ablations
    ab_df, frac_df = ablations.run_all_ablations(
        ds, arms=config.ARMS, best_params=best, fractions=(0.5, 1.0),
        out_tables_dir=tables_dir, max_epochs_override=2,
    )
    assert "ORACLE UPPER BOUND, NOT A RESULT" in set(ab_df["ablation_tag"])
    assert "plus_rule_hit_count" in set(ab_df["ablation"])
    assert "unsup_baseline_only" in set(ab_df["ablation"])
    assert set(frac_df["train_fraction"]) == {0.5, 1.0}

    # 5. SHAP + AE recon error + IF permutation + error analysis
    exp_out = shap_explain.run_all_explanations(
        ds, models_dir=models_dir, out_tables_dir=tables_dir,
        max_tree_rows=40, max_mlp_rows=30, mlp_bg_size=20,
    )
    assert set(exp_out["shap_summary"]["arm"]) == {"rf", "xgb", "mlp"}
    assert set(exp_out["shap_summary"]["feature"]) == set(config.FEATURES)
    assert len(exp_out["spearman"]) == 3   # (rf,xgb), (rf,mlp), (xgb,mlp)
    assert set(exp_out["ae_recon_error"]["feature"]) == set(config.FEATURES)
    assert set(exp_out["iforest_perm"]["feature"]) == set(config.FEATURES)

    # 6. Figures (seed a synthetic Track B pair too so all 9 figures render)
    pd.DataFrame({"arm": config.ARMS, "arm_name": [config.ARM_DISPLAY[a] for a in config.ARMS], "pr_auc": [0.9]*5}).to_csv(
        tables_dir / "track_b_split1.csv", index=False
    )
    pd.DataFrame({"arm": config.ARMS, "arm_name": [config.ARM_DISPLAY[a] for a in config.ARMS], "pr_auc": [0.8]*5}).to_csv(
        tables_dir / "track_b_split2.csv", index=False
    )
    fig_manifest = figures.generate_all_figures(tables_dir=tables_dir, figures_dir=figs_dir)
    assert len(fig_manifest) == 18   # 9 figures x (png + pdf)
    assert (figs_dir / "figures_manifest.json").exists()
    for item in fig_manifest:
        assert Path(item["file"]).exists()


def test_export_findings_schema_and_no_ground_truth_technique_leak(tmp_path):
    # Deliberately set bogus ground-truth technique_id="T9999" to verify exporter NEVER uses it.
    df = pd.DataFrame([
        {   # Fires RULE-001 -> technique_id MUST be T1547.001, NOT T9999
            "artifact_type": "run_key",
            "artifact_key": "run_key|hku\\s-1-5-21-1\\software\\microsoft\\windows\\currentversion\\run|updater",
            "name": "updater",
            "path": "C:\\Users\\Public\\updater.ps1",
            "command_line": "powershell.exe -enc SQBFAFgA",
            "registry_key": "HKU\\S-1-5-21-1\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            "registry_value": "powershell.exe -enc SQBFAFgA",
            "signature_status": "NotSigned",
            "attributes": "Archive",
            "file_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "modified_utc": "2026-11-21T11:58:10Z",
            "technique_id": "T9999",
            "label": "attacker_induced",
        },
        {   # Zero rule hits -> goes to leads with technique_id=null
            "artifact_type": "file",
            "artifact_key": "file|c:\\users\\public\\custom_notes.txt|custom_notes.txt",
            "name": "custom_notes.txt",
            "path": "C:\\Users\\Public\\custom_notes.txt",
            "command_line": None,
            "registry_key": None,
            "registry_value": None,
            "signature_status": None,
            "attributes": "Archive",
            "file_sha256": None,
            "modified_utc": "2026-11-21T11:58:22Z",
            "technique_id": "T9999",
            "label": "attacker_induced",
        },
    ])
    per_row_shap = [
        {"has_encoded_flag": 1.42, "autostart_flag": 0.9, "name_entropy": 0.2},
        {"name_entropy": 1.15, "name_length": 0.4},
    ]
    out_p = tmp_path / "findings.json"
    payload = export_findings.export_findings(
        df, scores=[0.9412, 0.8831], ml_model_name="xgboost", run_id="run_001",
        manifest_sha256="abc123", per_row_shap=per_row_shap, out_path=out_p,
    )
    loaded = json.loads(out_p.read_text(encoding="utf-8"))
    assert loaded == payload
    assert len(loaded["findings"]) == 1
    assert len(loaded["leads"]) == 1

    f0 = loaded["findings"][0]
    assert f0["finding_id"] == "F-0001"
    assert f0["technique_id"] == "T1547.001"   # from RULE-001, never T9999!
    assert "RULE-001" in f0["rule_ids_triggered"]
    assert f0["ml_rank"] == 1
    assert "|" in f0["artifact_refs"][0]["artifact_key"]
    assert f0["artifact_refs"][0]["file_sha256"] is not None
    assert len(f0["artifact_refs"][0]["record_sha256"]) == 64

    l0 = loaded["leads"][0]
    assert l0["lead_id"] == "L-0001"
    assert l0["technique_id"] is None
    assert l0["rule_ids_triggered"] == []
    assert l0["ml_rank"] == 2
    assert l0["artifact_ref"]["file_sha256"] is None
    assert len(l0["artifact_ref"]["record_sha256"]) == 64
