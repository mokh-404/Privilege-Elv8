# DFIR-Triage ML (`dfir-triage-ml`)

Learned artifact prioritisation layer for local, read-only Windows forensic triage (**rules prove, the model ranks, the human decides**).

- **Track A (core):** Host-artifact benchmark generated across **51** isolated Windows 11 libvirt/QEMU VM runs (`1,549` deduplicated rows: `103` `attacker_induced`, `380` `benign_drift`, `1,066` `baseline`), grouped strictly by `technique_id` (`11` dev / `5` holdout) with hash-bucketed benign keys (`0` dev/test overlaps). Evaluated once on the frozen test set under two pre-registered feature schemas: `full_20` (all 20 features) and `no_content` (18 features dropping `file_size_log` and `file_entropy`).
- **Track B (benchmark):** `CIC-MalMem-2022` (`Obfuscated-MalMem2022.csv`, `58,596 x 57`) evaluated under both a leaky stratified 80/20 reproduction split (`LEAKY`) and a family-grouped holdout split (+ 5-family rotation).
- **Mandatory model families:** Random Forest (`rf`), XGBoost (`xgb`), Isolation Forest (`iforest`, benign-only), PyTorch Tabular MLP (`mlp`), and PyTorch Deep Autoencoder (`ae`, benign-only), plus Logistic Regression sanity baseline (`lr`) and non-ML baselines (`rules_binary`, `rules_count`, `random`).

> **Full Technical Report:** See [`COMPLETE_REPORT.md`](COMPLETE_REPORT.md) for all methodology details, dev CV tables, frozen test metrics, dual-config bootstrap verdicts, ablations, SHAP/AE/IF explainability, 300-DPI figures, and caveats.  
> **Documentation Index:** See [`docs/INDEX.md`](docs/INDEX.md) and [`docs/FINAL_EVAL_PLAN.md`](docs/FINAL_EVAL_PLAN.md).

---

## Headline Frozen Test Results (Track A, `n = 370`, `33` Positives / `5` Techniques)

| Arm / Baseline | `full_20` PR-AUC [95% `run_id` CI] | `full_20` P@10 | `no_content` PR-AUC [95% `run_id` CI] | `no_content` P@10 | Dual-Config Verdict vs `rules_binary` |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Random Forest (`rf`)** | **0.8902** `[0.7605, 0.9887]` | 0.9000 | **0.7078** `[0.5270, 0.8410]` | 0.9000 | `a_better` (`+0.6421` / `+0.4597`) |
| **XGBoost (`xgb`)** | 0.8552 `[0.7410, 0.9406]` | 0.9000 | 0.6248 `[0.4069, 0.7928]` | 0.8000 | `a_better` (`+0.6071` / `+0.3768`) |
| **PyTorch MLP (`mlp`)** | 0.7677 `[0.5785, 0.9009]` | 0.9000 | 0.6621 `[0.4802, 0.8004]` | 1.0000 | — |
| **Logistic Regression (`lr`)** | 0.6954 `[0.5091, 0.8324]` | 0.9000 | 0.7050 `[0.5076, 0.8456]` | 0.9000 | — |
| **PyTorch Autoencoder (`ae`)** | 0.4402 `[0.2502, 0.5964]` | 0.8000 | 0.4929 `[0.3081, 0.6311]` | 0.9000 | — |
| **Isolation Forest (`iforest`)** | 0.1466 `[0.0783, 0.2523]` | 0.1000 | 0.1601 `[0.0928, 0.2659]` | 0.1000 | — |
| **`rules_count`** | 0.2698 `[0.1668, 0.3765]` | 0.2800 | *(same)* | *(same)* | — |
| **`rules_binary`** (`rule_hit_count > 0`) | 0.2481 `[0.1582, 0.3393]` | 0.2583 | *(same)* | *(same)* | baseline |
| **`random`** | 0.1421 `[0.0862, 0.2619]` | 0.3000 | *(same)* | *(same)* | — |

- `xgb vs rf` paired `run_id` bootstrap dual-config verdict: **`configuration-dependent`** (`-0.0350 [-0.1165, +0.0542]` not distinguishable in `full_20`; `-0.0830 [-0.1713, -0.0050]` RF higher in `no_content`).
- On the combined hard-negative slice (`file+run_key+task`, `228` rows, `24` pos / `204` neg): RF reaches `0.9821` (`full_20`) / `0.7586` (`no_content`) vs `rules_binary` `0.2030`.
- **Track B (`CIC-MalMem-2022`):** Split 1 (leaky) PR-AUC `1.0000` (RF/XGB/MLP); Split 2 family holdout PR-AUC `0.9992` (RF), `0.9989` (XGB), `0.9995` (MLP), `0.9814` (AE), `0.9516` (IF) with substantial test-FPR drift (`8.1%–22.3%` at nominal 1% benign-val FPR; SMOTE cluster caveat applies).

---

## Repository Layout

```text
dfir-triage-ml/
├── COMPLETE_REPORT.md              # Full end-to-end project report (results, figures, caveats)
├── README.md
├── pytest.ini
├── requirements.in / requirements.txt
├── collector/                      # Read-only PowerShell Win11 collector & schema tests
├── data/
│   ├── processed/                  # Frozen dataset_v1.parquet, stats, label_corrections.csv, review_sample.csv
│   ├── splits/                     # dataset_v1_manifest.json (frozen test_sha256 & review_sample sign-off metadata)
│   ├── raw/runs/                   # [.gitignore] 644 MB raw VM snapshots (51 runs)
│   └── external/cic_malmem_2022/   # [.gitignore] Obfuscated-MalMem2022.csv (place here for Track B)
├── docs/                           # Operational docs, FINAL_EVAL_PLAN.md, INDEX.md
│   └── specs/                      # Original 13 Phase-1 specification docs (00..12)
├── lab_automation/                 # Libvirt/QEMU runner, 16-technique catalog, benign_noise.ps1, provenance/
├── results/
│   ├── findings.json               # REVENANT schema export (rf_full_20: 123 findings, 20 leads)
│   ├── findings_no_content.json    # REVENANT schema export (rf_no_content: 123 findings, 20 leads)
│   ├── figures/                    # 300-DPI PNG/PDF plots (fig1..fig9 + no_content/)
│   ├── logs/                       # 51-run batch log, runner drops, Track B meta, final_eval_audit.jsonl
│   ├── models/                     # Trained final models & preprocessors (full_20 + no_content/)
│   └── tables/                     # Dev CV, frozen test, dual-config verdicts, ablations, SHAP, errors
├── scripts/                        # verify_stratified_shortcuts.py (offline benign alignment audit)
├── src/                            # Locked feature schema, sanitizer, rules, models, eval, figures, exporter
└── tests/                          # Unit & integration suite (185 tests)
```

---

## Environment Setup & Running Tests

Python **3.12** (`3.12.16`) is used in `.venv` (`requirements.txt` pins 57 packages). CUDA is auto-detected via `src/utils/repro.py:get_device()` with clean CPU fallback (`DFIR_FORCE_CPU=1` forces CPU).

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/pytest
```

Latest verified test run: **`185 passed`**.

---

## Reproduction Commands

```bash
# Track A — GroupKFold Dev CV only (does NOT touch frozen test split)
.venv/bin/python -u -m src.eval.run_track_a --dev --include-lr --dual-config

# Track A — Dev-fitted ablations & training-size curves (evaluated on frozen test)
.venv/bin/python -u -m src.eval.ablations --dataset data/processed/dataset_v1.parquet --arms rf xgb iforest mlp ae lr

# Explainability (SHAP, AE MSE diff, IF permutation importance, RF error analysis)
.venv/bin/python -u -m src.eval.shap_explain --dataset data/processed/dataset_v1.parquet --config full_20 --models-dir results/models --out-dir results/tables
.venv/bin/python -u -m src.eval.shap_explain --dataset data/processed/dataset_v1.parquet --config no_content --models-dir results/models/no_content --out-dir results/tables/no_content

# Regenerate 300-DPI PNG/PDF figures
.venv/bin/python -u -m src.eval.figures --tables-dir results/tables --figures-dir results/figures
.venv/bin/python -u -m src.eval.figures --tables-dir results/tables/no_content --figures-dir results/figures/no_content

# Regenerate REVENANT findings JSON exports (Layer 1 rules + Layer 2 RF leads)
.venv/bin/python -m src.eval.export_findings --dataset data/processed/dataset_v1.parquet --predictions results/tables/track_a_test_predictions.parquet --shap results/tables/shap_rf_rows.parquet --model-name rf_full_20 --run-id frozen_test_full_20 --out results/findings.json
```

> **Note on `--final`:** Frozen test evaluation (`run_track_a --final`) is protected by a one-time audit guard in `results/logs/final_eval_audit.jsonl` (already executed once at `2026-11-22T02:04:38Z`) and refuses re-execution without `--force`.

### Track B (`CIC-MalMem-2022`)

Place `Obfuscated-MalMem2022.csv` at `data/external/cic_malmem_2022/Obfuscated-MalMem2022.csv` (excluded from git via `.gitignore`), then run:

```bash
.venv/bin/python -m src.data.cic_malmem --inspect
.venv/bin/python -m src.eval.run_track_b --smoke
.venv/bin/python -m src.eval.run_track_b --split1 --split2 --rotate
```

### Tracked vs. Excluded Artifacts in Git

- **Tracked in git:** Source code, tests, docs, `lab_automation/` scripts + `techniques.yaml` + 51 production `provenance/*.jsonl` logs, frozen `data/processed/dataset_v1.parquet` (296 KB), `data/splits/dataset_v1_manifest.json`, trained models under `results/models/` (16 MB total, max file 6.8 MB), all tables, 300-DPI PNG/PDF figures, audit logs, and `findings*.json`.
- **Excluded via `.gitignore`:** `.venv/`, `data/raw/runs/` (644 MB raw collector JSONs), `data/external/**/*.csv` (19 MB `Obfuscated-MalMem2022.csv`), `data/raw/dry_runs/`, `data/interim/`, `lab_automation/provenance/dry_runs/`, and `lab_automation/lab_config.yaml` (machine-local VM/SSH config).
