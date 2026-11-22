# Track A Final Evaluation Plan (Pre-Registered Protocol)

**Status:** Amended, pre-registered, and committed **before** any `--final` evaluation of the frozen holdout split.  
**Repository:** `dfir-triage-ml` (branch `main`)

---

## 1. Pre-Final Bug Fix & Frozen Holdout Lock

- **Pre-Final Bug Fix (`commit 8add423`, applied before any test-set evaluation):**
  - `_SIG_MAP["unknownerror"]` in `src/data/features.py` was changed from `"signed_untrusted"` to `"na"` (with regression tests in `tests/test_features.py`).
  - Rationale: PowerShell `Get-AuthenticodeSignature` returns `UnknownError` (`SignerCertificate = $null`) for unsupported or unreadable file types (`.cmd`, `.bat`, `.hta`, `.pf`, non-catalog `.lnk`, 0-byte `WindowsApps` execution aliases, non-PE stubs) rather than untrusted certificates.
  - Dataset rebuilt via `src.data.labeler --baseline-utc 2026-11-21T03:59:52Z`: **`0` changed labels** (`1549` rows: `103` `attacker_induced`, `380` `benign_drift`, `1066` `baseline`; `dev = 1179`, `test = 370`, `test_positives = 33`).
- **Frozen Test Split (`split_pool == "test"`):**
  - **5 holdout ATT&CK techniques** across 5 tactics (`HOLDOUT_TECHNIQUE_DRAW_SEED = 42`): `T1036.005`, `T1059.003`, `T1087.001`, `T1543.003`, `T1548.002`.
  - **Hash integrity check:** `run_final_eval` verifies `compute_frozen_test_hash(df)` against `test_sha256` in `data/splits/dataset_v1_manifest.json`:
    - `test_sha256`: `0f1ff3ec054bf00c66875fb5d2466e3b8d35685d69c2f0203d6787b71852ffa8` (updated from `2046f3ffbcbb9bdbc05f5db0e97b8d7554e41179a6f46dadb77fe65506db9e07` strictly due to the `UnknownError -> na` feature fix, with `0` changed labels).
- **One-Time Execution Guard:**
  - `run_final_eval` refuses a second `--final` run unless `--force` is passed, logging every execution and refused attempt to `results/logs/final_eval_audit.jsonl`.
  - Both configurations (`full_20` and `no_content`) are evaluated in **one single audited `--final --dual-config` pass**.

---

## 2. Two Pre-Registered Configurations at `--final`

Both configurations are tuned strictly via grouped dev CV (`GroupKFold` over `11` dev techniques + hash-bucket benign folds, `DEV_CV_SEEDS = [0, 1, 2]`) prior to `--final` and evaluated once on the frozen test set (`SEED = 42`, `BOOTSTRAP_SEED = 42`, `N_BOOTSTRAP = 1000`). `ORACLE_FEATURES`, `RULE_FEATURES`, `META_COLUMNS`, and `LABEL_COL` are strictly excluded in both.

1. **`full_20` (all 20 locked features):**
   - Categorical (6): `artifact_type`, `path_class`, `ext_class`, `signature_state`, `parent_process_class`, `registry_location_class`
   - Numeric (8): `path_depth`, `name_length`, `name_entropy`, `file_size_log`, `file_entropy`, `cmdline_length`, `cmdline_entropy`, `cmdline_nonalnum_ratio`
   - Binary (6): `has_double_extension`, `has_encoded_flag`, `has_url_or_ip`, `has_lolbin`, `has_hidden_attr`, `autostart_flag`
   - Output directory: `results/tables/` (`results/models/`)
2. **`no_content` (18 features — drops `file_size_log` and `file_entropy`):**
   - Categorical (6): `artifact_type`, `path_class`, `ext_class`, `signature_state`, `parent_process_class`, `registry_location_class`
   - Numeric (6): `path_depth`, `name_length`, `name_entropy`, `cmdline_length`, `cmdline_entropy`, `cmdline_nonalnum_ratio`
   - Binary (6): `has_double_extension`, `has_encoded_flag`, `has_url_or_ip`, `has_lolbin`, `has_hidden_attr`, `autostart_flag`
   - Output directory: `results/tables/no_content/` (`results/models/no_content/`)

---

## 3. Disclosed Benchmark Limitation (No Re-Collection)

- Dev-pool auditing established that `lab_automation/benign_noise.ps1` writes `benign_drift` script bodies from a small fixed set of templates: across `221` benign dev script files (`artifact_type == "file"` & `ext_class == "script"`), there are only **`18` unique file sizes (`file_size_log`)** and **`30` unique `(file_size_log, file_entropy)` pairs** (versus `34` distinct pairs across `36` dev attacker-induced script files).
- Consequently, tree models achieve near-ceiling separation on benign vs attack scripts from `(file_size_log, file_entropy)` template memorization alone.
- **No dataset re-collection was performed.** Reporting `full_20` and `no_content` side by side is the pre-registered mitigation so readers see both full-schema performance and performance stripped of script-content template quantization.

---

## 4. Primary & Secondary Metrics

- **Primary Metric:** Overall frozen-test **PR-AUC** (`average_precision_score`) on all `370` test rows for each configuration (`full_20` and `no_content`), reported with **stratified `run_id`-clustered percentile bootstrap 95% CIs** (`bootstrap_track_a(..., group_by="run_id", n_boot=1000, seed=42)`).
  - *Caveat:* Run-level bootstrap CIs cover run-to-run variation across the `5` holdout techniques, **not** generalization variance across unseen ATT&CK techniques; technique-level CIs and per-technique scores (`T5`) are also reported.
- **Secondary Metrics & Views:**
  - Combined hard-negative view **`file+run_key+task`** and **`file+run_key+task_drift_only`**, plus individual per-`artifact_type` slices.
  - **Precision@10** (`tie_expected_precision_at_k` at `k = 10`, invariant across score ties), alongside `P@50`, `P@100`, `R@10`, `R@50`, `R@100`, and `ROC-AUC`.
  - **FPR at 90% recall** (`FIXED_RECALL = 0.9`) over `clean_baseline`, `all_benign`, and `benign_drift`.
  - Non-ML baselines (`rules_binary`, `rules_count`, `random`), feature-subset probes, ablations (`src/eval/ablations.py`, tagging `oracle_upper_bound` as `"ORACLE UPPER BOUND, NOT A RESULT"`), and SHAP / AE / IF explainability (`src/eval/shap_explain.py`) + 300-DPI figures (`src/eval/figures.py`) + REVENANT `findings.json`.

---

## 5. Pre-Registered Dual-Configuration Winner Rule

- Pairwise differences $\Delta\text{PR-AUC} = \text{PR-AUC}(A) - \text{PR-AUC}(B)$ are evaluated via **paired stratified `run_id`-clustered bootstrap** (`src/eval/metrics.py:paired_bootstrap_track_a`, `group_by="run_id"`, `n_boot=1000`, `seed=42`, `alpha=0.05`) using identical resampled clusters/baseline indices per replicate, within each configuration (`full_20` and `no_content`) separately.
- **Strict Decision Rule (`combine_dual_config_verdicts`):**
  - Declare model $A$ better than model $B$ (or vice versa) **only if the paired `run_id`-bootstrap 95% CI strictly excludes `0` in the same direction in BOTH `full_20` and `no_content` configurations**.
  - Otherwise report **`"not distinguishable"`** (if both CIs include `0`) or **`"configuration-dependent"`** (if the CI excludes `0` in only one configuration or directions disagree).
- **Pre-Registered Comparisons** (reported on `all`, `file+run_key+task`, and `file+run_key+task_drift_only` in `track_a_test_dual_config_verdict.csv`):
  1. `xgb` vs `rf`
  2. Best ML model vs `rules_binary` (evaluated for the highest-PR-AUC ML arm in either config vs `rules_binary`, plus both `rf` vs `rules_binary` and `xgb` vs `rules_binary`)
  3. `rf` vs `mlp` (plus `xgb` vs `mlp`)

---

## 6. Execution Command Sequence

```bash
# 1. Regenerate dev tables for both full_20 and no_content (verified strictly on dev split)
.venv/bin/python -u -m src.eval.run_track_a --dev --include-lr --dual-config

# 2. Check pre-final gate, then execute ONE-TIME --final across both configurations
.venv/bin/python -u -m src.eval.run_track_a --final --include-lr --dual-config
.venv/bin/python -u -m src.eval.ablations --dataset data/processed/dataset_v1.parquet --arms rf xgb iforest mlp ae lr
.venv/bin/python -u -m src.eval.shap_explain --dataset data/processed/dataset_v1.parquet --config full_20 --models-dir results/models --out-dir results/tables
.venv/bin/python -u -m src.eval.shap_explain --dataset data/processed/dataset_v1.parquet --config no_content --models-dir results/models/no_content --out-dir results/tables/no_content
.venv/bin/python -u -m src.eval.figures --tables-dir results/tables --figures-dir results/figures
.venv/bin/python -u -m src.eval.figures --tables-dir results/tables/no_content --figures-dir results/figures/no_content
```

---

## 7. Methodological Reporting Notes

1. **Ablations (`src/eval/ablations.py`) Fit Strictly on Dev Data:** Every ablation model and preprocessing pipeline (`primary_20`, `plus_rule_hit_count`, `oracle_upper_bound`, `drop_<group>`, `no_content`, unsupervised benign-scope runs, and `frac_*`) fits exclusively on `split_pool == "dev"` using dev-frozen hyperparameters (`track_a_best_params.json`), with zero tuning on `split_pool == "test"`. The `oracle_upper_bound` row remains explicitly tagged `"ORACLE UPPER BOUND, NOT A RESULT"`.
2. **FPR at 90% Recall Is Descriptive, Not a Deployable Operating Point:** `threshold_at_recall(y_test, scores, 0.9)` picks the score threshold on the test set's positives themselves (`n_pos = 33`), so `fpr_at_recall_0.9_*` characterizes the test ranking curve rather than a pre-calibrated deployment threshold (which must be selected on dev data).
3. **"Best ML Model vs `rules_binary`" Selection Optimism:** Identifying the highest-PR-AUC ML model after observing test results slightly flatters that headline contrast; `rf vs rules_binary` and `xgb vs rules_binary` are therefore always reported separately alongside `"best ML vs rules_binary"`.
4. **Statistical Power & Expected `no_content` Drop:** With only `33` test positives across `5` holdout techniques, `"not distinguishable"` between `xgb` and `rf` under paired `run_id` bootstrap is expected and reported as a legitimate empirical outcome, and `no_content` PR-AUC is expected to be lower than `full_20` due to removing `file_size_log` and `file_entropy`.

