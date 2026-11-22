# Track A Final Evaluation Plan (Pre-Registered Protocol)

**Status:** Pre-registered and committed **before** any `--final` evaluation of the frozen holdout split.  
**Repository:** `dfir-triage-ml` (branch `main`)

---

## 1. Scope & Frozen Holdout Lock

- **Frozen Test Split (`split_pool == "test"`):**
  - **5 holdout ATT&CK techniques** across 5 tactics (`HOLDOUT_TECHNIQUE_DRAW_SEED = 42`): `T1036.005`, `T1059.003`, `T1087.001`, `T1543.003`, `T1548.002`.
  - **370 rows total**: `33` `attacker_induced`, `92` `benign_drift`, `245` `baseline` (`0` overlap with dev `technique_id`s or `artifact_key`s).
- **Hash Integrity Check:**
  - `src/eval/run_track_a.py:run_final_eval` verifies `compute_frozen_test_hash(df)` against `test_sha256` in `data/splits/dataset_v1_manifest.json` (`2046f3ffbcbb9bdbc05f5db0e97b8d7554e41179a6f46dadb77fe65506db9e07` on `dataset_v1.parquet` built at `a72c0b4`).
  - If an operator-approved pre-`--final` bug fix is applied (see Section 5), `data/splits/dataset_v1_manifest.json` must be regenerated and committed before `--final` so `--final` verifies the updated frozen hash.
- **One-Time Execution Guard:**
  - `run_final_eval` refuses a second `--final` run unless `--force` is passed, logging every execution and refused attempt to `results/logs/final_eval_audit.jsonl`.
- **Locked Hyperparameters & Seeds:**
  - Every model arm (`rf`, `xgb`, `iforest`, `mlp`, `ae`, and optional sanity `lr`) refits on all `1,179` development rows using the hyperparameters frozen in `results/tables/track_a_best_params.json` (`SEED = 42`, `BOOTSTRAP_SEED = 42`, `N_BOOTSTRAP = 1000`).
  - Only the 20 locked features (`src/config.py:FEATURES`) are exposed to primary benchmark models (`ORACLE_FEATURES`, `RULE_FEATURES`, `META_COLUMNS`, `LABEL_COL` excluded).

---

## 2. Primary Metric

- **Overall frozen-test PR-AUC** (`sklearn.metrics.average_precision_score`, macro-averaged rank curve across all `370` test rows) reported in `results/tables/track_a_test_results.csv`.
- **Uncertainty Interval:** Stratified `run_id`-clustered percentile bootstrap 95% CI (`src/eval/metrics.py:bootstrap_track_a(..., group_by="run_id", n_boot=1000, seed=42, alpha=0.05)`):
  - Resamples non-baseline rows (`label != "baseline"`) clustered by `run_id` with replacement and independently resamples deduplicated `baseline` rows (mostly anchored to `ctrl_01`) with replacement by row.
  - **Caveat:** Run-level bootstrap CIs quantify run-to-run variance on this 5-technique holdout set, **not** generalization variance over unseen ATT&CK techniques. Because there are only 5 held-out techniques, technique-level CIs (`group_by="technique_id"`) and per-technique results (`track_a_per_technique.csv`, T5) are reported alongside as an explicit check on technique-to-technique variance.

---

## 3. Secondary Metrics, Views, & Mandatory Diagnostics

1. **Combined Hard-Negative & Per-Type Views (`track_a_test_by_artifact_type.csv`):**
   - `file+run_key+task`: all artifact types where both `attacker_induced` and `benign_drift` hard negatives exist.
   - `file+run_key+task_drift_only`: `attacker_induced` vs `benign_drift` only (without clean `baseline` rows).
   - Individual per-`artifact_type` slices for every artifact type present with test positives.
2. **Analyst Top-K Ranking Metrics:**
   - **Precision@10** (`tie_expected_precision_at_k` at `k = 10`, invariant to row ordering across score ties), reported alongside `P@50`, `P@100`, `R@10`, `R@50`, `R@100`, and `ROC-AUC`.
3. **Fixed-Recall False Positive Rate (`FIXED_RECALL = 0.9`):**
   - `FPR at 90% recall`, reported separately over `all_benign` (`baseline + benign_drift`), `clean_baseline`, and `benign_drift`.
4. **Non-ML Baselines (`track_a_test_baselines.csv`):**
   - `rules_binary` (`rule_hit_count > 0`), `rules_count` (ranked by `rule_hit_count`), and `random` (`SEED = 42`), evaluated with exact tie-expected `@k` and the identical bootstrap procedure.
5. **Ablations, Probes & Explainability (Post-Prediction Artifacts):**
   - `track_a_test_probes.csv`: `full_20`, `probe_name_path`, `probe_content`, `probe_artifact_type`.
   - `src/eval/ablations.py` (`track_a_ablations.csv`, `track_a_train_size.csv`): `plus_rule_hit_count`, `oracle_upper_bound` (tagged `"ORACLE UPPER BOUND, NOT A RESULT"`), feature-group drops (`drop_path`, `drop_cmdline`, `drop_signature`, `drop_registry`), unsupervised benign-scope ablation (`unsup_baseline_only` vs `unsup_baseline_plus_drift`), and 25%/50%/100% training-fraction curves.
   - `src/eval/shap_explain.py`: SHAP (`TreeExplainer` for RF/XGB, Kernel/Gradient for MLP), Spearman top-10 feature rank correlation, AE per-feature reconstruction error, IF permutation importance, top-20 FP/FN error analysis, and REVENANT `findings.json` export check.

---

## 4. Pre-Registered Winner Declaration Rule

- Pairwise model differences $\Delta\text{PR-AUC} = \text{PR-AUC}(A) - \text{PR-AUC}(B)$ are tested via **paired stratified `run_id`-clustered bootstrap** (`src/eval/metrics.py:paired_bootstrap_track_a`, `group_by="run_id"`, `n_boot=1000`, `seed=42`, `alpha=0.05`).
- In each bootstrap replicate $b$, both models $A$ and $B$ are evaluated on the **identical** resampled cluster/baseline index vector `idx` before taking `PR-AUC(A)[idx] - PR-AUC(B)[idx]`, removing shared run-difficulty variance.
- **Decision Rule:**
  - Declare a statistically distinguishable winner between model $A$ and model $B$ **only if the paired-bootstrap 95% percentile CI strictly excludes `0`** (`ci_lo > 0` $\Rightarrow A$ better; `ci_hi < 0` $\Rightarrow B$ better).
  - If `ci_lo <= 0 <= ci_hi`, explicitly report **`"not distinguishable"`** (even if one arm has a higher point estimate).
- **Pre-Registered Comparisons (`track_a_test_paired_bootstrap.csv`):**
  Evaluated on `all`, `file+run_key+task`, and `file+run_key+task_drift_only`:
  1. `xgb` vs `rf`
  2. Best ML arm (highest overall test PR-AUC) vs `rules_binary` (plus `rf` / `xgb` vs `rules_binary` if not identical)
  3. `rf` vs `mlp` (plus `xgb` vs `mlp`)
- Cross-check per-technique ordering in `track_a_per_technique.csv`: even when paired run-level intervals separate two arms on the 5 holdout techniques, conclusions about generalisation across arbitrary unseen ATT&CK techniques remain tentative (`n = 5` techniques).

---

## 5. Pre-`--final` Bug-Fix & Benchmark-Limitation Policy

1. **Pre-`--final` Bug-Fix Gate:**
   - No feature extraction (`src/data/features.py`), collector (`collector/Collect-Artifacts.ps1`), or labeler code may be altered silently before or after `--final`.
   - Any operator-approved bug fix (specifically, the `UnknownError -> signed_untrusted` mapping in `src/data/features.py:_SIG_MAP` investigated prior to `--final`) must be applied as a documented commit **before** `--final`, followed by regenerating `data/processed/dataset_v1.parquet`, updating `data/splits/dataset_v1_manifest.json` (`test_sha256`), re-running all Track A dev CV + dev summary/probe/ablation/paired-bootstrap tables (`--dev --include-lr`), and committing those dev artifacts before running `--final`.
2. **Script-Content Quantization Disclosure:**
   - Dev inspection established that `lab_automation/benign_noise.ps1` generates `benign_drift` script files from a small set of fixed template bodies (`221` dev `benign_drift` `.cmd`/`.ps1` files occupy `18` distinct sizes and `30` distinct `(file_size_log, file_entropy)` pairs vs `34/36` distinct pairs for dev attack script files), giving tree models high PR-AUC on `file_size_log` + `file_entropy` alone (`probe_content`).
   - Therefore, any final benchmark write-up will present `drop_signature` (which removes `signature_state`, `file_size_log`, `file_entropy`, `has_hidden_attr`) and `probe_name_path` alongside `full_20` so readers see performance both with and without synthetic script-size/entropy cues.

---

## 6. Execution Command Sequence (HELD — Do NOT Run Without Operator Approval)

Once the operator explicitly approves the final configuration (`"go --final"`):

```bash
.venv/bin/python -u -m src.eval.run_track_a --final --include-lr
.venv/bin/python -u -m src.eval.ablations --dataset data/processed/dataset_v1.parquet --arms rf xgb iforest mlp ae lr
.venv/bin/python -u -m src.eval.shap_explain --dataset data/processed/dataset_v1.parquet
.venv/bin/python -u -m src.eval.figures --tables results/tables --figures results/figures
```
