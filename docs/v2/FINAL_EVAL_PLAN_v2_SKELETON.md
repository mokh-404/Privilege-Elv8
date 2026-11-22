# Track A v2 Pre-Registered Evaluation Plan (`FINAL_EVAL_PLAN_v2`)

> [!WARNING]
> **DRAFT SKELETON — NOT FINAL.**  
> No numbers, thresholds, split hashes, or technique/family selections are filled in here. **Do NOT execute v2 `--final`** until the Stage A pilot is complete, the blind test set is frozen, ALL `[TBD]` fields below are populated from committed artifacts, and this document is committed cleanly as `FINAL_EVAL_PLAN_v2.md`.

**Status:** `[TBD: DRAFT SKELETON — awaiting pilot, safety gate, & blind freeze]`  
**Repository:** `dfir-triage-ml` | **Planned Script/Entry:** `[TBD]`  
**Dataset Artifact:** `[TBD: data/processed/dataset_v2.parquet]`  
**Target Schemas:** `full_20`, `no_content`, `[TBD: optional v2_extended]`  

---

## 1. Blind Holdout Lock & One-Shot Execution Guard

- **Holdout Unit of Grouping:** Disjoint **`sample_family`**, **`ssdeep`/TLSH near-duplicate cluster**, `sample_sha256`, and **benign VM session / software-profile pool** (`0` cross-split family, binary, benign-key, or benign-run overlap verified by hard assertions).
- **Blind-Test Split Ratios:** `[TBD: dev families / blind_test families; dev benign sessions / blind_test benign sessions]` (set after Stage A pilot calibration).
- **Pre-Modeling Seal:**
  - `data/splits/v2_blind_test_manifest.json` committed at `[TBD: freeze_commit_sha]` **before** any developer dev-CV run, hyperparameter tuning, or threshold selection.
  - Canonical **`blind_test_sha256`**: `[TBD]` (covers sorted test `run_id`, `sample_sha256`, `sample_family`, `execution_state`, `artifact_key`, `label`, and all evaluated feature columns).
  - Pre-final code/bugfix commit (must strictly predate `--final`): `[TBD]`.
- **One-Shot Audit Guard:**
  - `run_v2_final` verifies `compute_frozen_test_hash(df) == manifest["blind_test_sha256"]` and aborts if `results/logs/final_eval_audit_v2.jsonl` contains any `"status": "executed"` entry (unless `--force` is explicitly logged).
  - All configurations (`full_20`, `no_content`, `[TBD: optional v2_extended]`) execute in **one single audited `--final` pass**.

---

## 2. Feature Configurations at `--final`

All forbidden columns (`ORACLE_FEATURES`, `RULE_FEATURES`, `META_COLUMNS` incl. all v2 provenance fields `sample_sha256`, `sample_family`, `sample_category`, `sample_source`, `execution_state`, `run_duration_s`, `detonation_exit_status`, `process_tree_root_guid`, `attribution_method`, `attribution_confidence`, and `LABEL_COL`) are strictly barred from `X` via `assert_no_forbidden_inputs()`.

1. **`full_20`** *(primary benchmark schema; identical 20 locked features to v1 for cross-version continuity)*:
   - Categorical (6): `artifact_type`, `path_class`, `ext_class`, `signature_state`, `parent_process_class`, `registry_location_class`
   - Numeric (8): `path_depth`, `name_length`, `name_entropy`, `file_size_log`, `file_entropy`, `cmdline_length`, `cmdline_entropy`, `cmdline_nonalnum_ratio`
   - Binary (6): `has_double_extension`, `has_encoded_flag`, `has_url_or_ip`, `has_lolbin`, `has_hidden_attr`, `autostart_flag`
2. **`no_content`** *(18 features; drops `file_size_log`, `file_entropy` — isolates non-byte structural signals & tests dormant visibility limits)*.
3. **`[TBD: optional v2_extended]`** *(if approved by operator in OPEN QUESTIONS; strictly secondary and never mixed into the `full_20`/`no_content` primary winner rule)*.

---

## 3. Evaluation Strata & Yield Summary (Locked Post-Pilot)

Performance will be reported **separately for each stratum** and `[TBD: overall stratified summary]`:
1. **`executed` Stratum:** `[TBD: N_dev_runs / N_test_runs; dev pos / neg; test pos / neg; N_families]`.
2. **`dormant` Stratum:** `[TBD: N_dev_runs / N_test_runs; dev pos / neg; test pos / neg; N_families]`.
3. **`[TBD: optional emulated Stratum]`:** `[TBD]`.

Rows flagged `ambiguous_unattributed` during automated Sysmon/ETW + diff labeling are audited in `label_corrections_v2.csv` / blind human adjudication before `blind_test_sha256` freeze and are **not** silently coerced to `benign_drift`.

---

## 4. Primary & Secondary Metrics

- **Primary Metric:** Overall and per-stratum (`executed`, `dormant`) frozen-test **PR-AUC** (`average_precision_score`) under both `full_20` and `no_content`.
- **Confidence Intervals:** Family- and session-clustered percentile/BCa bootstrap 95% CIs (`n_boot = [TBD: >= 2000]`, `seed = [TBD]`), explicitly reflecting **out-of-sample family generalization** (not merely run-to-run variation across fixed families).
- **Random Baseline:** Exact finite-sample expected PR-AUC computed via `[TBD: e.g. 10,000]` random permutations (reporting analytical/MC mean and 5th–95th percentile band) rather than a single arbitrary seed draw.
- **Deployable Operating Points (Dev-Calibrated Only):** Thresholds for `[TBD: target benign val FPR e.g. 1% and fixed alert budgets]` selected strictly from **nested dev OOF predictions** and evaluated once on blind test (never calibrated on test positives/negatives).
- **Secondary Metrics & Views:**
  - `tie_expected_precision_at_k` and `tie_expected_recall_at_k` at `k in [TBD: e.g. 10, 20, 50, 100]`, plus `ROC-AUC`.
  - Combined hard-negative drift slices (`benign_drift`-only negatives; `file+run_key+task+service` hard-negative view), per-`artifact_type`, and per-family (`N_test_families` breakdown).
  - Rule baselines (`rules_binary`, `rules_count`) and descriptive operating-point precision/recall matching against rules (tagged clearly if any threshold is retrospective).
  - **Learning Curve:** Family-grouped dev subsampling `[TBD: fractions]` × `[TBD: K >= 5]` seeds across all 6 ML arms (`mlp`, `rf`, `xgb`, `lr`, `ae`, `iforest`).
  - Scale-invariant SHAP normalized share & rank comparison (`mean|SHAP| / sum(mean|SHAP|)`, Spearman across all features and top-10 union), AE reconstruction error, IF permutation drop, and RF/XGB/MLP error analysis.

---

## 5. Multi-Seed Training, Nested Dev CV & Equal Tuning Budgets

- **Models Evaluated (All Preserved in Every Table):** Supervised: `rf`, `xgb`, `mlp`, `lr`; Unsupervised (benign-only `fit` + benign-only `pre.fit`, `n_attack_seen_in_fit_ == 0`): `ae`, `iforest`.
- **Nested Family-Grouped CV (Dev):** Outer `[TBD]`-fold family-grouped CV estimates unbiased dev PR-AUC; inner `[TBD]`-fold family-grouped CV tunes hyperparameters with an **equal trial budget `[TBD: N_trials]`** per tuned arm.
- **Early Stopping & Effective Training Size:** `mlp` and `ae` early-stop exclusively on disjoint **inner** grouped validation splits (never outer CV validation folds). Unsupervised `iforest` trains on `100%` of benign dev rows (never dropping a fold for unused `X_val`). Config-matched hyperparameters are mandatory for `full_20` vs `no_content` and all ablations.
- **Multi-Seed `--final` Protocol:** Run across `[TBD: K >= 5]` independent seeds (`seeds = [TBD]`), reporting single-seed mean ± std PR-AUC alongside the K-seed ensemble score for both dev and blind test.

---

## 6. Pre-Registered Confirmatory Comparisons & Winner Rule

- **Fixed Pre-Registered Comparison Family (No Post-Hoc `best_ml` Selection):**
  - `[TBD: finalize exact pair list, e.g.:]`
    1. `xgb` vs `rf`
    2. `rf` vs `mlp`
    3. `xgb` vs `mlp`
    4. `rf` vs `rules_count` & `rf` vs `rules_binary`
    5. `xgb` vs `rules_count` & `xgb` vs `rules_binary`
    6. `mlp` vs `rules_count` & `mlp` vs `rules_binary`
- **Multiple-Comparison Adjustment:** Paired family-clustered bootstrap p-values / CIs adjusted via **Holm-Bonferroni** across the pre-registered comparison family within each primary slice (`executed`, `dormant`, `[pooled]`).
- **Exact Dual-Configuration Winner Rule:**
  - Declare $A$ better than $B$ (`a_better` or `b_better`) **only if** the Holm-adjusted dual criterion shows significance in the **same direction in BOTH `full_20` and `no_content`**.
  - Otherwise declare **`not distinguishable`** (neither config excludes 0 after adjustment) or **`configuration-dependent`** (significant in only one config, or opposite directions).

---

## 7. Pre-`--final` Execution & Sign-Off Gate

```text
[TBD: Exact v2 CLI commands populated and verified after Phase 4 dev run completes]
```

### Mandatory Sign-Off Checklist Before Removing `DRAFT SKELETON` Status
- [ ] Operator approved Gate 0 safety & sample provenance (`V2_PLAN.md` §7).
- [ ] Stage A pilot completed and yield metrics recorded in `docs/v2/` (`[TBD: pilot report link]`).
- [ ] Independent blinded human review completed (`review_sample_v2.csv`, $\kappa = \text{[TBD]}$) and `label_corrections_v2.csv` committed.
- [ ] `v2_blind_test_manifest.json` (`blind_test_sha256`) frozen before any dev modeling.
- [ ] Nested dev CV + multi-seed learning curves + dev thresholds frozen cleanly in git.
- [ ] All `[TBD]` placeholders in this document replaced with exact verified values and committed prior to running `--final`.
