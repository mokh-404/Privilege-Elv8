# Track A v2 Pre-Registered Evaluation Plan (`FINAL_EVAL_PLAN_v2`)

> [!WARNING]
> **DRAFT SKELETON — NOT FINAL.**  
> No numbers, thresholds, split hashes, or technique/family selections are filled in here. **Do NOT execute v2 `--final`** until the Stage A pilot is complete, the blind test set is frozen, ALL `[TBD]` fields below are populated from committed artifacts, and this document is committed cleanly as `FINAL_EVAL_PLAN_v2.md`.

**Status:** `[TBD: DRAFT SKELETON — awaiting pilot, safety gate, & blind freeze]`  
**Repository:** `dfir-triage-ml` | **Planned Script/Entry:** `[TBD]`  
**Dataset Artifact:** `[TBD: data/processed/dataset_v2.parquet]`  
**Primary Target Schemas:** `full_20`, `no_content` *(plus pre-registered secondary `v2_refgraph` and `[TBD: optional v2_extended]` strictly outside the primary winner rule)*

---

## 1. Blind Holdout Lock & One-Shot Execution Guard

- **Holdout Unit of Grouping:** Disjoint **`sample_family`**, **`ssdeep`/TLSH near-duplicate cluster**, `sample_sha256`, **`pair_group_id`** (linking paired `dormant` and `executed` runs of the exact same binary), and **benign VM session / software-profile pool** (`0` cross-split family, binary, pair, benign-key, or benign-run overlap verified by hard assertions). Specifically, hard assertions MUST verify that paired `(sample_sha256, execution_state)` runs (`execution_state in {"dormant", "executed"}`, linked via `pair_group_id` / `sample_sha256`) never straddle `dev` and `blind_test` — both runs of every paired binary and its entire `sample_family` + fuzzy-hash cluster reside strictly in the same split pool. Frozen v1 `dataset_v1.parquet` (`emulated` stratum) is restricted strictly to `split_pool == "dev"`; the v2 blind test is **100% new** (`0` v1 rows/keys/techniques).
- **Blind-Test Split Ratios:** `[TBD: dev families / blind_test families; dev benign sessions / blind_test benign sessions]` (target `>= 25–30` total families, `>= 10–15` blind-test families; Stage A pilot calibrates feasibility).
- **Pre-Modeling Seal:**
  - `data/splits/v2_blind_test_manifest.json` committed at `[TBD: freeze_commit_sha]` **before** any developer dev-CV run, hyperparameter tuning, or threshold selection.
  - Canonical **`blind_test_sha256`**: `[TBD]` (covers sorted test `run_id`, `sample_sha256`, `sample_family`, `execution_state`, `artifact_key`, `label`, and all evaluated feature columns).
  - Pre-final code/bugfix commit (must strictly predate `--final`): `[TBD]`.
- **One-Shot Audit Guard:**
  - `run_v2_final` verifies `compute_frozen_test_hash(df) == manifest["blind_test_sha256"]` and aborts if `results/logs/final_eval_audit_v2.jsonl` contains any `"status": "executed"` entry (unless `--force` is explicitly logged).
  - All primary (`full_20`, `no_content`) and pre-registered secondary configurations execute in **one single audited `--final` pass**.

---

## 2. Feature Configurations at `--final`

All forbidden columns (`ORACLE_FEATURES`, `RULE_FEATURES`, `META_COLUMNS` incl. all 15 v2 provenance/pairing fields `schema_version`, `sample_sha256`, `sample_family`, `sample_category`, `sample_source`, `execution_state`, `run_duration_s`, `detonation_exit_status`, `process_tree_root_guid`, `attribution_method`, `attribution_confidence`, `packer_cluster`, `label_review_status`, `stratum`, `pair_group_id`, raw `REFGRAPH_EDGE_COLUMNS` `ref_targets`, `ref_type`, `linked_artifact_keys`, and `LABEL_COL`) are strictly barred from `X` via `assert_no_forbidden_inputs()`.

### Primary Schemas (Dual-Config Confirmatory Benchmark)
1. **`full_20`** *(primary benchmark schema; identical 20 locked features to v1 for cross-version continuity)*:
   - Categorical (6): `artifact_type`, `path_class`, `ext_class`, `signature_state`, `parent_process_class`, `registry_location_class`
   - Numeric (8): `path_depth`, `name_length`, `name_entropy`, `file_size_log`, `file_entropy`, `cmdline_length`, `cmdline_entropy`, `cmdline_nonalnum_ratio`
   - Binary (6): `has_double_extension`, `has_encoded_flag`, `has_url_or_ip`, `has_lolbin`, `has_hidden_attr`, `autostart_flag`
2. **`no_content`** *(18 features; drops `file_size_log`, `file_entropy` — isolates non-byte structural signals & tests dormant visibility limits)*.

### Secondary Pre-Registered Schemas (Strictly Outside `full_20`/`no_content` & Winner Rule)
3. **`v2_refgraph` (`OD-V2-13`, Secondary Pre-Registered Arm):**
   - Built **ONLY** from static cross-references extracted from the artifacts' own content (`ref_targets`, `ref_type`, `linked_artifact_keys` — e.g., Run key value -> target image path, service `ImagePath` -> binary, scheduled task action -> script/binary, Prefetch referenced files).
   - **Zero leakage rule:** Links must **NEVER** use labeling provenance, Sysmon event logs, process trees, or timestamps. Raw edge columns are barred from `full_20` and `no_content` via `FORBIDDEN_MODEL_INPUTS`; only the dedicated `v2_refgraph` feature builder may read them to compute derived numeric graph features.
   - Reported strictly in its own secondary table block; **never** enters `full_20`/`no_content` or the primary dual-config winner rule.
4. **`[TBD: optional v2_extended]`** *(strictly secondary if added, never mixed into the `full_20`/`no_content` primary winner rule)*.

---

## 3. Evaluation Strata & Yield Summary (Locked Post-Pilot)

Performance will be reported **separately for each stratum** and `[TBD: overall stratified summary]`, with **natural (full-host snapshot) prevalence as the main evaluation view** and a **subsampled prevalence view as secondary** (with stratum/sampling weights explicitly disclosed; `OD-V2-12`). For cross-stratum evaluation, `dormant` and `executed` runs are **paired by exact `sample_sha256` (`pair_group_id`)** and staged at the matching initial filesystem path:
1. **`executed` Stratum (~60–70% of real-malware runs):** `[TBD: N_dev_runs / N_test_runs; dev pos / neg; test pos / neg; N_families; N_paired_sha256]`.
2. **`dormant` Stratum (~30–40% of real-malware runs):** `[TBD: N_dev_runs / N_test_runs; dev pos / neg; test pos / neg; N_families; N_paired_sha256]` (paired `sample_sha256` binaries staged without execution at the matching initial staging path).
3. **`emulated` Stratum (`dev` / training pool ONLY; `0%` of blind test):** Frozen v1 (`dataset_v1.parquet`: `1,549` rows, `103` pos) disclosed explicitly as an `"emulated"` training-pool stratum (`[TBD: dev training weight / ablation disclosure]`).

Rows flagged `ambiguous_unattributed` during automated Sysmon/ETW + diff labeling are audited in `label_corrections_v2.csv` / blind human adjudication before `blind_test_sha256` freeze and are **not** silently coerced to `benign_drift`.

---

## 4. Primary & Secondary Metrics

### Primary Confirmatory Metric & Uncertainty
- **Primary Metric:** Overall and per-stratum (`executed`, `dormant`) frozen-test **PR-AUC** (`average_precision_score`) under both `full_20` and `no_content` (natural full-host prevalence main view; subsampled prevalence secondary view with weights disclosed).
- **Bootstrap Confidence Intervals (Unadjusted Effect-Size Spread):** Family- and session-clustered bootstrap 95% CIs (`n_boot = [TBD: >= 2000]`, `seed = [TBD]`), explicitly reflecting **out-of-sample family generalization** (not merely run-to-run variation across fixed families). Unadjusted 95% percentile CIs are reported alongside `p_raw` and Holm-adjusted `p_adj` for effect-size estimation only.
- **Random Baseline:** Exact finite-sample expected PR-AUC computed via `[TBD: 10,000]` random permutations (reporting Monte Carlo mean, SD, and 5th–95th percentile band) rather than a single arbitrary seed draw.
- **Deployable Operating Points (Dev-Calibrated Only):** Thresholds for `[TBD: target benign val FPR e.g. 1% and fixed alert budgets]` selected strictly from **nested dev OOF predictions** and evaluated once on blind test (never calibrated on test positives/negatives).

### Secondary Pre-Registered Metrics & Diagnostics (`OD-V2-13`, `OD-V2-14`, `OD-V2-15`)
- **Top-`k` Ranking & Slice Views:** `tie_expected_precision_at_k` and `tie_expected_recall_at_k` at `k in {10, 20, 50, 100}`, plus `ROC-AUC`. Combined hard-negative drift slices (`benign_drift`-only negatives; `file+run_key+task+service` hard-negative view), per-`artifact_type`, and per-family (`N_test_families` breakdown).
- **Tail-Risk & Analyst-Effort Metrics (`OD-V2-14`, Secondary Pre-Registered):**
  - `worst_positive_rank` (1-indexed rank and percentile of the worst-ranked positive artifact),
  - Recall at analyst review budgets (`k in {10, 20, 50, 100}`),
  - Positives in bottom 50% and bottom 90% of model scores (`pos_in_bottom_50pct`, `pos_in_bottom_90pct`),
  - `effort@recall` (`effort_at_recall_50`, `effort_at_recall_80`, `effort_at_recall_90` — count and fraction of artifacts reviewed to reach 50%, 80%, and 90% recall).
  - **Random Tail Audit Sample-Size Calculator *(Future Work Only)*:** Observing `0` missed positives in $n$ uniform random tail draws yields a 95% upper bound on the missed-positive rate of $p_{\text{upper}}(n) = 1 - 0.05^{1/n}$ (e.g., $n = 5 \to 45.1\%$, $n = 59 \to 5.0\%$, $n = 300 \to 1.0\%$). Any live/field tail audit is deferred strictly as **future work only**.
- **Referential-Graph Arm (`v2_refgraph`, `OD-V2-13`, Secondary Pre-Registered):** Evaluated with the exact same dev-calibrated/nested pipeline on static cross-reference features; reported in its own secondary table block alongside per-type link coverage.

### Cross-Stratum Execution Delta (`executed` vs `dormant` on Paired `sample_sha256` Binaries, `OD-V2-15`, Secondary Pre-Registered)
Evaluated strictly over paired `sample_sha256` binaries ($s \in \mathcal{S}_{\text{paired}}$, linked by `pair_group_id`) tested in both `dormant` (unexecuted staging run) and `executed` (detonated from the matching initial staging path) strata within the same split pool:
1. **Stratum-Conditional PR-AUC & Recall@k Delta ($\Delta_{\text{exec}}$):**
   $$\Delta_{\text{exec}}(M, C) = \text{Metric}(M, C \mid \text{executed}) - \text{Metric}(M, C \mid \text{dormant})$$
   computed across configurations $C \in \{\text{full\_20}, \text{no\_content}, \text{drop\_signature}, \text{no\_content\_no\_sig}\}$ *(plus secondary `v2_refgraph`)* with **family-clustered paired bootstrap 95% CIs** (`n_boot = [TBD: >= 2000]`), resampling whole malware families/clusters so paired `executed` and `dormant` runs of family $f$ are always resampled together.
2. **Sample-Level First-Detection Rank / Effort Delta ($\Delta_{\text{first\_hit}}$):**
   Because detonation emits multiple host artifacts whereas `dormant` runs contain only the quiescent binary row (resulting in differing row-level positive prevalences across strata), define for each paired sample $s \in \mathcal{S}_{\text{paired}}$:
   - $\text{Rank}_{\min}(s, \text{stratum})$: the 1-indexed rank (and normalized percentile effort $\text{Rank}_{\min} / N_{\text{run}}$) of the **highest-scored `attacker_induced` artifact** produced by sample $s$ within its host run;
   - Report **median and IQR** of $\Delta_{\text{first\_hit}}(s) = \text{Rank}_{\min}(s, \text{dormant}) - \text{Rank}_{\min}(s, \text{executed})$ alongside **Intrusion-Detection Recall@k** (fraction of paired malware samples $s \in \mathcal{S}_{\text{paired}}$ with at least one `attacker_induced` artifact inside the top $k \in \{5, 10, 20, 50\}$ ranked host leads).
3. **Byte/Signature Evasion Resilience Hypothesis (Pre-Registered Secondary Contrast):**
   Explicitly test the pre-registered hypothesis that under `dormant` staging, removing file content and signature signals (`full_20` $\to$ `no_content` / `drop_signature` / `no_content_no_sig`) causes a severe ranking drop ($\Delta_{\text{ablation, dormant}}$), whereas after detonation (`executed`), the multi-artifact OS execution footprint preserves ranking performance under the exact same feature deprivation:
   $$|\Delta_{\text{ablation, executed}}| < |\Delta_{\text{ablation, dormant}}|$$
   evaluated via family-clustered paired bootstrap 95% CIs and two-sided paired family-clustered bootstrap p-values (`p_raw`).

- **Rule Baselines, Learning Curves & Explainability:** `rules_binary` and `rules_count`; family-grouped dev learning curve across `[TBD: fractions]` × `K = 5` seeds; scale-invariant SHAP normalized share & rank comparison, AE reconstruction error, IF permutation drop, and RF/XGB/MLP error analysis.

---

## 5. Multi-Seed Training, Nested Dev CV & Equal Tuning Budgets

- **Models Evaluated (All Preserved in Every Table):** Supervised: `rf`, `xgb`, `mlp`, `lr`; Unsupervised (benign-only `fit` + benign-only `pre.fit`, `n_attack_seen_in_fit_ == 0`): `ae`, `iforest` (default selection strictly label-free; any labeled-val selection explicitly tagged `"label-selected"`).
- **Nested Family-Grouped CV (Dev):** Outer `[TBD: 5]`-fold family-grouped CV estimates unbiased dev PR-AUC (+ leave-one-family-out LOFO table); inner `[TBD: 4]`-fold family-grouped CV tunes hyperparameters with an **equal trial budget `[TBD: 30 (fallback 20 if pilot compute heavy)]`** per tuned arm.
- **Early Stopping & Effective Training Size:** `mlp` and `ae` early-stop exclusively on disjoint **inner** grouped validation splits (never outer CV validation folds). Unsupervised `iforest` and all non-early-stopped arms train on `100%` of eligible dev rows (never dropping a fold for unused `X_val`). Config-matched hyperparameters are mandatory for `full_20` vs `no_content`, `v2_refgraph`, and all ablations.
- **Multi-Seed `--final` Protocol:** Run across `K = 5` independent seeds (`seeds = [TBD: 42, 43, 44, 45, 46]`), reporting single-seed mean ± std PR-AUC alongside the K-seed ensemble score for both dev and blind test.

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
- **Multiple-Comparison Adjustment (Bootstrap p-Values Only — Do NOT Adjust CIs):**
  - For each pre-registered pair $(A, B)$ within a primary slice (`executed`, `dormant`, `[pooled]`) and primary config (`full_20`, `no_content`), compute the **two-sided paired family-clustered bootstrap p-value** from the $B$ paired bootstrap replicates $\{\Delta_b = \text{PR-AUC}_b(A) - \text{PR-AUC}_b(B)\}_{b=1}^B$:
    $$p_{\text{raw}} = 2 \cdot \min\left(\frac{1 + \#\{\Delta_b \le 0\}}{1 + B}, \; \frac{1 + \#\{\Delta_b \ge 0\}}{1 + B}\right)$$
  - Apply **Holm-Bonferroni step-down adjustment to `p_raw`** across the fixed pre-registered comparison family (`p_adj`, significance threshold `alpha = 0.05`). **Holm-Bonferroni adjusts bootstrap p-values, NOT percentile confidence intervals**; unadjusted 95% family-clustered bootstrap CIs are reported alongside `p_raw` and `p_adj` for effect-size context only.
- **Exact Dual-Configuration Winner Rule:**
  - Declare $A$ better than $B$ (`a_better` or `b_better`) **only if Holm-adjusted `p_adj < 0.05` in the SAME direction in BOTH `full_20` and `no_content`**.
  - Otherwise declare **`not distinguishable`** (neither config has `p_adj < 0.05`) or **`configuration-dependent`** (`p_adj < 0.05` in only one config, or opposite directions).
  - Secondary arms (`v2_refgraph`, `[TBD: optional v2_extended]`) and secondary metrics (`OD-V2-14` tail-risk/effort, `OD-V2-15` Cross-Stratum Execution Delta $\Delta_{\text{exec}}$, $\Delta_{\text{first\_hit}}$, Intrusion-Detection Recall@k, and Byte/Signature Evasion Resilience Hypothesis $|\Delta_{\text{ablation, executed}}| < |\Delta_{\text{ablation, dormant}}|$) are strictly outside this confirmatory winner rule and are evaluated using family-clustered paired bootstrap 95% CIs (resampling whole families/clusters together) and two-sided paired family-clustered bootstrap p-values (`p_raw`).

---

## 7. Pre-`--final` Execution & Sign-Off Gate

```text
[TBD: Exact v2 CLI commands populated and verified after Phase 4 dev run completes]
```

### Mandatory Sign-Off Checklist Before Removing `DRAFT SKELETON` Status
- [ ] Written professor/university approval obtained and Operator approved Gate 0 safety & sample provenance (`V2_PLAN.md` §7, `OD-V2-07`).
- [ ] Stage A pilot completed and yield metrics recorded in `docs/v2/` (`[TBD: pilot report link]`).
- [ ] Independent blinded human review completed (friend = primary blinded reviewer, Mokh = 20% overlap scorer; `review_sample_v2.csv`, $\kappa = \text{[TBD]}$) and `label_corrections_v2.csv` committed.
- [ ] `v2_blind_test_manifest.json` (`blind_test_sha256`) frozen before any dev modeling.
- [ ] Nested dev CV + multi-seed learning curves + dev thresholds frozen cleanly in git.
- [ ] All `[TBD]` placeholders in this document replaced with exact verified values and committed prior to running `--final`.
