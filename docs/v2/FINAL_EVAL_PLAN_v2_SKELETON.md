# Track A v2 Pre-Registered Evaluation Plan (`FINAL_EVAL_PLAN_v2`)

> [!WARNING]
> **DRAFT SKELETON — NOT FINAL.**  
> No numbers, thresholds, split hashes, or family selections are filled in here. **Do NOT execute v2 `--final`** until the Stage A pilot and Stage B collection are complete, blinded human review is adjudicated, the blind test set is frozen, ALL `[TBD]` fields below are populated from committed artifacts, and this document is committed cleanly as `FINAL_EVAL_PLAN_v2.md`.

**Status:** `[TBD: DRAFT SKELETON — awaiting Stage A pilot, Stage B collection, & blind freeze]`  
**Repository:** `dfir-triage-ml` | **Comparative Study Target:** `~20` ML, LTR, Deep Tabular, Unsupervised & Rule Arms (`full_20`, `no_content`)  
**Dataset Artifact:** `[TBD: data/processed/dataset_v2.parquet]`

---

## 1. Blind Holdout Lock & One-Shot Execution Guard

- **Holdout Unit of Grouping:** Disjoint **`sample_family`**, **`ssdeep`/`ppdeep`/`tlsh`/`imphash` near-duplicate cluster**, `sample_sha256`, **`pair_group_id`** (pairing `executed` and `dormant` runs of the exact same binary), and **benign host profile / asset pool** (`DEV_WORKLOAD_PROFILES` `B_dev_01..20` vs `BLIND_TEST_WORKLOAD_PROFILES` `B_test_01..10`, `0` cross-split SHA-256, filename, package, key, or `run_id` overlap).
- **Scale Target (`OD-V2-01`):**
  - **Tier 2 Target:** `1,000` usable standalone-`.exe` real malware samples (`800` dev / `200` blind test) across `50–60` non-destructive families (`F_test = 20–25` blind test, `>= 15` floor, per-family caps `<= 30` dev / `<= 15` test) + `200` benign-only runs (`160` dev / `40` test).
  - **Checkpoint 1 (Tier 1):** `400` usable (`300`/`100`), `30` families (`15` blind test) + `100` benign-only runs (`80`/`20`).
  - **Hard Exclusions (`OD-V2-08`):** Zero ransomware, wipers, or self-propagating worms.
  - **v1 `emulated` Stratum (`OD-V2-02`):** Frozen `dataset_v1.parquet` (`1,104` cold-disk `dev` rows excluding `75` live `process` rows) restricted strictly to `split_pool == "dev"` (`0%` blind test).
- **Pre-Modeling Seal:**
  - `data/splits/v2_blind_test_manifest.json` (`blind_test_sha256`) committed at `[TBD: freeze_commit_sha]` **before** any dev-CV run, hyperparameter tuning, calibration, or threshold selection.
  - One-shot guard via `results/logs/final_eval_audit_v2.jsonl` refuses duplicate `--final` runs without explicit `--force`.

---

## 2. Feature Schemas & Prevalence Separation

All `FORBIDDEN_MODEL_INPUTS` (`ORACLE_FEATURES`, `RULE_FEATURES`, `META_COLUMNS` incl. 15 v2 provenance columns, `REFGRAPH_EDGE_COLUMNS`, `LABEL_COL`) are barred from `X` via `assert_no_forbidden_inputs()`.

- **Primary Dual Schemas (`OD-V2-11`):**
  1. **`full_20`** (locked 20 features matching v1 for `H3` cross-version transfer parity)
  2. **`no_content`** (18 features dropping `file_size_log` and `file_entropy`)
  *(Note: `v2_refgraph` is descoped from v2 core per 2026-11-25 strategic pivot.)*
- **Train-vs-Test Prevalence Separation (`OD-V2-12`):**
  - **Dev Pointwise/Unsupervised (`dev_dedup`):** Fold-local / dev-only cross-run OS-baseline deduplication (`deduplicate_dev_os_baseline`) collapses untouched identical `baseline` rows on `(artifact_key, stable_content_hash)` (`~61k–91k` rows).
  - **Dev LTR (`dev_ltr`):** Per-host `qid=run_id` query groups retaining all positives, all `benign_drift`, and `200` stratified baseline negatives/host (`~400k` rows).
  - **Blind Test (`MAIN VIEW`):** **ZERO cross-run deduplication** (`~1.96M` rows across `440` independent hosts, `0.0714%` positive prevalence). Secondary benign-subsampled view (`200` benign/host) reported with explicit inverse-probability weights.

---

## 3. Model Arms, Equal `20`-Trial Nested CV & Natural-Prevalence Calibration

- **Evaluated Arms (~20 Total):**
  - *Linear / Kernel / Instance:* `lr`, `linear_svc` (+ Platt), `nystroem_rbf`, `knn_capped` (`15k` stratified index cap)
  - *Classical & Boosted Trees:* `dt`, `rf`, `et`, `histgbdt`, `xgb`, `lgbm`, `catboost`
  - *Learning-to-Rank (`dev_ltr`):* `xgb_ranker`, `lgbm_ranker`
  - *Neural / Deep Tabular (RTX 2050 CUDA):* `mlp`, `ft_transformer` / `resnet_tabular` *(optional `tabpfn_10k` exploratory-only if weights available)*
  - *Unsupervised (`y == 0` benign fit):* `iforest`, `ae`, `nystroem_ocsvm`, `lof_capped` (`15k` benign index cap)
  - *Deterministic / Baselines / Hybrid:* `rules_binary`, `rules_count`, `mc_random` (`10,000` perms), `rule_ml_hybrid`
- **Equal Tuning Budget (`OD-V2-06`):** **ALL tuned models** receive an **identical `20`-trial random/Optuna budget** inside **`5`-fold outer × `3`-fold inner** family-grouped nested CV (`V2_N_SEARCH_TRIALS = 20`, `V2_OUTER_FOLDS = 5`, `V2_INNER_FOLDS = 3`), evaluated across **`K = 5` final seeds (`[42, 43, 44, 45, 46]`)**.
- **Natural-Prevalence Calibration & Thresholds:** Probability calibrators (`Platt` / `Isotonic`) and dev-calibrated `1%` & `5%` FPR thresholds are fitted strictly on **natural-prevalence dev OOF predictions, or on deduped dev rows weighted by multiplicity**, NEVER on unweighted `dev_dedup` (`~7%`) prevalence.

---

## 4. Hypotheses (`H1`–`H4`), Multiple-Comparison Control & 5-Axis Selection

- **Pre-Registered Hypotheses (`REPLAN_COMPARATIVE_STUDY.md` §6):**
  - **`H1` (Split-Leakage Sensitivity):** Random row split vs family + fuzzy-hash grouped split (`>= +0.05` vs falsified `< 0.02`).
  - **`H2` (Provenance-Label Trust):** Strict `labeler_v2` provenance vs heuristic pseudo-labels anchored by blinded human review (`kappa >= 0.70`, `400` friend / `80` Mokh overlap).
  - **`H3` (Emulated vs Real Transfer):** `emulated-only` vs `real-matched` (size-matched control) vs `real-full` vs `mixed` tested on unseen blind real malware.
  - **`H4` (Decisive Paradigm Separation):** Omnibus Friedman + Nemenyi CD + pre-registered `m = 10` paradigm-representative Holm-Bonferroni contrasts + 5-axis decision scorecard.
- **Per-State & Descriptive Contrasts:** Report `executed`, `dormant`, and pooled real-malware metrics separately alongside evasion ablations (`drop_signature`, `no_content`, `no_content_no_sig`) strictly as plain descriptive tables (zero novelty claim).
- **Two-Stage Inference & 5-Axis Selection:**
  1. Stage 1: Omnibus Friedman ($\alpha = 0.05$) + Nemenyi CD over blind-test family-level `AP`.
  2. Stage 2: Pre-registered `m = 10` paradigm-representative contrasts (selected on dev OOF before unblinding test) evaluated with family-clustered paired bootstrap ($B \ge 2000$) + step-down Holm-Bonferroni (`p_adj < 0.05` on p-values only; unadjusted 95% CIs reported for spread).
  3. 5-Axis Scorecard: Discrimination (`35%`), Effort & Tail Risk (`25%`), Evasion Resilience (`15%`), Stability/LOFO/ECE (`15%`), CPU Inference + Top-25 SHAP Latency (`10%`, disqualified if `> 5.0s/host` or fails `rules_count`/`mc_random`).

---

## 5. Pre-`--final` Sign-Off Gate

- [ ] Written Supervisor Marawan (AASTMT) approvals (`2026-11-23` + `2026-11-25` addendum) and Mokh `0400` `GATE0_SIGNED_OFF` + `preflight` + `--canary` (`CANARY_PASSED`) verified.
- [ ] Stage A Pilot completed (`docs/v2/STAGE_A_PILOT_REPORT.md`) with calibrated detonation yield and empirical between-family SD $\hat{\sigma}_{\Delta,\text{family}}$.
- [ ] Disjoint `dev`/`blind_test` benign pool audit passed (`check_template_quantization` PASS, `0` cross-split overlap).
- [ ] Blinded human review completed (`400` friend / `80` Mokh overlap, $\kappa = \text{[TBD]}$) and `label_corrections_v2.csv` committed.
- [ ] `v2_blind_test_manifest.json` (`blind_test_sha256`) frozen before any dev modeling, and all `[TBD]` placeholders populated.
