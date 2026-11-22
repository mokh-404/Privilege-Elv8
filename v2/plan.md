# DFIR-Triage ML — v2 Phase 1 Preparation Plan

**Status:** `APPROVED — STEP 0 IN PROGRESS / COMPLETE (NEXT: STEP 1)`  
**Repository:** `dfir-triage-ml` (branch `main`, base commit `c5b30c1`)  
**Scope:** Phase 1 preparation ONLY — **NO malware acquisition, downloads, or execution**, **NO VM runs**, **NO host firewall, network, or libvirt domain XML changes applied**. Gate 0 is **NOT** signed off.

---

## 1. Documentation Audit & Repository State Summary

All non-duplicate `.md` documentation across `grad/` has been reviewed prior to planning:
- **Top-level project docs:** `grad/docs/DFIR-Triage_Literature_Presenter_Guide.md`, `grad/docs/DFIR-Triage_Project_Explanation.md`
- **Phase-1 archive variants:** `docs_aistudio/*.md` (7 files) and `docs_gemini/*.md` (7 files)
- **Active repository (`docs_claude/dfir-triage-ml/`):** `README.md`, `COMPLETE_REPORT.md`, `collector/README.md`, `lab_automation/README.md`, `data/processed/data_dictionary.md`, `docs/FINAL_EVAL_PLAN.md`, `docs/IMPROVEMENT_ANALYSIS.md`, `docs/INDEX.md`, `docs/PLAN.md`, `docs/PRE_51_LAUNCH.md`, `docs/PROGRESS.md`, `docs/WINDOWS_11_LAB_SETUP.md`, `docs/WORK_SUMMARY.md`, `docs/specs/00_README.md`..`12_operator_decisions.md`, `docs/v2/V2_PLAN.md`, `docs/v2/FINAL_EVAL_PLAN_v2_SKELETON.md`. *(Duplicate files in `docs_claude/00..10` and `data/interim/dry_run_processed/data_dictionary.md` were excluded as duplicates of `docs/specs/` and `data/processed/data_dictionary.md`.)*

### Key State Findings
- **v1 is permanently frozen:** `51` live Windows 11 VM runs (`1,549` rows: `103` `attacker_induced`, `380` `benign_drift`, `1,066` `baseline`), `full_20` + `no_content` dual-config `--final` executed once at `2026-11-22T02:04:38Z` (`results/logs/final_eval_audit.jsonl`).
- **Known gaps tracked in `docs/IMPROVEMENT_ANALYSIS.md` (`IMP-01`..`IMP-19`) and `docs/v2/V2_PLAN.md`:**
  - Safety/isolation gaps for real malware (`IMP-01`, `IMP-02`, `IMP-16`).
  - Labeling/review gaps (`IMP-03`, `IMP-04`).
  - Splits/realism/schema gaps (`IMP-05`, `IMP-06`, `IMP-07`, `IMP-13`).
  - Training/stats/ablation/hygiene gaps (`IMP-08`, `IMP-09`, `IMP-10`, `IMP-11`, `IMP-14`, `IMP-15`).

---

## 2. Frozen v1 Baseline & Hard Rules

### Frozen v1 Integrity Baseline (Verified Before Step 0)
- `data/processed/dataset_v1.parquet` SHA-256: `39527f85fbda75f952e0cf5134a07467bf546501cb540ba68cd65b14983c7f21`
- `data/splits/dataset_v1_manifest.json` SHA-256: `788b6a7cab836c1851a90c5069e89496aa748c33f86643a84d9d70cc50857fbe`
- Internal `test_sha256` inside `dataset_v1_manifest.json`: `0f1ff3ec054bf00c66875fb5d2466e3b8d35685d69c2f0203d6787b71852ffa8`
- `results/logs/runner_footprint_dropped.csv`: `99` lines (`1` header + `98` dropped rows)

### Non-Negotiable Hard Rules (Enforced on Every Step)
1. **v1 is frozen.** Implement v2 changes as new modules (`src/v2/`, `docs/v2/`, `v2/`) or v2-gated flags; v1 default behavior must stay 100% reproducible.
2. **After every step, prove v1 is unchanged** using:
   ```bash
   .venv/bin/pytest
   sha256sum data/processed/dataset_v1.parquet data/splits/dataset_v1_manifest.json
   git diff --stat results/ data/ docs/FINAL_EVAL_PLAN.md
   ```
   `git diff --stat results/ data/ docs/FINAL_EVAL_PLAN.md` must be empty.
3. **Do NOT run `--final` for v1**, and **do NOT write any research-paper text**.
4. **Do NOT acquire, download, or execute any malware.** Gate 0 is not signed off.
5. **Command boundaries:** Sudo exists only for `virsh`, `qemu-img`, `chown`, `cp`, `rm`. Never use `virsh create`. Anything needing `iptables`/`nftables`/libvirt network or domain XML changes must be written as scripts + verification checklists into `docs/v2/hardening/` for Mokh to run — never run them directly.
6. **Commit, stop, and report after every step** (files changed, tests run and results, proof v1 is unchanged, anything blocked, and the next step).

> **Pre-Step-1 Pitfall (`IMP-15`):** In Step 0 (docs-only, before Step 1 fixes `IMP-15`), running `.venv/bin/pytest` triggers `tests/test_rules_and_labeler.py` (`build_dataset(...)` without `runner_log_path` override), which appends 2 synthetic rows to tracked `results/logs/runner_footprint_dropped.csv` (`mode="a"`). During Step 0 verification, we will run `pytest`, record the exact `IMP-15` side effect, restore `results/logs/runner_footprint_dropped.csv` cleanly (`git checkout -- results/logs/runner_footprint_dropped.csv`), and verify `git diff --stat results/ data/ docs/FINAL_EVAL_PLAN.md` is empty. From Step 1 onward, `pytest` must leave zero tracked diffs automatically.

---

## 3. Proposed v2 Directory Layout

Keeping v2 decoupled from frozen v1 artifacts and defaults:

```text
dfir-triage-ml/
├── v2/
│   └── plan.md                         # This master Phase 1 preparation plan
├── docs/v2/
│   ├── OPERATOR_DECISIONS.md           # Step 0: pending operator confirmations
│   ├── V2_PLAN.md                      # Step 0: updated v2 architecture & pilot plan
│   ├── FINAL_EVAL_PLAN_v2_SKELETON.md  # Pre-registered v2 evaluation skeleton
│   ├── BENIGN_GENERATOR_V2_DESIGN.md   # Step 5: varied benign generator design
│   ├── benign_noise_v2_stub.ps1        # Step 5: PowerShell v2 generator stub (no VM run)
│   └── hardening/                      # Step 6: scripts & checklists for Mokh to run
│       ├── README.md
│       ├── 01_firewall_win11_isolated.sh
│       ├── 02_domain_xml_hardening.md
│       ├── 02_patch_win11_xml.py
│       ├── 03_inetsim_vm_setup.md
│       ├── 03_inetsim.conf
│       ├── 04_watchdog_and_base_hash.py
│       ├── 05_negative_egress_checklist.md
│       └── 06_offline_extraction_design.md
├── src/v2/
│   ├── __init__.py
│   ├── config_v2.py                    # Step 2: K=5 seeds, 30 trials, expanded v2 search spaces
│   ├── models_v2.py                    # Step 2: configurable v2 MLP & AE arms
│   ├── training.py                     # Step 2: 100%-dev iforest, inner-val early stop, nested CV, multi-seed final
│   ├── stats.py                        # Step 3: MC random PR-AUC, family-clustered bootstrap, Holm-Bonferroni, dev thresholds, LOFO
│   ├── ablations_v2.py                 # Step 3: dev-only, config-matched, tie-expected, audit-guarded ablations
│   ├── labeler_v2.py                   # Step 4: Sysmon process-tree, multi-control baseline, ambiguous_unattributed, dormant manifest
│   ├── review_v2.py                    # Step 4: blinded review export, non-overwrite guard, Cohen's kappa
│   └── benign_generator_v2.py          # Step 5: offline varied benign software/script/service/registry generator + realism gate
└── tests/
    ├── test_repo_hygiene.py            # Step 1: asserts pytest mutates zero tracked files
    ├── test_v2_schema.py               # Step 1: asserts v2 provenance columns barred from X + rule export parity
    ├── test_v2_training.py             # Step 2: asserts 100% iforest fit, inner-only ES/preproc, nested CV, multi-seed final
    ├── test_v2_stats.py                # Step 3: asserts MC PR-AUC, Holm-Bonferroni, dev thresholds, LOFO, ablations
    ├── test_v2_labeler_and_review.py   # Step 4: synthetic process-tree/dormant labeling, blinded export, kappa
    ├── test_v2_realism_audit.py        # Step 5: real byte histograms in shortcut audit + benign realism gate
    └── test_v2_hardening_tools.py      # Step 6: unit tests on synthetic XML/mock subprocesses (no host changes)
```

---

## 4. Detailed Step-by-Step Execution Plan

### STEP 0 — Record Decisions
- **Deliverables:**
  - Create `docs/v2/OPERATOR_DECISIONS.md` and update `docs/v2/V2_PLAN.md` (plus sync `docs/INDEX.md` entry if appropriate).
  - Mark **every single item** explicitly as **`pending Mokh's confirmation`**:
    1. **Data targets expressed in FAMILIES + positives/runs:** `>= 25–30` total distinct malware families, `>= 10–15` distinct families in the blind test (pilot decides final feasibility), paired with rough planning anchor of ~300–500 positives across 100+ VM runs calibrated via pilot yield.
    2. **v1 data reuse:** Reuse `dataset_v1.parquet` strictly as a third `"emulated"` training-pool stratum (`dev` only); the v2 blind test is **100% new** (zero v1 rows, keys, or techniques in v2 blind test), with reuse disclosed in all reports/tables.
    3. **Fake-internet responder:** `INetSim` on a **separate isolated Linux VM** attached to `win11-isolated` (never on the host OS, never in-guest FakeNet-NG).
    4. **Offline extraction:** **User-space offline parsing inside an unprivileged container** (`--network=none`, `--read-only`, `--cap-drop=ALL`, pure user-space QCOW2/NTFS/registry/EVTX/Amcache/Prefetch parsing); **never host-kernel mounts** (`mount` / `qemu-nbd` kernel filesystem mount) of infected images.
    5. **Stage A Pilot size:** `~3` control boots + `6–8` non-test families × `1–2` runs (`executed` + `dormant`).
    6. **Compute/tuning budget:** `K = 5` seeds for multi-seed `--final` and learning curves; `30` equal trials per tuned model arm in nested dev CV.
    7. **Other open-question defaults from `docs/v2/V2_PLAN.md` §14:**
       - Authorized malware sample source + encrypted non-executable host vault (`0700`/`0400`) + SHA-256 manifest + written Gate 0 sign-off.
       - AVClass2 / ClarAVy family consensus normalization + `ssdeep`/TLSH/imphash near-duplicate clustering across Ransomware, InfoStealer, Loader/Dropper, RAT/Backdoor, Coinminer, Trojanized Installer.
       - Independent blinded human review (Mokh + second independent reviewer on a 20% overlap slice for Cohen's $\kappa$).
       - Feature schema scope: `full_20` + `no_content` as primary benchmark schemas, with any optional additive `v2_extended` strictly separated.
       - Realistic varied benign software/script/service/registry roster + full-host snapshot prevalence reported alongside hard-negative diagnostic slices.
- **Planned commit message:** `docs(v2): record pending operator decisions and update V2_PLAN (Step 0)`

---

### STEP 1 — Hygiene and Schema (`IMP-15`, `IMP-07`, `IMP-13`)
- **`IMP-15` (Test hygiene — stop mutating tracked logs):**
  - Update `tests/test_rules_and_labeler.py` (`test_labeler_end_to_end_diff_dedupe_and_no_leakage`, `test_labeler_rejects_forbidden_tokens`, `test_label_does_not_depend_on_timestamps_or_rules`) to pass `runner_log_path=tmp_path / "runner_dropped.csv"` and `sanitization_report=tmp_path / "san_fail.csv"`.
  - In `src/data/labeler.py`: add optional `sanitization_report: str | Path | None = config.SANITIZATION_FAILURES_CSV` to `build_dataset()` (forwarding to `assert_clean` and `label_run`), and initialize `runner_log_path` cleanly per `build_dataset()` invocation (fresh file / `mode="w"` accumulation across the build) while keeping `sanitize.drop_runner_footprint(..., log_path=...)` backward-compatible for existing tests.
  - Create `tests/test_repo_hygiene.py` asserting that running labeler/eval tests leaves `results/`, `data/`, and `docs/FINAL_EVAL_PLAN.md` unchanged (checking `results/logs/runner_footprint_dropped.csv` SHA-256 and `git diff --stat results/ data/ docs/FINAL_EVAL_PLAN.md`).
- **`IMP-07` (v2 provenance columns in `META_COLUMNS` & `FORBIDDEN_MODEL_INPUTS`):**
  - Keep `config.FEATURES` (exact 20 columns) completely unchanged.
  - Preserve `V1_META_COLUMNS = ["run_id", "technique_id", "variant", "launcher", "artifact_key"]` in `src/config.py`.
  - Define `V2_PROVENANCE_COLUMNS` containing all 14 exact columns:
    `schema_version`, `sample_sha256`, `sample_family`, `sample_category`, `sample_source`, `execution_state`, `run_duration_s`, `detonation_exit_status`, `process_tree_root_guid`, `attribution_method`, `attribution_confidence`, `packer_cluster`, `label_review_status`, `stratum`.
  - Set `META_COLUMNS = V1_META_COLUMNS + V2_PROVENANCE_COLUMNS` and `FORBIDDEN_MODEL_INPUTS = frozenset(ORACLE_FEATURES + RULE_FEATURES + META_COLUMNS + [LABEL_COL])`.
  - Update `tests/test_config.py::test_locked_lists_exact` to check `V1_META_COLUMNS` and v2-extended `META_COLUMNS`, and create `tests/test_v2_schema.py` proving none of the 14 v2 provenance columns (nor any v1 meta/oracle/rule/label column) can ever enter `X` via `assert_no_forbidden_inputs()` or `SharedPreprocessor`, even if passed in `allowed_extra`.
- **`IMP-13` (Export rule-critical fields so rules re-evaluate identically):**
  - Define `RULE_EXPORT_COLUMNS = ["task_name", "service_name", "start_mode", "task_triggers", "account_is_admin", "account_enabled"]` in `src/config.py`.
  - In `src/rules/deterministic_rules.py` (`evaluate_row` `RULE-013`): support flattened `account_is_admin` / `account_enabled` columns when `raw` dict is absent while preserving exact v1 behavior when `raw` dict is present.
  - In `src/data/labeler.py` (`build_dataset` `meta_extra`): flatten `account_is_admin` / `account_enabled` from `raw` if present and export `RULE_EXPORT_COLUMNS` when present in input rows (v1 `dataset_v1.parquet` is NOT rebuilt).
  - In `src/eval/run_track_a.py` (`_eval_single_config_on_test` `test_meta_cols`): persist `RULE_EXPORT_COLUMNS` when present in `test_df`.
  - In `tests/test_v2_schema.py`: prove round-trip parquet serialization + `deterministic_rules.evaluate_dataframe` / `export_findings.export_findings` yields **identical** rule hits before and after parquet round-trip (specifically verifying `\Microsoft\...` tasks do not misfire `RULE-002` and non-default admin accounts fire `RULE-013`).
- **Planned commit message:** `feat(v2): fix pytest hygiene, add v2 provenance schema, and export rule-critical fields (Step 1)`

---

### STEP 2 — Training Integrity (`IMP-08`, `IMP-09`) as v2 Code Paths
- **Deliverables:**
  - `src/v2/config_v2.py`: `V2_FINAL_SEEDS = [42, 43, 44, 45, 46]` (`K = 5`), `V2_N_SEARCH_TRIALS = 30`, `V2_OUTER_FOLDS = 5`, `V2_INNER_FOLDS = 4`, equal trial budgets per tuned arm, expanded `V2_SEARCH_SPACES`:
    - `rf`: `n_estimators`, `max_depth`, `min_samples_leaf`, `max_features`
    - `xgb`: `n_estimators`, `learning_rate`, `max_depth`, `subsample`, `colsample_bytree`, `min_child_weight`
    - `iforest`: `n_estimators`, `max_samples`, `max_features`, `bootstrap`
    - `mlp`: `batch_size`, `lr`, `weight_decay`, `hidden_dims` (wider/deeper options), `dropout`, `norm_type` (`"batch"` / `"layer"`), `pos_weight_mode` (`"1"`, `"sqrt"`, `"full"`)
    - `ae`: `batch_size`, `lr`, `weight_decay`, `hidden_dims`, `bottleneck_dim`
    - `lr`: `C` (plus penalty/tol options if desired)
  - `src/v2/models_v2.py`: `TabularMLPArmV2` and `DeepAutoencoderArmV2` supporting configurable architecture search hyperparameters and optional fixed-epoch 100%-dev refit (`fixed_epochs: int | None`), leaving v1 `TabularMLPArm` and `DeepAutoencoderArm` untouched.
  - `src/v2/training.py`:
    - `fit_arm_v2(...)`: fits `iforest`, `rf`, `xgb`, `lr` on **100%** of eligible dev/training rows (`iforest` fits on 100% of benign dev rows, never dropping a fold for unused `X_val`); forces `ae` and `mlp` early stopping **strictly** on a disjoint inner grouped validation split carved from `tr_df` (never outer `va_df`).
    - `make_family_grouped_folds(...)`: partitions positives by `sample_family` (with optional `packer_cluster` union-find grouping) and benign rows by `benign_session_id` / `dev_fold` with hard disjointness assertions.
    - `run_nested_dev_cv_v2(...)`: nested family-grouped CV (`outer` estimates unbiased CV; `inner` selects hyperparameters with equal `N_trials = 30` budget per tuned arm). Enforces `selection_mode = "label_free"` by default for `ae` and `iforest` (benign-only OOF reconstruction MSE for `ae`, benign-only OOF score variance/stability for `iforest` — zero attack labels inspected), while an explicit `"label_selected"` opt-in tags outputs `"label-selected"`.
    - `run_multiseed_final_v2(...)`: runs all `K` seeds (`V2_FINAL_SEEDS`), reports per-seed PR-AUC mean and std alongside the K-seed ensemble score, and supports documented `refit_strategy` (`"full_dev_median_epoch"` default vs `"fold_ensemble"`).
    - Strict train-fold-only fitting for `SharedPreprocessor` (imputers, scalers, encoders) — benign-only training rows for `ae` and `iforest`.
  - `tests/test_v2_training.py`: asserts `iforest` 100%-benign fit (`n_benign_fit_ == n_benign_dev`), outer-fold `va_df` corruption does NOT alter `SharedPreprocessor` parameters (`mean_`, `scale_`, `categories_`, missing indicators) or `ae`/`mlp` early-stopped weights/`best_epoch_`, strict nested family/benign disjointness, equal trial counts per tuned arm, label-free `ae`/`iforest` invariance to inner-val attack labels + `"label-selected"` tagging, and multi-seed `--final` mean/std + ensemble output.
- **Planned commit message:** `feat(v2): add v2 training integrity, nested family-grouped CV, and multi-seed final paths (Step 2)`

---

### STEP 3 — Statistics (`IMP-10`, `IMP-11`, `IMP-14`)
- **Deliverables:**
  - `src/v2/stats.py`:
    - `monte_carlo_random_pr_auc(y, n_perm=10000, seed=42)`: computes finite-sample expected random PR-AUC across 10,000 permutations (reporting `prevalence`, `mean`, `std`, `p05`, `p50`, `p95`, `n_perm`, `seed`).
    - `V2_PREREGISTERED_PAIRS`: fixed pre-registered comparison family with **no dynamic `best_ml` selection** (`xgb vs rf`, `rf vs mlp`, `xgb vs mlp`, `rf vs rules_count`, `rf vs rules_binary`, `xgb vs rules_count`, `xgb vs rules_binary`, `mlp vs rules_count`, `mlp vs rules_binary`).
    - `paired_bootstrap_family_clustered(...)`: resamples positives clustered by `sample_family` (or specified group col), `benign_drift` by session/`run_id`, and `baseline` by session/row; outputs `point_a`, `point_b`, `diff`, `ci_lo`, `ci_hi`, two-sided `p_raw`, `n_boot_valid`, `group_by`.
    - `holm_bonferroni_adjust(df, p_col="p_raw", alpha=0.05)` & `combine_dual_config_verdicts_v2(...)`: applies Holm-Bonferroni correction across the fixed pre-registered comparison family and applies the dual-config (`full_20` + `no_content`) winner rule.
    - `calibrate_dev_thresholds_from_oof(...)` & `evaluate_frozen_thresholds(...)`: calibrates fixed operating thresholds strictly from nested dev OOF predictions (e.g., 1% / 5% benign val FPR and fixed alert budgets) and evaluates once on blind test, tagged `dev_nested_oof_calibrated`.
    - `compute_lofo_dev_table(...)`: leave-one-family-out dev diagnostic table using `tie_expected_precision_at_k` / `tie_expected_recall_at_k` everywhere plus macro summary across families.
  - `src/v2/ablations_v2.py`:
    - Defaults strictly to `eval_split="dev"` (nested/grouped dev OOF ablations — never touches blind test by default).
    - Requires config-matched hyperparameters (`best_params_by_config`) — raises `ValueError` on mismatched config keys.
    - Uses `M.tie_expected_precision_at_k` and `M.tie_expected_recall_at_k` everywhere.
    - If `eval_split="test"` is ever requested, verifies `blind_test_sha256` against `manifest` and enforces the one-shot `final_eval_audit_v2.jsonl` guard (refusing re-execution without `force=True`).
  - `tests/test_v2_stats.py`: unit & integration tests covering MC 10,000-permutation band, family-clustered paired bootstrap determinism/symmetry, hand-verified Holm-Bonferroni adjusted p-values and dual-config verdicts, absence of dynamic `best_ml`, dev-calibrated threshold freezing, tie-expected P@k invariance, LOFO table, and ablation dev-only + config-matched + one-shot audit guards.
- **Planned commit message:** `feat(v2): add v2 statistics, Holm-Bonferroni, dev thresholds, LOFO, and guarded ablations (Step 3)`

---

### STEP 4 — Labeling and Review (`IMP-03`, `IMP-04`)
- **Deliverables:**
  - `src/v2/labeler_v2.py` (tested on **SYNTHETIC fixtures only**):
    - `build_multi_control_baseline(control_dfs)`: union of `(artifact_key -> stable content hashes)` across multiple control boots plus per-key control observation counts and OS-idle drift key tracking.
    - `resolve_root_guids(sysmon_events, sample_sha256, staged_path)` & `build_process_tree(sysmon_events, root_guids)`: builds causal descendant graph over Sysmon EventIDs 1 (ProcessCreate), 8/10 (CreateRemoteThread / cross-process injection), 11 (FileCreate), 12/13/14 (RegistryEvent), 19/20/21 (WmiEvent), and service/task artifacts.
    - `label_executed_run_v2(...)`: baseline -> `baseline`; attacker causal tree -> `attacker_induced` (`attribution_method="process_tree_etw"`, `process_tree_root_guid=...`); benign scheduler tree or multi-control OS-idle drift -> `benign_drift`; conflicting attribution or unattributed residual -> explicit **`ambiguous_unattributed`** (never silently defaulted to `benign_drift`).
    - `label_dormant_run_v2(...)`: labels strictly from pre-registered staging manifest `(staged_path, sample_sha256, ...)` + baseline diff, flagging/failing or quarantining to `ambiguous_unattributed` if unexpected execution traces appear for the staged binary.
    - `build_dataset_v2(...)`: populates all 14 v2 provenance columns + `RULE_EXPORT_COLUMNS`, enforces DS-10 runner exclusion + FE-08 `assert_clean`, and **never calls `export_review_sample()`**.
  - `src/v2/review_v2.py`:
    - `export_blinded_review_sample(df, out_csv, private_key_path, ...)`: strips `label`, `label_reason`, `launcher`, `technique_id`, `sample_family`, `sample_category`, `attribution_method`, `attribution_confidence`; adds required columns `reviewer_id`, `reviewed_at_utc`, `human_label`, `human_notes`; **refuses to overwrite** any existing populated review file (`FileExistsError`).
    - `export_dual_reviewer_packs(...)`: creates Reviewer A & Reviewer B blinded packs with configurable overlap (default 20%, stratified).
    - `validate_review_csv(path)`: enforces non-empty `reviewer_id`, valid ISO-8601 `reviewed_at_utc`, valid `human_label`, and non-empty per-row `human_notes` (rejecting single-string boilerplate when `reject_boilerplate=True`).
    - `compute_cohens_kappa(rev_a_df, rev_b_df)`: computes exact observed agreement, chance agreement, Cohen's $\kappa$, confusion counts, and disagreement table.
  - `tests/test_v2_labeler_and_review.py`: synthetic fixture tests for multi-hop process trees, remote-thread injection, multi-control diff, `ambiguous_unattributed` quarantine, dormant manifest + execution-leak detection, blinded column removal, populated-file overwrite protection, required review fields, and hand-checked Cohen's $\kappa$.
- **Planned commit message:** `feat(v2): add synthetic-tested process-tree/dormant labeler and blinded multi-reviewer workflow (Step 4)`

---

### STEP 5 — Realism Audit and Generator Design (`IMP-06`)
- **Deliverables:**
  - Update `scripts/verify_stratified_shortcuts.py`:
    - Compute real byte sizes and real 256-bin byte histograms from actual script/file payloads instead of hard-coded constants (`file_size=2048` / `[1]*256`).
    - Add explicit template-quantization / content-diversity diagnostics (`unique_size_count`, `unique_pair_count`, `unique_pair_ratio`, `max_single_size_share`, `file_entropy` IQR/std) so fixed-template quantization is detected pre-collection.
  - Create `docs/v2/BENIGN_GENERATOR_V2_DESIGN.md`:
    - Varied real software installations/invocations (Git, Python, 7-Zip, Notepad++, Sysinternals, varied procedural admin scripts), benign Windows services, benign scheduled tasks (varied triggers including `ONLOGON`/`DAILY`/`ONCE`), benign registry edits, and legitimate unsigned PE binaries (`exe`/`dll`) to break the `signature_state` shortcut.
    - Separate dev vs. blind-test benign host/software profiles (`IMP-05`).
    - Quantitative pass/fail gates verifying zero template quantization (`unique_pair_ratio >= 0.85`, `max_single_size_share <= 0.08`, non-constant `file_entropy` spread, single-feature AUC bounds).
  - Create `src/v2/benign_generator_v2.py` (offline generator stubs + `check_benign_realism(...)` pass/fail evaluator; NO VM runs) and `docs/v2/benign_noise_v2_stub.ps1` (leaving v1 `lab_automation/benign_noise.ps1` untouched).
  - Create `tests/test_v2_realism_audit.py`: proves `verify_stratified_shortcuts.py` computes real non-constant sizes/histograms and flags v1 quantization, and proves `benign_generator_v2.py` emits diverse benign services/tasks/registry/unsigned-PEs/scripts with zero FE-08 tokens, disjoint dev/test profiles, and passes `check_benign_realism(...)`.
- **Planned commit message:** `feat(v2): compute real byte stats in shortcut audit and design v2 benign generator (Step 5)`

---

### STEP 6 — Hardening Kit for Mokh to Run (`IMP-01`, `IMP-02`, `IMP-16`)
- **Strict Constraint:** Write scripts, docs, and verification checklists only — **DO NOT apply** any firewall, libvirt network, or domain XML changes, and **DO NOT touch** the VM or base image.
- **Deliverables in `docs/v2/hardening/`:**
  - `docs/v2/hardening/README.md`: Master operator runbook and pre-pilot sign-off checklist.
  - `docs/v2/hardening/01_firewall_win11_isolated.sh`: Default-DROP firewall rules for `virbr1` (`192.168.150.0/24`), replacing v1's permissive `INPUT ACCEPT`/`FORWARD ACCEPT`, blocking all guest-to-host services and cross-bridge forwarding, with `--dry-run` / `--status` support.
  - `docs/v2/hardening/02_domain_xml_hardening.md` and `docs/v2/hardening/02_patch_win11_xml.py`: Domain XML hardening patching `virsh dumpxml win11` to strip SPICE clipboard (`<clipboard copypaste='no'/>`), `spicevmc`/vdagent channels, SPICE file transfer, `<filesystem>` shared folders, `<redirdev>` USB redirection, and USB `<hostdev>` passthrough; applied via `virsh define` (never `virsh create`).
  - `docs/v2/hardening/03_inetsim_vm_setup.md` and `docs/v2/hardening/03_inetsim.conf`: Dedicated separate isolated Linux VM (`inetsim-vm`, `192.168.150.10` on `win11-isolated`) configuration for DNS/HTTP/HTTPS/SMTP/FTP/NTP simulation, CoW overlay reset, and per-run network capture.
  - `docs/v2/hardening/04_watchdog_and_base_hash.py`: Host-side wall-clock watchdog enforcing `sudo -n /usr/bin/virsh -c qemu:///system destroy win11` on timeout, plus automated pre/post `win11_base.qcow2` and `win11_VARS.fd.base` SHA-256 + `0444` permission checks logged to `results/logs/v2_base_image_integrity.jsonl`.
  - `docs/v2/hardening/05_negative_egress_checklist.md`: Negative-egress, clipboard-disabled, USB-disabled, INetSim-resolution, and base-hash verification tests for Mokh to run and sign off.
  - `docs/v2/hardening/06_offline_extraction_design.md`: Unprivileged container (`--network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges`) user-space offline read-only extraction design (`dissect`/`regipy`/`evtx`/`libscca`, zero host-kernel mounts) capturing `Amcache.hve`, `Prefetch`, `Sysmon` EVTX, Registry hives, Scheduled Tasks, and first-1 MiB file histograms without VSS.
  - `tests/test_v2_hardening_tools.py`: Unit tests for `02_patch_win11_xml.py` (synthetic XML in `tmp_path`) and `04_watchdog_and_base_hash.py` (mocked subprocess + synthetic files in `tmp_path`).
- **Planned commit message:** `docs(v2): add Gate 0 hardening kit, watchdog/hash tools, and offline extraction design (Step 6)`
- **Final handoff after Step 6:** List the exact commands/scripts Mokh must execute on the host and every Gate 0 + `OPERATOR_DECISIONS.md` item Mokh must confirm before starting Stage A pilot runs.
