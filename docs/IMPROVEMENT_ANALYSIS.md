# DFIR-Triage ML — Repository Improvement Analysis (Post-v1 Audit -> v2)

**Audit Scope:** Read-only inspection of `src/`, `lab_automation/`, `collector/`, `scripts/`, `tests/`, `docs/`, `COMPLETE_REPORT.md`, and `results/` at commit `ad9bf28`.  
**Frozen v1 Rule:** No v1 code, data, labels, splits, models, `results/`, or `docs/FINAL_EVAL_PLAN.md` were altered by this audit. Items marked **`Affects v1 reporting: Yes`** document how existing v1 outputs must be presented alongside their caveats; items marked `P0` must be resolved before acquiring real malware or running v2 experiments.

---

## Summary Table (Ordered Strictly by Priority)

| Priority | ID | Domain | Title | Effort | Affects v1 Reporting? |
| :---: | :--- | :--- | :--- | :---: | :---: |
| **P0** | [`IMP-01`](#imp-01) | Lab / Safety | Permissive `virbr1` `iptables` rules & SPICE bidirectional clipboard enabled | M | No |
| **P0** | [`IMP-02`](#imp-02) | Lab / Safety | Live-guest Admin SSH + `scp -r` collection & missing fake-internet, timeout kill, and sample SHA-256 preflight | L | No |
| **P0** | [`IMP-03`](#imp-03) | Labeling | `expected_artifact_keys`-only attribution breaks on real malware side effects & dormant payloads | L | No |
| **P0** | [`IMP-04`](#imp-04) | Labeling / Review | Unblinded & overwritten `review_sample.csv` export; v1 `111/111` review lacks independent audit trail | S | **Yes** |
| **P0** | [`IMP-05`](#imp-05) | Splits / Freeze | Technique-only split lacks malware-family / near-duplicate grouping, leaks dev-run drift into test, & freezes late | M | **Yes** |
| **P0** | [`IMP-06`](#imp-06) | Realism | Fixed 6-template benign script noise, missing benign `service`/`registry` drift, `signature_state` shortcut, & placeholder shortcut audit | L | **Yes** |
| **P0** | [`IMP-07`](#imp-07) | Schema | Missing v2 provenance/stratum columns & missing rule-critical fields (`task_name`, `raw` account flags) | S | No |
| **P0** | [`IMP-08`](#imp-08) | Training Integrity | Effective 80% dev fit for `--final` `mlp`/`ae`/`iforest`, outer-fold `ae` early stopping in CV, & 3-seed dev vs 1-seed `--final` mismatch | M | **Yes** |
| **P1** | [`IMP-09`](#imp-09) | Training Integrity | Non-nested dev CV & unequal search budgets / constrained MLP & AE hyperparameter spaces | M | **Yes** |
| **P1** | [`IMP-10`](#imp-10) | Statistics | Unadjusted multiple comparisons (`30`+`18` CIs), plain percentile bootstrap, post-hoc `best_ml`, & test-picked thresholds | S | **Yes** |
| **P1** | [`IMP-11`](#imp-11) | Statistics | Single-draw `random` baseline (`0.1421` vs `0.1027` finite-sample expectation) & dev-vs-test PR-AUC gap diagnostics | S | **Yes** |
| **P1** | [`IMP-12`](#imp-12) | Track B | Split-2 1%-val threshold -> 8.1%–22.3% test FPR from non-exchangeable KMeans cells, score-floor ties, & val reuse | S | **Yes** |
| **P1** | [`IMP-13`](#imp-13) | Export / Rules | Missing `task_name` in test parquet causes `findings.json` (`123`) vs `rules_binary` (`120`) mismatch on 3 MS tasks | S | **Yes** |
| **P1** | [`IMP-14`](#imp-14) | Ablations | `ablations.py` uses tie-sensitive `precision_at_k`, defaults `--best-params` to `full_20`, & lacks `--final` guard | S | **Yes** |
| **P1** | [`IMP-15`](#imp-15) | Tests / Hygiene | `pytest` mutates tracked `results/logs/runner_footprint_dropped.csv` (`mode="a"`) | S | No |
| **P1** | [`IMP-16`](#imp-16) | Collector | `amcache` skipped `51/51` runs (`locked_hive_no_vss`) & `MaxScannedFiles = 1500` file cap | M | No |
| **P2** | [`IMP-17`](#imp-17) | Docs / CLI | `README.md` CLI mismatch, stale test count (`185` vs `190`), and stale docstring references | S | No |
| **P2** | [`IMP-18`](#imp-18) | Reproducibility | Missing host CPU/GPU SKUs, missing automated post-batch base hash check, `weights_only=False`, PR curve subsampling | S | No |
| **P2** | [`IMP-19`](#imp-19) | Dead Code | Dead `if args.inspect or True`, unused `metrics.py` helpers, and unimplemented `QemuGuestAgentRunner.download_dir` | S | No |

---

## P0 Findings — Must Fix Before v2

### `IMP-01`
- **Title:** Permissive `virbr1` `iptables` rules & SPICE bidirectional clipboard enabled in VM setup
- **Domain:** Lab Automation / Malware Safety
- **Evidence:** `docs/WINDOWS_11_LAB_SETUP.md:50-56` (`iptables -I INPUT -i virbr1 -j ACCEPT`, `iptables -I FORWARD -i virbr1 -j ACCEPT`, `iptables -I FORWARD -o virbr1 -j ACCEPT`), `docs/WINDOWS_11_LAB_SETUP.md:86` (`SPICE Guest Tools / VirtIO Drivers (bidirectional clipboard synchronization, dynamic display resizing)`).
- **Why it matters:** Acceptable for v1 offline PowerShell scripts, **unsafe for live malware**. Blanket `INPUT ACCEPT` exposes all Linux host services to an infected guest over `virbr1`, blanket `FORWARD ACCEPT` allows routing across other bridges/interfaces if host forwarding is enabled, and SPICE bidirectional clipboard/agent channels create a direct host-guest data-exfiltration/clipboard-injection bridge.
- **Proposed fix:** Replace `INPUT ACCEPT` on `virbr1` with strict default-`DROP` (allowing only host-initiated management traffic if needed, DHCP/DNS strictly to the isolated fake-net endpoint, and `DROP` on all other RFC1918/WAN destinations); remove `FORWARD` rules; rebuild or reconfigure domain XML to remove SPICE clipboard/shared-folders and disable host-guest clipboard sharing before loading real malware.
- **Effort:** M
- **Priority:** **P0**
- **Affects v1 reporting?** No (v1 executed self-written offline emulations only, never live wild malware).

### `IMP-02`
- **Title:** Live-guest Admin SSH + `scp -r` collection & missing fake-internet, hard timeout kill, and sample SHA-256 preflight
- **Domain:** Lab Automation / Collection Architecture
- **Evidence:** `lab_automation/run_one.py:336-340` (`SSHGuestRunner` Admin OpenSSH), `lab_automation/run_one.py:381-466` (uploads/executes scripts over SSH then runs `Collect-Artifacts.ps1` inside the potentially infected guest and `scp -r` downloads `C:\collector_out`), `lab_automation/guest_runner.py:76-158`, `lab_automation/lab_config.example.yaml:18-35`.
- **Why it matters:** Live malware can (a) terminate or hijack `sshd`, (b) hook WMI/PowerShell/APIs to blind or tamper with `Collect-Artifacts.ps1`, (c) drop symlink/path-traversal or weaponized payloads inside `C:\collector_out` downloaded to the Linux host, or (d) refuse to detonate meaningfully without DNS/HTTP responses. Furthermore, `run_one.py` relies on `launcher_timeout_seconds` per SSH command rather than an independent VM-level hard kill timer, has no host-side SHA-256 allowlist/quarantine vault check, and deletes `overlay_image` inside `finally` (`run_one.py:170`) before host-side offline inspection is possible.
- **Proposed fix:** Move artifact collection to **offline read-only overlay parsing** (`virsh destroy` after detonation window -> inspect/mount `win11_overlay.qcow2` read-only on host or isolated extractor container using `qemu-nbd --read-only` / `dissect` / `hivex` before deleting overlay; only extract strict JSON/binary fields via schema-validated parsers, never raw executables into host workspace); run detonation inside a dedicated fake-internet responder (`INetSim` or `FakeNet-NG` on an isolated segment); enforce an external host-side `run_wall_clock_limit` that runs `virsh destroy`; verify sample SHA-256 against a locked manifest before injection; verify `base_image` SHA-256 after every batch.
- **Effort:** L
- **Priority:** **P0**
- **Affects v1 reporting?** No.

### `IMP-03`
- **Title:** `expected_artifact_keys`-only labeling logic breaks on live malware process trees, side effects & dormant binaries
- **Domain:** Labeling Pipeline
- **Evidence:** `src/data/labeler.py:102-137` (`_key_matches_expected`), `src/data/labeler.py:260-285` (`provenance_attack_match -> technique_expected_match -> provenance_benign_match -> os_or_background_drift`), `src/data/labeler.py:41-51` (`stable_content_hash`), `data/processed/label_corrections.csv` (8 secondary attack artifacts missed in v1 because keys did not match the two hard-coded keys per variant).
- **Why it matters:** Real malware creates unpredictable dropped files, mutexes/scheduled tasks/services with random names, injected or child processes, and secondary registry edits that are **not** known beforehand in `techniques.yaml`. In `labeler.py:280-284`, any malware artifact absent from `expected_artifact_keys` is silently labeled `benign_drift` (`os_or_background_drift`) — poisoning both training negatives and test evaluation with false negatives! Conversely, dormant malware files staged on disk may have no child process execution trace.
- **Proposed fix:**
  1. For `executed` runs: install **Sysmon + ETW** logging inside the v2 base image (with host-side offline EVTX extraction from the stopped overlay) and label via **process-tree causal attribution** starting from the injected sample's PID/ProcessGuid/file hash (every file create/modify, registry value set, service/task/WMI creation, and child/remote thread spawned by that process tree is `attacker_induced`), crossed against expanded control-boot diffs (more control boots capturing OS idle variance) and concurrent benign provenance PIDs.
  2. For `dormant` runs: label strictly from the pre-registered placement manifest `(staged_path, sample_sha256)` + pre/post disk diff.
  3. Add an explicit **`ambiguous_unattributed`** label/quarantine state for unattributed diff rows instead of defaulting unknown drift straight to `benign_drift`.
- **Effort:** L
- **Priority:** **P0**
- **Affects v1 reporting?** No (v1's 8 missed secondary keys and 6 ambiguous Prefetch rows were manually audited and documented in `label_corrections.csv` and `WORK_SUMMARY.md`).

### `IMP-04`
- **Title:** Unblinded & destructive `review_sample.csv` export; v1 `111/111` review lacks verifiable independent human sign-off
- **Domain:** Labeling Pipeline / Human Review
- **Evidence:** `src/data/labeler.py:353-384, 567-568` (`build_dataset` overwrites `review_sample.csv` on every run with `label` and `label_reason` visible and blank `human_label`/`human_notes`), `data/processed/review_sample.csv` (`111/111` identical `human_notes = "operator_verified_agree"`, committed in `a72c0b4` in one commit alongside the populated manifest `human_review` block).
- **Why it matters:** Rebuilding the dataset destroys prior manual review annotations (`build_dataset` line `568`), showing automated `label`/`label_reason` anchors reviewers (no blinding), and v1's single-commit uniform string cannot substantiate independent human verification.
- **Proposed fix:** Separate `export_review_sample()` from `build_dataset()`, write a **blinded** review pack (strip `label`, `label_reason`, `launcher`, `technique_id`, `family`; show raw artifact fields + Sysmon process tree context), require non-empty `reviewer_id`, `reviewed_at_utc`, and per-row justification notes, support two reviewers on an overlap slice for inter-rater Cohen's $\kappa$, and commit the blank export before the populated review commit.
- **Effort:** S
- **Priority:** **P0**
- **Affects v1 reporting?** **Yes** — must continue stating explicitly that `review_sample.csv` (`111/111` `operator_verified_agree`) cannot prove independent per-row human review from repo artifacts alone (already reported in `COMPLETE_REPORT.md` §7.2.3).

### `IMP-05`
- **Title:** Splitting & blind-test freeze lack family/fuzzy-hash grouping, leak dev-run `benign_drift` rows into test, and freeze after full build
- **Domain:** Splits & Blind Test Design
- **Evidence:** `src/data/labeler.py:294-350` (deduplicates `ben_df` globally across dev and test attack runs before hashing `artifact_key` into `dev`/`test`; positive rows grouped by `technique_id` only), `dataset_v1.parquet` (`test` contains `125` non-baseline rows across `45` `run_id`s: `15` test attack runs + **`30` dev-run `run_id`s** attached to hash-bucketed `benign_drift` rows), `src/data/labeler.py:577-595` (hash computed at end of dataset build).
- **Why it matters:**
  1. In real malware, variants of the **same family** (or packed copies sharing compiler/stub traits) often map across different `technique_id`s — splitting only by technique would leak family signatures into test!
  2. In v1, deduplicating `benign_drift` across all 51 runs meant dev runs could anchor `benign_drift` rows that landed in `test` (creating mixed dev/test `run_id`s in `run_id` bootstrap).
  3. Holding out only `5` techniques in v1 meant `technique_id` bootstrap could not credibly estimate generalization variance.
- **Proposed fix:**
  1. Partition v2 test positives by **whole malware family AND near-duplicate binary clusters (`ssdeep`/TLSH / import-hash graph)** — not just ATT&CK technique — across dedicated blind-test VM sessions.
  2. Partition control + benign runs at the **session/host-profile level** so dev benign activity and blind-test benign activity never share `artifact_key`, `run_id`, or `benign_noise` templates.
  3. Seal raw collector outputs + `v2_blind_test_manifest.json` (SHA-256 of test feature rows + test artifact IDs) **before** any developer inspects test rows or runs dev tuning.
- **Effort:** M
- **Priority:** **P0**
- **Affects v1 reporting?** **Yes** — v1 reports must keep noting that `5` holdout techniques (`33` positives) limit unseen-technique CI generalizability and that `test_df` non-baseline `run_id` clusters include `30` `run_id`s from dev runs via hash-bucketed `benign_drift`.

### `IMP-06`
- **Title:** Benign noise template quantization, missing benign `service`/`registry` drift, `signature_state` reliance, & placeholder shortcut audit
- **Domain:** Realism & Feature Integrity
- **Evidence:**
  - `lab_automation/benign_noise.ps1:40-187`: 6 fixed body templates (`workspace_doc`, `ps_diag`, `backup_task`, `run_note`, `cmd_archive`, `sysinternals_check`) produce **`221` benign dev scripts mapped to `18` unique `file_size_log` values and `30` `(file_size_log, file_entropy)` pairs** (`COMPLETE_REPORT.md` §7.1.3).
  - `dataset_v1.parquet` crosstabs: `0` benign `service` drift rows (`0/237`), `0` benign `registry` drift rows (`0/7`), `0` benign `wmi_subscription`/`account`/`startup` drift, `1` benign `prefetch` drift in test, and only `3` dev + `2` test `unsigned` baseline rows (while `unsigned` benign scripts concentrate in synthetic templates).
  - `results/tables/track_a_ablations.csv`: `drop_signature` drops `rf` PR-AUC from **`0.8902` to `0.5729`** and `xgb` from **`0.8552` to `0.6000`**.
  - Test attack prevalence is `33/370 = 8.92%` (`dev = 5.94%`), far above realistic enterprise host snapshots (`< 0.1%–1%`).
  - `scripts/verify_stratified_shortcuts.py:44-45, 171-172`: hard-coded `file_size=2048` and `file_head_histogram=[1]*256` on simulated rows, completely hiding content-feature template quantization before collection!
- **Proposed fix:** (a) Replace fixed PowerShell strings with diverse real benign workloads (unsigned open-source admin utilities, Git/Python scripts of variable real content/comments, legitimate third-party installers creating benign `service`, `registry`, `task`, and `run_key` entries); (b) ensure legitimate unsigned PE binaries exist in benign drift and baseline; (c) update `verify_stratified_shortcuts.py` to compute real on-disk sizes/histograms before collection; (d) evaluate at realistic low-prevalence host snapshots (preserving full host snapshot counts alongside balanced diagnostic slices).
- **Effort:** L
- **Priority:** **P0**
- **Affects v1 reporting?** **Yes** — template quantization, `signature_state` sensitivity (`drop_signature = 0.5729`), `0` benign `service`/`registry` drift, and pre-51 audit placeholder constants must be clearly disclosed.

### `IMP-07`
- **Title:** Dataset schema lacks v2 sample/stratum provenance columns & drops rule-critical fields
- **Domain:** Dataset Schema & Compatibility
- **Evidence:** `src/data/labeler.py:548-558` (`meta_extra` omits `sample_sha256`, `family`, `source`, `execution_state`, `run_duration_s`, `process_tree_id`, `task_name`, `account_is_admin`), `src/config.py:82-92` (`FORBIDDEN_MODEL_INPUTS` covers v1 columns only).
- **Why it matters:** Without sample/stratum metadata, stratified evaluation (`executed` vs `dormant` vs `emulated`), family-grouped splitting, detonation troubleshooting, and deterministic rule fidelity break. Putting new metadata columns outside `FORBIDDEN_MODEL_INPUTS` would create leakage risk.
- **Proposed fix:** Keep v1's 20 locked `config.FEATURES` (`full_20` / `no_content`) intact for direct v1-to-v2 comparability, isolate any new v2 PE/static features under a named `FEATURES_V2` schema, add all new v2 provenance columns (`schema_version`, `sample_sha256`, `sample_family`, `sample_category`, `sample_source`, `execution_state`, `run_duration_s`, `detonation_exit_status`, `process_tree_root_guid`, `attribution_method`, `attribution_confidence`, `packer_cluster`, `label_review_status`) to `META_COLUMNS` / `FORBIDDEN_MODEL_INPUTS` enforced by `assert_no_forbidden_inputs()`, and export `task_name`, `service_name`, `start_mode`, `task_triggers`, and `raw_account_flags`.
- **Effort:** S
- **Priority:** **P0**
- **Affects v1 reporting?** No.

### `IMP-08`
- **Title:** Training integrity flaws: `--final` discards ~20% of dev data for `mlp`/`ae`/`iforest`; outer-fold `ae` early stopping in CV; 3-seed dev vs 1-seed `--final`
- **Domain:** Training Integrity
- **Evidence:**
  1. `src/eval/run_track_a.py:213-234, 873-878`: On `--final` (`va_df=None`), `_fit_arm_on_split` sends `ae` AND **`iforest`** into `_split_inner_grouped_val`, discarding `dev_fold == 4` (~20% of benign dev, leaving ~`887` rows instead of `1,109`) even though `IsolationForestArm.fit` (`src/models/sklearn_models.py:142-156`) **completely ignores `X_val` and `y_val`**!
  2. `src/eval/run_track_a.py:237-242`: On `--final`, `mlp` drops `2/11` dev techniques + `dev_fold == 4` for early stopping (`~80%` of dev) and does not refit on `100%` dev using mean `best_epoch_` (or multi-fold ensemble).
  3. `src/eval/run_track_a.py:218-221, 539-546`: During dev CV, `_run_dev_oof` passes `va_fit` (**outer CV fold rows**) to `_fit_arm_on_split`, so `ae` early-stops using the outer validation fold's benign reconstruction MSE (same benign fold it is subsequently scored on!), whereas `mlp` explicitly triggers `inner_val_seed` to hold out an inner validation split.
  4. `src/eval/run_track_a.py:611, 876` & `results/tables/track_a_dev_trials.csv`: Dev summary PR-AUC averages OOF predictions across 3 seeds (`SEED in [0,1,2]`), boosting `mlp` (`no_content` `0.2493` single-seed mean -> `0.3142` 3-seed avg) and `xgb` (`full_20` `0.5808` -> `0.6147`), while `mlp` (`full_20` best trial std = `0.0600`, seeds `[0.1659, 0.3129, 0.2402]`) and `ae` (`std = 0.0411`) exhibit high seed variance — yet `--final` trains **only 1 seed (`SEED = 42`)**!
- **Why it matters:** Asymmetric effective sample size (`iforest`/`ae`/`mlp` lose ~20% of dev data while `rf`/`xgb`/`lr` use 100%), mild dev-CV early-stopping optimism for `ae`, ensemble-vs-single-seed inconsistency between dev and test, and high neural seed fragility on 1-seed `--final`.
- **Proposed fix:**
  1. Fit `iforest` (and all non-early-stopped arms) on **100%** of available dev/train rows.
  2. Force `ae` (like `mlp`) to early-stop strictly on a disjoint **inner** grouped validation split in CV (never `va_df`).
  3. Run `--final` across **multiple seeds** (e.g., `K = 5` seeds), recording mean ± std single-seed test PR-AUC alongside the K-seed ensemble score, and either average fold-models or refit on 100% of dev for median `best_epoch_`.
- **Effort:** M
- **Priority:** **P0**
- **Affects v1 reporting?** **Yes** — must state explicitly that v1 `--final` trained `mlp`/`ae`/`iforest` on ~80% of dev (single seed `42`), while `track_a_dev_summary.csv` averaged 3 OOF seeds and `ae` dev-CV early stopping used the outer benign fold.

---

## P1 Findings — Should Fix Before or During v2 Execution

### `IMP-09`
- **Title:** Non-nested dev CV & unequal tuning budgets / constrained neural and outlier search spaces
- **Domain:** Training Integrity (Tuning & CV)
- **Evidence:** `src/eval/run_track_a.py:176-194, 555-643`, `src/config.py:234-246`, `results/tables/track_a_dev_trials.csv` (`rf`: 20 of 120 combos; `xgb`: 20 of 150; `mlp`: 20 of 75 with fixed `128-64-32` width, fixed dropout `0.3/0.2`, fixed `pos_weight=n_neg/n_pos`; `ae`: 20 of 60 selected by **labeled dev OOF PR-AUC** despite being labelled "unsupervised"; `iforest`: 10 of 10 in narrow space missing `max_features`; `lr`: 5 of 5 `C`-only).
- **Why it matters:** Plain CV mixes hyperparameter selection and OOF performance estimation on the same 5 folds (selection bias); unequal grid sizes and fixed MLP/IF capacity disadvantage non-tree models. Additionally, tuning `ae` hyperparameters on labeled OOF PR-AUC means `ae` was indirectly selected using labels on dev (`docs/specs/04_approaches_and_datasets.md`), unlike `fit()`, which is strictly benign-only.
- **Proposed fix:** Implement **nested family-grouped CV** on v2 dev (outer fold estimates unbiased CV; inner fold selects hyperparameters); give every tuned arm an **equal random/Optuna budget** (e.g., `N = 30–50` trials) spanning regularization, depth/width (`mlp` hidden dims, dropout, weighted sampler/`pos_weight`; `iforest` `max_features`, `bootstrap`); keep unsupervised `ae`/`iforest` model selection strictly label-free in a pure-unsupervised arm or explicitly distinguish unsupervised-fit from labeled-val hyperparameter selection.
- **Effort:** M
- **Priority:** **P1**
- **Affects v1 reporting?** **Yes** — dev CV numbers reflect non-nested tuning selection, and `ae` hyperparameter choice maximized dev labeled PR-AUC (`docs/specs/04_approaches_and_datasets.md`).

### `IMP-10`
- **Title:** Unadjusted multiple comparisons (`30`+`18` CIs), post-hoc `best_ml`, plain percentile bootstrap, & test-selected thresholds
- **Domain:** Statistics
- **Evidence:** `results/tables/track_a_test_dual_config_verdict.csv` (`15` dual tests = `30` config CIs), `results/tables/supp_posthoc_dual_config_vs_rules_count.csv` (`9` dual tests = `18` CIs), `src/eval/run_track_a.py:338` (`best_ml = max(ml_keys, ...)`), `src/eval/metrics.py:111-135, 383` (raw quantile CI without multiplicity adjustment; `threshold_at_recall` selects threshold on test).
- **Why it matters:** Uncorrected 95% CIs across 15+ pre-registered tests inflate family-wise Type I error; selecting `best_ml` after observing test scores introduces winner selection bias; percentile bootstrap can under-cover with small cluster counts (`15` test attack runs across `5` techniques); test-selected `FPR@R=0.9` is descriptive only, not deployable.
- **Proposed fix:** Apply **Holm-Bonferroni** (or stepdown max-T / Westfall-Young bootstrap) across a smaller, pre-registered confirmatory contrast set (remove dynamic `best_ml`); increase test clusters (`>= 20` families) and use family-clustered bootstrap (plus Stratified permutation/cluster CIs); calibrate fixed operating thresholds on **dev nested OOF predictions** only and evaluate frozen thresholds once on blind test.
- **Effort:** S
- **Priority:** **P1**
- **Affects v1 reporting?** **Yes** — keep unadjusted CI caveat, post-hoc `best_ml` caveat, `5`-technique scope caveat, and `"descriptive, thresholds chosen on test, not a deployable operating point"` on all test threshold metrics.

### `IMP-11`
- **Title:** Single-draw `random` baseline (`0.1421` vs `0.1027` finite-sample expectation) & dev-vs-test PR-AUC gap diagnostics
- **Domain:** Statistics
- **Evidence:** `src/eval/run_track_a.py:273` (`np.random.default_rng(seed).random(len(df))`), `results/tables/track_a_test_baselines.csv` (`random = 0.1421`), `results/tables/track_a_dev_per_technique.csv` (`rf`: `0.0545–0.3228`; `xgb`: `0.0060–0.8667`; `mlp`: `0.0151–0.3040`).
- **Why it matters:** On `n = 370, pos = 33`, true prevalence is `0.0892`, while the **finite-sample expected PR-AUC** of uniform random rankings is **`0.1027 ± 0.0213`** (10k Monte Carlo draws, 5th–95th percentile `[0.0762, 0.1441]`). Seed `42` happened to hit the ~94.4th percentile (`0.1421`), artificially shrinking `iforest`'s apparent margin (`0.1466` vs `0.1027` expected). Meanwhile, `track_a_dev_per_technique.csv` reveals massive technique-to-technique dispersion (`xgb` `0.0060` on `T1574.001` vs `0.8667` on `T1059.001`), explaining why dev-vs-test PR-AUC jumped steeply when harder classes (`task`, `T1574.001`) stayed in dev only.
- **Proposed fix:** Compute and report the **expected** random PR-AUC (10,000-permutation Monte Carlo mean + 5th–95th band) rather than relying on one lucky/unlucky seed; always run **leave-one-family-out (LOFO)** dev diagnostics alongside pooled OOF PR-AUC so technique/family difficulty variance is visible before unblinding test.
- **Effort:** S
- **Priority:** **P1**
- **Affects v1 reporting?** **Yes** — `COMPLETE_REPORT.md` §7.2.2 should explicitly quote both `0.0892` prevalence and `0.1027 ± 0.0213` finite-sample expected PR-AUC vs single-draw `0.1421`.

### `IMP-12`
- **Title:** Track B Split-2 1%-validation threshold yields 8.1%–22.3% test FPR (root causes & read-only diagnostic proposal)
- **Domain:** Track B Evaluation (`CIC-MalMem-2022`)
- **Evidence:** `src/data/splits.py:97-157` (`_assign_benign_clusters`), `src/eval/run_track_b.py:86-98, 222-226, 338`, `src/eval/metrics.py:137-159` (`threshold_at_fpr(..., method="higher")`, `fpr_at_threshold` strict `>`), `results/tables/track_b_split2.csv` (`xgb` has identical **`0.2233`** test FPR at **both** `1%` and `5%` val FPR targets; `rf` `0.0813`; `mlp` `0.1846`; `ae` `0.0380`; `iforest` `0.0058`), `results/tables/track_b_split2_rotations.csv` (across 5 rotations, `test_fpr_at_target_0.01` swings `rf: 0.0237–0.1448`, `xgb: 0.0077–0.2445`, `mlp: 0.0859–0.2811` — omitted from `track_b_split2_rotations_summary.csv`!).
- **Why it matters & Root Causes:**
  1. **Non-exchangeable benign cluster partition (`_assign_benign_clusters`):** `50` KMeans clusters (~29,298 benign rows, many SMOTE twins) are partitioned into ~`10%` (`~3,219` rows, ~5 Voronoi cells) for `benign_val_idx` vs ~`20%` (`~5,860+` rows, ~10 disjoint Voronoi cells) for `benign_test`. Supervised trees learn tight decision boundaries around `benign_train` clusters; unseen benign clusters in `benign_test` fall on the outlier side differently than the specific 5 clusters sampled in `benign_val`. (Also `KMeans`/`StandardScaler` fits transductively on all `29,298` benign rows.)
  2. **Threshold flattening / score quantization:** On nearly linearly/tree-separable malware vs benign clusters, `xgb` (`0.2233` at both `q=0.99` and `q=0.95`!) assigns an almost flat low-score quantile cliff across `benign_val`, so small shifts in unseen benign cluster feature distributions push `8%–22%` of `benign_test` past `t`.
  3. **Validation reuse:** For `mlp` (`run_track_b.py:91, 98`) and `ae`, `benign_val_idx` is used **both** for early stopping/model selection and for calibrating `threshold_at_fpr`, biasing val quantiles downward relative to fresh `benign_test`.
- **Proposed Read-Only Diagnostic (do NOT run on v1 outputs):** Take the already-trained Split-2 model/predictions and compare `fpr_at_threshold(benign_test, t)` under (a) the **cluster-grouped** `benign_val`/`benign_test` split vs (b) a **random 1:2 exchangeable reshuffle** of the exact same `benign_val ∪ benign_test` pool (no retraining — evaluates the exact same rows to isolate Voronoi cluster non-exchangeability vs SMOTE/model drift); also log scalar threshold `t`, validation-tie fraction at `t`, and split `benign_val` cleanly into disjoint early-stopping and calibration halves.
- **Effort:** S
- **Priority:** **P1**
- **Affects v1 reporting?** **Yes** — Track B remains secondary/appendix on a different task/data modality, with `test_fpr_at_target_0.01` rotation range (`0.0077–0.2811`) and non-exchangeable Voronoi + score-tie + val-reuse explanation documented.

### `IMP-13`
- **Title:** Missing `task_name` and `raw` columns in `track_a_test_predictions.parquet` causes `findings.json` (`123`) vs `rules_binary` (`120`) mismatch
- **Domain:** Exporter & Deterministic Rules
- **Evidence:** `src/eval/run_track_a.py:850-858` omits `task_name` and `raw` from `preds_df`; `src/eval/export_findings.py:144` re-runs `deterministic_rules.evaluate_row` on parquet rows; `src/rules/deterministic_rules.py:157-158` (`is_non_ms = not task_p.startswith("\\microsoft\\")`) treats `None`/`""` as non-Microsoft and misfires `RULE-002` on 3 benign Microsoft scheduled tasks (`Pre-staged app cleanup`, `WsSwapAssessmentTask`, `Scheduled Start`); `RULE-013` (`deterministic_rules.py:233-234`) also checks `row.get("raw")` for `is_admin`.
- **Why it matters:** `results/findings.json` reports `123` findings whereas `rules_binary` in `track_a_test_baselines.csv` and `supp_posthoc_operating_points.csv` flagged `120` rows!
- **Proposed fix:** Persist `task_name`, `service_name`, `start_mode`, `task_triggers`, and flattened `account_is_admin`/`account_enabled` in `dataset_v2.parquet` and predictions parquet (or serialize exact `rule_ids_triggered` during dataset build inside `META_COLUMNS`).
- **Effort:** S
- **Priority:** **P1**
- **Affects v1 reporting?** **Yes** — note plainly that `findings.json` / `findings_no_content.json` (`123` findings) include 3 false `RULE-002` re-evaluation hits on Microsoft tasks compared to the `120` rows flagged by `rules_binary`.

### `IMP-14`
- **Title:** `src/eval/ablations.py` uses tie-sensitive `precision_at_k`, defaults `--best-params` to `full_20`, and lacks a `--final` guard
- **Domain:** Ablation Evaluation
- **Evidence:** `src/eval/ablations.py:71-72` calls `M.precision_at_k` instead of `M.tie_expected_precision_at_k`; `src/eval/ablations.py:182` defaults `--best-params` to `results/tables/track_a_best_params.json` (`full_20` MLP params), causing `mlp no_content` PR-AUC `0.7685` vs primary `0.6621`; `ablations.py` touches `test_df` with no audit-log check (`final_eval_audit.jsonl`).
- **Why it matters:** Post-hoc `--best-params` mismatch creates confusing discrepancies (`0.7685` vs `0.6621`), and unguarded test scoring violates one-shot blind-test discipline.
- **Proposed fix:** Use `tie_expected_precision_at_k`, run ablations via **dev nested CV** only (never touching blind test for feature-drop exploration), or gate any blind-test ablation under the same one-shot audit guard with per-config matched hyperparameters.
- **Effort:** S
- **Priority:** **P1**
- **Affects v1 reporting?** **Yes** — keep the `0.6621` primary vs `0.7685` ablation explanation (`COMPLETE_REPORT.md` §7.2.1).

### `IMP-15`
- **Title:** Test suite mutates tracked `results/logs/runner_footprint_dropped.csv` (`mode="a"`)
- **Domain:** Tests & Repository Hygiene
- **Evidence:** `tests/test_rules_and_labeler.py:186-194` calls `labeler.build_dataset(...)` without overriding `runner_log_path` (defaults to `config.RUNNER_FOOTPRINT_LOG_CSV`), and `src/data/sanitize.py:136-140` opens it with `mode="a"`, appending 2 synthetic rows every time `pytest` runs.
- **Why it matters:** Pollutes a tracked v1 log file with test artifacts and causes duplicate rows if `build_dataset()` is ever run twice.
- **Proposed fix:** Pass `runner_log_path=tmp_path / "dropped.csv"` in tests, make `build_dataset()` write a fresh log (`mode="w"` on build start, returning/accumulating dropped DataFrames across runs), and add a test verifying zero tracked files change under `pytest`.
- **Effort:** S
- **Priority:** **P1**
- **Affects v1 reporting?** No.

### `IMP-16`
- **Title:** `Collect-Artifacts.ps1` skipped `amcache` `51/51` times (`locked_hive_no_vss`) & caps file scan at `MaxScannedFiles = 1500`
- **Domain:** Telemetry Collection
- **Evidence:** `collector/Collect-Artifacts.ps1:18` (`$MaxScannedFiles = 1500`), all `51` run `manifest.json` files (`amcache` skipped `51/51`, `reason="locked_hive_no_vss"`).
- **Why it matters:** Live malware frequently stages/executes short-lived PE payloads whose execution traces persist primarily in `Amcache.hve` or beyond a 1,500-file truncation window.
- **Proposed fix:** In v2 offline overlay collection (after clean `virsh destroy`), parse `C:\Windows\AppCompat\Programs\Amcache.hve`, registry hives, `Prefetch`, and `Sysmon` EVTX directly from the read-only disk without needing VSS, and raise/audit `MaxScannedFiles` with explicit directory quotas.
- **Effort:** M
- **Priority:** **P1**
- **Affects v1 reporting?** No (already reported in `COMPLETE_REPORT.md`).

---

## P2 Findings — Nice to Have (Documentation, Reproducibility, Dead Code)

### `IMP-17`
- **Title:** Documentation & CLI flag mismatches (`README.md`, docstrings)
- **Domain:** Documentation Consistency
- **Evidence:** `README.md:97` lists `--dataset`, `--shap`, `--model-name` for `src/eval/export_findings.py`, which actually accepts only `--predictions`, `--arm`, `--run-id`, `--case-id`, `--manifest-sha256`, `--top-k-leads`, `--out` (`src/eval/export_findings.py:188-197`); `README.md:60,75` still cites `185` tests (now `190` after `supp_posthoc`) and lacks explicit Track B secondary/appendix framing; `src/data/features.py:4` references non-existent `docs/data_dictionary_features.md`; `src/data/cic_malmem.py:7-8` docstring inaccurately states `parse_category()` raises `NotImplementedError`.
- **Why it matters:** Misleads operators trying to reproduce `findings.json` or audit Track B code.
- **Proposed fix:** Sync `README.md` CLI examples, test count, and Track B appendix note alongside v2 onboarding, and update stale module docstrings.
- **Effort:** S
- **Priority:** **P2**
- **Affects v1 reporting?** No.

### `IMP-18`
- **Title:** Reproducibility & checkpoint hardening gaps
- **Domain:** Reproducibility
- **Evidence:** `src/utils/repro.py:83-100` does not log CPU/GPU SKU names or base-image SHA-256 (`results/logs/base_image_stat_after.txt` was never written); `src/models/mlp.py:210` & `src/models/autoencoder.py:199` use `torch.load(..., weights_only=False)`; `src/eval/run_track_a.py:923-925` downsamples PR curves via `np.linspace(..., 200)`.
- **Why it matters:** `weights_only=False` uses unsafe pickle deserialization; PR downsampling can slightly alter step corners visually in Fig 1; automated base-image post-batch hash check protects VM integrity.
- **Proposed fix:** Record CPU/GPU SKU and automated pre/post `base_image` SHA-256 in run metadata, serialize PyTorch state dicts + JSON metadata safely without `weights_only=False`, and preserve exact PR-curve breakpoints.
- **Effort:** S
- **Priority:** **P2**
- **Affects v1 reporting?** No.

### `IMP-19`
- **Title:** Minor dead code & unimplemented QGA backend method
- **Domain:** Code Quality / Dead Code
- **Evidence:** `src/data/cic_malmem.py:183` (`if args.inspect or True:`), unused functions in `src/eval/metrics.py:98, 173, 403` (`grouped_at_k`, `bootstrap_by_group`, `ranking_report`), and `QemuGuestAgentRunner.download_dir` raising `NotImplementedError` (`lab_automation/guest_runner.py:230-231`).
- **Why it matters:** Dead branches and half-implemented backends complicate maintenance before extending `lab_automation/` for v2.
- **Proposed fix:** Clean up unused functions, fix `cic_malmem.py` CLI flag condition, and remove `QemuGuestAgentRunner` if v2 adopts offline overlay extraction.
- **Effort:** S
- **Priority:** **P2**
- **Affects v1 reporting?** No.

---

## Top 10 Before v2 (Execution Priority Order)

| Rank | ID | Item | Priority | Effort | Why Do This First |
| :---: | :--- | :--- | :---: | :---: | :--- |
| **1** | [`IMP-01`](#imp-01) | Harden `virbr1` `iptables` & remove SPICE clipboard/guest channels | **P0** | M | Mandatory host-safety prerequisite before any live malware touches the VM. |
| **2** | [`IMP-02`](#imp-02) | Switch to offline overlay collection, fake-internet responder, hard VM kill timer, & SHA-256 preflight | **P0** | L | Prevents live malware from blinding collectors, poisoning host via `scp`, or timing out silently. |
| **3** | [`IMP-03`](#imp-03) | Build Sysmon/ETW process-tree + multi-control diff + `ambiguous_unattributed` labeler | **P0** | L | `expected_artifact_keys` fails completely on unknown real-malware behaviors and dormant payloads. |
| **4** | [`IMP-05`](#imp-05) | Design family + fuzzy-hash (`ssdeep`/TLSH) grouped blind test & seal by SHA-256 before modeling | **P0** | M | Eliminates family/benign-run leakage and locks a truly blind v2 holdout split up front. |
| **5** | [`IMP-08`](#imp-08) | Fix `iforest` 100%-dev fit, inner-only `ae` early stopping, & multi-seed `--final` evaluation | **P0** | M | Ensures fair effective training sizes, eliminates CV early-stopping leak, & bounds MLP/AE variance. |
| **6** | [`IMP-04`](#imp-04) | Enforce blinded, non-destructive `review_sample` workflow with reviewer IDs & $\kappa$ | **P0** | S | Produces an independently auditable ground-truth verification trail for v2. |
| **7** | [`IMP-06`](#imp-06) | Replace fixed 6-template benign noise & add legitimate unsigned/service/registry drift + real byte audits | **P0** | L | Fixes template quantization (`221 -> 18` sizes) and `signature_state` shortcut before v2 data growth. |
| **8** | [`IMP-07`](#imp-07) | Versioned v2 metadata schema in `FORBIDDEN_MODEL_INPUTS` + export `task_name` / account flags | **P0** | S | Supports `executed`/`dormant` strata & family splits while fixing the `RULE-002` export bug (`IMP-13`). |
| **9** | [`IMP-09`](#imp-09) | Nested family-grouped dev CV & equal tuning budgets (including expanded MLP/IF spaces) | **P1** | M | Gives fair, unbiased dev estimates and trustworthy MLP learning curves in v2. |
| **10** | [`IMP-10`](#imp-10) / [`IMP-11`](#imp-11) | Dev-calibrated thresholds, Holm-Bonferroni adjustment, & MC/analytical random baseline | **P1** | S | Produces deployable operating points and properly calibrated statistical tests at blind `--final`. |
