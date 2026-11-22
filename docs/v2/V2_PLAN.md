# DFIR-Triage ML — Phase v2 Plan (Draft Proposal — Awaiting Operator Approvals)

**Status:** **PLANNING ONLY — DO NOT ACQUIRE MALWARE, START VM RUNS, OR WRITE v2 CODE UNTIL GATE 0 APPROVALS AND OPEN QUESTIONS ARE RESOLVED.**  
**v1 Separation:** Phase v1 (`dataset_v1.parquet`, `docs/FINAL_EVAL_PLAN.md`, `results/`) is permanently frozen and unmodified. All v2 specifications live under `docs/v2/`.  
**Related Docs:** [`docs/IMPROVEMENT_ANALYSIS.md`](../IMPROVEMENT_ANALYSIS.md) | [`docs/v2/FINAL_EVAL_PLAN_v2_SKELETON.md`](FINAL_EVAL_PLAN_v2_SKELETON.md) | [`COMPLETE_REPORT.md`](../../COMPLETE_REPORT.md)

---

## 1. Objectives

Phase v2 addresses the structural sample-size, realism, and generalization gaps identified in v1:
1. **(a) Real Malware Artifacts (Executed & Dormant):** Evaluate host-artifact triage against real malware samples (detonated inside hardened isolated VMs and staged dormant on disk as separate strata), rather than only synthetic ATT&CK emulation scripts.
2. **(b) Substantially Larger Sample Size & MLP Learning Curves:** Collect a pilot-calibrated dataset large enough to evaluate the MLP alongside RF, XGBoost, LR, AE, and IF via statistically stable learning curves and nested dev CV. *(Rough starting target to calibrate via pilot: several times v1's positives, roughly 300–500 positives across 100+ runs — exact counts deferred until the pilot measures yield.)*
3. **(c) Fresh, Strictly Blind Hash-Frozen Test Set:** Partition and cryptographically seal a blind v2 holdout split (holding out whole malware families, near-duplicate clusters, and isolated benign hosts/sessions) **before** any developer EDA, feature debugging, or model tuning occurs.
4. **(d) Full Training & Statistical Integrity:** Enforce equal tuning budgets, multi-seed evaluation, nested family-grouped CV, strict train-only preprocessing and early stopping, dev-calibrated deployable thresholds, and multiple-comparison control.

---

## 2. What Is Reused vs. Changed from v1

| Component | v1 Reference | Disposition in v2 | Planned Change |
| :--- | :--- | :--- | :--- |
| Layering principle & 15 deterministic rules | `src/rules/deterministic_rules.py` | **Reuse + fix export gap** | Persist `task_name`, `service_name`, `start_mode`, `task_triggers`, and account admin flags (`IMP-13`); keep rules separate from ML (`RULE_FEATURES` barred from `X`). |
| Locked 20-feature schema (`full_20`) & `no_content` (18) | `src/config.py`, `src/data/features.py` | **Reuse as primary baseline schema** | Keep `full_20` and `no_content` identical for direct v1-vs-v2 comparability; place any new static/PE features strictly in an optional additive `FEATURES_V2` config. |
| Strict `FORBIDDEN_MODEL_INPUTS` guard & FE-08 | `src/models/preprocess.py`, `src/data/sanitize.py` | **Reuse + extend** | Add all v2 sample/family/stratum metadata columns (`IMP-07`) to `FORBIDDEN_MODEL_INPUTS`; retain FE-08 anti-leakage scanning. |
| 6 ML model interfaces + baselines | `src/models/*.py`, `src/eval/run_track_a.py` | **Reuse + fix bugs & budgets** | Fix `iforest` 100%-dev fit, inner-only `ae` early stopping, multi-seed `--final` (`IMP-08`), equal tuning budgets + nested CV (`IMP-09`), and MC/analytical `random` baseline (`IMP-11`). |
| Hypervisor CoW overlay + UEFI/TPM base image | `lab_automation/run_one.py`, `docs/WINDOWS_11_LAB_SETUP.md` | **Harden heavily before reuse** | Lock `virbr1` `iptables`, strip SPICE clipboard, add isolated fake-internet + hard kill timer + SHA-256 vault check (`IMP-01`, `IMP-02`). |
| Live SSH + `scp -r` `Collect-Artifacts.ps1` | `collector/Collect-Artifacts.ps1`, `lab_automation/guest_runner.py` | **Replace for `executed` runs** | Stop live overlay -> parse registry hives, `Amcache.hve`, Prefetch, filesystem, and Sysmon EVTX **offline read-only** (`IMP-02`, `IMP-16`). |
| `expected_artifact_keys`-only labeler & review export | `src/data/labeler.py` | **Replace / upgrade** | Replace with Sysmon/ETW process-tree causal attribution + multi-control & pre/post diff + `ambiguous_unattributed` + blinded multi-reviewer export (`IMP-03`, `IMP-04`). |
| `benign_noise.ps1` | `lab_automation/benign_noise.ps1` | **Replace / expand** | Eliminate 6-template script quantization (`IMP-06`); generate varied real software, unsigned dev binaries, benign services, registry edits, and scheduled tasks. |
| Track B (`CIC-MalMem-2022`) | `src/eval/run_track_b.py` | **Retain as archived v1 appendix** | Do not expand; keep optional cluster-exchangeability diagnostic proposal separate (`IMP-12`). |

---

## 3. Evaluation Strata (Reported Separately & Pooled With Weights Disclosed)

Every positive sample and run belongs to exactly one declared stratum (never mixed silently in headline numbers):
1. **`executed` Stratum (Primary Real-Malware Dynamic Stratum):** Live malware binaries injected and detonated in hardened Win11 overlays with fake-internet service and Sysmon/ETW recording. Captures active persistence, execution, service/task creation, WMI, registry modifications, child processes, Prefetch, and dropped payloads.
2. **`dormant` Stratum (Static-Only On-Disk Malware Stratum):** Real malware binaries staged on disk across realistic user/system/temp locations *without* executing them (paired with realistic host baseline/benign drift). Explicitly tests whether host-artifact triage detects quiescent/unexecuted binaries using path, name, file size/entropy (`full_20` vs `no_content`), signature state, and attributes when no command-line/process/persistence artifacts exist.
3. **`emulated` Stratum (Optional Continuity Stratum — `[TBD: Keep or Drop?]`):** Parameterized/de-templated ATT&CK emulation runs serving purely as a calibration bridge back to v1; never substituted for real-malware performance metrics.

All v2 primary tables will report `(a) executed`, `(b) dormant`, `(c) [optional emulated]`, and combined metrics separately across `full_20` and `no_content`.

---

## 4. Pilot-First Data Collection Plan (No Hard Counts Until Pilot Completes)

Rather than guessing final batch counts before measuring real sample yield, v2 uses a **two-stage pilot-first design**:

1. **Stage A — Small Safety & Yield Pilot (Strict Dev-Only Pilot Families):**
   - Execute a small, operator-approved pilot batch covering `[TBD: N_pilot_families]` distinct malware families (`executed` + `dormant`) plus `[TBD: N_pilot_controls]` clean control boots and expanded benign noise schedules. *(Pilot families stay strictly in a non-test dev/calibration bucket and never enter the blind test pool.)*
   - Measure empirically from pilot logs:
     - Clean detonation rate (fraction of `executed` samples producing observable host changes within `T_detonate` vs sandbox-evading/crashed/missing-DLL duds)
     - Mean & median **verified `attacker_induced` rows per successful run** (separately for `executed` and `dormant`)
     - Ambiguous / quarantined row rate (`ambiguous_unattributed` %)
     - Mean `benign_drift` rows per run & content-feature entropy/size diversity (verify zero template quantization)
     - End-to-end per-run wall time, overlay size, and offline parser reliability.
2. **Stage B — Full Target Calibration (Informed by Pilot Measurements):**
   - Use measured pilot yield `(positives_per_run, detonation_success_rate, benign_per_run)` to set exact dev and blind-test run quotas via:
     $$\text{Target Runs} = \left\lceil \frac{\text{Target Positives}}{\text{Yield per Run} \times \text{Success Rate}} \right\rceil$$
   - **Initial Rough Planning Anchor (To Be Adjusted Post-Pilot):** Several times v1's `103` total positives (`33` test positives), roughly **`300–500` total positives across `100+` VM runs** spanning `[TBD]` distinct malware families, with exact dev vs. blind-test split ratios decided before freezing blind test.

---

## 5. MLP Learning-Curve & Capacity Plan

Because v1 had only `70` dev positives (`1,179` rows) where MLP jumped steeply from `0.1388` (25%) -> `0.2630` (50%) -> `0.7677` (100% test, vs `0.2496` dev CV) with `0.0600` seed std:
1. **Family-Grouped Training-Size Sweep (Dev Nested CV & Frozen Blind Evaluation):**
   - Subsample dev **by whole malware family & benign session groups** (never random rows, fixing v1 `_grouped_subsample_dev` benign row-level sampling) across `[TBD: e.g., 10%, 25%, 50%, 75%, 100%]` of dev families.
   - Evaluate ALL 6 ML arms (`rf`, `xgb`, `lr`, `mlp`, `ae`, `iforest`) at each fraction across **`[TBD: K >= 5]` seeds**, plotting mean ± 1 SD and min/max bands.
2. **MLP Stabilization & Capacity Diagnostics:**
   - Expand MLP search space slightly while preserving equal tuning trial budget (`IMP-09`): layer widths, dropout, `weight_decay`, `lr`, BatchNorm vs LayerNorm (reduces sensitivity to positive-rare minibatches), and calibrated `pos_weight` (`[1, sqrt(n_neg/n_pos), n_neg/n_pos]`).
   - Compare single-seed MLP vs K-seed bagged MLP ensemble so variance reduction is quantified explicitly.

---

## 6. Training, Tuning & Evaluation Integrity Protocol

Non-negotiable training rules enforced in v2 pipeline tests:
1. **Strict Split-Local Preprocessing:** `SharedPreprocessor` (imputers, scalers, one-hot encoders) and any v2 transformers fit **exclusively inside each CV training fold** (and benign-only training rows for `ae` and `iforest`). No feature selection (`drop_*`, frequency filtering) occurs outside folds.
2. **Equal Tuning Budgets:** Every tuned model family receives an identical trial budget `N_trials = [TBD]` using the exact same inner family-grouped splits and seed schedule. No post-hoc `--best-params` reuse across different feature subsets (`IMP-14`).
3. **Nested Family-Grouped Dev CV:** Outer CV folds hold out whole malware families + benign sessions to produce an **unbiased** dev generalization estimate and per-family leave-one-family-out (LOFO) table; inner CV selects hyperparameters; a strictly separate **inner validation slice** handles `mlp`/`ae` early stopping (`IMP-08`).
4. **Full Dev Refit & Multi-Seed `--final`:** Models without early stopping (`rf`, `xgb`, `lr`, **`iforest`**) train on `100%` of eligible dev data; `mlp`/`ae` run across `[TBD: K >= 5]` seeds via CV-fold ensembling or epoch-matched full-dev refit.
5. **Dev-Calibrated Deployable Operating Thresholds:** Precision/FPR operating points (e.g., target val FPR `1%` or fixed alert budget) are frozen from dev nested OOF predictions **before** unblinding test (`IMP-10`), eliminating test-selected threshold bias.

---

## 7. Malware Safety Protocol (Gate 0 — Required Before Any Sample Acquisition or Execution)

> [!CAUTION]
> **Hard Safety Gate:** No malware binary may be acquired, stored, transferred, or booted until every item below is verified by automated preflight checks AND explicitly signed off by the operator.

1. **Sample Storage & Access Hygiene (Host Side):**
   - Encrypted, non-executable quarantine vault outside the repo (`chmod 0700` dir, `0400` AES-256 encrypted zip or isolated loopback volume, NEVER committed to git and excluded from host indexing/antivirus auto-quarantine confusion).
   - Mandatory SHA-256 manifest verification (`sample_sha256`, source provenance ID, family label, execution mode) immediately prior to each VM injection.
2. **Host-Guest Containment & Network Isolation:**
   - Dedicated libvirt network `win11-isolated` (`no <forward> element`) with **hardened default-DROP `iptables`/`nftables`** rules (`IMP-01`): block ALL guest-to-host (`INPUT`) services during execution except strictly scoped control/fake-net ports (or zero host `INPUT` when using offline collection + dedicated VM/namespace responder), and block all `FORWARD` traffic.
   - Strip SPICE clipboard sharing, shared folders, host USB passthrough, and host-accessible network shares (`qemu` guest-agent file-copy disabled except bounded single-file injection prior to execution, or disk/ISO image injection read-only).
   - Dedicated isolated **fake-internet responder** (`[TBD: INetSim container in netns vs secondary isolated VM vs FakeNet-NG]`) so DNS/HTTP/HTTPS queries resolve inside the sandbox without touching any real network.
3. **Immutable Base & Guaranteed Cleanup:**
   - Base disk `win11_base.qcow2` (`chmod 0444`) and `win11_VARS.fd.base` remain read-only; automated SHA-256 hash recorded **before** and verified **after** each batch.
   - Every run boots from a fresh disposable `win11_overlay.qcow2` + fresh NVRAM copy.
   - External host-side hard watchdog enforces `run_wall_clock_max_seconds` via `virsh destroy`.
4. **Offline Read-Only Artifact Extraction (`IMP-02`):**
   - Do **not** run `Collect-Artifacts.ps1` or `scp -r` from inside a live malware-infected guest.
   - After `virsh destroy`, mount or parse `win11_overlay.qcow2` **strictly read-only** (`qemu-nbd --read-only` / isolated extractor namespace or `dissect`/`libguestfs`), extracting only schema-validated structured records and first-1 MiB byte histograms (never copying executable payloads onto the host filesystem workspace), then securely unlink `win11_overlay.qcow2`.
5. **Incident / Abort Criteria:** Immediate `virsh destroy` + batch halt if any unexpected packet leaves `virbr1`, base image mtime/hash changes, host CPU/disk guard triggers, or overlay unmount fails.

---

## 8. v2 Labeling & Independent Human Review Method

1. **Extended Telemetry:** Add **Sysmon + ETW** process/file/registry/task/WMI/network logging inside the clean base image (capturing `ProcessGuid`, `ParentProcessGuid`, `Hashes`, `CommandLine`, target keys/files) alongside offline registry hive + `Amcache.hve` + Prefetch extraction.
2. **Three-Tier Labeling Pipeline:**
   - **`executed` runs:** (a) Match against expanded multi-control boot baseline index -> unchanged = `baseline`; (b) trace Sysmon/ETW descendant trees from the injected malware PID/`ProcessGuid` -> matched changes = `attacker_induced` (`attribution_method = "process_tree_etw"`); (c) trace descendant trees from synthetic benign scheduler PIDs -> `benign_drift`; (d) compare remaining OS background diffs against a clean-window idle catalog (`[TBD: >= 5-10` varied control boots across uptime lengths); any unverified residual artifact is quarantined to **`ambiguous_unattributed`** (never silently coerced to benign negative).
   - **`dormant` runs:** Label directly from deterministic pre-registered staging manifest `(staged_path, sample_sha256)` + pre/post offline disk diff, verified negative for any execution trace.
3. **Genuinely Independent Human Review (`IMP-04`):**
   - Freeze automated labels cleanly, then export a **blinded** stratified review sample (hiding `label`, `label_reason`, `sample_family`, and `launcher`, displaying artifact fields + process-tree parent chain + control-boot frequency).
   - Reviewer(s) record `reviewer_id`, `reviewed_at_utc`, `human_label`, and per-row forensic rationale notes; compute agreement & Cohen's $\kappa$ on a dual-reviewed overlap subset (`[TBD: e.g. 20%]`) before merging adjudicated corrections via `label_corrections_v2.csv`.

---

## 9. Blind-Test Freeze Procedure

1. **Disjoint Unit of Assignment:** Group all positives by **`sample_family`** AND **`ssdeep`/TLSH near-duplicate cluster** so no related binary or variant ever straddles dev and blind test. Assign benign runs from **separate VM sessions / benign software profiles** into the blind-test pool so zero `artifact_key`, `run_id`, or `benign_noise` template matches occur across pools.
2. **Holdout Sealing Before Modeling:** Immediately after dataset assembly & blind human review adjudication (zero feature exploration, zero CV runs, zero model code execution on test rows):
   - Write split assignments into `data/splits/v2_blind_test_manifest.json` containing **`blind_test_sha256`** (canonical SHA-256 over sorted test artifact keys, run IDs, labels, strata, and all `FEATURES` + `FEATURES_V2`), holdout family list (hashed or stored in a restricted blind-split manifest), row counts per stratum, and git commit hash.
   - Move/store raw blind-test run artifacts in a sealed read-only path until `--final`, exposing only `split_pool == "dev"` to model development scripts until the pre-registered v2 evaluation plan is locked and committed.
3. **One-Shot Execution Guard:** Enforce `results/logs/final_eval_audit_v2.jsonl` checking `blind_test_sha256` and refusing duplicate `--final` runs without `--force`.

---

## 10. Pre-Registered Winner Rule (Carried Over & Hardened from v1)

Preserving v1's core dual-configuration philosophy:
- Evaluate every arm in both **`full_20`** and **`no_content`** (plus optional **`v2_extended`** reported strictly in its own block, never replacing the `full_20`/`no_content` primary test).
- Report per-stratum (`executed`, `dormant`, `[optional emulated]`) and overall PR-AUC with family-clustered & run-clustered bootstrap 95% CIs.
- **Dual-Config Winner Rule:** Model $A$ is declared better than $B$ on a pre-registered comparison **only if the family-clustered paired bootstrap CI excludes `0` in the same direction in BOTH `full_20` and `no_content` AFTER Holm-Bonferroni family-wise correction across the pre-registered comparison set** (without post-hoc `best_ml` selection); otherwise report `"not distinguishable"` or `"configuration-dependent"`.

---

## 11. Success Criteria & Limitations to State Plainly

### Success Criteria (Qualitative / Threshold-Relative — Specific `[TBD]` Targets After Pilot)
1. Zero containment incidents; 100% pre/post `base_image` SHA-256 verification and `100%` overlay cleanup.
2. Verified blind-test isolation (`0` family, fuzzy-hash cluster, `sample_sha256`, benign `artifact_key`, and benign-run overlap) sealed by `blind_test_sha256` before dev modeling.
3. Unbiased nested dev CV + multi-seed (`K >= 5`) MLP learning curve clearly resolving v1's under-powered MLP variance (`std = 0.0600` on v1 `full_20`), alongside equal tuning budgets across all 6 models.
4. Dev-calibrated deployable thresholds evaluated **once** on blind test (separately for `executed` and `dormant`), paired with statistically corrected dual-config verdicts (`full_20` + `no_content`) and rule/hybrid comparisons.
5. Plain elimination of v1 script template quantization (`benign_noise` diversity > v1's `18/221` unique script sizes) and missing benign `service`/`registry` coverage.

### Limitations to State Plainly in v2 Paper / Report
- Sandbox detonation window (`run_duration_s`) cannot observe long-dormant logic bombs or C2 payloads requiring real live external infrastructure beyond the fake-internet responder.
- VM-based artifacts capture fresh/moderate host state rather than multi-year enterprise endpoint telemetry.
- Dormant-file performance under `no_content` intentionally excludes file bytes/size/entropy and reflects metadata/path/signature visibility limits.
- Real malware sample bias reflects the chosen repository/feeds and dates.

---

## 12. Risk Register

| Risk | Likelihood | Impact | Mitigation |
| :--- | :---: | :---: | :--- |
| Host infection / network escape during malware run | Low | Critical | Default-DROP `virbr1` firewall, no SPICE clipboard/shares, immutable `0444` base + hash verification, offline overlay parsing (`IMP-01`, `IMP-02`). |
| Malware detects VM/sandbox (`VMware`/`QEMU`/`VirtualBox` artifacts) and exits early (low detonation rate) | High | High | Stage **pilot** first to measure actual detonation rate; add fake-internet responder; classify failed detonations explicitly (`detonation_exit_status`) & analyze root cause rather than mislabeling. |
| Attribution errors (system side effects mislabeled `attacker_induced`, or malware child missed) | Medium | High | Sysmon + ETW process-tree attribution + multi-control idle index + explicit `ambiguous_unattributed` quarantine + blinded multi-reviewer adjudication. |
| Packer/compiler stub leakage across malware families (`UPX`, shared builder) | Medium | High | Cluster samples by `ssdeep`/TLSH/imphash *in addition to* family before assigning dev vs blind-test folds. |
| Benign software/noise remains overly synthetic -> over-optimistic PR-AUC | Medium | High | Diverse genuine benign apps/installers, unsigned benign scripts, benign services/tasks/registry edits, and realistic low-prevalence host test slice (`IMP-06`). |
| Compute / disk bottleneck from 100+ runs × offline overlay inspection × nested 5-seed CV | Medium | Medium | Measure exact runtime/disk in pilot first; enforce `min_free_disk_gb` guard; clean up each overlay immediately after schema-validated JSON extraction. |

---

## 13. Ordered Task List (No Dates)

1. **Resolve all OPEN QUESTIONS (§14)** and obtain explicit written/recorded operator approval on malware sample sourcing and the **Gate 0 Safety Protocol (§7)**.
2. **Phase 1 — Hardening & Infrastructure Upgrades (Code + VM):**
   - Lock `virbr1` `iptables`/`nftables`, strip SPICE clipboard/shared channels, deploy isolated fake-internet responder, and verify containment via negative egress test.
   - Install Sysmon + ETW baseline inside a clean v2 VM base image and lock `0444` + SHA-256 baseline.
   - Implement offline read-only overlay extractor (`IMP-02`, `IMP-16`), schema-v2 provenance + `FORBIDDEN_MODEL_INPUTS` (`IMP-07`), process-tree diff labeler + `ambiguous_unattributed` + blinded review exporter (`IMP-03`, `IMP-04`), diverse benign noise generator (`IMP-06`), and v2 ML training/stats fixes (`IMP-08`–`IMP-15`).
3. **Phase 2 — Pilot Run & Yield Measurement:**
   - Run clean control boots + approved small pilot batch (`executed` + `dormant`).
   - Measure yield (`positives/run`, detonation rate, ambiguous rate, benign diversity/quantization check) and set full target sample/run counts + prevalence.
4. **Phase 3 — Full Data Collection, Labeling & Blind-Test Freeze:**
   - Execute dev and blind-test collection batches with pre/post base-image hash checks.
   - Run Sysmon/ETW + offline snapshot labeler; run blinded independent human review; adjudicate `label_corrections_v2.csv`.
   - Group by family + fuzzy-hash cluster + benign session; generate and **cryptographically freeze** `v2_blind_test_manifest.json` (`blind_test_sha256`).
5. **Phase 4 — Dev Modeling, Nested CV, Learning Curves & Pre-Registration Lock:**
   - On `dev` only: run nested family-grouped CV with equal tuning budgets, multi-seed MLP learning curves, dev ablations, and dev-calibrated operating thresholds.
   - Fill all `[TBD]` placeholders in `docs/v2/FINAL_EVAL_PLAN_v2_SKELETON.md` -> commit final `docs/v2/FINAL_EVAL_PLAN_v2.md` **before** running `--final`.
6. **Phase 5 — One-Shot Blind `--final`, Explainability & v2 Report:**
   - Execute `--final` **once** under `final_eval_audit_v2.jsonl` across `full_20` & `no_content` (and optional `v2_extended`), reporting `executed` and `dormant` strata, Holm-Bonferroni dual-config verdicts, dev-calibrated thresholds, SHAP ranks/normalized shares, and error analysis.

---

## 14. OPEN QUESTIONS (Requiring Operator Decision — Do Not Proceed Until Decided)

1. **Malware Sample Sourcing & Approvals:** Which authorized malware repository/feed (e.g., MalwareBazaar, VirusShare, institutional/research collection, internal malware zoo) will supply v2 samples, and what ethical/legal/institutional approvals or handling rules apply?
2. **Number & Choice of Malware Families:** How many distinct malware families (`dev` vs `blind_test`) and which categories (e.g., Ransomware, InfoStealer, Loader/Dropper, RAT/Backdoor, Coinminer, Trojanized Installer) do you want represented? Should family labels come from AVClass2 / ClarAVy consensus normalization?
3. **Stratum Mix (`executed` vs `dormant` vs `emulated`):** What target proportion/count of runs or positives should belong to **`executed`** vs **`dormant`**, and do you want to keep an **`emulated`** continuity stratum at all or focus 100% on real malware + benign?
4. **Pilot Size:** How many clean control boots, malware families, and runs (`executed` + `dormant`) do you approve for Stage A pilot yield calibration?
5. **Fake-Internet Responder Architecture:** Which isolated fake-network setup should `win11-isolated` use (`INetSim` in an isolated Linux network namespace, `FakeNet-NG` in-guest, a second isolated Linux DNS/HTTP VM, or pure offline with NXDOMAIN)?
6. **Offline Overlay Parser Stack:** After `virsh destroy`, which host-side read-only extraction toolchain do you prefer (`qemu-nbd --read-only` + `dissect`/`regipy`/`evtx` in an unprivileged container vs `libguestfs`/`guestmount`)?
7. **Independent Human Label Review Ownership:** Who will perform the **blinded** human label review on v2 (name/role), and can a second independent reviewer score an overlap sample for inter-rater Cohen's $\kappa$?
8. **Feature Schema Scope (`full_20` / `no_content` vs `v2_extended`):** Should v2 evaluate strictly the locked v1 schemas (`full_20` and `no_content`) only, or also add a clearly separated `v2_extended` ablation/secondary schema (e.g., PE imports/sections/entropy distributions, rich Sysmon parent chains, Amcache)?
9. **Benign Software Roster & Target Test Prevalence:** Which legitimate installers/admin tools/unsigned scripts will compose the expanded benign noise suite, and at what realistic host attack prevalence (raw full-host snapshot ratio vs. specified subsampled prevalence alongside full snapshot reporting) should blind test be evaluated?
10. **Compute Budget for Multi-Seed & Nested CV:** What seed count (e.g., `K = 5` vs `10`) and equal per-arm tuning budget (`N_trials`, e.g., `30` vs `50`) fit the machine's available GPU/CPU hours?
