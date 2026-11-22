# DFIR-Triage ML — Phase v2 Plan (Draft Proposal — Pending Operator Confirmation)

**Status:** **PHASE 1 PREP / PLANNING — DO NOT ACQUIRE MALWARE OR START VM RUNS UNTIL GATE 0 APPROVALS AND [`OPERATOR_DECISIONS.md`](OPERATOR_DECISIONS.md) ITEMS ARE CONFIRMED BY MOKH.**  
**v1 Separation:** Phase v1 (`dataset_v1.parquet`, `docs/FINAL_EVAL_PLAN.md`, `results/`) is permanently frozen and unmodified. All v2 specifications live under `docs/v2/`.  
**Related Docs:** [`docs/v2/OPERATOR_DECISIONS.md`](OPERATOR_DECISIONS.md) | [`v2/plan.md`](../../v2/plan.md) | [`docs/IMPROVEMENT_ANALYSIS.md`](../IMPROVEMENT_ANALYSIS.md) | [`docs/v2/FINAL_EVAL_PLAN_v2_SKELETON.md`](FINAL_EVAL_PLAN_v2_SKELETON.md) | [`COMPLETE_REPORT.md`](../../COMPLETE_REPORT.md)

---

## 1. Objectives

Phase v2 addresses the structural sample-size, realism, and generalization gaps identified in v1:
1. **(a) Real Malware Artifacts (Executed & Dormant):** Evaluate host-artifact triage against real malware samples (detonated inside hardened isolated VMs and staged dormant on disk as separate strata), rather than only synthetic ATT&CK emulation scripts.
2. **(b) Substantially Larger Family Coverage, Sample Size & MLP Learning Curves:** Target **`>= 25–30` total distinct malware families with `>= 10–15` distinct families in the blind test** *(pilot decides final feasibility; pending Mokh's confirmation, [`OD-V2-01`](OPERATOR_DECISIONS.md))*, paired with a pilot-calibrated run/positive volume (rough starting anchor: `~300–500` positives across `100+` VM runs) large enough to evaluate MLP alongside RF, XGBoost, LR, AE, and IF via statistically stable learning curves and nested dev CV.
3. **(c) Fresh, Strictly Blind Hash-Frozen Test Set:** Partition and cryptographically seal a 100%-new blind v2 holdout split (holding out whole malware families, near-duplicate clusters, and isolated benign hosts/sessions — zero v1 rows/keys/techniques) **before** any developer EDA, feature debugging, or model tuning occurs.
4. **(d) Full Training & Statistical Integrity:** Enforce equal tuning budgets (`N_trials = 30`), multi-seed evaluation (`K = 5` seeds), nested family-grouped CV, strict train-only preprocessing and early stopping, dev-calibrated deployable thresholds, and Holm-Bonferroni multiple-comparison control.

---

## 2. What Is Reused vs. Changed from v1

| Component | v1 Reference | Disposition in v2 | Planned Change |
| :--- | :--- | :--- | :--- |
| Frozen v1 dataset (`dataset_v1.parquet`) | `data/processed/dataset_v1.parquet` (`1,549` rows, `103` pos) | **Reuse as `dev`-only `"emulated"` stratum** *(pending Mokh's confirmation)* | Kept strictly inside the training pool (`dev` only) as a third `"emulated"` stratum; v2 blind test is **100% new**, and reuse is explicitly disclosed (`OD-V2-02`). |
| Layering principle & 15 deterministic rules | `src/rules/deterministic_rules.py` | **Reuse + fix export gap** | Persist `task_name`, `service_name`, `start_mode`, `task_triggers`, and account admin/enabled flags (`IMP-13`); keep rules separate from ML (`RULE_FEATURES` barred from `X`). |
| Locked 20-feature schema (`full_20`) & `no_content` (18) | `src/config.py`, `src/data/features.py` | **Reuse as primary baseline schema** | Keep `full_20` and `no_content` identical for direct v1-vs-v2 comparability; place any new static/PE features strictly in an optional additive `v2_extended` config *(pending Mokh's confirmation, `OD-V2-11`)*. |
| Strict `FORBIDDEN_MODEL_INPUTS` guard & FE-08 | `src/models/preprocess.py`, `src/data/sanitize.py` | **Reuse + extend** | Add all 14 v2 provenance/stratum metadata columns (`IMP-07`) to `META_COLUMNS` / `FORBIDDEN_MODEL_INPUTS`; retain FE-08 anti-leakage scanning. |
| 6 ML model interfaces + baselines | `src/models/*.py`, `src/eval/run_track_a.py` | **Reuse + fix bugs & budgets** | Add v2 paths fixing `iforest` 100%-dev fit, inner-only `ae` early stopping, `K = 5` multi-seed `--final` (`IMP-08`), `30` equal trials + nested CV (`IMP-09`), and 10k-perm MC `random` baseline (`IMP-11`). |
| Hypervisor CoW overlay + UEFI/TPM base image | `lab_automation/run_one.py`, `docs/WINDOWS_11_LAB_SETUP.md` | **Harden heavily before reuse** | Lock `virbr1` `iptables` (default-DROP), strip SPICE clipboard/shared folders/USB, run `INetSim` on a **separate isolated Linux VM**, add hard kill timer + SHA-256 vault check (`IMP-01`, `IMP-02`, `OD-V2-03`). |
| Live SSH + `scp -r` `Collect-Artifacts.ps1` | `collector/Collect-Artifacts.ps1`, `lab_automation/guest_runner.py` | **Replace for `executed` runs** | Stop live overlay -> parse registry hives, `Amcache.hve`, Prefetch, filesystem, and Sysmon EVTX via **user-space offline parsing in an unprivileged container (never host-kernel mounts)** (`IMP-02`, `IMP-16`, `OD-V2-04`). |
| `expected_artifact_keys`-only labeler & review export | `src/data/labeler.py` | **Replace / upgrade** | Replace with Sysmon/ETW process-tree causal attribution + multi-control & pre/post diff + `ambiguous_unattributed` + blinded multi-reviewer export (`IMP-03`, `IMP-04`, `OD-V2-10`). |
| `benign_noise.ps1` | `lab_automation/benign_noise.ps1` | **Replace / expand** | Eliminate 6-template script quantization (`IMP-06`); generate varied real software, unsigned dev binaries, benign services, registry edits, and scheduled tasks (`OD-V2-12`). |
| Track B (`CIC-MalMem-2022`) | `src/eval/run_track_b.py` | **Retain as archived v1 appendix** | Do not expand; keep optional cluster-exchangeability diagnostic proposal separate (`IMP-12`). |

---

## 3. Evaluation Strata (Reported Separately & Pooled With Weights Disclosed)

Every positive sample and run belongs to exactly one declared stratum (never mixed silently in headline numbers):
1. **`executed` Stratum (Primary Real-Malware Dynamic Stratum):** Live malware binaries injected and detonated in hardened Win11 overlays with the separate isolated `INetSim` VM and Sysmon/ETW recording. Captures active persistence, execution, service/task creation, WMI, registry modifications, child processes, Prefetch, and dropped payloads.
2. **`dormant` Stratum (Static-Only On-Disk Malware Stratum):** Real malware binaries staged on disk across realistic user/system/temp locations *without* executing them (paired with realistic host baseline/benign drift). Explicitly tests whether host-artifact triage detects quiescent/unexecuted binaries using path, name, file size/entropy (`full_20` vs `no_content`), signature state, and attributes when no command-line/process/persistence artifacts exist.
3. **`emulated` Stratum (v1 Training-Pool Continuity Stratum — `dev` only, `OD-V2-02` *(pending Mokh's confirmation)*):** Reuse frozen v1 (`dataset_v1.parquet`) strictly as a third training-pool stratum (`dev` only) serving as a continuity bridge back to v1. Zero v1 rows, keys, or simulated techniques enter the v2 blind test (which is 100% new), and v1 reuse is explicitly disclosed in every v2 table and report.

All v2 primary tables will report `(a) executed`, `(b) dormant`, `(c) emulated` (`dev`/training disclosure only), and combined real-malware metrics separately across `full_20` and `no_content`.

---

## 4. Pilot-First Data Collection Plan (No Hard Quotas Until Pilot Completes)

Rather than guessing final batch counts before measuring real sample yield, v2 uses a **two-stage pilot-first design**:

1. **Stage A — Small Safety & Yield Pilot (Strict Dev-Only Pilot Families, `OD-V2-05` *(pending Mokh's confirmation)*):**
   - Execute a small, operator-approved pilot batch covering **`~3` clean control boots** + **`6–8` distinct non-test malware families × `1–2` runs** (`executed` + `dormant`) with expanded benign noise schedules *(pending Mokh's confirmation)*. *(Pilot families stay strictly in a non-test dev/calibration bucket and never enter the blind test pool.)*
   - Measure empirically from pilot logs:
     - Clean detonation rate (fraction of `executed` samples producing observable host changes within `T_detonate` vs sandbox-evading/crashed/missing-DLL duds)
     - Mean & median **verified `attacker_induced` rows per successful run** (separately for `executed` and `dormant`)
     - Ambiguous / quarantined row rate (`ambiguous_unattributed` %)
     - Mean `benign_drift` rows per run & content-feature entropy/size diversity (verify zero template quantization)
     - End-to-end per-run wall time, overlay size, and offline parser reliability.
2. **Stage B — Full Target Calibration (Informed by Pilot Measurements, `OD-V2-01` *(pending Mokh's confirmation)*):**
   - Use measured pilot yield `(positives_per_run, detonation_success_rate, benign_per_run)` to set exact dev and blind-test run quotas via:
     $$\text{Target Runs} = \left\lceil \frac{\text{Target Positives}}{\text{Yield per Run} \times \text{Success Rate}} \right\rceil$$
   - **Proposed Family & Volume Targets (Pilot Decides Final Feasibility, *pending Mokh's confirmation*):** **`>= 25–30` total distinct malware families**, with **`>= 10–15` distinct families in the blind test**, alongside a rough starting volume anchor of **`~300–500` total positives across `100+` VM runs**. Exact dev vs. blind-test counts are locked after pilot yield calibration and prior to blind-test freeze.

---

## 5. MLP Learning-Curve & Capacity Plan

Because v1 had only `70` dev positives (`1,179` rows) where MLP jumped steeply from `0.1388` (25%) -> `0.2630` (50%) -> `0.7677` (100% test, vs `0.2496` dev CV) with `0.0600` seed std:
1. **Family-Grouped Training-Size Sweep (Dev Nested CV & Frozen Blind Evaluation):**
   - Subsample dev **by whole malware family & benign session groups** (never random rows, fixing v1 `_grouped_subsample_dev` benign row-level sampling) across `[e.g., 10%, 25%, 50%, 75%, 100%]` of dev families.
   - Evaluate ALL 6 ML arms (`rf`, `xgb`, `lr`, `mlp`, `ae`, `iforest`) at each fraction across **`K = 5` seeds (`[42, 43, 44, 45, 46]`, `OD-V2-06`, *pending Mokh's confirmation*)**, plotting mean ± 1 SD and min/max bands.
2. **MLP Stabilization & Capacity Diagnostics:**
   - Expand MLP search space slightly while preserving equal tuning trial budget (`N_trials = 30`, `IMP-09`): layer widths, dropout, `weight_decay`, `lr`, BatchNorm vs LayerNorm (reduces sensitivity to positive-rare minibatches), and calibrated `pos_weight` (`[1, sqrt(n_neg/n_pos), n_neg/n_pos]`).
   - Compare single-seed MLP vs K-seed bagged MLP ensemble so variance reduction is quantified explicitly.

---

## 6. Training, Tuning & Evaluation Integrity Protocol

Non-negotiable training rules enforced in v2 pipeline tests:
1. **Strict Split-Local Preprocessing:** `SharedPreprocessor` (imputers, scalers, one-hot encoders) and any v2 transformers fit **exclusively inside each CV training fold** (and benign-only training rows for `ae` and `iforest`). No feature selection (`drop_*`, frequency filtering) occurs outside folds.
2. **Equal Tuning Budgets (`OD-V2-06`, *pending Mokh's confirmation*):** Every tuned model family receives an identical trial budget **`N_trials = 30`** using the exact same inner family-grouped splits and seed schedule. No post-hoc `--best-params` reuse across different feature subsets (`IMP-14`). `ae`/`iforest` hyperparameter selection uses label-free benign OOF criteria by default unless explicitly tagged `"label-selected"`.
3. **Nested Family-Grouped Dev CV:** Outer CV folds hold out whole malware families + benign sessions to produce an **unbiased** dev generalization estimate and per-family leave-one-family-out (LOFO) table; inner CV selects hyperparameters; a strictly separate **inner validation slice** handles `mlp`/`ae` early stopping (`IMP-08`).
4. **Full Dev Refit & Multi-Seed `--final` (`OD-V2-06`, *pending Mokh's confirmation*):** Models without early stopping (`rf`, `xgb`, `lr`, **`iforest`**) train on `100%` of eligible dev data; `mlp`/`ae` run across **`K = 5` seeds** via documented median-epoch full-dev refit or fold ensembling, reporting per-seed mean/std alongside the 5-seed ensemble.
5. **Dev-Calibrated Deployable Operating Thresholds:** Precision/FPR operating points (e.g., target val FPR `1%` or fixed alert budget) are frozen from dev nested OOF predictions **before** unblinding test (`IMP-10`), eliminating test-selected threshold bias.

---

## 7. Malware Safety Protocol (Gate 0 — Required Before Any Sample Acquisition or Execution)

> [!CAUTION]
> **Hard Safety Gate:** No malware binary may be acquired, stored, transferred, or booted until every item below is verified by automated preflight checks AND explicitly signed off by the operator.

1. **Sample Storage & Access Hygiene (Host Side):**
   - Encrypted, non-executable quarantine vault outside the repo (`chmod 0700` dir, `0400` AES-256 encrypted zip or isolated loopback volume, NEVER committed to git and excluded from host indexing/antivirus auto-quarantine confusion).
   - Mandatory SHA-256 manifest verification (`sample_sha256`, source provenance ID, family label, execution mode) immediately prior to each VM injection.
2. **Host-Guest Containment & Network Isolation (`OD-V2-03`, *pending Mokh's confirmation*):**
   - Dedicated libvirt network `win11-isolated` (`no <forward> element`) with **hardened default-DROP `iptables`/`nftables`** rules (`IMP-01`): block ALL guest-to-host (`INPUT`) services and block all cross-bridge `FORWARD` traffic.
   - Strip SPICE clipboard sharing (`copypaste='no'`), vdagent/file-transfer channels, shared folders, host USB passthrough, and host-accessible network shares (`qemu` guest-agent file-copy disabled except bounded single-file injection prior to execution, or read-only ISO/disk injection).
   - Dedicated isolated **fake-internet responder (`INetSim` on a separate isolated Linux VM `inetsim-vm` attached to `win11-isolated`)** so DNS/HTTP/HTTPS queries resolve inside the sandbox without touching the host OS or any real network.
3. **Immutable Base & Guaranteed Cleanup:**
   - Base disk `win11_base.qcow2` (`chmod 0444`) and `win11_VARS.fd.base` remain read-only; automated SHA-256 hash recorded **before** and verified **after** each batch.
   - Every run boots from a fresh disposable `win11_overlay.qcow2` + fresh NVRAM copy.
   - External host-side hard watchdog enforces `run_wall_clock_max_seconds` via `virsh destroy`.
4. **Offline Read-Only Artifact Extraction (`IMP-02`, `OD-V2-04`, *pending Mokh's confirmation*):**
   - Do **not** run `Collect-Artifacts.ps1` or `scp -r` from inside a live malware-infected guest.
   - After `virsh destroy`, parse `win11_overlay.qcow2` via **user-space offline parsing inside an unprivileged container (`--network=none`, `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`)** using pure user-space QCOW2/NTFS/registry/EVTX/Amcache/Prefetch parsers (`dissect`/`regipy`/`evtx`/`libscca`) — **NEVER perform host-kernel mounts (`mount` or kernel `qemu-nbd` block mounts) of infected images**. Extract only schema-validated structured records and first-1 MiB byte histograms (never copying executable payloads onto the host filesystem workspace), then securely unlink `win11_overlay.qcow2`.
5. **Incident / Abort Criteria:** Immediate `virsh destroy` + batch halt if any unexpected packet leaves `virbr1`, base image mtime/hash changes, host CPU/disk guard triggers, or overlay unmount fails.

---

## 8. v2 Labeling & Independent Human Review Method

1. **Extended Telemetry:** Add **Sysmon + ETW** process/file/registry/task/WMI/network logging inside the clean base image (capturing `ProcessGuid`, `ParentProcessGuid`, `Hashes`, `CommandLine`, target keys/files) alongside offline registry hive + `Amcache.hve` + Prefetch extraction.
2. **Three-Tier Labeling Pipeline:**
   - **`executed` runs:** (a) Match against expanded multi-control boot baseline index -> unchanged = `baseline`; (b) trace Sysmon/ETW descendant trees from the injected malware PID/`ProcessGuid` -> matched changes = `attacker_induced` (`attribution_method = "process_tree_etw"`); (c) trace descendant trees from synthetic benign scheduler PIDs -> `benign_drift`; (d) compare remaining OS background diffs against a clean-window idle catalog (`[TBD: >= 5-10` varied control boots across uptime lengths); any unverified residual artifact is quarantined to **`ambiguous_unattributed`** (never silently coerced to benign negative).
   - **`dormant` runs:** Label directly from deterministic pre-registered staging manifest `(staged_path, sample_sha256)` + pre/post offline disk diff, verified negative for any execution trace.
3. **Genuinely Independent Human Review (`IMP-04`, `OD-V2-10`, *pending Mokh's confirmation*):**
   - Freeze automated labels cleanly, then export a **blinded** stratified review sample (hiding `label`, `label_reason`, `sample_family`, and `launcher`, displaying artifact fields + process-tree parent chain + control-boot frequency).
   - Reviewer(s) record `reviewer_id`, `reviewed_at_utc`, `human_label`, and per-row forensic rationale notes; compute agreement & Cohen's $\kappa$ on a dual-reviewed overlap subset (`20%` stratified overlap, *pending Mokh's confirmation*) before merging adjudicated corrections via `label_corrections_v2.csv`.

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
- Report per-stratum (`executed`, `dormant`, and dev-only `emulated` disclosure) and overall real-malware PR-AUC with family-clustered & run-clustered bootstrap 95% CIs.
- **Dual-Config Winner Rule:** Model $A$ is declared better than $B$ on a pre-registered comparison **only if the family-clustered paired bootstrap CI excludes `0` in the same direction in BOTH `full_20` and `no_content` AFTER Holm-Bonferroni family-wise correction across the pre-registered comparison set** (without post-hoc `best_ml` selection); otherwise report `"not distinguishable"` or `"configuration-dependent"`.

---

## 11. Success Criteria & Limitations to State Plainly

### Success Criteria (Qualitative / Threshold-Relative — Specific `[TBD]` Targets After Pilot)
1. Zero containment incidents; 100% pre/post `base_image` SHA-256 verification and `100%` overlay cleanup.
2. Verified blind-test isolation (`0` family, fuzzy-hash cluster, `sample_sha256`, benign `artifact_key`, and benign-run overlap; zero v1 rows in blind test) sealed by `blind_test_sha256` before dev modeling.
3. Unbiased nested dev CV + multi-seed (`K = 5` seeds) MLP learning curve clearly resolving v1's under-powered MLP variance (`std = 0.0600` on v1 `full_20`), alongside equal `30`-trial tuning budgets across all 6 models.
4. Dev-calibrated deployable thresholds evaluated **once** on blind test (separately for `executed` and `dormant`), paired with statistically corrected dual-config verdicts (`full_20` + `no_content`) and rule/hybrid comparisons.
5. Plain elimination of v1 script template quantization (`benign_noise` diversity > v1's `18/221` unique script sizes) and missing benign `service`/`registry` coverage.

### Limitations to State Plainly in v2 Paper / Report
- Sandbox detonation window (`run_duration_s`) cannot observe long-dormant logic bombs or C2 payloads requiring real live external infrastructure beyond the isolated `INetSim` VM.
- VM-based artifacts capture fresh/moderate host state rather than multi-year enterprise endpoint telemetry.
- Dormant-file performance under `no_content` intentionally excludes file bytes/size/entropy and reflects metadata/path/signature visibility limits.
- Real malware sample bias reflects the chosen repository/feeds and dates; v1 `emulated` reuse inside the training pool (`dev` only) is explicitly disclosed.

---

## 12. Risk Register

| Risk | Likelihood | Impact | Mitigation |
| :--- | :---: | :---: | :--- |
| Host infection / network escape during malware run | Low | Critical | Default-DROP `virbr1` firewall, no SPICE clipboard/shares/USB, immutable `0444` base + hash verification, `INetSim` on separate isolated Linux VM, user-space unprivileged-container offline parsing (`IMP-01`, `IMP-02`). |
| Malware detects VM/sandbox (`VMware`/`QEMU`/`VirtualBox` artifacts) and exits early (low detonation rate) | High | High | Stage **pilot** first to measure actual detonation rate; add isolated `INetSim` VM responder; classify failed detonations explicitly (`detonation_exit_status`) & analyze root cause rather than mislabeling. |
| Attribution errors (system side effects mislabeled `attacker_induced`, or malware child missed) | Medium | High | Sysmon + ETW process-tree attribution + multi-control idle index + explicit `ambiguous_unattributed` quarantine + blinded multi-reviewer adjudication. |
| Packer/compiler stub leakage across malware families (`UPX`, shared builder) | Medium | High | Cluster samples by `ssdeep`/TLSH/imphash *in addition to* family before assigning dev vs blind-test folds. |
| Benign software/noise remains overly synthetic -> over-optimistic PR-AUC | Medium | High | Diverse genuine benign apps/installers, unsigned benign scripts/PEs, benign services/tasks/registry edits, and realistic low-prevalence host test slice (`IMP-06`). |
| Compute / disk bottleneck from 100+ runs × offline overlay inspection × nested 5-seed CV | Medium | Medium | Measure exact runtime/disk in pilot first; enforce `min_free_disk_gb` guard; clean up each overlay immediately after schema-validated JSON extraction. |

---

## 13. Ordered Task List (No Dates)

1. **Resolve and confirm [`OPERATOR_DECISIONS.md`](OPERATOR_DECISIONS.md) (§14 defaults)** and obtain explicit written/recorded operator approval on malware sample sourcing and the **Gate 0 Safety Protocol (§7)**.
2. **Phase 1 — Hardening & Infrastructure Upgrades (Code + VM):**
   - Lock `virbr1` `iptables`/`nftables`, strip SPICE clipboard/shared/USB channels, deploy `INetSim` on a separate isolated Linux VM, and verify containment via negative egress test.
   - Install Sysmon + ETW baseline inside a clean v2 VM base image and lock `0444` + SHA-256 baseline.
   - Implement user-space unprivileged-container offline overlay extractor (`IMP-02`, `IMP-16`), schema-v2 provenance + `FORBIDDEN_MODEL_INPUTS` (`IMP-07`), process-tree diff labeler + `ambiguous_unattributed` + blinded review exporter (`IMP-03`, `IMP-04`), diverse benign noise generator (`IMP-06`), and v2 ML training/stats fixes (`IMP-08`–`IMP-15`).
3. **Phase 2 — Pilot Run & Yield Measurement:**
   - Run `~3` clean control boots + `6–8` non-test pilot families × `1–2` runs (`executed` + `dormant`).
   - Measure yield (`positives/run`, detonation rate, ambiguous rate, benign diversity/quantization check) and lock Stage B family (`>= 25–30` total, `>= 10–15` blind test) & run targets + prevalence.
4. **Phase 3 — Full Data Collection, Labeling & Blind-Test Freeze:**
   - Execute dev and blind-test collection batches with pre/post base-image hash checks.
   - Run Sysmon/ETW + offline snapshot labeler; run blinded independent human review; adjudicate `label_corrections_v2.csv`.
   - Group by family + fuzzy-hash cluster + benign session; generate and **cryptographically freeze** `v2_blind_test_manifest.json` (`blind_test_sha256`).
5. **Phase 4 — Dev Modeling, Nested CV, Learning Curves & Pre-Registration Lock:**
   - On `dev` only: run nested family-grouped CV with equal `30`-trial budgets, `K = 5` multi-seed MLP learning curves, dev ablations, and dev-calibrated operating thresholds.
   - Fill all `[TBD]` placeholders in `docs/v2/FINAL_EVAL_PLAN_v2_SKELETON.md` -> commit final `docs/v2/FINAL_EVAL_PLAN_v2.md` **before** running `--final`.
6. **Phase 5 — One-Shot Blind `--final`, Explainability & v2 Report:**
   - Execute `--final` **once** under `final_eval_audit_v2.jsonl` across `full_20` & `no_content` (and optional `v2_extended`), reporting `executed` and `dormant` strata, Holm-Bonferroni dual-config verdicts, dev-calibrated thresholds, SHAP ranks/normalized shares, and error analysis.

---

## 14. OPEN QUESTIONS & Recorded Onboarding Defaults *(All Items Pending Mokh's Confirmation)*

Full decision records and sign-off checkboxes live in [`docs/v2/OPERATOR_DECISIONS.md`](OPERATOR_DECISIONS.md):

1. **Malware Sample Sourcing & Approvals (`OD-V2-07` — `pending Mokh's confirmation`):** Authorized academic/research feed (e.g., MalwareBazaar / institutional collection) under recorded institutional/ethics approval, encrypted non-executable vault (`0700`/`0400`) + SHA-256 preflight; zero acquisition until Gate 0 written sign-off.
2. **Number & Choice of Malware Families (`OD-V2-01`, `OD-V2-08` — `pending Mokh's confirmation`):** Target **`>= 25–30` total distinct families** and **`>= 10–15` distinct families in the blind test** (pilot decides feasibility; ~300–500 total positives across 100+ runs anchor), spanning Ransomware, InfoStealer, Loader/Dropper, RAT/Backdoor, Coinminer, and Trojanized Installer, with AVClass2/ClarAVy family normalization + `ssdeep`/TLSH/imphash clustering.
3. **Stratum Mix & v1 Data Reuse (`OD-V2-02`, `OD-V2-09` — `pending Mokh's confirmation`):** Reuse frozen v1 (`dataset_v1.parquet`) strictly as a third **`"emulated"` training-pool stratum (`dev` only)**, with the v2 blind test **100% new** and reuse explicitly disclosed; split new real-malware runs across `executed` (~60–70%) and `dormant` (~30–40%).
4. **Pilot Size (`OD-V2-05` — `pending Mokh's confirmation`):** **`~3` clean control boots + `6–8` distinct non-test malware families × `1–2` runs** (`executed` + `dormant`).
5. **Fake-Internet Responder Architecture (`OD-V2-03` — `pending Mokh's confirmation`):** **`INetSim` on a separate isolated Linux VM** (`inetsim-vm`) connected solely to `win11-isolated` (never on host OS, never in-guest FakeNet-NG).
6. **Offline Overlay Parser Stack (`OD-V2-04` — `pending Mokh's confirmation`):** **User-space offline parsing inside an unprivileged container** (`--network=none --read-only --cap-drop=ALL`, pure user-space QCOW2/NTFS/registry/EVTX/Amcache/Prefetch parsers); **never host-kernel mounts** of infected disk images.
7. **Independent Human Label Review Ownership (`OD-V2-10` — `pending Mokh's confirmation`):** Mokh as primary blinded reviewer + a second independent reviewer scoring a stratified **`20%` overlap slice** for inter-rater Cohen's $\kappa$, requiring `reviewer_id`, `reviewed_at_utc`, and per-row rationale notes.
8. **Feature Schema Scope (`OD-V2-11` — `pending Mokh's confirmation`):** Evaluate locked v1 schemas **`full_20` (20) and `no_content` (18)** as primary dual-configuration benchmark; isolate any additive PE/Sysmon/Amcache features under a separate `v2_extended` evaluation block.
9. **Benign Software Roster & Target Test Prevalence (`OD-V2-12` — `pending Mokh's confirmation`):** Varied real software (Git, Python, 7-Zip, Notepad++, Sysinternals, varied procedural scripts), benign services, varied-trigger tasks, benign registry edits, and legitimate unsigned PEs across disjoint dev/test host profiles; evaluate blind test at full realistic host-snapshot prevalence alongside hard-negative diagnostic slices.
10. **Compute Budget for Multi-Seed & Nested CV (`OD-V2-06` — `pending Mokh's confirmation`):** **`K = 5` seeds** (`[42, 43, 44, 45, 46]`) for multi-seed `--final` and learning curves, with **`30` equal trials per tuned model arm** in nested dev CV.
