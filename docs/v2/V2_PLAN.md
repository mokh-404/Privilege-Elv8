# DFIR-Triage ML — Phase v2 Plan

**Status:** **PHASE 1 PREP — `OD-V2-01..06, 08, 09, 11..15` CONFIRMED (`2026-11-23`); `OD-V2-10` CHANGED & CONFIRMED (`2026-11-23`); `OD-V2-07` DESIGN CONFIRMED — WRITTEN PROFESSOR/UNIVERSITY APPROVAL & GATE 0 SIGN-OFF REMAIN PENDING. DO NOT ACQUIRE MALWARE OR START VM RUNS.**  
**Single Source of Truth:** This file (`docs/v2/V2_PLAN.md`) together with [`docs/v2/OPERATOR_DECISIONS.md`](OPERATOR_DECISIONS.md) is the single source of truth for Phase v2 policy, safety, strata, and evaluation design. [`v2/plan.md`](../../v2/plan.md) tracks Phase 1 implementation steps only.  
**v1 Separation:** Phase v1 (`dataset_v1.parquet`, `docs/FINAL_EVAL_PLAN.md`, `results/`) is permanently frozen and unmodified. All v2 specifications live under `docs/v2/`.  
**Related Docs:** [`docs/v2/OPERATOR_DECISIONS.md`](OPERATOR_DECISIONS.md) | [`v2/plan.md`](../../v2/plan.md) | [`docs/IMPROVEMENT_ANALYSIS.md`](../IMPROVEMENT_ANALYSIS.md) | [`docs/v2/FINAL_EVAL_PLAN_v2_SKELETON.md`](FINAL_EVAL_PLAN_v2_SKELETON.md) | [`COMPLETE_REPORT.md`](../../COMPLETE_REPORT.md)

---

## 1. Objectives

Phase v2 addresses the structural sample-size, realism, and generalization gaps identified in v1:
1. **(a) Real Malware Artifacts (Executed & Dormant):** Evaluate host-artifact triage against real malware samples (detonated inside hardened isolated VMs and staged dormant on disk as separate strata), rather than only synthetic ATT&CK emulation scripts (`OD-V2-09`, confirmed by Mokh `2026-11-23`). Prefer malware families that run meaningfully without live C2 and leave persistence artifacts (`OD-V2-08`, confirmed by Mokh `2026-11-23`).
2. **(b) Substantially Larger Family Coverage, Sample Size & MLP Learning Curves:** Target **`>= 25–30` total distinct malware families with `>= 10–15` distinct families in the blind test** — Stage A pilot decides what is feasible (`OD-V2-01`, confirmed by Mokh `2026-11-23`) — paired with a pilot-calibrated run/positive volume (rough anchor: `~300–500` positives across `100+` VM runs) large enough to evaluate MLP alongside RF, XGBoost, LR, AE, and IF via statistically stable learning curves and nested dev CV.
3. **(c) Fresh, Strictly Blind Hash-Frozen Test Set:** Partition and cryptographically seal a 100%-new blind v2 holdout split (holding out whole malware families, near-duplicate clusters, and isolated benign hosts/sessions — zero v1 rows/keys/techniques) **before** any developer EDA, feature debugging, or model tuning occurs (`OD-V2-02`, confirmed by Mokh `2026-11-23`). Evaluate natural (full-host snapshot) prevalence as the main view and a subsampled prevalence view as secondary, with weights disclosed (`OD-V2-12`, confirmed by Mokh `2026-11-23`).
4. **(d) Full Training, Statistical & Secondary Analytical Integrity:** Enforce equal tuning budgets (`N_trials = 30`, with `20`-trial fallback if pilot compute is too heavy; `OD-V2-06`), multi-seed evaluation (`K = 5` seeds), nested family-grouped CV, strict train-only preprocessing and early stopping, dev-calibrated deployable thresholds, Holm-Bonferroni adjustment on two-sided paired family-clustered bootstrap p-values, plus secondary pre-registered `v2_refgraph` (`OD-V2-13`), tail-risk/effort (`OD-V2-14`), and formal **Cross-Stratum Execution Delta (`executed` vs `dormant` on `sample_sha256`-paired binaries; `OD-V2-15`)** analyses ($\Delta_{\text{exec}}$, sample-level first-detection rank delta $\Delta_{\text{first\_hit}}$, Intrusion-Detection Recall@k, and the Byte/Signature Evasion Resilience Hypothesis).

---

## 2. What Is Reused vs. Changed from v1

| Component | v1 Reference | Disposition in v2 | Planned Change |
| :--- | :--- | :--- | :--- |
| Frozen v1 dataset (`dataset_v1.parquet`) | `data/processed/dataset_v1.parquet` (`1,549` rows, `103` pos) | **Reuse as `dev`-only `"emulated"` stratum** (`OD-V2-02`, confirmed `2026-11-23`) | Kept strictly inside the training pool (`dev` only) as a third `"emulated"` stratum; v2 blind test is **100% new**, and reuse is explicitly disclosed. |
| Layering principle & 15 deterministic rules | `src/rules/deterministic_rules.py` | **Reuse + fix export gap** | Persist `task_name`, `service_name`, `start_mode`, `task_triggers`, and `account_is_admin`/`account_enabled` (`IMP-13`); keep rules separate from ML (`RULE_FEATURES` barred from `X`). |
| Locked 20-feature schema (`full_20`) & `no_content` (18) | `src/config.py`, `src/data/features.py` | **Reuse as primary baseline schema** (`OD-V2-11`, confirmed `2026-11-23`) | Keep `full_20` and `no_content` identical for direct v1-vs-v2 comparability; add a separate pre-registered secondary **`v2_refgraph`** arm (`OD-V2-13`) strictly outside `full_20`/`no_content` and the winner rule. |
| Strict `FORBIDDEN_MODEL_INPUTS` guard & FE-08 | `src/models/preprocess.py`, `src/data/sanitize.py` | **Reuse + extend** | Add all 15 v2 provenance/stratum/pairing metadata columns (`IMP-07`, incl. `pair_group_id`) and 3 raw edge columns (`ref_targets`, `ref_type`, `linked_artifact_keys`) to `FORBIDDEN_MODEL_INPUTS`; retain FE-08 anti-leakage scanning. |
| 6 ML model interfaces + baselines | `src/models/*.py`, `src/eval/run_track_a.py` | **Reuse + fix bugs & budgets** (`OD-V2-06`, confirmed `2026-11-23`) | Add v2 paths fixing `iforest` 100%-dev fit, inner-only `ae` early stopping, `K = 5` multi-seed `--final` (`IMP-08`), `30` equal trials (`20`-trial fallback) + nested CV (`IMP-09`), and 10k-perm MC `random` baseline (`IMP-11`). |
| Hypervisor CoW overlay + UEFI/TPM base image | `lab_automation/run_one.py`, `docs/WINDOWS_11_LAB_SETUP.md` | **Harden heavily before reuse** (`OD-V2-03`, confirmed `2026-11-23`) | Lock `virbr1` `iptables` (default-DROP), strip SPICE clipboard/shared folders/USB, run `INetSim` on a **separate isolated Linux VM**, add hard kill timer + SHA-256 vault check (`IMP-01`, `IMP-02`). |
| Live SSH + `scp -r` `Collect-Artifacts.ps1` | `collector/Collect-Artifacts.ps1`, `lab_automation/guest_runner.py` | **Replace for `executed` runs** (`OD-V2-04`, confirmed `2026-11-23`) | Stop live overlay -> parse registry hives, `Amcache.hve`, Prefetch, filesystem, and Sysmon EVTX via **user-space offline parsing in an unprivileged container (never host-kernel mounts)** (`IMP-02`, `IMP-16`). |
| `expected_artifact_keys`-only labeler & review export | `src/data/labeler.py` | **Replace / upgrade** (`OD-V2-10`, changed & confirmed `2026-11-23`) | Replace with Sysmon/ETW process-tree causal attribution + multi-control & pre/post diff + `ambiguous_unattributed` + blinded multi-reviewer export (Mokh's friend primary reviewer; Mokh scores 20% overlap for Cohen's $\kappa$). |
| `benign_noise.ps1` | `lab_automation/benign_noise.ps1` | **Replace / expand** (`OD-V2-12`, confirmed `2026-11-23`) | Eliminate 6-template script quantization (`IMP-06`); generate varied real software, unsigned dev binaries, benign services, registry edits, and scheduled tasks. |
| Track B (`CIC-MalMem-2022`) | `src/eval/run_track_b.py` | **Retain as archived v1 appendix** | Do not expand; keep optional cluster-exchangeability diagnostic proposal separate (`IMP-12`). |

---

## 3. Evaluation Strata & Secondary Configs (Reported Separately & Pooled With Weights Disclosed)

Every positive sample and run belongs to exactly one declared stratum (never mixed silently in headline numbers; `OD-V2-02`, `OD-V2-09`, confirmed `2026-11-23`), with **paired `sample_sha256` sampling** linking `dormant` and `executed` runs:
1. **`executed` Stratum (~60–70% of real-malware runs, Primary Dynamic Stratum):** Live malware binaries injected at a realistic initial staging path and detonated in hardened Win11 overlays with the separate isolated `INetSim` VM and Sysmon/ETW recording. Captures active persistence, execution, service/task creation, WMI, registry modifications, child processes, Prefetch, and dropped payloads.
2. **`dormant` Stratum (~30–40% of real-malware runs, Static-Only On-Disk Stratum):** The **exact same `sample_sha256` binaries** selected for cross-stratum evaluation (linked via forbidden `pair_group_id`) staged on disk at the **matching initial staging path** *without* executing them (paired with realistic host baseline/benign drift). Explicitly tests whether host-artifact triage detects quiescent/unexecuted binaries using path, name, file size/entropy (`full_20` vs `no_content`), signature state, and attributes when no command-line/process/persistence artifacts exist. **Anti-Leakage Rule:** Paired `dormant` and `executed` runs of any `sample_sha256` (and its entire `sample_family` + `ssdeep`/TLSH cluster) MUST reside in the exact same split pool (`dev` OR `blind_test`, never split across them).
3. **`emulated` Stratum (`dev` / training pool ONLY, `OD-V2-02`):** Reuse frozen v1 (`dataset_v1.parquet`) strictly as a third training-pool stratum (`dev` only) serving as a continuity bridge back to v1. Zero v1 rows, keys, or simulated techniques enter the v2 blind test (which is **100% new**), and v1 reuse is explicitly disclosed in every v2 table and report.

All v2 primary tables report `(a) executed`, `(b) dormant`, `(c) emulated` (`dev`/training disclosure only), and combined real-malware metrics separately across `full_20` and `no_content`, with **natural (full-host snapshot) prevalence as the main view** and a **subsampled prevalence view as secondary** (weights disclosed; `OD-V2-12`).

### Secondary Pre-Registered Analytical Arms (`OD-V2-13`, `OD-V2-14`, `OD-V2-15`, confirmed `2026-11-23`)
1. **`v2_refgraph` Referential-Graph Arm (`OD-V2-13`):** Secondary pre-registered config built **ONLY** from static cross-references inside the artifacts themselves (`ref_targets`, `ref_type`, `linked_artifact_keys` — e.g., Run key value -> image path, service `ImagePath` -> binary, scheduled task action -> script/binary, Prefetch referenced files). Links must **NOT** use labeling provenance, process trees, Sysmon, or timestamps (preventing label leakage). Never part of `full_20`/`no_content` or the primary winner rule.
2. **Tail-Risk & Analyst-Effort Metrics (`OD-V2-14`):** Secondary metrics measuring rank of the worst-ranked positive (`worst_positive_rank` + percentile), recall at review budgets (`k = 10/20/50/100`), positives in the bottom 50% and bottom 90% of scores, and artifacts reviewed to reach 50%/80%/90% recall (`effort@recall`). Includes the documented random tail-audit sample-size upper bound $1 - 0.05^{1/n}$ ($n=5 \to 45\%$, $n=59 \to 5\%$, $n=300 \to 1\%$); any live tail audit is **future work only**.
3. **Cross-Stratum Execution Delta (`executed` vs `dormant`, `OD-V2-15`):** On paired `sample_sha256` binaries ($s \in \mathcal{S}_{\text{paired}}$, linked by forbidden provenance column `pair_group_id`), pre-register a dedicated secondary analysis quantifying how detonation transforms triage detectability:
   - **Stratum-Conditional PR-AUC & Recall@k Delta ($\Delta_{\text{exec}}$):** $\Delta_{\text{exec}}(M, C) = \text{Metric}(M, C \mid \text{executed}) - \text{Metric}(M, C \mid \text{dormant})$ evaluated across $C \in \{\text{full\_20}, \text{no\_content}, \text{drop\_signature}, \text{no\_content\_no\_sig}\}$ (plus secondary `v2_refgraph`) with family-clustered paired bootstrap 95% CIs resampling whole families/clusters so paired runs stay together.
   - **Sample-Level First-Detection Rank / Effort Delta ($\Delta_{\text{first\_hit}}$):** Because `executed` runs emit multiple host artifacts while `dormant` runs contain a single binary row (differing in positive prevalence), define $\text{Rank}_{\min}(s, \text{stratum})$ as the rank (and normalized percentile effort) of the **highest-scored `attacker_induced` artifact** produced by binary $s$ inside its host run; report median and IQR of $\text{Rank}_{\min}(s, \text{dormant}) - \text{Rank}_{\min}(s, \text{executed})$ and **Intrusion-Detection Recall@k** ($k \in \{5, 10, 20, 50\}$).
   - **Byte/Signature Evasion Resilience Hypothesis:** Pre-register the secondary contrast testing whether stripping byte/signature features triggers severe ranking collapse in `dormant` staging ($\Delta_{\text{ablation, dormant}}$) whereas post-detonation OS execution artifacts preserve ranking ($|\Delta_{\text{ablation, executed}}| < |\Delta_{\text{ablation, dormant}}|$, via family-clustered paired bootstrap CI).

---

## 4. Pilot-First Data Collection Plan (No Hard Quotas Until Pilot Completes)

Rather than guessing final batch counts before measuring real sample yield, v2 uses a **two-stage pilot-first design**:

1. **Stage A — Small Safety & Yield Pilot (Strict Dev-Only Pilot Families, `OD-V2-05`, confirmed `2026-11-23`):**
   - Execute a small, operator-approved pilot batch covering **`~3` clean control boots** + **`6–8` distinct non-test malware families × paired `dormant` and `executed` runs per `sample_sha256` (`pair_group_id`, matching initial staging path)** with expanded benign noise schedules. *(Pilot families and `sample_sha256` pairs stay strictly in a non-test dev/calibration bucket and never enter the blind test pool.)*
   - Measure empirically from pilot logs:
     - Clean detonation rate (fraction of `executed` samples producing observable host changes within `T_detonate` vs sandbox-evading/crashed/missing-DLL duds)
     - Mean & median **verified `attacker_induced` rows per successful run** (separately for `executed` and `dormant`)
     - Ambiguous / quarantined row rate (`ambiguous_unattributed` %)
     - Mean `benign_drift` rows per run & content-feature entropy/size diversity (verify zero template quantization)
     - End-to-end per-run wall time, overlay size, compute cost for `30` vs `20` trials (`OD-V2-06`), and offline parser reliability.
2. **Stage B — Full Target Calibration (Informed by Pilot Measurements, `OD-V2-01`, confirmed `2026-11-23`):**
   - Use measured pilot yield `(positives_per_run, detonation_success_rate, benign_per_run)` to set exact dev and blind-test run quotas via:
     $$\text{Target Runs} = \left\lceil \frac{\text{Target Positives}}{\text{Yield per Run} \times \text{Success Rate}} \right\rceil$$
   - **Confirmed Family Targets & Volume Anchor (Pilot Decides Final Feasibility):** **`>= 25–30` total distinct malware families**, with **`>= 10–15` distinct families in the blind test**, alongside a rough starting volume anchor of **`~300–500` total positives across `100+` VM runs**. Exact dev vs. blind-test counts are locked after pilot yield calibration and prior to blind-test freeze.

---

## 5. MLP Learning-Curve & Capacity Plan

Because v1 had only `70` dev positives (`1,179` rows) where MLP jumped steeply from `0.1388` (25%) -> `0.2630` (50%) -> `0.7677` (100% test, vs `0.2496` dev CV) with `0.0600` seed std:
1. **Family-Grouped Training-Size Sweep (Dev Nested CV & Frozen Blind Evaluation):**
   - Subsample dev **by whole malware family & benign session groups** (never random rows, fixing v1 `_grouped_subsample_dev` benign row-level sampling) across `[e.g., 10%, 25%, 50%, 75%, 100%]` of dev families.
   - Evaluate ALL 6 ML arms (`rf`, `xgb`, `lr`, `mlp`, `ae`, `iforest`) at each fraction across **`K = 5` seeds (`[42, 43, 44, 45, 46]`, `OD-V2-06`, confirmed `2026-11-23`)**, plotting mean ± 1 SD and min/max bands.
2. **MLP Stabilization & Capacity Diagnostics:**
   - Expand MLP search space slightly while preserving equal tuning trial budget (`N_trials = 30`, fallback `20`, `IMP-09`): layer widths, dropout, `weight_decay`, `lr`, BatchNorm vs LayerNorm (reduces sensitivity to positive-rare minibatches), and calibrated `pos_weight` (`[1, sqrt(n_neg/n_pos), n_neg/n_pos]`).
   - Compare single-seed MLP vs K-seed bagged MLP ensemble so variance reduction is quantified explicitly.

---

## 6. Training, Tuning & Evaluation Integrity Protocol

Non-negotiable training rules enforced in v2 pipeline tests:
1. **Strict Split-Local Preprocessing:** `SharedPreprocessor` (imputers, scalers, one-hot encoders) and any v2 transformers fit **exclusively inside each CV training fold** (and benign-only training rows for `ae` and `iforest`). No feature selection (`drop_*`, frequency filtering) occurs outside folds.
2. **Equal Tuning Budgets (`OD-V2-06`, confirmed `2026-11-23`):** Every tuned model family receives an identical trial budget **`N_trials = 30` (with an authorized fallback to `20` trials if Stage A pilot compute is too heavy)** using the exact same inner family-grouped splits and seed schedule. No post-hoc `--best-params` reuse across different feature subsets (`IMP-14`). `ae`/`iforest` hyperparameter selection uses label-free benign OOF criteria by default unless explicitly tagged `"label-selected"`.
3. **Nested Family-Grouped Dev CV:** Outer CV folds hold out whole malware families + benign sessions to produce an **unbiased** dev generalization estimate and per-family leave-one-family-out (LOFO) table; inner CV selects hyperparameters; a strictly separate **inner validation slice** handles `mlp`/`ae` early stopping (`IMP-08`).
4. **Full Dev Refit & Multi-Seed `--final` (`OD-V2-06`, confirmed `2026-11-23`):** Models without early stopping (`rf`, `xgb`, `lr`, **`iforest`**) train on `100%` of eligible dev data; `mlp`/`ae` run across **`K = 5` seeds** via documented median-epoch full-dev refit or fold ensembling, reporting per-seed mean/std alongside the 5-seed ensemble.
5. **Dev-Calibrated Deployable Operating Thresholds:** Precision/FPR operating points (e.g., target val FPR `1%` or fixed alert budget) are frozen from dev nested OOF predictions **before** unblinding test (`IMP-10`), eliminating test-selected threshold bias.

---

## 7. Malware Safety Protocol (Gate 0 — Required Before Any Sample Acquisition or Execution)

> [!CAUTION]
> **Hard Safety Gate (`OD-V2-07` — Written Approval & Gate 0 Sign-Off PENDING):** Design confirmed `2026-11-23`, **but written professor/university approval and Gate 0 sign-off remain PENDING**. No malware binary may be acquired, stored, transferred, or booted until every item below is verified by automated preflight checks AND explicitly signed off by the operator.

1. **Sample Storage & Access Hygiene (Host Side):**
   - Encrypted, non-executable quarantine vault outside the repo (`chmod 0700` dir, `0400` AES-256 encrypted zip or isolated loopback volume, NEVER committed to git and excluded from host indexing/antivirus auto-quarantine confusion).
   - Mandatory SHA-256 manifest verification (`sample_sha256`, source provenance ID, family label, execution mode) immediately prior to each VM injection.
2. **Host-Guest Containment & Network Isolation (`OD-V2-03`, confirmed `2026-11-23`):**
   - Dedicated libvirt network `win11-isolated` (`no <forward> element`) with **hardened default-DROP `iptables`/`nftables`** rules (`IMP-01`): block ALL guest-to-host (`INPUT`) services and block all cross-bridge `FORWARD` traffic.
   - Strip SPICE clipboard sharing (`copypaste='no'`), vdagent/file-transfer channels, shared folders, host USB passthrough, and host-accessible network shares (`qemu` guest-agent file-copy disabled except bounded single-file injection prior to execution, or read-only ISO/disk injection).
   - Dedicated isolated **fake-internet responder (`INetSim` on a separate isolated Linux VM `inetsim-vm` attached to `win11-isolated`)** so DNS/HTTP/HTTPS queries resolve inside the sandbox without touching the host OS or any real network.
3. **Immutable Base & Guaranteed Cleanup:**
   - Base disk `win11_base.qcow2` (`chmod 0444`) and `win11_VARS.fd.base` remain read-only; automated SHA-256 hash recorded **before** and verified **after** each batch.
   - Every run boots from a fresh disposable `win11_overlay.qcow2` + fresh NVRAM copy.
   - External host-side hard watchdog enforces `run_wall_clock_max_seconds` via `virsh destroy`.
4. **Offline Read-Only Artifact Extraction (`IMP-02`, `OD-V2-04`, confirmed `2026-11-23`):**
   - Do **not** run `Collect-Artifacts.ps1` or `scp -r` from inside a live malware-infected guest.
   - After `virsh destroy`, parse `win11_overlay.qcow2` via **user-space offline parsing inside an unprivileged container (`--network=none`, `--read-only`, `--cap-drop=ALL`, `--security-opt=no-new-privileges`)** using pure user-space QCOW2/NTFS/registry/EVTX/Amcache/Prefetch parsers (`dissect`/`regipy`/`evtx`/`libscca`) — **NEVER perform host-kernel mounts (`mount` or kernel `qemu-nbd` block mounts) of infected images**. Extract only schema-validated structured records and first-1 MiB byte histograms (never copying executable payloads onto the host filesystem workspace), then securely unlink `win11_overlay.qcow2`.
5. **Incident / Abort Criteria:** Immediate `virsh destroy` + batch halt if any unexpected packet leaves `virbr1`, base image mtime/hash changes, host CPU/disk guard triggers, or overlay cleanup fails.

---

## 8. v2 Labeling & Independent Human Review Method

1. **Extended Telemetry:** Add **Sysmon + ETW** process/file/registry/task/WMI/network logging inside the clean base image (capturing `ProcessGuid`, `ParentProcessGuid`, `Hashes`, `CommandLine`, target keys/files) alongside offline registry hive + `Amcache.hve` + Prefetch extraction.
2. **Three-Tier Labeling Pipeline:**
   - **`executed` runs:** (a) Match against expanded multi-control boot baseline index -> unchanged = `baseline`; (b) trace Sysmon/ETW descendant trees from the injected malware PID/`ProcessGuid` -> matched changes = `attacker_induced` (`attribution_method = "process_tree_etw"`); (c) trace descendant trees from synthetic benign scheduler PIDs -> `benign_drift`; (d) compare remaining OS background diffs against a clean-window idle catalog (`[TBD: >= 5-10` varied control boots across uptime lengths); any unverified residual artifact is quarantined to **`ambiguous_unattributed`** (never silently coerced to benign negative).
   - **`dormant` runs:** Label directly from deterministic pre-registered staging manifest `(staged_path, sample_sha256)` + pre/post offline disk diff, verified negative for any execution trace.
3. **Genuinely Independent Human Review (`IMP-04`, `OD-V2-10`, CHANGED & confirmed `2026-11-23`):**
   - Freeze automated labels cleanly, then export a **blinded** stratified review sample (hiding `label`, `label_reason`, `sample_family`, and `launcher`, displaying artifact fields + process-tree parent chain + control-boot frequency).
   - **Mokh's friend acts as the primary blinded reviewer, and Mokh scores the stratified `20%` overlap slice for inter-rater Cohen's $\kappa$** (because Mokh authored the v2 labeler and is not independent).
   - Reviewers record `reviewer_id`, `reviewed_at_utc`, `human_label`, and per-row forensic rationale notes before merging adjudicated corrections via `label_corrections_v2.csv`.

---

## 9. Blind-Test Freeze Procedure

1. **Disjoint Unit of Assignment & Paired Binary Integrity:** Group all positives by **`sample_family`**, **`ssdeep`/TLSH near-duplicate cluster**, **`sample_sha256`**, and **`pair_group_id`** so no related binary or variant ever straddles dev and blind test, and so paired `(sample_sha256, execution_state)` runs (`dormant` + `executed`) ALWAYS stay together in the same split pool (`dev` OR `blind_test`, never split across them). Assign benign runs from **separate VM sessions / benign software profiles** into the blind-test pool so zero `artifact_key`, `run_id`, or `benign_noise` template matches occur across pools.
2. **Holdout Sealing Before Modeling:** Immediately after dataset assembly & blind human review adjudication (zero feature exploration, zero CV runs, zero model code execution on test rows):
   - Write split assignments into `data/splits/v2_blind_test_manifest.json` containing **`blind_test_sha256`** (canonical SHA-256 over sorted test artifact keys, run IDs, labels, strata, `pair_group_id`, and all `FEATURES` + `FEATURES_V2`), holdout family list (hashed or stored in a restricted blind-split manifest), row counts per stratum, and git commit hash.
   - Move/store raw blind-test run artifacts in a sealed read-only path until `--final`, exposing only `split_pool == "dev"` to model development scripts until the pre-registered v2 evaluation plan is locked and committed.
3. **One-Shot Execution Guard:** Enforce `results/logs/final_eval_audit_v2.jsonl` checking `blind_test_sha256` and refusing duplicate `--final` runs without `--force`.

---

## 10. Pre-Registered Winner Rule (Carried Over & Hardened from v1)

Preserving v1's core dual-configuration philosophy:
- Evaluate every arm in both **`full_20`** and **`no_content`**. Secondary **`v2_refgraph`** (`OD-V2-13`) and optional `v2_extended` are reported strictly in their own separate blocks and **never** enter the `full_20`/`no_content` primary winner rule.
- Report per-stratum (`executed`, `dormant`, and dev-only `emulated` disclosure) and overall real-malware PR-AUC with family-clustered & run-clustered bootstrap 95% CIs under natural prevalence (main) and subsampled prevalence (secondary, weights disclosed).
- **Dual-Config Winner Rule:** Compute **two-sided paired family-clustered bootstrap p-values (`p_raw`)** across the fixed pre-registered comparison set (without post-hoc `best_ml` selection) and apply **Holm-Bonferroni step-down adjustment to `p_raw`** (`p_adj < 0.05`) within each primary slice — **adjusting p-values, NOT percentile confidence intervals**. Declare $A$ better than $B$ (`a_better` or `b_better`) **only if Holm-adjusted `p_adj < 0.05` in the same direction in BOTH `full_20` and `no_content`**; otherwise declare `"not distinguishable"` or `"configuration-dependent"`.
- **Cross-Stratum Execution Delta & Evasion Resilience Contrast (`OD-V2-15`, Secondary Pre-Registered):** Strictly outside the primary winner rule, report paired `sample_sha256` execution deltas ($\Delta_{\text{exec}}$ across `full_20`, `no_content`, `drop_signature`, `no_content_no_sig`, plus `Rank_min` / $\Delta_{\text{first\_hit}}$ and Intrusion-Detection Recall@k) and evaluate $|\Delta_{\text{ablation, executed}}| < |\Delta_{\text{ablation, dormant}}|$ using family-clustered paired bootstrap 95% CIs (resampling whole families/clusters so paired `dormant` and `executed` runs move together) and two-sided paired family-clustered bootstrap p-values.

---

## 11. Success Criteria & Limitations to State Plainly

### Success Criteria (Qualitative / Threshold-Relative — Specific `[TBD]` Targets After Pilot)
1. Zero containment incidents; 100% pre/post `base_image` SHA-256 verification and `100%` overlay cleanup.
2. Verified blind-test isolation (`0` family, fuzzy-hash cluster, `sample_sha256`, `pair_group_id`, benign `artifact_key`, and benign-run overlap; zero v1 rows in blind test) sealed by `blind_test_sha256` before dev modeling.
3. Unbiased nested dev CV + multi-seed (`K = 5` seeds) MLP learning curve clearly resolving v1's under-powered MLP variance (`std = 0.0600` on v1 `full_20`), alongside equal `30`-trial tuning budgets (`20`-trial fallback if compute heavy) across all 6 models.
4. Dev-calibrated deployable thresholds evaluated **once** on blind test (separately for `executed` and `dormant`, natural prevalence main + subsampled secondary), paired with Holm-adjusted dual-config verdicts (`full_20` + `no_content`), rule/hybrid comparisons, and secondary `v2_refgraph`, tail-risk/effort (`OD-V2-14`), and Cross-Stratum Execution Delta (`OD-V2-15`) analyses.
5. Plain elimination of v1 script template quantization (`benign_noise` diversity > v1's `18/221` unique script sizes) and missing benign `service`/`registry` coverage.

### Limitations to State Plainly in v2 Paper / Report
- Sandbox detonation window (`run_duration_s`) cannot observe long-dormant logic bombs or C2 payloads requiring real live external infrastructure beyond the isolated `INetSim` VM.
- VM-based artifacts capture fresh/moderate host state rather than multi-year enterprise endpoint telemetry.
- Dormant-file performance under `no_content` intentionally excludes file bytes/size/entropy and reflects metadata/path/signature visibility limits.
- Real malware sample bias reflects the chosen repository/feeds and dates (including preference for non-C2-dependent persistence families); v1 `emulated` reuse inside the training pool (`dev` only) is explicitly disclosed. Any live/random tail audit remains **future work only**.

---

## 12. Risk Register

| Risk | Likelihood | Impact | Mitigation |
| :--- | :---: | :---: | :--- |
| Host infection / network escape during malware run | Low | Critical | Default-DROP `virbr1` firewall, no SPICE clipboard/shares/USB, immutable `0444` base + hash verification, `INetSim` on separate isolated Linux VM, user-space unprivileged-container offline parsing (`IMP-01`, `IMP-02`). |
| Malware detects VM/sandbox (`VMware`/`QEMU`/`VirtualBox` artifacts) or stalls needing live C2 | High | High | Stage **pilot** first to measure actual detonation rate; prefer families running without live C2 and leaving persistence (`OD-V2-08`); add isolated `INetSim` VM responder; classify failed detonations explicitly (`detonation_exit_status`). |
| Attribution errors (system side effects mislabeled `attacker_induced`, or malware child missed) | Medium | High | Sysmon + ETW process-tree attribution + multi-control idle index + explicit `ambiguous_unattributed` quarantine + blinded independent review (friend primary + Mokh 20% overlap). |
| Packer/compiler stub leakage across malware families (`UPX`, shared builder) | Medium | High | Cluster samples by `ssdeep`/TLSH/imphash *in addition to* family before assigning dev vs blind-test folds. |
| Benign software/noise remains overly synthetic -> over-optimistic PR-AUC | Medium | High | Diverse genuine benign apps/installers, unsigned benign scripts/PEs, benign services/tasks/registry edits, and natural full-host test prevalence (`IMP-06`, `OD-V2-12`). |
| Compute / disk bottleneck from 100+ runs × offline overlay inspection × nested 5-seed CV | Medium | Medium | Measure exact runtime/disk in pilot first; pre-authorized fallback from `30` to `20` trials (`OD-V2-06`); enforce `min_free_disk_gb` guard; clean up each overlay immediately after extraction. |

---

## 13. Ordered Task List (No Dates)

1. **Complete Pending Gate 0 Prerequisites (`OD-V2-07`):** Obtain written professor/university approval and operator Gate 0 verification/sign-off (no malware acquisition/execution before this completes).
2. **Phase 1 — Hardening & Infrastructure Upgrades (Code + Hardening Kit):**
   - Generate hardening scripts & verification checklists (`docs/v2/hardening/`) for Mokh to apply and verify (`virbr1` default-DROP firewall, SPICE clipboard/share/USB stripping, separate `INetSim` Linux VM, watchdog + base hash checks, unprivileged container offline parser).
   - Implement schema-v2 provenance + refgraph edge columns in `FORBIDDEN_MODEL_INPUTS` (`IMP-07`, `IMP-13`, `OD-V2-13`), v2 training/stats fixes (`IMP-08`–`IMP-15`, `OD-V2-14`), synthetic-tested process-tree diff labeler + blinded friend/Mokh review exporter (`IMP-03`, `IMP-04`, `OD-V2-10`), read-only v1-dev refgraph link coverage check, and diverse benign noise generator + shortcut audit (`IMP-06`).
3. **Phase 2 — Pilot Run & Yield Measurement:**
   - Run `~3` clean control boots + `6–8` non-test pilot families × paired `dormant` and `executed` runs per `sample_sha256` (`pair_group_id`, matching initial staging path).
   - Measure yield (`positives/run`, detonation rate, ambiguous rate, benign diversity/quantization check, compute cost for 30 vs 20 trials) and lock Stage B family (`>= 25–30` total, `>= 10–15` blind test) & paired run targets + prevalence.
4. **Phase 3 — Full Data Collection, Labeling & Blind-Test Freeze:**
   - Execute dev and blind-test collection batches with pre/post base-image hash checks.
   - Run Sysmon/ETW + offline snapshot labeler; run blinded independent human review (friend primary + Mokh 20% overlap Cohen's $\kappa$); adjudicate `label_corrections_v2.csv`.
   - Group by family + fuzzy-hash cluster + `sample_sha256` / `pair_group_id` + benign session; generate and **cryptographically freeze** `v2_blind_test_manifest.json` (`blind_test_sha256`).
5. **Phase 4 — Dev Modeling, Nested CV, Learning Curves & Pre-Registration Lock:**
   - On `dev` only: run nested family-grouped CV with equal `30`-trial (`20`-trial fallback) budgets, `K = 5` multi-seed MLP learning curves, dev ablations, and dev-calibrated operating thresholds.
   - Fill all `[TBD]` placeholders in `docs/v2/FINAL_EVAL_PLAN_v2_SKELETON.md` -> commit final `docs/v2/FINAL_EVAL_PLAN_v2.md` **before** running `--final`.
6. **Phase 5 — One-Shot Blind `--final`, Explainability & v2 Report:**
   - Execute `--final` **once** under `final_eval_audit_v2.jsonl` across `full_20` & `no_content` (plus secondary `v2_refgraph`, tail-risk/effort metrics, and Cross-Stratum Execution Delta), reporting `executed` and `dormant` strata, Holm-Bonferroni p-value dual-config verdicts, dev-calibrated thresholds, SHAP ranks/normalized shares, and error analysis.

---

## 14. Recorded Operator Decisions Summary (`OD-V2-01`..`OD-V2-15`)

All 15 decision records live in [`docs/v2/OPERATOR_DECISIONS.md`](OPERATOR_DECISIONS.md):
- **`OD-V2-01..06, 08, 09, 11..15`:** **Confirmed by Mokh (`2026-11-23`)**.
- **`OD-V2-10`:** **Changed & confirmed by Mokh (`2026-11-23`)** (friend = primary blinded reviewer; Mokh scores 20% overlap for Cohen's $\kappa$).
- **`OD-V2-07`:** **Design confirmed by Mokh (`2026-11-23`); written professor/university approval & Gate 0 sign-off remain PENDING**.
