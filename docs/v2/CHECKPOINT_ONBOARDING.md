# DFIR-Triage ML v2 — Consolidated Onboarding & Pre-Pilot Checkpoint

**Snapshot Timestamp:** `2026-11-23` (Git HEAD before this docs commit: `bbdf564` on branch `main`, 26 commits past frozen v1 base `ca73589`)  
**Current Phase:** `Phase 1 Preparation & Pre-Pilot Engineering COMPLETE (314 passed) — Host Hardening & Gate 0 Execution Underway`  
**Canonical Companions:** [`OPERATOR_DECISIONS.md`](OPERATOR_DECISIONS.md) (decision records `OD-V2-01..20`), [`V2_PLAN.md`](V2_PLAN.md) (v2 architecture, containment, strata, methodology), [`v2/plan.md`](../../v2/plan.md) (Phase 1 checklist), [`FINAL_EVAL_PLAN_v2_SKELETON.md`](FINAL_EVAL_PLAN_v2_SKELETON.md) (draft pre-registration skeleton — `[TBD]` until pilot & blind freeze)

> This document is the single onboarding entry point for any new agent or operator session resuming `dfir-triage-ml` v2. Everything below reflects verified repository commits and direct disk observations as of `2026-11-23`.

---

## 1. Non-Negotiable Operational & Scientific Rules

1. **v1 Is Permanently Frozen:** NEVER modify, overwrite, or re-run `--final` on v1 artifacts (`data/processed/dataset_v1.parquet`, `data/splits/dataset_v1_manifest.json`, `results/`, `docs/FINAL_EVAL_PLAN.md`, `collector/Collect-Artifacts.ps1`). Verify integrity after every step using §2.
2. **Gate 0 Hard Block (`OD-V2-07`):** NEVER download, extract, stage, or detonate real malware samples until Mokh executes and signs off the entire Gate 0 checklist (`NEG-01`..`NEG-10`, base image hash check, quarantine vault preflight, ASUS dedicated isolated user check) in [`hardening/08_NEGATIVE_EGRESS_AND_SIGN_OFF.md`](hardening/08_NEGATIVE_EGRESS_AND_SIGN_OFF.md).
3. **Zero Host-Kernel Mounts (`OD-V2-04`):** NEVER mount any infected QCOW2 overlay in the host kernel (`mount` / `qemu-nbd`). All post-run extraction goes strictly through pure user-space `dissect` inside the hardened `--network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges` container ([`hardening/06_unprivileged_container_runner.sh`](hardening/06_unprivileged_container_runner.sh)) or the read-only Python module [`src/v2/offline_extractor.py`](../../src/v2/offline_extractor.py).
4. **Zero SSH / Zero Guest-Agent Staging:** `win11_base.qcow2` has `sshd` disabled (`Start=4`) and `virbr1` drops all host<->guest traffic. Every VM run receives its manifest and payload via a read-only ISO-9660 + Joliet/RockRidge virtual CD-ROM (`DFIR_STAGE`) read at boot by `\DFIR-StageRunner`.
5. **Strict Scope Discipline:** No v1 `--final`, no research-paper prose unless explicitly asked, and end every session summary with a list of the `.md` files changed.
6. **Human Reviewer Independence (`OD-V2-10`):** Mokh built the v2 labeler, so **Mokh's friend** is the primary blinded reviewer and Mokh scores only the `20%` overlap slice for inter-rater Cohen's $\kappa$.

---

## 2. Frozen v1 Integrity Baseline (Must Match After Every Step)

| Artifact | Required Verification Value |
| :--- | :--- |
| `data/processed/dataset_v1.parquet` SHA-256 | `39527f85fbda75f952e0cf5134a07467bf546501cb540ba68cd65b14983c7f21` |
| `data/splits/dataset_v1_manifest.json` SHA-256 | `788b6a7cab836c1851a90c5069e89496aa748c33f86643a84d9d70cc50857fbe` |
| `results/logs/runner_footprint_dropped.csv` line count | `99` (`1` header + `98` dropped runner rows) |
| `git diff --stat -- results/ data/ docs/FINAL_EVAL_PLAN.md collector/Collect-Artifacts.ps1` | *(empty — zero modifications)* |

Verification command:
```bash
.venv/bin/pytest && \
sha256sum data/processed/dataset_v1.parquet data/splits/dataset_v1_manifest.json && \
wc -l results/logs/runner_footprint_dropped.csv && \
git diff --stat -- results/ data/ docs/FINAL_EVAL_PLAN.md collector/Collect-Artifacts.ps1
```

---

## 3. Governance, Written Supervisor Approval & Confirmed Decisions (`OD-V2-01`..`OD-V2-20`)

### Written Supervisor Authorization (`OD-V2-07`, Recorded `2026-11-23`)
- **Approving Authority:** **Supervisor Marawan (AASTMT)** — written approval granted `2026-11-23` for *"Research Approval Request: Controlled Malware Analysis for DFIR Triage"*, explicitly confirming separate institutional/legal ethics review is **"Not Required — Waived by Supervisor"**.
- **Three Mandatory Conditions:**
  - `(a)` Sole governing authorization is Supervisor Marawan's written approval (`2026-11-23`).
  - `(b)` ASUS host machine has zero personal credentials, zero sensitive data, and zero production workloads, operated strictly under a dedicated isolated user account.
  - `(c)` Hard Gate 0 enforcement: zero malware acquisition, extraction, or execution until `NEG-01..10`, base hash check, vault verify, and dedicated isolated user verification are signed off by Mokh.

### Summary of All 20 Operator Decisions

| ID | Confirmed Decision | Status |
| :--- | :--- | :--- |
| `OD-V2-01` | `>= 25–30` total distinct malware families (`>= 10–15` held-out blind test); rough anchor `~300–500` positives across `100+` VM runs; pilot calibrates feasibility | **Confirmed `2026-11-23`** |
| `OD-V2-02` | Reuse frozen `dataset_v1.parquet` (`1,549` rows) strictly as `"emulated"` `dev`-only stratum (`0%` blind test). **Step F0 parity rulings:** (a) exclude `75` live `process` rows (`1,179 -> 1,104` cold-disk rows) in mixed-stratum models while keeping `dataset_v1.parquet` untouched; (b) document/align `27` locked v1 OS files; (c) keep `run_key` raw (`--no-expand-env`) in `full_20` + raw/expanded in `v2_refgraph` | **Confirmed `2026-11-23`** |
| `OD-V2-03` | `INetSim` deployed on a separate isolated Linux VM (`inetsim-vm`, `192.168.150.10`) on `win11-isolated` (`virbr1`), zero WAN forwarding | **Confirmed `2026-11-23`** |
| `OD-V2-04` | Pure user-space offline QCOW2/NTFS/registry/EVTX/Amcache/Prefetch extraction inside unprivileged container (zero host-kernel mounts) | **Confirmed `2026-11-23`** |
| `OD-V2-05` | Stage A pilot: `~3` clean control boots + `6–8` non-test families × paired `dormant` + `executed` runs per `sample_sha256` (`pair_group_id`) | **Confirmed `2026-11-23`** |
| `OD-V2-06` | `K = 5` seeds (`[42..46]`) for `--final` & learning curves; `30` equal trials/arm in nested family CV (`20`-trial fallback if pilot compute too heavy) | **Confirmed `2026-11-23`** |
| `OD-V2-07` | Encrypted non-executable vault (`0700` dir, `0400` AES-256) + SHA-256 preflight + written approval (`Supervisor Marawan, AASTMT, 2026-11-23`) | **Approval GRANTED `2026-11-23`; Gate 0 sign-off PENDING** |
| `OD-V2-08` | Balanced multi-category malware mix preferring no-live-C2 persistence families; AVClass2/ClarAVy canonical family names + `ssdeep`/TLSH/imphash deduplication | **Confirmed `2026-11-23`** |
| `OD-V2-09` | Separate & combined stratum reporting (`executed` ~60–70%, `dormant` ~30–40%, `emulated` `dev`-only); `pair_group_id` pairs never straddle `dev`/`blind_test` | **Confirmed `2026-11-23`** |
| `OD-V2-10` | Blinded review packs strip labels/family/launcher; **Mokh's friend = primary blinded reviewer**, **Mokh = 20% overlap Cohen's $\kappa$** | **CHANGED & Confirmed `2026-11-23`** |
| `OD-V2-11` | Keep locked v1 `full_20` (20) & `no_content` (18) as primary dual-config benchmark; keep all extra features/arms outside primary winner rule | **Confirmed `2026-11-23`** |
| `OD-V2-12` | Varied real benign software (Git, Python, 7-Zip, Notepad++, Sysinternals, procedural scripts, unsigned PEs, services/tasks/registry), disjoint dev/test profiles; natural prevalence = main blind view, subsampled = secondary | **Confirmed `2026-11-23`** |
| `OD-V2-13` | Secondary static-only `v2_refgraph` arm using ONLY static artifact pointers (`ref_targets`, `ref_type`, `linked_artifact_keys`); zero Sysmon/timestamps/label leakage; barred from `full_20`/`no_content` | **Confirmed `2026-11-23`** |
| `OD-V2-14` | Pre-registered secondary tail-risk (`worst_positive_rank`, `bottom 50%/90%`, recall@`k={10,20,50,100}`) & `effort@recall` (`50%/80%/90%`) + $1-0.05^{1/n}$ audit calculator (tail audit = future work only) | **Confirmed `2026-11-23`** |
| `OD-V2-15` | **Concept C Cross-Stratum Execution Delta:** $\Delta_{\text{exec}}$, sample-level $\Delta_{\text{first\_hit}}$ ($\text{Rank}_{\min}$), Intrusion-Detection Recall@k, and Byte/Signature Evasion Resilience Hypothesis across matched `pair_group_id` binaries | **Confirmed `2026-11-23`** |
| `OD-V2-16` | Offline pointer-capture schema covering Prefetch, `$MFT`, Tasks XML/TaskCache, Registry (`Run`/`Winlogon`/`IFEO`/`CLSID`/`Services`), WMI, LNK, Amcache (`POINTER_CAPTURE_SPEC.md`) | **Confirmed `2026-11-23`** |
| `OD-V2-17` | Three interpretable propagation baselines for `v2_refgraph`: `(a)` base ranker alone, `(b)` naive undirected, `(c)` hub-attenuated typed propagation (context-split + training IHF) | **Confirmed `2026-11-23`** |
| `OD-V2-18` | Heterogeneous GNNs (`R-GCN`, `GAT`) deferred outside v2 core for forensic traceability | **Confirmed `2026-11-23`** |
| `OD-V2-19` | Strictly post-`--final` deferred stretch items (timestomp experiment, Prefetch-disabled server ablation, `ADFIR`/`NIST CFReDS`/`Magnet CTF` qualitative case studies with zero tuning) | **Confirmed `2026-11-23`** |
| `OD-V2-20` | Pre-scoring pilot go/no-go gate: `< 50%` uniquely resolved static links across persistence/execution rows (`task`, `service`, `run_key`, `wmi_subscription`, `prefetch`) downgrades `v2_refgraph` to exploratory only | **Confirmed `2026-11-23`** |

---

## 4. Phase 1 Chronological Commit Ledger (`ca73589` -> `bbdf564`)

| Commit | Step | Key Deliverables |
| :--- | :--- | :--- |
| `ca73589` | Baseline | v1 audit (`IMPROVEMENT_ANALYSIS.md`), initial `V2_PLAN.md`, `OPERATOR_DECISIONS.md`, `FINAL_EVAL_PLAN_v2_SKELETON.md` |
| `9835a13` | Step A | Confirmed `OD-V2-01..15`, designated `OPERATOR_DECISIONS.md` + `V2_PLAN.md` as single source of truth, created `v2/plan.md` |
| `1918f26` | Step B | Holm-Bonferroni on two-sided paired family-clustered bootstrap p-values (not CIs), secondary `v2_refgraph`/tail/delta specs |
| `366020a` | Step C.1 | `IMP-15` pytest log hygiene, `IMP-07` 15 v2 provenance + 3 refgraph edge columns in `FORBIDDEN_MODEL_INPUTS`, `IMP-13` rule exports |
| `098a8c7` | Concept C | Cross-Stratum Execution Delta ($\Delta_{\text{exec}}$, $\Delta_{\text{first\_hit}}$, Byte/Signature Evasion Resilience Hypothesis) |
| `a14de03` | Step C.2 | `src/v2/config_v2.py`, `models_v2.py`, `training.py` (nested family CV, inner-val early stopping, 100%-dev `iforest`, `K=5` seeds, `30`-trial budget) |
| `03d0113`..`837ac9b` | Steps E1–E7 | `OD-V2-16..19`, `POINTER_CAPTURE_SPEC.md`, `REFGRAPH_SPEC.md`, v1-dev audit `refgraph_audit.py` + `REFGRAPH_FEASIBILITY_V1_DEV.md`, `src/v2/refgraph.py`, `NOVELTY_VERIFICATION.md` (`[1]`–`[137]` marked `UNVERIFIED`), `v2_refgraph` protocol |
| `24222d8` | Step F0 | Per-feature v1-vs-v2 parity audit (`FEATURE_PARITY_AUDIT.md`) + clean-image parity test procedure |
| `69c0138` | Step D | Hardening kit `01..08`, `check_domain_xml.py`, `inetsim-vm` guide, watchdog + base hash scripts, vault script, incident abort |
| `6502905` | Step F | Pure user-space QCOW2/NTFS extractor `src/v2/offline_extractor.py`, `offline_extractor.Dockerfile`, clean-base dry run (`4,364` records) |
| `6239224` | Step C.6 | Upgraded `scripts/verify_stratified_shortcuts.py` (real sizes + 1-MiB histograms + `check_template_quantization`), `BENIGN_GENERATOR_DESIGN.md` |
| `6850cd4` | Step C.4 | `src/v2/labeler_v2.py` (multi-control baseline + Sysmon process tree + dormant + `ambiguous_unattributed`), `review_v2.py` |
| `469c06f` | Step C.3 | `src/v2/stats_v2.py` (10k MC random baseline, clustered paired bootstrap, Holm-Bonferroni, tail-risk/effort, Concept C), `ablations_v2.py` |
| `0663ccd` | Step G | `OD-V2-20` 50% pre-scoring gate, Statistical-Power Note §6, archived `research/concept_a_gap_audit.md` (`UNVERIFIED external report`) |
| `b6a93a0`..`8a3993d` | Pre-Pilot | Recorded Supervisor Marawan approval; added `--build-base-cache`, UTF-16LE Task XML + `TaskCache\Actions` + `CLSID` join (`99.63%` task coverage), `pilot_staging.py`, `00_bake_v2_base_image.sh`, `Install-V2BaseBootstrap.ps1`, `compare_v1_v2_parity.py`, `run_stage_a_pilot.py`, v2 harness footprint filter |
| `6405127` | Parity + Live Fixes 1–3 | `xorriso` Joliet/RockRidge ISO (`build_stage_iso`), relative `-b` + `open_qcow2_target_readonly`, UFW `ufw-user-*` cleanup + pos-1 firewall, 4 `full_20` parity fixes + `MAX_PE_SIGNIFY_BYTES=128 MiB` -> **`20/20 PASS` vs `ctrl_01`** & **`99.62%` `OD-V2-20`** |
| `bbdf564` | Live Fixes 4–5 | `06_unprivileged_container_runner.sh` dual `:ro` CoW overlay + base-cache + `--build`, `offline_extractor.Dockerfile` (`repro.py` + `/cache` + `scikit-learn`), sibling `/input/` fallback in `offline_extractor.py`, removed invalid `-RunId` from `Collect-Artifacts.ps1` parity ISO (`-OutDir` + `parity_stdout.log`) |

---

## 5. Complete Codebase, Hardening Kit & Test Inventory

- **v2 Source Modules ([`src/v2/`](../../src/v2/)):**
  - [`config_v2.py`](../../src/v2/config_v2.py) · [`models_v2.py`](../../src/v2/models_v2.py) · [`training.py`](../../src/v2/training.py)
  - [`offline_extractor.py`](../../src/v2/offline_extractor.py) *(2,200+ lines; pure user-space `dissect` + `WOF` + `CatRoot` + `TaskCache`/`CLSID` + `base_cache` + `open_qcow2_target_readonly`)*
  - [`refgraph.py`](../../src/v2/refgraph.py) · [`refgraph_audit.py`](../../src/v2/refgraph_audit.py)
  - [`labeler_v2.py`](../../src/v2/labeler_v2.py) · [`review_v2.py`](../../src/v2/review_v2.py)
  - [`stats_v2.py`](../../src/v2/stats_v2.py) · [`ablations_v2.py`](../../src/v2/ablations_v2.py)
  - [`pilot_staging.py`](../../src/v2/pilot_staging.py) · [`run_stage_a_pilot.py`](../../src/v2/run_stage_a_pilot.py)
- **Scripts ([`scripts/`](../../scripts/)):** [`compare_v1_v2_parity.py`](../../scripts/compare_v1_v2_parity.py) · [`verify_stratified_shortcuts.py`](../../scripts/verify_stratified_shortcuts.py)
- **Hardening & Lab Kit ([`docs/v2/hardening/`](hardening/)):**
  - [`00_bake_v2_base_image.sh`](hardening/00_bake_v2_base_image.sh) · [`Install-V2BaseBootstrap.ps1`](hardening/Install-V2BaseBootstrap.ps1) · [`01_firewall_win11_isolated.sh`](hardening/01_firewall_win11_isolated.sh)
  - [`02_domain_xml_hardening.md`](hardening/02_domain_xml_hardening.md) · [`check_domain_xml.py`](hardening/check_domain_xml.py) · [`03_inetsim_vm_setup.md`](hardening/03_inetsim_vm_setup.md)
  - [`04_watchdog_and_base_hash.sh`](hardening/04_watchdog_and_base_hash.sh) · [`05_quarantine_vault_setup.sh`](hardening/05_quarantine_vault_setup.sh) · [`06_unprivileged_container_runner.sh`](hardening/06_unprivileged_container_runner.sh)
  - [`07_incident_abort.sh`](hardening/07_incident_abort.sh) · [`08_NEGATIVE_EGRESS_AND_SIGN_OFF.md`](hardening/08_NEGATIVE_EGRESS_AND_SIGN_OFF.md) · [`09_STAGE_A_PILOT_ZERO_SSH_STAGING.md`](hardening/09_STAGE_A_PILOT_ZERO_SSH_STAGING.md)
  - [`offline_extractor.Dockerfile`](hardening/offline_extractor.Dockerfile) · [`requirements_extractor.txt`](hardening/requirements_extractor.txt) · [`POINTER_CAPTURE_SPEC.md`](hardening/POINTER_CAPTURE_SPEC.md)
- **Test Suite (`314 passed` across v1 + v2 tests at `bbdf564`):**
  - [`test_v2_schema.py`](../../tests/test_v2_schema.py) · [`test_v2_training.py`](../../tests/test_v2_training.py) · [`test_v2_refgraph_audit.py`](../../tests/test_v2_refgraph_audit.py) · [`test_v2_refgraph.py`](../../tests/test_v2_refgraph.py) · [`test_v2_hardening_validators.py`](../../tests/test_v2_hardening_validators.py) · [`test_v2_offline_extractor.py`](../../tests/test_v2_offline_extractor.py) · [`test_v2_shortcut_audit.py`](../../tests/test_v2_shortcut_audit.py) · [`test_v2_labeler_and_review.py`](../../tests/test_v2_labeler_and_review.py) · [`test_v2_stats_and_ablations.py`](../../tests/test_v2_stats_and_ablations.py) · [`test_v2_parity_and_pilot.py`](../../tests/test_v2_parity_and_pilot.py)

---

## 6. Observed Host & VM Lab State (`2026-11-23`)

| Asset / Check | Observed State on Disk / Host |
| :--- | :--- |
| **`/var/lib/libvirt/images/win11_base.qcow2`** | **Baked, sealed (`0444`), and verified (`Sysmon64=True`, `SysmonDrv=True`, `EVTX=True`, `Invoke-StagePayload.ps1=True`, `\DFIR-StageRunner=True`, `sshd Start=4`)**; SHA-256 = `d2facced4255e3ae1cb821249d5e6330e380f639cee8a5aae19ef99be690835c` |
| **`/var/lib/libvirt/qemu/nvram/win11_VARS.fd.base`** | Recorded in `/var/lib/libvirt/images/v2_base_hashes.sha256` (`2aeb86356d8c160607a0f258d8b0044b2e30a592c510992b28cb5f5312dda6be`) |
| **`/var/lib/dfir-quarantine-vault/win11_base_cache.json.gz`** | Host-built (`5,524,371` bytes), bound to `d2facced...` (`138,984` `CatRoot` digests, `2,641` file entries, `1,876` WOF-compressed) |
| **`/var/lib/libvirt/images/win11_overlay.qcow2`** | Active disposable CoW overlay (`~252 MB`) present from `05:40` host zero-SSH run |
| **`/var/lib/libvirt/images/inetsim_base.qcow2`** | Newly created (`~212 MB` at `05:56`) — INetSim VM provisioning in progress (`OD-V2-03`) |
| **Baked-base vs `ctrl_01` parity (`6405127`)** | **`20/20 PASS`** (`19/20` at `100.00%`, `signature_state = 98.07%`); `OD-V2-20` persistence/execution link coverage **`796/799` (`99.62%`)** (`4,413` rows kept, `8` harness rows dropped) |
| **Same-overlay zero-SSH host run (`05:54`, uncommitted [`CLEAN_IMAGE_PARITY_REPORT.md`](CLEAN_IMAGE_PARITY_REPORT.md))** | `991` shared cold-disk keys (`4,414` v2 rows); `17/20 PASS` (`signature_state = 98.39%`, `path_depth = 99.80%`), with minor diffs on `name_entropy` (`99.90%`, 1 row), `file_size_log` (`99.51%`, 4 rows), `file_entropy` (`99.49%`, 4 rows) to inspect from `/tmp/parity_report.json` |

---

## 7. Host & Extractor Pitfalls Already Resolved (Do Not Re-Introduce)

1. **ISO 8.3 Truncation Fixed (`bbdf564` / `6405127`):** Pure-Python ISO-9660 L1 truncated `run_manifest.json` -> `RUN_MANI.JSO`, silently skipping `\DFIR-StageRunner`. `build_stage_iso` now uses `xorriso -as mkisofs -J -R -V DFIR_STAGE` so Windows mounts untruncated Joliet filenames (`run_manifest.json`, `benign_workload.ps1`, `Invoke-StagePayload.ps1`, `COLLECT.PS1`).
2. **`dissect` Absolute Backing-Path Crash Fixed (`6405127` / `bbdf564`):** `dissect.hypervisor.disk.qcow2._open_backing_file` calls `Path.with_name()`, crashing with `ValueError: Invalid name` on `/...` backing paths. Overlays now use relative `-b win11_base.qcow2`, and `open_qcow2_target_readonly` + `_resolve_qcow2_backing_path` resolve absolute headers and fall back to sibling files under `/input/` inside containers.
3. **UFW Precedence Fixed (`6405127`):** `01_firewall_win11_isolated.sh --apply` deletes `ufw-user-input/output/forward` `virbr1` `ACCEPT` rules and inserts `V2_VIRBR1_IN`/`V2_VIRBR1_FWD` at position `1` (`INPUT`) and `1,2` (`FORWARD`).
4. **Container CoW & Base Cache Fixed (`bbdf564`):** `06_unprivileged_container_runner.sh` mounts both overlay and backing image `:ro` into `/input/`, mounts `win11_base_cache.json.gz` `:ro` at `/cache/base_cache.json.gz` (`--base-cache-path`), supports `--build`, and `offline_extractor.Dockerfile` + `requirements_extractor.txt` include `src/utils/repro.py`, `/cache`, and `scikit-learn`.
5. **Frozen `Collect-Artifacts.ps1` CLI Fixed (`bbdf564`):** `Collect-Artifacts.ps1` does NOT accept `-RunId`; `build_clean_parity_stage_iso` now calls it with `-OutDir` only and logs output to `C:\collector_out_parity\parity_stdout.log`.
6. **`v2_refgraph` vs `full_20` Field Separation & Large PE Sigs (`6405127`):** Tasks keep leaf `name`, `ServiceDll`/COM targets live in `task_com_target_path`/`ref_targets` without overwriting `command_line`/`path`, `COM:{GUID}` preserves case, and `MAX_PE_SIGNIFY_BYTES = 128 MiB` + stale-large-PE cache bypass keeps `OneDriveSetup.exe` (`89.7 MiB`) `Valid`.

---

## 8. Exact Remaining Critical Path

1. **Finalize Gate 0 Vault Marker (`NEG-01`..`NEG-10` & `inetsim-vm` Verified `PASS` `2026-11-23`):**
   - `NEG-01..NEG-10`, base hash `d2facced...`, `inetsim-vm` (`192.168.150.10` serving `win11` `192.168.150.50`), `NEG-09` container (`4,414` rows, `OD-V2-20 = 99.62%`), `NEG-10` abort drill, and Step 8 live-overlay parity all executed `2026-11-23`.
   - Rebuild container if needed (`./docs/v2/hardening/06_unprivileged_container_runner.sh --build`), verify ASUS dedicated isolated user (`OD-V2-07b`), initialize vault (`./docs/v2/hardening/05_quarantine_vault_setup.sh init`), write `/home/fsociety/.quarantine_vault_dfir_v2/GATE0_SIGNED_OFF`, and verify `preflight` passes.
2. **Stage A Pilot (`OD-V2-05`, `OD-V2-20`):**
   - Curate `6–8` persistence-favoring non-test families into `0400` encrypted vault archives via `scripts/v2_curate_vault_manifest.py` (`ABUSECH_AUTH_KEY` env var).
   - Run unattended Stage A Pilot via `src/v2/run_stage_a_pilot.py --batch-json ...` (auto-configures static `192.168.150.50` -> `192.168.150.10`, manages `inetsim-vm` start/destroy on `executed` runs, decrypts archives strictly in RAM into `DFIR_STAGE` ISO, extracts in `--cap-drop=ALL` container).
   - Evaluate `OD-V2-20` `50%` pre-scoring gate, `check_template_quantization`, pilot yield/variance, and empirical `sigma_delta_family` MDE calibration -> write `docs/v2/STAGE_A_PILOT_REPORT.md`.
3. **Freeze `FINAL_EVAL_PLAN_v2.md` & Run Stage B (`OD-V2-01`..`OD-V2-17`):**
   - Lock empirical `[TBD]` parameters into `docs/FINAL_EVAL_PLAN_v2.md` **before** collecting/freezing the blind test split (`dev` vs `blind_test` disjoint on `sample_family`, `ssdeep`/TLSH clusters, `pair_group_id`, benign profiles, and `emulated` v1 `dev`-only).
   - Collect Stage B runs, execute blinded human review via `src/v2/review_v2.py` (friend primary + Mokh 20% $\kappa$), run nested dev CV + `K=5` final evaluation (`full_20`, `no_content`, secondary `v2_refgraph`, Concept C execution delta, ablations, tail-risk/effort metrics).
