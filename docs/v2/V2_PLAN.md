# DFIR-Triage ML — Phase v2 Comparative Study Plan

**Status:** **LOCKED & APPROVED (`2026-11-25` — Supervisor Marawan AASTMT approval granted; Sprint 1 safety, curator, hybrid-dormant, pipelining & benign-generator upgrades implemented; awaiting `GATE0_SIGNED_OFF` & `--canary` pass before Stage A Pilot)**  
**Single Source of Truth:** [`OPERATOR_DECISIONS.md`](OPERATOR_DECISIONS.md), [`REPLAN_COMPARATIVE_STUDY.md`](REPLAN_COMPARATIVE_STUDY.md), and this file (`docs/v2/V2_PLAN.md`).  
**v1 Separation:** Phase v1 (`dataset_v1.parquet`, `dataset_v1_manifest.json`, `results/`, `docs/FINAL_EVAL_PLAN.md`, `collector/Collect-Artifacts.ps1`) is permanently frozen and unmodified. v1 is cited solely as the initial pilot motivating v2's comparative study (never a separate paper).

---

## 1. Objectives & Falsifiable Hypotheses (H1–H4)

Phase v2 executes a rigorous comparative study of ~20 ML, Learning-to-Rank (LTR), deep tabular, unsupervised, and deterministic-rule rankers on realistic Windows 11 cold-disk host artifacts (`full_20` and `no_content`):
- **Scale (`OD-V2-01`):** **Tier 2 Target** = `1,000` usable standalone-`.exe` real malware samples (`800` dev / `200` blind test) across `50–60` non-destructive families (`20–25` blind test, `>= 15` floor, caps `<= 30` dev / `<= 15` test) + `200` benign-only runs (`160` dev / `40` test). **Tier 1 (`400` usable, `30` families, `15` test)** serves as Checkpoint 1 after Stage A pilot yield verification.
- **Both Execution States (`OD-V2-09`, `OD-V2-15`):** Every usable sample is evaluated in both `executed` and `dormant` states (`executed`-first gating; dev dormant batch-staged at `16`/overlay inside `benign_workload.ps1` without re-baking base; blind-test dormant strictly `1` sample/boot). Executed-vs-dormant comparisons are reported strictly as plain descriptive tables (no novelty claim).
- **Descoped:** `v2_refgraph` (`OD-V2-13`/`17`/`18`/`20`) and Red-vs-Blue agents are descoped from v2 core (existing `offline_extractor.py` pointer capture and `refgraph*.py` tests remain untouched and green).
- **Pre-Registered Hypotheses (`REPLAN_COMPARATIVE_STUDY.md` §6):** `H1` Split-Leakage Sensitivity, `H2` Provenance-Label Trust, `H3` Emulated-vs-Real Transfer (with size-matched control), `H4` Decisive Paradigm Separation (`Friedman + Nemenyi CD` + `m=10` Holm-Bonferroni + 5-axis decision scorecard).

---

## 2. Prevalence Separation, Equal Tuning Budgets & Calibration (`OD-V2-06`, `OD-V2-12`)

1. **Train-Time OS-Baseline Deduplication (`dev` ONLY):**
   - Pointwise/Unsupervised dev training collapses identical untouched `baseline` rows matching `(artifact_key, stable_content_hash)` across dev runs (`deduplicate_dev_os_baseline`, strictly blocked outside `split_pool == "dev"`), yielding `~61k–91k` rows (`dev_dedup`).
   - LTR models (`XGBRanker`, `LGBMRanker`) use per-host `qid=run_id` query groups (`dev_ltr`, ~`200` stratified baseline negatives/run + all `benign_drift` + all positives).
   - **Blind Test (`Natural Prevalence` Main View):** NEVER deduplicated across runs (`~1.96M` rows, `0.0714%` positive across `440` independent host snapshots); secondary subsampled view (`200` benign/run) disclosed alongside sampling weights.
2. **Strict Equal Tuning Budgets (`20` Equal Trials, `5×3` Nested CV, `K=5` Seeds):**
   - **ALL tuned models** (linear/kernel/instance, trees, LTR, CUDA deep tabular, and unsupervised arms) receive an **exact equal `20`-trial budget** inside **`5`-fold outer × `3`-fold inner** family-grouped nested CV (`src/v2/config_v2.py`: `V2_N_SEARCH_TRIALS = 20`, `V2_OUTER_FOLDS = 5`, `V2_INNER_FOLDS = 3`, `V2_FINAL_SEEDS = [42, 43, 44, 45, 46]`), preventing any re-introduction of `IMP-09` unequal tuning budgets.
   - `iforest`/non-early-stopped arms fit on `100%` of eligible dev rows; neural arms early-stop strictly on disjoint inner grouped validation slices.
3. **Natural-Prevalence Probability Calibration & Thresholds:**
   - Probability calibrators (`Platt` / `Isotonic`) and deployable `1%` FPR thresholds MUST be fitted strictly on **natural-prevalence dev OOF predictions** (or exact dev-only Bayes prior-odds adjustment from `dev_dedup` to dev natural prevalence), NEVER on raw `~7%` deduplicated dev prevalence.

---

## 3. Malware Safety, Benign Generator & Air-Gap Enforcement

1. **Hard Exclusion & Standalone `.exe` Gate (`OD-V2-08`):** Fail-closed `FORBIDDEN_MALWARE_FAMILIES_AND_TAGS` across `scripts/v2_curate_vault_manifest.py` and `src/v2/pilot_staging.py` hard-blocks ransomware, wipers, and self-propagating worms. `validate_standalone_runnable_exe_pe` verifies every candidate in RAM (`pe.is_exe() and not pe.is_dll()`) before writing `0400` vault archives.
2. **6 Hardened Safety Guards (`OD-V2-07`):**
   - Strict `0400` `GATE0_SIGNED_OFF` with 5 required metadata fields + SHA-256 manifest completeness check (`05_quarantine_vault_setup.sh`).
   - Crash-surviving detached host watchdog (`arm-watchdog` / `disarm-watchdog` using `setsid`/`systemd-run`) armed **before** `virsh start win11` covering both `win11` and `inetsim-vm` (`04_watchdog_and_base_hash.sh`).
   - Fast per-run base immutability (`verify-base-fast` inside `try ... finally:`: `0444`, `lsattr +i`, `stat` inode/blocks/mtime, full `win11_VARS.fd.base` SHA-256) + full `win11_base.qcow2` `sha256sum -c` every `25` runs and at batch start/end/abort.
   - Per-run `virbr1` firewall position & packet-counter egress audit (`check-egress` -> `egress_audit.jsonl`).
   - Mandatory supervised `--canary` mode (`1` control + `1` dormant + `1` executed -> `CANARY_PASSED`) required before unattended malware batches.
   - Pure user-space container extraction (`06_unprivileged_container_runner.sh`) with safe 1-lane pipelining via per-run renamed overlays (`win11_overlay_<run_id>.qcow2`).
3. **Real Benign Drift Pools & Procedural Generator (`IMP-06`):** `scripts/v2_prepare_benign_pools.py` and `src/v2/benign_generator_v2.py` enforce zero overlap between `dev` (`B_dev_01..20`) and `blind_test` (`B_test_01..10`), targeting `1,500–2,000` unique files (`~300–400` unsigned PEs, `~300–400` signed 3rd-party PEs, `~500–700` scripts, `~400–500` high-entropy archives/data + `200–400` benign persistence entries).
4. **Blinded Human Review Cap (`OD-V2-10`):** `src/v2/review_v2.py` caps primary export at `400` stratified rows (`200` positives stratified by stratum+family, `100` `benign_drift`, `100` `ambiguous`) for Mokh's friend + proportional `20%` (`80`-row) overlap for Mokh Cohen's $\kappa$.
5. **Hard Air-Gap for Results API / UI (`Sprint 2`):** No malware VM (`win11` on `win11-isolated` / `virbr1`) may ever have a host/API route; research results load strictly from offline Linux JSONL/Parquet (`POST /api/v1/triage/import-offline`), while any live Windows demo uses a separate clean/emulated VM on `win11-demo-net` (`192.168.160.0/24`).

---

## 4. Ordered Execution Phases

1. **Sprint 1 (Complete):** 6 safety fixes, ransomware/wiper/worm blocklist + standalone `.exe` PE gate, `--patch-stale-large-pe-cache` + Sysmon EVTX export, zero-rebake hybrid batch-dormant + 1-lane pipelining, `400`/`80` review cap, real benign pools/generator, `.venv` packages, doc sync.
2. **Gate 0 Ops & Stage A Pilot:** Patch `win11_base_cache.json.gz`, populate/audit disjoint benign pools, sign `0400` `GATE0_SIGNED_OFF`, pass `preflight`, curate 7 non-destructive `.exe` pilot families, pass `--canary`, run Stage A Pilot (`~3` controls + `7` paired samples) -> calibrate empirical yield & `sigma_delta_family`.
3. **Sprint 2 (Comparative ML Suite + Results Screen/API):** Expand `models_v2.py`/`training.py`/`stats_v2.py` to ~20 arms (`20` equal trials in `5×3` nested CV, `dev_ltr` query batching, natural-prevalence calibrators, Friedman/Nemenyi + `m=10` Holm + 5-axis scorecard), plus `src/api/` (`ScorerAdapter`, SHAP fix for `export_findings.py:105`, React/HTML analyst UI).
4. **Stage B Collection & Freeze:** Collect Checkpoint 1 (`400`) -> Target (`1,000` usable + `200` benign), complete blinded review (`400`/`80`), freeze `v2_blind_test_manifest.json` (`blind_test_sha256`), commit `FINAL_EVAL_PLAN_v2.md`, execute one-shot `--final`.
