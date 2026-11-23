# DFIR-Triage ML — v2 Phase 1 Implementation Tracker (`v2/plan.md`)

**Status:** `IN PROGRESS — PHASE 1 PREP CONTINUING IN ORDER: F0 -> D -> F -> C.6 -> C.4 -> C.3 -> G`  
**Repository:** `dfir-triage-ml` (branch `main`, base commit `ca73589`)  
**Scope:** Phase 1 preparation ONLY — **NO malware acquisition, downloads, or execution**, **NO VM runs**, **NO host firewall, network, or libvirt domain XML changes applied**. Written institutional approval & Gate 0 sign-off (`OD-V2-07`) remain **PENDING**.

> **Single Source of Truth:** [`docs/v2/OPERATOR_DECISIONS.md`](../docs/v2/OPERATOR_DECISIONS.md) (confirmed decision status `OD-V2-01..19`) and [`docs/v2/V2_PLAN.md`](../docs/v2/V2_PLAN.md) (v2 architecture, safety protocol, strata, methodology, and risk register) are the **single source of truth** for v2 policy and design. This file (`v2/plan.md`) serves solely as the Phase 1 execution checklist, module layout, and step-by-step verification tracker.

---

## 1. Reconciliation Log (`docs/v2/V2_PLAN.md` vs. `v2/plan.md`)

Comparing the initial `v2/plan.md` draft (commit `ca73589`) against Mokh's confirmed decisions (`2026-11-23`) and `docs/v2/V2_PLAN.md`:

| Area | Previous State (`ca73589`) | Reconciled State (`2026-11-23`) |
| :--- | :--- | :--- |
| **Decision confirmation status** | All `OD-V2-01..12` marked `pending Mokh's confirmation` | `OD-V2-01..06, 08, 09, 11..15` confirmed `2026-11-23`; `OD-V2-07` design confirmed with written institutional approval & Gate 0 sign-off still `PENDING`. |
| **Trial budget fallback (`OD-V2-06`)** | Fixed at `30` trials only | `30` equal trials per tuned arm, with explicit `20`-trial fallback if pilot shows compute is too heavy. |
| **Malware family selection (`OD-V2-08`)** | Generic multi-category mix | Explicitly prefers families that run without live C2 and leave host persistence artifacts. |
| **Human review roles (`OD-V2-10`)** | Mokh primary reviewer + 2nd reviewer on 20% overlap | **Changed:** Mokh's friend is the primary blinded reviewer; Mokh scores the 20% overlap for Cohen's $\kappa$ (to maintain primary-reviewer independence). |
| **Test prevalence (`OD-V2-12`)** | Full host prevalence alongside diagnostic slices | Main blind-test view = natural (full-host) prevalence; secondary view = subsampled prevalence, with weights disclosed. |
| **New confirmed scopes (`OD-V2-13..15`)** | Not present in `V2_PLAN.md` or `v2/plan.md` | Added static-only `v2_refgraph` secondary arm (`OD-V2-13`), tail-risk & `effort@recall` metrics + tail-audit sample calculator as future work (`OD-V2-14`), and dormant-vs-executed feature-group delta (`OD-V2-15`). |
| **Holm-Bonferroni specification** | `V2_PLAN.md` §10 loosely referenced CIs after Holm correction | Corrected everywhere to specify **Holm-Bonferroni on two-sided paired family-clustered bootstrap p-values** (never adjusting percentile CIs). |
| **Step numbering & refgraph feasibility** | Numbered `Step 0..6` without `v2_refgraph` | Reconciled to **Step A** (decisions/reconcile), **Step B** (`FINAL_EVAL_PLAN_v2_SKELETON.md`), **Step C.1–C.6** (adding `ref_targets`/`ref_type`/`linked_artifact_keys` in C.1, tail-risk/effort in C.3, v1-dev-only refgraph coverage check in C.5), and **Step D** (hardening kit). |

---

## 2. Frozen v1 Integrity Baseline & Hard Rules

- `data/processed/dataset_v1.parquet` SHA-256: `39527f85fbda75f952e0cf5134a07467bf546501cb540ba68cd65b14983c7f21`
- `data/splits/dataset_v1_manifest.json` SHA-256: `788b6a7cab836c1851a90c5069e89496aa748c33f86643a84d9d70cc50857fbe`
- `results/logs/runner_footprint_dropped.csv`: `99` lines (`1` header + `98` rows)
- Verification after **every** step: `.venv/bin/pytest` passes, both v1 SHA-256 hashes match, and `git diff --stat results/ data/ docs/FINAL_EVAL_PLAN.md` is empty.
- No `--final` for v1, no research-paper text, no malware acquisition/execution, no VM runs, no host firewall/XML edits (`sudo` only for `virsh`, `qemu-img`, `chown`, `cp`, `rm`; never `virsh create`).

---

## 3. Phase 1 Implementation Steps (Commit & Verify Each Step)

- **STEP A:** *(Done — `9835a13`)* Update `docs/v2/OPERATOR_DECISIONS.md` (`OD-V2-01..15`), update `docs/v2/V2_PLAN.md`, reconcile with `v2/plan.md`, and designate `OPERATOR_DECISIONS.md` + `V2_PLAN.md` as single source of truth.
- **STEP B:** *(Done — `1918f26`)* Fix `docs/v2/FINAL_EVAL_PLAN_v2_SKELETON.md` (Holm-Bonferroni on two-sided paired family-clustered bootstrap p-values, NOT CIs; secondary `v2_refgraph`, tail-risk/effort + tail-audit calculator as future work, dormant-vs-executed delta; preserve `DRAFT` status & `[TBD]` fields).
- **STEP C.1 (Hygiene, Schema & Refgraph Edge Columns):** *(Done — `366020a`)* `IMP-15` pytest hygiene + repo-hygiene tests; `IMP-07` 15 v2 provenance columns (incl. `pair_group_id`) + 3 refgraph edge columns (`ref_targets`, `ref_type`, `linked_artifact_keys`) in `FORBIDDEN_MODEL_INPUTS`; `IMP-13` export `task_name`, `service_name`, `start_mode`, `task_triggers`, `account_is_admin`, `account_enabled`.
- **CONCEPT C (Cross-Stratum Execution Delta):** *(Done — `098a8c7`)* Formalize paired `sample_sha256` (`pair_group_id`) sampling across `dormant` + `executed`, anti-leakage holdout assertions, $\Delta_{\text{exec}}$, $\Delta_{\text{first\_hit}}$ ($\text{Rank}_{\min}$ + Intrusion-Detection Recall@k), and Byte/Signature Evasion Resilience Hypothesis across `OPERATOR_DECISIONS.md`, `V2_PLAN.md`, and `FINAL_EVAL_PLAN_v2_SKELETON.md`.
- **STEP C.2 (Training Integrity as v2 Code Paths):** *(Done — `a14de03`)* `src/v2/config_v2.py`, `src/v2/models_v2.py`, `src/v2/training.py` (`iforest`/non-ES arms fit 100% eligible dev; `ae`/`mlp` early-stop strictly on disjoint inner grouped validation split; `K=5` seeds; nested family-grouped CV; equal `30`-trial budget with `20` fallback; split-local preprocessing; label-free vs `"label-selected"` unsup selection).
- **STEPS E1–E7 (Concept A Static Referential Graph Additions):** *(Done)*
  - **E1:** *(Done — `03d0113`)* Record confirmed `OD-V2-16..19` in `OPERATOR_DECISIONS.md`, update `V2_PLAN.md`, `v2/plan.md`, `docs/INDEX.md`.
  - **E2:** *(Done — `6f88605`)* Offline pointer-capture schema & v1 collector gap audit in `docs/v2/hardening/POINTER_CAPTURE_SPEC.md`.
  - **E3:** *(Done — `a181e14`)* Write `docs/v2/REFGRAPH_SPEC.md` (nodes/edges, context-split, obfuscation, 4 MFT states, experimental Prefetch hashing, training-only IHF, 3 propagation baselines, leakage rules).
  - **E4:** *(Done — `5bcfc0c`)* Read-only link-coverage feasibility audit on `dataset_v1.parquet` (`split_pool == "dev"` ONLY) in `src/v2/refgraph_audit.py` + `docs/v2/REFGRAPH_FEASIBILITY_V1_DEV.md`.
  - **E5:** *(Done — `7ec7642`)* Prototype `src/v2/refgraph.py` link resolver + 3 propagation variants with synthetic hub-collapse and leakage-guard tests in `tests/test_v2_refgraph.py`.
  - **E6:** *(Done — `b22d62a`)* Catalog all prior works from `v2/concept_a_gap_audit.md` in `docs/v2/NOVELTY_VERIFICATION.md` with every item marked `UNVERIFIED`.
  - **E7:** *(Done — `837ac9b`)* Update `docs/v2/FINAL_EVAL_PLAN_v2_SKELETON.md` (`v2_refgraph` 3-variant comparison per stratum on PR-AUC, `effort@recall`, review-budget recall, tail risk; Concept C secondary; `OD-V2-19` deferred stretch).
- **STEP F0 (`full_20` Feature-Parity Audit):** *(Done — `24222d8`)* Per-feature v1 (`file:line`) vs offline v2 parity audit (`signature_state` catalog + `UnknownError->na`, `parent_process_class`, `file_entropy`/`file_size_log` 1 MiB window, `has_hidden_attr`, `autostart_flag`, `registry_location_class`, `cmdline_*`), `OD-V2-02` `process`-row exclusion effect, and clean-image parity test procedure in `docs/v2/FEATURE_PARITY_AUDIT.md`.
- **STEP D (Hardening Kit):** *(Done — `69c0138`)* Default-DROP `virbr1` firewall (`01_firewall_win11_isolated.sh`), domain XML hardening + validator (`02_domain_xml_hardening.md`, `check_domain_xml.py`), separate `inetsim-vm` guide (`03_inetsim_vm_setup.md`), wall-clock watchdog + base SHA-256 checks (`04_watchdog_and_base_hash.sh`), quarantine vault (`05_quarantine_vault_setup.sh`), unprivileged container runner (`06_unprivileged_container_runner.sh`), incident abort (`07_incident_abort.sh`), negative-egress checklist & ordered Mokh run/sign list (`08_NEGATIVE_EGRESS_AND_SIGN_OFF.md`), and `tests/test_v2_hardening_validators.py`.
- **STEP F (Offline Extractor):** *(Done — `6502905`)* Pure user-space QCOW2/NTFS extractor (`src/v2/offline_extractor.py`) per `POINTER_CAPTURE_SPEC.md`, `offline_extractor.Dockerfile` + `requirements_extractor.txt`, synthetic tests (`tests/test_v2_offline_extractor.py`), and read-only clean-base dry run (`docs/v2/CLEAN_IMAGE_EXTRACTION_DRYRUN.md`).
- **STEP C.6 (Realism Audit & Benign Generator Design):** *(Done)* Updated `scripts/verify_stratified_shortcuts.py` with real sizes and leading-1-MiB byte histograms + `check_template_quantization` pass/fail gate; wrote `docs/v2/BENIGN_GENERATOR_DESIGN.md` and `tests/test_v2_shortcut_audit.py`.
- **STEP C.4 (Labeling & Review):** Synthetic-tested multi-control/process-tree/dormant/`ambiguous_unattributed` v2 labeler (`src/v2/labeler_v2.py`) and decoupled blinded two-reviewer export (`src/v2/review_v2.py`, friend primary + Mokh 20% overlap Cohen's $\kappa$, non-overwrite guard).
- **STEP C.3 (Statistics):** 10,000-perm MC random baseline, family-clustered paired bootstrap p-values + Holm-Bonferroni over fixed comparison list, dev-calibrated thresholds from nested OOF, tie-expected P@k, LOFO dev table, dev-only/config-matched/guarded ablations, tail-risk and `effort@recall` metrics (`src/v2/stats_v2.py`, `src/v2/ablations_v2.py`).
- **STEP G (Pre-Registration Additions & Archive):** Add proposed `OD-V2-20` (`v2_refgraph` pilot 50% go/no-go gate), statistical-power note, commit `UNVERIFIED` Concept A audit under `docs/v2/research/concept_a_gap_audit.md` with fixed links in `NOVELTY_VERIFICATION.md`, and update `docs/INDEX.md` + `v2/plan.md`.
