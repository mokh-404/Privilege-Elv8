# DFIR-Triage ML — v2 Phase 1 Implementation Tracker (`v2/plan.md`)

**Status:** `IN PROGRESS — STEPS A, B, C.1, C.2 EXECUTING (HARD STOP AT END OF STEP C.2)`  
**Repository:** `dfir-triage-ml` (branch `main`, base commit `ca73589`)  
**Scope:** Phase 1 preparation ONLY — **NO malware acquisition, downloads, or execution**, **NO VM runs**, **NO host firewall, network, or libvirt domain XML changes applied**. Written institutional approval & Gate 0 sign-off (`OD-V2-07`) remain **PENDING**.

> **Single Source of Truth:** [`docs/v2/OPERATOR_DECISIONS.md`](../docs/v2/OPERATOR_DECISIONS.md) (confirmed decision status `OD-V2-01..15`) and [`docs/v2/V2_PLAN.md`](../docs/v2/V2_PLAN.md) (v2 architecture, safety protocol, strata, methodology, and risk register) are the **single source of truth** for v2 policy and design. This file (`v2/plan.md`) serves solely as the Phase 1 execution checklist, module layout, and step-by-step verification tracker.

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

- **STEP A:** Update `docs/v2/OPERATOR_DECISIONS.md` (`OD-V2-01..15`), update `docs/v2/V2_PLAN.md` to match, reconcile with `v2/plan.md`, and designate `OPERATOR_DECISIONS.md` + `V2_PLAN.md` as single source of truth.
- **STEP B:** Fix `docs/v2/FINAL_EVAL_PLAN_v2_SKELETON.md` (Holm-Bonferroni on two-sided paired family-clustered bootstrap p-values, NOT CIs; add `v2_refgraph`, tail-risk/effort + tail-audit sample calculator as future work, and dormant-vs-executed delta as pre-registered secondary items outside the winner rule; preserve `DRAFT` status & `[TBD]` fields).
- **STEP C.1 (Hygiene, Schema & Refgraph Edge Columns):** `IMP-15` pytest hygiene + repo-hygiene tests; `IMP-07` 14 v2 provenance columns + 3 refgraph edge columns (`ref_targets`, `ref_type`, `linked_artifact_keys`) in `FORBIDDEN_MODEL_INPUTS` (never allowed in `full_20`/`no_content`, even via `allowed_extra`); `IMP-13` export `task_name`, `service_name`, `start_mode`, `task_triggers`, `account_is_admin`, `account_enabled` for identical rule re-evaluation.
- **STEP C.2 (Training Integrity as v2 Code Paths):** `src/v2/config_v2.py`, `src/v2/models_v2.py`, `src/v2/training.py` (`iforest`/non-ES arms fit 100% eligible dev; `ae`/`mlp` early-stop strictly on disjoint inner grouped validation split; `K=5` seeds; nested family-grouped CV; equal `30`-trial budget with `20` fallback; split-local preprocessing; label-free vs `"label-selected"` unsup selection). **HARD STOP AFTER STEP C.2 UNTIL MOKH CONFIRMS.**
- **STEP C.3 (Statistics — deferred past C.2 stop):** 10,000-perm MC random baseline, family-clustered paired bootstrap p-values + Holm-Bonferroni over fixed pairs, dev-calibrated thresholds from nested OOF, tie-expected P@k, LOFO dev table, dev-only/config-matched/guarded ablations, and `OD-V2-14` tail-risk/effort metrics.
- **STEP C.4 (Labeling & Review — deferred past C.2 stop):** Synthetic-tested process-tree/multi-control/dormant/`ambiguous_unattributed` v2 labeler, separated blinded review export (friend primary, Mokh 20% overlap Cohen's $\kappa$, non-overwrite guard).
- **STEP C.5 (Referential-Graph Feasibility — deferred past C.2 stop):** Read-only static link extractor/resolver run on **v1 DEV rows only** reporting per-type and cross-type link coverage honestly (no training/scoring).
- **STEP C.6 (Realism Audit & Benign Generator Design — deferred past C.2 stop):** Update `scripts/verify_stratified_shortcuts.py` with real sizes/byte histograms; design varied benign generator + template-quantization check (no VM code).
- **STEP D (Hardening Kit — deferred past C.2 stop):** Write scripts and checklists in `docs/v2/hardening/` for Mokh to run (do not apply).
