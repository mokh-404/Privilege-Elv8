# DFIR-Triage ML v2 — Operator Decisions & Onboarding Record

**Status:** `STRATEGIC PIVOT TO COMPARATIVE STUDY LOCKED BY MOKH & APPROVED BY SUPERVISOR MARAWAN (AASTMT, 2026-11-25) — SPRINT 1 COMPLETE, AWAITING GATE 0 MARKER SIGN-OFF & --canary RUN`  
**Single Source of Truth:** This document (`docs/v2/OPERATOR_DECISIONS.md`), [`REPLAN_COMPARATIVE_STUDY.md`](REPLAN_COMPARATIVE_STUDY.md), and [`V2_PLAN.md`](V2_PLAN.md) govern Phase v2 policy, safety, strata, and evaluation design.  
**Related Docs:** [`REPLAN_COMPARATIVE_STUDY.md`](REPLAN_COMPARATIVE_STUDY.md) | [`V2_PLAN.md`](V2_PLAN.md) | [`FINAL_EVAL_PLAN_v2_SKELETON.md`](FINAL_EVAL_PLAN_v2_SKELETON.md) | [`v2/plan.md`](../../v2/plan.md) | [`IMPROVEMENT_ANALYSIS.md`](../IMPROVEMENT_ANALYSIS.md)

---

## Summary Table (Updated `2026-11-25` for Comparative Study Pivot)

| ID | Topic | Locked v2 Comparative Study Decision | Status |
| :--- | :--- | :--- | :--- |
| **`OD-V2-01`** | **Data targets (Families + Samples/Runs)** | **Tier 2 Target:** `1,000` usable standalone-`.exe` real malware samples (`800` dev / `200` blind test) from `~2,000` executed attempts across `50–60` families (`20–25` blind test, `>= 15` floor, caps `<= 30` dev / `<= 15` test) + `200` benign-only runs (`160` dev / `40` test). **Checkpoint 1 (Tier 1):** `400` usable (`300`/`100`), `30` families (`15` blind test) | **Locked & Approved `2026-11-25`** |
| **`OD-V2-02`** | **v1 reuse (`emulated`) & Step F0 parity rulings** | Frozen `dataset_v1.parquet` (`1,104` cold-disk `dev` rows after excluding `75` live `process` rows) stays strictly `dev`-only `"emulated"` stratum (`0%` blind test; cited only as initial pilot motivating v2, NOT a separate paper); 27 locked OS files aligned; `run_key` raw (`--no-expand-env`) in `full_20` | **Confirmed `2026-11-23`; Retained** |
| **`OD-V2-03`** | **Fake-internet responder** | `INetSim` on separate isolated Linux VM (`inetsim-vm`, `192.168.150.10`) attached solely to `win11-isolated` (`virbr1`), zero WAN forwarding | **Confirmed `2026-11-23`; Verified Live** |
| **`OD-V2-04`** | **Offline artifact extraction** | Pure user-space offline parsing inside unprivileged container (`--network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges`) with incremental `128 MiB` patched `win11_base_cache.json.gz`; safe 1-lane pipelining via per-run renamed overlays | **Confirmed `2026-11-23`; Upgraded `2026-11-25`** |
| **`OD-V2-05`** | **Stage A pilot scope & `--canary` gate** | Supervised `--canary` (`1` control + `1` dormant + `1` executed) required (`CANARY_PASSED`) before Stage A pilot (`~3` controls + `6–8` non-test non-destructive standalone-`.exe` families × paired `executed` then `dormant`) calibrating yield & `sigma_delta_family` | **Updated & Locked `2026-11-25`** |
| **`OD-V2-06`** | **Multi-seed, equal budget & calibration** | `K = 5` seeds (`[42..46]`), **EQUAL `20`-trial tuning budget across ALL tuned models** (`5` outer × `3` inner family-grouped nested CV, fixing `IMP-09`), and **probability calibration (`Platt`/`Isotonic`) + `1%` FPR thresholds fitted strictly on natural-prevalence dev OOF** (or exact dev-only Bayes prior-odds adjustment), NEVER raw `dev_dedup` | **Locked `2026-11-25`** |
| **`OD-V2-07`** | **Vault, Supervisor approval & Gate 0** | **Written approval granted `2026-11-23` AND comparative-study scale/exclusion addendum approved `2026-11-25` by Supervisor Marawan (AASTMT)** (*ethics waived by supervisor*); isolated user `fsociety`; strict `0400` `GATE0_SIGNED_OFF` metadata + SHA-256 manifest + detached watchdog + `finally:` base hash + `virbr1` counter checks enforced | **Approval `2026-11-25`; `GATE0_SIGNED_OFF` sign-off PENDING** |
| **`OD-V2-08`** | **Malware categories & hard exclusions** | **HARD EXCLUDE ransomware, wipers, and self-propagating worms** (fail-closed `FORBIDDEN_MALWARE_FAMILIES_AND_TAGS` across curator & `validate_stage_run_spec`). Use 5 allowed categories (`InfoStealer`, `RAT/Backdoor`, `Loader/Dropper`, `Coinminer/Clipper`, `Trojanized Installer`), **standalone runnable `.exe` PE gate** (`pe.is_exe() and not pe.is_dll()`), AVClass2 canonical family names + `ssdeep`/`ppdeep`/`tlsh`/`imphash` clustering | **Updated & Locked `2026-11-25`** |
| **`OD-V2-09`** | **Stratum mix & Hybrid Dormant strategy** | Evaluate 100% of usable samples in both `executed` and `dormant` (`executed`-first gating; dev dormant batch-staged at `16`/overlay inside `benign_workload.ps1` without re-baking base; blind-test dormant strictly `1` sample/boot); `emulated` `dev`-only | **Locked `2026-11-25`** |
| **`OD-V2-10`** | **Independent blinded human review** | Mokh's friend = primary blinded reviewer **capped at `400` stratified rows** (`200` positives stratified by stratum+family, `100` `benign_drift`, `100` `ambiguous`); Mokh = `20%` (`80`-row) overlap for Cohen's $\kappa$ | **Locked `2026-11-25`** |
| **`OD-V2-11`** | **Feature schema scope** | Locked `full_20` (20) & `no_content` (18) across `~20` comparative models (ML, LTR, deep tabular, unsupervised, rule baselines); `v2_refgraph` descoped from v2 core | **Updated & Locked `2026-11-25`** |
| **`OD-V2-12`** | **Real benign drift pools & prevalence separation** | Disjoint `dev` (`B_dev_01..20`) vs `blind_test` (`B_test_01..10`) benign asset pools targeting **`1,500–2,000` unique files** (`~300–400` unsigned PE, `~300–400` signed 3rd-party PE, `~500–700` varied scripts, `~400–500` high-entropy archives/data + `200–400` persistence entries). **Train-time OS-baseline deduplication in dev ONLY** vs **100% natural prevalence in blind test** (+ subsampled secondary view) | **Updated & Locked `2026-11-25`** |
| **`OD-V2-13`** | **Referential-graph arm (`v2_refgraph`)** | **DESCOPED** from v2 core (keep existing `src/v2/refgraph*.py` & tests non-breaking; zero further refgraph work or paper claims) | **Descoped `2026-11-25`** |
| **`OD-V2-14`** | **Tail-risk & analyst-effort metrics** | Integral part of the 5-axis comparative scorecard (`worst_positive_rank`, `Recall@k`, `Effort@Recall`, bottom `50%/90%`, clean-host FPs/host) | **Confirmed `2026-11-23`; Retained** |
| **`OD-V2-15`** | **Executed vs. Dormant reporting** | Report `executed`, `dormant`, and pooled real-malware metrics separately alongside `drop_signature`/`no_content_no_sig` ablations strictly as a **plain descriptive table (no novelty claim)** | **Updated `2026-11-25`** |
| **`OD-V2-16`** | **Offline pointer capture (`offline_extractor.py`)** | **KEEP (FROZEN)** inside `offline_extractor.py` so existing extractor & parity tests pass; added read-only `sysmon_events.jsonl` oracle export for causal labeling | **Frozen & Extended (Sysmon) `2026-11-25`** |
| **`OD-V2-17`** | **3 refgraph propagation baselines** | **DESCOPED** alongside `v2_refgraph` | **Descoped `2026-11-25`** |
| **`OD-V2-18`** | **Heterogeneous GNNs (`R-GCN`, `GAT`)** | **DESCOPED / EXCLUDED** from v2 core | **Descoped `2026-11-25`** |
| **`OD-V2-19`** | **Post-freeze Results UI / API & deferred stretch** | End-user model-agnostic `ScorerAdapter` + Results Screen / API (Sprint 2, strictly air-gapped from malware VMs) and post-`--final` case studies | **Locked `2026-11-25`** |
| **`OD-V2-20`** | **`v2_refgraph` 50% pilot gate** | **DESCOPED** from v2 go/no-go gating (kept solely as a passive diagnostic metric inside pilot summary) | **Descoped `2026-11-25`** |

---

## Operator Sign-Off Checklist (Mokh)

- [x] `OD-V2-01`..`OD-V2-20` Comparative Study Pivot Decisions Locked (`2026-11-25`)
- [x] Supervisor Marawan (AASTMT) initial approval (`2026-11-23`) + Comparative Study Scaling & Ransomware/Wiper/Worm Exclusion Approval (`2026-11-25`)
- [x] Containment (`NEG-01`..`NEG-10`) & Sealed Base Hash (`d2facced...`) Verified (`2026-11-23`)
- [ ] Host Pre-Pilot Ops: Patch `win11_base_cache.json.gz` (`--patch-stale-large-pe-cache`), populate disjoint `dev`/`blind_test` benign pools, sign `0400` `GATE0_SIGNED_OFF`, pass `05_quarantine_vault_setup.sh preflight`, curate 7 standalone-`.exe` pilot families, pass `--canary` (`CANARY_PASSED`)
