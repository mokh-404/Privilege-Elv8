# Documentation Index

- **[Complete Project Report](../COMPLETE_REPORT.md)** — End-to-end technical report covering Steps 1–8, Track B, Win11 lab & 51-run collection, dataset freeze & pre-`--final` bug fix, dev CV, one-time frozen test results (`full_20` & `no_content`), dual-config statistical verdicts, dev-fitted ablations, SHAP/AE/IF explainability, 300-DPI figures, REVENANT exports, methodological caveats, and reproduction commands.
- **[Repository Overview & Quickstart](../README.md)** — Setup, test suite execution, headline results, and artifact layout.

## Active Project & Protocol Docs

| Document | Purpose |
| :--- | :--- |
| [FINAL_EVAL_PLAN.md](FINAL_EVAL_PLAN.md) | Pre-registered Track A dual-configuration (`full_20` + `no_content`) evaluation protocol, winner rule, template-quantization disclosure, and methodological notes (committed prior to `--final`) |
| [PLAN.md](PLAN.md) | Python `3.12.16` `.venv` environment setup and 8-step implementation roadmap |
| [PROGRESS.md](PROGRESS.md) | Live milestone checklist across Steps 1–8, known limitations, and resolved configuration decisions (`Q-S6-2`) |
| [PRE_51_LAUNCH.md](PRE_51_LAUNCH.md) | Pre-51-run stratified benign shortcut alignment audit (`ALL STOPPING CRITERIA SATISFIED: True`, max numeric AUC `0.6865`, max categorical gap `17.5pp`) |
| [WORK_SUMMARY.md](WORK_SUMMARY.md) | Archived Step 1–7 pre-Step-8 execution checkpoint (Win11 51-run batch details, 8 label corrections, 6 kept `.pf` drift audits, per-technique coverage) |
| [WINDOWS_11_LAB_SETUP.md](WINDOWS_11_LAB_SETUP.md) | Windows 11 libvirt/QEMU/KVM + UEFI Secure Boot + swtpm 2.0 guest image build & snapshot isolation guide |
| [IMPROVEMENT_ANALYSIS.md](IMPROVEMENT_ANALYSIS.md) | Post-v1 read-only codebase, statistics, safety, and labeling audit (prioritized P0/P1/P2 findings + top 10 before v2) |
| [v2/CHECKPOINT_ONBOARDING.md](v2/CHECKPOINT_ONBOARDING.md) | **Single-file onboarding checkpoint** spanning v1 freeze baseline, `OD-V2-01..20`, Phase 1 commit ledger (`ca73589..bc12c57`), codebase inventory, host lab state, solved pitfalls, and Gate 0 -> Stage A -> `--final` checklist |
| [v2/PIVOT_CODEBASE_AUDIT.md](v2/PIVOT_CODEBASE_AUDIT.md) | **Strategic Pivot Read-Only Codebase & Safety Audit (2026-11-25)** covering 6 safety items, `win11_base_cache` `192.9s` root cause, `review_v2.py` cap, SHAP `feature_value: null` bug, and ASUS host/package feasibility |
| [v2/REPLAN_COMPARATIVE_STUDY.md](v2/REPLAN_COMPARATIVE_STUDY.md) | **Locked Comparative Study Re-Scope & Execution Plan (2026-11-25)**: Tier 2 (`1,000` usable + `200` benign), Hybrid dormant, 1-lane pipelining, equal `20`-trial `5x3` nested CV, `H1`–`H4` hypotheses, Friedman/Nemenyi + `m=10` Holm, and air-gapped API/UI design |
| [v2/OPERATOR_DECISIONS.md](v2/OPERATOR_DECISIONS.md) | Recorded v2 operator decisions (`OD-V2-01`..`OD-V2-20`, updated & locked `2026-11-25` under Supervisor Marawan AASTMT comparative study addendum and strict ransomware/wiper/worm exclusion) |
| [v2/V2_PLAN.md](v2/V2_PLAN.md) | Single-source-of-truth comparative-study v2 plan (strata, hybrid dormant, 6 safety guards, equal `20`-trial `5x3` CV, natural-prevalence calibration, real benign pools, `400`/`80` review cap, blind freeze) |
| [v2/FINAL_EVAL_PLAN_v2_SKELETON.md](v2/FINAL_EVAL_PLAN_v2_SKELETON.md) | Draft pre-registration skeleton for ~20-arm comparative study (`full_20`, `no_content`, `H1`–`H4`, equal `20`-trial `5x3` nested CV, `m=10` Holm + Friedman/Nemenyi + 5-axis scorecard; `[TBD]` until Stage A pilot & blind freeze) |
| [v2/REFGRAPH_SPEC.md](v2/REFGRAPH_SPEC.md) | Static referential graph specification (context-split nodes, 4 MFT states, experimental forward Prefetch hashing, training-pool IHF, 3 propagation baselines, leakage rules) |
| [v2/REFGRAPH_FEASIBILITY_V1_DEV.md](v2/REFGRAPH_FEASIBILITY_V1_DEV.md) | Step E4 read-only v1-dev referential-graph link coverage feasibility audit (`5.16%` outgoing / `10.33%` any cold-disk link rate; v2 extractor recommendations) |
| [v2/NOVELTY_VERIFICATION.md](v2/NOVELTY_VERIFICATION.md) | Step E6 prior-art verification ledger from `docs/v2/research/concept_a_gap_audit.md` (`[1]`–`[137]` cataloged with every row marked `UNVERIFIED` + 2026 anomaly flags) |
| [v2/research/concept_a_gap_audit.md](v2/research/concept_a_gap_audit.md) | Step G archived external Concept A literature/gap report tagged **`UNVERIFIED external report`** (all citations & claims `UNVERIFIED` pending primary-source checks) |
| [v2/FEATURE_PARITY_AUDIT.md](v2/FEATURE_PARITY_AUDIT.md) | Step F0 live-v1 vs offline-v2 parity audit of all 20 locked `full_20` features, confirmed `OD-V2-02` parity rulings (`2026-11-23`), and clean-image parity test procedure |
| [v2/CLEAN_IMAGE_EXTRACTION_DRYRUN.md](v2/CLEAN_IMAGE_EXTRACTION_DRYRUN.md) | Step F safe read-only extraction dry run on `/var/lib/libvirt/images/win11_base.qcow2` (`4,364` records, `19.70s` cached runtime, `99.63%` task & `99.62%` `OD-V2-20` link coverage, unchanged SHA-256) |
| [v2/CLEAN_IMAGE_PARITY_REPORT.md](v2/CLEAN_IMAGE_PARITY_REPORT.md) | Clean-image `full_20` feature-parity report (v1 live vs. v2 offline extractor) and `OD-V2-20` `v2_refgraph` link coverage verification |
| [v2/BENIGN_GENERATOR_DESIGN.md](v2/BENIGN_GENERATOR_DESIGN.md) | Step C.6 real benign workload & disjoint pool design (`src/v2/benign_generator_v2.py`, `scripts/v2_prepare_benign_pools.py`, `1,500–2,000` unique files, `6`-criterion quantization gate) |
| [v2/hardening/POINTER_CAPTURE_SPEC.md](v2/hardening/POINTER_CAPTURE_SPEC.md) | Offline unprivileged-container pointer-capture schema & v1 collector gap audit (`OD-V2-04`, `OD-V2-16`) |
| [v2/hardening/02_domain_xml_hardening.md](v2/hardening/02_domain_xml_hardening.md) | Step D libvirt domain/network XML hardening runbook (`win11` & `win11-isolated`) + `check_domain_xml.py` validator |
| [v2/hardening/03_inetsim_vm_setup.md](v2/hardening/03_inetsim_vm_setup.md) | Step D separate isolated Linux `inetsim-vm` (`192.168.150.10`) fake-internet VM setup (`OD-V2-03`) |
| [v2/hardening/08_NEGATIVE_EGRESS_AND_SIGN_OFF.md](v2/hardening/08_NEGATIVE_EGRESS_AND_SIGN_OFF.md) | Step D negative-egress verification checklist (`NEG-01`..`NEG-10`), Supervisor Marawan (AASTMT) written approval conditions, and ordered Mokh Gate 0 sign-off list |
| [v2/hardening/09_STAGE_A_PILOT_ZERO_SSH_STAGING.md](v2/hardening/09_STAGE_A_PILOT_ZERO_SSH_STAGING.md) | Zero-SSH / Zero-Guest-Agent Stage A pilot run staging specification via read-only `DFIR_STAGE` ISO-9660 virtual CD-ROM (`src/v2/pilot_staging.py`) |
| [v2/plan.md](../v2/plan.md) | Reconciled Phase 1 implementation tracker and step checklist (`Steps A, B, C.1, Concept C, C.2, E1–E7, F0, D..G`) |

## Original Phase-1 Design Specifications (`docs/specs/`)

| File | Scope |
| :--- | :--- |
| [specs/00_README.md](specs/00_README.md) | Original spec index, locked decisions, changelog, rules for AI assistants |
| [specs/01_overview_and_explanation.md](specs/01_overview_and_explanation.md) | Motivation, ML vs rules positioning, forensic admissibility rationale |
| [specs/02_feasibility_and_hardware.md](specs/02_feasibility_and_hardware.md) | Schedule feasibility, hardware budget, cut lines |
| [specs/03_requirements.md](specs/03_requirements.md) | Functional, non-functional, hardware, and acceptance requirements |
| [specs/04_approaches_and_datasets.md](specs/04_approaches_and_datasets.md) | Ranked modeling approaches, verified datasets, five model families |
| [specs/05_dataset_generation_playbook.md](specs/05_dataset_generation_playbook.md) | Lab build, run automation, labeling, leakage & string-sanitization rules |
| [specs/06_schedule_3days.md](specs/06_schedule_3days.md) | 3-day execution schedule, roles, gates |
| [specs/07_evaluation_protocol.md](specs/07_evaluation_protocol.md) | Track A & Track B split protocols, metrics, ablations, table schemas |
| [specs/08_paper_outline.md](specs/08_paper_outline.md) | Research paper skeleton |
| [specs/09_risks_and_verify.md](specs/09_risks_and_verify.md) | Verified facts, open verification items, risk register |
| [specs/10_implementation_and_prompts.md](specs/10_implementation_and_prompts.md) | Repo layout, locked 20-feature schema, guardrails, implementation prompts |
| [specs/11_prompt_E_libvirt.md](specs/11_prompt_E_libvirt.md) | Host libvirt orchestration prompt specification |
| [specs/12_operator_decisions.md](specs/12_operator_decisions.md) | Operator design rulings (`Q-S1-1`, `Q-S1-2`, etc.) |
