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
| [v2/OPERATOR_DECISIONS.md](v2/OPERATOR_DECISIONS.md) | Recorded v2 operator decisions (`OD-V2-01`..`OD-V2-19`: `01..06, 08..19` confirmed `2026-11-23`; `07` approval & Gate 0 pending) |
| [v2/V2_PLAN.md](v2/V2_PLAN.md) | Single-source-of-truth pilot-first v2 plan (strata, safety gate, offline extraction, labeling, blind freeze, secondary refgraph/tail/execution-delta specs) |
| [v2/FINAL_EVAL_PLAN_v2_SKELETON.md](v2/FINAL_EVAL_PLAN_v2_SKELETON.md) | Draft pre-registration skeleton for v2 (all `[TBD]` fields pending pilot & blind-test freeze) |
| [v2/REFGRAPH_SPEC.md](v2/REFGRAPH_SPEC.md) | Static referential graph specification (context-split nodes, 4 MFT states, experimental forward Prefetch hashing, training-pool IHF, 3 propagation baselines, leakage rules) |
| [v2/REFGRAPH_FEASIBILITY_V1_DEV.md](v2/REFGRAPH_FEASIBILITY_V1_DEV.md) | Step E4 read-only v1-dev referential-graph link coverage feasibility audit (`5.16%` outgoing / `10.33%` any cold-disk link rate; v2 extractor recommendations) |
| [v2/NOVELTY_VERIFICATION.md](v2/NOVELTY_VERIFICATION.md) | Step E6 prior-art verification ledger from `v2/concept_a_gap_audit.md` (`[1]`–`[137]` cataloged with every row marked `UNVERIFIED` + 2026 anomaly flags) |
| [v2/FEATURE_PARITY_AUDIT.md](v2/FEATURE_PARITY_AUDIT.md) | Step F0 live-v1 vs offline-v2 parity audit of all 20 locked `full_20` features, `OD-V2-02` `process`-row exclusion impact, and clean-image parity test procedure |
| [v2/CLEAN_IMAGE_EXTRACTION_DRYRUN.md](v2/CLEAN_IMAGE_EXTRACTION_DRYRUN.md) | Step F safe read-only extraction dry run on `/var/lib/libvirt/images/win11_base.qcow2` (`4,145` records, `69.56%` persistence/exec link coverage, unchanged SHA-256) |
| [v2/BENIGN_GENERATOR_DESIGN.md](v2/BENIGN_GENERATOR_DESIGN.md) | Step C.6 varied benign workload design (disjoint dev/blind_test profiles, unsigned PEs, services/tasks/registry) & pass/fail quantization gate (`IMP-06`) |
| [v2/hardening/POINTER_CAPTURE_SPEC.md](v2/hardening/POINTER_CAPTURE_SPEC.md) | Offline unprivileged-container pointer-capture schema & v1 collector gap audit (`OD-V2-04`, `OD-V2-16`) |
| [v2/hardening/02_domain_xml_hardening.md](v2/hardening/02_domain_xml_hardening.md) | Step D libvirt domain/network XML hardening runbook (`win11` & `win11-isolated`) + `check_domain_xml.py` validator |
| [v2/hardening/03_inetsim_vm_setup.md](v2/hardening/03_inetsim_vm_setup.md) | Step D separate isolated Linux `inetsim-vm` (`192.168.150.10`) fake-internet VM setup (`OD-V2-03`) |
| [v2/hardening/08_NEGATIVE_EGRESS_AND_SIGN_OFF.md](v2/hardening/08_NEGATIVE_EGRESS_AND_SIGN_OFF.md) | Step D negative-egress verification checklist (`NEG-01`..`NEG-10`) and exact ordered Mokh run & Gate 0 sign-off list |
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
