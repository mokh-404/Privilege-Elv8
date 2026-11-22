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
