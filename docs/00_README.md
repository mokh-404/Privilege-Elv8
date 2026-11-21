# DFIR-Triage: ML Research Plan (3-day scope) — Revision 2

Handoff package for developers and AI assistants. Read in order.

## File index

| File | Purpose |
|---|---|
| `00_README.md` | This index, locked decisions, changelog, rules for AI assistants |
| `01_overview_and_explanation.md` | The idea, the ML vs AI question, the admissibility reasoning, what to tell the professor |
| `02_feasibility_and_hardware.md` | Can it be done in 3 days, can the laptop do it, what is cut |
| `03_requirements.md` | Numbered requirements (functional, non-functional, hardware, acceptance) |
| `04_approaches_and_datasets.md` | Ranked approaches, verified dataset facts, the five model families |
| `05_dataset_generation_playbook.md` | Lab build, run automation, labeling, leakage and string-sanitization rules |
| `06_schedule_3days.md` | Day-by-day plan, roles, gates, cut lines |
| `07_evaluation_protocol.md` | Splits for Track A and Track B, metrics, ablations, result tables |
| `08_paper_outline.md` | Research paper skeleton |
| `09_risks_and_verify.md` | Verified facts with sources, items still unverified, risk register |
| `10_implementation_and_prompts.md` | Repo layout, locked 20-feature schema, guardrail block, four coding prompts |

## Terminology

- **Track A:** our generated host-artifact dataset (the core contribution).
- **Track B:** the public CIC-MalMem-2022 benchmark (`Obfuscated-MalMem2022.csv`).
- **Benign rows (Track A):** `baseline` plus `benign_drift`.

## Locked decisions

| ID | Decision |
|---|---|
| D1 | ML and AI are not alternatives. We compare ML and deep-learning families and report which is better per task. |
| D2 | Layering: **rules prove, the model ranks, the local LLM drafts, the human decides.** A model score is a lead, never a verdict or evidence. |
| D3 | Dataset strategy: **Hybrid-lite.** Track A (generated, one VM profile) plus Track B (CIC-MalMem-2022, two splits). |
| D4 | Splits are grouped (by technique on Track A, by family on Track B's second split). A test set is frozen before any tuning. |
| D5 | No live malware. Atomic Red Team style simulations only, in an isolated lab. |
| D6 | LLM is local only and not part of the measured results. |
| D7 | Red/blue rounds are a stretch goal, scored on a frozen holdout. |
| D8 | Metrics: PR-AUC, precision@k, recall@k, FPR on clean baseline, runtime. Not accuracy. |
| D9 | **Five mandatory model families:** Random Forest, XGBoost, Isolation Forest, PyTorch tabular MLP, PyTorch deep autoencoder. Logistic regression is an optional sanity baseline only. |
| D10 | **SHAP is mandatory** for the tree models and the MLP. Autoencoder and Isolation Forest use per-feature reconstruction error and permutation importance. |
| D11 | **Anti-leakage rules (do not weaken):** (1) `created_in_window` and `file_age_minutes` are oracle features, excluded from main models; (2) benign noise runs **inside the attack window**, interleaved with the attack step; (3) baseline rows are deduplicated and assigned to train or test by hash of `artifact_key`. |
| D12 | **String sanitization:** no simulation keywords in any artifact the collector sees, enforced by an automated assertion (see `05` and `10`). |
| D13 | MVP lab footprint: **one** comprehensive Windows VM profile. A second profile is a Day-2 stretch. |

## Assumptions (confirm; each changes the plan if false)

- A1: A collector exists or is written on Day 1 (minimal spec in `03_requirements.md`, FE-01 to FE-06).
- A2: At least 3 people work in parallel.
- A3: Windows host with hardware virtualization enabled (SVM on AMD).
- A4: The professor wants the model-family comparison, not one named model (confirmed by the team).

## Revision 2 changelog

| # | Change | Files |
|---|---|---|
| 1 | Deep autoencoder and PyTorch MLP made mandatory; SHAP mandatory; LR demoted to optional sanity baseline | 03, 04, 07, 10 |
| 2 | CIC-MalMem-2022 facts replaced with primary-source checks; `Category` must be dropped; two Track B splits | 04, 07, 09 |
| 3 | Day-1 footprint cut to one VM; 15 to 18 techniques; 45 to 65 runs | 02, 03, 05, 06 |
| 4 | String-sanitization rule and assertion | 05, 10 |
| 5 | Repo layout, 20-feature schema, coding prompts | 10 |
| 6 | Benign noise moved **inside** the attack window (previous revision ran it before the window, which did not match the intended leakage rule) | 05 |
| 7 | Consequential edits for consistency: bootstrap by run (only 5 held-out techniques), runner-footprint exclusion, family-rotation evaluation on Track B, SMOTE caveat on benign FPR | 05, 07, 09 |

## Rules for AI assistants using this package

1. Do not make the model the source of a verdict. Use "ranks" or "prioritises".
2. Never split data randomly by row on Track A. Track B's stratified split exists only to reproduce a published setup and must be labelled as leaky.
3. Never report accuracy as a headline metric.
4. Do not write result numbers into the paper. Use the placeholder tables.
5. Do not invent citations. Anything under "unverified" in `09_risks_and_verify.md` must be checked first.
6. Do not add live malware, cloud LLM calls, or autonomous remediation.
7. Do not weaken D11 or D12.
8. Time, size and score figures in these files are planning estimates, not measurements.
