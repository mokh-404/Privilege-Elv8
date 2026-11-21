# 06. Three-Day Schedule — Rev 2

Assumes 3 to 4 people, about 8 to 10 working hours per day. Durations are estimates.

## 1. Roles

| Role | Responsibilities |
|---|---|
| A: Lab and runs | One VM, snapshots, techniques, benign-noise script, run automation, unattended runs |
| B: Collector, features, labeling | Collector, 20 features, sanitization assertion, labeling script, data dictionary |
| C1: Classical ML and Track B | Splits, Random Forest, XGBoost, Isolation Forest, Track B (both splits), metrics |
| C2: Deep learning, SHAP, figures | PyTorch MLP and autoencoder, SHAP, 300-DPI figures (with 3 people, C1 and C2 are one person and D is shared) |
| D: Paper | Related work, methodology, results text, limitations |

## 2. Day 0 (1 to 2 hours)

Checklist in `02_feasibility_and_hardware.md`. Download Windows ISO, Atomic Red Team, CIC-MalMem-2022. Agree the locked schema in `10_implementation_and_prompts.md`.

## 3. Day 1: one VM, collector, runs started

| Time | A | B | C1 | C2 | D |
|---|---|---|---|---|---|
| Morning | Build the single VM (office + developer tools), baseline snapshot | Collector (Prompt A) on the live VM | Track B loader; assert shape (58,596 x 57); inspect `Category`; both splits | Preprocessing pipeline; PyTorch MLP and autoencoder skeletons, trained on Track B first | Intro, general idea, related work |
| Midday | Choose 15 to 18 techniques; parameterize payloads (no forbidden tokens); benign-noise script | Feature extractor + sanitization assertion + unit tests (Prompt B) | RF, XGBoost, Isolation Forest on Track B | MLP and AE debugging on Track B | Methodology skeleton |
| Afternoon | `run_one.py`, `run_all.py` (resume, disk guard); 3 dry runs; measure run time | Labeling script v0 with provenance log; dry-run labels | Metrics code (PR-AUC, P@k, FPR at recall) | Metrics integration; shared pipeline test | Dataset section draft |
| Evening | **Start the unattended batch (45 to 65 runs, one VM)** | Check first outputs for sanitization failures | Track B tables (both splits) done | Track B DL results done | |

**Gate G1 (end of Day 1):**
- [ ] Collector produces rows on the VM.
- [ ] Sanitization assertion passes on dry-run output.
- [ ] At least 10 labelled dry or real runs exist; run time per run measured.
- [ ] Unattended batch started.
- [ ] Track B tables exist for all five families.

If G1 fails on the lab side: reduce to 12 techniques (8 dev + 4 holdout) and tell the team lead. Do not start a second VM.

## 4. Day 2: finish data, freeze, tune

| Time | A | B | C1 | C2 | D |
|---|---|---|---|---|---|
| Morning | Monitor runs; fix failures; (stretch) clone second profile only if G1 passed and the batch is on track | Label completed runs; human review sample (10% attack, 100 drift) | Prepare Track A splits (hash assignment for benign keys) | MLP and AE adapted to Track A | Methodology text: lab, labeling, leakage rules |
| Midday | Stop runs at the target; archive logs | Fix labeling rules where review disagrees; re-label | Dev-fold tuning (RF, XGBoost, IF) | Dev-fold tuning (MLP, AE) | Results skeleton with placeholder tables |
| Afternoon | Optional stretch runs | **Freeze dataset v1 and the test set; record hash (G2)** | Full dev-fold results | Full dev-fold results | Related work polish |
| Evening | | Data dictionary, dataset statistics | Track B family rotation (EV-07) | SHAP code ready on dev models (not the test set) | |

**Gate G2 (late Day 2):**
- [ ] At least 45 completed runs.
- [ ] Dataset frozen, test set hash recorded.
- [ ] Human review done, rules fixed.
- [ ] Count of attacker-induced rows in the 5 holdout techniques recorded.

If G2 fails: freeze what exists and state the sample size honestly.

## 5. Day 3: final evaluation, SHAP, paper

| Time | Everyone |
|---|---|
| Morning | C1 and C2: evaluate every arm on the frozen test set **once**. B: oracle and rule-hit ablations, error analysis. A: help with ablations and reproducibility. |
| Midday | SHAP for XGBoost, Random Forest, MLP; reconstruction-error and permutation importance for AE and Isolation Forest. Figures at 300 DPI (Prompt D). |
| Afternoon | D and all: results and discussion text; limitations; ethics. Stretch: red/blue round figure. |
| Evening | Clean-checkout reproducibility run; proofreading. |

**Gate G3 (start of Day 3):** no more changes to data or the test set. New findings are exploratory.

## 6. Cut list (apply in order if behind)

1. Red/blue rounds (already stretch).
2. Second VM profile (already stretch).
3. Memory add-on.
4. Track B family rotation (keep the single grouped split).
5. Logistic regression and the training-size curve.
6. Reduce techniques to 12 (8 dev + 4 holdout).

**Never cut:** grouped splits, frozen test set, the three leakage rules, the sanitization assertion, PR-AUC reporting, human label review, the limitations section, the five mandatory families, SHAP for the tree models and MLP.

If the ML role is overloaded, drop the MLP's SHAP to permutation importance only after flagging it to the team lead, because SHAP is a stated requirement.

## 7. Overnight checklist

- [ ] Charger connected, sleep disabled, laptop elevated.
- [ ] `run_all.py` resumes after a crash and logs failures.
- [ ] Disk guard active.
- [ ] Lab VM's network adapter disabled.
- [ ] First 3 runs succeeded and passed the sanitization assertion before leaving.
- [ ] No other heavy process (LLM, large training) competing for RAM with the VM.
