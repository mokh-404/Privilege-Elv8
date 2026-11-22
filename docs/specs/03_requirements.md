# 03. Requirements — Rev 2

Priority: **M** must (3-day MVP), **S** should, **C** could (stretch).

## 1. Scope

Produce a labelled host-artifact dataset (Track A), compare five model families that rank artifacts by attacker-induced likelihood, run the CIC-MalMem-2022 benchmark (Track B), explain results with SHAP, and write the paper. The ranking model never produces a verdict.

## 2. Functional requirements

### Lab and data generation (DS)

| ID | Requirement | Pri |
|---|---|---|
| DS-01 | **One** comprehensive Windows 10/11 VM profile: 6 to 8 GB RAM, 60 GB disk. Pre-installed with office-style and developer tools: Python, Git, VS Code, 7-Zip, Notepad++, Sysinternals, and local (offline) browser pages. | M |
| DS-02 | Clean base VM with a baseline snapshot taken after setup; linked clones if used. | M |
| DS-03 | A **randomized benign-noise script runs inside every attack run**, interleaved with the attack step so that `benign_drift` artifacts fall in the same time window as `attacker_induced` artifacts. Include legitimate PowerShell and PsExec use. | M |
| DS-04 | Select **15 to 18 curated offline-safe techniques**: 10 to 12 development techniques across 5 to 6 tactics, plus **5 frozen holdout techniques** from at least 4 tactics. | M |
| DS-05 | 3 to 4 parameter variants per technique, for **45 to 65 automated runs**, started unattended on Day 1 evening. | M |
| DS-06 | Lab network is isolated during runs; prerequisites staged beforehand. | M |
| DS-07 | Each run records metadata and a host-side provenance log (which launcher produced which action). | M |
| DS-08 | Second VM profile (for example a more developer-heavy or admin-heavy clone) on Day 2 if gates are met. | S |
| DS-09 | Parameterize all payloads so the strings `Atomic`, `AtomicRedTeam`, `ART`, technique IDs and the runner's module name never appear in paths, filenames, registry values, task names, service names or command lines of technique artifacts. | M |
| DS-10 | Runner footprint (Atomic module folder, execution logs, PowerShell history from the runner) is excluded from collection or dropped from the dataset and logged. | M |
| DS-11 | Red/blue rounds on a frozen holdout. | C |

### Feature extraction (FE)

| ID | Requirement | Pri |
|---|---|---|
| FE-01 | Collect read-only: scheduled tasks, services, Run/RunOnce keys, startup folder, Prefetch, Amcache, running processes (parent, command line), local accounts. | M |
| FE-02 | One row per artifact with a stable `artifact_key` (type + normalised path or key + name). | M |
| FE-03 | Compute the locked 20 features in `10_implementation_and_prompts.md`. | M |
| FE-04 | SHA-256 for each collected file artifact, plus a manifest with timestamps (chain-of-custody minimum). | M |
| FE-05 | Collection must not modify the host. | M |
| FE-06 | Export Parquet or CSV with a data dictionary. | M |
| FE-07 | Memory features via Volatility 3 (pslist, psxview, dlllist, ldrmodules, malfind, svcscan, netscan, handles, callbacks). | C |
| FE-08 | **Sanitization assertion:** before computing `name_length`, `name_entropy`, `cmdline_length`, `cmdline_entropy` and any other string feature, an automated check asserts zero matches of the forbidden-token patterns (`10_implementation_and_prompts.md`) on all feature-input strings. A match fails the build and lists the offending rows. | M |
| FE-09 | Feature extraction is deterministic and unit-tested for entropy edge cases (empty string, single repeated character, random bytes). | M |

### Labeling (LB)

| ID | Requirement | Pri |
|---|---|---|
| LB-01 | Labels `attacker_induced`, `benign_drift`, `baseline` from ground truth: baseline diff, technique definition, and the host-side provenance log (**not** time windows, and **not** the detection rules). | M |
| LB-02 | Human review of at least 10% of `attacker_induced` rows and 100 `benign_drift` rows; disagreements logged. | M |
| LB-03 | Baseline rows deduplicated across runs and assigned to train or test by hash of `artifact_key`. | M |
| LB-04 | Labeling script is deterministic and versioned. | M |

### Modeling (ML)

| ID | Requirement | Pri |
|---|---|---|
| ML-01 | Random Forest (supervised classical tree ensemble). | M |
| ML-02 | XGBoost (supervised gradient-boosted trees). | M |
| ML-03 | Isolation Forest (unsupervised classical), trained strictly on benign rows. | M |
| ML-04 | PyTorch tabular MLP: `Input -> 128 -> BatchNorm1d -> ReLU -> Dropout(0.3) -> 64 -> BatchNorm1d -> ReLU -> Dropout(0.2) -> 32 -> ReLU -> 1`; `BCEWithLogitsLoss(pos_weight=num_benign/num_attack)`; AdamW; early stopping on validation PR-AUC. | M |
| ML-05 | PyTorch deep autoencoder: `Input -> 64 -> 32 -> 16 -> 32 -> 64 -> Input`; trained strictly on benign rows with MSE; anomaly score = per-row reconstruction MSE. | M |
| ML-06 | Logistic regression as a quick sanity baseline. | S |
| ML-07 | Class imbalance handled by weights, never by resampling the evaluation sets. | M |
| ML-08 | Hyperparameter search only on development folds. | M |
| ML-09 | **SHAP (mandatory):** `TreeExplainer` for XGBoost and Random Forest; `GradientExplainer` (or `KernelExplainer` on a background sample) for the PyTorch MLP. | M |
| ML-10 | Autoencoder and Isolation Forest explained with per-feature reconstruction error and permutation importance. | S |
| ML-11 | One shared preprocessing pipeline (imputation with missing-indicator, one-hot, scaling fitted on training data only) used by every arm. | M |

### Evaluation (EV)

| ID | Requirement | Pri |
|---|---|---|
| EV-01 | Freeze the Track A test set before tuning; store its hash. | M |
| EV-02 | Track A: grouped split by technique (see `07`). | M |
| EV-03 | Report PR-AUC, precision@k, recall@k, FPR on clean baseline, training and inference time. | M |
| EV-04 | Track B: **`Category` is dropped from the feature matrix** before binary classification; `Class` is the label. An assertion checks that neither column is in `X`. | M |
| EV-05 | Track B split 1: stratified 80/20, used **only** to reproduce and critique Tiwari et al.'s near-saturated score, labelled as leaky in every table. | M |
| EV-06 | Track B split 2: family-grouped holdout of 3 unseen families (1 ransomware, 1 spyware, 1 trojan), with unseen-malware recall at fixed benign FPR. | M |
| EV-07 | Track B split 2 repeated over a rotation so every family is held out once (5 rotations, one family per category per rotation). | S |
| EV-08 | Ablations: with and without rule-hit features; oracle features as an upper bound only; feature groups; training-set size; unsupervised trained on baseline only vs baseline + benign_drift. | S |
| EV-09 | Uncertainty: repeated grouped CV on dev; bootstrap over runs on the frozen test set; per-technique results. | S |
| EV-10 | Red/blue per-round holdout curve. | C |

### Documentation (DOC)

| ID | Requirement | Pri |
|---|---|---|
| DOC-01 | Data dictionary, run log, README to reproduce every table. | M |
| DOC-02 | Paper sections per `08_paper_outline.md`. | M |
| DOC-03 | Each result in the paper points to a script and an output file. | S |

## 3. Non-functional requirements

| ID | Requirement |
|---|---|
| NF-01 | Reproducible: fixed seeds, pinned versions, one command per table. |
| NF-02 | Local only: no data leaves the machine, no cloud LLM. |
| NF-03 | Safe: no live malware, isolated lab, snapshot revert after each run. |
| NF-04 | Runs on the target laptop (24 GB RAM, CPU-only training is sufficient). |
| NF-05 | Collector run time per VM under about 2 minutes (estimate; measure Day 1). |
| NF-06 | Ranking inference over one host's artifacts completes in seconds on CPU. |
| NF-07 | The top-ranked artifacts show the features that drove the score. |

## 4. Constraints

- C-01: The model ranks. Only deterministic rules produce findings.
- C-02: Read-only collection.
- C-03: No accuracy-only reporting.
- C-04: No random row-level splits on Track A.
- C-05: Three days, three or more people.
- C-06: Laptop as in `02_feasibility_and_hardware.md`.

## 5. Acceptance criteria (3-day MVP)

- [ ] At least **45 completed runs** with metadata and provenance logs; no missing collections.
- [ ] Sanitization assertion passes on the full dataset.
- [ ] Labeled dataset exported with data dictionary and review log.
- [ ] Frozen Track A test set (5 techniques) with recorded hash, untouched during tuning.
- [ ] All five mandatory model families trained and evaluated on the same splits.
- [ ] Track B tables for both splits, with the stratified split labelled as leaky.
- [ ] SHAP outputs for XGBoost, Random Forest and the MLP.
- [ ] Result tables and at least four 300-DPI figures.
- [ ] Paper draft with every section, results taken from real output, limitations listed.
- [ ] Repository runs end to end from a clean checkout.
