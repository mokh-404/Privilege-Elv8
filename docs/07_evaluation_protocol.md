# 07. Evaluation Protocol — Rev 2

## 1. Tracks and arms

| Track | Data | Arms |
|---|---|---|
| A: host-artifact ranking (core) | Generated | Random Forest, XGBoost, Isolation Forest, PyTorch MLP, PyTorch autoencoder (+ optional LR) |
| B: memory-dump classification | CIC-MalMem-2022 | Same five arms (+ optional LR) |

Compare arms within a track only.

## 2. Track A splits

1. **Group key:** `technique_id`. All variants of a technique stay together.
2. **Frozen test set:** the **5 holdout techniques** (from at least 4 tactics, chosen by seeded draw before looking at data). Store the technique list and the dataset hash. Nothing is tuned on it.
3. **Development set:** the other 10 to 12 techniques. Use `StratifiedGroupKFold(n_splits=5)` grouped by technique for tuning and model selection (2 to 3 techniques per fold).
4. **Benign rows** (`baseline` and `benign_drift`): assign each `artifact_key` by hash. Example: `h = int(sha256(artifact_key)[:8], 16) % 100`; `h >= 75` goes to the test pool; `h < 75` is development, with dev fold = `h % 5`. A benign key never appears on both sides.
5. **Unsupervised arms** train on benign rows of the training split only. No attack row is seen in training.
6. **Early stopping** (MLP) uses an inner validation split grouped by technique within the training folds. The AE early-stops on benign validation reconstruction loss.
7. **Final evaluation:** refit on all development data with the chosen hyperparameters, evaluate **once** on the frozen test set.
8. No leave-one-profile-out check in the MVP (one profile). If the second profile exists, add it as exploratory.

## 3. Track B splits (CIC-MalMem-2022)

Setup for both splits:
- Load the CSV and assert shape `(58596, 57)`.
- Inspect `Category` values; write a parser for the 15 families once you have seen the real strings; assert exactly 15 families plus benign.
- **Label = `Class`** (`Benign` vs `Malware`).
- **Drop `Category` from `X`** and assert that neither `Class` nor `Category` is in `X` (EV-04).

### Split 1: standard stratified 80/20 (leaky by construction)

Purpose: reproduce and critique Tiwari et al. 2025's roughly 0.9999 accuracy only.
- Stratified by `Class`, fixed seed.
- Label this split **"leaky"** in every table and caption. Reason: about 10 dumps per malware sample at 15-second gaps, and SMOTE-synthesised benign rows, can put near-duplicates on both sides.
- Do not use it to rank the model families.

### Split 2: family-grouped holdout (the real test)

- Hold out **3 unseen families: 1 ransomware, 1 spyware, 1 trojan** (for example drawn by a seeded random choice, seed recorded, before training). All rows of those families go to test.
- Malware training rows: the remaining 12 families.
- Benign rows: cannot be grouped by family or sample. Reduce leakage by clustering benign rows (for example k-means with about 50 clusters on the training-scaled features) and assigning **clusters** to train or test. This is an approximation for SMOTE twins, not a guarantee.
- Report: PR-AUC, **recall on unseen-family malware at fixed benign FPR** (1% and 5%, threshold set on a benign validation portion), runtime.
- **Caveat to print with the table:** benign false-positive rates are likely optimistic because SMOTE twins cannot be fully separated.

### Rotation (EV-07, Should)

Five rotations, where rotation *i* holds out the *i*-th family of each category, so every family is held out exactly once. Report mean and range across rotations. This removes dependence on which 3 families were chosen.

## 4. Metrics

| Metric | Use |
|---|---|
| **PR-AUC** (average precision) | Headline for both tracks |
| **Precision@k / Recall@k** (k = 10, 50, 100 artifacts per host) | Track A, analyst workflow |
| **FPR on clean baseline at fixed recall (for example 0.9)** | Track A |
| **Unseen-family recall at fixed benign FPR** | Track B split 2 |
| Accuracy | **Secondary only**; reported for Track B split 1 to compare with the literature |
| ROC-AUC, F1 | Secondary |
| Training time, inference time per 1,000 rows | Practicality |

## 5. Uncertainty

- Dev: repeat grouped CV with 3 seeds; report mean and standard deviation.
- **Frozen test set: only 5 techniques.** Resampling techniques gives almost no information. So:
  - bootstrap over **runs** (`run_id`) within technique for confidence intervals, and say these intervals cover run-to-run variation, **not** generalisation across techniques;
  - report **per-technique** results in a table;
  - do not claim significance between arms unless intervals clearly separate and the per-technique ordering agrees.
- Track B rotation (if run) gives a direct spread across held-out families.

## 6. Ablations

| Ablation | Question |
|---|---|
| With vs without `rule_hit_count` | Does the model add anything beyond the rules? |
| With oracle features (`created_in_window`, `file_age_minutes`) | Upper bound only; shows how much trivial proxies inflate scores |
| Feature groups removed (path, command line, signature, registry) | Which signals matter? |
| Training fraction (25%, 50%, 100% of dev data) | Does the MLP or AE need more data? |
| Unsupervised trained on baseline only vs baseline + `benign_drift` | Does exposure to benign drift help? |
| Isolation Forest and AE vs supervised arms | Are labels needed? |

## 7. Explainability (mandatory)

- **XGBoost and Random Forest:** SHAP `TreeExplainer`.
- **PyTorch MLP:** SHAP `GradientExplainer`, or `KernelExplainer` on a background sample of about 100 rows if the gradient version fails; explain a few hundred test rows.
- Aggregate one-hot columns back to the original 20 features for comparison.
- Compare top-10 feature rankings across RF, XGBoost and MLP (rank correlation).
- **Autoencoder:** per-feature reconstruction error contribution. **Isolation Forest:** permutation importance.
- Error analysis: the top 20 false positives and top 20 false negatives per best arm, each with technique and a one-line reason.

## 8. Reporting why one family won

State a hypothesis only after looking at the outputs. Support it with at least one of: SHAP comparison, training-size curve, error analysis, or runtime. If two arms are within the intervals, say they are indistinguishable on this data. With 5 held-out techniques, say plainly that conclusions about generalising to new techniques are tentative.

## 9. Result tables (leave empty until experiments run)

**T1: Track A, frozen test set**

| Arm | PR-AUC | P@10 | P@50 | R@50 | FPR @ R=0.9 | Train time | Infer time |
|---|---|---|---|---|---|---|---|
| Random Forest | | | | | | | |
| XGBoost | | | | | | | |
| Isolation Forest | | | | | | | |
| PyTorch MLP | | | | | | | |
| PyTorch autoencoder | | | | | | | |
| (opt.) Logistic regression | | | | | | | |

**T2a: Track B split 1, stratified 80/20 (leaky)**: PR-AUC, accuracy, F1 per arm. Caption states it is leaky and reproduces the literature setup.

**T2b: Track B split 2, family-grouped holdout**: PR-AUC, unseen-family recall at 1% and 5% benign FPR, per arm; rotation mean and range if run.

**T3: Ablations** (arm x ablation, PR-AUC). **T4: Dataset statistics** (runs, techniques, tactics, rows per label, benign vs attack, holdout positives). **T5: Per-technique results on the frozen test set.**

**Figures:** PR curves (T1); precision@k with run-level intervals; FPR at fixed recall; training-size curve; SHAP summary for XGBoost; SHAP rank comparison across RF, XGBoost, MLP; Track B split 1 vs split 2 comparison; ablation bars; (stretch) per-round holdout curve.
