# 08. Research Paper Outline

Maps to the sections the professor asked for: general idea, introduction, methodology (model, datasets, algorithms), results of the model, and results comparing algorithms with reasons.

Rule: write text only from real outputs. Do not pre-write result claims.

## Working title options

- "Prioritising Host Artifacts in DFIR Triage: A Comparison of Machine Learning Rankers under a Rules-Prove Design"
- "Learned Prioritisation for Forensic Triage Without Learned Verdicts"

## Abstract (write last, 150 to 200 words)

Problem, approach (rules prove, ML ranks, LLM drafts), dataset, models compared, headline result with metric and interval, main limitation.

## 1. General idea of the project

- One paragraph: read-only local triage of a possibly compromised Windows host.
- The three layers and the human decision (diagram from `01_overview_and_explanation.md`).
- The research question: which ML family ranks attacker-induced artifacts best under grouped evaluation, and at what cost?

## 2. Introduction

- Why triage is needed (volume of artifacts, analyst time, small teams such as helpdesk and MSSP).
- Why a model verdict is a problem for admissibility, and why ranking is not. State that this is not legal advice and varies by jurisdiction.
- Gap: no public labelled dataset known to the authors for host-artifact ranking (verify before stating).
- Contributions: (1) a generated labelled artifact dataset and the method to build it, (2) a grouped evaluation protocol, (3) a comparison of model families, (4) the design principle.

## 3. Related work (short)

- Tiwari et al. 2025: ML on memory features plus an LLM for investigation. Note: one dataset, near-perfect scores that indicate an easy dataset, qualitative LLM evaluation.
- DFIR-Chain, Karne et al. 2025: Volatility 3 + YARA + IOC + local LLM; one-image evaluation.
- Kuforiji 2025 review: use only for framing limitations; cite primary standards directly (GDPR, ISO/IEC 27037, 27043, NIST SP 800-61, 800-86; verify each).
- Position: we differ by host-wide artifacts (not memory only), chain of custody, and a grouped evaluation.

## 4. Methodology

### 4.1 System design
Layers, data flow, read-only collection, chain of custody.

### 4.2 Datasets
- Track A (generated): one VM profile, interleaved benign-noise script, techniques table (technique, tactic, variants, dev or holdout), run counts, row counts per label, labeling rules, human review result, sanitization rule.
- Track B (CIC-MalMem-2022): source, 58,596 records, 2,916 malware samples, 10 dumps per sample at 15 s gaps, SMOTE on benign, 15 families, 2 GB Windows 10 VM, Volatility 2.6. State that the random split is leaky and why.

### 4.3 Features
Feature table from the schema, excluded features and why (leakage rules).

### 4.4 Algorithms (the models)
For each arm: what it is, why included, hyperparameter search ranges, class imbalance handling.
- Five families: Random Forest, XGBoost, Isolation Forest (unsupervised, benign only), PyTorch tabular MLP (exact architecture), PyTorch deep autoencoder (exact architecture, benign only). Optional logistic regression as a sanity baseline.

### 4.5 Evaluation protocol
Track A grouped splits and hash-assigned benign keys, frozen test set of 5 techniques, Track B split 1 (leaky, reproduction only) and split 2 (family-grouped), metrics, uncertainty (run-level bootstrap, per-technique table), ablations, SHAP.

## 5. Results of the model

- Dataset statistics (Table T4).
- Per-arm results on the frozen test set (Table T1) with intervals.
- Track B (Tables T2a and T2b): split 1 reproduces the saturated literature setup and is labelled leaky; split 2 shows unseen-family performance. Say that the contrast between the two is evidence about leakage, and note the benign-FPR caveat.
- Figures: PR curves, precision@k.

## 6. Results: which algorithm was better and why

- Ranking of arms by PR-AUC and precision@k, with intervals.
- Reasons, each tied to evidence: SHAP comparison across RF, XGBoost and MLP, reconstruction-error analysis for the autoencoder, training-size curve (does the deep model need more data?), error analysis, runtime.
- Ablations: effect of rule-hit features, oracle features, feature groups.
- Unsupervised vs supervised: are labels worth the cost?
- (Stretch) per-round holdout curve.

## 7. Discussion

- What the ranking buys an analyst (precision@k in plain terms).
- Why the verdict stays with rules and the analyst.
- Practicality on a laptop (training and inference time).

## 8. Limitations (must be honest)

- One VM profile, 15 to 18 techniques, simulated rather than real attacks; Defender configuration in the lab; only 5 held-out techniques, so intervals cover run-to-run variation, not generalisation across techniques.
- Labels come from simulation ground truth plus partial human review.
- CIC-MalMem-2022 is pre-extracted with Volatility 2.6, not truly fileless, and benign false-positive rates are optimistic because SMOTE twins cannot be fully separated.
- Memory features from the generated lab not evaluated (if cut).
- LLM layer not evaluated quantitatively.
- Results may not transfer to other Windows versions or real intrusions.

## 9. Ethics and safety

- No live malware; isolated lab; read-only collection; local processing only.
- Dual-use consideration for published simulation scripts.
- Admissibility: model outputs are leads, not evidence.

## 10. Conclusion and future work

Larger and more diverse profiles, real incident data with consent, memory features, red/blue rounds, quantitative LLM evaluation.

## References checklist

- [ ] Every cited paper opened and checked (see `09_risks_and_verify.md`).
- [ ] Dataset citations include version and licence.
- [ ] Standards cited from the primary source.

## Figures and tables list

Architecture diagram; lab diagram; techniques table; feature table; T1 to T4; PR curves; precision@k; feature importance; training-size curve.
