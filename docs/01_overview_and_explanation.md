# 01. Overview and Explanation

## 1. General idea of the project

DFIR-Triage is a read-only, local triage tool for a possibly compromised Windows host. It collects artifacts (registry, scheduled tasks, services, Prefetch, Amcache, processes, files, and optionally memory), hashes them with a chain-of-custody record, applies deterministic detection rules (15 in the proposal), maps findings to MITRE ATT&CK with a confidence score, assesses persistence and exposure, and drafts a report with a local LLM.

The research paper adds a **learned prioritisation layer**: a model that ranks artifacts by how likely they are attacker-induced, so the analyst looks at the most suspicious items first. The paper compares several model families and reports which is better and why.

## 2. ML vs AI: the question that was open

**They are not two choices.**

- AI is the broad field. Machine learning is a part of it. Deep neural networks are a kind of machine learning.
- A model trained on a dataset is already AI. The professor's suggestion to use AI with techniques such as deep neural networks describes one family of ML model, not a replacement for ML.
- Both the professor and the team are right on their own points. The professor is right that such models can output decisions. The team is right that a decision from a model alone is a legal and forensic risk.

## 3. Why the model's role matters more than its label

In forensics, weight comes from evidence: artifacts collected read-only, hashed, with chain of custody, that another examiner can reproduce and explain. A model score is not evidence.

| Design | Court exposure |
|---|---|
| Model outputs "host compromised" and nothing else | High, whether it is a random forest or a deep network |
| Model ranks artifacts; every finding rests on a deterministic rule hit plus a hashed artifact; analyst signs off | Low, because the model never enters the evidentiary chain |

This is the common principle in the literature the team reviewed. It is not legal advice, and admissibility standards differ by jurisdiction. Confirm with a qualified person before claiming anything about a specific court.

## 4. The architecture the paper describes

```
Artifacts (read-only, hashed, chain of custody)
        |
Layer 1: Deterministic rules  -> FINDINGS (the proof)
        |
Layer 2: ML model             -> RANKING (which artifacts to look at first)
        |
Layer 3: Local LLM            -> DRAFT narrative, must cite artifact IDs
        |
Human analyst                 -> DECISION
```

The deep-learning work lives in Layer 2 as an experiment with five families: Random Forest and XGBoost (supervised trees), Isolation Forest (unsupervised classical), a PyTorch tabular MLP (supervised deep network) and a PyTorch deep autoencoder (unsupervised deep network).

## 5. What to tell the professor

> "We will build an AI-assisted system with three layers. Deterministic rules produce the findings, learned models prioritise them, and a local LLM drafts the report. We will compare several model families, including a neural network, and report which performs best. The model ranks and never issues the verdict, so the output stays defensible."

Fits what he asked for (AI, deep learning, decisions-support) and keeps the verdict with rules and the analyst.

## 6. What prior work says (for framing, verify before citing)

- Tiwari et al. (ISCS 2025): Volatility-derived features, five classifiers compared, XGBoost best (about 0.9999 accuracy on CIC-MalMem-2022), neural network weakest and slowest. One dataset, controlled setting. Their LLM step is qualitative only.
- DFIR-Chain (Karne et al., ICISC 2025): Volatility 3 + YARA + IOC matching + local LLM. One memory image, so the ablation is not statistically meaningful.
- Kuforiji (DFIR automation review): background only; weak source.

Why this matters for us: a near-1.0 score on CIC-MalMem-2022 indicates the dataset is easy to separate, not that the method is strong. Our paper should not chase that number.

## 7. Wording rules for the paper

- Say "prioritise", "rank", "triage score", "lead".
- Do not say "detect compromise", "determine", "verdict", "prove" about the model.
- Say "findings are produced by deterministic rules".
