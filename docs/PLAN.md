# Implementation Plan (DFIR-Triage / REVENANT Phase 1 ML Benchmark)

## Environment & Python Installation
- **Python version**: `python@3.12.16` installed via `mise` (`/home/fsociety/.local/share/mise/installs/python/3.12.16/bin/python3`), because Python 3.14.8 on the host lacks prebuilt wheel support for parts of the ML/explainability stack (`torch`, `xgboost`, `shap`).
- **Virtual environment**: isolated `.venv/` at the repository root (`/home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/.venv`).
- **Pinned dependencies**: top-level specs live in `requirements.in`; the exact resolved and pinned dependency freeze lives in `requirements.txt` (generated via `pip freeze`).
- **Device selection**: `src/utils/repro.py:get_device()` auto-detects CUDA if available (`torch.cuda.is_available()` and test tensor allocation succeeds) and falls back cleanly to CPU. Setting `DFIR_FORCE_CPU=1` forces CPU-only execution.

## Eight-Step Roadmap (Aligned with `docs/12_operator_decisions.md`)
1. **Step 1 — Repo skeleton & config**: directory layout (`collector/`, `lab_automation/`, `data/`, `src/`, `tests/`, `results/`, `docs/`), pinned `requirements.txt`, locked 20-feature schema and seeds (`SEED = 42`) in `src/config.py`, reproducibility utilities in `src/utils/repro.py`, and `pytest` setup.
2. **Step 2 — Sanitization & feature extractor**: `src/data/sanitize.py` (FE-08 forbidden-token assertion, DS-10 runner-footprint exclusion) and `src/data/features.py` (Shannon entropy edge cases + the 20 locked features, plus isolated oracle columns) with unit tests.
3. **Step 3 — Shared preprocessing & ranking metrics**: `src/models/preprocess.py` (shared `ColumnTransformer`, `assert_no_forbidden_inputs` leakage guard) and `src/eval/metrics.py` (`pr_auc`, `precision_at_k`, `recall_at_k`, `fpr_at_recall`, `threshold_at_fpr`, `bootstrap_by_group`, secondary accuracy/F1 for Track B Split 1 only) with unit tests.
4. **Step 4 — Five-model suite & Track B (`CIC-MalMem-2022`)**:
   - `src/models/sklearn_models.py` (`RandomForestArm`, `XGBoostArm`, `IsolationForestArm`, optional `LogisticRegressionArm`).
   - `src/models/mlp.py` (`TabularMLPNet` / `TabularMLPArm`, exact layer spec, `BCEWithLogitsLoss(pos_weight=...)`, AdamW, early stopping on grouped validation PR-AUC).
   - `src/models/autoencoder.py` (`DeepAutoencoderNet` / `DeepAutoencoderArm`, exact layer spec, benign-only training & early stopping on benign validation MSE).
   - `src/data/splits.py` (Track A key bucketing + Track B Split 1 leaky, Split 2 family-grouped + benign k-means clusters, 5-rotation generator).
   - `src/data/cic_malmem.py` (shape check `(58596, 57)`, `Category` & `Class` inspection; `parse_category` intentionally gated until operator inspects real `Category` values).
   - `src/eval/run_track_b.py` (all 5 arms across Split 1, Split 2, and optional 5-rotation, plus `--smoke` test mode).
5. **Step 5 — Read-only PowerShell collector** (`collector/Collect-Artifacts.ps1`, Prompt A) after VM readiness (`HKU\<SID>` user hives, `sshd.exe`/wrapper filtering, Prefetch, AppCompatCache, soft-fail VSS Amcache, SHA-256 manifest).
6. **Step 6 — libvirt lab automation** (`lab_automation/`, Prompt E): self-contained 16-technique `techniques.yaml` (11 dev + 5 holdout across 6 tactics × 3 variants + 3 control boots = 51 runs), `benign_noise.ps1`, `run_one.py`, `run_all.py`, dry-run check.
7. **Step 7 — Deterministic rules, labeler, dataset freeze**: `src/rules/deterministic_rules.py` (15 rules), `src/data/labeler.py`, baseline/drift deduplication, review-sample export, dataset freeze + test-set hash lock.
8. **Step 8 — Track A evaluation, ablations, SHAP, figures, and REVENANT `findings.json` export**: `src/eval/run_track_a.py` (dev CV, `--final` single evaluation), `src/eval/ablations.py`, `src/eval/shap_explain.py`, `src/eval/figures.py` (300-DPI PNG/PDF), and `src/eval/export_findings.py`.
