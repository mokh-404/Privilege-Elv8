# Project Progress

## Done
- **Step 1** (commit `b3a5a26`, `tests/test_config.py`: 7 passed):
  - Repo layout created under `docs_claude/dfir-triage-ml/` with docs `00..12`, `.gitignore`, `pytest.ini`, `requirements.in`, and pinned `requirements.txt` (57 lines, Python 3.12.16 `.venv`).
  - `src/config.py` with locked 20-feature schema, `ORACLE_FEATURES`, `RULE_FEATURES`, `META_COLUMNS`, `LABEL_COL`, `SEED = 42`, and `LOLBIN_LIST`.
  - `src/utils/repro.py` for seeding, CUDA/CPU detection, git commit hash, and run metadata.
- **Step 2** (commit `d0aba7a`, `tests/test_sanitize.py` + `tests/test_features.py`: 103 passed):
  - `src/data/sanitize.py` (FE-08 assertion + DS-10 runner footprint exclusion).
  - `src/data/features.py` (Shannon entropy + 20 locked features + isolated oracle columns; CLI flag token guard for `/sc` / `/reg`).
- **Step 3** (commit `ec995ed`, `tests/test_metrics_preprocess.py`: 12 passed):
  - `src/models/preprocess.py` (`SharedPreprocessor` + `assert_no_forbidden_inputs` leakage guard).
  - `src/eval/metrics.py` (`pr_auc`, `precision_at_k`, `recall_at_k`, `fpr_at_recall`, `threshold_at_fpr`, `bootstrap_by_group`, secondary accuracy/F1 for Track B Split 1 only).
- **Step 4 (code written & tested on synthetic data; full suite 135 passed)**:
  - `src/models/sklearn_models.py`, `src/models/mlp.py`, `src/models/autoencoder.py`.
  - `src/data/splits.py`, `src/data/cic_malmem.py`, `src/eval/run_track_b.py`.
  - `tests/test_models.py`, `tests/test_track_b.py` (including synthetic 1,000-row end-to-end Track B smoke test).

## In progress
- Step 4 real-CSV inspection and operator sign-off on distinct `Category` strings before writing `src/data/cic_malmem.py:parse_category`.

## Blocked
- **Track B `Category` parser (`src/data/cic_malmem.py:parse_category`)**: blocked on `data/external/cic_malmem_2022/Obfuscated-MalMem2022.csv` placement and operator review of the printed distinct `Category` strings (stop-and-ask rule).
- **Steps 5–8 (VM collector, libvirt automation, Track A labeling & evaluation)**: waiting for `"VM ready"` from the operator.

## Questions for the operator
- **Q-S1-1 (`artifact_key` separator)**: Doc 10 (`10_implementation_and_prompts.md` line 171) specifies `"<artifact_type>|<normalised lower-case path or key>|<name>"` (`|`), whereas the `findings.json` example in `docs/12_operator_decisions.md` uses `"::"` (`"run_key::hku\\...::updater"`). Currently `src/config.py` uses `ARTIFACT_KEY_SEP = "|"`. Should `artifact_key` stay `|` everywhere, use `::` everywhere, or convert `|` -> `::` only when exporting `findings.json`?
- **Q-S1-2 (Extra `artifact_type` categorical levels)**: Doc 10 lists 8 `artifact_type` levels (`task`, `service`, `run_key`, `startup`, `prefetch`, `amcache`, `process`, `account`). Based on the operator's additions (ShimCache, WMI subscriptions, UAC/IFEO registry keys, dropped files), `src/config.py` includes `file`, `shimcache`, `wmi_subscription`, `registry`, `other`, `na` as proposed levels in `ARTIFACT_TYPE_LEVELS` (within the locked 20-feature schema). Please confirm these extra levels are acceptable.
- **Step 4 CSV placement**: Place `Obfuscated-MalMem2022.csv` at `data/external/cic_malmem_2022/Obfuscated-MalMem2022.csv` (if not already placed) so we can run `--inspect` and obtain your confirmation before implementing `parse_category`.
