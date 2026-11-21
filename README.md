# DFIR-Triage ML (`dfir-triage-ml`)

Learned artifact prioritisation layer for local, read-only Windows forensic triage (**rules prove, the model ranks, the human decides**).

- **Track A (core)**: generated host-artifact dataset from an isolated Windows 11 lab VM, grouped strictly by `technique_id` with hash-bucketed benign keys.
- **Track B (benchmark)**: `CIC-MalMem-2022` (`Obfuscated-MalMem2022.csv`) evaluated under both a leaky stratified 80/20 reproduction split (`LEAKY`) and a family-grouped holdout split.
- **Mandatory model families**: Random Forest, XGBoost, Isolation Forest (benign-only), PyTorch Tabular MLP, and PyTorch Deep Autoencoder (benign-only), plus optional Logistic Regression sanity baseline.

## Environment Setup
Python **3.12** is used in `.venv` (installed via `mise` because Python 3.14 lacks prebuilt wheels for parts of the ML stack). Exact pinned packages are recorded in `requirements.txt`.

```bash
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

CUDA is auto-detected when available (`src/utils/repro.py:get_device()`) with clean CPU fallback. Set `DFIR_FORCE_CPU=1` to force CPU execution.

## Running Tests
```bash
.venv/bin/pytest
```

## Track B (`CIC-MalMem-2022`)
Place `Obfuscated-MalMem2022.csv` at `data/external/cic_malmem_2022/Obfuscated-MalMem2022.csv`, then inspect distinct `Category` values before writing/enabling the family parser:

```bash
.venv/bin/python -m src.data.cic_malmem --inspect
```

Run Track B (Split 1 leaky + Split 2 family-grouped; add `--rotate` for 5-family rotation, or `--smoke` for a synthetic 1,000-row pipeline check):

```bash
.venv/bin/python -m src.eval.run_track_b --smoke
.venv/bin/python -m src.eval.run_track_b --split1 --split2
```

Every results file logs the git commit hash, seeds, and runtime metadata (`results/logs/`).
