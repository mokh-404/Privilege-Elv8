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
- **Step 4 (commit `d5c8713`, `tests/test_models.py` + `tests/test_track_b.py` passing; CSV inspected)**:
  - `src/models/sklearn_models.py`, `src/models/mlp.py`, `src/models/autoencoder.py`, `src/data/splits.py`, `src/data/cic_malmem.py`, `src/eval/run_track_b.py`.
  - Inspected `data/external/cic_malmem_2022/Obfuscated-MalMem2022.csv`: shape `(58596, 57)` matches expected, `Class` = `Benign: 29298` / `Malware: 29298`, 0 NaNs, 0 infs, MD5 `7a969ce248207e80af81bdf73601601a`. Distinct `Category` strings = `28346` (`"Benign"` and `<category>-<family>-<sample_hash>-<dump_idx>.raw`), grouping into 3 malware categories × 5 families = 15 families (`Maze`, `180solutions`, `CWS`, `Scar`, etc.).
- **Step 5 (written, static tests passing; awaiting live Win11 VM output)**:
  - `collector/Collect-Artifacts.ps1` (PS 5.1 read-only collector with `HKU\<SID>`, `sshd.exe` + PID exclusions, Prefetch, AppCompatCache/ShimCache, soft-fail Amcache, WMI subscriptions, UAC/IFEO keys, `record_sha256`, `file_sha256`, `|`).
  - `collector/manifest_schema.json`, `collector/Test-Collector.ps1`, `collector/README.md`, `tests/test_collector.py`.
- **Step 6 (written, unit tests passing; awaiting operator holdout approval & frozen VM dry run)**:
  - `lab_automation/techniques.yaml` (16 self-contained offline-safe techniques × 3 variants across 6 tactics, zero forbidden tokens), `lab_automation/benign_noise.ps1`, `lab_automation/guest_runner.py`, `lab_automation/run_one.py` (persistent `win11` overlay + NVRAM restore + 20s settle + parallel seeded interleaving), `lab_automation/run_all.py`, `lab_automation/lab_config.example.yaml`, `tests/test_lab_automation.py`.
  - Full test suite (`148 passed in 7.37s`).

## In progress
- **Step 4 (`parse_category`)**: waiting for operator approval of the `<category>-<family>-<sample_hash>-<dump_idx>.raw` parser before implementing `parse_category()` and running Track B.
- **Step 5 (live VM verification)**: operator running `collector/Test-Collector.ps1` / `Collect-Artifacts.ps1` on the live `win11` VM before freezing `win11_base.qcow2`.

## Blocked
- **Track B full training**: gated on operator sign-off on `parse_category` mapping (stop-and-ask rule).
- **Step 6 dry run & 51-run batch**: gated on operator approval of the 5 proposed holdout techniques (`seed=42`) and frozen `win11_base.qcow2` + `lab_automation/lab_config.yaml`.
- **Steps 7–8 (labeler, Track A eval, SHAP, figures, `export_findings.py`)**: waiting on dry-run / frozen Track A data.

## Questions for the operator
- **Q-S4-1 (`parse_category` approval)**: Every malware row in `Obfuscated-MalMem2022.csv` follows `<category>-<family>-<sample_hash>-<dump_idx>.raw` (e.g. `Spyware-CWS-...-1.raw`, `Ransomware-Maze-...-1.raw`). Approve implementing `parse_category` by splitting `"-"`: `"Benign"` -> `("Benign", "Benign")`, else `(parts[0], parts[1])` (and running `run_track_b.py --split1 --split2` + `--rotate`)? Note also that the file's observed MD5 is `7a969ce248207e80af81bdf73601601a` (vs `9e1be3f2b0393d5d287dae5d529f356a`), with exact `(58596, 57)` shape and balanced counts.
- **Q-S6-1 (Proposed 5 holdout techniques, `seed=42`)**: Approve holding out `T1036.005` (`defense_evasion`), `T1087.001` (`discovery`), `T1059.003` (`execution`), `T1543.003` (`persistence`), `T1548.002` (`privilege_escalation`) across 5 tactics, leaving 11 dev techniques across all 6 tactics?
- **Q-S6-2 (`lab_config.yaml` missing host values)**: Once `win11_base.qcow2` + `win11_VARS.fd.base` are frozen, supply `network_name`, `guest_ip`, `ssh_user`, `ssh_key_path`, and whether `use_sudo_for_libvirt_files: true` is needed for `/var/lib/libvirt/{images,qemu/nvram}`.
