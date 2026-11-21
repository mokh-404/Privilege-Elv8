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
- **Step 4 complete (commits `d5c8713`, `644201c`)**:
  - Implemented `src/data/cic_malmem.py:parse_category` and executed full Track B (`--split1 --split2 --rotate`) on `Obfuscated-MalMem2022.csv` (`58596 x 57`, MD5 `7a969ce248207e80af81bdf73601601a`).
  - Outputs: `results/tables/track_b_split1.csv`, `track_b_split2.csv`, `track_b_split2_rotations.csv`, `track_b_split2_rotations_summary.csv`, `results/logs/track_b_meta.json`, and `results/figures/fig7_track_b_comparison.{png,pdf}`.
  - Note: on Split 2 rotations 0 and 2, `mlp` triggered the near-saturated `PR-AUC` leakage warning; inspection confirmed zero family or benign-cluster overlap and revealed substantial test-FPR drift on supervised arms under benign cluster shift (see `results/tables/track_b_split2*.csv`).
- **Step 5 (commit `624923a`, static tests passing; awaiting live Win11 VM output)**:
  - `collector/Collect-Artifacts.ps1`, `collector/manifest_schema.json`, `collector/Test-Collector.ps1`, `collector/README.md`, `tests/test_collector.py`.
- **Step 6 (commit `2e207a5`, `644201c` holdout split approved & `T1087.001`/`T1082`/`T1552.001` strengthened)**:
  - `lab_automation/techniques.yaml` (`split_status: approved_frozen`, 5 approved holdout techniques across 5 tactics), `benign_noise.ps1`, `guest_runner.py`, `run_one.py`, `run_all.py`, `lab_config.example.yaml`, `tests/test_lab_automation.py`.
- **Step 7 (commit `a157c67`, unit tests passing on synthetic fixtures)**:
  - `src/rules/deterministic_rules.py` (15 rules `RULE-001..RULE-015`), `src/data/labeler.py` (baseline diff + provenance labeling, baseline/drift deduplication, hash-bucketed splits, review-sample export), `tests/test_rules_and_labeler.py`.
- **Step 8 (code & synthetic end-to-end tests passing; awaiting frozen Track A dataset)**:
  - `src/eval/run_track_a.py`, `src/eval/ablations.py`, `src/eval/shap_explain.py`, `src/eval/figures.py`, `src/eval/export_findings.py`, `tests/test_track_a_and_step8.py` (+ `keep_empty_features=True` fix in `src/models/preprocess.py`).
  - Full test suite: `172 passed in 25.04s`.

## In progress
- **Step 5 (live VM verification)**: ready to run `collector/Test-Collector.ps1` over SSH on the provisioned `win11` guest (`192.168.150.50`, user `mokh`).
- **Step 6 (unblocked, pending dry run)**: `Q-S6-2` answered (`win11` persistent domain on `qemu:///system`, `win11-isolated`, `192.168.150.50`, `mokh`, `use_sudo_for_libvirt_files: true`, `nvram_live` + `nvram_base`, `post_ssh_settle_seconds: 20`); implementing exact reset sequence and running the 3-run dry run.

## Blocked
- **51-run batch & Steps 7–8 on real Track A data**: waiting on live collector smoke test, 3-run dry run, dry-run labeling sanity check, and operator go-ahead.

## Resolved Questions
- **`Q-S6-2` (`lab_config.yaml` host values)**: Resolved — `libvirt_uri: qemu:///system`, `domain_name: win11`, `network_name: win11-isolated`, `guest_ip: 192.168.150.50`, `ssh_user: mokh`, `ssh_key_path: /home/fsociety/.ssh/id_ed25519`, `base_image: /var/lib/libvirt/images/win11_base.qcow2`, `overlay_image: /var/lib/libvirt/images/win11_overlay.qcow2`, `nvram_live: /var/lib/libvirt/qemu/nvram/win11_VARS.fd`, `nvram_base: /var/lib/libvirt/qemu/nvram/win11_VARS.fd.base`, `use_sudo_for_libvirt_files: true`, `post_ssh_settle_seconds: 20`.
