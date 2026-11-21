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
- **Step 5 complete (commits `624923a`, `ea9701c`, live Win11 VM verified)**:
  - `collector/Collect-Artifacts.ps1`, `collector/manifest_schema.json`, `collector/Test-Collector.ps1`, `collector/README.md`, `tests/test_collector.py`.
  - Live smoke test on `win11`: `SMOKE_PASS`, `total_records=1187` in `54.8s`, all 11 SHA-256 hashes re-verified on host (`ALL_HASHES_MATCH=True`), `amcache` fail-soft `locked_hive_no_vss`, zero SSH/collector leak rows, `win11_base.qcow2` `stat` unchanged.
- **Step 6 complete through dry run (commits `2e207a5`, `a9620c9`, `ece0e5f`, `8f2dc06`)**:
  - `lab_automation/techniques.yaml` (`split_status: approved_frozen`, 5 approved holdout techniques across 5 tactics), `benign_noise.ps1`, `guest_runner.py`, `run_one.py`, `run_all.py`, `lab_config.example.yaml`, `tests/test_lab_automation.py`.
  - Exact Win11 sudo reset sequence implemented and verified (`destroy` -> `rm -f overlay` -> `qemu-img create` -> `chown nobody:nobody` -> `cp nvram_base nvram_live` -> `virsh start` -> `virsh shutdown` -> `rm -f overlay`).
  - 3-run `--dry-run` successfully executed on live Win11: `dry_ctrl_01` (173.97s), `dry_T1053_005_v1` (133.23s), `dry_T1543_003_v1` (136.94s). All 3 succeeded, overlays cleanly deleted after each run, `win11_base.qcow2` untouched.
- **Step 7 dry-run sanity check complete (commit `a157c67` + live verification)**:
  - `src/rules/deterministic_rules.py` (15 rules `RULE-001..RULE-015`), `src/data/labeler.py` (baseline diff + provenance labeling, baseline/drift deduplication, hash-bucketed splits, review-sample export), `tests/test_rules_and_labeler.py`.
  - Dry-run labeling into `data/interim/dry_run_processed/dataset_v1.parquet`: 1,084 total rows (1,065 baseline, 15 benign_drift, 4 attacker_induced), all 20 locked features computed cleanly, zero forbidden tokens under FE-08, zero `sshd*.pf` leaks (4 dropped and logged), zero NTFS junction duplicates, 2 dev positives (`T1053.005`) and 2 test positives (`T1543.003`).
- **Step 8 (code & synthetic end-to-end tests passing; awaiting frozen Track A dataset)**:
  - `src/eval/run_track_a.py`, `src/eval/ablations.py`, `src/eval/shap_explain.py`, `src/eval/figures.py`, `src/eval/export_findings.py`, `tests/test_track_a_and_step8.py`.
  - Full test suite: `180 passed in 24.14s`.

## In progress
- None (pre-batch dry-run verification and sanity checks complete).

## Blocked / Awaiting Operator Decision
- **51-run full Track A batch**: Ready to launch upon operator approval (`.venv/bin/python -m lab_automation.run_all --resume`).
- **Step 7 final dataset freeze & Step 8 Track A execution**: Scheduled to run immediately following the 51-run batch completion.

## Resolved Questions
- **`Q-S6-2` (`lab_config.yaml` host values)**: Resolved — `libvirt_uri: qemu:///system`, `domain_name: win11`, `network_name: win11-isolated`, `guest_ip: 192.168.150.50`, `ssh_user: mokh`, `ssh_key_path: /home/fsociety/.ssh/id_ed25519`, `base_image: /var/lib/libvirt/images/win11_base.qcow2`, `overlay_image: /var/lib/libvirt/images/win11_overlay.qcow2`, `nvram_live: /var/lib/libvirt/qemu/nvram/win11_VARS.fd`, `nvram_base: /var/lib/libvirt/qemu/nvram/win11_VARS.fd.base`, `use_sudo_for_libvirt_files: true`, `post_ssh_settle_seconds: 20`.
