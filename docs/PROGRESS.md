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
- **Step 6 complete (`51/51` live Win11 runs, commits `2e207a5`..`30be588`)**:
  - `lab_automation/techniques.yaml` (`split_status: approved_frozen`, 5 approved holdout techniques across 5 tactics), `benign_noise.ps1` (stratified compound naming & interpreter/target alignment; offline audit max numeric AUC `0.6865`, max categorical gap `17.5pp`), `guest_runner.py`, `run_one.py`, `run_all.py`, `lab_config.yaml`, `tests/test_lab_automation.py`.
  - Full 51-run batch (`ctrl_01..ctrl_03` + 48 attack runs) completed `51/51` `status=success` on attempt 1 in `7007.2s` (`116.8 min`, `607.1 MB` raw collector output, `0` manifest SHA-256 mismatches, `51/51` overlays deleted, `win11` `shut off`, `win11_base.qcow2` unchanged).
- **Step 7 complete & frozen (commit `a157c67` + dataset freeze)**:
  - `src/rules/deterministic_rules.py` (15 rules `RULE-001..RULE-015`), `src/data/labeler.py`, `tests/test_rules_and_labeler.py`.
  - 8 audited `expected_artifact_keys` corrections recorded in `data/processed/label_corrections.csv`; 6 shared `.pf` `os_or_background_drift` rows verified and retained as `benign_drift`.
  - Frozen `data/processed/dataset_v1.parquet`: `1549` total rows (`1066` baseline, `380` benign_drift, `103` attacker_induced [`70` dev / `33` test]), `dev=1179`, `test=370`, `test_sha256=2046f3ffbcbb9bdbc05f5db0e97b8d7554e41179a6f46dadb77fe65506db9e07`, `0` dev/test overlaps, `0` FE-08 failures, `98` runner Prefetch drops (`54` `sshd.exe`, `44` `sftp-server.exe`).
  - Human review of `data/processed/review_sample.csv` signed off (`111/111` agreed, recorded in `data/splits/dataset_v1_manifest.json`).
- **Step 8 (code & synthetic end-to-end tests passing; extending Track A dev eval)**:
  - `src/eval/run_track_a.py`, `src/eval/ablations.py`, `src/eval/shap_explain.py`, `src/eval/figures.py`, `src/eval/export_findings.py`, `tests/test_track_a_and_step8.py`.
  - Full pre-freeze unit test suite: `180 passed in 25.84s`.

## In progress
- Step 8 Track A Dev `GroupKFold` CV (`--dev`, plus rules/random baselines, per-`artifact_type` + `file+run_key+task` views, run+technique bootstrap CIs, and feature-subset probes; awaiting `"go --final"` before frozen test evaluation).

## Known Limitations
- **Benign Artifact Types Coverage**: Benign activity generator (`benign_noise.ps1`) produces hard-negative artifacts across `file`, `task`, `run_key`, and `prefetch`. `service` and security-sensitive `registry` keys (IFEO, UAC hijack, Defender policies) are produced exclusively by attack techniques (`T1543.003`, `T1112`, `T1562.001`, `T1548.002`). Service creation (`sc.exe create`) and security registry modifications were omitted from background benign noise to prevent cross-run interference, host security collisions, and provenance destabilization during concurrent simulation.

## Blocked / Awaiting Operator Decision
- **Step 8 Track A `--final` frozen test evaluation**: Held pending operator review of Dev `GroupKFold` CV results and `"go --final"` confirmation.

## Resolved Questions
- **`Q-S6-2` (`lab_config.yaml` host values)**: Resolved — `libvirt_uri: qemu:///system`, `domain_name: win11`, `network_name: win11-isolated`, `guest_ip: 192.168.150.50`, `ssh_user: mokh`, `ssh_key_path: /home/fsociety/.ssh/id_ed25519`, `base_image: /var/lib/libvirt/images/win11_base.qcow2`, `overlay_image: /var/lib/libvirt/images/win11_overlay.qcow2`, `nvram_live: /var/lib/libvirt/qemu/nvram/win11_VARS.fd`, `nvram_base: /var/lib/libvirt/qemu/nvram/win11_VARS.fd.base`, `use_sudo_for_libvirt_files: true`, `post_ssh_settle_seconds: 20`.
