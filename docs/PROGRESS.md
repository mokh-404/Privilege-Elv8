# Project Progress

## Done
- **Step 1** (commit `b3a5a26`, `tests/test_config.py`):
  - Repo layout created under `dfir-triage-ml/` with specs (now in `docs/specs/00..12`), `.gitignore`, `pytest.ini`, `requirements.in`, and pinned `requirements.txt` (57 packages, Python `3.12.16` `.venv`).
  - `src/config.py` with locked 20-feature schema, `ORACLE_FEATURES`, `RULE_FEATURES`, `META_COLUMNS`, `LABEL_COL`, `SEED = 42`, and `LOLBIN_LIST`.
  - `src/utils/repro.py` for seeding, CUDA/CPU detection, git commit hash, and run metadata.
- **Step 2** (commit `d0aba7a`, `tests/test_sanitize.py` + `tests/test_features.py`):
  - `src/data/sanitize.py` (FE-08 assertion + DS-10 runner footprint exclusion).
  - `src/data/features.py` (Shannon entropy + 20 locked features + isolated oracle columns; CLI flag token guard for `/sc` / `/reg`).
- **Step 3** (commit `ec995ed`, `tests/test_metrics_preprocess.py`):
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
- **Step 7 complete & frozen (commits `a157c67`, `a72c0b4`)**:
  - `src/rules/deterministic_rules.py` (15 rules `RULE-001..RULE-015`), `src/data/labeler.py`, `tests/test_rules_and_labeler.py`.
  - 8 audited `expected_artifact_keys` corrections recorded in `data/processed/label_corrections.csv`; 6 shared `.pf` `os_or_background_drift` rows verified and retained as `benign_drift`.
  - Review sample export (`data/processed/review_sample.csv`) populated with `111/111` `operator_verified_agree` and metadata recorded in `data/splits/dataset_v1_manifest.json` (see `COMPLETE_REPORT.md` §7.2 for audit-trail limits).
- **Step 8 complete — Pre-`--final` Bug Fix, Dual-Config Evaluation, Explanations, Figures & Exports (commits `70d6b25`, `c0b7742`, `8add423`, `4e32ab1`, `69ad02e`)**:
  - Pre-`--final` bug fix (`8add423`): mapped `_SIG_MAP["unknownerror"] = "na"` in `src/data/features.py` with regression tests in `tests/test_features.py` and rebuilt `data/processed/dataset_v1.parquet` (`0` changed labels, `1549` total rows: `1066` baseline, `380` benign_drift, `103` attacker_induced [`70` dev / `33` test]; `dev=1179`, `test=370`, `test_sha256=0f1ff3ec054bf00c66875fb5d2466e3b8d35685d69c2f0203d6787b71852ffa8`; `0` overlaps; `0` FE-08 failures; `98` runner Prefetch drops).
  - Pre-registered dual-configuration evaluation (`full_20` + `no_content`) and four methodological reporting notes committed in `docs/FINAL_EVAL_PLAN.md` (`4e32ab1`, `69ad02e`) prior to any `--final` run; unit suite verified at `185 passed`.
  - Regenerated dev `GroupKFold` CV tables across `full_20` and `no_content` (pre-fix dev PR-AUC baseline is `NOT RECORDED` in repo files; updated `rf` dev PR-AUC = `0.5550`, `xgb` = `0.6147`).
  - Executed ONE-TIME `--final --include-lr --dual-config` (`results/logs/final_eval_audit.jsonl`, `2026-11-22T02:04:38Z`, zero leakage warnings), dev-fitted ablations + train-size curves (`track_a_ablations.csv`, `track_a_train_size.csv`), SHAP / AE / IF / error analysis (`full_20` + `no_content/`), 300-DPI PNG/PDF figures (`18` full + `12` no_content), and schema-validated REVENANT exports (`results/findings.json`, `results/findings_no_content.json`).
  - Authored `COMPLETE_REPORT.md` and organized repository docs under `docs/specs/` and `docs/INDEX.md`.

## In progress
- None (all Phase-1 implementation, collection, frozen evaluation, explainability, and reporting tasks complete).

## Known Limitations
- **Benign Artifact Types Coverage**: Benign activity generator (`benign_noise.ps1`) produces hard-negative artifacts across `file`, `task`, `run_key`, and `prefetch`. `service` and security-sensitive `registry` keys (IFEO, UAC hijack, Defender policies) are produced exclusively by attack techniques (`T1543.003`, `T1112`, `T1562.001`, `T1548.002`). Service creation (`sc.exe create`) and security registry modifications were omitted from background benign noise to prevent cross-run interference, host security collisions, and provenance destabilization during concurrent simulation.
- **Benign Script Content Template Quantization (`full_20` vs `no_content`)**: Across `221` dev `benign_drift` script files (`artifact_type == "file"` & `ext_class == "script"`), fixed templates yield only `18` unique `file_size_log` values and `30` unique `(file_size_log, file_entropy)` pairs (vs `34` distinct pairs across `36` dev attacker-induced script files), enabling tree models to memorize benign script content sizes/entropies. Mitigated without re-collection by pre-registering and reporting `no_content` (`18` features dropping `file_size_log` and `file_entropy`) alongside `full_20`.

## Blocked / Awaiting Operator Decision
- None (all evaluation gates and `--final` outputs complete).

## Resolved Questions
- **`Q-S6-2` (`lab_config.yaml` host values)**: Resolved — `libvirt_uri: qemu:///system`, `domain_name: win11`, `network_name: win11-isolated`, `guest_ip: 192.168.150.50`, `ssh_user: mokh`, `ssh_key_path: ~/.ssh/id_ed25519` (machine-local override in gitignored `lab_config.yaml`), `base_image: /var/lib/libvirt/images/win11_base.qcow2`, `overlay_image: /var/lib/libvirt/images/win11_overlay.qcow2`, `nvram_live: /var/lib/libvirt/qemu/nvram/win11_VARS.fd`, `nvram_base: /var/lib/libvirt/qemu/nvram/win11_VARS.fd.base`, `use_sudo_for_libvirt_files: true`, `post_ssh_settle_seconds: 20`.
