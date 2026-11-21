# DFIR-Triage / REVENANT Phase 1 ML Benchmark — Work Summary

**Updated:** 2026-11-22  
**Repository:** [dfir-triage-ml](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/) (branch `main`, HEAD `30be588` + uncommitted Step 7 label-correction updates)  
**Status:** Steps 1–7 complete & verified (`180 passed in 25.84s`); Step 8 code pre-built & unit-tested, **paused before commit and before Step 8 execution** pending operator review of [review_sample.csv](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/data/processed/review_sample.csv).

---

## 1. Completed Milestones (Steps 1–8 Code & Git History)

| Step | Scope & Key Deliverables | Key Commits | Verification Status |
| :--- | :--- | :--- | :--- |
| **Step 1** | Repo skeleton, isolated Python `3.12.16` `.venv` (`57` pinned dependencies), locked 20-feature schema (`SEED = 42`), reproducibility helpers | `b3a5a26` | Verified (`tests/test_config.py` in unit suite) |
| **Step 2** | FE-08 forbidden-token sanitizer & DS-10 runner exclusion ([sanitize.py](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/src/data/sanitize.py)), Shannon entropy & 20-feature extractor ([features.py](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/src/data/features.py)) | `d0aba7a`, `ea9701c` | Verified (`tests/test_sanitize.py`, `tests/test_features.py`) |
| **Step 3** | Shared `ColumnTransformer` preprocessing & leakage guard, ranking metrics (`pr_auc`, `precision@k`, `recall@k`, `fpr_at_recall`, `bootstrap_by_group`) | `ec995ed` | Verified (`tests/test_metrics_preprocess.py`) |
| **Step 4** | Five-model suite (RF, XGBoost, Isolation Forest, PyTorch MLP, PyTorch Autoencoder) + full **Track B** (`CIC-MalMem-2022`) benchmark | `d5c8713`, `644201c` | Verified (`track_b_split1`, `split2`, 5-rotation, `fig7`) |
| **Step 5** | Read-only PowerShell collector ([Collect-Artifacts.ps1](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/collector/Collect-Artifacts.ps1)), SHA-256 manifest, smoke test, NTFS junction & SSH/PowerShell path fixes | `624923a`, `ea9701c`, `ece0e5f`, `30b27a3` | Verified live on `win11` (`SMOKE_PASS`, `1187` records in `54.8s`) |
| **Step 6** | Persistent Win11 libvirt overlay automation ([run_one.py](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/lab_automation/run_one.py), [run_all.py](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/lab_automation/run_all.py)), 16-technique catalog ([techniques.yaml](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/lab_automation/techniques.yaml)), stratified benign generator ([benign_noise.ps1](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/lab_automation/benign_noise.ps1)), **51-run batch** | `2e207a5`, `4eff2d5`, `a9620c9`, `ece0e5f`, `8f2dc06`, `8198c8b`, `30b27a3`, `30be588` | Verified live: **51/51 runs succeeded** (`116.8 min`) |
| **Step 7** | 15 deterministic rules (`RULE-001..RULE-015`, [deterministic_rules.py](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/src/rules/deterministic_rules.py)), diff+provenance labeler ([labeler.py](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/src/data/labeler.py)), 8 audited label corrections ([label_corrections.csv](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/data/processed/label_corrections.csv)), dataset freeze | `a157c67` + uncommitted corrections | Verified (`1549` rows, `103` positives, `0` leaks, `180 passed`) |
| **Step 8** | Track A evaluator ([run_track_a.py](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/src/eval/run_track_a.py)), ablations, SHAP/importance, 300-DPI figures, REVENANT `findings.json` exporter | `1dd8c19` | Synthetic end-to-end tests pass; **real Track A run pending** |

**Full Test Suite Verification** (`.venv/bin/pytest`): **`180 passed in 25.84s`** (verified after all `techniques.yaml` edits and `labeler` re-run).

---

## 2. Track B (`CIC-MalMem-2022`) Completed Results

- **Dataset verified**: `Obfuscated-MalMem2022.csv`, shape `(58596, 57)` (`29298` benign / `29298` malware across `15` families), MD5 `7a969ce248207e80af81bdf73601601a`.
- **Category parser (`Q-S4-1`)**: `"Benign"` $\to$ `("Benign", "Benign")`, else `val.split("-")` (4 parts) $\to$ `(parts[0], parts[1])`.
- **Metadata & Figure**: [track_b_meta.json](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/results/logs/track_b_meta.json), [fig7_track_b_comparison.png](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/results/figures/fig7_track_b_comparison.png).

### 2.1 Split 1 — Standard Stratified 80/20 (**LEAKY**: reproduction of published setup only)
From [track_b_split1.csv](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/results/tables/track_b_split1.csv):

| Arm | PR-AUC | ROC-AUC | Accuracy | F1 | Train (s) | Infer / 1k (s) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| Random Forest | 1.0000 | 1.0000 | 0.9999 | 0.9999 | 1.575 | 0.0038 |
| XGBoost | 1.0000 | 1.0000 | 0.9998 | 0.9998 | 0.477 | 0.0004 |
| Isolation Forest | 0.9474 | 0.9754 | 0.9695 | 0.9704 | 0.247 | 0.0049 |
| PyTorch MLP | 1.0000 | 1.0000 | 0.9991 | 0.9991 | 4.107 | 0.0003 |
| PyTorch autoencoder | 0.9992 | 0.9994 | 0.9697 | 0.9706 | 13.101 | 0.0003 |

### 2.2 Split 2 — Family-Grouped Holdout (`Ako|TIBS|Scar`, plus 5-Rotation Summary)
> **Caveat:** Benign false-positive rates are likely optimistic because SMOTE-synthesised benign rows cannot be fully separated between train and test (k-means cluster grouping is an approximation).

From [track_b_split2.csv](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/results/tables/track_b_split2.csv) and [track_b_split2_rotations_summary.csv](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/results/tables/track_b_split2_rotations_summary.csv):

| Arm | Split 2 PR-AUC | Split 2 R@1% Val FPR | Split 2 Test FPR@1% | Split 2 R@5% Val FPR | Split 2 Test FPR@5% | 5-Rot PR-AUC Mean [Min, Max] | 5-Rot R@1% Mean |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| Random Forest | 0.9992 | 1.0000 | 0.0813 | 1.0000 | 0.1614 | 0.9978 [0.9974, 0.9983] | 0.9993 |
| XGBoost | 0.9989 | 1.0000 | 0.2233 | 1.0000 | 0.2233 | 0.9992 [0.9988, 0.9995] | 0.9991 |
| Isolation Forest | 0.9516 | 0.3652 | 0.0058 | 0.4780 | 0.0229 | 0.9444 [0.9377, 0.9498] | 0.2751 |
| PyTorch MLP | 0.9995 | 1.0000 | 0.1846 | 1.0000 | 0.2494 | 0.9998 [0.9994, 1.0000] | 1.0000 |
| PyTorch autoencoder | 0.9814 | 0.9018 | 0.0380 | 0.9641 | 0.1572 | 0.9920 [0.9794, 0.9954] | 0.9677 |

*(On Split 2 rotations 0 and 2, `mlp` triggered the near-saturated PR-AUC check; zero family/benign-cluster overlap was confirmed, while supervised arms exhibited elevated actual test-FPR drift `8.1%–22.3%` at the nominal 1% benign-val threshold under cluster shift.)*

---

## 3. Windows 11 Lab Infrastructure & Generator Hardening (Steps 5–6)

- **VM Isolation** (`lab_config.yaml`, `Q-S6-2`): Persistent domain `win11` on `qemu:///system`, UEFI NVRAM (`win11_VARS.fd.base` $\to$ `win11_VARS.fd`), TPM 2.0 (`tpm-crb`), isolated network `win11-isolated` (`192.168.150.50`, MAC `52:54:00:ba:30:f3`), read-only `0444` base image `/var/lib/libvirt/images/win11_base.qcow2` (`137460187136` bytes), disposable `win11_overlay.qcow2` per run.
- **Collector & Runner Hardening**:
  - Added NTFS reparse-point/junction skipping, `$PID` collision & SSH ancestor/wrapper exclusion, and `sftp-server.exe` runner Prefetch/process dropping ([sanitize.py](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/src/data/sanitize.py)).
  - Extended `Extract-TargetPath` in [Collect-Artifacts.ps1](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/collector/Collect-Artifacts.ps1) to resolve bare `powershell.exe` against `System32\WindowsPowerShell\v1.0`, eliminating `path_class="na"` / `path_depth=NaN` on attack scheduled tasks.
  - Uploaded [benign_noise.ps1](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/lab_automation/benign_noise.ps1) to guest to avoid OpenSSH stdin stalls.
- **Stratified Shortcut Alignment** ([verify_stratified_shortcuts.py](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/scripts/verify_stratified_shortcuts.py), [PRE_51_LAUNCH.md](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/docs/PRE_51_LAUNCH.md)):
  - Rebuilt [benign_noise.ps1](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/lab_automation/benign_noise.ps1) with compound snake_case file names matching attack lengths (`15.79` vs `15.46`), `56%` `_v1.._v3` file suffixes (`60%` `V1..V3` run keys, `0%` tasks), matched PowerShell/cmd interpreter mixes, and shared `ProgramData` / `Users\Public` / `Windows\Temp` target pools with exact dynamic provenance.
  - Offline 48-seed audit passed all stopping criteria (`ALL STOPPING CRITERIA SATISFIED: True`): `358` unique benign keys after dedup, max numeric within-type AUC **`0.6865`** ($\le 0.70$), max categorical class gap **`17.5pp`** ($\le 25\text{pp}$).
  - **Known limitation** (documented in [PROGRESS.md](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/docs/PROGRESS.md)): `service` and security-sensitive `registry` keys are produced exclusively by attack techniques (`T1543.003`, `T1112`, `T1562.001`, `T1548.002`) rather than background benign noise to prevent host collisions and provenance destabilization.

---

## 4. 51-Run Production Batch Execution (`commit 30be588`)

Executed via `.venv/bin/python -u -m lab_automation.run_all --resume` inside `tmux` + `systemd-inhibit --what=idle:sleep` (`3` control boots `ctrl_01..ctrl_03` + `48` attack runs across `16` techniques $\times$ `3` variants):

- **Completion**: **`51 / 51` `status=success` on attempt `1`** ([run_table.csv](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/results/logs/run_table.csv), [batch51.log](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/results/logs/batch51.log)).
- **Cleanup & Integrity**: `51 / 51` `overlay_deleted=True`, `win11` `shut off`, `/var/lib/libvirt/images/win11_base.qcow2` `stat` unchanged (`0444`, `137460187136` bytes, mtime `2026-11-21 05:59:52.232095818 +0200`).
- **Collector Manifests**: `51 / 51` present, **`0` SHA-256 output-file mismatches** across all 51 runs; `total_records` per run min `1076`, median `1087`, max `1091`; `amcache` soft-skipped `51/51` with `locked_hive_no_vss`.
- **Resource & Timing Totals**: `7007.2s` (`116.8 min`, mean `137.4s/run`), `607.1 MB` raw collector output (mean `11.90 MB/run`), max overlay `107.31 MB`.

---

## 5. Step 7 Dataset Freeze, Label Corrections & Audit

Built with `.venv/bin/python -m src.data.labeler --baseline-utc 2026-11-21T03:59:52Z`:

### 5.1 Audited Label Corrections ([label_corrections.csv](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/data/processed/label_corrections.csv))
Initial audit flagged `8` real attack artifacts sitting inside `os_or_background_drift` (`benign_drift`) due to `1` typo (`sysauditoncelv1`) and `7` omitted secondary attack keys in [techniques.yaml](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/lab_automation/techniques.yaml). Each was verified against `steps[].cmd`, added to `expected_artifact_keys` without touching `split` or holdout assignments, and re-labeled cleanly from raw runs:

| `run_id` | Technique (Split) | Verified Command Evidence in `techniques.yaml` | Correction |
| :--- | :--- | :--- | :--- |
| `run_013_T1546_003_v1` | `T1546.003` v1 (`dev`) | `Set-WmiInstance ... __FilterToConsumerBinding` (`DiskQuotaFilterV1`->`DiskQuotaConsumerV1`) | `benign_drift` $\to$ `attacker_induced` |
| `run_014_T1546_003_v2` | `T1546.003` v2 (`dev`) | `Set-WmiInstance ... __FilterToConsumerBinding` (`NetProbeIntervalV2`->`NetProbeHandlerV2`) | `benign_drift` $\to$ `attacker_induced` |
| `run_015_T1546_003_v3` | `T1546.003` v3 (`dev`) | `Set-WmiInstance ... __FilterToConsumerBinding` (`SessionAuditFilterV3`->`SessionAuditScriptV3`) | `benign_drift` $\to$ `attacker_induced` |
| `run_022_T1059_003_v1` | `T1059.003` v1 (`holdout`) | `reg.exe ADD "HKCU\...\RunOnce" /v "ShellRunnerV1" /d "cmd.exe /c C:\Users\Public\runner_v1.cmd"` | `benign_drift` $\to$ `attacker_induced` |
| `run_026_T1036_005_v2` | `T1036.005` v2 (`holdout`) | Copies `hostname.exe` to `C:\Users\Public\report.pdf.exe` & runs via `open_report_v2.cmd` (Prefetch) | `benign_drift` $\to$ `attacker_induced` |
| `run_040_T1574_001_v1` | `T1574.001` v1 (`dev`) | `reg.exe ADD "HKCU\...\Run" /v "SideViewerV1" /d "C:\Users\Public\side_app\viewer.exe"` | `benign_drift` $\to$ `attacker_induced` |
| `run_042_T1574_001_v3` | `T1574.001` v3 (`dev`) | `reg.exe ADD "HKCU\...\RunOnce" /v "LoaderV3" /d "C:\Windows\Temp\loader\updater.exe"` | `benign_drift` $\to$ `attacker_induced` |
| `run_043_T1082_v1` | `T1082` v1 (`dev`) | `reg.exe ADD "HKCU\...\RunOnce" /v "SysAuditOnceV1"` (fixed `sysauditoncelv1` typo) | `benign_drift` $\to$ `attacker_induced` |

**Audit of the 6 Remaining `.pf` `os_or_background_drift` Rows (All Kept `benign_drift`):**
- `CMD.EXE-0BD30981.pf`, `CONHOST.EXE-0C6456FB.pf`, `POWERSHELL.EXE-CA1AE517.pf` (first `run_004`): present in `ctrl_01..03`, hash-changed in `48/48` attack runs from OS/SSH/benign runners.
- `REG.EXE-A93A1343.pf` (first `run_004`): present in `ctrl_01..03`, hash-changed in `13/48` attack runs (`run_004`'s `T1053.005` v1 never invokes `reg.exe`; updated by `benign_noise.ps1`'s `run_note`).
- `SCHTASKS.EXE-8B6144A9.pf` (first `run_005`): absent in `ctrl_01..03`, newly created in `13/48` attack runs including non-`T1053.005` runs (`run_009`, `run_013`, `run_022`, etc.) because `benign_noise.ps1`'s `backup_task` runs `schtasks.exe` — shared across classes.
- `SVCHOST.EXE-9EB5DE68.pf` (first `run_032`): present in `ctrl_01..03`, hash-changed in `4/48` runs (`run_032`, `run_040`, `run_044`, `run_050`) from OS service activity (not `T1036.005` v1's masqueraded `ProgramData\svchost.exe`).

### 5.2 Final Post-Correction Dataset Statistics & Manifest
From [dataset_v1_manifest.json](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/data/splits/dataset_v1_manifest.json), [dataset_stats.csv](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/data/processed/dataset_stats.csv), and [dataset_v1.parquet](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/data/processed/dataset_v1.parquet):
- **Total rows**: **`1549`** (`baseline`: **`1066`**, `benign_drift`: **`380`**, `attacker_induced`: **`103`**)
- **Label reasons**: `control_boot_baseline`: `1066`, `provenance_benign_match`: `361`, `os_or_background_drift`: `19`, `provenance_attack_match`: `95`, `technique_expected_match`: `8`
- **Split pools**:
  - `dev`: **`1179`** (`70` `attacker_induced`, `288` `benign_drift`, `821` `baseline`)
  - `test`: **`370`** (`33` `attacker_induced`, `92` `benign_drift`, `245` `baseline`)
- **Holdout techniques (5)**: `["T1036.005", "T1059.003", "T1087.001", "T1543.003", "T1548.002"]`
- **Frozen `test_sha256`**: `2046f3ffbcbb9bdbc05f5db0e97b8d7554e41179a6f46dadb77fe65506db9e07`
- **Anti-leakage & sanitization**: `benign_dev_test_overlap = 0`, `technique_dev_test_overlap = 0`, `0` FE-08 sanitization failures, `98` runner Prefetch rows dropped (`54` `sshd.exe`, `44` `sftp-server.exe` in [runner_footprint_dropped.csv](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/results/logs/runner_footprint_dropped.csv)).

### 5.3 Post-Correction Per-Technique Coverage & Breakdown Tables

**Per-Technique Coverage (`16/16` techniques, `48/48` variants with $\ge 1$ observed positive):**

| Technique | Tactic | Split | Expected | Observed | v1 | v2 | v3 |
| :--- | :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| `T1053.005` | `persistence` | `dev` | 6 | 6 | 2 | 2 | 2 |
| `T1547.001` | `persistence` | `dev` | 6 | 6 | 2 | 2 | 2 |
| `T1543.003` | `persistence` | `holdout` | 6 | 6 | 2 | 2 | 2 |
| `T1546.003` | `persistence` | `dev` | 12 | 12 | 4 | 4 | 4 |
| `T1136.001` | `persistence` | `dev` | 6 | 6 | 2 | 2 | 2 |
| `T1059.001` | `execution` | `dev` | 6 | 3 | 1 | 1 | 1 |
| `T1059.003` | `execution` | `holdout` | 7 | 4 | 2 | 1 | 1 |
| `T1036.005` | `defense_evasion` | `holdout` | 7 | 7 | 2 | 3 | 2 |
| `T1112` | `defense_evasion` | `dev` | 6 | 6 | 2 | 2 | 2 |
| `T1218.011` | `defense_evasion` | `dev` | 6 | 5 | 2 | 2 | 1 |
| `T1562.001` | `defense_evasion` | `dev` | 6 | 4 | 2 | 1 | 1 |
| `T1548.002` | `privilege_escalation` | `holdout` | 6 | 8 | 3 | 2 | 3 |
| `T1574.001` | `privilege_escalation` | `dev` | 8 | 8 | 3 | 2 | 3 |
| `T1082` | `discovery` | `dev` | 9 | 8 | 3 | 2 | 3 |
| `T1087.001` | `discovery` | `holdout` | 9 | 8 | 3 | 3 | 2 |
| `T1552.001` | `credential_access` | `dev` | 6 | 6 | 2 | 2 | 2 |

**`artifact_type` $\times$ `label` Crosstab:**
- `file`: `63` attacker / `233` baseline / `284` benign_drift (`580`)
- `run_key`: `11` attacker / `4` baseline / `43` benign_drift (`58`)
- `task`: `3` attacker / `240` baseline / `33` benign_drift (`276`)
- `wmi_subscription`: `9` attacker / `2` baseline / `0` benign_drift (`11`)
- `registry`: `9` attacker / `7` baseline / `0` benign_drift (`16`)
- `service`: `3` attacker / `237` baseline / `0` benign_drift (`240`)
- `account`: `3` attacker / `5` baseline / `0` benign_drift (`8`)
- `prefetch`: `1` attacker / `250` baseline / `7` benign_drift (`258`)
- `startup`: `1` attacker / `0` baseline / `0` benign_drift (`1`)
- `process`: `0` attacker / `83` baseline / `13` benign_drift (`96`)
- `shimcache`: `0` attacker / `5` baseline / `0` benign_drift (`5`)

**Non-Zero Feature Missingness (`NaN` Rate by Label) & Dev-Only Within-Type AUCs:**
- All 14 remaining features + `rule_hit_count` have `0.0000` NaN rate across all labels; `benign_drift` has `0.0000` NaN across **every** feature. Non-zero NaN rates (structural to Registry/Account/WMI objects without backing files): `path_depth` (`0.1068` att / `0.1604` base), `file_size_log` (`0.1262` / `0.1660`), `file_entropy` (`0.1262` / `0.1998`), `file_age_minutes` (`0.1262` / `0.1557`), `created_in_window` (`0.1262` / `0.1510`).
- **Dev-only (`split_pool == "dev"`) within-type ROC-AUCs (`attacker_induced` vs `benign_drift`)**:
  - `file` (`43` vs `221`): max AUC `0.6774` (`path_depth`; `name_length=0.5575`, `name_entropy=0.5629`, `file_size_log=0.5781`, `file_entropy=0.5360`).
  - `run_key` (`7` vs `31`): max AUC `0.6728` (`cmdline_entropy`; `file_entropy=0.6267`, `name_entropy=0.5737`, `name_length=0.5691`, `path_depth=0.5069`).
  - `task` (`3` vs `21`): continuous numeric AUCs $\le 0.6587$ (`name_length=0.6587`, `cmdline_length=0.6190`), `autostart_flag=0.8333` (`T1053.005` v1/v3 use `ONLOGON`/`ONSTART` vs `/SC ONCE`).

### 5.4 Human Review Sample ([review_sample.csv](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/data/processed/review_sample.csv))
- **`111` rows**: `10` `attacker_induced` (`provenance_attack_match`), `1` `attacker_induced` (`technique_expected_match`), `92` `benign_drift` (`provenance_benign_match`), `8` `benign_drift` (`os_or_background_drift`).

---

## 6. Pending Next Steps (Awaiting Operator Sign-Off)

1. Operator reviews [review_sample.csv](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/data/processed/review_sample.csv) and signs off.
2. Commit Step 7 outputs, [techniques.yaml](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/lab_automation/techniques.yaml) corrections, and [WORK_SUMMARY.md](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/docs/WORK_SUMMARY.md).
3. Extend [run_track_a.py](file:///home/fsociety/grad/implementation_phase1/docs_claude/dfir-triage-ml/src/eval/run_track_a.py) (prior to running) with:
   - Rules-only baseline (`rule_hit_count > 0` + ranking by `rule_hit_count`) and random baseline.
   - Per-`artifact_type` results and a combined `file+run_key+task` view.
   - Bootstrap by `run_id` in addition to by `technique_id`.
   - Feature-subset probe models: name/path features only, content features only (`file_size_log`, `file_entropy`, `signature_state`), and `artifact_type` only.
4. Execute **dev `GroupKFold` CV** first and report results.
5. Execute **`--final`** (plus ablations, SHAP, 300-DPI figures, and REVENANT `findings.json`) **only once after explicit operator confirmation**.
