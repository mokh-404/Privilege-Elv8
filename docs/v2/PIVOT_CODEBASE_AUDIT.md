# DFIR-Triage ML v2 Strategic Pivot — Read-Only Codebase, Safety & Feasibility Audit

**Audit Date:** `2026-11-25`  
**Mode:** Strictly Read-Only Audit (Zero code/script/test edits, zero VM boots, zero malware downloads, zero package installations, zero Gate 0 sign-off)  
**Git HEAD:** `bc12c57` on `main`  
**Companion Re-Scope Plan:** [`REPLAN_COMPARATIVE_STUDY.md`](REPLAN_COMPARATIVE_STUDY.md)

---

## 1. Frozen v1 Integrity & Full Test Suite Baseline (Verified `2026-11-25`)

All checks below were executed directly on the host prior to authoring these documents:

| Check | Command / Target | Observed Verified Result | Status |
| :--- | :--- | :--- | :---: |
| **Active QEMU Processes** | `pgrep -a qemu` | *(empty — zero VMs running)* | `PASS` |
| **Full Test Suite** | `.venv/bin/pytest` | **`317 passed in 193.39s (0:03:13)`** (`0` failures) | `PASS` |
| **Frozen v1 Parquet** | `sha256sum data/processed/dataset_v1.parquet` | `39527f85fbda75f952e0cf5134a07467bf546501cb540ba68cd65b14983c7f21` | `PASS` |
| **v1 Shape & Label Mix** | `data/processed/dataset_v1.parquet` | `(1549, 43)` — `baseline=1,066`, `benign_drift=380`, `attacker_induced=103` (`1,104` cold-disk `dev` rows when excluding `75` live `process` rows) | `VERIFIED` |
| **Frozen v1 Split Manifest** | `sha256sum data/splits/dataset_v1_manifest.json` | `788b6a7cab836c1851a90c5069e89496aa748c33f86643a84d9d70cc50857fbe` | `PASS` |
| **Frozen v1 Footprint Log** | `wc -l results/logs/runner_footprint_dropped.csv` | `99` lines (`1` header + `98` dropped runner rows) | `PASS` |
| **Frozen v1 Git Diff** | `git diff --stat -- results/ data/ docs/FINAL_EVAL_PLAN.md collector/Collect-Artifacts.ps1` | *(empty — zero modifications)* | `PASS` |

**Uncommitted Pre-Existing Working-Tree Note (`git status -s`):**
- `M docs/v2/CLEAN_IMAGE_PARITY_REPORT.md` *(left untouched)* reports Mokh's latest live-overlay zero-SSH parity run: `991` shared cold-disk `artifact_key`s (`996` v1 cold-disk rows, `4,414` v2 offline rows), **`17/20 PASS`** (`signature_state = 98.39%`, `path_class = 100.00%`, `path_depth = 99.80%`, `parent_process_class = 100.00%`), with 3 minor numeric mismatches on strict `100% (|diff| <= 1e-6)` gates: `name_entropy` (`99.90%`, 1 row), `file_size_log` (`99.51%`, 4 rows), and `file_entropy` (`99.49%`, 4 rows). These 4 rows (most likely active files modified between `\DFIR-StageRunner`'s live collector pass and VM poweroff) should be inspected via `/tmp/parity_report.json` before starting Stage A pilot runs.

---

## 2. Audit of the 6 Pending Safety Items (`DONE` / `PARTIAL` / `GAP`)

Every safety requirement below was audited directly against the current repository scripts and decision docs:

| # | Safety Item | Audit Verdict | Exact `file:line` Evidence | Specific Gap & Required Remediation |
| :---: | :--- | :---: | :--- | :--- |
| **1** | **`05_quarantine_vault_setup.sh preflight` fails hard without a valid `GATE0_SIGNED_OFF` marker** | **`PARTIAL DONE / MINOR GAP`** | [`05_quarantine_vault_setup.sh:20-44`](hardening/05_quarantine_vault_setup.sh#L20-L44); [`v2_curate_vault_manifest.py:112-132`](../../scripts/v2_curate_vault_manifest.py#L112-L132); [`run_stage_a_pilot.py:164-171`](../../src/v2/run_stage_a_pilot.py#L164-L171) | Lines `21-24` check only `[[ ! -f "$GATE0_MARKER" ]]` (file existence — an empty `touch` passes!). Line `41` only prints `WARN: No $MANIFEST yet` if missing, even when `archives/` holds files. **Fix needed:** require `0400` permissions on `GATE0_SIGNED_OFF`, parse non-empty `SIGNED_BY=`, `DATE=`, `SUPERVISOR_APPROVAL=`, `CONTAINMENT_CHECKS=`, `DEDICATED_USER_VERIFIED=`, and fail hard if `archives/` is non-empty without a valid `sample_manifest.sha256`. *(Today `~/.quarantine_vault_dfir_v2/GATE0_SIGNED_OFF` is absent, so curation is blocked.)* |
| **2** | **`scripts/v2_curate_vault_manifest.py` and `OD-V2-08` hard-exclude ransomware, wiper, and worm families** | **`MAJOR GAP`** | [`OPERATOR_DECISIONS.md:20,76`](OPERATOR_DECISIONS.md#L20); [`v2_curate_vault_manifest.py:36-43,52`](../../scripts/v2_curate_vault_manifest.py#L36-L43); [`test_v2_parity_and_pilot.py:415,464`](../../tests/test_v2_parity_and_pilot.py#L415) | **Contradiction against Supervisor Marawan's safety scope:** `OD-V2-08` explicitly lists **`Ransomware`**; `v2_curate_vault_manifest.py:37` actively searches `("ransomware", ("ransomware", "lockbit", "stop", "makop", "phobos"))`; line `52` boosts `"ransom"` in `_PERSISTENCE_HINT_TOKENS`; **zero hard-deny blocklist** exists for ransomware, wipers, or self-propagating worms in `select_pilot_families` or `StageRunSpec`; and `test_v2_parity_and_pilot.py:415,464` uses `"lockbit"`/`"ransomware"` test fixtures. **Fix needed:** amend `OD-V2-08` (with Supervisor Marawan addendum), remove ransomware search tags/tokens, add a fail-closed family/tag deny-list across curator + `validate_stage_run_spec`, and update test fixtures. |
| **3** | **Wall-clock VM kill survives a Python runner crash (independent host watchdog)** | **`GAP`** | [`run_stage_a_pilot.py:218-225`](../../src/v2/run_stage_a_pilot.py#L218-L225); [`04_watchdog_and_base_hash.sh:33-56`](hardening/04_watchdog_and_base_hash.sh#L33-L56) | `run_stage_a_pilot.py:218` starts `win11` first and only then invokes `04_watchdog_and_base_hash.sh watchdog` **synchronously as a direct child subprocess** (lines `222-223`). If Python hits OOM/`SIGKILL`/Ctrl-C/unhandled error, the child watchdog dies with the Python process group and both `win11` and `inetsim-vm` stay powered on indefinitely. Additionally `04_watchdog_and_base_hash.sh` only watches `$DOMAIN` (`win11`), never `inetsim-vm`. **Fix needed:** arm a detached OS-level timer (`systemd-run --on-active=...` or detached `setsid` supervisor daemon + PID/epoch lease) **before** `virsh start win11` that destroys both `win11` and `inetsim-vm` independently of Python. |
| **4** | **Base-image SHA-256 check runs before and after every run** | **`PARTIAL DONE / EXCEPTION-PATH & SCALING GAP`** | [`run_stage_a_pilot.py:184,248`](../../src/v2/run_stage_a_pilot.py#L184); [`04_watchdog_and_base_hash.sh:20-32`](hardening/04_watchdog_and_base_hash.sh#L20-L32) | `execute_stage_a_pilot_batch` calls `verify-base` at line `184` (before `prepare-overlay`) and line `248` (after extraction), **but:** (a) line `248` is outside `try ... finally:`, so any VM/watchdog/container failure skips the post-run base check; (b) `04_watchdog_and_base_hash.sh:30` runs `sha256sum` over the full `129 GiB` logical / `15.7 GiB` disk `win11_base.qcow2` (`~50–90s` per check -> `~100–180s/run` = `~60–110 hours` overhead over 2,200+ runs). **Fix needed:** move post-run verification inside `finally:`, check both `win11_base.qcow2` and `inetsim_base.qcow2`, and pair fast per-run immutability (`lsattr` `+i`, `0444`, `stat` inode/blocks/mtime, full SHA-256 of `528 KiB` NVRAM) with periodic full `sha256sum -c` (or full SHA-256 every run if Mokh requires). |
| **5** | **Egress counters checked on `virbr1`** | **`GAP`** | [`01_firewall_win11_isolated.sh:126-146`](hardening/01_firewall_win11_isolated.sh#L126-L146); [`run_stage_a_pilot.py`](../../src/v2/run_stage_a_pilot.py) | `01_firewall_win11_isolated.sh` installs `V2_VIRBR1_IN` and `V2_VIRBR1_FWD` (`DROP` + `[V2-VIRBR1-DROP]` logging), verified once in `NEG-02`/`NEG-05`. However, neither `run_stage_a_pilot.py` nor `04_watchdog_and_base_hash.sh` checks that `V2_VIRBR1_IN`/`V2_VIRBR1_FWD` are still at position `1`/`1,2`, snapshots `iptables -L V2_VIRBR1_FWD -v -n -x` and `V2_VIRBR1_IN` byte/packet counters before/after each run, or halts the batch on non-zero cross-interface forward packets or anomalous `[V2-VIRBR1-DROP]` bursts. |
| **6** | **Canary mode passes before any unattended batch** | **`GAP`** | [`run_stage_a_pilot.py:538-567`](../../src/v2/run_stage_a_pilot.py#L538-L567) | CLI supports `--dry-run` only. There is no `--canary` supervised smoke test (`1` clean control + `1` dormant + `1` executed checking Sysmon ProcessCreate/Registry/FileCreate yield, zero egress counters, intact base hash, clean container output -> writing `CANARY_PASSED`) required before unattended batch execution. |

---

## 3. Critical Codebase Bottlenecks & Bugs Discovered

1. **Root Cause of `192.9s` vs. `~20s` Container Extraction (`offline_extractor.py:49,1090-1095`):**
   - On disk, [`/var/lib/dfir-quarantine-vault/win11_base_cache.json.gz`](file:///var/lib/dfir-quarantine-vault/win11_base_cache.json.gz) (`5.3 MB`, built `Nov 23 04:43`) was generated *before* commit `6405127` raised `MAX_PE_SIGNIFY_BYTES` from `64 * MIB` to `128 * MIB` (`offline_extractor.py:49`).
   - Because that pre-`6405127` cache stored `signature_status = "NotSigned"` for `OneDriveSetup.exe` (`89.7 MiB`) and other `> 64 MiB` signed PEs, [`offline_extractor.py:1090-1095`](../../src/v2/offline_extractor.py#L1090-L1095) triggers `stale_large_pe_hit` on every extraction (`base_cache_misses: 7`, `~160–193s`).
   - **Fix impact:** Rebuilding `win11_base_cache.json.gz` **once** against sealed `win11_base.qcow2` (`~3 min`) stores the `128 MiB`-valid entries cleanly, dropping cached container extraction back to **`~20–25s`** (`~8×` speedup, saving **`~104+ hours`** across 2,200+ runs).

2. **Unbounded Blinded-Review Positive Export (`review_v2.py:85`):**
   - [`src/v2/review_v2.py:85`](../../src/v2/review_v2.py#L85) sets:
     `n_pick = len(sub) if target_lbl == config.POSITIVE_LABEL else min(len(sub), int(max_per_stratum))`
   - With `1,000` samples (`~5,600–6,800` `attacker_induced` rows), this exports **every single positive row** instead of a stratified sample, imposing an unfeasible `~115+ hour` workload on Mokh's friend. Must be capped & family-stratified (e.g., `200` positives + `100` drift + `100` ambiguous = `400` rows).

3. **v1 REVENANT SHAP `feature_value: null` Bug (`export_findings.py:105`, `results/findings.json:20-36,68-84`):**
   - In [`src/eval/export_findings.py:95-110`](../../src/eval/export_findings.py#L95-L110), `_top_shap_list` reads `row.get(feat)` directly on the input DataFrame row. In [`results/findings.json`](../../results/findings.json#L20-L36), raw collector metadata contains `artifact_type` (`"file"`), so `feature_value` works there, **but engineered features** (`path_class`, `path_depth`, `file_size_log`, `name_entropy`) are missing on raw collector dicts and serialize as **`"feature_value": null`**.
   - Any v2 end-user API/dashboard adapter must compute/attach `F.row_features(row)` values before SHAP formatting and map them to plain-English explanations.

4. **Missing Train-Time Cross-Run OS-Baseline Deduplication (`training.py`):**
   - [`src/v2/training.py`](../../src/v2/training.py) currently sends all rows in `dev_df` unmodified to `SharedPreprocessor` and estimators. Scaling to `1,760+` dev runs (`~7.83M` raw rows, `98.9%` identical untouched OS files) will bloat memory and training time unless dev-only baseline deduplication (and stratified per-run baseline sampling for LTR `run_id` query groups) is separated cleanly from full-prevalence blind-test evaluation.

---

## 4. Audit of Existing `src/v2/` Modeling, Rules & Statistics Pipeline

### 4.1 Current `src/v2/` Model & Evaluation Inventory (`config_v2.py`, `models_v2.py`, `training.py`, `stats_v2.py`, `ablations_v2.py`)
- **Currently implemented models (`src/v2/config_v2.py:16-103`, `models_v2.py:611-632`):** Only **6 arms**:
  1. `rf` (`RandomForestArm`, 4 hyperparams)
  2. `xgb` (`XGBoostArm`, 5 hyperparams)
  3. `lr` (`LogisticRegressionArmV2`, `C` + `class_weight`)
  4. `iforest` (`IsolationForestArmV2`, 4 hyperparams, fit strictly on `y == 0`)
  5. `mlp` (`TabularMLPArmV2` PyTorch `Linear -> BatchNorm/LayerNorm -> ReLU -> Dropout`, 7 hyperparams, grouped inner-val early stopping or fixed-epoch full-dev refit)
  6. `ae` (`DeepAutoencoderArmV2` symmetric MSE autoencoder, 5 hyperparams, fit strictly on `y == 0`)
- **CV & Tuning Integrity (`src/v2/training.py`):** Strong anti-leakage foundation already built:
  - `build_family_cluster_groups` (`lines 54-123`): transitive union-find grouping over `sample_family`/`technique_id`, `packer_cluster`, `sample_sha256`, and `pair_group_id` for positives; `benign_session_id`/`run_id`/`artifact_key` for benign rows.
  - `make_inner_val_split` (`lines 126-164`) & `fit_arm_v2` (`lines 174-246`): outer `va_df` never accepted during training; inner-val early stopping uses disjoint grouped slices; `SharedPreprocessor` fits strictly inside train/fit slices.
  - `V2_FINAL_SEEDS = [42, 43, 44, 45, 46]`, `V2_N_SEARCH_TRIALS = 30` (`20` fallback), `V2_OUTER_FOLDS = 5`, `V2_INNER_FOLDS = 4`.
- **Statistics & Ablations (`src/v2/stats_v2.py`, `ablations_v2.py`):**
  - `FIXED_V2_COMPARISONS` (`stats_v2.py:54-64`): `9` fixed pairs over `(xgb, rf, mlp, rules_count, rules_binary)`.
  - `family_clustered_paired_bootstrap_p` (`lines 191-280`) + `holm_bonferroni_adjust` (`lines 283-303`) + `_dual_config_verdict` (`lines 306-324`): clean cluster-level bootstrap + dual-config verdict logic (needs expansion for an ~18–22 model study to avoid pairwise power collapse).
  - `tail_risk_and_effort_metrics` (`lines 116-176`), `compute_lofo_table` (`lines 455-507`), `cross_stratum_execution_delta` (`lines 510-652`), `assert_dev_only_ablation_guard` & `run_dev_ablations_v2` (`ablations_v2.py:102-334`).
- **Missing Pieces Needed for the Comparative Study:**
  - Models: `LinearSVC`, `Nystroem-RBF`, `kNN`, `DecisionTree`, `ExtraTrees`, `HistGradientBoosting`, `LightGBM`, `CatBoost`, `XGBRanker` (`rank:ndcg`), `LGBMRanker` (`lambdarank`), deep tabular (`FT-Transformer` / `ResNet-Tabular`, optional capped `TabPFN`), `OneClassSVM` (`Nystroem`), `LOF`, `Rule+ML Hybrid`.
  - Statistical & systems tools: Friedman/Nemenyi omnibus + critical-difference ranker, probability calibration (`ECE`, Brier, Platt/Isotonic), learning curves across family fractions, per-host inference + SHAP latency benchmarking, train-time baseline deduplication, and LTR `run_id` query-group batching.

### 4.2 Existing Rules & REVENANT Export Schema (`src/rules/deterministic_rules.py`, `src/eval/export_findings.py`, `results/findings.json`)
- **Deterministic Rules (`src/rules/deterministic_rules.py:43-72`):** 15 forensic rules (`RULE-001`..`RULE-015`) mapping cleanly to ATT&CK techniques (`T1547.001`, `T1053.005`, `T1543.003`, `T1546.003`, `T1218.011`, `T1059.001`, `T1574.001`, `T1036.005`, `T1548.002`, `T1112`, `T1136.001`, `T1562.001`, `T1552.001`) with `category`, `severity`, `confidence`, and `reason`.
- **Exporter Layering (`src/eval/export_findings.py:114-185`):**
  - Strictly strips ground-truth columns (`technique_id`, `label`, `label_reason`, `launcher`) before rule evaluation (`line 132`).
  - Separates **Layer 1 Findings (`F-xxxx`)** (artifacts with `>= 1` deterministic rule hit; `technique_id` sourced strictly from rule, sorted by ML score) from **Layer 2 Leads (`L-xxxx`)** (top-K unruled artifacts; `rule_ids_triggered: []`, `technique_id: null`).
  - Emits `artifact_ref` (`artifact_key`, `artifact_type`, `timestamp_utc`, `file_sha256`, `record_sha256`), `extracted_iocs` (`file_paths`, `sha256_hashes`, `urls_or_ips`), and `shap_top_features` (affected by the `feature_value: null` bug noted in §3.3).

---

## 5. ASUS Host Hardware, `.venv` Package & $O(N^2)$ Scaling Audit

### 5.1 Verified Host Hardware & Storage (`2026-11-25`)
| Resource | Measured Value on Host | Engineering Implication |
| :--- | :--- | :--- |
| **CPU** | **AMD Ryzen 7 7435HS** (`8` cores / `16` threads) | Fast parallel CPU training (`XGB`/`LGBM`/`RF`/`ET` with `n_jobs`). |
| **RAM & Swap** | **`23 GiB` usable** (`14–16 GiB` idle available) + `46 GiB` swap | `1` Windows 11 VM lane (`~7–9 GiB` total) fits comfortably; `2` parallel lanes (`~17.5–21.5 GiB` with `4 GiB` Win11 or `21.5–25.5 GiB` with `6 GiB` Win11) sit close to swap pressure. |
| **GPU** | **NVIDIA GeForce RTX 2050** (`4,096 MiB` VRAM, driver `615.78.08`, **`torch.cuda.is_available() = True`**) | Accelerates `MLP`, `AE`, `FT-Transformer`/`ResNet-Tabular`, and CatBoost GPU/CPU cleanly for `~60k–90k` tabular rows (`4 GiB` VRAM handles batch size `256–1024` easily). |
| **Disk (`/var` & `/home`)** | **`930 GB` total, `129 GB` used, `800 GB` free** (`/dev/mapper/root`) | Base images total `16.6 GiB` (`win11_base.qcow2` `15.7 GiB` actual / `129 GiB` virtual + `inetsim_base.qcow2` `862 MB`); live overlay `~253 MB`; `800 GB` easily accommodates all data tiers (`< 30 GB` peak). |
| **Extractor Container Limit** | `--memory=4g` ([`06_unprivileged_container_runner.sh:146`](hardening/06_unprivileged_container_runner.sh#L146)) | Serializing container extraction keeps host RAM headroom safe during concurrent runs. |

### 5.2 `.venv` Installed vs. Missing Packages & $O(N^2)$ / Row-Cap Feasibility

| Model / Package | Current `.venv` Status | Computational Scaling on `N_dev ~ 61k–91k` (LTR `320k–500k`) & `N_test ~ 1.96M` | Feasibility & Planned Mitigation on ASUS 24 GB Host |
| :--- | :---: | :--- | :--- |
| `LogisticRegression` (`scikit-learn==1.9.1`) | **INSTALLED** | $O(N \cdot d)$ train & infer; seconds | **Native — full data, zero cap** |
| `LinearSVC` + Platt (`scikit-learn==1.9.1`) | **INSTALLED** | $O(N \cdot d)$ dual/primal linear; seconds | **Native — full data, zero cap** |
| **Exact `SVC(kernel="rbf")`** | **INSTALLED** | **$O(N^2 \text{--} N^3)$ fit (`61k–91k` rows = multi-hour / infeasible CV) + $O(N_{\text{sv}} \cdot N_{\text{test}})$ infer** | **Infeasible exact -> use `Nystroem(kernel="rbf", n_components=500..1500) + LogisticRegression` ($O(N \cdot m^2)$)** *(optional 10k-subsample exact-RBF sanity check)* |
| **`KNeighborsClassifier`** (`kNN`) | **INSTALLED** | Exact brute/KD-tree query vs `N_train = 80k` over **`1.96M` blind-test rows** costs **$>150$ billion distances** ($O(N_{\text{train}} \cdot N_{\text{test}})$) | **Requires mitigation -> stratified `N_index <= 15,000` training reference + PCA/low-dim (`d <= 20`) or PyNNDescent/capped leaf index**; explicitly document reference cap |
| `DecisionTreeClassifier`, `RandomForest`, `ExtraTrees`, `HistGradientBoosting` (`scikit-learn==1.9.1`) | **INSTALLED** | $O(N \cdot d \log N)$ train, ms/host infer | **Native — full data (`n_jobs` parallel)** |
| `XGBClassifier`, `XGBRanker` (`xgboost==3.4.1`) | **INSTALLED** | $O(N \cdot d)$ `hist` tree builder; `rank:ndcg` grouped by `run_id` | **Native — full data** |
| `LGBMClassifier`, `LGBMRanker` (`lightgbm`) | **MISSING** (`pip install lightgbm`) | Fast CPU histogram trees + `lambdarank` | **Clean PyPI Linux wheel** (`pip install lightgbm`) |
| `CatBoostClassifier` (`catboost`) | **MISSING** (`pip install catboost`) | Symmetric oblivious trees; fast batch infer | **Clean PyPI Linux wheel** (`pip install catboost`) |
| `MLP`, `Autoencoder`, `ResNet-Tabular`, `FT-Transformer` (`torch==2.15.0` CUDA) | **INSTALLED** | Mini-batch $O(\text{epochs} \cdot N)$ on **RTX 2050 (4 GiB VRAM)**; `batch_size <= 512` | **Native CUDA — full data** (`< 30–60s` per fit) |
| **`TabPFN`** (`tabpfn`, optional) | **MISSING** (`pip install tabpfn` + weights) | **Hard architectural cap (`<= 10,000` training rows, $O(N^2)$ attention across context rows)** + batch infer limits over `1.96M` rows | **Strictly optional exploratory arm** on deterministic stratified `10k`-row dev subsample; excluded from full-data confirmatory winner tie if HF/VRAM limits apply |
| `IsolationForest` (`scikit-learn==1.9.1`) | **INSTALLED** | Subsampled tree paths (`256`–`1024`), fast | **Native — full benign dev data** |
| **Exact `OneClassSVM`** | **INSTALLED** | **$O(N^2 \text{--} N^3)$ QP solver fails to scale past `~15k–20k` benign rows** | **Use `Nystroem + SGDOneClassSVM` ($O(N \cdot m^2)$) for full benign dev** *(plus optional 15k-capped exact RBF-OCSVM sanity note)* |
| **`LocalOutlierFactor` (`novelty=True`)** | **INSTALLED** | Query cost is **$O(N_{\text{benign\_train}} \cdot N_{\text{test}})$** across `1.96M` test rows | **Requires stratified `N_index <= 15,000` benign reference cap** to bound `1.96M`-row blind-test scoring |
| API / Curation utilities (`optuna`, `fastapi`, `uvicorn`, `pydantic`, `pyzipper`) | **MISSING** | Lightweight host libraries | **Clean PyPI wheels** |
| Fuzzy hashing (`ssdeep`, `ppdeep`, `tlsh`, `py-tlsh`) | **MISSING** | Needs pure-Python or C wheel for local clustering | **`ssdeep` requires system `libfuzzy-dev` C headers** — use MalwareBazaar API metadata (`ssdeep`, `tlsh`, `imphash`) first + pure-Python `ppdeep` / `py-tlsh` (with `tlsh-c` optional) |

---

## 6. High-Level Keep / Archive (Descope) / Modify Summary

*(Full per-item matrix across `OD-V2-01..20`, all 13 `src/v2/` modules, `scripts/`, and all 10 `tests/test_v2_*.py` files is in [`REPLAN_COMPARATIVE_STUDY.md` §4](REPLAN_COMPARATIVE_STUDY.md#4-impact-analysis-keep--change--descope).)*

- **KEEP Untouched (Already Hardened & Verified):** Locked v1 files (`data/`, `results/`, `docs/FINAL_EVAL_PLAN.md`, `collector/Collect-Artifacts.ps1`), sealed `win11_base.qcow2` (`d2facced...`) & `Install-V2BaseBootstrap.ps1`, `00_bake_v2_base_image.sh`, `01_firewall_win11_isolated.sh`, `02_domain_xml_hardening.md`, `03_inetsim_vm_setup.md`, `06_unprivileged_container_runner.sh`, `07_incident_abort.sh`, `check_domain_xml.py`, `src/v2/offline_extractor.py` (keep pointer capture as-is), `src/v2/labeler_v2.py` (core Sysmon/dormant attribution), `src/v2/ablations_v2.py` (add learning-curve/baseline-dedup hooks cleanly), `scripts/compare_v1_v2_parity.py`, `scripts/verify_stratified_shortcuts.py`.
- **DESCOPE / ARCHIVE (No Further Feature Work; Keep Existing Code Non-Breaking):** `src/v2/refgraph.py`, `src/v2/refgraph_audit.py`, `docs/v2/REFGRAPH_SPEC.md`, `docs/v2/REFGRAPH_FEASIBILITY_V1_DEV.md`, `docs/v2/NOVELTY_VERIFICATION.md`, `docs/v2/FINAL_EVAL_PLAN_v2_SKELETON.md` §5 (`v2_refgraph` primary/secondary hypothesis framing — replaced by the comparative study pre-registration). Preserve existing unit tests cleanly so `317` regression guards remain intact.
- **CHANGE / NEW WORK REQUIRED:** Safety fixes (Items 1–6 above, especially removing ransomware + hard-blocking ransomware/wiper/worm in `OPERATOR_DECISIONS.md` / `v2_curate_vault_manifest.py` / `pilot_staging.py`, detached watchdog + `virbr1` counter assertions + canary mode in `run_stage_a_pilot.py`), `win11_base_cache.json.gz` rebuild, batch-dormant staging support in `pilot_staging.py`, `review_v2.py:85` positive cap, expanded model/LTR/stats/calibration suite (`config_v2.py`, `models_v2.py`, `training.py`, `stats_v2.py`), and new offline/demo API + Analyst Results UI module (`src/api/` + fix for `export_findings.py:105`).
