# DFIR-Triage ML v2 — Consolidated Sprint 1 – 1.7 Work Summary

**Date:** `2026-11-27`  
**Active Branch:** `v2-comparative-study` (HEAD `ebfe72d` before Sprint 1.7 commit; `origin/main` permanently untouched)  
**Status:** **`Sprint 1`, Container Fast-Refresh, `Sprint 1.5`, `Sprint 1.6`, and `Sprint 1.7` COMPLETE (`341 passed` in `200.56s`, `0` failures; containerized extraction `27.9s`)**  
**Governance:** Written approval granted by **Supervisor Marawan (AASTMT)** on `2026-11-23` and comparative study addendum approved `2026-11-25` (Tier 2 Target: `1,000` usable standalone-`.exe` samples + `200` benign runs; Tier 1 `400` usable Checkpoint 1; hard exclusion of ransomware, wipers, and self-propagating worms).

> **Scope Reminder:** Frozen v1 (`dataset_v1.parquet`) is cited solely as the initial baseline motivating v2 (`dev`-only `"emulated"` transfer stratum; `0%` blind test). All Phase v2 modeling (`Sprint 2`) awaits completion of operator family allowlist review, benign pool ingestion, Gate 0 vault init/`--canary`, and Stage A Pilot yield calibration.

---

## 1. Frozen v1 & Protected Baseline (Verified Untouched)

Every commit and test cycle verified zero modifications to frozen v1 artifacts (and throughout Sprint 1.6 zero modifications to `src/v2/offline_extractor.py`):

| Protected Artifact | Verified State (`2026-11-27`) |
| :--- | :--- |
| [`data/processed/dataset_v1.parquet`](../../data/processed/dataset_v1.parquet) | SHA-256 `39527f85fbda75f952e0cf5134a07467bf546501cb540ba68cd65b14983c7f21` |
| [`data/splits/dataset_v1_manifest.json`](../../data/splits/dataset_v1_manifest.json) | SHA-256 `788b6a7cab836c1851a90c5069e89496aa748c33f86643a84d9d70cc50857fbe` |
| [`results/logs/runner_footprint_dropped.csv`](../../results/logs/runner_footprint_dropped.csv) | `99` lines (`1` header + `98` dropped runner rows) |
| [`docs/FINAL_EVAL_PLAN.md`](../FINAL_EVAL_PLAN.md), [`collector/Collect-Artifacts.ps1`](../../collector/Collect-Artifacts.ps1) | `git diff --stat` empty (untouched) |
| [`src/v2/offline_extractor.py`](../../src/v2/offline_extractor.py) *(Sprint 1.6 vs 1.7 scope)* | Untouched throughout Sprint 1.6 vs. `39a2401`; updated in Sprint 1.7 strictly for the `> 128 MiB` WOF cache-miss fix |

---

## 2. Chronological Commit Ledger (`f969eee` -> `Sprint 1.7`)

| Commit | Timestamp | Branch | Scope & Summary | Changed Files / Diff |
| :--- | :---: | :---: | :--- | :---: |
| **`f969eee`** | `2026-11-25 23:54` | `main` (ancestor) | **Sprint 1:** Strategic comparative study pivot, 6 safety guards, standalone `.exe` gate, `--patch-stale-large-pe-cache`, offline `sysmon_events.jsonl`, hybrid `dormant_batch`, `deduplicate_dev_os_baseline`, 1-lane pipelining, `400`/`80` review cap, real benign pools/generator, `20`-trial `5×3` config, `.venv` packages, doc sync | `28` files (`+4891 / -906`) |
| **`de695d3`** | `2026-11-26 00:23` | `v2-comparative-study` | **Container Fast-Refresh Fix:** Offline code-only image refresh when `requirements_extractor.txt` is unchanged + BuildKit pip cache mount in `offline_extractor.Dockerfile` | `3` files (`+132 / -5`) |
| **`39a2401`** | `2026-11-26 01:00` | `v2-comparative-study` | **Sprint 1.5 (Safety):** Pin `GOLDEN_BASE_SHA256`, add `FORCE_RECORD=1` backup guard + unset `GOLDEN_NVRAM_SHA256` warning, fail-closed `ALLOWED_FAMILIES` + 22 whole-token blocks, and cryptographic/git/24h TTL binding for `CANARY_PASSED` + interactive `DETONATE` prompt | `7` files (`+791 / -75`) |
| **`fd95867`** | `2026-11-26 01:34` | `v2-comparative-study` | **Sprint 1.6:** Generator/extractor predicate alignment, pool `--enforce-quotas` + `synthetic_fallback` + `--require-real-pools`, `DORMANT_BATCH_MAX = 16` + `evaluate_stage_a_pilot_runs` wiring, `lime`/`limerat` removal + 13 canonical family aliases + review table, doc math/calibration/unsupervised fixes, systemd unit + IPv6 `virbr1` firewall chains | `19` files (`+1342 / -176`) |
| **`ebfe72d`** | `2026-11-26` | `v2-comparative-study` | `docs(v2): add consolidated Sprint 1-1.6 work summary and index entries` | `docs/v2/SPRINT_1_WORK_SUMMARY.md`, `docs/INDEX.md` |
| **`Sprint 1.7` *(this commit)*** | `2026-11-27` | `v2-comparative-study` | `>128 MiB` WOF cache-miss fix (`204s -> 27.9s`), warm `inetsim-vm` reuse, per-stratum dwell defaults (`45s`/`15s`/`15s`) + `dormant_batch_size`, diverse synthetic PE entropy, `GOLDEN_NVRAM_SHA256` pin, `arkei->vidar` / `recordbreaker->raccoon` aliases + `lineage_or_fork_notes` | `14` files |

---

## 3. Detailed Work Completed by Phase

### 3.1 Sprint 1 — Comparative Study Pivot, 6 Safety Guards & Infrastructure (`f969eee`)
- **Governance, Re-Scope & Audit Docs:** Audited pre-pivot bottlenecks and safety gaps in [`docs/v2/PIVOT_CODEBASE_AUDIT.md`](PIVOT_CODEBASE_AUDIT.md) and locked the comparative study design in [`docs/v2/REPLAN_COMPARATIVE_STUDY.md`](REPLAN_COMPARATIVE_STUDY.md), [`docs/v2/V2_PLAN.md`](V2_PLAN.md), [`docs/v2/OPERATOR_DECISIONS.md`](OPERATOR_DECISIONS.md), [`docs/v2/FINAL_EVAL_PLAN_v2_SKELETON.md`](FINAL_EVAL_PLAN_v2_SKELETON.md), and [`v2/plan.md`](../../v2/plan.md). Kept `v2_refgraph` descoped from v2 core while preserving existing pointer capture and unit tests intact.
- **6 Audited Safety Guards:**
  1. [`docs/v2/hardening/05_quarantine_vault_setup.sh`](hardening/05_quarantine_vault_setup.sh): Enforced `0400` permissions on `GATE0_SIGNED_OFF`, strict parsing of 5 non-empty metadata fields (`SIGNED_BY`, `DATE`, `SUPERVISOR_APPROVAL`, `CONTAINMENT_CHECKS`, `DEDICATED_USER_VERIFIED`), and fail-closed `sample_manifest.sha256` completeness check whenever `archives/` is non-empty.
  2. [`src/v2/pilot_staging.py`](../../src/v2/pilot_staging.py) & [`scripts/v2_curate_vault_manifest.py`](../../scripts/v2_curate_vault_manifest.py): Removed ransomware search tags/`"ransom"` hints, added fail-closed `FORBIDDEN_MALWARE_FAMILIES_AND_TAGS` + `FORBIDDEN_SUBSTRING_STEMS` across curator and `validate_stage_run_spec`, and added in-RAM `pefile` standalone runnable `.exe` verification (`validate_standalone_runnable_exe_pe`, rejecting DLLs/drivers/non-PEs before writing `0400` vault archives).
  3. [`docs/v2/hardening/04_watchdog_and_base_hash.sh`](hardening/04_watchdog_and_base_hash.sh): Added detached crash-surviving watchdog (`arm-watchdog` / `disarm-watchdog` via `setsid` / `systemd-run`) armed before `virsh start win11` covering both `win11` and `inetsim-vm`.
  4. [`src/v2/run_stage_a_pilot.py`](../../src/v2/run_stage_a_pilot.py) & `04_watchdog_and_base_hash.sh`: Added `verify-base-fast` (`0444`, `chattr +i` / inode / blocks / mtime, full NVRAM SHA-256) inside `try ... finally:`, paired with full `win11_base.qcow2` `verify-base` at batch start, end, aborts, and every `25` runs (`--full-base-hash-every`).
  5. `04_watchdog_and_base_hash.sh` & `run_stage_a_pilot.py`: Added `check-egress snapshot` / `verify` and `evaluate_egress_delta` verifying `virbr1` `INPUT`/`FORWARD` position 1 rules, zero UFW `ACCEPT` rules, and zero `V2_VIRBR1_FWD` drop-packet leakage -> logged to `egress_audit.jsonl`.
  6. `run_stage_a_pilot.py`: Implemented `--canary` supervised 3-boot smoke gate (`_select_canary_subset`: 1 `control` + 1 `executed` + 1 paired `dormant`) writing `CANARY_PASSED`, plus `--pipelined` (safe 1-lane overlay rename `win11_overlay_<run_id>.qcow2` + per-overlay `domblklist` check in `06_unprivileged_container_runner.sh`) and `completed_runs.jsonl` resume.
- **Extraction Speedup, Hybrid Dormant, Review Cap & Benign Pools:**
  - [`src/v2/offline_extractor.py`](../../src/v2/offline_extractor.py): Added `patch_stale_large_pe_cache` (`--patch-stale-large-pe-cache`) + atomic cache write to resolve `stale_large_pe_hit` (`OneDriveSetup.exe` `89.7 MiB`), plus read-only `sysmon_events.jsonl` EVTX export (`normalize_sysmon_evtx_record`).
  - [`src/v2/labeler_v2.py`](../../src/v2/labeler_v2.py) & `pilot_staging.py`: Implemented zero-rebake dev-only `dormant_batch` staging (`build_dormant_batch_bundle`, `label_dormant_batch_run`) and dev-only cross-run baseline collapse (`deduplicate_dev_os_baseline`, raising outside `split_pool == "dev"`).
  - [`src/v2/review_v2.py`](../../src/v2/review_v2.py): Fixed unbounded positive export (`line 85`), capping `export_blinded_review_sample` at `400` stratified primary rows (`200` `attacker_induced` stratified across stratum + family, `100` `benign_drift`, `100` `ambiguous_unattributed`) and `80` proportional `20%` overlap rows.
  - [`scripts/v2_prepare_benign_pools.py`](../../scripts/v2_prepare_benign_pools.py) & [`src/v2/benign_generator_v2.py`](../../src/v2/benign_generator_v2.py): Built disjoint `dev` / `blind_test` pool manager (zero package/SHA-256/filename overlap) and procedural benign workload generator (`B_dev_01..20` vs `B_test_01..10`).
  - [`src/v2/config_v2.py`](../../src/v2/config_v2.py): Locked `V2_N_SEARCH_TRIALS = 20` and `V2_INNER_FOLDS = 3` (`5×3` nested CV, `K=5` seeds `[42..46]`).
  - **`.venv` Package Versions Verified:** `lightgbm==4.7.0`, `catboost==1.2.10`, `optuna==5.1.0`, `fastapi==0.165.0`, `uvicorn==0.54.0`, `pydantic==2.14.4`, `pyzipper==0.4.0`, `ppdeep==20260221`, `py-tlsh==5.0.0` (alongside `scikit-learn==1.9.1`, `xgboost==3.4.1`, `torch==2.15.0`).

### 3.2 Container Extractor Fast-Refresh Fix (`de695d3`)
- [`docs/v2/hardening/06_unprivileged_container_runner.sh`](hardening/06_unprivileged_container_runner.sh) & [`docs/v2/hardening/offline_extractor.Dockerfile`](hardening/offline_extractor.Dockerfile): Added BuildKit pip cache mount and fast offline code-only refresh (`--pull=false` over cached `dfir-v2-offline-extractor-deps:<hash>`) whenever `requirements_extractor.txt` is unchanged (`~2s` instead of multi-minute base rebuild), preserving `--build --full` for full rebuilds.

### 3.3 Sprint 1.5 — Golden Hash Pinning, Fail-Closed Allowlist & Bound Canary (`39a2401`)
- [`docs/v2/hardening/04_watchdog_and_base_hash.sh`](hardening/04_watchdog_and_base_hash.sh): Pinned `GOLDEN_BASE_SHA256=d2facced4255e3ae1cb821249d5e6330e380f639cee8a5aae19ef99be690835c` in both `record-base` and `verify-base`; added no-overwrite guard unless `FORCE_RECORD=1` (creating timestamped `.bak.*` backups); emitted loud warning whenever `GOLDEN_NVRAM_SHA256` is unset.
- [`src/v2/pilot_staging.py`](../../src/v2/pilot_staging.py) & [`scripts/v2_curate_vault_manifest.py`](../../scripts/v2_curate_vault_manifest.py): Enforced fail-closed `ALLOWED_FAMILIES` allowlist (`require_allowlist=True` by default, rejecting blank/unreviewed/unknown families) plus 22 whole-token ransomware/worm additions; intentionally kept `njrat`, `bladabindi`, `qakbot`, `emotet`, and `trickbot` excluded pending supervisor review.
- [`src/v2/run_stage_a_pilot.py`](../../src/v2/run_stage_a_pilot.py): Cryptographically bound `CANARY_PASSED` to `batch_json_sha256`, `base_image_sha256`, `git_head`, `git_dirty`, `verified_at_utc`, and `expires_at_utc` (`24h` TTL via `CANARY_STAMP_TTL_SECONDS`, rejecting dirty working trees in unattended runs), and required exact interactive `DETONATE` confirmation before the first executed canary VM boot.

### 3.4 Sprint 1.6 — Generator/Extractor Parity, Pool Quotas, `dormant_batch=16`, Canonical Families, Docs Sync & IPv6/Systemd Firewall (`fd95867`)
- **Pre-Edit Bug Findings Diagnosed & Fixed:**
  1. `benign_generator_v2.py` previously emitted `.py` and `.zip`/`.json`/`.log` (`113 / 300` = `37.7%` files failed `_USER_SCAN_TARGET_EXTS` across all 30 profiles: `23` profiles failed `4/10`, `7` failed `3/10`; `0` directory/depth failures). Fixed **only** in `benign_generator_v2.py` to emit strictly safe `_USER_SCAN_TARGET_EXTS` (`BENIGN_SAFE_COLLECTED_EXTS`, excluding `.hta`/`.scr` and zero `.py`/`.zip`/`.json`/`.log`) inside walked `scan_roots` within depth limits, drawing high-entropy benign files from real pool `.exe`/`.msi` installers (with high-entropy PE fallback when allowed) and updating task commands off `.py`. Updated `simulate_benign_generator_rows` and `tests/test_v2_shortcut_audit.py` to import `_USER_SCAN_TARGET_EXTS` and `_SKIP_DIR_FRAGS` from `src.v2.offline_extractor` and assert 100% pass across all 30 profiles.
  2. Added `--enforce-quotas` and `HARD_FLOOR_QUOTAS` to `scripts/v2_prepare_benign_pools.py --audit` (exits non-zero `2` if `dev` or `blind_test` has `0` signed PEs or `0` unsigned PEs, or misses hard floors); recorded `synthetic_fallback`, `synthetic_fallback_count`, and `synthetic_fallback_counts` in `benign_manifest.json`; wired `require_real_pools` / `--stage {a,b}` / `--[no-]require-real-pools` through `pilot_staging.py` and `run_stage_a_pilot.py` (fatal when real pools are missing; default ON for Stage B, OFF for Stage A).
  3. Set single constant `DORMANT_BATCH_MAX = 16` used consistently in `validate_stage_run_spec`, `_DORMANT_BATCH_PS1_LOOP` (`$maxBatch = 16`), `build_dormant_batch_bundle` docstring, and `labeler_v2.label_dormant_batch_run`; wired `label_dormant_batch_run` into `evaluate_stage_a_pilot_runs` (which previously dropped `dormant_batch` via `else: continue`), included `"dormant_batch"` in `dorm_yield`, and replaced silent `else: continue` with `raise PilotStagingError`.
  4. Removed `'lime'` and `'limerat'` from `ALLOWED_FAMILIES` and added them to `FORBIDDEN_MALWARE_FAMILIES_AND_TAGS`; added `FAMILY_ALIAS_TO_CANONICAL`, `canonicalize_family_name`, and `CANONICAL_ALLOWED_FAMILIES` collapsing all 13 alias groups (`lumma`, `warzone`/`avemaria`, `redline`, `raccoon`, `remcos`, `quasar`, `orcus`, `nanocore`, `buer`, `aurora`, `revenge`, `gh0st`, `formbook`/`xloader`) to one canonical key used in `assign_v2_splits`, `build_family_cluster_groups`, `canonical_family_slug`, and `select_pilot_families`; created [`docs/v2/ALLOWED_FAMILIES_REVIEW.md`](ALLOWED_FAMILIES_REVIEW.md) listing all 62 canonical families with a blank `"spreader modules? (Mokh+supervisor to verify)"` column.
  5. Updated doc consistency across [`REPLAN_COMPARATIVE_STUDY.md`](REPLAN_COMPARATIVE_STUDY.md) (`440 × 200 = 88,000` benign + `1,400` positives = `~89,400` rows, `~1.57%`), [`V2_PLAN.md`](V2_PLAN.md) (unsupervised arms fit strictly on 100% of eligible `BENIGN (y == 0)` dev rows), [`OPERATOR_DECISIONS.md`](OPERATOR_DECISIONS.md), [`FINAL_EVAL_PLAN_v2_SKELETON.md`](FINAL_EVAL_PLAN_v2_SKELETON.md), and [`BENIGN_GENERATOR_DESIGN.md`](BENIGN_GENERATOR_DESIGN.md) (replaced every `Bayes prior-odds` claim with fitting calibrators/thresholds on natural-prevalence dev OOF or deduped dev rows weighted by multiplicity; updated benign extensions; verified 0 `"9 locked decisions"` header mismatches).
  6. Created systemd oneshot persistence unit [`docs/v2/hardening/v2-virbr1-firewall.service`](hardening/v2-virbr1-firewall.service) (`After=docker.service ufw.service libvirtd.service`) and added IPv6 `V2_VIRBR1_IN6` / `V2_VIRBR1_FWD6` chains + `ufw6-user-*` cleanup + `--status` IPv6 output to [`docs/v2/hardening/01_firewall_win11_isolated.sh`](hardening/01_firewall_win11_isolated.sh), verified with mocked `iptables`/`ip6tables` tests in [`tests/test_v2_hardening_validators.py`](../../tests/test_v2_hardening_validators.py).

### 3.5 Sprint 1.7 — `>128 MiB` WOF Cache-Miss Fix, Fast-Boot Optimization, Diverse PE Entropy & NVRAM/Alias Pinning
- **`src/v2/offline_extractor.py` (`>128 MiB` WOF Cache-Miss Fix):**
  - Root cause: `294.8 MiB` `MSEDGE.DLL` (`wof_compressed=True`, `> MAX_PE_SIGNIFY_BYTES` `128 MiB`) never computes full-file SHA-256 or Authenticode (`NotSigned`), yet unbounded `> 64 * MIB` stale checks caused every run to treat it as a cache miss and decompress all `37,734` WOF chunks in pure Python (`~185s`/run).
  - Fix: Added `max_out_bytes: int | None = None` early loop break to `decompress_wof_stream`; passed `max_out_bytes=MIB` in `_read_mft_file_bytes`'s huge-WOF branch; bounded both `patch_stale_large_pe_cache` and `stale_large_pe_hit` in `extract_from_qcow2` to `64 * MIB < size <= MAX_PE_SIGNIFY_BYTES` and `not checked_128mib` (setting `checked_128mib=True` on cached entries).
  - Containerized extraction benchmark on clean disposable overlay: `elapsed_seconds: 27.9` (down from `204s`/`388s`), `base_cache_hits: 2680`, `base_cache_misses: 4`, `total_records: 4413`, `wof_compressed_files: 2466`, `catroot_digests_loaded: 138984`, `sysmon_events_count: 7306`.
- **`src/v2/run_stage_a_pilot.py` & `scripts/v2_curate_vault_manifest.py` (Warm `inetsim-vm` Reuse & Per-Stratum Dwell Defaults):**
  - Added `keep_inetsim_warm: bool = True` (`--keep-inetsim-warm` / `--no-keep-inetsim-warm`) to `execute_stage_a_pilot_batch` to keep `inetsim-vm` running across consecutive `executed` runs and tear it down cleanly before non-executed strata, on `run_failed`, and in the outer `finally:` block.
  - Replaced uniform `120s` dwell with per-stratum defaults in `build_pilot_batch_specs` and `curate_pilot_vault_and_batch`: `DEFAULT_EXECUTED_DWELL_SECONDS = 45`, `DEFAULT_DORMANT_DWELL_SECONDS = 15`, `DEFAULT_CONTROL_DWELL_SECONDS = 15`, plus `dormant_batch_size` (`1..DORMANT_BATCH_MAX=16`, dev-only), `split_pool`, and `group_executed_runs` using `dataclasses.asdict(spec)`.
- **`src/v2/benign_generator_v2.py` (Diverse Synthetic PE Entropy):**
  - Updated `_synth_unsigned_pe_bytes` to sample across 3 ASCII pools and 3 entropy regimes (low-entropy padded/resource, native `.text`/`.rdata`, dense packed) and varied `high_entropy=True` code/string fractions, verified by `test_synthetic_pe_fallback_entropy_spread` (`std >= 0.50`, `range >= 2.0` over `n >= 48` PEs).
- **`docs/v2/hardening/04_watchdog_and_base_hash.sh`, `src/v2/pilot_staging.py`, `docs/v2/ALLOWED_FAMILIES_REVIEW.md` & `docs/INDEX.md` (NVRAM Pin & Canonical Family Aliases):**
  - Pinned `GOLDEN_NVRAM_SHA256=2aeb86356d8c160607a0f258d8b0044b2e30a592c510992b28cb5f5312dda6be` (verified by `verify-base-fast`).
  - Added `"arkei": "vidar"`, `"vidar": "vidar"`, and `"recordbreaker": "raccoon"` to `FAMILY_ALIAS_TO_CANONICAL` (`77` allowed slugs -> `60` canonical families), removed standalone `arkei`/`recordbreaker` rows and added the `lineage_or_fork_notes` column to [`docs/v2/ALLOWED_FAMILIES_REVIEW.md`](ALLOWED_FAMILIES_REVIEW.md).
- **Test Coverage:** Added Sprint 1.7 unit tests across `tests/test_v2_offline_extractor.py`, `tests/test_v2_parity_and_pilot.py`, `tests/test_v2_shortcut_audit.py`, `tests/test_v2_labeler_and_review.py`, and `tests/test_v2_hardening_validators.py`.

---

## 4. Verification & Test Progression

| Milestone | Verification Command | Observed Result |
| :--- | :--- | :--- |
| Pre-Pivot Audit (`bc12c57`) | `.venv/bin/pytest` | `317 passed in 193.39s (0:03:13)` |
| Sprint 1.5 (`39a2401`) | `.venv/bin/pytest -ra` | `330 passed in 196.71s (0:03:16)` |
| Sprint 1.6 (`fd95867`) | `.venv/bin/pytest -ra` | `337 passed in 201.68s (0:03:21)` (`0` failures, `0` skipped) |
| Shell & Policy Checks (`fd95867`) | `bash -n docs/v2/hardening/*.sh` + doc grep + frozen diff check | Exit `0`; `0` `Bayes`/`prior-odds` hits; frozen v1 hashes & `offline_extractor.py` diff empty |
| **Sprint 1.7 (full suite)** | `.venv/bin/pytest -ra` | **`341 passed in 200.56s (0:03:20)`** (`0` failures, `0` skipped) |
| **Sprint 1.7 (container benchmark)** | `06_unprivileged_container_runner.sh` (`win11_base.qcow2` overlay + `win11_base_cache.json.gz`) | Exit `0`; `elapsed_seconds: 27.9`, `base_cache_hits: 2680`, `base_cache_misses: 4`, `total_records: 4413`, `sysmon_events_count: 7306` |
| **Sprint 1.7 (host integrity & scripts)** | `04_watchdog_and_base_hash.sh verify-base-fast` + `bash -n docs/v2/hardening/*.sh` + frozen v1 check | Exit `0`; NVRAM + `+i`/`0444` immutability PASSED; `bash -n` OK; frozen v1 untouched |

---

## 5. Pending Operator Actions & Next Phase (`Sprint 2`)

### Host Actions (Completed vs. Pending)
1. **DONE (`2026-11-26`) — Persistent IPv4+IPv6 firewall unit installed (`/etc/systemd/system/v2-virbr1-firewall.service`).**
2. **DONE (`2026-11-26`) — Golden base & NVRAM hashes recorded (`GOLDEN_NVRAM_SHA256` pinned + verified with `verify-base-fast`) and `/var/lib/dfir-quarantine-vault/win11_base_cache.json.gz` patched.**
3. **PENDING — Verify [`docs/v2/ALLOWED_FAMILIES_REVIEW.md`](ALLOWED_FAMILIES_REVIEW.md) blank column** (`spreader modules? (Mokh+supervisor to verify)`) with Supervisor Marawan before large-scale curation.
4. **PENDING — Populate & audit disjoint `dev`/`blind_test` benign pools** (`scripts/v2_prepare_benign_pools.py --init-dirs`, ingest real third-party signed/unsigned PEs, scripts, and `.msi`/`.exe` installers, then verify with `--audit --enforce-quotas`).
5. **PENDING — Initialize Gate 0 Vault & run supervised `--canary`** (`05_quarantine_vault_setup.sh init` -> sign `0400` `GATE0_SIGNED_OFF` -> `preflight` -> curate 7 pilot families -> `run_stage_a_pilot.py --canary` -> execute Stage A Pilot).

### Upcoming Engineering (`Sprint 2`, Post-Stage-A-Pilot)
- Expand [`src/v2/models_v2.py`](../../src/v2/models_v2.py), [`src/v2/training.py`](../../src/v2/training.py), and [`src/v2/stats_v2.py`](../../src/v2/stats_v2.py) to the full `~20`-arm comparative suite (`XGBRanker`, `LGBMRanker`, `CatBoost`, `LightGBM`, `LinearSVC`, `Nystroem-RBF`, capped `kNN`/`LOF`, `FT-Transformer`/`ResNet-Tabular`, `Nystroem-OCSVM`, `RuleMLHybrid`, natural-prevalence dev OOF / weighted calibration, Friedman/Nemenyi + `m=10` Holm-Bonferroni + 5-axis scorecard).
- Build air-gapped `src/api/` (not yet created; `ScorerAdapter`, SHAP `feature_value` fix, FastAPI results reader + clean demo separation, analyst UI).
