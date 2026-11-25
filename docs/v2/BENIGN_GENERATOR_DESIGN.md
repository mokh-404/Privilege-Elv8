# Step C.6 — Real Benign Workload Generator & Disjoint Pool Design (`IMP-06`, `OD-V2-12`)

**Status:** `IMPLEMENTED IN src/v2/benign_generator_v2.py & scripts/v2_prepare_benign_pools.py (2026-11-25)`  
**Audit Scripts:** [`scripts/v2_prepare_benign_pools.py`](../../scripts/v2_prepare_benign_pools.py) | [`scripts/verify_stratified_shortcuts.py`](../../scripts/verify_stratified_shortcuts.py)

---

## 1. Root Cause Fixed from v1 (`IMP-06`)

In v1, `lab_automation/benign_noise.ps1` drew from 6 fixed string templates, collapsing `221` benign dev script files onto `18` unique `file_size_log` values (`0.081` ratio) and `30` `(file_size_log, file_entropy)` pairs, while producing **`0` benign `service` drift**, **`0` benign `registry` drift**, and concentrating `unsigned` rows inside synthetic templates.

---

## 2. Disjoint Real Benign Asset Pools & Target Quotas

Ingests real open-source Windows binaries, scripts, and installers into external non-repo pools (`/var/lib/dfir-quarantine-vault/benign_pools/dev/` vs `.../blind_test/`) with hard assertions enforcing **zero SHA-256, normalized filename, and package-folder overlap** (never harvesting from `win11_base.qcow2`, whose single OS vendor breaks vendor-disjointness):

| Benign Drift Component | Target Unique Quota | Hard Floor (`dev + blind_test`) | Disjoint Assignment |
| :--- | :---: | :---: | :--- |
| **Legitimate Unsigned PE Binaries (`.exe`/`.dll`)** | `300–400` | `>= 200` (`>= 1` in `dev` & `blind_test`) | Disjoint open-source tool rosters (`DEV_PACKAGE_ROSTER` vs `BLIND_TEST_PACKAGE_ROSTER`) |
| **Signed 3rd-Party PE Binaries (`.exe`/`.dll`)** | `300–400` | `>= 200` (`>= 1` in `dev` & `blind_test`) | Verified via offline `signify` + `CatRoot` (`Valid` vs `NotSigned`) |
| **Procedurally Varied Scripts (`.ps1`/`.psm1`/`.bat`/`.cmd`/`.vbs`/`.vbe`/`.js`)** | `500–700` | `>= 350` | Procedural script/comment synthesis per `run_id` inside extractor `_USER_SCAN_TARGET_EXTS` (zero `.py`) |
| **High-Entropy Benign Installers (`.exe`/`.msi`)** | `400–500` | `>= 250` | Real pool `.exe`/`.msi` installers staged in walked user cache roots (zero `.zip`/`.json`/`.log`; `.hta`/`.scr` avoided) |
| **Total Unique Benign Drift Files** | **`1,500–2,000`** | **`>= 1,000`** | `~1,200–1,600` `dev` / `~300–400` `blind_test` (`--enforce-quotas` enforces hard floors + PE splits) |
| **Benign Persistence Entries** | **`200–400`** | `>= 100` | Benign Services (`Auto`/`Manual`), varied-trigger Scheduled Tasks (`ONLOGON`/`ONSTART`/`DAILY`/`ONCE`/`ONIDLE`), `Run`/`RunOnce`, and benign `IFEO` Registry keys |

- **Quota Enforcement & Real-Pool Requirement:** `scripts/v2_prepare_benign_pools.py --audit --enforce-quotas` exits non-zero if either split has `0` signed PEs, `0` unsigned PEs, or misses any hard floor. Whenever `_synth_unsigned_pe_bytes` fallback is used, `benign_manifest.json` records `synthetic_fallback: true` plus `synthetic_fallback_counts`; passing `--require-real-pools` (default ON for Stage B, OFF for Stage A) makes synthetic fallback fatal.

---

## 3. Procedural Per-Run Generator & Disjoint Host Profiles

[`src/v2/benign_generator_v2.py`](../../src/v2/benign_generator_v2.py) replaces placeholder scripts in [`pilot_staging.py`](../../src/v2/pilot_staging.py) and [`run_stage_a_pilot.py`](../../src/v2/run_stage_a_pilot.py):
- **Disjoint Profiles:** `DEV_WORKLOAD_PROFILES` (`B_dev_01..B_dev_20`) vs `BLIND_TEST_WORKLOAD_PROFILES` (`B_test_01..B_test_10`) use separate user names, `ProgramData`/`Users`/`Temp` subdirectories, service prefixes, scheduled-task folders (`\DevOpsTasks` vs `\EndpointOps`), `Run`/`RunOnce` prefixes, and `IFEO` target names.
- **Deterministic Per-Run Benign Manifest:** Exports `benign_manifest.json` per run so [`src/v2/labeler_v2.py`](../../src/v2/labeler_v2.py) cleanly attributes staged benign files, services, tasks, run keys, and registry edits to `benign_drift` rather than `ambiguous_unattributed`.

---

## 4. Automated Pass/Fail Template-Quantization & Disjointness Gate

[`tests/test_v2_shortcut_audit.py`](../../tests/test_v2_shortcut_audit.py) enforces ALL six criteria on `benign_generator_v2` plus `0` cross-split overlap:
- `unique_size_ratio >= 0.60`
- `unique_size_entropy_pair_ratio >= 0.75`
- `max_single_size_share <= 0.10`
- `benign_services > 0`, `benign_registry > 0`, `benign_unsigned_pes > 0`
- `0` SHA-256, filename, `artifact_key`, task, service, and registry overlap between `dev` and `blind_test`.
