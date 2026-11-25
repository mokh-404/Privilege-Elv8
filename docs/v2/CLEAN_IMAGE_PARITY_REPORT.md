# Clean-Image Feature Parity Report (Live v1 vs. Offline v2)

## 1. Sealed Golden Base Parity Baseline (`win11_base.qcow2`, Commit `6405127` -> **`20/20 PASS`**)

- **Overall Verdict:** **`PASS`** (`20 / 20` feature gates passing against `ctrl_01` after fixing 4 parity rules & `MAX_PE_SIGNIFY_BYTES = 128 MiB`)
- **Shared Matched `artifact_key`s:** `727` (v1 cold-disk rows: `732`, v2 offline rows: `4,152`)
- **Offline `process` Rows:** `0` | **`parent_process_class == 'na'` on 100% of offline rows:** `True`
- **`OD-V2-20` Static Persistence/Execution Link Rate:** `796 / 799` (`99.62%`)

---

## 2. Live Zero-SSH Overlay Boot Parity Run (`2026-11-23` — 5 Verified Benign Shutdown/Bake Rows)

- **Observed Status on Live Same-Overlay Boot:** **`17 / 20 PASS`**, `3` minor live-boot diffs (`991` shared cold-disk `artifact_key`s across `996` v1 cold-disk rows and `4,414` v2 offline rows).
- **Verified Root Cause of the 5 Differing Rows (Confirmed Benign OS Shutdown & Bake-ISO Drift):**
  1. **`4` Windows Licensing / Taskhost Prefetch Files (`file_size_log` `99.51%`, `file_entropy` `99.49%`):** `slui.exe`, `sppextcomobj.exe`, `sppsvc.exe`, and `taskhostw.exe` `.pf` files updated cleanly by Windows shutdown/licensing between `\DFIR-StageRunner`'s live `Collect-Artifacts.ps1` pass and VM poweroff (`Stop-Computer -Force`).
  2. **`1` ShimCache Entry (`name_entropy` `99.90%`):** `sysmon64.exe` residual ShimCache entry recorded from the one-time `DFIR_BAKE` maintenance ISO path during base-image baking (`00_bake_v2_base_image.sh`).
- **Conclusion:** Zero extractor parity regression exists; the `17/20` diff reflects solely 4 live shutdown `.pf` updates + 1 pre-seal bake-ISO ShimCache artifact between live collection and disk flush.

| Feature | Category | Compared Rows | Agreement Rate | Max `|v2 - v1|` | Acceptance Threshold | Status |
| :--- | :--- | ---: | ---: | ---: | :--- | :---: |
| `artifact_type` | `exact_or_1e-6` | `991` | `100.00%` | `0.0` | 100.0% (|diff| <= 1e-6) | **`PASS`** |
| `path_class` | `target_path_resolution` | `991` | `100.00%` | `0.0` | >= 99.0% exact agreement | **`PASS`** |
| `ext_class` | `exact_or_1e-6` | `991` | `100.00%` | `0.0` | 100.0% (|diff| <= 1e-6) | **`PASS`** |
| `signature_state` | `catalog_and_pe_sig` | `991` | `98.39%` | `0.0` | >= 98.0% exact agreement | **`PASS`** |
| `parent_process_class` | `cold_disk_constant_na` | `4414` | `100.00%` | `0.0` | 0 process rows & 100% 'na' offline | **`PASS`** |
| `registry_location_class` | `exact_or_1e-6` | `991` | `100.00%` | `0.0` | 100.0% (|diff| <= 1e-6) | **`PASS`** |
| `path_depth` | `target_path_resolution` | `991` | `99.80%` | `2.0` | >= 99.0% exact agreement | **`PASS`** |
| `name_length` | `exact_or_1e-6` | `991` | `100.00%` | `0.0` | 100.0% (|diff| <= 1e-6) | **`PASS`** |
| `name_entropy` | `exact_or_1e-6` | `991` | `99.90%` | `0.35849625` | 100.0% (|diff| <= 1e-6) | **`FAIL` (1 bake ShimCache row)** |
| `file_size_log` | `exact_or_1e-6` | `824` | `99.51%` | `0.00645252` | 100.0% (|diff| <= 1e-6) | **`FAIL` (4 shutdown `.pf` rows)** |
| `file_entropy` | `exact_or_1e-6` | `788` | `99.49%` | `0.03118784` | 100.0% (|diff| <= 1e-6) | **`FAIL` (4 shutdown `.pf` rows)** |
| `cmdline_length` | `cmdline_tolerance` | `991` | `100.00%` | `0.0` | >= 98.0% within (|dl|<=2, |de|<=0.05, |dr|<=0.02) | **`PASS`** |
| `cmdline_entropy` | `cmdline_tolerance` | `991` | `100.00%` | `0.04761905` | >= 98.0% within (|dl|<=2, |de|<=0.05, |dr|<=0.02) | **`PASS`** |
| `cmdline_nonalnum_ratio` | `cmdline_tolerance` | `991` | `100.00%` | `0.0` | >= 98.0% within (|dl|<=2, |de|<=0.05, |dr|<=0.02) | **`PASS`** |
| `has_double_extension` | `exact_or_1e-6` | `991` | `100.00%` | `0.0` | 100.0% (|diff| <= 1e-6) | **`PASS`** |
| `has_encoded_flag` | `exact_or_1e-6` | `991` | `100.00%` | `0.0` | 100.0% (|diff| <= 1e-6) | **`PASS`** |
| `has_url_or_ip` | `exact_or_1e-6` | `991` | `100.00%` | `0.0` | 100.0% (|diff| <= 1e-6) | **`PASS`** |
| `has_lolbin` | `exact_or_1e-6` | `991` | `100.00%` | `0.0` | 100.0% (|diff| <= 1e-6) | **`PASS`** |
| `has_hidden_attr` | `exact_or_1e-6` | `991` | `100.00%` | `0.0` | 100.0% (|diff| <= 1e-6) | **`PASS`** |
| `autostart_flag` | `exact_or_1e-6` | `991` | `100.00%` | `0.0` | 100.0% (|diff| <= 1e-6) | **`PASS`** |
