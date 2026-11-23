# Clean-Image Feature Parity Report (Live v1 vs. Offline v2)

- **Overall Verdict:** **`PASS`**
- **Shared Matched `artifact_key`s:** `727` (v1 cold-disk rows: `732`, v2 offline rows: `4152`)
- **Offline `process` Rows:** `0` | **`parent_process_class == 'na'` on 100% of offline rows:** `True`

| Feature | Category | Compared Rows | Agreement Rate | Max `|v2 - v1|` | Acceptance Threshold | Status |
| :--- | :--- | ---: | ---: | ---: | :--- | :---: |
| `artifact_type` | `exact_or_1e-6` | `727` | `100.00%` | `0.0` | 100.0% (|diff| <= 1e-6) | **`PASS`** |
| `path_class` | `target_path_resolution` | `727` | `100.00%` | `0.0` | >= 99.0% exact agreement | **`PASS`** |
| `ext_class` | `exact_or_1e-6` | `727` | `100.00%` | `0.0` | 100.0% (|diff| <= 1e-6) | **`PASS`** |
| `signature_state` | `catalog_and_pe_sig` | `727` | `98.07%` | `0.0` | >= 98.0% exact agreement | **`PASS`** |
| `parent_process_class` | `cold_disk_constant_na` | `4152` | `100.00%` | `0.0` | 0 process rows & 100% 'na' offline | **`PASS`** |
| `registry_location_class` | `exact_or_1e-6` | `727` | `100.00%` | `0.0` | 100.0% (|diff| <= 1e-6) | **`PASS`** |
| `path_depth` | `target_path_resolution` | `727` | `100.00%` | `0.0` | >= 99.0% exact agreement | **`PASS`** |
| `name_length` | `exact_or_1e-6` | `727` | `100.00%` | `0.0` | 100.0% (|diff| <= 1e-6) | **`PASS`** |
| `name_entropy` | `exact_or_1e-6` | `727` | `100.00%` | `0.0` | 100.0% (|diff| <= 1e-6) | **`PASS`** |
| `file_size_log` | `exact_or_1e-6` | `566` | `100.00%` | `0.0` | 100.0% (|diff| <= 1e-6) | **`PASS`** |
| `file_entropy` | `exact_or_1e-6` | `530` | `100.00%` | `0.0` | 100.0% (|diff| <= 1e-6) | **`PASS`** |
| `cmdline_length` | `cmdline_tolerance` | `727` | `100.00%` | `0.0` | >= 98.0% within (|dl|<=2, |de|<=0.05, |dr|<=0.02) | **`PASS`** |
| `cmdline_entropy` | `cmdline_tolerance` | `727` | `100.00%` | `0.04761905` | >= 98.0% within (|dl|<=2, |de|<=0.05, |dr|<=0.02) | **`PASS`** |
| `cmdline_nonalnum_ratio` | `cmdline_tolerance` | `727` | `100.00%` | `0.0` | >= 98.0% within (|dl|<=2, |de|<=0.05, |dr|<=0.02) | **`PASS`** |
| `has_double_extension` | `exact_or_1e-6` | `727` | `100.00%` | `0.0` | 100.0% (|diff| <= 1e-6) | **`PASS`** |
| `has_encoded_flag` | `exact_or_1e-6` | `727` | `100.00%` | `0.0` | 100.0% (|diff| <= 1e-6) | **`PASS`** |
| `has_url_or_ip` | `exact_or_1e-6` | `727` | `100.00%` | `0.0` | 100.0% (|diff| <= 1e-6) | **`PASS`** |
| `has_lolbin` | `exact_or_1e-6` | `727` | `100.00%` | `0.0` | 100.0% (|diff| <= 1e-6) | **`PASS`** |
| `has_hidden_attr` | `exact_or_1e-6` | `727` | `100.00%` | `0.0` | 100.0% (|diff| <= 1e-6) | **`PASS`** |
| `autostart_flag` | `exact_or_1e-6` | `727` | `100.00%` | `0.0` | 100.0% (|diff| <= 1e-6) | **`PASS`** |

## 2. `v2_refgraph` Link Coverage Verification (`OD-V2-20` Persistence/Execution Gate)

Extracted from closed `/var/lib/libvirt/images/win11_base.qcow2` (`d2facced4255e3ae1cb821249d5e6330e380f639cee8a5aae19ef99be690835c`, `extractor_version: 2.2.0`, `base_cache_used: true`, `base_cache_hits: 2,677`, `base_cache_misses: 7`, `catroot_digests_loaded: 138,984`, `wof_compressed_files: 2,466`, `total_records: 4,413`):

- **`OD-V2-20` Persistence/Execution Gate (`task`, `service`, `run_key`, `wmi_subscription`, `prefetch`):** **`796 / 799` (`99.62%`)** resolved (well above the `50.0%` go/no-go threshold).
- **Overall Dataset Link Rates:** `rows_with_resolved_outgoing = 1,672 / 4,413` (`37.89%`), `rows_with_any_resolved_link = 2,344 / 4,413` (`53.12%`).

| `artifact_type` | Rows | `with_resolved_link` | `resolved_targets` | `resolved_rate_pct` |
| :--- | ---: | ---: | ---: | ---: |
| `task` | `272` | `271` | `281` | `99.63%` |
| `service` | `261` | `261` | `483` | `100.00%` |
| `run_key` | `4` | `4` | `4` | `100.00%` |
| `prefetch` | `260` | `260` | `12,843` | `100.00%` |
| `wmi_subscription` | `2` | `0` | `0` | `0.00%` |
| `amcache` | `673` | `672` | `672` | `99.85%` |
| `registry` | `210` | `204` | `204` | `97.14%` |
| `file` | `2,421` | `0` *(target node)* | `0` | `0.00%` |
| `shimcache` | `306` | `0` | `0` | `0.00%` |
| `account` | `4` | `0` | `0` | `0.00%` |

## 3. Residual Signature Notes & v2 Harness Footprint Filtering

- **v2 Harness Footprint Excluded Deterministically (`v2_harness_footprint_dropped_count: 8`):** `task|\|dfir-stagerunner`, `service|...|sysmon64`, `2` `SYSMON64.EXE-*.pf` prefetch rows, `1` `shimcache` `sysmon64.exe` row, `2` `amcache` `sysmon64.exe` rows, and `1` `file` `C:\WINDOWS\Sysmon64.exe` row.
- **Residual `signature_state` Discrepancies (`14 / 727`, `98.07%` `PASS`):** `OneDriveSetup.exe` (`89,771,848` bytes; `1` `file` + `2` `run_key` rows) now verifies as `Valid` (`signed_trusted`) after raising `MAX_PE_SIGNIFY_BYTES` to `128 MiB`; the remaining `14` diffs are `10` OLE2-signed `.msi` installers under `C:\Users\mokh\AppData\Local\Package Cache` and `4` `.lnk` shortcuts (`v1: signed_trusted`, `v2: na`).

