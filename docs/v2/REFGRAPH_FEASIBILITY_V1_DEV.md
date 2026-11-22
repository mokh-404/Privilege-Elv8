# Step E4 — Read-Only Referential-Graph Link Coverage Feasibility Audit (v1 `DEV` Only)

**Scope & Isolation Guarantee:** Executed strictly on `data/processed/dataset_v1.parquet` filtered immediately to **`split_pool == "dev"` (`1,179` rows: `1,104` cold-disk static rows + `75` live-collected `process` rows)** via [`src/v2/refgraph_audit.py`](../../src/v2/refgraph_audit.py).  
- **Zero blind/test rows accessed:** `split_pool == "test"` was never read or inspected.  
- **Zero model training or scoring:** This feasibility audit measures static pointer extraction and resolution coverage only.  
- **Reproduction command:** `.venv/bin/python -m src.v2.refgraph_audit --include-live-process`

---

## 1. Plain Verdict on v1 Link Coverage

> [!IMPORTANT]
> **Cold-disk static link coverage on v1 `dev` data is LOW: only `5.16%` (`57 / 1,104`) of cold-disk artifacts have `>= 1` resolved outgoing static link, and only `10.33%` (`114 / 1,104`) participate in ANY resolved static link (outgoing or incoming).**  
> Out of `707` extracted static pointers on cold-disk rows, **`638` (`90.24%`) dangle**, **`9` (`1.27%`) are ambiguous**, and only **`60` (`8.49%`) resolve uniquely**. Major persistence and execution types — `service` (`0/192`), `prefetch` (`0/194`), `shimcache` (`0/3`), `account` (`0/8`), and all `108` COM-handler `task` pointers — have **`0%` verified cold-disk connectivity** in v1 fields.

The low coverage is a direct consequence of what v1's live PowerShell collector omitted (`Collect-Artifacts.ps1` did not collect `$MFT`, `System32` binaries, `.pf` File Metrics, `CLSID` hives, `Services\Parameters\ServiceDll`, `Amcache.hve`, or `TaskCache`) and validates why the offline pointer-capture extensions in [`hardening/POINTER_CAPTURE_SPEC.md`](hardening/POINTER_CAPTURE_SPEC.md) are required for `v2_refgraph` to operate meaningfully in Phase v2.

---

## 2. Per-`artifact_type` Coverage (v1 `DEV`, Cold-Disk Static Rows: `n = 1,104`)

*(Cold-disk view excludes `75` live-collected `process` rows, which do not exist on powered-off dead disks.)*

| `artifact_type` | `total_rows` | `rows_with_extracted_pointer` | `rows_with_resolved_outgoing` (%) | `rows_with_resolved_incoming` (`incoming_links`) | `rows_with_any_resolvable_link` (%) | `dangling_pointers` | `ambiguous_pointers` |
| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `file` | 444 | 0 | 0 (`0.00%`) | 53 (`54`) | 53 (`11.94%`) | 0 | 0 |
| `task` | 201 | 201 | 19 (`9.45%`) | 0 (`0`) | 19 (`9.45%`) | 220 | 0 |
| `prefetch` | 194 | 194 | 0 (`0.00%`) | 0 (`0`) | 0 (`0.00%`) | 185 | 9 |
| `service` | 192 | 192 | 0 (`0.00%`) | 0 (`0`) | 0 (`0.00%`) | 192 | 0 |
| `run_key` | 41 | 41 | 29 (`70.73%`) | 0 (`0`) | 29 (`70.73%`) | 29 | 0 |
| `registry` | 10 | 4 | 3 (`30.00%`) | 0 (`0`) | 3 (`30.00%`) | 4 | 0 |
| `wmi_subscription` | 10 | 6 | 5 (`50.00%`) | 6 (`6`) | 9 (`90.00%`) | 4 | 0 |
| `account` | 8 | 0 | 0 (`0.00%`) | 0 (`0`) | 0 (`0.00%`) | 0 | 0 |
| `shimcache` | 3 | 3 | 0 (`0.00%`) | 0 (`0`) | 0 (`0.00%`) | 3 | 0 |
| `startup` | 1 | 1 | 1 (`100.00%`) | 0 (`0`) | 1 (`100.00%`) | 1 | 0 |
| **Total (Cold Disk)** | **1,104** | **642** | **57 (`5.16%`)** | **59 (`60`)** | **114 (`10.33%`)** | **638** | **9** |

### Separate Reference With Live `process` Rows (`n = 1,179`)
When the `75` live-collected `process` rows are included (shown for completeness only — live process tables are absent in cold dead-disk triage):
- `total_rows = 1,179`, `total_extracted_pointers = 773`, `total_resolved_links = 64` (`+2 service -> process`, `+2 process -> process`), `total_dangling_pointers = 414`, `total_ambiguous_pointers = 295`, `rows_with_resolved_outgoing = 61` (`5.17%`), `rows_with_any_resolvable_link = 120` (`10.18%`).
- `service` resolved `2/192` (`1.04%`, `164` ambiguous via shared `svchost.exe` processes) and `process` resolved `2/75` outgoing (`2.67%`), `4/75` any (`5.33%`), with `52` ambiguous and `12` dangling pointers.

---

## 3. Cross-Type Links & Pointer Status Breakdown (Cold Disk, `n = 1,104`)

### 3.1 Resolved Cross-Type & Intra-Type Links (`60` Total)

| Source Type | Target Type | Edge Type | Resolved Count |
| :--- | :--- | :--- | ---: |
| `run_key` | `file` | `PERSISTS_AT_LOGON` | 29 |
| `task` | `file` | `TRIGGERS_EXEC` | 19 |
| `registry` | `file` | `PERSISTS_AT_LOGON` | 3 |
| `wmi_subscription` | `file` | `WMI_CONSUMER_EXEC` | 2 |
| `startup` | `file` | `REFERENCES_FILE` | 1 |
| `wmi_subscription` | `wmi_subscription` | `WMI_BINDS_FILTER` | 3 |
| `wmi_subscription` | `wmi_subscription` | `WMI_BINDS_CONSUMER` | 3 |
| **Total Resolved** | | | **60 (`54` cross-type + `6` intra-WMI)** |

### 3.2 Edge Types Possible With v1 Fields vs. Dangling / Ambiguous Counts

| Edge Type | Resolved Unique | Dangling | Ambiguous | Why Dangling / Ambiguous in v1 `DEV` |
| :--- | ---: | ---: | ---: | :--- |
| `PERSISTS_AT_LOGON` (`run_key` / `registry`) | 32 | 31 | 0 | `file` resolved user-writable scripts/EXEs; `System32\WindowsPowerShell\v1.0\powershell.exe` (`17` from `run_key`) & Windows binaries absent without `$MFT`. |
| `TRIGGERS_EXEC` (`task`) | 19 | 112 | 0 | Tasks launching `cmd.exe` (`13`), `powershell.exe` (`12`), `rundll32.exe` (`9`), `usoclient.exe` (`8`) have no `$MFT` `file` targets in v1. |
| `RUNS_SERVICE` (`service`) | 0 | 192 | 0 | All `163` `svchost.exe` + `29` service binary paths lack `System32`/`Program Files` `$MFT` nodes and `Parameters\ServiceDll`. |
| `PREFETCH_EXE_NAME` (`prefetch`) | 0 | 185 | 9 | Only `.pf` filenames exist (`svchost.exe` `50`, `dllhost.exe` `13`, `rundll32.exe` `9`); zero File Metrics arrays, zero unambiguous path resolution. |
| `INVOKES_COM` (`task`) | 0 | 108 | 0 | Task XML `COM:{GUID}` strings exist (e.g. `COM:{ae31b729-...}` `10`), but v1 captured `0` `CLSID` registry keys. |
| `WMI_BINDS_*` / `WMI_CONSUMER_EXEC` | 8 | 4 | 0 | `3` bindings resolved to both Filter & Consumer + `2` Consumers resolved to `file`; built-in `SCM` consumer/filter missing or scriptless. |
| `REFERENCES_FILE` (`startup`) | 1 | 1 | 0 | `AudioMixerLink.lnk` resolved to `C:\Windows\Temp\mixer_init_v3.vbs`; `wscript.exe` dangled (`System32` absent). |
| `SHIMCACHE_REFERENCES_PATH` | 0 | 3 | 0 | All 3 entries point to `C:\Windows\System32\*` (`curl.exe`, `dashost.exe`, `ncpa.cpl`) — absent from `file`. |
| `IFEO_TARGETS_IMAGE` (`registry`) | 0 | 2 | 0 | `utilman.exe` and `sethc.exe` (`System32`) absent from `file`. |

---

## 4. Edge Types Impossible From v1 Data

These `REFGRAPH_SPEC.md` edge families are **100% impossible** on `dataset_v1.parquet`:
1. **`LOADED_RESOURCE` (`.pf` $\to$ loaded DLLs/EXEs):** Prefetch File Metrics array (`file_path`, `mft_index`, `mft_sequence`) was never parsed in v1.
2. **`INVOKES_COM -> RESOLVES_COM_DLL` (`Task -> CLSID -> DLL`):** All `108` `COM:{GUID}` dev tasks dangle because `HKCU`/`HKLM`/`Wow6432Node` `CLSID` keys were not collected.
3. **`HOSTS_SERVICEDLL` (`Service -> ServiceDll`):** `HKLM\SYSTEM\CurrentControlSet\Services\<svc>\Parameters\ServiceDll` was not read for any of the `163` `svchost.exe` services.
4. **`INVENTORIED_BINARY` (`Amcache -> Binary`):** `Amcache.hve` collection failed (`locked_hive_no_vss`) in `51/51` v1 runs.
5. **`CONTAINS_CHILD`, 4-state `$MFT` verification, DOS 8.3 resolution, and ADS edges:** NTFS `$MFT` was never collected in v1.
6. **`PARITY_MISMATCH` (`TaskCache` vs XML):** `Schedule\TaskCache` registry hive entries and `task_xml_exists` were never captured.
7. **`REFERENCES_FILE` binary MFT/Tracker resolution (`.lnk`):** `BEEF0004` MFT index/sequence, `TrackerDataBlock` `ObjectId`, and `VolumeSerial` were never extracted.

---

## 5. Concrete Recommendations for the v2 Offline Extractor (`POINTER_CAPTURE_SPEC.md`)

1. **Parse `$MFT` completely inside the unprivileged offline container:** Eliminates the `163` `svchost.exe` + `112` task + `31` `run_key` + `3` `shimcache` + `2` `IFEO` artificial dangling pointers on standard Windows binaries and unlocks all 4 `$MFT` states, DOS 8.3 short-name expansion, and ADS detection.
2. **Parse `.pf` internals (`libscca` / `dissect`):** Extract `pf_executable_name`, `pf_scca_hash`, `pf_format_version`, `pf_run_count`, and the complete `pf_file_metrics` list (`file_path`, `mft_index`, `mft_sequence`) to unlock `LOADED_RESOURCE` edges and IHF attenuation across `ntdll.dll`/`kernel32.dll`.
3. **Collect offline `CLSID` (`InprocServer32`/`LocalServer32`, HKCU + HKLM + Wow6432Node) & `Services\Parameters\ServiceDll`:** Converts the `108` dangling `COM:{GUID}` tasks and `163` opaque `svchost.exe` services into multi-hop resolvable chains.
4. **Collect `Amcache.hve` & `Schedule\TaskCache` offline without VSS:** Since offline container extraction reads the closed QCOW2 overlay directly, `Amcache.hve` (`FileId`, `LowerCaseLongPath`) and `TaskCache` parity are recovered in 100% of runs.
5. **Parse `.lnk` `BEEF0004` / `TrackerDataBlock` / `VolumeSerial` and WMI `OBJECTS.DATA` offline:** Ensures uniform cold-disk graph construction across every persistence and execution layer in Phase v2.
