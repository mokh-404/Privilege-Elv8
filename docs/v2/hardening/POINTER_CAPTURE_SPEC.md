# DFIR-Triage ML v2 — Offline Pointer-Capture Specification & v1 Collector Gap Audit

**Status:** `Phase 1 Preparation Spec (OD-V2-04, OD-V2-16 confirmed by Mokh 2026-11-23)`  
**Scope:** Schema-validated structured pointer capture inside the unprivileged offline container parser (`--network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges`). **Zero host-kernel mounts** (`mount` / `qemu-nbd` on host) and **zero executable payloads** copied out of disposable QCOW2 overlays.  
**Model Leakage Guard:** Every raw pointer field and resolved graph-edge field defined here is **strictly barred** from primary model feature schemas `full_20` and `no_content` via `config.FORBIDDEN_MODEL_INPUTS` (`REFGRAPH_EDGE_COLUMNS` + `V2_PROVENANCE_COLUMNS`).

---

## 1. Design Contract (`OD-V2-04`, `OD-V2-16`)

1. **Pure User-Space Extraction Only:** After clean `virsh destroy` and SHA-256 verification of the read-only base image, an unprivileged offline container parses the closed QCOW2 overlay directly in user space (e.g., `dissect`, `regipy`, `libscca`, `python-evtx`, user-space NTFS/`$MFT` and LNK parsers).
2. **Structured Pointer Metadata Only — No Executable Tooling Extraction:** The extractor emits schema-validated JSONL/Parquet structured fields (`artifact_record` + `pointer_capture` sub-records) plus leading 1 MiB byte histograms (max `256` integer bins) needed for `full_20`. Raw PE sections, DLL binaries, embedded scripts, and raw binary hives are **never** extracted onto the host workspace.
3. **Strict Isolation From `full_20` / `no_content`:** All pointer-capture fields are excluded from `config.FEATURES` (the locked 20 features) and barred from `SharedPreprocessor` (`full_20`, `no_content`, and primary winner comparisons). Only the secondary `v2_refgraph` pipeline (`src/v2/refgraph.py`) may read static pointer fields to build per-disk referential graphs (see [`../REFGRAPH_SPEC.md`](../REFGRAPH_SPEC.md)).
4. **Zero Runtime / Labeling Provenance Inside Static Pointers:** Pointer records never read labeling provenance, Sysmon event logs, process trees (`pid`, `ppid`, `parent_name`), or timestamps (`created_utc`, `modified_utc`, `collected_utc`).

---

## 2. Exact Per-Source Pointer Fields to Capture

All path strings preserve a paired representation when environment variables or quotes are present: `*_raw` (exact on-disk value before substitution) and `*_expanded` (normalized string with OS environment variables resolved).

### 2.1 Prefetch (`.pf`)

| Field Name | Type | Description & Capture Requirement |
| :--- | :--- | :--- |
| `pf_executable_name` | `str` | Executable filename stored inside the Prefetch header (max 29 UTF-16 chars). |
| `pf_scca_hash` | `str` | 8-hex-digit 32-bit SCCA path/command-line hash (from header / `.pf` filename). |
| `pf_format_version` | `int` | SCCA format version identifier (e.g., `17`, `23`, `26`, `30`). |
| `pf_run_count` | `int` | Recorded execution run count integer from header. |
| `pf_file_metrics` | `list[dict]` | Ordered list of referenced file/module entries: `{"file_path": str, "mft_index": int \| null, "mft_sequence": int \| null}` covering every entry in the File Metrics + Filename Strings tables (note: Windows 10 v30 stores volume/MFT references alongside strings; `null` only where format omits MFT refs). |

### 2.2 NTFS Master File Table (`$MFT`)

| Field Name | Type | Description & Capture Requirement |
| :--- | :--- | :--- |
| `mft_record_number` | `int` | 48-bit (6-byte) `$MFT` file record index. |
| `mft_sequence_number` | `int` | 16-bit (2-byte) `$MFT` reuse sequence number. |
| `mft_in_use` | `bool` | Record allocation flag from `$MFT` record header (`flags & 0x01`). |
| `mft_parent_index` | `int` | Parent directory 48-bit `$MFT` record index from `$FILE_NAME`. |
| `mft_parent_sequence` | `int` | Parent directory 16-bit `$MFT` sequence number from `$FILE_NAME`. |
| `mft_file_names` | `list[dict]` | All `$FILE_NAME` attributes on the record: `{"namespace": "POSIX" \| "WIN32" \| "DOS" \| "WIN32_DOS", "name": str, "parent_index": int, "parent_sequence": int}` so DOS 8.3 short names resolve deterministically to WIN32 long names. |
| `mft_ads_streams` | `list[dict]` | Named alternate `$DATA` streams (excluding default unnamed `$DATA`): `{"stream_name": str, "stream_size": int}` (metadata only; stream content bytes are not exported). |

### 2.3 Scheduled Tasks (`C:\Windows\System32\Tasks` XML + `TaskCache` Registry)

| Field Name | Type | Description & Capture Requirement |
| :--- | :--- | :--- |
| `task_xml_path` | `str \| null` | Canonical task XML path relative to `System32\Tasks` (e.g., `\CustomSync`), or `null` if XML file missing. |
| `task_xml_exists` | `bool` | Whether the task XML file actually exists on disk (false surfaces registry-only `TaskCache` tampering patterns such as GhostTask, pending primary-source verification). |
| `task_exec_actions` | `list[dict]` | Parsed `<Exec>` actions from XML / `Actions` blob: `{"command_raw": str, "command_expanded": str, "arguments_raw": str \| null, "arguments_expanded": str \| null, "working_dir": str \| null}`. |
| `task_com_handlers` | `list[str]` | All `<ComHandler><ClassId>{GUID}</ClassId>` GUID strings normalized to lowercase braced `{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}`. |
| `taskcache_entries` | `list[dict]` | Registry state from `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\{Tree,Tasks}\{...}`: `{"tree_path": str, "task_guid": str \| null, "has_sd": bool, "has_actions": bool, "actions_source": "xml" \| "registry_blob" \| "missing", "triggers_present": bool}`. |

### 2.4 Windows Registry (`SOFTWARE`, `SYSTEM`, per-user `NTUSER.DAT`)

1. **ASEP Values (`Run`, `RunOnce`, `Policies\Explorer\Run`, `Winlogon`, `IFEO`):**
   - `reg_hive` (`HKLM` | `HKU\<SID>` | `HKCU`), `reg_wow64_view` (`64bit` | `32bit_wow6432`), `reg_key_path` (`str`), `reg_value_name` (`str`), `reg_value_raw` (`str`), `reg_value_expanded` (`str`).
   - Specifically cover: `Run` / `RunOnce` (HKLM, HKU, `Wow6432Node`), `Winlogon` (`Shell`, `Userinit`, `Taskman`), and `Image File Execution Options\<exe>` (`Debugger`, `GlobalFlag`, `VerifierDlls`, `MonitorProcess`).
2. **COM `CLSID` Resolution (`InprocServer32` / `LocalServer32`):**
   - Capture from ALL four precedence/view roots:
     - `HKU\<SID>\Software\Classes\CLSID\{GUID}\InprocServer32|LocalServer32` (64-bit user view — highest precedence for COM hijacking)
     - `HKU\<SID>\Software\Classes\Wow6432Node\CLSID\{GUID}\InprocServer32|LocalServer32` (32-bit user view)
     - `HKLM\SOFTWARE\Classes\CLSID\{GUID}\InprocServer32|LocalServer32` (64-bit machine view)
     - `HKLM\SOFTWARE\Classes\WOW6432Node\CLSID\{GUID}\InprocServer32|LocalServer32` (32-bit machine view)
   - Fields: `clsid_guid`, `clsid_hive` (`HKU` | `HKLM`), `clsid_sid` (`str | null`), `clsid_wow64` (`bool`), `clsid_server_type` (`InprocServer32` | `LocalServer32`), `clsid_server_raw` (`str`), `clsid_server_expanded` (`str`), `clsid_threading_model` (`str | null`).
3. **Windows Services (`SYSTEM\CurrentControlSet\Services\<svc>`):**
   - `service_name` (`str`), `service_start_mode` (`int | str`), `service_type` (`int`), `service_image_path_raw` (`str`), `service_image_path_expanded` (`str`), `service_dll_raw` (`str | null` from `<svc>\Parameters\ServiceDll`), `service_dll_expanded` (`str | null`).
   - Environment variable expansion uses the target guest image's canonical offline OS environment mapping (`%SystemRoot%`, `%WinDir%`, `%SystemDrive%`, `%ProgramFiles%`, `%ProgramFiles(x86)%`, `%ProgramW6432%`, `%ProgramData%`, `%ComSpec%`, plus per-user `%USERPROFILE%`, `%APPDATA%`, `%LOCALAPPDATA%`, `%TEMP%`, `%TMP%` when parsed from a user hive).

### 2.5 WMI Permanent Event Subscriptions (`\Windows\System32\wbem\Repository\OBJECTS.DATA`)

| Field Name | Type | Description & Capture Requirement |
| :--- | :--- | :--- |
| `wmi_namespace` | `str` | Subscription namespace (typically `root\subscription`). |
| `wmi_filters` | `list[dict]` | `{"filter_name": str, "query_language": str, "query": str, "event_namespace": str \| null}`. |
| `wmi_consumers` | `list[dict]` | `{"consumer_class": "CommandLineEventConsumer" \| "ActiveScriptEventConsumer" \| str, "consumer_name": str, "executable_path_raw": str \| null, "executable_path_expanded": str \| null, "command_line_raw": str \| null, "command_line_expanded": str \| null, "scripting_engine": str \| null, "script_filename": str \| null, "inline_script_len": int \| null, "inline_script_sha256": str \| null}` (never dumps unvalidated executable blobs). |
| `wmi_bindings` | `list[dict]` | Parsed `__FilterToConsumerBinding` pairs: `{"filter_ref": str, "consumer_ref": str}`. |

### 2.6 LNK Shortcut Files (`.lnk`)

| Field Name | Type | Description & Capture Requirement |
| :--- | :--- | :--- |
| `lnk_source_path` | `str` | Canonical filesystem path of the `.lnk` file on the offline image. |
| `lnk_target_mft_index` | `int \| null` | 48-bit target `$MFT` record index from Shell Link ExtraData `BEEF0004` block (`null` if absent). |
| `lnk_target_mft_sequence` | `int \| null` | 16-bit target `$MFT` sequence number from `BEEF0004` (`null` if absent). |
| `lnk_tracker_object_id` | `str \| null` | GUID string from `TrackerDataBlock` (`ObjectId`), plus `lnk_tracker_droid_volume_id` if present. |
| `lnk_volume_serial` | `str \| null` | Hex volume serial number from `LinkInfo` / VolumeID structure. |
| `lnk_target_path_raw` | `str \| null` | Local base path / common path / relative target string before normalization. |
| `lnk_target_path_expanded` | `str \| null` | Environment-variable and canonical-drive expanded target path. |
| `lnk_arguments` | `str \| null` | Command-line arguments stored inside the `.lnk` `COMMAND_LINE_ARGUMENTS` section. |

### 2.7 Amcache (`C:\Windows\AppCompat\Programs\Amcache.hve`)

| Field Name | Type | Description & Capture Requirement |
| :--- | :--- | :--- |
| `amcache_file_id` | `str \| null` | `InventoryApplicationFile` `FileId` string (`"0000" + 40-hex SHA-1` format; note: practitioner reports state this hashes only the leading 31 MiB — marked `pending verification` against our target Windows 11 builds). |
| `amcache_lowercase_long_path` | `str \| null` | `LowerCaseLongPath` canonical file path from `InventoryApplicationFile` / `File` subkeys. |
| `amcache_program_id` | `str \| null` | Linked `ProgramId` associating file entry with application inventory record. |

---

## 3. Audit of What the v1 Collector (`collector/Collect-Artifacts.ps1`) Did NOT Capture

Inspection of `collector/Collect-Artifacts.ps1` (lines 1–912) establishes the exact pointer-capture omissions in v1:

| Source | What v1 Captured (`collector/Collect-Artifacts.ps1`) | Critical Pointer Fields NOT Captured by v1 |
| :--- | :--- | :--- |
| **Prefetch** (L549–L562) | Only listed `*.pf` files via `Get-ChildItem` + `Get-FileMetadata` on the `.pf` file itself (`name`, `.pf` size, `.pf` SHA-256, `.pf` byte histogram). | Parsed `.pf` internal header (`pf_executable_name`, `pf_scca_hash`, `pf_format_version`, `pf_run_count`) and entire **File Metrics array** (`file_path`, `mft_index`, `mft_sequence`). Zero `LOADED_RESOURCE` links possible in v1. |
| **NTFS `$MFT`** (L763–L840) | **Not parsed at all.** Only walked `Windows\Temp`, `Users\Public`, `ProgramData`, and `Users\*\AppData` with `$MaxScannedFiles = 1500` and extension allowlist. | Complete filesystem index (zero `C:\Windows\System32` / `Program Files` binaries in `file`), `mft_record_number`, `mft_sequence_number`, `mft_in_use`, `mft_parent_index`/`seq`, DOS 8.3 vs WIN32 `$FILE_NAME` pairs, and ADS streams. |
| **Scheduled Tasks** (L313–L337) | Live COM/API `Get-ScheduledTask`: joined actions into `command_line`, extracted only `$firstExec` into `path`, formatted `COM:<ClassId>` into `command_line` only. | Structured split of multi-action `<Exec>` command & arguments vs `ComHandler` `<ClassId>`, all **`TaskCache` registry keys** (`SD`, `Actions`, `Id`), and `task_xml_exists` parity flag. Also missed GhostTask tasks hidden from `Get-ScheduledTask`. |
| **Registry — CLSID** (L423–L497) | **Not collected at all (`0` CLSID records).** | Entire `HKCU` and `HKLM` and `Wow6432Node` `CLSID\{GUID}\InprocServer32` and `LocalServer32` resolution subtree. `COM:{GUID}` tasks cannot resolve to DLLs in v1. |
| **Registry — Services** (L340–L351) | Read `Win32_Service.PathName` (resolved `svchost.exe` / service EXE in `path` and raw `PathName` in `command_line`). | **`Parameters\ServiceDll`** (`REG_EXPAND_SZ`) for `svchost.exe -k <Group>` services, raw unexpanded `ImagePath` preserved separately from expanded form. |
| **Registry — Run / Winlogon / IFEO** (L354–L497) | Collected `Run`/`RunOnce`/`Policies\Run`, UAC bypass, `IFEO` (`Debugger`/`GlobalFlag`/`VerifierDlls`/`MonitorProcess`), `Winlogon` (`Shell`/`Userinit`/`Taskman`), Defender keys. | Structured raw + expanded path pair (Winlogon/UAC/IFEO/Run values), `Wow6432Node` per-user view tracking, and `Services` `ServiceDll`. |
| **WMI** (L396–L420) | Live `Get-CimInstance -Namespace root\subscription` putting filter/consumer/binding fields in `raw` dict & `command_line`. | Offline `OBJECTS.DATA` parsing and structured separate `filter_ref` / `consumer_ref` schema fields outside unparsed `raw` dicts (note: `raw` is omitted from `dataset_v1.parquet`). |
| **LNK Shortcuts** (L500–L546) | Only scanned Startup folders via `WScript.Shell.CreateShortcut` (`command_line` + `raw.lnk_target`); skipped all non-Startup `.lnk` files. | Target MFT reference (`BEEF0004` index & sequence), `TrackerDataBlock` `ObjectId`, `volume_serial`, and system-wide `.lnk` coverage outside Startup. |
| **Amcache** (L617–L656) | Attempted live `System.IO.File.Open` of `Amcache.hve` + existing VSS fallback; skipped `51/51` v1 runs (`locked_hive_no_vss`). | **100% absent in v1 (`0` records).** Never parsed internal `InventoryApplicationFile` `FileId` or `LowerCaseLongPath` records. |
