# Step F (Upgraded v2.1.0) — Read-Only Clean Base Image Offline Extraction & Base-Cache Benchmark

**Status:** `Dry Run & Base-Cache Benchmark Complete (Read-Only, Zero VM Boot, Base Image SHA-256 Verified Identical Before & After)`  
**Extractor Version:** `2.1.0` ([`src/v2/offline_extractor.py`](../../src/v2/offline_extractor.py))  
**Tooling / Runtime Note:** Executed with `.venv/bin/python -m src.v2.offline_extractor` (pure-Python `dissect.target 3.25.1`, `dissect.ntfs 3.16`, `dissect.regf 3.14`, `dissect.cim 3.13`, `dissect.shellitem 3.13`, `pefile 2024.8.26`, `signify 0.9.3`, `LnkParse3 1.6.0`). Container spec [`hardening/offline_extractor.Dockerfile`](hardening/offline_extractor.Dockerfile) and [`hardening/requirements_extractor.txt`](hardening/requirements_extractor.txt) are ready for host container execution via [`hardening/06_unprivileged_container_runner.sh`](hardening/06_unprivileged_container_runner.sh).

---

## 1. Pre/Post Image Integrity & Base-Cache Speedup Benchmark (`51.7x` Speedup)

- **Active QEMU/VM check prior to run:** `pgrep -a qemu` empty (zero running VMs).
- **Target image inspected (read-only `0444`):** `/var/lib/libvirt/images/win11_base.qcow2`
- **SHA-256 BEFORE:** `feddb54d208174d3d1eda45e69ac831965a8572ead71f276ddf229a0ac3d0674`
- **SHA-256 AFTER:** `feddb54d208174d3d1eda45e69ac831965a8572ead71f276ddf229a0ac3d0674` (`EXACT MATCH`)

| Benchmark Pass | Command Mode | Wall-Clock Time | `CatRoot` Digests | `base_cache_hits` / `misses` | `wof_compressed_files` | Notes |
| :--- | :--- | ---: | ---: | ---: | ---: | :--- |
| **Step F Initial Baseline (`v2.0.0`)** | Cold uncached | `1,015.586 s` (`~16.93 min`) | `138,984` (live ASN.1 scan) | `0` / `2,304` | `0` *(flag not propagated)* | UTF-16LE Task XML & `TaskCache` binary `Actions` not decoded (`task = 11.76%`) |
| **Pass 1 (`v2.1.0` Cache Build)** | `--build-base-cache --base-cache-path ...` | `1,017.735 s` (`~16.96 min`) | `138,984` (indexed & saved) | `0` / `2,643` | **`2,569`** | Writes `5.3 MiB` `.json.gz` cache cryptographically bound to `win11_base.qcow2` SHA-256 |
| **Pass 2 (`v2.1.0` Cached Run)** | `--base-cache-path ...` | **`19.702 s` (`0.33 min`, `51.7x` faster)** | `138,984` (O(1) cache load) | **`2,639` hits / `4` misses** | **`2,569`** | Reuses unchanged base MFT `(seg, seq, size, mtime_ns)` in O(1); parses any new/modified overlay files live |

---

## 2. Per-Artifact-Type Extraction Counts & Upgraded `v2_refgraph` Link Coverage (`n = 4,364` Records)

Upgrading [`src/v2/offline_extractor.py`](../../src/v2/offline_extractor.py) to decode UTF-16LE Task XML files, parse `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{GUID}\Actions` binary blobs (`0x6666` `ExecAction` and `0x7777`/`0x5555` `ComHandlerAction`), and join Task `ComHandler` CLSIDs against `HKLM/HKCU\SOFTWARE\Classes\CLSID\{GUID}\InprocServer32`, `LocalServer32`, and `AppID -> LocalService` increased `task` link coverage from **`11.76%` (`32 / 272`)** to **`99.63%` (`271 / 272`)**:

| `artifact_type` | Extracted Records (`v2.1.0`) | `with_resolved_link` | `resolved_targets` | `v2_refgraph` Resolved Link Rate (`v2.1.0`) | Previous Rate (`v2.0.0`) | Notes |
| :--- | ---: | ---: | ---: | ---: | ---: | :--- |
| `file` | `2,387` | `0` | `0` | `0.00%` *(inbound target node)* | `0.00%` (`2,304`) | User-writable scan + referenced `System32` / `Program Files` / COM server PEs & DLLs |
| `amcache` | `671` | `670` | `670` | **`99.85%`** | `99.85%` | Recovered from offline `Amcache.hve` (`0` in v1 due to `locked_hive_no_vss`) |
| `shimcache` | `302` | `0` | `0` | `0.00%` | `0.00%` | Informational execution residue (`AppCompatCache`) |
| **`task`** | **`272`** | **`271`** | **`281`** | **`99.63%`** | `11.76%` (`32/272`) | `240` UTF-16LE XML + `TaskCache` binary `Actions` (`93` `0x6666` Exec + `147` `0x7777` COM CLSIDs) + `31/32` `TaskCache`-only tasks |
| `service` | `261` | `261` | `483` | **`100.00%`** | `100.00%` | Includes expanded `ImagePath` + `Parameters\ServiceDll` targets |
| `prefetch` | `256` | `256` | `12,631` | **`100.00%`** | `100.00%` | Extracts Win11 v31 `.pf` File Metrics module lists |
| `registry` | `205` | `204` | `204` | **`99.51%`** | `100.00%` (`69/69`) | `Winlogon`, `IFEO`, plus `136` task-referenced `Classes\CLSID` (`InprocServer32` / `LocalServer32` / `LocalService`) entries |
| `run_key` | `4` | `4` | `4` | **`100.00%`** | `100.00%` | `Run` / `RunOnce` values (raw unexpanded in `full_20`, expanded target in `v2_refgraph`) |
| `account` | `4` | `0` | `0` | `0.00%` | `0.00%` | Local SAM accounts |
| `wmi_subscription` | `2` | `0` | `0` | `0.00%` | `0.00%` | Built-in CIM repository objects without payload files |
| **Total (Cold Disk)** | **`4,364`** | **`1,666`** | **`14,273`** | **`38.18%` outgoing / `53.53%` any link (`2,336/4,364`)** | `31.17%` / `47.33%` | Zero live `process` rows (`0` vs `75` in v1) |

- **Signature Status Breakdown Across Extracted Records (`n = 4,364`):** `Valid: 2,595`, `None/NaN: 1,026` (non-file records), `NotSigned: 416`, `UnknownError: 324` (`256` `.pf` + non-SIP files, mapped to `"na"` per `src/data/features.py:59`), `NotTrusted: 3`.
- **WOF CompactOS Decompression Count:** `wof_compressed_files = 2,569` records properly flagged and counted in `extraction_manifest.json`.
- **Confirmed `OD-V2-20` Persistence/Execution Subset (`task`, `service`, `run_key`, `wmi_subscription`, `prefetch`):**
  - **`792 / 795` (`99.62%`)** resolved to at least one static target link (up from `69.56%` / `553/795` prior to the `TaskCache` binary `Actions` + UTF-16LE XML + `CLSID` join upgrade, well above the confirmed `50%` `OD-V2-20` pilot go/no-go threshold).

---

## 3. Resolution of Step F Technical Caveats

1. **Immutable Base-Image Cache (`16.96 min -> 19.70 s`):** `--build-base-cache` pre-computes and compresses the `138,984` `CatRoot` Authenticode digests and all `2,639` base MFT file tuples `(mft_record_number, mft_sequence_number, file_size, mtime_ns) -> (file_sha256, file_head_histogram, signature_status, wof_compressed)` bound cryptographically to `win11_base.qcow2` SHA-256 (`feddb54d208174d3d1eda45e69ac831965a8572ead71f276ddf229a0ac3d0674`). On overlay extraction runs (`--base-cache-path`), unchanged base files resolve in O(1) while newly created or modified overlay files (`benign_drift` / `attacker_induced`) miss the cache and are decompressed, hashed, and signature-verified live.
2. **`wof_compressed` Flag Propagation:** Fixed in `build_record` (`wof_compressed_files = 2,569`).
3. **Scheduled Task `TaskCache\Tasks\{GUID}\Actions` + UTF-16LE XML + `CLSID` Join:** Implemented in `_parse_task_xml`, `decode_taskcache_actions_blob`, and `clsid_resolved_target`, raising `task` link resolution from `11.76%` (`32/272`) to **`99.63%` (`271/272`)** and `OD-V2-20` persistence/execution link coverage from `69.56%` to **`99.62%` (`792/795`)**.
