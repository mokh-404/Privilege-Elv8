# Step F — Read-Only Clean Base Image Offline Extraction Dry Run

**Status:** `Dry Run Complete (Read-Only, Zero VM Boot, Base Image SHA-256 Verified Identical Before & After)`  
**Tooling / Runtime Note:** Executed with `.venv/bin/python -m src.v2.offline_extractor` (pure-Python `dissect.target 3.25.1`, `dissect.ntfs 3.16`, `dissect.regf 3.14`, `dissect.cim 3.13`, `dissect.shellitem 3.13`, `pefile 2024.8.26`, `signify 0.9.3`, `LnkParse3 1.6.0`). Container spec [`hardening/offline_extractor.Dockerfile`](hardening/offline_extractor.Dockerfile) and [`hardening/requirements_extractor.txt`](hardening/requirements_extractor.txt) were created; **container runtime observation:** `docker 29.9.2` CLI is installed (`podman` is NOT installed), and `dockerd` daemon was inactive/inaccessible from the unprivileged environment.

---

## 1. Pre/Post Image Integrity & Safety Proof

- **Active QEMU/VM check prior to run:** `pgrep -a qemu` empty (zero running VMs).
- **Target image inspected (read-only `0444`):** `/var/lib/libvirt/images/win11_base.qcow2`
- **SHA-256 BEFORE:** `feddb54d208174d3d1eda45e69ac831965a8572ead71f276ddf229a0ac3d0674`
- **SHA-256 AFTER:** `feddb54d208174d3d1eda45e69ac831965a8572ead71f276ddf229a0ac3d0674` (`EXACT MATCH`)
- **Wall-clock duration:** `1,015.586 s` (`~16.9 min`; `138,984` `CatRoot` catalog digests loaded + user-space PE/WOF `lzxpress_huffman` decompression across `2,304` extracted file records; pure-Python per-run throughput should be budgeted or cached in Stage A pilot).

---

## 2. Per-Artifact-Type Extraction Counts (`n = 4,145` Total Records)

| `artifact_type` | Extracted Records | `with_resolved_link` | `resolved_targets` | `v2_refgraph` Resolved Link Rate | Notes |
| :--- | ---: | ---: | ---: | ---: | :--- |
| `file` | `2,304` | `0` | `0` | `0.00%` *(inbound target node)* | User-writable scan + referenced `System32` / `Program Files` PEs & DLLs |
| `amcache` | `671` | `670` | `670` | **`99.85%`** | Recovered from offline `Amcache.hve` (`0` in v1 due to `locked_hive_no_vss`) |
| `shimcache` | `302` | `0` | `0` | `0.00%` | Informational execution residue (`AppCompatCache`) |
| `task` | `272` | `32` | `32` | `11.76%` | Remaining inbox MS tasks use `TaskCache` binary `Actions` or COM handlers |
| `service` | `261` | `261` | `483` | **`100.00%`** | Up from `0.00%` in v1; includes expanded `ImagePath` + `ServiceDll` targets |
| `prefetch` | `256` | `256` | `12,631` | **`100.00%`** | Up from `0.00%` in v1; extracts `.pf` File Metrics module lists |
| `registry` | `69` | `69` | `69` | **`100.00%`** | `Winlogon`, `IFEO`, `CLSID` `InprocServer32`/`LocalServer32` |
| `run_key` | `4` | `4` | `4` | **`100.00%`** | `Run` / `RunOnce` values |
| `account` | `4` | `0` | `0` | `0.00%` | Local accounts |
| `wmi_subscription` | `2` | `0` | `0` | `0.00%` | Built-in CIM repository objects without payload files |
| **Total (Cold Disk)** | **`4,145`** | **`1,292`** | **`13,889`** | **`31.17%` outgoing / `47.33%` any link (`1,962/4,145`)** | Zero live `process` rows (`0` vs `75` in v1) |

- **Signature Status Breakdown Across Extracted Records:** `Valid: 1,917`, `None/NaN: 1,487` (non-file records), `NotSigned: 414`, `UnknownError: 324` (`256` `.pf` + non-SIP files), `NotTrusted: 3`.
- **Persistence/Execution Subset (`task`, `service`, `run_key`, `wmi_subscription`, `prefetch`):** **`553 / 795` (`69.56%`)** had at least one uniquely resolved static link (exceeding the proposed `50%` `OD-V2-20` threshold on clean disk metadata, subject to verification on pilot malware + benign runs and `TaskCache` binary `Actions` decoding).

---

## 3. Observed Technical Caveats to Address Before Stage B

1. **`wof_compressed` Record Field & Perf:** Windows 11 CompactOS `WofCompressedData` decompression via `dissect.util.compression.lzxpress_huffman` matched live `svchost.exe` SHA-256 identically during unit verification, though `build_record` did not propagate the `wof_compressed` boolean flag into the manifest counter (`wof_compressed_files: 0`). Pure-Python LZXPRESS decompression + `signify` hashing took `~16.9 min` for `2,304` files; caching static immutable base-image `(sha256, signature_status)` tuples across clean overlay runs can cut per-run wall time substantially if needed after clean-image parity testing.
2. **Windows 11 Prefetch v31 & Inbox COM Tasks:** Clean Windows 11 25H2 produces Prefetch version `31` headers (`ntfs_reference` field returns `0` in `FILE_METRICS_ARRAY_ENTRY_23`, safely falling back to normalized `file_path` matching), and `task` resolved `11.76%` (`32/272`) because Windows inbox tasks frequently store binary `Actions` inside `TaskCache\Tasks\{GUID}\Actions` without XML `<Exec>` paths (binary `Actions` blob decoding is a worthwhile pre-pilot addition if needed).
3. **Host Container Daemon:** `docker` CLI (`29.9.2`) is installed, `podman` is not installed, and `dockerd` was not running from the sandbox; Mokh must start `dockerd` and build `offline_extractor.Dockerfile` before running `06_unprivileged_container_runner.sh`.
