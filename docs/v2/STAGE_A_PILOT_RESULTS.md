# DFIR-Triage ML v2 — Stage A Pilot Complete Execution & Empirical Evaluation Report

**Date Completed:** `2026-11-28` (`01:43:28 UTC` / `03:43:28 EET`)  
**Branch / Commit:** `v2-comparative-study` (`HEAD = 07a522ca78ea02663a990a7356dad3b1b909b1c5`, `git_dirty = false`)  
**Overall Verdict:** **`PASS (17 / 17 VM Runs Completed, 7 / 7 Live Malware Families Detonated, 0 Egress Leaks, 100% Base-Image Immutability, All Pre-Registration Gates Passed)`**

---

## 1. Executive Summary & Go/No-Go Gate Verdicts

The Stage A Pilot (`17` isolated VM runs: `3` clean control boots + `7` paired `executed` and `7` `dormant` runs across `7` canonical malware families from `5` threat categories) completed end-to-end under the zero-SSH / zero-guest-agent `DFIR_STAGE` SATA ISO-9660 architecture, warm `inetsim-vm` CoW overlay reuse, and 1-lane pipelined unprivileged Docker offline extraction (`v2.2.0`).

| Gate / Invariant | Requirement | Measured Stage A Result | Verdict |
| :--- | :--- | :--- | :---: |
| **Run Completion** | `17 / 17` runs (`3` control, `7` executed, `7` dormant) | **`17 / 17` completed** (`0` timeouts, `0` crashes, `0` extraction errors) | **`PASS`** |
| **Golden Base & NVRAM Integrity** | `win11_base.qcow2`, `win11_VARS.fd.base`, `inetsim_base.qcow2` unchanged | `0444` + `chattr +i` + full SHA-256 & `verify-base-fast` passed before, during, and after batch | **`PASS`** |
| **Air-Gap & Egress Audit (`virbr1`)** | `0` cross-interface forwarded packets/bytes across all 17 runs | `17 / 17` passed (`MAX_FWD_DROP_PKTS = 0`, `MAX_FWD_DROP_BYTES = 0`, `firewall_rules_valid = true`) | **`PASS`** |
| **Supervised `--canary` Gate** | `3`-boot canary (`control` + `executed` + `dormant`) + positive Sysmon delta | `CANARY_PASSED` bound to `07a522c`; `81,003` executed Sysmon events vs. `70,005` control (`+10,998`) | **`PASS`** |
| **Live Detonation Rate (`OD-V2-05`)** | Executed payloads launch & trace in Sysmon Event ID 1 | **`7 / 7` (`100.0%`)** matched in Sysmon `EventID=1` with exact `SHA256` & `ProcessGuid` | **`PASS`** |
| **Dormant Non-Execution Invariant** | `0` malware process creations in dormant runs; `100%` staged file recovery | **`0 / 7` (`0.0%`)** Sysmon process trees in dormant runs; **`7 / 7` (`100.0%`)** staged payloads labeled | **`PASS`** |
| **`ambiguous_unattributed` Rate** | Low unattributed OS drift quarantine rate (`< 5%`) | **`28 / 62,023` (`0.045%` raw)** / **`28 / 4,570` (`0.61%` deduplicated dev)** | **`PASS`** |
| **Template-Quantization Gate (`IMP-06`)** | `>= 50%` unique sizes, `>= 75%` unique `(size, entropy)` pairs, `<= 10%` max size share, `> 0` services/registry/unsigned PEs | **Procedural drift (`n=138` files):** `100.0%` unique sizes, `100.0%` unique pairs, `0.72%` max share, `14` services, `14` registry, `55` unsigned PEs (`failures = []`) | **`PASS`** |
| **`OD-V2-20` Static Refgraph Diagnostic** | `>= 50.0%` resolved link rate on persistence/execution artifacts | **`563 / 849` (`66.31%`)** deduplicated (`796 / 801` = **`99.38%`** per-run including forward Prefetch) | **`PASS`** |

---

## 2. Cryptographic Integrity, Containment & `--canary` Stamp

### 2.1 Immutable Base Images & Quarantine Vault
- **`/var/lib/libvirt/images/win11_base.qcow2`:** mode `0444`, `chattr +i`, SHA-256 `d2facced4255e3ae1cb821249d5e6330e380f639cee8a5aae19ef99be690835c` (`OK` at batch start and end).
- **`/var/lib/libvirt/qemu/nvram/win11_VARS.fd.base`:** mode `0444`, SHA-256 `2aeb86356d8c160607a0f258d8b0044b2e30a592c510992b28cb5f5312dda6be` (`OK` on every run).
- **`/var/lib/libvirt/images/inetsim_base.qcow2`:** mode `0444`, `chattr +i`, `INETSIM_STAT` verified unchanged after every run (`inetsim-vm` runs from disposable CoW overlay `/var/lib/libvirt/images/inetsim_overlay.qcow2`).
- **Frozen v1 Baseline:** `git diff --stat -- results/ data/ docs/FINAL_EVAL_PLAN.md collector/Collect-Artifacts.ps1` is empty (`dataset_v1.parquet` SHA-256 `39527f85fbda75f952e0cf5134a07467bf546501cb540ba68cd65b14983c7f21`, `dataset_v1_manifest.json` SHA-256 `788b6a7cab836c1851a90c5069e89496aa748c33f86643a84d9d70cc50857fbe`, `runner_footprint_dropped.csv` = `99` lines).

### 2.2 Bound `CANARY_PASSED` Stamp (`runs/stage_a_pilot/CANARY_PASSED`)
```json
{
  "base_image_sha256": "d2facced4255e3ae1cb821249d5e6330e380f639cee8a5aae19ef99be690835c",
  "batch_json_sha256": "13fb93fa19e10904b837eb09ad39fec4a8eca36a3541b329795dfc49e1fc842c",
  "executed_sysmon_events_total": 81003,
  "expires_at_utc": "2026-11-29T00:41:11.385331+00:00",
  "git_dirty": false,
  "git_head": "07a522ca78ea02663a990a7356dad3b1b909b1c5",
  "max_control_sysmon_events": 70005,
  "n_canary_runs": 3,
  "run_ids": [
    "pilot_ctrl_01",
    "pilot_01_redline_executed",
    "pilot_01_redline_dormant"
  ],
  "status": "PASS",
  "ttl_seconds": 86400,
  "verified_at_utc": "2026-11-28T00:41:11.385331+00:00"
}
```

---

## 3. Complete 17-Run Execution, Extraction & Sysmon Telemetry Ledger

All `17` runs extracted via `docs/v2/hardening/06_unprivileged_container_runner.sh` (`--network=none --read-only --cap-drop=ALL --user 1000:1000`) using `/var/lib/dfir-quarantine-vault/win11_base_cache.json.gz`. Every run dropped all `8` v2 harness footprint rows (`\DFIR-StageRunner`, `Sysmon64` service/file/shimcache/amcache/prefetch) into per-run `v2_runner_footprint_dropped.csv`.

| # | Run ID | Stratum | Family | INetSim | Dwell | Records | Cache Hits / Miss | Extract Time | Sysmon Total | EID 1 (Proc) | EID 7 (Img) | EID 8 (Thread) | EID 11 (File) | EID 12 (RegKey) | EID 13 (RegVal) | EID 22 (DNS) | Completed UTC |
| :-: | :--- | :---: | :---: | :---: | :-: | ---: | :---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | :---: |
| 01 | `pilot_ctrl_01` | `control` | — | No | `15s` | `4,427` | `2680 / 14` | `50.51s` | `70,005` | `140` | `15` | `155` | `196` | `40,224` | `29,247` | `28` | `00:26:29Z` |
| 02 | `pilot_01_redline_executed` | `executed` | `redline` | Yes | `45s` | `4,447` | `2680 / 17` | `54.88s` | `81,003` | `154` | `24` | `158` | `305` | `50,819` | `29,495` | `48` | `00:32:37Z` |
| 03 | `pilot_01_redline_dormant` | `dormant` | `redline` | No | `15s` | `4,427` | `2680 / 15` | `52.20s` | `75,326` | `141` | `15` | `156` | `200` | `45,575` | `29,212` | `27` | `00:38:03Z` |
| 04 | `pilot_ctrl_02` | `control` | — | No | `15s` | `4,427` | `2680 / 14` | `49.95s` | `70,000` | `140` | `15` | `155` | `196` | `40,218` | `29,249` | `27` | `00:53:07Z` |
| 05 | `pilot_ctrl_03` | `control` | — | No | `15s` | `4,427` | `2680 / 14` | `50.92s` | `75,517` | `140` | `15` | `156` | `198` | `45,749` | `29,234` | `25` | `00:56:51Z` |
| 06 | `pilot_02_asyncrat_executed` | `executed` | `asyncrat` | Yes | `45s` | `4,442` | `2680 / 25` | `57.15s` | `76,344` | `152` | `16` | `158` | `220` | `46,375` | `29,392` | `31` | `01:00:52Z` |
| 07 | `pilot_03_privateloader_executed` | `executed` | `privateloader` | Yes | `45s` | `4,430` | `2678 / 15` | `53.27s` | `74,157` | `150` | `16` | `154` | `256` | `44,044` | `29,498` | `39` | `01:04:47Z` |
| 08 | `pilot_04_coinminer_executed` | `executed` | `coinminer` | Yes | `45s` | `4,430` | `2680 / 15` | `51.50s` | `70,590` | `145` | `16` | `153` | `210` | `40,659` | `29,376` | `31` | `01:08:42Z` |
| 09 | `pilot_05_cobaltstrike_executed` | `executed` | `cobaltstrike` | Yes | `45s` | `4,429` | `2680 / 15` | `54.00s` | `70,367` | `143` | `16` | `154` | `208` | `40,476` | `29,338` | `32` | `01:12:38Z` |
| 10 | `pilot_06_lumma_executed` | `executed` | `lumma` | Yes | `45s` | `4,430` | `2680 / 15` | `53.47s` | `70,374` | `143` | `16` | `153` | `207` | `40,452` | `29,372` | `31` | `01:16:29Z` |
| 11 | `pilot_07_quasar_executed` | `executed` | `quasar` | Yes | `45s` | `4,437` | `2678 / 21` | `54.17s` | `73,819` | `153` | `16` | `159` | `262` | `43,792` | `29,398` | `39` | `01:20:21Z` |
| 12 | `pilot_02_asyncrat_dormant` | `dormant` | `asyncrat` | No | `15s` | `4,428` | `2680 / 15` | `50.31s` | `70,049` | `140` | `15` | `155` | `198` | `40,278` | `29,236` | `27` | `01:24:14Z` |
| 13 | `pilot_03_privateloader_dormant` | `dormant` | `privateloader` | No | `15s` | `4,427` | `2680 / 15` | `53.28s` | `75,214` | `141` | `15` | `156` | `200` | `45,475` | `29,202` | `25` | `01:28:06Z` |
| 14 | `pilot_04_coinminer_dormant` | `dormant` | `coinminer` | No | `15s` | `4,428` | `2680 / 15` | `52.91s` | `75,492` | `141` | `15` | `156` | `200` | `45,729` | `29,224` | `27` | `01:31:59Z` |
| 15 | `pilot_05_cobaltstrike_dormant` | `dormant` | `cobaltstrike` | No | `15s` | `4,427` | `2680 / 15` | `52.40s` | `75,576` | `141` | `15` | `156` | `200` | `45,833` | `29,204` | `27` | `01:35:50Z` |
| 16 | `pilot_06_lumma_dormant` | `dormant` | `lumma` | No | `15s` | `4,427` | `2680 / 15` | `52.13s` | `75,540` | `141` | `15` | `156` | `200` | `45,793` | `29,210` | `25` | `01:39:37Z` |
| 17 | `pilot_07_quasar_dormant` | `dormant` | `quasar` | No | `15s` | `4,428` | `2680 / 15` | `52.67s` | `75,626` | `144` | `15` | `156` | `204` | `45,839` | `29,241` | `27` | `01:43:28Z` |

- **Pipelined Throughput:** The remaining `14` runs (`04` through `17`) ran unattended from `00:49 UTC` to `01:43:28 UTC` (**`~54 minutes` total**, averaging **`3m 52s` per run** end-to-end including VM boot, dwell, clean guest shutdown, `verify-base-fast`, and container extraction).
- **Warm `inetsim-vm` Reuse:** `inetsim-vm` booted once for consecutive executed runs `06`..`11` (`pilot_02_asyncrat_executed` through `pilot_07_quasar_executed`) and was automatically torn down before run `12` (`pilot_02_asyncrat_dormant`).

---

## 4. Sysmon Causal Process-Tree & Per-Run Labeling Yield (`src/v2/labeler_v2.py`)

Multi-control baseline index (`build_multi_control_baseline`) indexed **`4,343` unique `artifact_key`s** across the `3` clean control boots (`pilot_ctrl_01..03`).

### 4.1 Per-Run Sysmon Process Trees & Cold-Disk Artifact Yield

| Run ID | Family | Sample SHA-256 (Prefix) | Root Sysmon `ProcessGuid` (PID) | Tree Processes (`GUID`s) | Tree File Paths | Tree Reg Objects | Cold-Disk `attacker_induced` (`y=1`) | Positive Breakdown by `artifact_type` | `benign_drift` | `ambiguous` | `baseline` |
| :--- | :---: | :---: | :--- | :-: | :-: | :-: | :-: | :--- | :-: | :-: | :-: |
| `pilot_01_redline_executed` | `redline` | `8211468fff3c` | `{3F08756F-0020-0A6B-8100-000000000B00}` (`5076`) | `9` | `36` | `184` | **`21`** | `shimcache: 9, amcache: 6, file: 3, registry: 2, task: 1` | `13` | `4` | `4,408` |
| `pilot_02_asyncrat_executed` | `asyncrat` | `64fe92d83db4` | `{3F08756F-3526-0A6B-7E00-000000000B00}` (`5008`) | `3` | `7` | `9` | **`7`** | `shimcache: 3, file: 3, amcache: 1` | `13` | `10` | `4,411` |
| `pilot_03_privateloader_executed` | `privateloader` | `fcd465bfb29a` | `{3F08756F-0027-0A6B-8100-000000000B00}` (`5000`) | `2` | `16` | `174` | **`3`** | `shimcache: 1, amcache: 1, file: 1` | `11` | `4` | `4,411` |
| `pilot_04_coinminer_executed` | `coinminer` | `9a527eb9bd02` | `{3F08756F-F227-0A6B-8300-000000000B00}` (`3800`) | `1` | `1` | `0` | **`3`** | `shimcache: 1, amcache: 1, file: 1` | `13` | `2` | `4,411` |
| `pilot_05_cobaltstrike_executed` | `cobaltstrike` | `f535cdbb32dd` | `{3F08756F-DB28-0A6B-8100-000000000B00}` (`5040`) | `1` | `1` | `1` | **`2`** | `shimcache: 1, file: 1` | `13` | `0` | `4,413` |
| `pilot_06_lumma_executed` | `lumma` | `cacc573a567a` | `{3F08756F-C829-0A6B-8100-000000000B00}` (`992`) | `1` | `1` | `6` | **`3`** | `shimcache: 1, amcache: 1, file: 1` | `13` | `0` | `4,413` |
| `pilot_07_quasar_executed` | `quasar` | `eda7de5855de` | `{3F08756F-B42A-0A6B-8300-000000000B00}` (`4376`) | `3` | `23` | `159` | **`8`** | `shimcache: 3, file: 3, amcache: 2` | `13` | `4` | `4,411` |
| `pilot_01_redline_dormant` | `redline` | `8211468fff3c` | — *(not executed)* | `0` | `0` | `0` | **`1`** | `file: 1` | `13` | `0` | `4,412` |
| `pilot_02_asyncrat_dormant` | `asyncrat` | `64fe92d83db4` | — *(not executed)* | `0` | `0` | `0` | **`1`** | `file: 1` | `13` | `0` | `4,413` |
| `pilot_03_privateloader_dormant` | `privateloader` | `fcd465bfb29a` | — *(not executed)* | `0` | `0` | `0` | **`1`** | `file: 1` | `13` | `0` | `4,412` |
| `pilot_04_coinminer_dormant` | `coinminer` | `9a527eb9bd02` | — *(not executed)* | `0` | `0` | `0` | **`1`** | `file: 1` | `13` | `2` | `4,411` |
| `pilot_05_cobaltstrike_dormant` | `cobaltstrike` | `f535cdbb32dd` | — *(not executed)* | `0` | `0` | `0` | **`1`** | `file: 1` | `13` | `0` | `4,412` |
| `pilot_06_lumma_dormant` | `lumma` | `cacc573a567a` | — *(not executed)* | `0` | `0` | `0` | **`1`** | `file: 1` | `13` | `0` | `4,412` |
| `pilot_07_quasar_dormant` | `quasar` | `eda7de5855de` | — *(not executed)* | `0` | `0` | `0` | **`1`** | `file: 1` | `13` | `2` | `4,411` |

- **Total Raw Labeled Rows (`14` malware runs):** `62,023` (`baseline = 61,761`, `benign_drift = 180`, `attacker_induced = 54`, `ambiguous_unattributed = 28`).
- **Deduplicated Dev Dataset (`deduplicate_dev_os_baseline`):** **`4,570` rows** (`baseline = 4,308`, `benign_drift = 180`, `attacker_induced = 54`, `ambiguous_unattributed = 28`).
- **Mean `attacker_induced` Positives per Run:**
  - **`executed`:** **`6.71`** positives/run (`47` total across `7` runs; range `2`..`21`)
  - **`dormant`:** **`1.00`** positive/run (`7` total across `7` runs)

### 4.2 Notable Real Malware Behaviors Captured Cold-Disk
1. **RedLine (`pilot_01_redline_executed`, `21` positives):** Unpacked multi-stage droppers into `C:\Windows\Temp\IXP000.TMP\..IXP002.TMP\` (`w1d29.exe`, `4l907v.exe`, `j9l23.exe`, `3v67v.exe`, `1h65c3.exe`, `2r4474.exe`), dropped payload `C:\Windows\Temp\abc3bc1985\skotes.exe`, registered scheduled task `\skotes`, and wrote Windows Defender tampering policies (`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\DisableAntiSpyware` and `...\Real-Time Protection\DisableIOAVProtection`).
2. **AsyncRAT (`pilot_02_asyncrat_executed`, `7` positives):** Executed `asyncrat_updater_64fe92d8.exe` and spawned `.NET` LOLBin `C:\Windows\Microsoft.NET\Framework\v4.0.30319\RegAsm.exe` (captured across `shimcache`, `amcache`, and `file`).
3. **QuasarRAT (`pilot_07_quasar_executed`, `8` positives):** Executed `quasar_updater_eda7de58.exe` and spawned `C:\Windows\SysWOW64\svchost.exe` (`shimcache`, `amcache`, `file`).
4. **PrivateLoader, Coinminer, CobaltStrike, Lumma (`2`–`3` positives each):** Captured execution footprints across `file`, `shimcache`, and `amcache`.
5. **Unattributed Drift (`28` rows total across `14` runs = `2.0` rows/run):** Consisted solely of background Windows OneDrive scheduled task metadata updates (`OneDrive Reporting Task`, `OneDrive Standalone Update Task`, `10` rows), Windows Update services (`WaaSMedicSvc`, `wuauserv`, `2` rows), and Windows Error Reporting / fault-tolerant heap system DLL/Prefetch touches (`WerFault.exe`, `svchost.exe`, `fthsvc.dll`, `raserver.exe`, `16` rows) — all cleanly quarantined into `ambiguous_unattributed` so zero unverified OS drift pollutes `benign_drift` (`y=0`).

---

## 5. Pre-Registration Gates, Preliminary Nested CV & Power Calibration

### 5.1 Template-Quantization Gate (`IMP-06`, `scripts/verify_stratified_shortcuts.py`)
- **Procedural `benign_drift` rows (`180` rows across `14` runs: `138` files, `14` services, `14` run keys, `14` registry entries):**
  - `unique_size_ratio`: **`1.0000`** (`138 / 138` unique file sizes, threshold `>= 0.50`)
  - `unique_size_entropy_pair_ratio`: **`1.0000`** (`138 / 138` unique `(size, entropy)` pairs, threshold `>= 0.75`)
  - `max_single_size_share`: **`0.0072`** (`0.72%`, threshold `<= 0.10`)
  - `benign_services = 14`, `benign_registry = 14`, `benign_unsigned_pes = 55` -> **`passed = true` (`failures = []`)**
- **Full deduplicated benign corpus (`4,488` rows: `2,560` files, `275` services, `224` registry):**
  - `unique_size_ratio = 0.6898`, `unique_size_entropy_pair_ratio = 0.9473`, `max_single_size_share = 0.0141` -> **`passed = true` (`failures = []`)**
- *(Code note for Sprint 2 cleanup: `evaluate_stage_a_pilot_runs` line 1057 currently filters `full_pilot_df` to `artifact_type == "file"` before calling `check_template_quantization`, which hides the `service` and `registry` rows from `check_template_quantization` and also runs CV prior to calling `deduplicate_dev_os_baseline`. Passing all benign artifact types and deduplicating dev baseline rows before CV resolves both.)*

### 5.2 `OD-V2-20` Pre-Scoring Static Referential Graph Diagnostic
- **Deduplicated Dev Set (`4,570` rows):** `563 / 849` (**`66.31%`** >= `50.0%` threshold) persistence/execution rows resolved (`task: 94.08%`, `service: 99.64%`, `run_key: 94.44%`, `registry: 96.02%`, `amcache: 99.42%`).
- **Per-Run Extraction Manifests (with forward Prefetch SCCA resolution):** `796 / 801` (**`99.38%`**) persistence/execution rows resolved.

### 5.3 Preliminary 3-Arm Nested Family CV, LOFO & Execution Delta (`n_eval = 4,542` Deduplicated Dev Rows, `54` Positives)

| Family (`n_pos`) | `XGBoost` PR-AUC | `XGBoost` ROC-AUC | `RandomForest` PR-AUC | `RandomForest` ROC-AUC | `IsolationForest` PR-AUC | `IsolationForest` ROC-AUC | `XGBoost` Effort@Recall50 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `redline` (`22`) | **`0.1263`** | `0.3955` | `0.0065` | `0.3879` | `0.0029` | `0.1568` | `3,358` |
| `lumma` (`4`) | `0.0683` | **`0.9147`** | **`0.1310`** | `0.9051` | `0.0012` | `0.4406` | `174` |
| `asyncrat` (`8`) | **`0.0082`** | `0.7815` | `0.0080` | **`0.7822`** | `0.0022` | `0.4826` | `373` |
| `coinminer` (`4`) | **`0.0075`** | **`0.9216`** | `0.0057` | `0.8836` | `0.0012` | `0.4324` | `372` |
| `quasar` (`9`) | **`0.0044`** | **`0.7235`** | `0.0037` | `0.6181` | `0.0012` | `0.0447` | `955` |
| `privateloader` (`4`) | **`0.0032`** | **`0.8141`** | `0.0022` | `0.7383` | `0.0007` | `0.1237` | `744` |
| `cobaltstrike` (`3`) | **`0.0025`** | **`0.7965`** | `0.0013` | `0.6324` | `0.0006` | `0.1034` | `864` |
| **Overall Outer OOF** | **`0.0838`** | — | **`0.0303`** | — | **`0.0073`** | — | — |

- **Intrusion-Level Recall@k (`cross_stratum_execution_delta`, `7` paired families):**
  - **`XGBoost`:** `Intrusion Recall@5 = 100.0%` (`7/7` executed) and `100.0%` (`7/7` dormant), `median Delta_first_hit = 0.0` ranks.
  - **`RandomForest`:** `Intrusion Recall@5 = 85.7%` (`6/7` executed) and `100.0%` (`7/7` dormant), `median Delta_first_hit = 0.0` ranks.
- **Empirical Statistical-Power Calibration (`oof_xgb` vs `oof_rf` across `7` pilot families):**
  - Empirical between-family paired PR-AUC difference SD: **`sigma_delta_family = 0.0544`** (`mean_paired_diff = +0.0089`).
  - Projected 80%-power Minimum Detectable Effect (`MDE`, `m=10` Holm-Bonferroni):
    - `F_test = 10` families: `MDE_step1 = 0.0628`, `MDE_step10 = 0.0482`
    - `F_test = 15` families: `MDE_step1 = 0.0512`, `MDE_step10 = 0.0393`
    - `F_test = 22` families: `MDE_step1 = 0.0423`, `MDE_step10 = 0.0325`
    - `F_test = 25` families: `MDE_step1 = 0.0397`, `MDE_step10 = 0.0305`

---

## 6. Next Steps (Transition to Stage B & Sprint 2)

1. **Supervisor Allowlist Sign-Off & Benign Pool Population (Before Stage B Full Collection):**
   - Review the blank `spreader modules?` column in [`docs/v2/ALLOWED_FAMILIES_REVIEW.md`](ALLOWED_FAMILIES_REVIEW.md) (`60` canonical families).
   - Populate real third-party signed/unsigned PEs, scripts, and `.exe`/`.msi` installers into `/var/lib/dfir-quarantine-vault/benign_pools/{dev,blind_test}` and verify with `.venv/bin/python scripts/v2_prepare_benign_pools.py --audit --enforce-quotas`.
2. **Sprint 2 Modeling, Statistical Suite & Air-Gapped Analyst UI/API:**
   - Fix the 2 minor `evaluate_stage_a_pilot_runs` helper issues noted in §5.1 (pass all benign types to `check_template_quantization` and call `deduplicate_dev_os_baseline` prior to CV).
   - Expand `src/v2/models_v2.py`, `src/v2/training.py`, and `src/v2/stats_v2.py` to the locked `~20`-model comparative study (`XGBRanker`, `LGBMRanker`, `CatBoost`, `LightGBM`, `LinearSVC`, `Nystroem-RBF`, capped `kNN`/`LOF`, `FT-Transformer`/`ResNet-Tabular`, `Nystroem-OCSVM`, `RuleMLHybrid`, natural-prevalence calibration, Friedman/Nemenyi + `m=10` Holm-Bonferroni + 5-axis scorecard) and build `src/api/`.
