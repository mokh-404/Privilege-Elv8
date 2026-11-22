# Pre-51-Run Final Stratified Shortcut Audit & Launch Readiness

**Generated:** 2026-11-21  
**Repository:** [dfir-triage-ml](..)  
**Status:** ALL STRATIFIED CRITERIA PASSED & VERIFIED LIVE — AWAITING OPERATOR LAUNCH GO-AHEAD  

---

## 1. Generator Changes & Git Diff

### `lab_automation/benign_noise.ps1`
1. **Compound Name Pools**:
   - Replaced simple single-word stems with compound pools matching empirical attack length distributions.
   - Files: `FilePrefixes` + `FileStems` (`sys_audit`, `net_probe`, `disk_clean`, etc.) matching mean length 15.8 chars.
   - Tasks: `TaskPrefixes` + `TaskStems` (`CacheMaintenanceHelper`, `TelemetryIndexRefresh`, `FontCacheUpdater`, etc.) matching mean length 18.9 chars, 0% `_vN`.
   - Run Keys: `RunPrefixes` + `RunStems` (`DesktopSyncAgent`, `PrinterSpoolFix`, `SysHealthMonV1`, etc.) matching mean length 12.7 chars, ~60% `V1..V3`.
2. **Suffix Policy**:
   - `_vN` suffix rate set to empirical attack rate of 56% for files, 60% for run keys, and 0% for tasks.
3. **Matched Interpreters & Targets**:
   - Tasks: 67% `powershell.exe -NoProfile -WindowStyle Hidden -File <target_script>`, 33% `cmd.exe /c <target_script>`, targeting scripts in `ProgramData` and `Users\Public`.
   - Run Keys: 50% `powershell.exe -File <target_script>`, 50% direct `<target_path>` in `ProgramData` / `Users\Public`.
4. **Exact Provenance Emission**:
   - All dropped scripts and registry/task artifacts emit exact expected keys dynamically per draw.

```diff
--- a/lab_automation/benign_noise.ps1
+++ b/lab_automation/benign_noise.ps1
@@ -37,12 +37,15 @@ function Emit-Prov([string]$Action, [string[]]$ExpectedKeys) {
 }
 
 # Shared word pools and directory pool matching attack distributions from techniques.yaml
-$DocStems = @("notes", "review", "status", "incident", "sync", "release", "summary", "plan", "catalog", "wiki", "docs", "report")
-$HtmlStems = @("portal", "intranet", "dashboard", "index", "guide", "support")
-$ScriptStems = @("audit", "chk", "probe", "report", "cfg", "log", "mon", "maint", "diag", "queue", "sync", "sweep")
-$TaskStems = @("SyncCheck", "MaintHelper", "DiskAudit", "LogRotate", "IndexRefresh", "CertMon", "HealthCheck", "DiagSweep", "QueueMgr", "CacheMaint")
-$RunStems = @("Notes", "SyncAgent", "SessionHelper", "Notifier", "ProfileSync", "Assistant", "QueueSvc")
-$Suffixes = @("", "_v1", "_v2", "_v3")
+$FilePrefixes = @("sys", "net", "host", "acct", "cfg", "disk", "user", "svc", "diag", "log", "sync", "data", "cache", "task", "file", "env", "mon", "perf")
+$FileStems = @("audit", "probe", "scan", "sweep", "check", "helper", "monitor", "worker", "agent", "status", "report", "clean", "maint", "sync", "update", "refresh", "backup", "review")
+$FileExts = @("ps1", "ps1", "cmd", "cmd", "bat", "vbs")
+
+$TaskPrefixes = @("Cache", "Telemetry", "Font", "System", "Index", "Network", "Health", "Service", "Data", "Disk")
+$TaskStems = @("MaintenanceHelper", "IndexRefresh", "CacheUpdater", "StatusMonitor", "HealthCheck", "UpdateHelper")
+
+$RunPrefixes = @("Desktop", "Printer", "SysHealth", "Cert", "SysAudit", "Acct", "Cfg", "Health", "Sync", "Net")
+$RunStems = @("SyncAgent", "SpoolFix", "Mon", "Sync", "Once", "Scan", "Audit", "Indexer", "Agent", "Fix")
 
 $Dirs = @(
     "C:\ProgramData\Diagnostics",
@@ -57,8 +60,13 @@ $Dirs = @(
 function Get-TargetDir {
     return (Get-Random -InputObject $Dirs)
 }
-function Get-Suffix {
-    return (Get-Random -InputObject $Suffixes)
+
+function Get-CompoundFileName([string]$ForcedExt = "") {
+    $p = Get-Random -InputObject $FilePrefixes
+    $s = Get-Random -InputObject $FileStems
+    $suf = if ((Get-Random -Minimum 0 -Maximum 100) -lt 56) { "_v" + (Get-Random -InputObject @(1, 2, 3)) } else { "" }
+    $ext = if (-not [string]::IsNullOrWhiteSpace($ForcedExt)) { $ForcedExt } else { Get-Random -InputObject $FileExts }
+    return "$p`_$s$suf.$ext"
 }
 
 foreach ($step in $StepList) {
@@ -66,30 +74,23 @@ foreach ($step in $StepList) {
         "workspace_doc" {
             $d = Get-TargetDir
             [void][System.IO.Directory]::CreateDirectory($d)
-            $stem1 = Get-Random -InputObject $DocStems
-            $suf1 = Get-Suffix
-            $fn1 = "$stem1$suf1.txt"
-            $doc = Join-Path $d $fn1
+            $fn1 = Get-CompoundFileName "cmd"
+            $doc1 = Join-Path $d $fn1
+            $fn2 = Get-CompoundFileName "ps1"
+            $doc2 = Join-Path $d $fn2
 
-            $stem2 = Get-Random -InputObject $HtmlStems
-            $suf2 = Get-Suffix
-            $fn2 = "$stem2$suf2.html"
-            $html = Join-Path $d $fn2
-
-            [System.IO.File]::WriteAllText($doc, "Quarterly engineering review notes.")
-            [System.IO.File]::WriteAllText($html, "<html><body><h1>Offline Intranet Docs</h1></body></html>")
+            [System.IO.File]::WriteAllText($doc1, "@echo off`r`nrem System maintenance batch`r`necho Maintenance OK`r`n")
+            [System.IO.File]::WriteAllText($doc2, "# Administrative telemetry and health check`r`nGet-Date | Out-Null`r`n")
             Emit-Prov "workspace_doc" @(
-                ("file|" + $doc.ToLowerInvariant() + "|" + $fn1.ToLowerInvariant()),
-                ("file|" + $html.ToLowerInvariant() + "|" + $fn2.ToLowerInvariant())
+                ("file|" + $doc1.ToLowerInvariant() + "|" + $fn1.ToLowerInvariant()),
+                ("file|" + $doc2.ToLowerInvariant() + "|" + $fn2.ToLowerInvariant())
             )
             Start-Sleep -Milliseconds (300 + (($Seed * 17) % 700))
         }
         "ps_diag" {
             $d = Get-TargetDir
             [void][System.IO.Directory]::CreateDirectory($d)
-            $stem = Get-Random -InputObject $ScriptStems
-            $suf = Get-Suffix
-            $fn = "$stem$suf.ps1"
+            $fn = Get-CompoundFileName "ps1"
             $psScript = Join-Path $d $fn
             $csvOut = Join-Path $d "service_status.csv"
             $body = "Get-Service | Select-Object -First 15 Name,Status | Export-Csv -NoTypeInformation -Path '$csvOut'"
@@ -100,32 +101,59 @@ foreach ($step in $StepList) {
             )
         }
         "backup_task" {
-            $stem = Get-Random -InputObject $TaskStems
-            $suf = Get-Suffix
-            $tName = "$stem$suf"
-            $outTxt = "C:\Windows\Temp\task_idx.txt"
-            $cmd = "cmd.exe /c dir C:\Users\Public > $outTxt"
-            & schtasks.exe /Create /TN $tName /TR $cmd /SC ONCE /ST 23:55 /F | Out-Null
+            $tp = Get-Random -InputObject $TaskPrefixes
+            $ts = Get-Random -InputObject $TaskStems
+            $tName = "$tp$ts"
+            $td = Get-TargetDir
+            [void][System.IO.Directory]::CreateDirectory($td)
+            $tScriptFn = Get-CompoundFileName "ps1"
+            $tScript = Join-Path $td $tScriptFn
+            [System.IO.File]::WriteAllText($tScript, "Get-Date | Out-File -FilePath `"$td\task_idx.log`"")
+
+            # 67% powershell, 33% cmd matching attack task distribution
+            if ((Get-Random -Minimum 0 -Maximum 100) -lt 67) {
+                $trCmd = "powershell.exe -NoProfile -WindowStyle Hidden -File `"$tScript`""
+            } else {
+                $trCmd = "cmd.exe /c `"$tScript`""
+            }
+            & schtasks.exe /Create /TN $tName /TR $trCmd /SC ONCE /ST 23:55 /F | Out-Null
             Emit-Prov "backup_task" @(
-                ("task|\|" + $tName.ToLowerInvariant())
+                ("task|\|" + $tName.ToLowerInvariant()),
+                ("file|" + $tScript.ToLowerInvariant() + "|" + $tScriptFn.ToLowerInvariant())
             )
         }
         "run_note" {
-            $stem = Get-Random -InputObject $RunStems
-            $suf = Get-Suffix
-            $valName = "$stem$suf"
-            $valCmd = "C:\Windows\System32\notepad.exe C:\Users\Public\meeting_notes.txt"
-            & reg.exe ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v $valName /t REG_SZ /d $valCmd /f | Out-Null
+            $rp = Get-Random -InputObject $RunPrefixes
+            $rs = Get-Random -InputObject $RunStems
+            $rsuf = if ((Get-Random -Minimum 0 -Maximum 100) -lt 60) { "V" + (Get-Random -InputObject @(1, 2, 3)) } else { "" }
+            $valName = "$rp$rs$rsuf"
+            $rd = Get-TargetDir
+            [void][System.IO.Directory]::CreateDirectory($rd)
+            $rScriptFn = Get-CompoundFileName "ps1"
+            $rScript = Join-Path $rd $rScriptFn
+            [System.IO.File]::WriteAllText($rScript, "Write-Output `"sync ok`" | Out-File `"$rd\run_sync.log`"")
+
+            # 50% powershell interpreter, 50% direct path matching attack run key distribution
+            if ((Get-Random -Minimum 0 -Maximum 100) -lt 50) {
+                $valCmd = "powershell.exe -NoProfile -WindowStyle Hidden -File `"$rScript`""
+            } else {
+                $valCmd = "`"$rScript`""
+            }
+            $regHive = if ((Get-Random -Minimum 0 -Maximum 100) -lt 88) {
+                "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
+            } else {
+                "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"
+            }
+            & reg.exe ADD $regHive /v $valName /t REG_SZ /d $valCmd /f | Out-Null
             Emit-Prov "run_note" @(
-                ("run_key|hku|" + $valName.ToLowerInvariant())
+                ("run_key|hku|" + $valName.ToLowerInvariant()),
+                ("file|" + $rScript.ToLowerInvariant() + "|" + $rScriptFn.ToLowerInvariant())
             )
         }
         "cmd_archive" {
             $d = Get-TargetDir
             [void][System.IO.Directory]::CreateDirectory($d)
-            $stem = Get-Random -InputObject $ScriptStems
-            $suf = Get-Suffix
-            $fn = "$stem$suf.cmd"
+            $fn = Get-CompoundFileName "cmd"
             $bat = Join-Path $d $fn
             $batBody = "@echo off`r`ndir C:\Users\Public > `"$d\dir_list.txt`"`r`n"
             [System.IO.File]::WriteAllText($bat, $batBody)
```

---

## 2. Offline Stratified Shortcut Audit (Real Feature Extractor)

Across 48 simulated seeds (seeds 46..93, matching the 48 attack runs) vs `techniques.yaml` attack artifacts:
- **Total Attack Rows evaluated**: 74 (63 files, 3 tasks, 8 run keys)
- **Total Benign Rows evaluated**: 384 (288 files, 48 tasks, 48 run keys)
- **Distinct Benign Keys after cross-run deduplication**: **358 unique keys** (target: $\ge 100$)

### 2.1 Artifact Type: `file` (Attack N=63, Benign N=288)

**Name Length Distributions:**
- **Attack**: Mean = **15.46**, Median = 16.0, Std = 2.59, Min = 9, Max = 23
- **Benign**: Mean = **15.79**, Median = 16.0, Std = 1.74, Min = 12, Max = 19

| Numeric Feature | Attack Mean | Benign Mean | Single-Feature ROC-AUC | Status ($\le 0.70$) |
| :--- | :---: | :---: | :---: | :---: |
| `path_depth` | 1.83 | 2.26 | **0.6865** | **PASS** |
| `name_length` | 15.46 | 15.79 | **0.5370** | **PASS** |
| `name_entropy` | 3.47 | 3.53 | **0.5604** | **PASS** |
| `file_size_log` | 3.31 | 3.31 | **0.5000** | **PASS** |
| `file_entropy` | 8.00 | 8.00 | **0.5000** | **PASS** |
| `cmdline_length` | 0.00 | 0.00 | **0.5000** | **PASS** |
| `cmdline_entropy` | 0.00 | 0.00 | **0.5000** | **PASS** |
| `cmdline_nonalnum_ratio` | 0.00 | 0.00 | **0.5000** | **PASS** |
| `has_double_extension` | 0.02 | 0.00 | **0.5079** | **PASS** |
| `has_encoded_flag` | 0.00 | 0.00 | **0.5000** | **PASS** |
| `has_url_or_ip` | 0.00 | 0.00 | **0.5000** | **PASS** |
| `has_lolbin` | 0.00 | 0.00 | **0.5000** | **PASS** |
| `has_hidden_attr` | 0.00 | 0.00 | **0.5000** | **PASS** |
| `autostart_flag` | 0.00 | 0.00 | **0.5000** | **PASS** |

| Categorical Feature | Level | Attack Share | Benign Share | Class Gap | Status ($\le 25\text{pp}$) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| `path_class` | `temp` | 31.7% | 23.3% | 8.5pp | **PASS** |
| `path_class` | `user_writable` | 68.3% | 76.7% | 8.5pp | **PASS** |
| `ext_class` | `dll` | 6.3% | 0.0% | 6.3pp | **PASS** |
| `ext_class` | `exe` | 11.1% | 0.0% | 11.1pp | **PASS** |
| `ext_class` | `script` | 82.5% | 100.0% | 17.5pp | **PASS** |
| `registry_location_class` | `na` | 100.0% | 100.0% | 0.0pp | **PASS** |
| `parent_process_class` | `na` | 100.0% | 100.0% | 0.0pp | **PASS** |
| `signature_state` | `signed_trusted` | 11.1% | 0.0% | 11.1pp | **PASS** |
| `signature_state` | `unsigned` | 88.9% | 100.0% | 11.1pp | **PASS** |

---

### 2.2 Artifact Type: `task` (Attack N=3, Benign N=48)

**Name Length Distributions:**
- **Attack**: Mean = **19.67**, Median = 21.0, Std = 3.21, Min = 16, Max = 22
- **Benign**: Mean = **18.88**, Median = 18.0, Std = 2.74, Min = 15, Max = 26

| Numeric Feature | Attack Mean | Benign Mean | Single-Feature ROC-AUC | Status ($\le 0.70$) |
| :--- | :---: | :---: | :---: | :---: |
| `path_depth` | 3.33 | 3.50 | **0.5417** | **PASS** |
| `name_length` | 19.67 | 18.88 | **0.5937** | **PASS** |
| `name_entropy` | 3.53 | 3.44 | **0.6667** | **PASS** |
| `file_size_log` | 5.65 | 5.65 | **0.5000** | **PASS** |
| `file_entropy` | 8.00 | 8.00 | **0.5000** | **PASS** |
| `cmdline_length` | 111.00 | 105.12 | **0.5382** | **PASS** |
| `cmdline_entropy` | 4.63 | 4.69 | **0.5312** | **PASS** |
| `cmdline_nonalnum_ratio` | 0.15 | 0.15 | **0.5174** | **PASS** |
| `has_double_extension` | 0.00 | 0.00 | **0.5000** | **PASS** |
| `has_encoded_flag` | 0.33 | 0.23 | **0.5521** | **PASS** |
| `has_url_or_ip` | 0.00 | 0.00 | **0.5000** | **PASS** |
| `has_lolbin` | 0.00 | 0.00 | **0.5000** | **PASS** |
| `has_hidden_attr` | 0.00 | 0.00 | **0.5000** | **PASS** |
| `autostart_flag` | 0.00 | 0.00 | **0.5000** | **PASS** |

| Categorical Feature | Level | Attack Share | Benign Share | Class Gap | Status ($\le 25\text{pp}$) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| `path_class` | `system` | 100.0% | 100.0% | 0.0pp | **PASS** |
| `ext_class` | `exe` | 100.0% | 100.0% | 0.0pp | **PASS** |
| `registry_location_class` | `na` | 100.0% | 100.0% | 0.0pp | **PASS** |
| `parent_process_class` | `na` | 100.0% | 100.0% | 0.0pp | **PASS** |
| `signature_state` | `signed_trusted` | 100.0% | 100.0% | 0.0pp | **PASS** |

---

### 2.3 Artifact Type: `run_key` (Attack N=8, Benign N=48)

**Name Length Distributions:**
- **Attack**: Mean = **12.88**, Median = 13.5, Std = 2.30, Min = 10, Max = 16
- **Benign**: Mean = **12.73**, Median = 13.0, Std = 3.02, Min = 8, Max = 18

| Numeric Feature | Attack Mean | Benign Mean | Single-Feature ROC-AUC | Status ($\le 0.70$) |
| :--- | :---: | :---: | :---: | :---: |
| `path_depth` | 2.62 | 3.10 | **0.5924** | **PASS** |
| `name_length` | 12.88 | 12.73 | **0.5195** | **PASS** |
| `name_entropy` | 3.42 | 3.33 | **0.5612** | **PASS** |
| `file_size_log` | 4.33 | 4.22 | **0.5208** | **PASS** |
| `file_entropy` | 8.00 | 8.00 | **0.5000** | **PASS** |
| `cmdline_length` | 53.62 | 55.75 | **0.5859** | **PASS** |
| `cmdline_entropy` | 4.41 | 4.45 | **0.5234** | **PASS** |
| `cmdline_nonalnum_ratio` | 0.18 | 0.18 | **0.5391** | **PASS** |
| `has_double_extension` | 0.00 | 0.00 | **0.5000** | **PASS** |
| `has_encoded_flag` | 0.00 | 0.00 | **0.5000** | **PASS** |
| `has_url_or_ip` | 0.00 | 0.00 | **0.5000** | **PASS** |
| `has_lolbin` | 0.00 | 0.00 | **0.5000** | **PASS** |
| `has_hidden_attr` | 0.00 | 0.00 | **0.5000** | **PASS** |
| `autostart_flag` | 1.00 | 1.00 | **0.5000** | **PASS** |

| Categorical Feature | Level | Attack Share | Benign Share | Class Gap | Status ($\le 25\text{pp}$) |
| :--- | :--- | :---: | :---: | :---: | :---: |
| `path_class` | `system` | 50.0% | 45.8% | 4.2pp | **PASS** |
| `path_class` | `temp` | 0.0% | 8.3% | 8.3pp | **PASS** |
| `path_class` | `user_writable` | 50.0% | 45.8% | 4.2pp | **PASS** |
| `ext_class` | `exe` | 62.5% | 45.8% | 16.7pp | **PASS** |
| `ext_class` | `script` | 37.5% | 54.2% | 16.7pp | **PASS** |
| `registry_location_class` | `run` | 87.5% | 85.4% | 2.1pp | **PASS** |
| `registry_location_class` | `runonce` | 12.5% | 14.6% | 2.1pp | **PASS** |
| `parent_process_class` | `na` | 100.0% | 100.0% | 0.0pp | **PASS** |
| `signature_state` | `signed_trusted` | 50.0% | 45.8% | 4.2pp | **PASS** |
| `signature_state` | `unsigned` | 50.0% | 54.2% | 4.2pp | **PASS** |

---

## 3. Fresh Live Dry-Run Missingness & Task Audit

Executed fresh live dry run `dry_T1053_005_v1` on `win11` (145.45s runtime):
- Overlay created, used, and cleanly deleted (`overlay_deleted: true`).
- `win11_base.qcow2` unchanged (`0444`, `137460187136` bytes, mtime `2026-11-21 05:59:52.232095818 +0200`).
- Processed through `labeler.py` into `data/interim/dry_run_processed/dataset_v1.parquet` (1,088 total rows: 1,065 baseline, 19 benign_drift, 4 attacker_induced).

### 3.1 Feature NaN Rate by Label (Post-Fix)

| Feature | `attacker_induced` | `benign_drift` | `baseline` |
| :--- | :---: | :---: | :---: |
| `artifact_type` | **0.00** | **0.00** | 0.0000 |
| `path_class` | **0.00** | **0.00** | 0.0000 |
| `ext_class` | **0.00** | **0.00** | 0.0000 |
| `signature_state` | **0.00** | **0.00** | 0.0000 |
| `parent_process_class` | **0.00** | **0.00** | 0.0000 |
| `registry_location_class` | **0.00** | **0.00** | 0.0000 |
| `path_depth` | **0.00** | **0.00** | 0.1606 |
| `name_length` | **0.00** | **0.00** | 0.0000 |
| `name_entropy` | **0.00** | **0.00** | 0.0000 |
| `file_size_log` | **0.00** | **0.00** | 0.1662 |
| `file_entropy` | **0.00** | **0.00** | 0.2000 |
| `cmdline_length` | **0.00** | **0.00** | 0.0000 |
| `cmdline_entropy` | **0.00** | **0.00** | 0.0000 |
| `cmdline_nonalnum_ratio` | **0.00** | **0.00** | 0.0000 |
| `has_double_extension` | **0.00** | **0.00** | 0.0000 |
| `has_encoded_flag` | **0.00** | **0.00** | 0.0000 |
| `has_url_or_ip` | **0.00** | **0.00** | 0.0000 |
| `has_lolbin` | **0.00** | **0.00** | 0.0000 |
| `has_hidden_attr` | **0.00** | **0.00** | 0.0000 |
| `autostart_flag` | **0.00** | **0.00** | 0.0000 |

### 3.2 Observed Attacker Rows & Task Target Resolution

```text
                                                               artifact_key artifact_type                    name     path_class  path_depth  file_size_log  file_entropy signature_state
0                                             task|\|cachemaintenancehelper          task  CacheMaintenanceHelper         system         4.0       5.657684      5.361462  signed_trusted
1             file|c:\programdata\maint\cache_sync_v1.ps1|cache_sync_v1.ps1          file       cache_sync_v1.ps1  user_writable         2.0       1.799341      4.663243        unsigned
2  service|hklm\system\currentcontrolset\services\mediaindexerhost|mediaindexerhost       service        MediaIndexerHost         system         2.0       5.536640      5.882084  signed_trusted
3          file|c:\programdata\mediactl\media_host_v1.cmd|media_host_v1.cmd          file       media_host_v1.cmd  user_writable         2.0       1.591065      4.201232  signed_untrusted
```

**Resolution Confirmed:**
- Attacker scheduled task `CacheMaintenanceHelper` target path extracted as `C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe`.
- Yields `path_class="system"`, `path_depth=4.0`, `ext_class="exe"`, `signature_state="signed_trusted"`, `file_size_log=5.658`, `file_entropy=5.361`.
- **Zero NaN rate across all 20 features for `attacker_induced` rows.**

---

## 4. Test Suite Verification

```bash
.venv/bin/pytest
```
- **Result:** `180 passed in 25.29s`
- Zero test failures or regressions.

---

## 5. Ready-to-Launch Command (Wrapped in tmux + systemd-inhibit)

To launch the full 51-run Track A batch in the background with power/sleep inhibition and persistent tmux session:

```bash
tmux new-session -d -s batch51 'systemd-inhibit --why="Track A 51-run VM collection benchmark" .venv/bin/python -m lab_automation.run_all --resume 2>&1 | tee results/logs/batch51.log'
```

To monitor progress:
```bash
tmux attach -t batch51
# or follow log:
tail -f results/logs/batch51.log
```
