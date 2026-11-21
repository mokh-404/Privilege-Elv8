<#
.SYNOPSIS
Randomized, seeded benign-activity generator running inside the attack window.

.DESCRIPTION
Generates realistic hard-negative benign_drift artifacts (scheduled task, Run key,
admin PowerShell query, offline file creation/browsing, cmd.exe archive/dir, and
legitimate Sysinternals invocation if staged) in the exact interleaved time window
of an attack run. Prints PROVENANCE:<json> lines on stdout for the host-side log.
Contains ZERO forbidden simulation tokens.
#>
param(
    [int]$Seed = 42,
    [string]$Order = "workspace_doc,ps_diag,backup_task,run_note,cmd_archive,sysinternals_check",
    [string]$Steps = ""
)

$ErrorActionPreference = "Continue"
$SelfPid = $PID
Write-Output ("WRAPPER_PID={0}" -f $SelfPid)

$Selected = if (-not [string]::IsNullOrWhiteSpace($Steps)) { $Steps } else { $Order }
$StepList = @($Selected -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" })

Get-Random -SetSeed $Seed

function Emit-Prov([string]$Action, [string[]]$ExpectedKeys) {
    $rec = [ordered]@{
        launcher = "benign"
        action = $Action
        timestamp_utc = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
        expected_artifact_keys = $ExpectedKeys
        wrapper_pid = $SelfPid
        seed = $Seed
    }
    Write-Output ("PROVENANCE:" + ($rec | ConvertTo-Json -Depth 4 -Compress))
}

# Shared word pools and directory pool matching attack distributions from techniques.yaml
$FilePrefixes = @("sys", "net", "host", "acct", "cfg", "disk", "user", "svc", "diag", "log", "sync", "data", "cache", "task", "file", "env", "mon", "perf")
$FileStems = @("audit", "probe", "scan", "sweep", "check", "helper", "monitor", "worker", "agent", "status", "report", "clean", "maint", "sync", "update", "refresh", "backup", "review")
$FileExts = @("ps1", "ps1", "cmd", "cmd", "bat", "vbs")

$TaskPrefixes = @("Cache", "Telemetry", "Font", "System", "Index", "Network", "Health", "Service", "Data", "Disk")
$TaskStems = @("MaintenanceHelper", "IndexRefresh", "CacheUpdater", "StatusMonitor", "HealthCheck", "UpdateHelper")

$RunPrefixes = @("Desktop", "Printer", "SysHealth", "Cert", "SysAudit", "Acct", "Cfg", "Health", "Sync", "Net")
$RunStems = @("SyncAgent", "SpoolFix", "Mon", "Sync", "Once", "Scan", "Audit", "Indexer", "Agent", "Fix")

$Dirs = @(
    "C:\ProgramData\Diagnostics",
    "C:\ProgramData\Support",
    "C:\ProgramData\Maintenance",
    "C:\Users\Public",
    "C:\Users\Public\Reports",
    "C:\Windows\Temp",
    "C:\Windows\Temp\Maint"
)

function Get-TargetDir {
    return (Get-Random -InputObject $Dirs)
}

function Get-CompoundFileName([string]$ForcedExt = "") {
    $p = Get-Random -InputObject $FilePrefixes
    $s = Get-Random -InputObject $FileStems
    $suf = if ((Get-Random -Minimum 0 -Maximum 100) -lt 56) { "_v" + (Get-Random -InputObject @(1, 2, 3)) } else { "" }
    $ext = if (-not [string]::IsNullOrWhiteSpace($ForcedExt)) { $ForcedExt } else { Get-Random -InputObject $FileExts }
    return "$p`_$s$suf.$ext"
}

foreach ($step in $StepList) {
    switch ($step) {
        "workspace_doc" {
            $d = Get-TargetDir
            [void][System.IO.Directory]::CreateDirectory($d)
            $fn1 = Get-CompoundFileName "cmd"
            $doc1 = Join-Path $d $fn1
            $fn2 = Get-CompoundFileName "ps1"
            $doc2 = Join-Path $d $fn2

            [System.IO.File]::WriteAllText($doc1, "@echo off`r`nrem System maintenance batch`r`necho Maintenance OK`r`n")
            [System.IO.File]::WriteAllText($doc2, "# Administrative telemetry and health check`r`nGet-Date | Out-Null`r`n")
            Emit-Prov "workspace_doc" @(
                ("file|" + $doc1.ToLowerInvariant() + "|" + $fn1.ToLowerInvariant()),
                ("file|" + $doc2.ToLowerInvariant() + "|" + $fn2.ToLowerInvariant())
            )
            Start-Sleep -Milliseconds (300 + (($Seed * 17) % 700))
        }
        "ps_diag" {
            $d = Get-TargetDir
            [void][System.IO.Directory]::CreateDirectory($d)
            $fn = Get-CompoundFileName "ps1"
            $psScript = Join-Path $d $fn
            $csvOut = Join-Path $d "service_status.csv"
            $body = "Get-Service | Select-Object -First 15 Name,Status | Export-Csv -NoTypeInformation -Path '$csvOut'"
            [System.IO.File]::WriteAllText($psScript, $body)
            & powershell.exe -NoProfile -NonInteractive -InputFormat None -ExecutionPolicy Bypass -File $psScript | Out-Null
            Emit-Prov "ps_diag" @(
                ("file|" + $psScript.ToLowerInvariant() + "|" + $fn.ToLowerInvariant())
            )
        }
        "backup_task" {
            $tp = Get-Random -InputObject $TaskPrefixes
            $ts = Get-Random -InputObject $TaskStems
            $tName = "$tp$ts"
            $td = Get-TargetDir
            [void][System.IO.Directory]::CreateDirectory($td)
            $tScriptFn = Get-CompoundFileName "ps1"
            $tScript = Join-Path $td $tScriptFn
            [System.IO.File]::WriteAllText($tScript, "Get-Date | Out-File -FilePath `"$td\task_idx.log`"")

            # 67% powershell, 33% cmd matching attack task distribution
            if ((Get-Random -Minimum 0 -Maximum 100) -lt 67) {
                $trCmd = "powershell.exe -NoProfile -WindowStyle Hidden -File `"$tScript`""
            } else {
                $trCmd = "cmd.exe /c `"$tScript`""
            }
            & schtasks.exe /Create /TN $tName /TR $trCmd /SC ONCE /ST 23:55 /F | Out-Null
            Emit-Prov "backup_task" @(
                ("task|\|" + $tName.ToLowerInvariant()),
                ("file|" + $tScript.ToLowerInvariant() + "|" + $tScriptFn.ToLowerInvariant())
            )
        }
        "run_note" {
            $rp = Get-Random -InputObject $RunPrefixes
            $rs = Get-Random -InputObject $RunStems
            $rsuf = if ((Get-Random -Minimum 0 -Maximum 100) -lt 60) { "V" + (Get-Random -InputObject @(1, 2, 3)) } else { "" }
            $valName = "$rp$rs$rsuf"
            $rd = Get-TargetDir
            [void][System.IO.Directory]::CreateDirectory($rd)
            $rScriptFn = Get-CompoundFileName "ps1"
            $rScript = Join-Path $rd $rScriptFn
            [System.IO.File]::WriteAllText($rScript, "Write-Output `"sync ok`" | Out-File `"$rd\run_sync.log`"")

            # 50% powershell interpreter, 50% direct path matching attack run key distribution
            if ((Get-Random -Minimum 0 -Maximum 100) -lt 50) {
                $valCmd = "powershell.exe -NoProfile -WindowStyle Hidden -File `"$rScript`""
            } else {
                $valCmd = "`"$rScript`""
            }
            $regHive = if ((Get-Random -Minimum 0 -Maximum 100) -lt 88) {
                "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
            } else {
                "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce"
            }
            & reg.exe ADD $regHive /v $valName /t REG_SZ /d $valCmd /f | Out-Null
            Emit-Prov "run_note" @(
                ("run_key|hku|" + $valName.ToLowerInvariant()),
                ("file|" + $rScript.ToLowerInvariant() + "|" + $rScriptFn.ToLowerInvariant())
            )
        }
        "cmd_archive" {
            $d = Get-TargetDir
            [void][System.IO.Directory]::CreateDirectory($d)
            $fn = Get-CompoundFileName "cmd"
            $bat = Join-Path $d $fn
            $batBody = "@echo off`r`ndir C:\Users\Public > `"$d\dir_list.txt`"`r`n"
            [System.IO.File]::WriteAllText($bat, $batBody)
            & cmd.exe /c $bat | Out-Null
            Emit-Prov "cmd_archive" @(
                ("file|" + $bat.ToLowerInvariant() + "|" + $fn.ToLowerInvariant())
            )
        }
        "sysinternals_check" {
            $cand = @(
                "C:\Tools\Sysinternals\autorunsc.exe",
                "C:\Sysinternals\autorunsc.exe",
                "C:\Tools\Sysinternals\sigcheck.exe",
                "C:\Sysinternals\sigcheck.exe"
            ) | Where-Object { Test-Path $_ } | Select-Object -First 1
            if ($cand) {
                & $cand -accepteula -nobanner | Select-Object -First 5 | Out-Null
                Emit-Prov "sysinternals_check" @(
                    ("prefetch|c:\windows\prefetch|" + ([System.IO.Path]::GetFileName($cand)).ToLowerInvariant())
                )
            } else {
                # Fall back to standard built-in system query so step still executes harmlessly
                & whoami.exe | Out-Null
                Emit-Prov "sysinternals_check_fallback" @(
                    "prefetch|c:\windows\prefetch|whoami.exe"
                )
            }
        }
    }
    Start-Sleep -Milliseconds 400
}
