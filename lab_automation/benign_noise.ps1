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
$DocStems = @("notes", "review", "status", "incident", "sync", "release", "summary", "plan", "catalog", "wiki", "docs", "report")
$HtmlStems = @("portal", "intranet", "dashboard", "index", "guide", "support")
$ScriptStems = @("audit", "chk", "probe", "report", "cfg", "log", "mon", "maint", "diag", "queue", "sync", "sweep")
$TaskStems = @("SyncCheck", "MaintHelper", "DiskAudit", "LogRotate", "IndexRefresh", "CertMon", "HealthCheck", "DiagSweep", "QueueMgr", "CacheMaint")
$RunStems = @("Notes", "SyncAgent", "SessionHelper", "Notifier", "ProfileSync", "Assistant", "QueueSvc")
$Suffixes = @("", "_v1", "_v2", "_v3")

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
function Get-Suffix {
    return (Get-Random -InputObject $Suffixes)
}

foreach ($step in $StepList) {
    switch ($step) {
        "workspace_doc" {
            $d = Get-TargetDir
            [void][System.IO.Directory]::CreateDirectory($d)
            $stem1 = Get-Random -InputObject $DocStems
            $suf1 = Get-Suffix
            $fn1 = "$stem1$suf1.txt"
            $doc = Join-Path $d $fn1

            $stem2 = Get-Random -InputObject $HtmlStems
            $suf2 = Get-Suffix
            $fn2 = "$stem2$suf2.html"
            $html = Join-Path $d $fn2

            [System.IO.File]::WriteAllText($doc, "Quarterly engineering review notes.")
            [System.IO.File]::WriteAllText($html, "<html><body><h1>Offline Intranet Docs</h1></body></html>")
            Emit-Prov "workspace_doc" @(
                ("file|" + $doc.ToLowerInvariant() + "|" + $fn1.ToLowerInvariant()),
                ("file|" + $html.ToLowerInvariant() + "|" + $fn2.ToLowerInvariant())
            )
            Start-Sleep -Milliseconds (300 + (($Seed * 17) % 700))
        }
        "ps_diag" {
            $d = Get-TargetDir
            [void][System.IO.Directory]::CreateDirectory($d)
            $stem = Get-Random -InputObject $ScriptStems
            $suf = Get-Suffix
            $fn = "$stem$suf.ps1"
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
            $stem = Get-Random -InputObject $TaskStems
            $suf = Get-Suffix
            $tName = "$stem$suf"
            $outTxt = "C:\Windows\Temp\task_idx.txt"
            $cmd = "cmd.exe /c dir C:\Users\Public > $outTxt"
            & schtasks.exe /Create /TN $tName /TR $cmd /SC ONCE /ST 23:55 /F | Out-Null
            Emit-Prov "backup_task" @(
                ("task|\|" + $tName.ToLowerInvariant())
            )
        }
        "run_note" {
            $stem = Get-Random -InputObject $RunStems
            $suf = Get-Suffix
            $valName = "$stem$suf"
            $valCmd = "C:\Windows\System32\notepad.exe C:\Users\Public\meeting_notes.txt"
            & reg.exe ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v $valName /t REG_SZ /d $valCmd /f | Out-Null
            Emit-Prov "run_note" @(
                ("run_key|hku|" + $valName.ToLowerInvariant())
            )
        }
        "cmd_archive" {
            $d = Get-TargetDir
            [void][System.IO.Directory]::CreateDirectory($d)
            $stem = Get-Random -InputObject $ScriptStems
            $suf = Get-Suffix
            $fn = "$stem$suf.cmd"
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
