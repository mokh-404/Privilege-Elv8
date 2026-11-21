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
$Tag = ("{0:D4}" -f ([math]::Abs($Seed) % 10000))

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

$WorkDir = "C:\Users\Public\Documents\Workspace_$Tag"
[void][System.IO.Directory]::CreateDirectory($WorkDir)

foreach ($step in $StepList) {
    switch ($step) {
        "workspace_doc" {
            $doc = Join-Path $WorkDir "meeting_notes_$Tag.txt"
            $html = Join-Path $WorkDir "local_portal_$Tag.html"
            [System.IO.File]::WriteAllText($doc, "Quarterly engineering review notes ($Tag).")
            [System.IO.File]::WriteAllText($html, "<html><body><h1>Offline Intranet Docs $Tag</h1></body></html>")
            Emit-Prov "workspace_doc" @(
                ("file|" + $doc.ToLowerInvariant() + "|" + ("meeting_notes_$Tag.txt").ToLowerInvariant()),
                ("file|" + $html.ToLowerInvariant() + "|" + ("local_portal_$Tag.html").ToLowerInvariant())
            )
            Start-Sleep -Milliseconds (300 + (($Seed * 17) % 700))
        }
        "ps_diag" {
            $psScript = Join-Path $WorkDir "health_check_$Tag.ps1"
            $csvOut = Join-Path $WorkDir "service_status_$Tag.csv"
            $body = "Get-Service | Select-Object -First 15 Name,Status | Export-Csv -NoTypeInformation -Path '$csvOut'"
            [System.IO.File]::WriteAllText($psScript, $body)
            & powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $psScript | Out-Null
            Emit-Prov "ps_diag" @(
                ("file|" + $psScript.ToLowerInvariant() + "|" + ("health_check_$Tag.ps1").ToLowerInvariant())
            )
        }
        "backup_task" {
            $tName = "DailySyncCheck_$Tag"
            $cmd = "cmd.exe /c dir C:\Users\Public > $WorkDir\backup_idx_$Tag.txt"
            & schtasks.exe /Create /TN $tName /TR $cmd /SC ONCE /ST 23:55 /F | Out-Null
            Emit-Prov "backup_task" @(
                ("task|\|" + $tName.ToLowerInvariant())
            )
        }
        "run_note" {
            $valName = "WorkspaceNotes_$Tag"
            $valCmd = "C:\Windows\System32\notepad.exe $WorkDir\meeting_notes_$Tag.txt"
            & reg.exe ADD "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v $valName /t REG_SZ /d $valCmd /f | Out-Null
            Emit-Prov "run_note" @(
                ("run_key|hku|" + $valName.ToLowerInvariant())
            )
        }
        "cmd_archive" {
            $bat = Join-Path $WorkDir "local_sync_$Tag.cmd"
            $batBody = "@echo off`r`ndir C:\Users\Public\Documents > `"$WorkDir\dir_list_$Tag.txt`"`r`n"
            [System.IO.File]::WriteAllText($bat, $batBody)
            & cmd.exe /c $bat | Out-Null
            Emit-Prov "cmd_archive" @(
                ("file|" + $bat.ToLowerInvariant() + "|" + ("local_sync_$Tag.cmd").ToLowerInvariant())
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
