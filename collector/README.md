# Read-Only Artifact Collector (`Collect-Artifacts.ps1`)

Windows PowerShell 5.1+ read-only collector for DFIR-Triage Track A lab runs.

## Read-Only Guarantee
- Only uses `Get-*` cmdlets, read-only registry reads (`HKLM:\` and loaded `Registry::HKEY_USERS\<SID>` hives), and `[System.IO.File]::Open(..., Open, Read, ReadWrite)`.
- Never creates or modifies files, services, scheduled tasks, registry keys, or VSS shadow copies outside `-OutDir`.
- Amcache (`C:\Windows\AppCompat\Programs\Amcache.hve`) is read only if unlocked or present in an existing shadow copy; otherwise it soft-fails and records `{"artifact_type": "amcache", "status": "skipped", "reason": "locked_hive_no_vss"}` in `manifest.json`.
- Drops `sshd.exe`, `sshd-session.exe`, `ssh-agent.exe`, its own `$PID` descendant tree, and caller-supplied `-ExcludePids` / `-ExcludePaths`.

## Usage (inside elevated Windows 10/11 VM)
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Collect-Artifacts.ps1 -OutDir C:\collector_out
```

Optional parameters:
- `-ExcludePids <int[]>`: launcher wrapper PIDs to omit from `process` artifacts.
- `-ExcludePaths <string[]>`: path prefixes to exclude from `process` and `file` collection.
- `-SkipFileHistogram`: omit 256-bin first-1-MiB byte histograms (`file_head_histogram`).
- `-MaxScannedFiles <int>`: cap for user-writable/Temp file scan (default `1500`).

## Smoke Test
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-Collector.ps1
```

Verifies `manifest.json` exists, every listed output file's SHA-256 matches, `artifacts.json` row count matches `total_records`, `record_sha256` is populated, and `host_changes` is empty, then prints measured runtime and stage timings.
