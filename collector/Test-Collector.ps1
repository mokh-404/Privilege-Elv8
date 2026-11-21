<#
.SYNOPSIS
Smoke test for Collect-Artifacts.ps1 (Prompt A deliverable).
Runs the collector into a temporary directory, verifies manifest SHA-256 hashes
match the written files, checks record_sha256 on sample rows, and prints timings.
#>
param(
    [string]$TestOutDir = (Join-Path $env:TEMP ("collector_smoke_" + [guid]::NewGuid().ToString("N").Substring(0, 8))),
    [switch]$KeepOutput
)

$ErrorActionPreference = "Stop"
$CollectorScript = Join-Path $PSScriptRoot "Collect-Artifacts.ps1"
if (-not (Test-Path $CollectorScript)) {
    throw "Missing collector script: $CollectorScript"
}

Write-Output "Running collector into $TestOutDir ..."
& $CollectorScript -OutDir $TestOutDir

$ManifestPath = Join-Path $TestOutDir "manifest.json"
if (-not (Test-Path $ManifestPath)) { throw "manifest.json missing" }
$Manifest = Get-Content -LiteralPath $ManifestPath -Raw | ConvertFrom-Json

if ($Manifest.artifact_key_sep -ne "|") {
    throw "Unexpected artifact_key_sep: $($Manifest.artifact_key_sep)"
}
if ($Manifest.host_changes.Count -ne 0) {
    throw "Expected empty host_changes, got $($Manifest.host_changes.Count)"
}

foreach ($out in $Manifest.outputs) {
    $fp = Join-Path $TestOutDir $out.file
    if (-not (Test-Path $fp)) { throw "Listed output missing: $fp" }
    $actual = (Get-FileHash -LiteralPath $fp -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actual -ne $out.sha256) {
        throw "SHA-256 mismatch for $($out.file): manifest=$($out.sha256) actual=$actual"
    }
}

$Artifacts = Get-Content -LiteralPath (Join-Path $TestOutDir "artifacts.json") -Raw | ConvertFrom-Json
if ($Artifacts.Count -ne $Manifest.total_records) {
    throw "artifacts.json count $($Artifacts.Count) != manifest total_records $($Manifest.total_records)"
}
$MissingHash = @($Artifacts | Where-Object { [string]::IsNullOrWhiteSpace($_.record_sha256) }).Count
if ($MissingHash -ne 0) {
    throw "$MissingHash artifact(s) missing record_sha256"
}

Write-Output ("SMOKE_PASS total_records={0} elapsed_seconds={1}" -f $Manifest.total_records, $Manifest.elapsed_seconds)
Write-Output ("Stage timings: " + ($Manifest.stage_timings_seconds | ConvertTo-Json -Compress))
Write-Output ("Skipped items: " + ($Manifest.skipped | ConvertTo-Json -Compress))

if (-not $KeepOutput) {
    Remove-Item -LiteralPath $TestOutDir -Recurse -Force -ErrorAction SilentlyContinue
}
