# Install-V2BaseBootstrap.ps1 — One-Time Clean Base Image Bake Script (Run Inside Clean Guest Before Sealing 0444)
#
# Performs three mandatory v2 base-image preparation steps inside the clean Windows 11 guest:
#   (a) Installs/updates Sysmon64 with the v2 process/file/registry/task/WMI configuration and sets a 64 MB EVTX buffer;
#   (b) Installs C:\DFIR-Bootstrap\Invoke-StagePayload.ps1 and registers \DFIR-StageRunner (SYSTEM, ONSTART);
#   (c) Disables & stops OpenSSH Server (sshd) so zero network listeners exist during runs, clears transient setup logs,
#       flushes NTFS volume caches, and shuts down cleanly.

param(
    [string]$SysmonExePath = "",
    [switch]$SkipShutdown
)

$ErrorActionPreference = "Stop"
$bootstrapDir = "C:\DFIR-Bootstrap"
if (-not (Test-Path -LiteralPath $bootstrapDir)) {
    New-Item -ItemType Directory -Path $bootstrapDir -Force | Out-Null
}

# Locate maintenance CD-ROM (volume label DFIR_BAKE) if attached
$bakeVol = Get-Volume | Where-Object { $_.FileSystemLabel -eq "DFIR_BAKE" -and $_.DriveLetter } | Select-Object -First 1
$bakeRoot = if ($bakeVol) { "$($bakeVol.DriveLetter):\" } else { $PSScriptRoot }

# 1. Write deterministic v2 Sysmon configuration (ProcessCreate, FileCreate, RegistryEvent, WmiEvent, ImageLoad, DriverLoad)
$sysmonConfigPath = Join-Path $bootstrapDir "sysmon_v2_config.xml"
$sysmonXml = @'
<Sysmon schemaversion="4.90">
  <HashAlgorithms>SHA256</HashAlgorithms>
  <CheckRevocation>False</CheckRevocation>
  <EventFiltering>
    <RuleGroup name="v2_process_create" groupRelation="or">
      <ProcessCreate onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup name="v2_file_create_time" groupRelation="or">
      <FileCreateTime onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup name="v2_driver_load" groupRelation="or">
      <DriverLoad onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup name="v2_image_load" groupRelation="or">
      <ImageLoad onmatch="include">
        <ImageLoaded condition="begin with">C:\Users\</ImageLoaded>
        <ImageLoaded condition="begin with">C:\ProgramData\</ImageLoaded>
        <ImageLoaded condition="begin with">C:\Windows\Temp\</ImageLoaded>
      </ImageLoad>
    </RuleGroup>
    <RuleGroup name="v2_create_remote_thread" groupRelation="or">
      <CreateRemoteThread onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup name="v2_file_create" groupRelation="or">
      <FileCreate onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup name="v2_registry_event" groupRelation="or">
      <RegistryEvent onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup name="v2_file_stream_hash" groupRelation="or">
      <FileCreateStreamHash onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup name="v2_wmi_event" groupRelation="or">
      <WmiEvent onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup name="v2_dns_query" groupRelation="or">
      <DnsQuery onmatch="exclude"/>
    </RuleGroup>
    <RuleGroup name="v2_process_tampering" groupRelation="or">
      <ProcessTampering onmatch="exclude"/>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
'@
Set-Content -LiteralPath $sysmonConfigPath -Value $sysmonXml -Encoding UTF8

# Locate Sysmon64.exe (explicit parameter, DFIR_BAKE ISO, C:\Tools, or C:\Windows)
$candidates = @()
if ($SysmonExePath) { $candidates += $SysmonExePath }
if ($bakeRoot) {
    $candidates += (Join-Path $bakeRoot "Sysmon64.exe")
    $candidates += (Join-Path $bakeRoot "SYSMON64.EXE")
}
$candidates += @(
    "C:\DFIR-Bootstrap\Sysmon64.exe",
    "C:\Tools\Sysinternals\Sysmon64.exe",
    "C:\Windows\Sysmon64.exe",
    "C:\Windows\System32\Sysmon64.exe"
)
$resolvedSysmon = $candidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
if (-not $resolvedSysmon) {
    throw "Sysmon64.exe not found. Place Sysmon64.exe on the DFIR_BAKE ISO or in C:\DFIR-Bootstrap\Sysmon64.exe before running Install-V2BaseBootstrap.ps1."
}

$existingSvc = Get-Service -Name "Sysmon64","Sysmon" -ErrorAction SilentlyContinue | Select-Object -First 1
if ($existingSvc) {
    & $resolvedSysmon -c $sysmonConfigPath | Out-Null
} else {
    & $resolvedSysmon -accepteula -i $sysmonConfigPath | Out-Null
}

# Set Sysmon Operational EVTX channel buffer to 64 MB (67108864 bytes)
& wevtutil.exe sl "Microsoft-Windows-Sysmon/Operational" /ms:67108864 /rt:false /ab:false
& wevtutil.exe sl "Microsoft-Windows-PowerShell/Operational" /ms:33554432 /rt:false /ab:false
& wevtutil.exe sl "Microsoft-Windows-WMI-Activity/Operational" /ms:16777216 /rt:false /ab:false

# 2. Install C:\DFIR-Bootstrap\Invoke-StagePayload.ps1 and register \DFIR-StageRunner (SYSTEM, ONSTART)
$stagePayloadPath = Join-Path $bootstrapDir "Invoke-StagePayload.ps1"
$stagePayloadScript = @'
# Invoke-StagePayload.ps1 — Zero-SSH / Zero-Guest-Agent Stage A Pilot In-Guest Bootstrapper
$ErrorActionPreference = "Stop"
$vol = Get-Volume | Where-Object { $_.FileSystemLabel -eq "DFIR_STAGE" -and $_.DriveLetter } | Select-Object -First 1
if (-not $vol) {
    exit 0
}
$stageRoot = "$($vol.DriveLetter):\"
$manifestPath = Join-Path $stageRoot "run_manifest.json"
if (-not (Test-Path -LiteralPath $manifestPath)) {
    exit 0
}
$manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json

# 1. Run deterministic benign workload if present
$benignScript = Join-Path $stageRoot "benign_workload.ps1"
if (Test-Path -LiteralPath $benignScript) {
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $benignScript -ProfileId $manifest.benign_profile_id
}

# 2. For dormant or executed strata, copy payload to exact matching initial staging_target_path and verify SHA-256
if ($manifest.stratum -in @("dormant", "executed")) {
    $payloadSrc = Join-Path $stageRoot "payload.bin"
    $targetPath = [string]$manifest.staging_target_path
    $targetDir = Split-Path -Parent $targetPath
    if (-not (Test-Path -LiteralPath $targetDir)) {
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    }
    Copy-Item -LiteralPath $payloadSrc -Destination $targetPath -Force
    $actualHash = (Get-FileHash -LiteralPath $targetPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $manifest.sample_sha256.ToLowerInvariant()) {
        throw "SHA-256 mismatch on staged payload: $actualHash != $($manifest.sample_sha256)"
    }
    if ($manifest.stratum -eq "executed" -and $manifest.execute_payload -eq $true) {
        Start-Process -FilePath $targetPath -WorkingDirectory $targetDir
    }
}

# 3. Wait dwell_seconds, flush NTFS volume cache, and power off cleanly
$dwell = if ($manifest.dwell_seconds) { [int]$manifest.dwell_seconds } else { 120 }
Start-Sleep -Seconds $dwell
Write-VolumeCache -DriveLetter C -ErrorAction SilentlyContinue
if ($manifest.auto_poweroff -ne $false) {
    Stop-Computer -Force
}
'@
Set-Content -LiteralPath $stagePayloadPath -Value $stagePayloadScript -Encoding UTF8

& schtasks.exe /Create /TN "\DFIR-StageRunner" /TR "powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\DFIR-Bootstrap\Invoke-StagePayload.ps1" /SC ONSTART /RU "SYSTEM" /RL HIGHEST /F | Out-Null

# Verify Sysmon service & \DFIR-StageRunner exist before disabling sshd
$verSvc = Get-Service -Name "Sysmon64","Sysmon" -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq "Running" }
if (-not $verSvc) {
    throw "Sysmon service failed to start during base bake!"
}
& schtasks.exe /Query /TN "\DFIR-StageRunner" | Out-Null

# 3. Disable OpenSSH Server (sshd) so zero network listeners exist during runs, clear setup logs, flush & power off
$sshdSvc = Get-Service -Name "sshd" -ErrorAction SilentlyContinue
if ($sshdSvc) {
    Set-Service -Name "sshd" -StartupType Disabled
    Stop-Service -Name "sshd" -Force -ErrorAction SilentlyContinue
}
& wevtutil.exe cl "Microsoft-Windows-Sysmon/Operational"
Write-VolumeCache -DriveLetter C -ErrorAction SilentlyContinue

if (-not $SkipShutdown) {
    & shutdown.exe /s /t 2 /c "DFIR v2 base image bake complete"
}
