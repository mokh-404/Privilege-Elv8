<#
.SYNOPSIS
Read-only Windows 10/11 forensic triage collector for DFIR-Triage (Prompt A).

.DESCRIPTION
Collects host artifacts read-only and writes per-type JSONL files, a combined
artifacts.json, and a SHA-256 integrity manifest.json inside -OutDir.
No host files, registry entries, services, tasks, or shadow copies are created
or modified outside -OutDir.
#>
[CmdletBinding()]
param(
    [Alias("OutputDir")]
    [string]$OutDir = "C:\collector_out",
    [int[]]$ExcludePids = @(),
    [string[]]$ExcludePaths = @(),
    [switch]$SkipFileHistogram,
    [int]$MaxScannedFiles = 1500
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$CollectorVersion = "1.0.0"
$ArtifactKeySep = "|"
$StartUtc = [DateTime]::UtcNow
$Utf8NoBom = [System.Text.UTF8Encoding]::new($false)
$Records = [System.Collections.Generic.List[object]]::new()
$StageTimings = [ordered]@{}
$Skipped = [System.Collections.Generic.List[object]]::new()
$HostChanges = [System.Collections.Generic.List[object]]::new()
$CommandClassesUsed = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$FileMetaCache = @{}
$ExcludedCounts = [ordered]@{
    processes_self_tree = 0
    processes_sshd = 0
    processes_param_pid = 0
    processes_param_path = 0
    files_excluded_path = 0
    files_capped = 0
}

function Record-CmdClass([string]$Name) {
    [void]$CommandClassesUsed.Add($Name)
}

function To-UtcIso($Dt) {
    if ($null -eq $Dt) { return $null }
    try {
        if ($Dt -is [DateTime]) {
            if ($Dt.Year -lt 1970) { return $null }
            return $Dt.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
        }
        $parsed = [DateTime]::Parse([string]$Dt, [System.Globalization.CultureInfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal)
        if ($parsed.Year -lt 1970) { return $null }
        return $parsed.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    } catch {
        return $null
    }
}

function Expand-NormPath([string]$Raw) {
    if ([string]::IsNullOrWhiteSpace($Raw)) { return $null }
    $s = $Raw.Trim().Trim('"').Trim()
    if ([string]::IsNullOrWhiteSpace($s)) { return $null }
    $s = [Environment]::ExpandEnvironmentVariables($s)
    $s = $s.Replace("/", "\")
    if ($s.StartsWith("\??\")) { $s = $s.Substring(4) }
    elseif ($s.StartsWith("\\?\")) { $s = $s.Substring(4) }
    if ($s -match '^(?i)\\systemroot\\(.+)$') { $s = "$env:SystemRoot\$($Matches[1])" }
    elseif ($s -match '^(?i)systemroot\\(.+)$') { $s = "$env:SystemRoot\$($Matches[1])" }
    elseif ($s -match '^(?i)system32\\(.+)$') { $s = "$env:SystemRoot\System32\$($Matches[1])" }
    return $s
}

function Extract-TargetPath([string]$CmdLine) {
    if ([string]::IsNullOrWhiteSpace($CmdLine)) { return $null }
    $s = $CmdLine.Trim()
    $candidate = $null
    if ($s.StartsWith('"')) {
        $end = $s.IndexOf('"', 1)
        $candidate = if ($end -gt 1) { $s.Substring(1, $end - 1) } else { $s.Substring(1) }
    } elseif ($s -match '^(?i)(.+?\.(?:exe|dll|ps1|psm1|bat|cmd|vbs|vbe|js|jse|wsf|hta|sys|scr|msi|lnk|com))(?=\s|,|$)') {
        $candidate = $Matches[1]
    } else {
        $candidate = ($s -split '\s+')[0]
    }
    $norm = Expand-NormPath $candidate
    if ($null -eq $norm) { return $null }
    if ($norm -notmatch '\\' -and $norm -match '\.(exe|dll|com|msc|cpl)$') {
        $sysPath = Join-Path "$env:SystemRoot\System32" $norm
        if ([System.IO.File]::Exists($sysPath)) { return $sysPath }
        $psPath = Join-Path "$env:SystemRoot\System32\WindowsPowerShell\v1.0" $norm
        if ([System.IO.File]::Exists($psPath)) { return $psPath }
    }
    return $norm
}

function Norm-KeyPart([string]$Val) {
    if ([string]::IsNullOrWhiteSpace($Val)) { return "" }
    return $Val.Trim().Replace("/", "\").ToLowerInvariant()
}

function Make-ArtifactKey([string]$Type, [string]$PathOrKey, [string]$Name) {
    return (@(
        (Norm-KeyPart $Type),
        (Norm-KeyPart $PathOrKey),
        (Norm-KeyPart $Name)
    ) -join $ArtifactKeySep)
}

function Compute-Sha256Hex([byte[]]$Bytes) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash($Bytes)
        return ([System.BitConverter]::ToString($hash)).Replace("-", "").ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

$NormExcludePrefixes = @()
foreach ($ep in @($ExcludePaths) + @($OutDir)) {
    $np = Expand-NormPath $ep
    if (-not [string]::IsNullOrWhiteSpace($np)) {
        $NormExcludePrefixes += $np.TrimEnd("\").ToLowerInvariant()
    }
}

function Is-ExcludedPath([string]$Text) {
    if ([string]::IsNullOrWhiteSpace($Text)) { return $false }
    $low = $Text.Replace("/", "\").ToLowerInvariant()
    foreach ($pref in $NormExcludePrefixes) {
        if ($low.StartsWith($pref) -or $low.Contains($pref)) { return $true }
    }
    return $false
}

function Get-FileMetadata([string]$FilePath) {
    $norm = Expand-NormPath $FilePath
    if ([string]::IsNullOrWhiteSpace($norm)) { return $null }
    $key = $norm.ToLowerInvariant()
    if ($FileMetaCache.ContainsKey($key)) {
        return $FileMetaCache[$key]
    }

    $meta = [ordered]@{
        path = $norm
        exists = $false
        file_size = $null
        attributes = $null
        signature_status = $null
        signature_subject = $null
        file_sha256 = $null
        file_head_histogram = $null
        created_utc = $null
        modified_utc = $null
    }

    try {
        if ([System.IO.File]::Exists($norm)) {
            $fi = [System.IO.FileInfo]::new($norm)
            $meta.exists = $true
            $meta.file_size = [int64]$fi.Length
            $meta.attributes = $fi.Attributes.ToString()
            $meta.created_utc = To-UtcIso $fi.CreationTimeUtc
            $meta.modified_utc = To-UtcIso $fi.LastWriteTimeUtc

            Record-CmdClass "Get-AuthenticodeSignature"
            try {
                $sig = Get-AuthenticodeSignature -FilePath $norm -ErrorAction Stop
                $meta.signature_status = [string]$sig.Status
                if ($null -ne $sig.SignerCertificate) {
                    $meta.signature_subject = [string]$sig.SignerCertificate.Subject
                }
            } catch {
                $meta.signature_status = "UnknownError"
            }

            Record-CmdClass "System.IO.File.Open(Read,ReadWrite)"
            try {
                $fs = [System.IO.File]::Open($norm, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
                $sha = [System.Security.Cryptography.SHA256]::Create()
                try {
                    $bufSize = 1048576
                    $buf = New-Object byte[] $bufSize
                    $firstChunk = $true
                    $hist = $null
                    if (-not $SkipFileHistogram) {
                        $hist = New-Object int[] 256
                    }
                    while (($read = $fs.Read($buf, 0, $buf.Length)) -gt 0) {
                        [void]$sha.TransformBlock($buf, 0, $read, $null, 0)
                        if ($firstChunk -and $null -ne $hist) {
                            for ($i = 0; $i -lt $read; $i++) {
                                $hist[$buf[$i]]++
                            }
                        }
                        $firstChunk = $false
                    }
                    [void]$sha.TransformFinalBlock($buf, 0, 0)
                    $meta.file_sha256 = ([System.BitConverter]::ToString($sha.Hash)).Replace("-", "").ToLowerInvariant()
                    if ($null -ne $hist) {
                        $meta.file_head_histogram = $hist
                    }
                } finally {
                    $sha.Dispose()
                    $fs.Dispose()
                }
            } catch {
                # File locked exclusively (e.g., certain kernel/protected files); leave hash/hist null
            }
        }
    } catch {
        # Best-effort metadata
    }

    $FileMetaCache[$key] = $meta
    return $meta
}

function Add-ArtifactRecord {
    param(
        [string]$ArtifactType,
        [string]$PathOrKey,
        [string]$Name,
        [string]$Path = $null,
        [string]$CommandLine = $null,
        [string]$RegistryKey = $null,
        [string]$RegistryValue = $null,
        [string]$TaskName = $null,
        [string]$ServiceName = $null,
        [string]$ParentName = $null,
        $PidVal = $null,
        $PpidVal = $null,
        [string]$StartMode = $null,
        [string]$TaskTriggers = $null,
        $FileMeta = $null,
        [string]$CreatedUtc = $null,
        [string]$ModifiedUtc = $null,
        $Raw = $null
    )

    if (Is-ExcludedPath $Path) {
        $ExcludedCounts.files_excluded_path++
        return
    }
    if (Is-ExcludedPath $CommandLine) {
        $ExcludedCounts.files_excluded_path++
        return
    }

    $effPath = if ($Path) { Expand-NormPath $Path } elseif ($FileMeta -and $FileMeta.path) { $FileMeta.path } else { $null }
    $effCreated = if ($CreatedUtc) { $CreatedUtc } elseif ($FileMeta) { $FileMeta.created_utc } else { $null }
    $effModified = if ($ModifiedUtc) { $ModifiedUtc } elseif ($FileMeta) { $FileMeta.modified_utc } else { $null }
    $artKey = Make-ArtifactKey $ArtifactType $PathOrKey $Name
    $collectedIso = To-UtcIso ([DateTime]::UtcNow)

    # Sorted alphabetical keys for canonical record_sha256
    $canonical = [ordered]@{
        artifact_key        = $artKey
        artifact_type       = $ArtifactType
        attributes          = if ($FileMeta) { $FileMeta.attributes } else { $null }
        collected_utc       = $collectedIso
        command_line        = $CommandLine
        created_utc         = $effCreated
        file_head_histogram = if ($FileMeta) { $FileMeta.file_head_histogram } else { $null }
        file_sha256         = if ($FileMeta) { $FileMeta.file_sha256 } else { $null }
        file_size           = if ($FileMeta) { $FileMeta.file_size } else { $null }
        modified_utc        = $effModified
        name                = $Name
        parent_name         = $ParentName
        path                = $effPath
        pid                 = $PidVal
        ppid                = $PpidVal
        raw                 = $Raw
        registry_key        = $RegistryKey
        registry_value      = $RegistryValue
        service_name        = $ServiceName
        signature_status    = if ($FileMeta) { $FileMeta.signature_status } else { $null }
        signature_subject   = if ($FileMeta) { $FileMeta.signature_subject } else { $null }
        start_mode          = $StartMode
        task_name           = $TaskName
        task_triggers       = $TaskTriggers
    }
    $canonJson = $canonical | ConvertTo-Json -Depth 6 -Compress
    $recHash = Compute-Sha256Hex ($Utf8NoBom.GetBytes($canonJson))
    $canonical["record_sha256"] = $recHash
    [void]$Records.Add($canonical)
}

function Run-Stage([string]$StageName, [scriptblock]$Body) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        & $Body
    } catch {
        [void]$Skipped.Add([ordered]@{
            artifact_type = $StageName
            status = "error"
            reason = $_.Exception.Message
        })
    } finally {
        $sw.Stop()
        $StageTimings[$StageName] = [math]::Round($sw.Elapsed.TotalSeconds, 3)
    }
}

# Create output directory only
[void][System.IO.Directory]::CreateDirectory($OutDir)
$OutDirFull = [System.IO.Path]::GetFullPath($OutDir)

# 1. Scheduled Tasks
Run-Stage "task" {
    Record-CmdClass "Get-ScheduledTask"
    foreach ($t in (Get-ScheduledTask -ErrorAction SilentlyContinue)) {
        $actions = @($t.Actions | Where-Object { $_ -ne $null })
        $cmdParts = @()
        $firstExec = $null
        foreach ($a in $actions) {
            if ($a.PSObject.Properties["Execute"] -and $a.Execute) {
                if ($null -eq $firstExec) { $firstExec = [string]$a.Execute }
                $cmdParts += ("{0} {1}" -f $a.Execute, $a.Arguments).Trim()
            } elseif ($a.PSObject.Properties["ClassId"] -and $a.ClassId) {
                $cmdParts += "COM:$($a.ClassId)"
            }
        }
        $cmdLine = ($cmdParts -join " ; ").Trim()
        $target = if ($firstExec) { Extract-TargetPath $firstExec } else { $null }
        $fmeta = if ($target) { Get-FileMetadata $target } else { $null }
        $trigs = @($t.Triggers | ForEach-Object { if ($_) { $_.CimClass.CimClassName } }) -join ","
        $fullTaskName = "$($t.TaskPath)$($t.TaskName)"
        Add-ArtifactRecord -ArtifactType "task" -PathOrKey $t.TaskPath -Name $t.TaskName `
            -Path $target -CommandLine $cmdLine -TaskName $fullTaskName `
            -TaskTriggers $trigs -FileMeta $fmeta `
            -Raw ([ordered]@{ state = [string]$t.State; user_id = [string]$t.Principal.UserId; run_level = [string]$t.Principal.RunLevel })
    }
}

# 2. Services
Run-Stage "service" {
    Record-CmdClass "Get-CimInstance:Win32_Service"
    foreach ($svc in (Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue)) {
        $target = Extract-TargetPath $svc.PathName
        $fmeta = if ($target) { Get-FileMetadata $target } else { $null }
        $regKey = "HKLM\SYSTEM\CurrentControlSet\Services\$($svc.Name)"
        Add-ArtifactRecord -ArtifactType "service" -PathOrKey $regKey -Name $svc.Name `
            -Path $target -CommandLine $svc.PathName -RegistryKey $regKey `
            -ServiceName $svc.Name -StartMode $svc.StartMode -FileMeta $fmeta `
            -Raw ([ordered]@{ display_name = $svc.DisplayName; state = $svc.State; start_name = $svc.StartName; process_id = $svc.ProcessId })
    }
}

# 3. Run / RunOnce Keys (HKLM + WOW6432Node + all loaded HKU\<SID> hives)
function Collect-RunKeyPath([string]$DisplayKey, [string]$PsPath) {
    Record-CmdClass "Get-Item:Registry"
    $item = Get-Item -LiteralPath $PsPath -ErrorAction SilentlyContinue
    if ($null -eq $item) { return }
    foreach ($valName in $item.GetValueNames()) {
        $val = [string]$item.GetValue($valName, "", [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        $dispName = if ([string]::IsNullOrEmpty($valName)) { "(Default)" } else { $valName }
        $target = Extract-TargetPath $val
        $fmeta = if ($target) { Get-FileMetadata $target } else { $null }
        Add-ArtifactRecord -ArtifactType "run_key" -PathOrKey $DisplayKey -Name $dispName `
            -Path $target -CommandLine $val -RegistryKey $DisplayKey -RegistryValue $val `
            -FileMeta $fmeta -Raw ([ordered]@{ raw_value_name = $valName })
    }
}

Run-Stage "run_key" {
    $hklmPaths = @(
        @{ Display = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; Ps = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" },
        @{ Display = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"; Ps = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" },
        @{ Display = "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"; Ps = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" },
        @{ Display = "HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"; Ps = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce" },
        @{ Display = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"; Ps = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run" }
    )
    foreach ($entry in $hklmPaths) {
        Collect-RunKeyPath $entry.Display $entry.Ps
    }

    Record-CmdClass "Get-ChildItem:HKEY_USERS"
    foreach ($sidKey in (Get-ChildItem -LiteralPath "Registry::HKEY_USERS" -ErrorAction SilentlyContinue)) {
        $sid = $sidKey.PSChildName
        if ($sid -like "*_Classes") { continue }
        foreach ($sub in @(
            "Software\Microsoft\Windows\CurrentVersion\Run",
            "Software\Microsoft\Windows\CurrentVersion\RunOnce",
            "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run"
        )) {
            Collect-RunKeyPath "HKU\$sid\$sub" "Registry::HKEY_USERS\$sid\$sub"
        }
    }
}

# 4. WMI Event Subscriptions (root\subscription)
Run-Stage "wmi_subscription" {
    Record-CmdClass "Get-CimInstance:root\subscription"
    foreach ($flt in (Get-CimInstance -Namespace "root\subscription" -ClassName "__EventFilter" -ErrorAction SilentlyContinue)) {
        Add-ArtifactRecord -ArtifactType "wmi_subscription" -PathOrKey "root\subscription\__EventFilter" -Name $flt.Name `
            -CommandLine $flt.Query -Raw ([ordered]@{ class = "__EventFilter"; query_language = $flt.QueryLanguage; event_namespace = $flt.EventNamespace })
    }
    foreach ($con in (Get-CimInstance -Namespace "root\subscription" -ClassName "CommandLineEventConsumer" -ErrorAction SilentlyContinue)) {
        $cmd = if ($con.CommandLineTemplate) { [string]$con.CommandLineTemplate } else { [string]$con.ExecutablePath }
        $target = Extract-TargetPath $cmd
        $fmeta = if ($target) { Get-FileMetadata $target } else { $null }
        Add-ArtifactRecord -ArtifactType "wmi_subscription" -PathOrKey "root\subscription\CommandLineEventConsumer" -Name $con.Name `
            -Path $target -CommandLine $cmd -FileMeta $fmeta `
            -Raw ([ordered]@{ class = "CommandLineEventConsumer"; executable_path = $con.ExecutablePath; command_line_template = $con.CommandLineTemplate })
    }
    foreach ($scr in (Get-CimInstance -Namespace "root\subscription" -ClassName "ActiveScriptEventConsumer" -ErrorAction SilentlyContinue)) {
        Add-ArtifactRecord -ArtifactType "wmi_subscription" -PathOrKey "root\subscription\ActiveScriptEventConsumer" -Name $scr.Name `
            -CommandLine $scr.ScriptText `
            -Raw ([ordered]@{ class = "ActiveScriptEventConsumer"; scripting_engine = $scr.ScriptingEngine; script_filename = $scr.ScriptFileName })
    }
    foreach ($bnd in (Get-CimInstance -Namespace "root\subscription" -ClassName "__FilterToConsumerBinding" -ErrorAction SilentlyContinue)) {
        $bName = "$($bnd.Filter)->$($bnd.Consumer)"
        Add-ArtifactRecord -ArtifactType "wmi_subscription" -PathOrKey "root\subscription\__FilterToConsumerBinding" -Name $bName `
            -Raw ([ordered]@{ class = "__FilterToConsumerBinding"; filter = [string]$bnd.Filter; consumer = [string]$bnd.Consumer })
    }
}

# 5. UAC Bypass, IFEO, Winlogon, and Defender Policy Registry Keys
Run-Stage "registry" {
    Record-CmdClass "Get-Item:Registry"
    # Per-user UAC bypass keys via HKU\<SID>
    foreach ($sidKey in (Get-ChildItem -LiteralPath "Registry::HKEY_USERS" -ErrorAction SilentlyContinue)) {
        $sid = $sidKey.PSChildName
        if ($sid -like "*_Classes") { continue }
        foreach ($uacSub in @(
            "Software\Classes\ms-settings\shell\open\command",
            "Software\Classes\mscfile\shell\open\command"
        )) {
            $psPath = "Registry::HKEY_USERS\$sid\$uacSub"
            $item = Get-Item -LiteralPath $psPath -ErrorAction SilentlyContinue
            if ($null -eq $item) { continue }
            $dispKey = "HKU\$sid\$uacSub"
            foreach ($vn in $item.GetValueNames()) {
                $val = [string]$item.GetValue($vn, "")
                $dispName = if ([string]::IsNullOrEmpty($vn)) { "(Default)" } else { $vn }
                $target = Extract-TargetPath $val
                $fmeta = if ($target) { Get-FileMetadata $target } else { $null }
                Add-ArtifactRecord -ArtifactType "registry" -PathOrKey $dispKey -Name $dispName `
                    -Path $target -CommandLine $val -RegistryKey $dispKey -RegistryValue $val -FileMeta $fmeta
            }
        }
    }

    # IFEO entries with Debugger / GlobalFlag / SilentProcessExit
    $ifeoRoot = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    foreach ($sub in (Get-ChildItem -LiteralPath $ifeoRoot -ErrorAction SilentlyContinue)) {
        $props = Get-ItemProperty -LiteralPath $sub.PSPath -ErrorAction SilentlyContinue
        if ($null -eq $props) { continue }
        foreach ($interesting in @("Debugger", "GlobalFlag", "VerifierDlls", "MonitorProcess")) {
            if ($props.PSObject.Properties[$interesting]) {
                $val = [string]$props.$interesting
                $dispKey = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\$($sub.PSChildName)"
                $target = Extract-TargetPath $val
                $fmeta = if ($target) { Get-FileMetadata $target } else { $null }
                Add-ArtifactRecord -ArtifactType "registry" -PathOrKey $dispKey -Name $interesting `
                    -Path $target -CommandLine $val -RegistryKey $dispKey -RegistryValue $val -FileMeta $fmeta
            }
        }
    }

    # Winlogon Shell / Userinit
    $wlPs = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    $wl = Get-ItemProperty -LiteralPath $wlPs -ErrorAction SilentlyContinue
    if ($null -ne $wl) {
        foreach ($wn in @("Shell", "Userinit", "Taskman")) {
            if ($wl.PSObject.Properties[$wn]) {
                $val = [string]$wl.$wn
                $dispKey = "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
                $target = Extract-TargetPath $val
                $fmeta = if ($target) { Get-FileMetadata $target } else { $null }
                Add-ArtifactRecord -ArtifactType "registry" -PathOrKey $dispKey -Name $wn `
                    -Path $target -CommandLine $val -RegistryKey $dispKey -RegistryValue $val -FileMeta $fmeta
            }
        }
    }

    # Defender policy & exclusions (read-only)
    foreach ($defSub in @(
        "SOFTWARE\Policies\Microsoft\Windows Defender",
        "SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection",
        "SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths"
    )) {
        $item = Get-Item -LiteralPath "HKLM:\$defSub" -ErrorAction SilentlyContinue
        if ($null -eq $item) { continue }
        foreach ($vn in $item.GetValueNames()) {
            $val = [string]$item.GetValue($vn, "")
            $dispName = if ([string]::IsNullOrEmpty($vn)) { "(Default)" } else { $vn }
            $dispKey = "HKLM\$defSub"
            Add-ArtifactRecord -ArtifactType "registry" -PathOrKey $dispKey -Name $dispName `
                -RegistryKey $dispKey -RegistryValue $val
        }
    }
}

# 6. Startup Folders (All Users + every C:\Users\* profile)
Run-Stage "startup" {
    Record-CmdClass "Get-ChildItem:Startup"
    $startupDirs = [System.Collections.Generic.List[string]]::new()
    [void]$startupDirs.Add("C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup")
    foreach ($uDir in (Get-ChildItem -LiteralPath "C:\Users" -Directory -ErrorAction SilentlyContinue)) {
        if (($uDir.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
        $cand = Join-Path $uDir.FullName "AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"
        if ([System.IO.Directory]::Exists($cand)) { [void]$startupDirs.Add($cand) }
    }

    $wsh = $null
    try {
        $wsh = [System.Activator]::CreateInstance([System.Type]::GetTypeFromProgID("WScript.Shell"))
    } catch { $wsh = $null }

    try {
        foreach ($dir in $startupDirs) {
            if (-not [System.IO.Directory]::Exists($dir)) { continue }
            foreach ($f in (Get-ChildItem -LiteralPath $dir -Force -File -ErrorAction SilentlyContinue)) {
                if ($f.Name -ieq "desktop.ini") { continue }
                $cmd = $null
                $targetPath = $f.FullName
                if ($f.Extension -ieq ".lnk" -and $null -ne $wsh) {
                    try {
                        $sc = $wsh.CreateShortcut($f.FullName)
                        $cmd = ("{0} {1}" -f $sc.TargetPath, $sc.Arguments).Trim()
                        if (-not [string]::IsNullOrWhiteSpace($sc.TargetPath)) {
                            $resolvedTarget = Expand-NormPath $sc.TargetPath
                            if ($resolvedTarget -and [System.IO.File]::Exists($resolvedTarget)) {
                                $targetPath = $resolvedTarget
                            }
                        }
                    } catch {}
                }
                $fmeta = Get-FileMetadata $targetPath
                Add-ArtifactRecord -ArtifactType "startup" -PathOrKey $f.FullName -Name $f.Name `
                    -Path $f.FullName -CommandLine $cmd -FileMeta $fmeta `
                    -CreatedUtc (To-UtcIso $f.CreationTimeUtc) -ModifiedUtc (To-UtcIso $f.LastWriteTimeUtc) `
                    -Raw ([ordered]@{ lnk_target = $targetPath })
            }
        }
    } finally {
        if ($null -ne $wsh) {
            try { [void][System.Runtime.InteropServices.Marshal]::ReleaseComObject($wsh) } catch {}
        }
    }
}

# 7. Prefetch (*.pf)
Run-Stage "prefetch" {
    Record-CmdClass "Get-ChildItem:Prefetch"
    $pfDir = "$env:SystemRoot\Prefetch"
    if ([System.IO.Directory]::Exists($pfDir)) {
        foreach ($f in (Get-ChildItem -LiteralPath $pfDir -Filter "*.pf" -File -ErrorAction SilentlyContinue)) {
            $fmeta = Get-FileMetadata $f.FullName
            Add-ArtifactRecord -ArtifactType "prefetch" -PathOrKey $f.FullName -Name $f.Name `
                -Path $f.FullName -FileMeta $fmeta `
                -CreatedUtc (To-UtcIso $f.CreationTimeUtc) -ModifiedUtc (To-UtcIso $f.LastWriteTimeUtc)
        }
    } else {
        [void]$Skipped.Add([ordered]@{ artifact_type = "prefetch"; status = "skipped"; reason = "directory_missing" })
    }
}

# 8. ShimCache (AppCompatCache)
Run-Stage "shimcache" {
    Record-CmdClass "Get-ItemProperty:AppCompatCache"
    $regKey = "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
    $prop = Get-ItemProperty -LiteralPath "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache" -Name "AppCompatCache" -ErrorAction SilentlyContinue
    if ($null -eq $prop -or $null -eq $prop.AppCompatCache) {
        [void]$Skipped.Add([ordered]@{ artifact_type = "shimcache"; status = "skipped"; reason = "registry_value_missing" })
        return
    }
    [byte[]]$bytes = $prop.AppCompatCache
    $parsedCount = 0
    try {
        if ($bytes.Length -ge 56) {
            $hdrSize = [System.BitConverter]::ToInt32($bytes, 0)
            $pos = $hdrSize
            if ($pos -ge 40 -and $pos + 4 -le $bytes.Length) {
                $sig = [System.Text.Encoding]::ASCII.GetString($bytes, $pos, 4)
                if ($sig -eq "10ts") {
                    while ($pos + 14 -le $bytes.Length -and $parsedCount -lt 2000) {
                        $tag = [System.Text.Encoding]::ASCII.GetString($bytes, $pos, 4)
                        if ($tag -ne "10ts") { break }
                        $entryDataLen = [System.BitConverter]::ToUInt32($bytes, $pos + 8)
                        $pathByteLen = [System.BitConverter]::ToUInt16($bytes, $pos + 12)
                        if ($pos + 14 + $pathByteLen + 8 -gt $bytes.Length) { break }
                        $rawPath = [System.Text.Encoding]::Unicode.GetString($bytes, $pos + 14, $pathByteLen)
                        $ft = [System.BitConverter]::ToInt64($bytes, $pos + 14 + $pathByteLen)
                        $modIso = $null
                        try {
                            if ($ft -gt 0) { $modIso = To-UtcIso ([DateTime]::FromFileTimeUtc($ft)) }
                        } catch {}
                        $normP = Expand-NormPath $rawPath
                        $bName = if ($normP) { [System.IO.Path]::GetFileName($normP) } else { "" }
                        $scKey = if ($normP) { $normP } else { $regKey }
                        Add-ArtifactRecord -ArtifactType "shimcache" -PathOrKey $scKey -Name $bName `
                            -Path $normP -RegistryKey $regKey -ModifiedUtc $modIso `
                            -Raw ([ordered]@{ cache_index = $parsedCount; raw_entry_path = $rawPath })
                        $parsedCount++
                        $step = 12 + [int]$entryDataLen
                        if ($step -le 14) { break }
                        $pos += $step
                    }
                }
            }
        }
    } catch {}
    if ($parsedCount -eq 0) {
        $blobHash = Compute-Sha256Hex $bytes
        Add-ArtifactRecord -ArtifactType "shimcache" -PathOrKey $regKey -Name "AppCompatCache" `
            -RegistryKey $regKey -Raw ([ordered]@{ byte_length = $bytes.Length; sha256 = $blobHash; parser = "raw_blob_fallback" })
    }
}

# 9. Amcache (read-only attempt or existing VSS; never creates a shadow copy)
Run-Stage "amcache" {
    $amPath = "$env:SystemRoot\AppCompat\Programs\Amcache.hve"
    $collectedAm = $false
    if ([System.IO.File]::Exists($amPath)) {
        try {
            $fs = [System.IO.File]::Open($amPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
            $fs.Dispose()
            $fmeta = Get-FileMetadata $amPath
            Add-ArtifactRecord -ArtifactType "amcache" -PathOrKey $amPath -Name "Amcache.hve" -Path $amPath -FileMeta $fmeta
            $collectedAm = $true
        } catch {
            $collectedAm = $false
        }
    }
    if (-not $collectedAm) {
        Record-CmdClass "Get-CimInstance:Win32_ShadowCopy"
        $shadows = @(Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction SilentlyContinue)
        foreach ($sc in $shadows) {
            if ($sc.DeviceObject) {
                $vssPath = "$($sc.DeviceObject)\Windows\AppCompat\Programs\Amcache.hve"
                try {
                    if ([System.IO.File]::Exists($vssPath)) {
                        $fmeta = Get-FileMetadata $vssPath
                        Add-ArtifactRecord -ArtifactType "amcache" -PathOrKey $amPath -Name "Amcache.hve" `
                            -Path $amPath -FileMeta $fmeta -Raw ([ordered]@{ source = "existing_vss"; shadow_id = $sc.ID })
                        $collectedAm = $true
                        break
                    }
                } catch {}
            }
        }
    }
    if (-not $collectedAm) {
        [void]$Skipped.Add([ordered]@{
            artifact_type = "amcache"
            status = "skipped"
            reason = "locked_hive_no_vss"
        })
    }
}

# 10. Running Processes (filtering self PID tree, sshd.exe, and -ExcludePids/-ExcludePaths)
Run-Stage "process" {
    Record-CmdClass "Get-CimInstance:Win32_Process"
    $allProcs = @(Get-CimInstance -ClassName Win32_Process -ErrorAction SilentlyContinue)
    $byPid = @{}
    $children = @{}
    foreach ($p in $allProcs) {
        $byPid[[int]$p.ProcessId] = $p
        $ppid = [int]$p.ParentProcessId
        if (-not $children.ContainsKey($ppid)) {
            $children[$ppid] = [System.Collections.Generic.List[int]]::new()
        }
        [void]$children[$ppid].Add([int]$p.ProcessId)
    }

    $sshdNames = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($sn in @("sshd.exe", "sshd-session.exe", "ssh-agent.exe", "sftp-server.exe")) { [void]$sshdNames.Add($sn) }

    $selfTree = [System.Collections.Generic.HashSet[int]]::new()
    $queue = [System.Collections.Generic.Queue[int]]::new()
    [void]$queue.Enqueue([int]$PID)
    while ($queue.Count -gt 0) {
        $cur = $queue.Dequeue()
        if ($selfTree.Add($cur) -and $children.ContainsKey($cur)) {
            foreach ($ch in $children[$cur]) { [void]$queue.Enqueue($ch) }
        }
    }

    # Exclude intermediate SSH wrapper ancestors when invoked via sshd (e.g. sshd -> cmd.exe -> powershell.exe)
    $ancChain = [System.Collections.Generic.List[int]]::new()
    $ancVisited = [System.Collections.Generic.HashSet[int]]::new()
    [void]$ancVisited.Add([int]$PID)
    $walkPid = if ($byPid.ContainsKey([int]$PID)) { [int]$byPid[[int]$PID].ParentProcessId } else { 0 }
    while ($walkPid -gt 0 -and $byPid.ContainsKey($walkPid) -and $ancVisited.Add($walkPid)) {
        $ancProc = $byPid[$walkPid]
        if ($sshdNames.Contains([string]$ancProc.Name)) {
            foreach ($apid in $ancChain) { [void]$selfTree.Add($apid) }
            break
        }
        [void]$ancChain.Add($walkPid)
        $walkPid = [int]$ancProc.ParentProcessId
    }

    $paramPidSet = [System.Collections.Generic.HashSet[int]]::new()
    foreach ($ep in $ExcludePids) { [void]$paramPidSet.Add([int]$ep) }

    foreach ($p in $allProcs) {
        $procId = [int]$p.ProcessId
        if ($selfTree.Contains($procId)) { $ExcludedCounts.processes_self_tree++; continue }
        if ($sshdNames.Contains([string]$p.Name)) { $ExcludedCounts.processes_sshd++; continue }
        if ($paramPidSet.Contains($procId)) { $ExcludedCounts.processes_param_pid++; continue }
        if ((Is-ExcludedPath $p.ExecutablePath) -or (Is-ExcludedPath $p.CommandLine)) {
            $ExcludedCounts.processes_param_path++
            continue
        }

        $pParentName = $null
        if ($byPid.ContainsKey([int]$p.ParentProcessId)) {
            $pParentName = [string]$byPid[[int]$p.ParentProcessId].Name
        }
        $execPath = Expand-NormPath $p.ExecutablePath
        $fmeta = if ($execPath) { Get-FileMetadata $execPath } else { $null }
        $cmdNorm = if ([string]::IsNullOrWhiteSpace($p.CommandLine)) { "" } else { $p.CommandLine.Trim().ToLowerInvariant() }
        $cmdTag = if ($cmdNorm) { (Compute-Sha256Hex ($Utf8NoBom.GetBytes($cmdNorm))).Substring(0, 8) } else { "nocmd" }
        $keyPath = if ($execPath) { "$execPath#$cmdTag" } else { "$($p.Name)#$cmdTag" }
        Add-ArtifactRecord -ArtifactType "process" -PathOrKey $keyPath -Name $p.Name `
            -Path $execPath -CommandLine $p.CommandLine -ParentName $pParentName `
            -PidVal $procId -PpidVal ([int]$p.ParentProcessId) -FileMeta $fmeta `
            -CreatedUtc (To-UtcIso $p.CreationDate)
    }
}

# 11. Local Accounts
Run-Stage "account" {
    Record-CmdClass "Get-LocalUser"
    $adminMembers = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    try {
        Record-CmdClass "Get-LocalGroupMember"
        foreach ($m in (Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue)) {
            if ($m.Name) { [void]$adminMembers.Add(($m.Name -split '\\')[-1]) }
        }
    } catch {}

    $users = @(Get-LocalUser -ErrorAction SilentlyContinue)
    if ($users.Count -gt 0) {
        foreach ($u in $users) {
            Add-ArtifactRecord -ArtifactType "account" -PathOrKey "local_user\$($u.Name)" -Name $u.Name `
                -Raw ([ordered]@{
                    enabled = [bool]$u.Enabled
                    last_logon_utc = To-UtcIso $u.LastLogon
                    password_required = [bool]$u.PasswordRequired
                    is_admin = $adminMembers.Contains($u.Name)
                    sid = [string]$u.SID
                })
        }
    } else {
        Record-CmdClass "Get-CimInstance:Win32_UserAccount"
        foreach ($u in (Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue)) {
            Add-ArtifactRecord -ArtifactType "account" -PathOrKey "local_user\$($u.Name)" -Name $u.Name `
                -Raw ([ordered]@{ disabled = [bool]$u.Disabled; sid = [string]$u.SID; is_admin = $adminMembers.Contains($u.Name) })
        }
    }
}

# 12. Recent / Executable & Script Files in User-Writable & Temp Directories
Run-Stage "file" {
    Record-CmdClass "Get-ChildItem:UserWritableFiles"
    $targetExts = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($e in @(".exe", ".dll", ".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".hta", ".lnk", ".scr", ".msi")) {
        [void]$targetExts.Add($e)
    }
    $skipDirFragments = @(
        "\programdata\microsoft\windows defender\",
        "\programdata\package cache\",
        "\programdata\ssh\",
        "\appdata\local\packages\",
        "\appdata\local\microsoft\windows\",
        "\code cache\",
        "\gpucache\",
        "\crashpad\"
    )

    $scanRoots = [System.Collections.Generic.List[object]]::new()
    [void]$scanRoots.Add(@{ Path = "$env:SystemRoot\Temp"; MaxDepth = 4 })
    [void]$scanRoots.Add(@{ Path = "C:\Users\Public"; MaxDepth = 5 })
    [void]$scanRoots.Add(@{ Path = "C:\ProgramData"; MaxDepth = 4 })
    foreach ($uDir in (Get-ChildItem -LiteralPath "C:\Users" -Directory -ErrorAction SilentlyContinue)) {
        if (($uDir.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { continue }
        [void]$scanRoots.Add(@{ Path = (Join-Path $uDir.FullName "AppData\Local\Temp"); MaxDepth = 4 })
        [void]$scanRoots.Add(@{ Path = (Join-Path $uDir.FullName "AppData\Roaming"); MaxDepth = 4 })
        [void]$scanRoots.Add(@{ Path = (Join-Path $uDir.FullName "AppData\Local"); MaxDepth = 3 })
    }

    $seenFiles = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $scanState = @{ count = 0 }

    function Walk-Dir([string]$DirPath, [int]$DepthLeft) {
        if ($scanState.count -ge $MaxScannedFiles) { return }
        if (-not [System.IO.Directory]::Exists($DirPath)) { return }
        if (Is-ExcludedPath $DirPath) { return }
        try {
            $di = [System.IO.DirectoryInfo]::new($DirPath)
            if (($di.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { return }
        } catch { return }
        $lowDir = ($DirPath.TrimEnd("\") + "\").ToLowerInvariant()
        foreach ($frag in $skipDirFragments) {
            if ($lowDir.Contains($frag)) { return }
        }
        try {
            foreach ($file in [System.IO.Directory]::EnumerateFiles($DirPath)) {
                if ($scanState.count -ge $MaxScannedFiles) {
                    $ExcludedCounts.files_capped++
                    return
                }
                if (Is-ExcludedPath $file) {
                    $ExcludedCounts.files_excluded_path++
                    continue
                }
                $ext = [System.IO.Path]::GetExtension($file)
                if (-not $targetExts.Contains($ext)) { continue }
                if (-not $seenFiles.Add($file)) { continue }
                $scanState.count++
                $fmeta = Get-FileMetadata $file
                $bName = [System.IO.Path]::GetFileName($file)
                Add-ArtifactRecord -ArtifactType "file" -PathOrKey $file -Name $bName -Path $file -FileMeta $fmeta
            }
            if ($DepthLeft -gt 0) {
                foreach ($sub in [System.IO.Directory]::EnumerateDirectories($DirPath)) {
                    if ($scanState.count -ge $MaxScannedFiles) { return }
                    Walk-Dir $sub ($DepthLeft - 1)
                }
            }
        } catch {}
    }

    foreach ($root in $scanRoots) {
        if ($scanState.count -ge $MaxScannedFiles) { break }
        Walk-Dir $root.Path $root.MaxDepth
    }
    if ($scanState.count -ge $MaxScannedFiles) {
        [void]$Skipped.Add([ordered]@{ artifact_type = "file"; status = "capped"; reason = "max_scanned_files_$MaxScannedFiles" })
    }
}

# Write per-type JSONL files, combined artifacts.json, and manifest.json (UTF-8 no BOM)
$Outputs = [System.Collections.Generic.List[object]]::new()
$ByType = @{}
foreach ($rec in $Records) {
    $t = [string]$rec.artifact_type
    if (-not $ByType.ContainsKey($t)) {
        $ByType[$t] = [System.Collections.Generic.List[object]]::new()
    }
    [void]$ByType[$t].Add($rec)
}

foreach ($t in ($ByType.Keys | Sort-Object)) {
    $fileName = "$t.jsonl"
    $outPath = Join-Path $OutDirFull $fileName
    $sw = [System.IO.StreamWriter]::new($outPath, $false, $Utf8NoBom)
    try {
        foreach ($rec in $ByType[$t]) {
            $sw.WriteLine(($rec | ConvertTo-Json -Depth 6 -Compress))
        }
    } finally {
        $sw.Dispose()
    }
    $bytes = [System.IO.File]::ReadAllBytes($outPath)
    [void]$Outputs.Add([ordered]@{
        file = $fileName
        artifact_type = $t
        row_count = $ByType[$t].Count
        sha256 = (Compute-Sha256Hex $bytes)
    })
}

$ArtifactsJsonPath = Join-Path $OutDirFull "artifacts.json"
$ArtifactsJsonText = ConvertTo-Json -InputObject @($Records.ToArray()) -Depth 6
[System.IO.File]::WriteAllText($ArtifactsJsonPath, $ArtifactsJsonText, $Utf8NoBom)
[void]$Outputs.Add([ordered]@{
    file = "artifacts.json"
    artifact_type = "all"
    row_count = $Records.Count
    sha256 = (Compute-Sha256Hex ([System.IO.File]::ReadAllBytes($ArtifactsJsonPath)))
})

$EndUtc = [DateTime]::UtcNow
$ScriptHash = $null
if ($PSCommandPath -and [System.IO.File]::Exists($PSCommandPath)) {
    $ScriptHash = Compute-Sha256Hex ([System.IO.File]::ReadAllBytes($PSCommandPath))
}

$Manifest = [ordered]@{
    collector_version = $CollectorVersion
    script_sha256 = $ScriptHash
    hostname = $env:COMPUTERNAME
    operator = "$env:USERDOMAIN\$env:USERNAME"
    start_utc = To-UtcIso $StartUtc
    end_utc = To-UtcIso $EndUtc
    elapsed_seconds = [math]::Round(($EndUtc - $StartUtc).TotalSeconds, 3)
    stage_timings_seconds = $StageTimings
    powershell_version = $PSVersionTable.PSVersion.ToString()
    os_version = [System.Environment]::OSVersion.VersionString
    artifact_key_sep = $ArtifactKeySep
    total_records = $Records.Count
    outputs = @($Outputs.ToArray())
    skipped = @($Skipped.ToArray())
    excluded_counts = $ExcludedCounts
    host_changes = @($HostChanges.ToArray())
    command_classes_used = @($CommandClassesUsed | Sort-Object)
}

$ManifestPath = Join-Path $OutDirFull "manifest.json"
[System.IO.File]::WriteAllText($ManifestPath, ($Manifest | ConvertTo-Json -Depth 6), $Utf8NoBom)

Write-Output ("COLLECTOR_DONE records={0} elapsed_s={1} out_dir={2}" -f $Records.Count, $Manifest.elapsed_seconds, $OutDirFull)
