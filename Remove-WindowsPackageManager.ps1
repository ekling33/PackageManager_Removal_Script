<#
.SYNOPSIS
    Reports the installed DameWare Remote Support (DRS) version on every machine in machines.txt.

.DESCRIPTION
    For each machine it checks:
      - The Uninstall registry keys (64-bit and 32-bit) for a "DameWare Remote Support" entry
        (Mini Remote Control entries are excluded - DRS often installs MRC alongside it)
      - The file version of the DRS console executable (DNTU.exe), found via the registry
        InstallLocation or the standard install folders

    Machines are queried in parallel over WinRM (Invoke-Command). If WinRM fails for a machine,
    the script falls back to reading the file version over the C$ admin share.

    Win32_Product is deliberately NOT used: querying it triggers an MSI consistency check on every
    machine and is very slow.

.PARAMETER ComputerList
    Path to the text file with one machine name per line. Blank lines and lines starting with # are ignored.
    Default: machines.txt in the same folder as this script.

.PARAMETER OutputCsv
    Where to save the results. Default: a timestamped CSV next to this script.

.PARAMETER ThrottleLimit
    How many machines to query at the same time. Default: 32.

.PARAMETER Credential
    Optional. Credentials to use for WinRM. If omitted, your current (admin) session is used.

.EXAMPLE
    .\Get-DamewareRemoteSupportVersion.ps1

.EXAMPLE
    .\Get-DamewareRemoteSupportVersion.ps1 -ComputerList D:\lists\machines.txt -Credential (Get-Credential)
#>
[CmdletBinding()]
param(
    [string]$ComputerList,
    [string]$OutputCsv,
    [int]$ThrottleLimit = 32,
    [System.Management.Automation.PSCredential]$Credential
)

# Folder the script lives in (falls back to the current folder if the code was pasted into a console)
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
if (-not $ComputerList) { $ComputerList = Join-Path $scriptDir 'machines.txt' }
if (-not $OutputCsv)    { $OutputCsv    = Join-Path $scriptDir ("DamewareRemoteSupport_Versions_{0:yyyyMMdd_HHmmss}.csv" -f (Get-Date)) }

# Install folders checked when the registry doesn't give one (relative to the system drive)
$knownFolders = @(
    'Program Files\SolarWinds\DameWare Remote Support',
    'Program Files (x86)\SolarWinds\DameWare Remote Support',
    'Program Files\DameWare Remote Support',
    'Program Files (x86)\DameWare Remote Support',
    'Program Files\SolarWinds\DameWare Remote Support x64',
    'Program Files\DameWare Development\DameWare NT Utilities',
    'Program Files (x86)\DameWare Development\DameWare NT Utilities'
)
$exeName = 'DNTU.exe'

# --- Load the machine list -----------------------------------------------------------------------
if (-not (Test-Path -LiteralPath $ComputerList)) {
    Write-Error "Machine list not found: $ComputerList"
    return
}

$computers = Get-Content -LiteralPath $ComputerList |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -and -not $_.StartsWith('#') } |
    Sort-Object -Unique

if (-not $computers) {
    Write-Error "No machine names found in $ComputerList"
    return
}

Write-Host "Checking DameWare Remote Support on $($computers.Count) machine(s)..." -ForegroundColor Cyan

# --- Code that runs ON each remote machine -------------------------------------------------------
$scanBlock = {
    param($knownFolders, $exeName)

    $result = [ordered]@{
        DisplayName     = $null
        RegistryVersion = $null
        FileVersion     = $null
        InstallLocation = $null
        ExePath         = $null
    }

    # 1) Uninstall registry keys (both 64-bit and 32-bit views)
    $uninstallPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $entries = Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like '*DameWare Remote Support*' -and $_.DisplayName -notlike '*Mini Remote Control*' }

    if ($entries) {
        $result.DisplayName     = ($entries | ForEach-Object { $_.DisplayName }    | Select-Object -Unique) -join '; '
        $result.RegistryVersion = ($entries | ForEach-Object { $_.DisplayVersion } | Select-Object -Unique) -join '; '
        $result.InstallLocation = ($entries | Where-Object { $_.InstallLocation } | ForEach-Object { $_.InstallLocation } | Select-Object -Unique) -join '; '
    }

    # 2) Find the console executable
    $candidates = @()
    foreach ($e in $entries) {
        if ($e.InstallLocation) { $candidates += (Join-Path $e.InstallLocation $exeName) }
    }
    foreach ($f in $knownFolders) {
        $candidates += (Join-Path $env:SystemDrive (Join-Path $f $exeName))
    }

    $exe = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1

    if ($exe) {
        $vi = (Get-Item -LiteralPath $exe).VersionInfo
        $result.ExePath     = $exe
        $result.FileVersion = '{0}.{1}.{2}.{3}' -f $vi.FileMajorPart, $vi.FileMinorPart, $vi.FileBuildPart, $vi.FilePrivatePart
    }

    [pscustomobject]$result
}

# --- Run it in parallel over WinRM --------------------------------------------------------------
$icmParams = @{
    ComputerName  = $computers
    ScriptBlock   = $scanBlock
    ArgumentList  = @(, $knownFolders) + $exeName
    ThrottleLimit = $ThrottleLimit
    ErrorAction   = 'SilentlyContinue'
    ErrorVariable = 'remoteErrors'
}
if ($Credential) { $icmParams.Credential = $Credential }

$remoteResults = Invoke-Command @icmParams

# Map connection errors back to the machine names
$errorByComputer = @{}
foreach ($err in $remoteErrors) {
    $name = $null
    if ($err.TargetObject -is [string]) { $name = $err.TargetObject }
    elseif ($err.OriginInfo)            { $name = $err.OriginInfo.PSComputerName }
    if ($name) { $errorByComputer[$name.ToUpper()] = ($err.Exception.Message -split "`n")[0].Trim() }
}

$report = New-Object System.Collections.Generic.List[object]

foreach ($r in $remoteResults) {
    $installed = [bool]($r.FileVersion -or $r.RegistryVersion)
    $report.Add([pscustomobject]@{
        ComputerName    = $r.PSComputerName
        Status          = if ($installed) { 'Installed' } else { 'Not installed' }
        Version         = if ($r.FileVersion) { $r.FileVersion } else { $r.RegistryVersion }
        RegistryVersion = $r.RegistryVersion
        FileVersion     = $r.FileVersion
        DisplayName     = $r.DisplayName
        InstallLocation = $r.InstallLocation
        ExePath         = $r.ExePath
        Method          = 'WinRM'
        Error           = $null
    })
}

# --- Fallback for machines WinRM couldn't reach: read the EXE over the C$ share -----------------
$answered = @($remoteResults | ForEach-Object { $_.PSComputerName.ToUpper() })
$failed   = $computers | Where-Object { $answered -notcontains $_.ToUpper() }

foreach ($c in $failed) {
    Write-Host "  WinRM failed for $c - trying admin share..." -ForegroundColor Yellow
    $row = [pscustomobject]@{
        ComputerName    = $c
        Status          = 'Unreachable'
        Version         = $null
        RegistryVersion = $null
        FileVersion     = $null
        DisplayName     = $null
        InstallLocation = $null
        ExePath         = $null
        Method          = 'AdminShare'
        Error           = $errorByComputer[$c.ToUpper()]
    }
    try {
        if (Test-Path -LiteralPath "\\$c\C$" -ErrorAction Stop) {
            $unc = $knownFolders |
                ForEach-Object { "\\$c\C$\$_\$exeName" } |
                Where-Object { Test-Path -LiteralPath $_ } |
                Select-Object -First 1

            if ($unc) {
                $vi = (Get-Item -LiteralPath $unc -ErrorAction Stop).VersionInfo
                $row.FileVersion = '{0}.{1}.{2}.{3}' -f $vi.FileMajorPart, $vi.FileMinorPart, $vi.FileBuildPart, $vi.FilePrivatePart
                $row.Version     = $row.FileVersion
                $row.ExePath     = $unc
                $row.Status      = 'Installed'
            }
            else {
                $row.Status = 'Not installed (default paths)'
            }
            $row.Error = "WinRM failed: $($row.Error)"
        }
    }
    catch {
        $row.Error = "WinRM and admin share both failed. $($row.Error) | $($_.Exception.Message)"
    }
    $report.Add($row)
}

# --- Flag anything not on the newest version found ----------------------------------------------
$parsed = foreach ($row in $report) {
    $v = $null
    if ($row.Version -and [version]::TryParse(($row.Version -split ';')[0].Trim(), [ref]$v)) { $v }
}
$latest = $parsed | Sort-Object -Descending | Select-Object -First 1

foreach ($row in $report) {
    $onLatest = $null
    $v = $null
    if ($latest -and $row.Version -and [version]::TryParse(($row.Version -split ';')[0].Trim(), [ref]$v)) {
        $onLatest = ($v -eq $latest)
    }
    $row | Add-Member -NotePropertyName OnNewestVersion -NotePropertyValue $onLatest
}

$report = $report | Sort-Object ComputerName

# --- Output -------------------------------------------------------------------------------------
$report |
    Select-Object ComputerName, Status, Version, OnNewestVersion, Method |
    Format-Table -AutoSize

Write-Host "Summary by version" -ForegroundColor Cyan
$report |
    Group-Object { if ($_.Version) { $_.Version } else { $_.Status } } |
    Sort-Object Count -Descending |
    Select-Object @{n='Version / Status';e={$_.Name}}, Count |
    Format-Table -AutoSize

if ($latest) {
    $behind = @($report | Where-Object { $_.OnNewestVersion -eq $false })
    $noData = @($report | Where-Object { -not $_.Version })
    Write-Host ("Newest version found: {0}" -f $latest) -ForegroundColor Green
    Write-Host ("Machines on an older version: {0}" -f $behind.Count) -ForegroundColor $(if ($behind.Count) { 'Yellow' } else { 'Green' })
    Write-Host ("Machines not installed / unreachable: {0}" -f $noData.Count) -ForegroundColor $(if ($noData.Count) { 'Yellow' } else { 'Green' })
}

$report |
    Select-Object ComputerName, Status, Version, OnNewestVersion, RegistryVersion, FileVersion,
                  DisplayName, InstallLocation, ExePath, Method, Error |
    Export-Csv -LiteralPath $OutputCsv -NoTypeInformation -Encoding UTF8

Write-Host "`nFull results saved to: $OutputCsv" -ForegroundColor Cyan
