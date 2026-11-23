<#
.SYNOPSIS
    Reports the installed DameWare Mini Remote Control (MRC) version on every machine in machines.txt.

.DESCRIPTION
    For each machine it checks:
      - The Uninstall registry keys (64-bit and 32-bit) for a "Mini Remote Control" entry
      - The file version of the actual service executable (DWRCS.EXE), located via the dwmrcs service
      - The state of the DameWare Mini Remote Control service (dwmrcs)

    Machines are queried in parallel over WinRM (Invoke-Command). If WinRM fails for a machine,
    the script falls back to reading the file version of \\<machine>\admin$\dwrcs\DWRCS.EXE.

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
    .\Get-DamewareVersion.ps1

.EXAMPLE
    .\Get-DamewareVersion.ps1 -ComputerList D:\lists\machines.txt -Credential (Get-Credential)
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
if (-not $OutputCsv)    { $OutputCsv    = Join-Path $scriptDir ("Dameware_Versions_{0:yyyyMMdd_HHmmss}.csv" -f (Get-Date)) }

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

Write-Host "Checking DameWare Mini Remote Control on $($computers.Count) machine(s)..." -ForegroundColor Cyan

# --- Code that runs ON each remote machine -------------------------------------------------------
$scanBlock = {
    $result = [ordered]@{
        DisplayName     = $null
        RegistryVersion = $null
        FileVersion     = $null
        ServiceState    = 'Not found'
        ExePath         = $null
    }

    # 1) Uninstall registry keys (both 64-bit and 32-bit views)
    $uninstallPaths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $entries = Get-ItemProperty -Path $uninstallPaths -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -like '*Mini Remote Control*' }

    if ($entries) {
        $result.DisplayName     = ($entries | ForEach-Object { $_.DisplayName }    | Select-Object -Unique) -join '; '
        $result.RegistryVersion = ($entries | ForEach-Object { $_.DisplayVersion } | Select-Object -Unique) -join '; '
    }

    # 2) The service and its executable
    $svc = Get-CimInstance -ClassName Win32_Service -Filter "Name='dwmrcs'" -ErrorAction SilentlyContinue
    $exe = $null
    if ($svc) {
        $result.ServiceState = "$($svc.State) ($($svc.StartMode))"
        if ($svc.PathName -match '^\s*"?(?<path>[^"]+?\.exe)') { $exe = $Matches['path'] }
    }
    if (-not $exe -or -not (Test-Path -LiteralPath $exe)) {
        $default = Join-Path $env:SystemRoot 'dwrcs\DWRCS.EXE'
        if (Test-Path -LiteralPath $default) { $exe = $default }
    }

    if ($exe -and (Test-Path -LiteralPath $exe)) {
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
        ServiceState    = $r.ServiceState
        DisplayName     = $r.DisplayName
        ExePath         = $r.ExePath
        Method          = 'WinRM'
        Error           = $null
    })
}

# --- Fallback for machines WinRM couldn't reach: read the EXE over the admin$ share --------------
$answered = @($remoteResults | ForEach-Object { $_.PSComputerName.ToUpper() })
$failed   = $computers | Where-Object { $answered -notcontains $_.ToUpper() }

foreach ($c in $failed) {
    Write-Host "  WinRM failed for $c - trying admin share..." -ForegroundColor Yellow
    $unc = "\\$c\admin$\dwrcs\DWRCS.EXE"
    $row = [pscustomobject]@{
        ComputerName    = $c
        Status          = 'Unreachable'
        Version         = $null
        RegistryVersion = $null
        FileVersion     = $null
        ServiceState    = 'Unknown'
        DisplayName     = $null
        ExePath         = $null
        Method          = 'AdminShare'
        Error           = $errorByComputer[$c.ToUpper()]
    }
    try {
        if (Test-Path -LiteralPath "\\$c\admin$" -ErrorAction Stop) {
            if (Test-Path -LiteralPath $unc) {
                $vi = (Get-Item -LiteralPath $unc -ErrorAction Stop).VersionInfo
                $row.FileVersion = '{0}.{1}.{2}.{3}' -f $vi.FileMajorPart, $vi.FileMinorPart, $vi.FileBuildPart, $vi.FilePrivatePart
                $row.Version     = $row.FileVersion
                $row.ExePath     = $unc
                $row.Status      = 'Installed'
            }
            else {
                $row.Status = 'Not installed (default path)'
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
    Select-Object ComputerName, Status, Version, OnNewestVersion, ServiceState, Method |
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
                  ServiceState, DisplayName, ExePath, Method, Error |
    Export-Csv -LiteralPath $OutputCsv -NoTypeInformation -Encoding UTF8

Write-Host "`nFull results saved to: $OutputCsv" -ForegroundColor Cyan
