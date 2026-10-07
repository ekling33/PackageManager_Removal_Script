<#
.SYNOPSIS
    Remotely removes Windows Package Manager (winget / App Installer) from many machines.

.DESCRIPTION
    For each target computer:
      1. Removes the provisioned package so new user profiles don't get it.
      2. Removes the installed AppX package(s) for ALL user profiles.
      3. (Optional) Sets the policy that disables App Installer / winget.

    Remove-AppxPackage fails inside a WinRM session with 0x80073D19
    ("a user was logged off"), so the removal itself runs locally on each
    machine as SYSTEM via a temporary scheduled task. WinRM (Invoke-Command)
    is only used to create the task, wait for it, and collect the result.
    Machines are processed in parallel and a CSV report is written.

.PARAMETER ComputerListPath
    Text file with one computer name per line.
    Defaults to machines.txt in the same folder as this script
    (or the current folder if the script folder can't be determined).

.PARAMETER ReportOnly
    Only report what is installed; change nothing.

.PARAMETER DisablePolicy
    Also set HKLM\SOFTWARE\Policies\Microsoft\Windows\AppInstaller\EnableAppInstaller = 0.

.PARAMETER TimeoutSeconds
    How long to wait on each machine for the removal task to finish.

.EXAMPLE
    .\Remove-WindowsPackageManager.ps1 -ReportOnly
.EXAMPLE
    .\Remove-WindowsPackageManager.ps1 -DisablePolicy
#>
[CmdletBinding()]
param(
    [string]$ComputerListPath,

    [switch]$ReportOnly,

    [switch]$DisablePolicy,

    [pscredential]$Credential,

    [int]$ThrottleLimit = 20,

    [int]$TimeoutSeconds = 600,

    [string]$ReportPath = ".\WinGetRemoval_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
)

# Default to machines.txt next to the script; fall back to the current folder
# when $PSScriptRoot is empty (e.g. pasted into the console or run from an unsaved ISE tab).
if (-not $ComputerListPath) {
    $baseDir = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $ComputerListPath = Join-Path $baseDir 'machines.txt'
}

if (-not (Test-Path $ComputerListPath)) { throw "Machine list not found: $ComputerListPath" }

$computers = Get-Content -Path $ComputerListPath |
    ForEach-Object { $_.Trim() } |
    Where-Object { $_ -and -not $_.StartsWith('#') } |
    Sort-Object -Unique

if (-not $computers) { throw "No computer names found in $ComputerListPath" }
Write-Host "Targeting $($computers.Count) computer(s)..." -ForegroundColor Cyan

# This script runs ON each target machine, as SYSTEM, from a scheduled task.
$workerScript = @'
param([switch]$ReportOnly, [switch]$DisablePolicy, [string]$ResultPath)

$names   = @('Microsoft.DesktopAppInstaller', 'Microsoft.Winget.Source')
$actions = New-Object System.Collections.Generic.List[string]
$errors  = New-Object System.Collections.Generic.List[string]

function Get-Installed {
    @(foreach ($n in $names) { Get-AppxPackage -AllUsers -Name $n -ErrorAction SilentlyContinue }) |
        Sort-Object PackageFullName -Unique
}

try {
    $installed   = @(Get-Installed)
    $provisioned = @(Get-AppxProvisionedPackage -Online | Where-Object { $names -contains $_.DisplayName })
    $before      = ($installed | Select-Object -ExpandProperty PackageFullName) -join '; '
    $provBefore  = ($provisioned | Select-Object -ExpandProperty PackageName) -join '; '

    if (-not $ReportOnly) {
        # Stop any running winget / App Installer processes that would block removal
        Get-Process -Name 'winget', 'AppInstaller', 'WindowsPackageManagerServer' -ErrorAction SilentlyContinue |
            Stop-Process -Force -ErrorAction SilentlyContinue

        # Deprovision first so the package isn't re-registered for users
        foreach ($p in $provisioned) {
            try {
                Remove-AppxProvisionedPackage -Online -PackageName $p.PackageName -ErrorAction Stop | Out-Null
                $actions.Add("Deprovisioned $($p.PackageName)")
            } catch { $errors.Add("Deprovision $($p.PackageName): $($_.Exception.Message)") }
        }

        foreach ($pkg in $installed) {
            try {
                Remove-AppxPackage -Package $pkg.PackageFullName -AllUsers -ErrorAction Stop
                $actions.Add("Removed $($pkg.PackageFullName) (all users)")
            } catch {
                # Fall back to removing it one user at a time
                $allUsersError = $_.Exception.Message
                $userFailures  = 0
                foreach ($u in $pkg.PackageUserInformation) {
                    $sid = $u.UserSecurityId.Sid
                    try {
                        Remove-AppxPackage -Package $pkg.PackageFullName -User $sid -ErrorAction Stop
                        $actions.Add("Removed $($pkg.PackageFullName) for $sid")
                    } catch {
                        $userFailures++
                        $errors.Add("Remove $($pkg.PackageFullName) for ${sid}: $($_.Exception.Message)")
                    }
                }
                if ($userFailures -gt 0) {
                    $errors.Add("Remove $($pkg.PackageFullName) -AllUsers: $allUsersError")
                }
            }
        }

        if ($DisablePolicy) {
            try {
                $key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppInstaller'
                if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
                New-ItemProperty -Path $key -Name 'EnableAppInstaller' -Value 0 -PropertyType DWord -Force | Out-Null
                $actions.Add('Policy EnableAppInstaller=0 set')
            } catch { $errors.Add("Policy: $($_.Exception.Message)") }
        }
    }

    $remaining = @(Get-Installed)
    $status = if ($errors.Count) { 'Error' }
              elseif ($ReportOnly) { 'ReportOnly' }
              elseif ($remaining.Count) { 'StillPresent' }
              else { 'Removed' }
} catch {
    $status = 'Error'
    $errors.Add("Unexpected: $($_.Exception.Message)")
    $remaining = @()
}

$result = [pscustomobject]@{
    Status            = $status
    InstalledBefore   = $before
    ProvisionedBefore = $provBefore
    RemainingAfter    = ($remaining | Select-Object -ExpandProperty PackageFullName) -join '; '
    Actions           = $actions -join ' | '
    Errors            = $errors -join ' | '
}

# Write to a temp name, then rename, so the caller never reads a half-written file
$result | ConvertTo-Json | Set-Content -Path "$ResultPath.tmp" -Encoding UTF8
Move-Item -Path "$ResultPath.tmp" -Destination $ResultPath -Force
'@

# This runs over WinRM: it sets up the SYSTEM task, waits for it, and returns the result.
$remoteBlock = {
    param([string]$WorkerScript, [bool]$ReportOnly, [bool]$DisablePolicy, [int]$TimeoutSeconds)

    $taskName   = 'Remove-WinGet-Temp'
    $workDir    = Join-Path $env:SystemRoot 'Temp'
    $workerPath = Join-Path $workDir 'Remove-WinGet-Worker.ps1'
    $resultPath = Join-Path $workDir 'Remove-WinGet-Result.json'

    try {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -Path $resultPath, "$resultPath.tmp" -Force -ErrorAction SilentlyContinue
        Set-Content -Path $workerPath -Value $WorkerScript -Encoding UTF8

        $arguments = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$workerPath`" -ResultPath `"$resultPath`""
        if ($ReportOnly)    { $arguments += ' -ReportOnly' }
        if ($DisablePolicy) { $arguments += ' -DisablePolicy' }

        $action    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $arguments
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings  = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
                        -ExecutionTimeLimit (New-TimeSpan -Seconds $TimeoutSeconds)

        Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
        Start-ScheduledTask -TaskName $taskName

        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        while (-not (Test-Path $resultPath) -and (Get-Date) -lt $deadline) {
            Start-Sleep -Seconds 3
        }

        if (Test-Path $resultPath) {
            Get-Content -Path $resultPath -Raw | ConvertFrom-Json
        } else {
            $lastResult = (Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction SilentlyContinue).LastTaskResult
            [pscustomobject]@{
                Status = 'Error'; InstalledBefore = ''; ProvisionedBefore = ''; RemainingAfter = ''; Actions = ''
                Errors = "Timed out after $TimeoutSeconds s waiting for removal task (LastTaskResult: $lastResult)"
            }
        }
    } catch {
        [pscustomobject]@{
            Status = 'Error'; InstalledBefore = ''; ProvisionedBefore = ''; RemainingAfter = ''; Actions = ''
            Errors = "Task setup: $($_.Exception.Message)"
        }
    } finally {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
        Remove-Item -Path $workerPath, $resultPath, "$resultPath.tmp" -Force -ErrorAction SilentlyContinue
    }
}

$icmParams = @{
    ComputerName  = $computers
    ScriptBlock   = $remoteBlock
    ArgumentList  = $workerScript, [bool]$ReportOnly, [bool]$DisablePolicy, $TimeoutSeconds
    ThrottleLimit = $ThrottleLimit
    ErrorAction   = 'SilentlyContinue'
    ErrorVariable = 'connErrors'
}
if ($Credential) { $icmParams.Credential = $Credential }

$results = @(Invoke-Command @icmParams | ForEach-Object {
    [pscustomobject]@{
        ComputerName      = $_.PSComputerName
        Status            = $_.Status
        InstalledBefore   = $_.InstalledBefore
        ProvisionedBefore = $_.ProvisionedBefore
        RemainingAfter    = $_.RemainingAfter
        Actions           = $_.Actions
        Errors            = $_.Errors
    }
})

# Machines that couldn't be reached over WinRM
foreach ($e in $connErrors) {
    $name = $e.TargetObject
    if (-not $name -and $e.OriginInfo) { $name = $e.OriginInfo.PSComputerName }
    $results += [pscustomobject]@{
        ComputerName = $name; Status = 'Unreachable'; InstalledBefore = ''; ProvisionedBefore = ''
        RemainingAfter = ''; Actions = ''; Errors = $e.Exception.Message
    }
}

$results | Sort-Object ComputerName | Export-Csv -Path $ReportPath -NoTypeInformation
$results | Sort-Object ComputerName | Format-Table ComputerName, Status, Errors -AutoSize -Wrap
$results | Group-Object Status | Format-Table Name, Count -AutoSize
Write-Host "Report saved to $ReportPath" -ForegroundColor Green
