#Requires -Version 5.1
<#
.SYNOPSIS
    Rotates the service account on a remote server for Audit Service,
    SubmitFormManager and the IIS application pools.

.DESCRIPTION
    1.  Prompts for the target server.
    2.  Stops Audit Service, SubmitFormManager and IIS on the target.
    3.  Pauses until you have the new password.
    4.  Prompts for the service account (DOMAIN\ACCOUNT).
    5.  Prompts for the password (entered twice, hidden).
    6.  Updates the logon account for Audit Service and SubmitFormManager.
    7.  Updates every IIS app pool EXCEPT .NET v4.5, .NET v4.5 Classic and DefaultAppPool.
    8.  Pauses and asks to continue.
    9.  Starts Audit Service, SubmitFormManager and IIS.
    10. Waits 60 seconds, then reports service, IIS, app pool and site health.

.NOTES
    Run from an elevated PowerShell session with an account that is a local
    admin on the target server. PowerShell Remoting (WinRM) must be enabled
    on the target.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
# Services can be given by service Name or Display Name.
$WindowsServices  = @('Audit Service', 'SubmitFormManager')
$ExcludedAppPools = @('.NET v4.5', '.NET v4.5 Classic', 'DefaultAppPool')
$IisServices      = @('W3SVC', 'WAS')
$HealthCheckDelay = 60
$ServiceTimeout   = 120   # seconds to wait for a service to stop/start

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
function Write-Step {
    param([string]$Text)
    Write-Host ''
    Write-Host ('=' * 70) -ForegroundColor Cyan
    Write-Host " $Text" -ForegroundColor Cyan
    Write-Host ('=' * 70) -ForegroundColor Cyan
}

function ConvertTo-PlainText {
    param([System.Security.SecureString]$Secure)
    [System.Net.NetworkCredential]::new('', $Secure).Password
}

$session = $null

try {
    # ------------------------------------------------------------------------
    # STEP 1 - Target server
    # ------------------------------------------------------------------------
    Write-Step 'STEP 1 - Target server'
    do {
        $TargetServer = (Read-Host 'Enter the target server name').Trim()
    } while (-not $TargetServer)

    Write-Host "Connecting to $TargetServer ..."
    $session = New-PSSession -ComputerName $TargetServer
    Write-Host "Connected to $TargetServer." -ForegroundColor Green

    # Define a helper on the remote side that finds a service by Name or Display Name.
    Invoke-Command -Session $session -ScriptBlock {
        function global:Resolve-TargetService {
            param([string]$Identifier)
            $svc = Get-Service -Name $Identifier -ErrorAction SilentlyContinue
            if (-not $svc) { $svc = Get-Service -DisplayName $Identifier -ErrorAction SilentlyContinue }
            if (-not $svc) { throw "Service '$Identifier' was not found on $env:COMPUTERNAME." }
            if (@($svc).Count -gt 1) {
                throw "'$Identifier' matched more than one service: $((@($svc).Name) -join ', ')"
            }
            $svc
        }
    }

    # Confirm all services exist before touching anything.
    Invoke-Command -Session $session -ScriptBlock {
        foreach ($id in ($using:WindowsServices + $using:IisServices)) {
            $null = Resolve-TargetService $id
        }
        Import-Module WebAdministration
    }

    # ------------------------------------------------------------------------
    # STEP 2 - Stop services and IIS
    # ------------------------------------------------------------------------
    Write-Step "STEP 2 - Stopping services and IIS on $TargetServer"
    Invoke-Command -Session $session -ScriptBlock {
        $timeout = [TimeSpan]::FromSeconds($using:ServiceTimeout)
        foreach ($id in $using:WindowsServices) {
            $svc = Resolve-TargetService $id
            if ($svc.Status -ne 'Stopped') {
                Write-Host "Stopping $($svc.DisplayName) [$($svc.Name)] ..."
                Stop-Service -InputObject $svc -Force
                $svc.WaitForStatus('Stopped', $timeout)
            }
            Write-Host "  $($svc.DisplayName): Stopped" -ForegroundColor Green
        }

        Write-Host 'Stopping IIS (iisreset /stop) ...'
        & iisreset.exe /stop | Out-Host
        if ($LASTEXITCODE -ne 0) { throw "iisreset /stop failed with exit code $LASTEXITCODE." }
        Write-Host '  IIS: Stopped' -ForegroundColor Green
    }

    # ------------------------------------------------------------------------
    # STEP 3 - Pause for the new password
    # ------------------------------------------------------------------------
    Write-Host ''
    Write-Host '                                                        ' -BackgroundColor Red
    Write-Host '   STOP! DO NOT PROCEED UNTIL YOU HAVE THE NEW PASSWORD   ' -ForegroundColor White -BackgroundColor Red
    Write-Host '                                                        ' -BackgroundColor Red
    Write-Host ''
    $null = Read-Host 'Press ENTER once you have the new password'

    # ------------------------------------------------------------------------
    # STEP 4 - Service account name
    # ------------------------------------------------------------------------
    Write-Step 'STEP 4 - Service account'
    do {
        $ServiceAccount = (Read-Host 'Enter the service account (DOMAIN\SERVICEACCOUNT)').Trim()
        $validFormat = $ServiceAccount -match '^[^\\\s]+\\[^\\\s]+$'
        if (-not $validFormat) { Write-Warning 'Format must be DOMAIN\SERVICEACCOUNT.' }
    } while (-not $validFormat)

    # ------------------------------------------------------------------------
    # STEP 5 - Service account password (entered twice)
    # ------------------------------------------------------------------------
    Write-Step 'STEP 5 - Service account password'
    do {
        $SecurePassword  = Read-Host "Enter the password for $ServiceAccount" -AsSecureString
        $SecureConfirm   = Read-Host 'Re-enter the password to confirm' -AsSecureString
        $p1 = ConvertTo-PlainText $SecurePassword
        $p2 = ConvertTo-PlainText $SecureConfirm
        $match = ($p1 -ceq $p2) -and ($p1.Length -gt 0)
        if (-not $match) { Write-Warning 'Passwords were empty or did not match. Try again.' }
    } while (-not $match)

    # Optional sanity check against the domain to avoid locking out the account.
    try {
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement
        $domainName, $userName = $ServiceAccount.Split('\', 2)
        $ctx = New-Object System.DirectoryServices.AccountManagement.PrincipalContext('Domain', $domainName)
        if ($ctx.ValidateCredentials($userName, $p1)) {
            Write-Host 'Credentials validated against the domain.' -ForegroundColor Green
        }
        else {
            Write-Warning 'The domain rejected these credentials (wrong password, or the change has not replicated yet).'
            $answer = Read-Host 'Continue anyway? (Y/N)'
            if ($answer -notmatch '^(y|yes)$') { throw 'Aborted by user after failed credential check. Services and IIS are still STOPPED.' }
        }
    }
    catch [System.Management.Automation.RuntimeException] {
        if ($_.Exception.Message -like 'Aborted by user*') { throw }
        Write-Warning "Could not validate credentials against the domain: $($_.Exception.Message)"
    }
    finally {
        $p1 = $null; $p2 = $null; $SecureConfirm = $null
        if ($ctx) { $ctx.Dispose() }
    }

    # ------------------------------------------------------------------------
    # STEP 6 - Update Windows service logon accounts
    # ------------------------------------------------------------------------
    Write-Step 'STEP 6 - Updating service logon accounts'
    Invoke-Command -Session $session -ScriptBlock {
        $account = $using:ServiceAccount
        $plain   = [System.Net.NetworkCredential]::new('', $using:SecurePassword).Password
        try {
            foreach ($id in $using:WindowsServices) {
                $svc = Resolve-TargetService $id
                $cim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($svc.Name)'"
                $r = Invoke-CimMethod -InputObject $cim -MethodName Change -Arguments @{
                    StartName     = $account
                    StartPassword = $plain
                }
                if ($r.ReturnValue -ne 0) {
                    throw "Failed to update '$($svc.DisplayName)'. Win32_Service.Change returned $($r.ReturnValue)."
                }
                Write-Host "  $($svc.DisplayName): logon set to $account" -ForegroundColor Green
            }
        }
        finally { $plain = $null }
    }

    # ------------------------------------------------------------------------
    # STEP 7 - Update IIS application pools
    # ------------------------------------------------------------------------
    Write-Step 'STEP 7 - Updating IIS application pools'
    Invoke-Command -Session $session -ScriptBlock {
        Import-Module WebAdministration
        $account  = $using:ServiceAccount
        $plain    = [System.Net.NetworkCredential]::new('', $using:SecurePassword).Password
        $excluded = $using:ExcludedAppPools
        try {
            foreach ($pool in Get-ChildItem IIS:\AppPools) {
                if ($excluded -contains $pool.Name) {
                    Write-Host "  $($pool.Name): skipped (excluded)" -ForegroundColor DarkGray
                    continue
                }
                Set-ItemProperty -Path "IIS:\AppPools\$($pool.Name)" -Name processModel -Value @{
                    userName     = $account
                    password     = $plain
                    identityType = 3   # SpecificUser
                }
                Write-Host "  $($pool.Name): identity set to $account" -ForegroundColor Green
            }
        }
        finally { $plain = $null }
    }

    $SecurePassword = $null

    # ------------------------------------------------------------------------
    # STEP 8 - Pause / confirm
    # ------------------------------------------------------------------------
    Write-Step 'STEP 8 - Ready to start services'
    $answer = Read-Host 'Credentials updated. Continue and start the services and IIS? (Y/N)'
    if ($answer -notmatch '^(y|yes)$') {
        Write-Warning "Stopping here. Audit Service, SubmitFormManager and IIS are still STOPPED on $TargetServer."
        exit 2
    }

    # ------------------------------------------------------------------------
    # STEP 9 - Start services and IIS
    # ------------------------------------------------------------------------
    Write-Step "STEP 9 - Starting services and IIS on $TargetServer"
    $StartTime = Invoke-Command -Session $session -ScriptBlock { Get-Date }
    Invoke-Command -Session $session -ScriptBlock {
        $timeout = [TimeSpan]::FromSeconds($using:ServiceTimeout)
        foreach ($id in $using:WindowsServices) {
            try {
                $svc = Resolve-TargetService $id
                Write-Host "Starting $($svc.DisplayName) [$($svc.Name)] ..."
                Start-Service -InputObject $svc
                $svc.WaitForStatus('Running', $timeout)
                Write-Host "  $($svc.DisplayName): Running" -ForegroundColor Green
            }
            catch {
                Write-Warning "Failed to start '$id': $($_.Exception.Message)"
            }
        }

        Write-Host 'Starting IIS (iisreset /start) ...'
        & iisreset.exe /start | Out-Host
        if ($LASTEXITCODE -ne 0) { Write-Warning "iisreset /start returned exit code $LASTEXITCODE." }
        else { Write-Host '  IIS: Started' -ForegroundColor Green }
    }

    # ------------------------------------------------------------------------
    # STEP 10 - Wait 60s, then health check
    # ------------------------------------------------------------------------
    Write-Step "STEP 10 - Waiting $HealthCheckDelay seconds before health check"
    for ($i = $HealthCheckDelay; $i -gt 0; $i--) {
        Write-Progress -Activity 'Waiting before health check' -Status "$i seconds remaining" `
            -PercentComplete ((($HealthCheckDelay - $i) / $HealthCheckDelay) * 100)
        Start-Sleep -Seconds 1
    }
    Write-Progress -Activity 'Waiting before health check' -Completed

    $health = Invoke-Command -Session $session -ScriptBlock {
        Import-Module WebAdministration
        $excluded = $using:ExcludedAppPools
        $results  = [System.Collections.Generic.List[object]]::new()

        foreach ($id in ($using:WindowsServices + $using:IisServices)) {
            $svc = Resolve-TargetService $id
            $cim = Get-CimInstance -ClassName Win32_Service -Filter "Name='$($svc.Name)'"
            $results.Add([pscustomobject]@{
                Type     = 'Service'
                Name     = $svc.DisplayName
                State    = [string]$svc.Status
                Identity = $cim.StartName
                Healthy  = ($svc.Status -eq 'Running')
                Note     = ''
            })
        }

        foreach ($pool in Get-ChildItem IIS:\AppPools) {
            $state    = (Get-WebAppPoolState -Name $pool.Name).Value
            $isExcl   = $excluded -contains $pool.Name
            $identity = if ($pool.processModel.identityType -eq 'SpecificUser') { $pool.processModel.userName }
                        else { [string]$pool.processModel.identityType }
            $results.Add([pscustomobject]@{
                Type     = 'AppPool'
                Name     = $pool.Name
                State    = $state
                Identity = $identity
                Healthy  = ($isExcl -or $state -eq 'Started')
                Note     = $(if ($isExcl) { 'Excluded from change' } else { '' })
            })
        }

        foreach ($site in Get-Website) {
            $results.Add([pscustomobject]@{
                Type     = 'Website'
                Name     = $site.Name
                State    = $site.State
                Identity = $site.applicationPool
                Healthy  = ($site.State -eq 'Started')
                Note     = ''
            })
        }

        # Errors since restart from WAS (bad app pool identity) and SCM (service logon failures).
        $events = Get-WinEvent -FilterHashtable @{
            LogName      = 'System'
            ProviderName = 'Microsoft-Windows-WAS', 'Service Control Manager'
            Level        = 1, 2, 3
            StartTime    = $using:StartTime
        } -ErrorAction SilentlyContinue

        [pscustomobject]@{
            Results = $results
            Events  = @($events | Select-Object TimeCreated, Id, ProviderName, Message)
        }
    }

    Write-Host ''
    Write-Host "Health report for $TargetServer" -ForegroundColor Cyan
    $health.Results |
        Select-Object Type, Name, State, Identity, Healthy, Note |
        Format-Table -AutoSize | Out-Host

    if ($health.Events.Count -gt 0) {
        Write-Warning "Warnings/errors logged by WAS or Service Control Manager since restart:"
        $health.Events | Format-List | Out-Host
    }

    $unhealthy = @($health.Results | Where-Object { -not $_.Healthy })
    if ($unhealthy.Count -eq 0) {
        Write-Host 'ALL CHECKS PASSED - services, IIS and app pools are running.' -ForegroundColor Green
    }
    else {
        Write-Host "$($unhealthy.Count) ITEM(S) NOT HEALTHY:" -ForegroundColor Red
        $unhealthy | ForEach-Object { Write-Host "  [$($_.Type)] $($_.Name): $($_.State)" -ForegroundColor Red }
        exit 1
    }
}
catch {
    Write-Host ''
    Write-Host "ERROR: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host 'Check the state of the services and IIS on the target server before re-running.' -ForegroundColor Yellow
    exit 1
}
finally {
    $SecurePassword = $null
    if ($session) { Remove-PSSession $session }
}
