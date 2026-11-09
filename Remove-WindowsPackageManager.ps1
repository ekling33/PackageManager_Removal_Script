<#
.SYNOPSIS
    Stops one or more Windows services on a remote server.

.DESCRIPTION
    Runs from a management/jump server and stops services on a target server
    using PowerShell Remoting (WinRM). Falls back to sc.exe (RPC/SMB) if WinRM
    is unavailable. Supports -WhatIf so you can preview before stopping anything.

.PARAMETER ComputerName
    Target server name(s) or IP(s).

.PARAMETER ServiceName
    Service names to stop (the short "Name", not the DisplayName). Wildcards allowed with WinRM.

.PARAMETER Credential
    Optional. Credentials for an account with local admin rights on the target.
    If omitted, your current logged-on account is used.

.PARAMETER Disable
    Also set the services' startup type to Disabled so they don't start again on reboot.

.PARAMETER TimeoutSeconds
    How long to wait for each service to reach Stopped. Default 60.

.EXAMPLE
    .\Stop-RemoteServices.ps1 -ComputerName SRV01 -ServiceName Spooler,W3SVC -WhatIf

.EXAMPLE
    .\Stop-RemoteServices.ps1 -ComputerName SRV01 -ServiceName Spooler -Credential (Get-Credential)

.EXAMPLE
    .\Stop-RemoteServices.ps1 -ComputerName SRV01,SRV02 -ServiceName "MyApp*" -Disable
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    # Optional. If you don't pass it, the script asks you for the target hostname.
    [string[]]$ComputerName,

    # Defaults to the three services you asked for. Override by passing -ServiceName.
    # Note: "IIS" = W3SVC (World Wide Web Publishing Service); -Force also stops WAS,
    # which W3SVC depends on. Add 'WAS' explicitly if you want it disabled too.
    [string[]]$ServiceName = @('AuditService', 'SubmitFormManager', 'W3SVC'),

    [System.Management.Automation.PSCredential]$Credential,

    [switch]$Disable,

    [int]$TimeoutSeconds = 60
)

# --- Prompt for the target if none was supplied -----------------------------
if (-not $ComputerName) {
    $answer = Read-Host "Enter the target hostname (separate multiple with commas)"
    $ComputerName = $answer -split '\s*,\s*' | Where-Object { $_ -ne '' }
    if (-not $ComputerName) {
        Write-Error "No hostname entered. Exiting."
        return
    }
}

$results = foreach ($computer in $ComputerName) {

    Write-Host "`n=== $computer ===" -ForegroundColor Cyan

    # --- Connectivity check -------------------------------------------------
    if (-not (Test-Connection -ComputerName $computer -Count 1 -Quiet)) {
        Write-Warning "$computer did not respond to ping (may just be blocked by firewall). Continuing..."
    }

    $useWinRM = $true
    try {
        $wsmanArgs = @{ ComputerName = $computer; ErrorAction = 'Stop' }
        if ($Credential) { $wsmanArgs.Credential = $Credential; $wsmanArgs.Authentication = 'Default' }
        Test-WSMan @wsmanArgs | Out-Null
    }
    catch {
        Write-Warning "WinRM not reachable on $computer. Falling back to sc.exe."
        $useWinRM = $false
    }

    # --- Method 1: PowerShell Remoting (preferred) --------------------------
    if ($useWinRM) {

        if (-not $PSCmdlet.ShouldProcess($computer, "Stop services: $($ServiceName -join ', ')")) { continue }

        $icmArgs = @{
            ComputerName = $computer
            ArgumentList = @($ServiceName, [bool]$Disable, $TimeoutSeconds)
            ErrorAction  = 'Stop'
        }
        if ($Credential) { $icmArgs.Credential = $Credential }

        try {
            Invoke-Command @icmArgs -ScriptBlock {
                param($Names, $DoDisable, $Timeout)

                $services = Get-Service -Name $Names -ErrorAction SilentlyContinue
                $missing  = $Names | Where-Object { $_ -notmatch '[\*\?]' -and -not (Get-Service -Name $_ -ErrorAction SilentlyContinue) }

                foreach ($m in $missing) {
                    [pscustomobject]@{ Service = $m; Before = 'NotFound'; After = 'NotFound'; Result = 'Service not found' }
                }

                foreach ($svc in $services) {
                    $before = $svc.Status
                    $result = 'OK'
                    try {
                        if ($svc.Status -ne 'Stopped') {
                            # -Force also stops services that depend on this one
                            Stop-Service -InputObject $svc -Force -ErrorAction Stop
                            $svc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds($Timeout))
                        }
                        else { $result = 'Already stopped' }

                        if ($DoDisable) {
                            Set-Service -Name $svc.Name -StartupType Disabled -ErrorAction Stop
                            $result += ' (disabled)'
                        }
                    }
                    catch [System.ServiceProcess.TimeoutException] {
                        $result = "Timed out after $Timeout s - still $((Get-Service $svc.Name).Status)"
                    }
                    catch {
                        $result = "FAILED: $($_.Exception.Message)"
                    }
                    $svc.Refresh()
                    [pscustomobject]@{ Service = $svc.Name; Before = $before; After = $svc.Status; Result = $result }
                }
            } | Select-Object @{n='Computer';e={$_.PSComputerName}}, Service, Before, After, Result
        }
        catch {
            Write-Error "Remoting to $computer failed: $($_.Exception.Message)"
        }
    }

    # --- Method 2: sc.exe fallback (no WinRM needed, uses RPC/SMB) ----------
    else {
        if ($Credential) {
            Write-Warning "sc.exe can't take -Credential directly. Mapping IPC$ with the supplied credentials first."
            $user = $Credential.UserName
            $pass = $Credential.GetNetworkCredential().Password
            net use "\\$computer\IPC$" /user:$user $pass | Out-Null
        }

        foreach ($name in $ServiceName) {
            if (-not $PSCmdlet.ShouldProcess("$computer\$name", 'Stop service (sc.exe)')) { continue }

            $out = sc.exe "\\$computer" stop $name 2>&1
            $result = if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq 1062) { 'Stop requested' } else { "FAILED (code $LASTEXITCODE): $($out -join ' ')" }

            # Poll until stopped or timeout
            $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
            do {
                Start-Sleep -Seconds 2
                $state = (sc.exe "\\$computer" query $name | Select-String 'STATE') -replace '.*:\s+\d+\s+', ''
            } while ($state -notmatch 'STOPPED' -and (Get-Date) -lt $deadline)

            if ($Disable -and $state -match 'STOPPED') {
                sc.exe "\\$computer" config $name start= disabled | Out-Null
                $result += ' (disabled)'
            }

            [pscustomobject]@{ Computer = $computer; Service = $name; Before = '?'; After = $state.Trim(); Result = $result }
        }

        if ($Credential) { net use "\\$computer\IPC$" /delete /y | Out-Null }
    }
}

$results | Format-Table -AutoSize
