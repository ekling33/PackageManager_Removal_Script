<#
.SYNOPSIS
    Pulls logon/logoff activity for a single user from the Windows Security event log.

.DESCRIPTION
    Give it a username (it resolves the SID for you) or a SID directly.
    Collects:
        4624  Logon
        4625  Failed logon
        4634  Logoff
        4647  User-initiated logoff
        4800  Workstation locked
        4801  Workstation unlocked
        4778  RDP session reconnected
        4779  RDP session disconnected

    Must be run from an elevated (Run as Administrator) PowerShell session,
    or with an account that can read the Security log on the target computer.

.EXAMPLE
    .\Get-UserLogonHistory.ps1 -UserName CONTOSO\jdoe

.EXAMPLE
    .\Get-UserLogonHistory.ps1 -UserName jdoe -StartTime (Get-Date).AddDays(-30) -InteractiveOnly -ExportCsv C:\Temp\jdoe_logons.csv

.EXAMPLE
    .\Get-UserLogonHistory.ps1 -Sid S-1-5-21-1111111111-2222222222-3333333333-1105 -ComputerName PC042
#>
[CmdletBinding(DefaultParameterSetName = 'ByName')]
param(
    # Username: "DOMAIN\user", "COMPUTER\user", or just "user"
    [Parameter(Mandatory, ParameterSetName = 'ByName', Position = 0)]
    [string]$UserName,

    # Use this instead of -UserName if you already have the SID
    [Parameter(Mandatory, ParameterSetName = 'BySid')]
    [string]$Sid,

    # Computer whose Security log to read (default: this one)
    [string]$ComputerName = $env:COMPUTERNAME,

    [datetime]$StartTime = (Get-Date).AddDays(-7),
    [datetime]$EndTime   = (Get-Date),

    # Only show interactive/RDP/unlock/cached logons (hides network, service, batch noise)
    [switch]$InteractiveOnly,

    # Optional path to save results as CSV
    [string]$ExportCsv
)

# ---------- Resolve username <-> SID ----------
if ($PSCmdlet.ParameterSetName -eq 'ByName') {
    try {
        $Sid = (New-Object System.Security.Principal.NTAccount($UserName)).
               Translate([System.Security.Principal.SecurityIdentifier]).Value
    }
    catch {
        throw "Could not resolve '$UserName' to a SID. Try DOMAIN\user format, or pass -Sid directly. " +
              "(Local accounts on a remote computer can't be resolved from here; use -Sid.)"
    }
}
else {
    try {
        $UserName = (New-Object System.Security.Principal.SecurityIdentifier($Sid)).
                    Translate([System.Security.Principal.NTAccount]).Value
    }
    catch { $UserName = $null }
}
$shortName = if ($UserName) { $UserName.Split('\')[-1] } else { $null }

Write-Host "User: $(if ($UserName) { $UserName } else { '(unresolved)' })  SID: $Sid" -ForegroundColor Cyan
Write-Host "Computer: $ComputerName   Range: $StartTime -> $EndTime" -ForegroundColor Cyan

# ---------- Build the event log query ----------
$fmt   = 'yyyy-MM-ddTHH:mm:ss.fffZ'
$start = $StartTime.ToUniversalTime().ToString($fmt)
$end   = $EndTime.ToUniversalTime().ToString($fmt)
$time  = "TimeCreated[@SystemTime&gt;='$start' and @SystemTime&lt;='$end']"

# Events that carry the user's SID can be filtered server-side by SID
$selects = @(
    "<Select Path=`"Security`">*[System[(EventID=4624 or EventID=4634 or EventID=4647 or EventID=4800 or EventID=4801) and $time]] and *[EventData[Data[@Name='TargetUserSid']='$Sid']]</Select>"
)
# Failed logons and RDP connect/disconnect only carry the name, so filter those by name below
if ($shortName) {
    $selects += "<Select Path=`"Security`">*[System[(EventID=4625 or EventID=4778 or EventID=4779) and $time]]</Select>"
}

$filterXml = @"
<QueryList>
  <Query Id="0" Path="Security">
    $($selects -join "`n    ")
  </Query>
</QueryList>
"@

# ---------- Lookup tables ----------
$eventNames = @{
    4624 = 'Logon'
    4625 = 'Failed logon'
    4634 = 'Logoff'
    4647 = 'User-initiated logoff'
    4800 = 'Workstation locked'
    4801 = 'Workstation unlocked'
    4778 = 'RDP reconnect'
    4779 = 'RDP disconnect'
}
$logonTypes = @{
    '2'  = 'Interactive (console)'
    '3'  = 'Network'
    '4'  = 'Batch'
    '5'  = 'Service'
    '7'  = 'Unlock'
    '8'  = 'NetworkCleartext'
    '9'  = 'NewCredentials (RunAs)'
    '10' = 'RemoteInteractive (RDP)'
    '11' = 'CachedInteractive'
}
$failReasons = @{
    '0xc0000064' = 'User does not exist'
    '0xc000006a' = 'Wrong password'
    '0xc0000234' = 'Account locked out'
    '0xc0000072' = 'Account disabled'
    '0xc000006f' = 'Outside allowed logon hours'
    '0xc0000070' = 'Workstation restriction'
    '0xc0000071' = 'Password expired'
    '0xc0000193' = 'Account expired'
    '0xc0000224' = 'Must change password'
}

# ---------- Query ----------
try {
    $events = Get-WinEvent -ComputerName $ComputerName -FilterXml $filterXml -ErrorAction Stop
}
catch {
    if ($_.Exception.Message -match 'No events were found') {
        Write-Warning 'No matching events found in that time range.'
        return
    }
    if ($_.Exception -is [System.UnauthorizedAccessException] -or $_.Exception.Message -match 'unauthorized|access is denied') {
        throw 'Access denied reading the Security log. Run PowerShell as Administrator.'
    }
    throw
}

# ---------- Parse ----------
$results = foreach ($e in $events) {
    $xml = [xml]$e.ToXml()
    $d = @{}
    foreach ($n in $xml.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }

    $acct = if ($d.TargetUserName) { $d.TargetUserName } else { $d.AccountName }

    # Name-filtered events: keep only this user (case-insensitive)
    if ($e.Id -in 4625, 4778, 4779 -and $acct -ne $shortName) { continue }

    $lt = $d.LogonType
    if ($InteractiveOnly -and $e.Id -in 4624, 4625, 4634 -and $lt -notin '2', '7', '10', '11') { continue }

    $domain = if ($d.TargetDomainName) { $d.TargetDomainName } else { $d.AccountDomain }
    $src    = @($d.IpAddress, $d.ClientAddress) | Where-Object { $_ -and $_ -ne '-' } | Select-Object -First 1
    $wks    = @($d.WorkstationName, $d.ClientName) | Where-Object { $_ -and $_ -ne '-' } | Select-Object -First 1

    $detail = $null
    if ($e.Id -eq 4625) {
        $code = "$($d.SubStatus)".ToLower()
        if ($code -eq '0x0' -or -not $code) { $code = "$($d.Status)".ToLower() }
        $detail = if ($failReasons[$code]) { $failReasons[$code] } else { $code }
    }

    [pscustomobject]@{
        Time        = $e.TimeCreated
        EventId     = $e.Id
        Action      = $eventNames[$e.Id]
        User        = "$domain\$acct"
        LogonType   = if ($lt) { $logonTypes[$lt] } else { $null }
        SourceIP    = $src
        Workstation = $wks
        LogonId     = if ($d.TargetLogonId) { $d.TargetLogonId } else { $d.LogonID }
        Detail      = $detail
        Computer    = $e.MachineName
    }
}

$results = @($results | Sort-Object Time)

if (-not $results) {
    Write-Warning 'No matching events found after filtering.'
    return
}

Write-Host "Found $($results.Count) events." -ForegroundColor Green
$results | Format-Table Time, Action, LogonType, SourceIP, Workstation, LogonId, Detail -AutoSize

if ($ExportCsv) {
    $results | Export-Csv -Path $ExportCsv -NoTypeInformation
    Write-Host "Saved to $ExportCsv" -ForegroundColor Green
}
