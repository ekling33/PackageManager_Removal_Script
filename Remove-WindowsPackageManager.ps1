<#
.SYNOPSIS
    Pulls logon/logoff, bad password and lockout activity for a single user
    from the Windows Security event log.

.DESCRIPTION
    Give it a username (it resolves the SID for you) or a SID directly.
    Collects:
        4624  Logon
        4625  Failed logon (includes bad password)        - workstation/server
        4634  Logoff
        4647  User-initiated logoff
        4800  Workstation locked
        4801  Workstation unlocked
        4778  RDP session reconnected
        4779  RDP session disconnected
        4740  Account locked out                          - domain controllers
        4767  Account unlocked                            - domain controllers
        4771  Kerberos pre-auth failed (bad password)     - domain controllers

    Use -Filter to narrow to bad passwords, lockouts, or all failures.

    Must be run from an elevated (Run as Administrator) PowerShell session,
    or with an account that can read the Security log on the target computer(s).

.EXAMPLE
    .\Get-UserLogonHistory.ps1 -UserName CONTOSO\jdoe

.EXAMPLE
    # Bad passwords on the user's PC
    .\Get-UserLogonHistory.ps1 -UserName CONTOSO\jdoe -ComputerName PC042 -Filter BadPassword

.EXAMPLE
    # Lockouts across all domain controllers, last 30 days
    $dcs = (Get-ADDomainController -Filter *).HostName
    .\Get-UserLogonHistory.ps1 -UserName CONTOSO\jdoe -ComputerName $dcs -Filter Lockout -StartTime (Get-Date).AddDays(-30)

.EXAMPLE
    .\Get-UserLogonHistory.ps1 -Sid S-1-5-21-1111111111-2222222222-3333333333-1105 -Filter Failures -ExportCsv C:\Temp\jdoe.csv
#>
[CmdletBinding(DefaultParameterSetName = 'ByName')]
param(
    # Username: "DOMAIN\user", "COMPUTER\user", or just "user"
    [Parameter(Mandatory, ParameterSetName = 'ByName', Position = 0)]
    [string]$UserName,

    # Use this instead of -UserName if you already have the SID
    [Parameter(Mandatory, ParameterSetName = 'BySid')]
    [string]$Sid,

    # One or more computers whose Security log to read (default: this one)
    [string[]]$ComputerName = $env:COMPUTERNAME,

    [datetime]$StartTime = (Get-Date).AddDays(-7),
    [datetime]$EndTime   = (Get-Date),

    # All         = everything (default)
    # BadPassword = wrong-password failures only (4625 0xC000006A, 4771 0x18)
    # Lockout     = lockout events (4740, 4767 unlock, 4625 "account locked out")
    # Failures    = every failed logon plus lockouts
    [ValidateSet('All', 'BadPassword', 'Lockout', 'Failures')]
    [string]$Filter = 'All',

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
Write-Host "Computer(s): $($ComputerName -join ', ')   Range: $StartTime -> $EndTime   Filter: $Filter" -ForegroundColor Cyan

# ---------- Build the event log query ----------
$fmt   = 'yyyy-MM-ddTHH:mm:ss.fffZ'
$start = $StartTime.ToUniversalTime().ToString($fmt)
$end   = $EndTime.ToUniversalTime().ToString($fmt)
$time  = "TimeCreated[@SystemTime&gt;='$start' and @SystemTime&lt;='$end']"

# Which event IDs we need for the chosen filter
$wantSidIds = switch ($Filter) {
    'All'         { 4624, 4634, 4647, 4800, 4801 }
    default       { @() }
}
$wantDcIds = switch ($Filter) {
    'All'         { 4740, 4767, 4771 }
    'BadPassword' { 4771 }
    'Lockout'     { 4740, 4767 }
    'Failures'    { 4740, 4771 }
}
$wantNameIds = switch ($Filter) {
    'All'         { 4625, 4778, 4779 }
    default       { 4625 }
}

function Join-Ids($ids) { ($ids | ForEach-Object { "EventID=$_" }) -join ' or ' }

$selects = @()
# Events that carry the user's SID as TargetUserSid
if ($wantSidIds) {
    $selects += "<Select Path=`"Security`">*[System[($(Join-Ids $wantSidIds)) and $time]] and *[EventData[Data[@Name='TargetUserSid']='$Sid']]</Select>"
}
# Domain controller events that carry the SID as TargetSid
if ($wantDcIds) {
    $selects += "<Select Path=`"Security`">*[System[($(Join-Ids $wantDcIds)) and $time]] and *[EventData[Data[@Name='TargetSid']='$Sid']]</Select>"
}
# Failed logons and RDP events only carry the name reliably, so filter those by name below
if ($shortName -and $wantNameIds) {
    $selects += "<Select Path=`"Security`">*[System[($(Join-Ids $wantNameIds)) and $time]]</Select>"
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
    4740 = 'ACCOUNT LOCKED OUT'
    4767 = 'Account unlocked'
    4771 = 'Kerberos pre-auth failed'
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
# 4625 Status / SubStatus codes
$failReasons = @{
    '0xc0000064' = 'User does not exist'
    '0xc000006a' = 'Bad password'
    '0xc0000234' = 'Account locked out'
    '0xc0000072' = 'Account disabled'
    '0xc000006f' = 'Outside allowed logon hours'
    '0xc0000070' = 'Workstation restriction'
    '0xc0000071' = 'Password expired'
    '0xc0000193' = 'Account expired'
    '0xc0000224' = 'Must change password'
}
# 4771 Kerberos failure codes
$kerbReasons = @{
    '0x18' = 'Bad password'
    '0x12' = 'Account disabled, expired or locked out'
    '0x17' = 'Password expired'
    '0x25' = 'Clock skew too great'
}

# ---------- Query each computer ----------
$events = foreach ($comp in $ComputerName) {
    try {
        Get-WinEvent -ComputerName $comp -FilterXml $filterXml -ErrorAction Stop
    }
    catch {
        if ($_.Exception.Message -match 'No events were found') { continue }
        if ($_.Exception -is [System.UnauthorizedAccessException] -or $_.Exception.Message -match 'unauthorized|access is denied') {
            Write-Warning "${comp}: access denied reading the Security log. Run PowerShell as Administrator."
        }
        else {
            Write-Warning "${comp}: $($_.Exception.Message)"
        }
    }
}

if (-not $events) {
    Write-Warning 'No matching events found in that time range.'
    return
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

    # Work out the failure reason and category
    $detail   = $null
    $category = 'Activity'
    switch ($e.Id) {
        4625 {
            $code = "$($d.SubStatus)".ToLower()
            if ($code -eq '0x0' -or -not $code) { $code = "$($d.Status)".ToLower() }
            $detail = if ($failReasons[$code]) { $failReasons[$code] } else { $code }
            $category = switch ($code) {
                '0xc000006a' { 'BadPassword' }
                '0xc0000234' { 'Lockout' }
                default      { 'Failure' }
            }
        }
        4771 {
            $code = "$($d.Status)".ToLower()
            $detail = if ($kerbReasons[$code]) { $kerbReasons[$code] } else { $code }
            $category = if ($code -eq '0x18') { 'BadPassword' } else { 'Failure' }
        }
        4740 {
            # In 4740, TargetDomainName holds the computer the lockout came from
            $detail = "Locked out by bad attempts from: $($d.TargetDomainName)"
            $category = 'Lockout'
        }
        4767 {
            $detail = "Unlocked by: $($d.SubjectDomainName)\$($d.SubjectUserName)"
            $category = 'Lockout'
        }
    }

    # Apply -Filter
    $keep = switch ($Filter) {
        'All'         { $true }
        'BadPassword' { $category -eq 'BadPassword' }
        'Lockout'     { $category -eq 'Lockout' }
        'Failures'    { $category -in 'BadPassword', 'Lockout', 'Failure' -and $e.Id -ne 4767 }
    }
    if (-not $keep) { continue }

    $domain = switch ($e.Id) {
        4740    { $d.SubjectDomainName }
        4771    { ($UserName -split '\\')[0] }
        default { if ($d.TargetDomainName) { $d.TargetDomainName } else { $d.AccountDomain } }
    }
    $src = @($d.IpAddress, $d.ClientAddress) |
           Where-Object { $_ -and $_ -ne '-' } |
           ForEach-Object { $_ -replace '^::ffff:', '' } |
           Select-Object -First 1
    $wks = if ($e.Id -eq 4740) { $d.TargetDomainName }
           else { @($d.WorkstationName, $d.ClientName) | Where-Object { $_ -and $_ -ne '-' } | Select-Object -First 1 }

    [pscustomobject]@{
        Time        = $e.TimeCreated
        EventId     = $e.Id
        Action      = $eventNames[$e.Id]
        Category    = $category
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

# Quick summary for failure-focused runs
if ($Filter -ne 'All') {
    $results | Group-Object Category | ForEach-Object {
        Write-Host ("  {0,-12} {1}" -f $_.Name, $_.Count) -ForegroundColor Yellow
    }
    $topSources = $results | Where-Object { $_.Workstation -or $_.SourceIP } |
                  Group-Object { if ($_.Workstation) { $_.Workstation } else { $_.SourceIP } } |
                  Sort-Object Count -Descending | Select-Object -First 5
    if ($topSources) {
        Write-Host '  Top sources:' -ForegroundColor Yellow
        $topSources | ForEach-Object { Write-Host ("    {0,-30} {1}" -f $_.Name, $_.Count) -ForegroundColor Yellow }
    }
}

$results | Format-Table Time, Action, Category, LogonType, SourceIP, Workstation, Detail, Computer -AutoSize

if ($ExportCsv) {
    $results | Export-Csv -Path $ExportCsv -NoTypeInformation
    Write-Host "Saved to $ExportCsv" -ForegroundColor Green
}
