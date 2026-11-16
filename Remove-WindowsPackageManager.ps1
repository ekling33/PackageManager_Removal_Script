<#
.SYNOPSIS
    Extracts the value between "CN=" and the first comma on each line of machines.txt.

.EXAMPLE
    Input line : CN=PC-ACCT-042,OU=Workstations,DC=contoso,DC=com
    Output line: PC-ACCT-042
#>

param(
    [string]$InputFile  = ".\machines.txt",
    [string]$OutputFile = ".\machines_names.txt"
)

if (-not (Test-Path $InputFile)) {
    Write-Error "Input file not found: $InputFile"
    exit 1
}

$results = Get-Content $InputFile | ForEach-Object {
    if ($_ -match 'CN=([^,]+)') {
        $Matches[1].Trim()
    }
    elseif ($_.Trim()) {
        Write-Warning "No CN= found on line: $_"
    }
}

$results | Set-Content $OutputFile
$results

Write-Host "`n$($results.Count) name(s) written to $OutputFile" -ForegroundColor Green
