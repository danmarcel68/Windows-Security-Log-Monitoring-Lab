
# Windows Security Log Monitoring & Threat Detection
# Script: account-lockout-monitor.ps1
# Purpose: Analyze Active Directory account lockouts (Event ID 4740)
# Run on a domain controller with administrative privileges.

param(
    [int]$MaxEvents = 100,
    [int]$WindowHours = 24
)

Write-Host "========================================"
Write-Host " ACTIVE DIRECTORY ACCOUNT LOCKOUT MONITOR"
Write-Host "========================================"
Write-Host ""

try {
    $events = @(Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id      = 4740
    } -MaxEvents $MaxEvents -ErrorAction Stop)
}
catch {
    if ($_.FullyQualifiedErrorId -like '*NoMatchingEventsFound*') {
        Write-Host "No account lockout events found."
    }
    else {
        Write-Host "Unable to retrieve account lockout events." -ForegroundColor Red
        Write-Host $_.Exception.Message
    }
    return
}

$results = foreach ($event in $events) {
    $xml = [xml]$event.ToXml()
    $data = @{}

    foreach ($item in $xml.Event.EventData.Data) {
        $data[$item.Name] = $item.'#text'
    }

    [PSCustomObject]@{
    TimeCreated    = $event.TimeCreated
    LockedAccount  = $data['TargetUserName']
    SubjectDomain  = $data['SubjectDomainName']
    CallerComputer = $data['TargetDomainName']
    }
}

$results = @($results)

Write-Host "Total lockout events analyzed: $($results.Count)"
Write-Host ""

Write-Host "ACCOUNT LOCKOUT DETAILS" -ForegroundColor Cyan

$results |
    Format-Table TimeCreated, LockedAccount, SubjectDomain, CallerComputer -AutoSize

Write-Host ""
Write-Host "LOCKOUT SUMMARY BY ACCOUNT" -ForegroundColor Cyan

$results |
    Group-Object LockedAccount |
    Sort-Object Count -Descending |
    Select-Object Count, Name |
    Format-Table -AutoSize

# Identify account lockouts within the monitoring window
$startTime = (Get-Date).AddHours(-$WindowHours)

$recentLockouts = @(
    $results | Where-Object {
        $_.TimeCreated -ge $startTime
    }
)

Write-Host ""
Write-Host "RECENT ACCOUNT LOCKOUT MONITORING" -ForegroundColor Cyan
Write-Host "Monitoring window: Last $WindowHours hours"
Write-Host "Window start: $startTime"
Write-Host "Recent lockout events: $($recentLockouts.Count)"

if ($recentLockouts.Count -gt 0) {
    $recentLockouts |
        Format-Table TimeCreated, LockedAccount, CallerComputer -AutoSize
}
else {
    Write-Host "No account lockouts found within the monitoring window."
}


# Export account lockout results to CSV
$exportFolder = "C:\SecurityLab\Exports"
$exportFile = Join-Path $exportFolder "account-lockout-report.csv"

try {
    if (-not (Test-Path $exportFolder)) {
        New-Item -Path $exportFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    $results |
        Export-Csv -Path $exportFile -NoTypeInformation -ErrorAction Stop

    Write-Host ""
    Write-Host "CSV EXPORT" -ForegroundColor Cyan
    Write-Host "Export completed successfully."
    Write-Host "Report location: $exportFile"
}
catch {
    Write-Host "CSV export failed: $($_.Exception.Message)" -ForegroundColor Red
}

Write-Host "Analysis completed."
