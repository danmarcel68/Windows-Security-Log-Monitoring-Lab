
# Windows Security Log Monitoring & Threat Detection
# Script: failed-logon-analyzer.ps1
# Purpose: Summarize Windows failed-logon events (4625)
# Run with administrative privileges on Windows.

param(
    [int]$MaxEvents = 1000
)

Write-Host "========================================"
Write-Host " WINDOWS FAILED LOGON ANALYZER"
Write-Host "========================================"
Write-Host ""

try {
    $events = @(Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id      = 4625
    } -MaxEvents $MaxEvents -ErrorAction Stop)
}
catch {
    Write-Host "Unable to retrieve Event ID 4625." -ForegroundColor Red
    Write-Host $_.Exception.Message
    return
}

$results = foreach ($event in $events) {

    $xml = [xml]$event.ToXml()
    $data = @{}

    foreach ($item in $xml.Event.EventData.Data) {
        $data[$item.Name] = $item.'#text'
    }

    [PSCustomObject]@{
        TimeCreated = $event.TimeCreated
        Username    = $data['TargetUserName']
        SourceIP    = $data['IpAddress']
        Status      = $data['Status']
        SubStatus   = $data['SubStatus']
    }
}

Write-Host "Total failed logons analyzed: $($results.Count)"
Write-Host ""

Write-Host "FAILED LOGON SUMMARY" -ForegroundColor Cyan

$results |
    Group-Object Username, SourceIP, Status, SubStatus |
    Sort-Object Count -Descending |
    Select-Object Count, Name |
    Format-Table -AutoSize

Write-Host "AUTHENTICATION FAILURE CODES" -ForegroundColor Cyan
Write-Host "0xC000006A = Incorrect password"
Write-Host "0xC0000133 = Clock synchronization problem"
Write-Host "0xC0000234 = Account locked out"
Write-Host ""


# Detect repeated incorrect-password attempts
Write-Host "SUSPICIOUS LOGIN DETECTION" -ForegroundColor Yellow

# Define the detection time window
$windowMinutes = 15
$startTime = (Get-Date).AddMinutes(-$windowMinutes)

Write-Host ""
Write-Host "DETECTION CONFIGURATION" -ForegroundColor Cyan
Write-Host "Detection window: Last $windowMinutes minutes"
Write-Host "Window start: $startTime"
Write-Host "Detection rule: Repeated incorrect-password attempts"
Write-Host ""

# Find incorrect-password attempts within the window
$incorrectPasswords = @(
    $results | Where-Object {
        $_.SubStatus -eq '0xC000006A' -and
        $_.TimeCreated -ge $startTime
    }
)

$threshold = 5

$alerts = @(
    $incorrectPasswords |
        Group-Object Username, SourceIP |
        Where-Object { $_.Count -ge $threshold }
)

if ($alerts.Count -gt 0) {
    foreach ($alert in $alerts) {
        Write-Host "ALERT: $($alert.Count) incorrect-password attempts from $($alert.Name)" -ForegroundColor Red
    }
}
else {
    Write-Host "No repeated incorrect-password patterns met the alert threshold."
}

Write-Host "Incorrect-password events: $($incorrectPasswords.Count)"
Write-Host "Alert threshold: $threshold attempts per account/source combination"
Write-Host ""


Write-Host "Analysis completed."
