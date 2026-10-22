
# Simulated Failed Logon Detection Test
# Purpose: Validate the alert threshold without
# generating real authentication failures.

$threshold = 5

$testEvents = @(
    1..5 | ForEach-Object {
        [PSCustomObject]@{
            Username  = 'labtestuser'
            SourceIP  = '10.10.10.20'
            SubStatus = '0xC000006A'
        }
    }
)

Write-Host "SIMULATED FAILED LOGON DETECTION TEST" -ForegroundColor Cyan
Write-Host "Test events generated: $($testEvents.Count)"

$alerts = @(
    $testEvents |
        Where-Object { $_.SubStatus -eq '0xC000006A' } |
        Group-Object Username, SourceIP |
        Where-Object { $_.Count -ge $threshold }
)

if ($alerts.Count -gt 0) {
    foreach ($alert in $alerts) {
        Write-Host "ALERT: $($alert.Count) incorrect-password attempts from $($alert.Name)" -ForegroundColor Red
    }
}
else {
    Write-Host "No suspicious login patterns detected."
}

Write-Host "Simulation completed."
