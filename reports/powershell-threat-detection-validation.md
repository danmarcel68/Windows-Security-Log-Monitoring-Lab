# PowerShell Threat Detection — Validation Report

**Project:** Windows Security Log Monitoring & Threat Detection  
**Case ID:** WIN-SEC-002  
**Environment:** Windows Server 2022 / Active Directory / Windows 11  
**Domain:** corp.itlab.test  
**Validation Date:** October 21, 2026  
**Status:** Completed — Detection logic validated

---

## 1. Executive Summary

This exercise developed and validated a PowerShell-based Windows Security log analyzer to identify failed authentication attempts and detect repeated incorrect-password activity.

The analyzer was tested against real Windows Security Event ID 4625 records collected from the domain controller, ITLAB-DC01.

A separate simulation script was used to validate threshold-based alert generation without creating actual failed login attempts or risking Active Directory account lockouts.

The testing demonstrated successful event parsing, authentication failure classification, event aggregation, and simulated alert generation.

## 2. Lab Environment

| Component | Configuration |
|---|---|
| Domain Controller | ITLAB-DC01 |
| Operating System | Windows Server 2022 |
| Workstation | ITLAB-PC01 |
| Workstation OS | Windows 11 |
| Active Directory Domain | corp.itlab.test |
| Domain Controller IP | 10.10.10.10 |
| Workstation IP | 10.10.10.20 |
| Analysis Tool | Windows PowerShell |
| Log Source | Windows Security Log |
| Monitored Event ID | 4625 — Failed Logon |

## 3. Investigation Objectives

- Retrieve Windows failed-logon events using PowerShell.
- Extract usernames, source IP addresses, and authentication failure codes.
- Aggregate authentication failures by account, source, and status.
- Distinguish incorrect-password failures from time synchronization errors.
- Implement threshold-based suspicious-login detection.
- Validate alert generation using controlled synthetic events.

## 4. PowerShell Scripts Developed

### 4.1 Failed Logon Analyzer

**Filename:** `scripts/failed-logon-analyzer.ps1`

The analyzer retrieves up to 1,000 recent Event ID 4625 records by default.

It extracts authentication details from the event XML and groups matching failures by username, source IP, status, and substatus.

The script also checks whether any account/source combination has at least five incorrect-password events.

### 4.2 Simulated Detection Test

**Filename:** `scripts/test-failed-logon-detection.ps1`

This script creates five synthetic authentication failure records in memory.

Each simulated record contains:

- Username: `labtestuser`
- Source IP: `10.10.10.20`
- Substatus: `0xC000006A`

The script applies the same grouping and threshold criteria used by the analyzer.

No real authentication attempts are performed.

## 5. Real Windows Security Log Analysis

The analyzer successfully processed 40 existing Event ID 4625 records.

| Account | Source IP | Failure code | Count |
|---|---|---|---:|
| ITLAB-PC01$ | 10.10.10.20 | 0xC0000133 | 25 |
| Not populated | 10.10.10.20 | 0xC0000133 | 14 |
| Administrator | 127.0.0.1 | 0xC000006A (substatus) | 1 |
| **Total** | | | **40** |

### Findings

**Clock synchronization failures**

Thirty-nine events reported status `0xC0000133`, indicating clock synchronization problems.

These events were associated with the Windows 11 workstation IP address, `10.10.10.20`.

**Incorrect-password failure**

One event involved the Administrator account and reported substatus `0xC000006A`, indicating an incorrect password.

The recorded source IP was `127.0.0.1`, the loopback address.

The available evidence did not establish malicious activity.

## 6. Detection Rule

The analyzer applies the following detection criteria:

| Rule component | Configuration |
|---|---|
| Event ID | 4625 |
| Failure substatus | 0xC000006A |
| Grouping | Username and source IP |
| Alert threshold | 5 matching events |
| Alert output | PowerShell console |
| Time window | Not implemented |

An alert is generated when at least five matching incorrect-password events are found for the same account/source combination among the retrieved records.

Clock synchronization failures are excluded from the incorrect-password alert count.

## 7. Test Results

### Test 1 — Real Security Log Analysis

**Input:** 40 existing Event ID 4625 records.

**Expected result:** No alert because only one incorrect-password event was identified.

**Observed result:** No suspicious-login alert generated.

**Outcome:** PASS

### Test 2 — Simulated Threshold Detection

**Input:** Five synthetic incorrect-password records for `labtestuser` from `10.10.10.20`.

**Expected result:** One alert indicating five incorrect-password attempts.

**Observed result:**

```text
SIMULATED FAILED LOGON DETECTION TEST
Test events generated: 5
ALERT: 5 incorrect-password attempts from labtestuser, 10.10.10.20
Simulation completed.
```

**Outcome:** PASS

## 8. Active Directory Lockout Policy

The domain password policy was inspected before testing.

| Setting | Value |
|---|---|
| Account lockout threshold | 5 failed attempts |
| Account lockout duration | 30 minutes |
| Observation window | 30 minutes |

Synthetic records were used to avoid deliberately locking real Active Directory accounts.

## 9. Evidence References

Evidence screenshots are stored in the project's `screenshots` directory.

- `16-powershell-failed-logon-query.png`
- `17-powershell-failed-logon-details.png`
- `18-powershell-incorrect-password-analysis.png`
- `19-powershell-failed-logon-summary.png`
- `20-powershell-failed-logon-analyzer-execution.png`
- `21-powershell-suspicious-login-detection.png`
- `22-active-directory-account-lockout-policy.png`
- `23-powershell-simulated-threat-detection-alert.png`

## 10. Limitations

- The analyzer examines up to 1,000 recent Event ID 4625 records by default.
- Detection is based on aggregate counts rather than a defined time window.
- The script does not currently generate email notifications or SIEM alerts.
- It does not automatically correlate Event IDs 4625 and 4740.
- The simulated test validates the threshold logic, not end-to-end detection of live authentication attempts.
- The script has not been validated against every possible Windows authentication event format.

## 11. Future Improvements

- Implement time-window-based detection.
- Add account lockout monitoring using Event ID 4740.
- Export findings to CSV.
- Add severity classifications.
- Introduce automated reporting.
- Expand monitoring to additional Windows Security Event IDs.

## 12. Conclusion

This project demonstrated practical Windows Security log analysis and introductory security detection engineering using PowerShell.

The analyzer successfully processed 40 real authentication failure events and distinguished clock synchronization problems from incorrect-password activity.

A separate synthetic test successfully generated an alert at the configured five-event threshold.

The exercise demonstrates PowerShell scripting, Windows Event Log analysis, authentication monitoring, security event correlation, and controlled detection validation.

**Final validation result: PASS**

---

**Classification:** Security Monitoring / Detection Engineering  
**Testing Method:** Real Security Log Analysis + Synthetic Alert Validation  
**Scope:** Isolated Active Directory Lab