# SOC Investigation Report: Active Directory Account Lockout

**Project:** Windows Security Log Monitoring & Threat Detection  
**Case ID:** WIN-SEC-001  
**Environment:** Windows Server 2022 / Windows 11 / Active Directory  
**Domain:** corp.itlab.test  
**Investigation Date:** October 21, 2026  
**Affected Account:** CORP\sjohnson  
**Status:** Investigation completed — root cause unconfirmed

---

## 1. Executive Summary

An investigation was conducted into an Active Directory account lockout involving the domain user `sjohnson`.

Windows Security Event ID 4740 confirmed that the account was locked out on October 13, 2026, at 2:42:11 AM. The event identified `ITLAB-PC01` as the caller computer.

Analysis of surrounding security events identified a successful administrator-initiated password-reset attempt and a subsequent successful password change by the affected user.

The password change occurred approximately 2 minutes and 42 seconds before the account lockout.

The sequence suggests a possible authentication issue involving outdated credentials. However, no matching failed-authentication events were identified to confirm the root cause.

## 2. Investigation Environment

| Component | Configuration |
|---|---|
| Domain Controller | ITLAB-DC01 |
| Operating System | Windows Server 2022 |
| Workstation | ITLAB-PC01 |
| Workstation OS | Windows 11 |
| Active Directory Domain | corp.itlab.test |
| Domain Controller IP | 10.10.10.10 |
| Workstation IP | 10.10.10.20 |
| Primary Analysis Tool | Windows Event Viewer |
| Log Source | Windows Logs → Security |

## 3. Investigation Objectives

- Identify the affected account and lockout timestamp.
- Examine authentication and password-management events.
- Determine which computer was associated with the lockout.
- Correlate security events chronologically.
- Identify possible causes without making unsupported conclusions.
- Document findings and recommendations.

## 4. Security Event Timeline

| Date and Time | Event ID | Description |
|---|---|---|
| October 13, 2026, 12:49:55 AM | 4724 | Administrator successfully attempted to reset the password for sjohnson |
| October 13, 2026, 2:39:29 AM | 4723 | sjohnson successfully changed their account password |
| October 13, 2026, 2:39:29 AM | 4738 | Account-change event recorded for sjohnson |
| October 13, 2026, 2:42:11 AM | 4740 | sjohnson account locked out; caller computer ITLAB-PC01 |

## 5. Detailed Investigation Findings

### Finding 1 — Administrator Password Reset

**Event ID:** 4724  
**Timestamp:** October 13, 2026, 12:49:55 AM  
**Subject:** CORP\Administrator  
**Target Account:** CORP\sjohnson  
**Audit Result:** Success

Windows recorded a successful password-reset attempt performed by the domain Administrator against the sjohnson account.

This event occurred approximately 1 hour and 49 minutes before the account lockout.

### Finding 2 — User Password Change

**Event ID:** 4723  
**Timestamp:** October 13, 2026, 2:39:29 AM  
**Subject:** CORP\sjohnson  
**Target Account:** CORP\sjohnson  
**Audit Result:** Success

Windows recorded a successful password-change attempt initiated by the affected user.

A related account-change event, Event ID 4738, was recorded at the same timestamp.

### Finding 3 — Account Lockout

**Event ID:** 4740  
**Timestamp:** October 13, 2026, 2:42:11 AM  
**Affected Account:** CORP\sjohnson  
**Caller Computer:** ITLAB-PC01

The domain controller recorded an account lockout approximately 2 minutes and 42 seconds after the successful password-change event.

The caller computer field identified the Windows 11 workstation, ITLAB-PC01.

### Finding 4 — Authentication Log Correlation

The investigation searched for related authentication failures using:

- Event ID 4625 — Failed Logon
- Event ID 4771 — Kerberos Pre-Authentication Failure
- Event ID 4776 — NTLM Credential Validation

No matching records were identified around the account lockout timestamp in the available domain controller Security log.

The absence of matching records limits the ability to establish the precise cause of the lockout.

## 6. Analysis and Possible Root Causes

The observed sequence is consistent with a possible stale-credential scenario.

For example, a workstation, scheduled task, mapped drive, service, or application might continue using a previously stored password after an account password change.

Repeated authentication attempts using outdated credentials could contribute to an account lockout.

**This remains a hypothesis, not a confirmed finding.**

Other possible explanations include manual password-entry errors or authentication activity not captured in the reviewed logs.

## 7. Investigation Limitations

- No matching failed-authentication events were found around the lockout timestamp.
- The affected workstation's historical authentication logs were not examined during this investigation.
- The account lockout policy threshold was not independently verified.
- The exact process or application responsible for the lockout was not identified.
- The available evidence does not establish malicious activity.

## 8. Recommended Remediation and Follow-Up

1. Review the affected workstation's Security logs around the lockout timestamp.
2. Inspect Windows Credential Manager for outdated saved credentials.
3. Review mapped drives, scheduled tasks, and services that authenticate using the affected account.
4. Verify Active Directory account lockout policy settings.
5. Confirm whether the password changes were expected and authorized.
6. Review authentication logging coverage to improve future investigations.
7. Continue monitoring for repeated account lockouts or unusual authentication patterns.

## 9. Evidence References

The following evidence files are available in the project's `screenshots` directory:

- `09-event-4740-account-lockout.png`
- `14-event-4724-sjohnson-password-reset.png`
- `15-event-4723-sjohnson-password-change.png`

Additional Event ID 4738 evidence was examined during the investigation but was not separately saved.

## 10. Conclusion

The investigation confirmed a sequence of password-management activity followed by an Active Directory account lockout.

The affected account was `CORP\sjohnson`, and the lockout event identified `ITLAB-PC01` as the caller computer.

Although the timing suggests a possible stale-credential authentication issue, the available evidence does not establish a definitive root cause.

The case demonstrates practical Windows Security Event analysis, Active Directory account monitoring, event correlation, and evidence-based incident documentation.

---

**Investigation classification:** Authentication / Account Lockout  
**Evidence confidence:** High for recorded events; limited for root-cause attribution  
**Final determination:** Confirmed account lockout — cause undetermined