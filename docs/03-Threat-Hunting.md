# Threat Hunting

This section will document threat hunting queries developed in Microsoft Sentinel
to identify suspicious authentication activity, mapped to the MITRE ATT&CK
framework.

At this stage, data ingestion delays were observed due to tenant freshness.
Threat hunting queries will be designed using expected log schema and validated
once telemetry becomes available.

## Hunt 1 – Multiple Failed Sign-In Attempts

**Objective**  
Identify repeated failed authentication attempts that may indicate brute force
or password spraying activity against user accounts.

**Data Source**  
Microsoft Entra ID Sign-In Logs (`SigninLogs`)

**KQL Query**
```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count()
    by UserPrincipalName, IPAddress, bin(TimeGenerated, 15m)
| where FailedAttempts >= 5
| sort by FailedAttempts desc

MITRE ATT&CK Mapping
- TA0006 – Credential Access
- T1110 – Brute Force

Observations
At the time of execution, the query returned no results due to the absence of
ingested sign-in events in the newly created tenant. This was validated and
documented as an expected condition rather than a detection failure.

Expected Outcome
Once authentication telemetry is available, this hunt will surface users or IP
addresses generating multiple failed sign-in attempts within a short time
window, enabling early identification of credential-based attacks.
