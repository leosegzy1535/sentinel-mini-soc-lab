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
