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

**MITRE ATT&CK Mapping**
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

**KQL Query**
```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count()
    by UserPrincipalName, IPAddress, bin(TimeGenerated, 15m)
| where FailedAttempts >= 5
| sort by FailedAttempts desc
```
**MITRE ATT&CK Mapping**
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

**Hunt 2 – Impossible Travel / Suspicious Login Locations**
Objective

Identify successful authentication events where a single user account logs in from multiple geographic locations within a short time window, which may indicate compromised credentials or session abuse.

Data Source

Microsoft Entra ID Sign-In Logs (SigninLogs)

MITRE ATT&CK Mapping

Tactic: Credential Access

Technique: Valid Accounts (T1078)

Sub-technique: Cloud Accounts (T1078.004)

This technique applies when adversaries use valid cloud credentials obtained through phishing, credential stuffing, or token theft to authenticate from geographically disparate locations.

KQL Query
```kql
SigninLogs
| where ResultType == 0
| summarize
    Locations = make_set(Location),
    IPs = make_set(IPAddress),
    SignInCount = count()
    by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(Locations) > 1
| sort by SignInCount desc
```
Expected Outcome

The query should surface user accounts authenticating successfully from multiple geographic locations within a one-hour window, indicating potential impossible travel or credential misuse.

Observed Result

No results were returned during the analysis period. This is expected due to the lab environment having no active Entra ID users generating sign-in activity at the time of testing.

Notes / Limitations

This hunt was implemented using a design-first SOC approach. Detection logic was validated syntactically and logically and is expected to function correctly once real or test user telemetry is present.
