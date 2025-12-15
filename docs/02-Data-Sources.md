# Data Sources

## Primary Data Sources

### Azure AD / Entra ID Sign-In Logs
These logs capture authentication activity including:
- Successful and failed sign-ins
- Source IP addresses
- User identities
- Authentication methods

These logs are critical for detecting:
- Brute-force attempts
- Suspicious login locations
- Account misuse

### Simulated Authentication Events
Controlled sign-in activity will be generated to test detection logic,
including:
- Multiple failed login attempts
- Sign-ins from unfamiliar locations
- Unusual login timing

## Data Source Selection Rationale
- Low ingestion volume
- High detection value
- Common in real SOC environments
- Suitable for Microsoft Sentinel free-tier usage
## Ingestion Status and Observations

### Entra ID Sign-In Logs
The Microsoft Entra ID Sign-In Logs connector was configured successfully in
Microsoft Sentinel.

Initial KQL validation using the `SigninLogs` table returned zero events. This
was identified as an expected condition due to tenant freshness and log
ingestion latency commonly observed in newly created Azure environments.

Log ingestion was verified at the table level, and the condition was documented
prior to proceeding with threat hunting and detection design.
