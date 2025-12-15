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
