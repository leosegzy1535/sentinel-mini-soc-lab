# Cost Control Strategy

## Objectives
Ensure the Mini-SOC lab remains within free-tier or very low-cost Azure usage
while still providing realistic SOC experience.

## Cost Control Measures
- Use Azure free tier where available
- Enable budget alerts immediately after subscription creation
- Start with low-volume data sources (Entra ID sign-in logs)
- Avoid long log retention periods
- No always-on virtual machines
- Remove unused resources promptly

## Monitoring
- Azure Cost Management budgets
- Regular review of Log Analytics ingestion volume

## Risk Mitigation
If unexpected costs are detected:
- Disable data connectors immediately
- Reduce log retention
- Delete unused resources
