# Lab Architecture

## Overview
This Mini-SOC lab is designed to simulate a small Security Operations Center
using Microsoft Sentinel as the central SIEM platform.

The lab focuses on identity-based telemetry and lightweight endpoint activity
to remain cost-effective and suitable for a home environment.

## Components

### Log Sources
- Azure AD / Entra ID sign-in logs
- Simulated authentication events

### SIEM
- Microsoft Sentinel
- Log Analytics Workspace

### Analysis & Response
- Analytic rules for detection
- Incident investigation within Sentinel
- Threat hunting using KQL
- Manual incident response documentation

## Design Principles
- Cloud-first (no heavy local infrastructure)
- Low cost and free-tier friendly
- Focused on SOC analyst workflows
