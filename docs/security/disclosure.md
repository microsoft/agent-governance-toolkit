---
title: Reporting a Security Vulnerability
last_reviewed: 2026-06-05
owner: security-responders
---

# Reporting a Security Vulnerability

If you believe you have found a security vulnerability in Agent Governance
Toolkit, **do not file a public GitHub issue**.

Use the repository's GitHub Security tab to file a private vulnerability report.
The canonical security policy lives in [SECURITY.md](../../SECURITY.md) so that
GitHub can surface it in the repository security UI.

## What to include

- Affected component or package
- Affected version or commit
- Reproduction steps
- Expected and actual behavior
- Potential impact
- Suggested fix or mitigation, if known

## What to expect

Security responders listed in [OWNERS.md](../../OWNERS.md) triage private reports.
The project targets coordinated disclosure within 90 days for confirmed
vulnerabilities, with faster handling for actively exploited issues.

AGT is proposed for AAIF hosting in `aaif/project-proposals#19`; as transfer
finalizes, security response will align with LF/AAIF project policy.
