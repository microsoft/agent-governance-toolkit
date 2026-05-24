---
title: Reporting a Security Vulnerability
last_reviewed: 2026-05-22
owner: agt-maintainers
---

# Reporting a Security Vulnerability

If you believe you have found a security vulnerability in Agent Governance
Toolkit, **do not file a public GitHub issue**. The canonical reporting process
is documented in the repository root file [SECURITY.md](../../SECURITY.md),
which follows the Microsoft Security Response Center (MSRC) flow required for
all Microsoft-owned open-source projects.

In short:

1. Report the vulnerability privately to MSRC at
   [https://msrc.microsoft.com/create-report](https://msrc.microsoft.com/create-report).
2. If you cannot use the portal, email
   [secure@microsoft.com](mailto:secure@microsoft.com), preferably with a
   PGP-encrypted message using the
   [MSRC public PGP key](https://aka.ms/msrcpgpkey).
3. Include the information requested by the
   [reporting template](../../SECURITY.md#security-contact) so MSRC
   can triage the report quickly.

## What to expect

| Stage | Typical timeline |
|-------|------------------|
| Acknowledgement of receipt | Within 24 hours |
| Initial assessment | Within 5 business days |
| Mitigation and coordinated disclosure | Per MSRC policy and CVSS severity |

## Preferred languages

English is preferred for all communications.

## Policy

Microsoft follows the principle of
[Coordinated Vulnerability Disclosure](https://aka.ms/opensource/security/cvd).
The full text of AGT's security policy lives in
[SECURITY.md](../../SECURITY.md) at the repository root so that GitHub picks it
up for the repository's Security tab.
