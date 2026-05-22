---
title: Security
last_reviewed: 2026-05-22
owner: agt-maintainers
---

# Security

This is the canonical home for all security documentation in Agent Governance Toolkit.

## Start here

| Topic | Page |
|-------|------|
| How threats are modeled across AGT's trust boundaries | [Threat Model](threat-model.md) |
| Multi-tenant isolation guarantees and operator checklist | [Tenant Isolation](tenant-isolation.md) · [Checklist](tenant-isolation-checklist.md) |
| Trust score calibration methodology and thresholds | [Trust Score Calibration](trust-score-calibration.md) |
| Plugin and dependency scanning that runs on every PR | [Security Scanning](scanning.md) |
| How AGT maps to the OWASP Agentic Top 10 | [OWASP Compliance](owasp-compliance.md) |
| Dated security audit notes (additive contracts, sandbox extensions, etc.) | [Audits](audits/README.md) |
| Reporting a vulnerability | [Disclosure](disclosure.md) |

## Scope

This section covers the **runtime** security posture of AGT: how the policy
engine, identity, sandbox, and audit subsystems defend against the threats
documented in the threat model, and how operators verify that posture in
production.

It does **not** cover:

- Compliance framework mapping (NIST AI RMF, EU AI Act, SOC2, ISO 42001 et al.) —
  see the per-framework pages under `docs/compliance/`, e.g.
  [NIST AI RMF alignment](../compliance/nist-ai-rmf-alignment.md) and
  [SOC2 mapping](../compliance/soc2-mapping.md).
- Release security or supply-chain attestation for shipped artifacts — see the
  release notes under `docs/releases/` and the SBOM workflow at
  `.github/workflows/sbom.yml`.

## Reporting a vulnerability

If you believe you have found a security vulnerability in this repository,
please follow the disclosure process in [disclosure.md](disclosure.md). Do not
file a public GitHub issue.
