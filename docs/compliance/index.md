---
title: Compliance
last_reviewed: 2026-05-26
owner: agt-maintainers
---

# Compliance

This is the canonical home for every compliance and standards mapping in
Agent Governance Toolkit. Each page below documents how AGT capabilities
align with a published framework — these are **internal self-assessments**,
not third-party certifications.

## Start here

Pick the framework that applies to your deployment context.

### Security and risk frameworks

| Framework | Page | Scope |
|-----------|------|-------|
| OWASP Agentic Security Initiative (ASI 2026) — 11 risks | [owasp-agentic-top10-architecture.md](owasp-agentic-top10-architecture.md) | **Canonical ASI coverage page.** Mitigation patterns, code evidence, and honest gap analysis (ASI01–ASI11). |
| OWASP Top 10 for LLM Applications (2025) | [owasp-llm-top10-mapping.md](owasp-llm-top10-mapping.md) | LLM-specific risks (prompt injection, insecure output handling, etc.). |
| OWASP Top 10 for MCP | [mcp-owasp-top10-mapping.md](mcp-owasp-top10-mapping.md) | Model Context Protocol-specific risks. |
| ASI policy-rule mapping | [owasp-asi-policy-mapping.md](owasp-asi-policy-mapping.md) | Cross-reference every rule in the starter policy packs to the ASI risk it mitigates. |
| NSA / CISA MCP Security Guidance | [nsa-mcp-alignment.md](nsa-mcp-alignment.md) | Alignment with the joint US guidance. |

### Regulatory and standards mappings

| Framework | Page |
|-----------|------|
| NIST AI Risk Management Framework (AI RMF 1.0) | [nist-ai-rmf-alignment.md](nist-ai-rmf-alignment.md) |
| NIST RFI 2026-00206 response | [nist-rfi-2026-00206.md](nist-rfi-2026-00206.md) |
| EU AI Act — implementation checklist | [eu-ai-act-checklist.md](eu-ai-act-checklist.md) |
| SOC 2 (Trust Services Criteria) | [soc2-mapping.md](soc2-mapping.md) |
| ISO/IEC 42001 (AI Management System) | [iso-42001-mapping.md](iso-42001-mapping.md) |
| CIS Controls v8.1 | [cis-controls-v81-mapping.md](cis-controls-v81-mapping.md) |
| Cloud Security Alliance — Agentic Trust Framework (ATF) | [atf-conformance-assessment.md](atf-conformance-assessment.md) |

### Operational templates and policies

| Document | Page |
|----------|------|
| Fundamental Rights Impact Assessment template (EU AI Act Art. 27) | [fria-template.md](fria-template.md) |
| General impact assessment template | [impact-assessment-template.md](impact-assessment-template.md) |
| Incident response workflow | [incident-response-workflow.md](incident-response-workflow.md) |
| Post-market monitoring procedure | [post-market-monitoring.md](post-market-monitoring.md) |
| Record retention policy | [record-retention-policy.md](record-retention-policy.md) |
| Data provenance model | [data-provenance-model.md](data-provenance-model.md) |

### Additional mappings (package-local)

These mappings live alongside the `agent-compliance` Python package rather
than under `docs/` because they are referenced from the package source and
tests. They are documented here so the framework matrix is complete.

| Framework | Page |
|-----------|------|
| South Korea AI Framework Act | [`agent-governance-python/agent-compliance/docs/compliance/south-korea-ai-framework-act.md`](https://github.com/microsoft/agent-governance-toolkit/blob/main/agent-governance-python/agent-compliance/docs/compliance/south-korea-ai-framework-act.md) |
| Singapore Model AI Governance Framework (MGF) | [`agent-governance-python/agent-compliance/docs/compliance/singapore-mgf-agentic-ai.md`](https://github.com/microsoft/agent-governance-toolkit/blob/main/agent-governance-python/agent-compliance/docs/compliance/singapore-mgf-agentic-ai.md) |

## Out of scope

This section does **not** cover:

- AGT's runtime security posture (threat model, scanning, tenant isolation) —
  see [`../security/`](../security/index.md).
- Release security and SBOM attestation — see the per-release notes under
  `docs/releases/` and the `.github/workflows/sbom.yml` pipeline.
- Compliance claims for frameworks AGT does **not** map to. Add a page only
  when the repo already documents the mapping somewhere.

## Reporting a compliance gap

If a mapping page documents a control AGT claims to support and you find that
the implementation does not match the claim, please open an issue with the
`compliance` label and reference both the page and the specific control ID.
