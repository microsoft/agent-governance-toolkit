# NIST RFI Mapping

AGT provides detailed NIST alignment documentation in the compliance section:

| Document | Description |
|----------|-------------|
| [NIST AI RMF 1.0 Alignment](../compliance/nist-ai-rmf-alignment.md) | Full mapping across GOVERN, MAP, MEASURE, and MANAGE functions |
| [NIST RFI 2026-00206 Response](../compliance/nist-rfi-2026-00206.md) | Response to NIST's request for information on AI agent governance |

## Quick Summary

AGT maps to all four NIST AI RMF functions:

- **GOVERN**: Deterministic YAML policy engine, role-based access, audit logging
- **MAP**: Threat modeling (OWASP Agentic Top 10), risk classification per agent
- **MEASURE**: 13,000+ automated tests, SLO monitoring, chaos testing via Agent SRE
- **MANAGE**: Kill switch, rate limiting, cost governance, incident response workflows

For the complete assessment with coverage matrices and gap analysis, see the [NIST AI RMF Alignment](../compliance/nist-ai-rmf-alignment.md) document.
