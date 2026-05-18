# ADR-0022: Compliance Framework Auto-Mapping

## Status

Accepted

## Context

Production deployments must demonstrate compliance with regulatory frameworks
(EU AI Act, SOC 2, HIPAA, GDPR). Two approaches were considered:

1. **Manual compliance tracking** -- operators manually map agent actions to
   controls and collect evidence. Error-prone and doesn't scale.

2. **Automatic mapping** -- the system maps each action type to applicable
   controls at runtime, auto-generates evidence where possible, and flags
   gaps requiring manual evidence.

## Decision

We implemented `ComplianceEngine` with automatic action-to-control mapping:

- `ComplianceFramework` enum: `EU_AI_ACT`, `SOC2`, `HIPAA`, `GDPR`
- `ComplianceMapping` links action types to control IDs with evidence metadata
- `ComplianceReport` aggregates findings with severity levels (`critical`, `high`, `medium`, `low`)
- Evidence is split into `evidence_generated` (automatic) and `evidence_required` (manual)

Action types mapped include:
- `agent_registration` -- identity and access controls
- `data_access` -- privacy and data protection controls
- `automated_decision` -- transparency and explainability controls
- `supply_chain_audit` -- third-party risk controls

The engine produces `ComplianceViolation` records when required controls lack
evidence, with severity based on the control's criticality.

## Consequences

- Compliance posture is continuously assessed, not just at audit time
- New frameworks can be added by extending the enum and adding control mappings
- Auto-generated evidence reduces manual burden significantly
- Gaps are surfaced as violations with actionable severity ratings
- Framework-specific language (article numbers, control IDs) is preserved

## References

- `agent-governance-python/agent-mesh/src/agentmesh/governance/compliance.py`
- `docs/specs/AUDIT-COMPLIANCE-1.0.md` Section 16
- `docs/compliance/` (SOC2, EU AI Act, ISO 42001 guides)
- PR #2119 (score compliance against per-framework control count)
