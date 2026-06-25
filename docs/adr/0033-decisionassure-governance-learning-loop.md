# ADR 0033: DecisionAssure Governance Learning Loop

- **Status:** Proposed
- **Date:** 2026-06-20
- **Author:** Akhilesh Warik
- **Decision:** Post‑execution capability discovery and ontology evolution loop

## Context

The Agent Governance Toolkit (AGT) currently supports policy enforcement and audit-grade tracing, but it does not provide a mechanism for detecting emergent capabilities from agent traces, nor does it support ontology evolution based on discovered capabilities. As AI agents become more autonomous and multi‑agent systems scale, governance must continuously learn from execution histories.

The DecisionAssure Governance Learning Loop addresses this gap by enabling:

- Discovery of emergent capabilities from execution traces
- Counterfactual verification of discovered capabilities
- Human‑review‑driven ontology evolution
- Historical replay to measure governance coverage improvement

This ADR proposes adding a Governance Learning Loop to AGT as a post‑execution analysis layer.

## Decision

We will add an **optional Governance Learning Loop** to AGT with the following components:

### 1. Emergent Capability Discovery

- Uses unsupervised clustering (DBSCAN + TF‑IDF) to identify recurring action patterns in agent traces
- Extracts minimal action sets that constitute a capability
- Assigns confidence scores based on cluster purity and frequency

### 2. Capability Witness Engine

- Generates cryptographic witnesses for discovered capabilities
- Each witness contains:
  - Required actions (agent + action type)
  - SHA‑256 hash of the canonical action set
  - Counterfactual proof (removing any action breaks the capability)
  - Governance recommendation (DENY / HUMAN_REVIEW / MONITOR / ADMIT)

### 3. Human Review Queue

- Unknown capabilities are routed to a review queue
- Analysts can approve, reject, or defer capabilities
- Approved capabilities are added to the governance ontology
- Each approval is recorded in an append‑only ledger

### 4. Ontology Evolution

- Approved capabilities are added to the evolving ontology
- Historical traces are replayed against the updated ontology
- Governance coverage metrics are recomputed

### 5. Governance Knowledge Accumulation Index (GKAI)

- Quantifies governance learning over time
- Formula: `GKAI = (classified / total discovered) * 100`
- Tracks ontology coverage improvement across versions

## Alternatives Considered

| Alternative | Why Rejected |
|-------------|--------------|
| Manual capability cataloguing | Does not scale; relies on human foresight |
| Rule‑based pattern matching | Cannot discover novel patterns |
| Real‑time capability detection | Inline enforcement would increase latency; different governance layer |
| No ontology evolution | Governance coverage would remain static |

## Consequences

### Positive

- Enables continuous governance improvement
- Detects emergent capabilities before they become incidents
- Provides measurable governance coverage metrics
- Creates audit‑grade evidence of governance learning

### Negative

- Adds computational overhead for offline trace analysis
- Requires human review for unknown capabilities
- May surface false positives requiring analyst triage

### Neutral

- Does not modify existing AGT policy enforcement
- Runs as a separate, opt‑in service

## Security Considerations

| Threat | Mitigation |
|--------|------------|
| Trace injection | Replay validation; cryptographic witnesses |
| Ontology drift | Human‑approved ontology changes only |
| Replay attacks | Deterministic verification; witness hashes |
| DoS via large traces | Configurable limits; batch processing |

## Interaction with Immutable Audit Trail

| Guarantee Class | Reviewer Checks By | Provided by This ADR? |
|-----------------|-------------------|----------------------|
| Detection / what happened | Replaying the trace and verifying the witness | Yes – Governance Learning Loop |
| Enforced at the gate | Checking policy/sandbox/fail‑closed control event or log | Existing AGT structural controls (referenced, not modified) |
| Unreachable by construction | Inspecting constructed reachable surface without replay | No – out of scope for this ADR |

## Privacy and Retention

- **Retention window:** Traces are retained for 90 days by default, configurable per deployment
- **PII handling:** Traces may contain PII; redaction is required before persistence
- **Redaction:** PII fields must be redacted using configurable rules (e.g., email, name, IP)
- **Residency:** Trace storage must comply with local data residency requirements
- **Immutability vs deletion:** Immutable storage is used for audit purposes; deletion requests are handled by marking records as deleted (soft delete) while preserving the audit chain

## Implementation Guidance

- Implement as an offline service (post‑execution, not inline)
- Use a separate database for trace storage and witness records
- Provide a CLI for ad‑hoc capability discovery
- Expose a web UI for the human review queue
- Integrate with AGT's existing audit trail for historical replay

## Status

Proposed – awaiting review and acceptance.

## References

- RFC #2873
- PR #3113 (closed implementation)
- DecisionAssure trace schema
- AGT audit trail guarantees
