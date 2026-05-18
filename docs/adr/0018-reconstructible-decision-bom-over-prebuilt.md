# ADR-0018: Reconstructible Decision BOM Over Pre-built

## Status

Accepted

## Context

Governance decisions involve multiple factors: policy evaluations, trust scores,
active policies at decision time, and distributed trace context. Two approaches
were considered for the Decision Bill of Materials (BOM):

1. **Pre-built BOM**: Capture all factors at decision time and store as a single
   document alongside the decision. Complete but invasive -- requires every
   action pipeline stage to report into the BOM builder.

2. **Reconstructible BOM**: Query existing observability signals (audit logs,
   trust scores, policy evaluations, OTel traces) after the fact to reconstruct
   the decision context on demand.

## Decision

We chose the reconstructible approach. The `DecisionBOMBuilder` queries four
protocol-based signal sources:

- `AuditSource` -- audit log entries by trace_id or agent_id + time range
- `TrustSource` -- trust score at a point in time, score history
- `PolicySource` -- policy evaluation results, active policies at timestamp
- `TraceSource` -- OTel spans for the decision's trace

Design principles:
- **Non-invasive**: no agent reporting required, no coupling to action pipeline
- **Protocol-based**: each source is a `runtime_checkable Protocol`
- **Completeness levels**: BOM reports how complete the reconstruction is
  (all sources available vs. partial)
- **Python-first implementation**

## Consequences

- Slower than pre-built (requires queries at reconstruction time) but complete
- Zero overhead on the hot path -- no BOM assembly during governance decisions
- Sources can be swapped (in-memory for tests, real backends for production)
- Partial reconstruction is explicitly surfaced rather than silently incomplete
- Agents never need to "cooperate" with BOM building -- fully passive

## References

- `agent-governance-python/agent-mesh/src/agentmesh/governance/decision_bom.py`
- `docs/specs/AUDIT-COMPLIANCE-1.0.md` Section 17
- `docs/tutorials/50-decision-bom.md`
- PR #1777, PR #1786
