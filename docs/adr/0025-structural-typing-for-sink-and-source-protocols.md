# ADR-0025: Structural Typing for Sink and Source Protocols

## Status

Accepted

## Context

AGT's audit and event systems define extension points where external packages
provide implementations (event sinks, audit sources, trust sources, policy
sources). Two approaches for the interface contract:

1. **Abstract base classes (ABCs)** -- external packages must import and inherit
   from AGT classes, creating a hard dependency on agent-os.

2. **Protocol classes (structural typing)** -- external packages implement the
   required methods without importing anything from AGT. Compatibility is
   verified at runtime via `isinstance()` checks with `runtime_checkable`.

## Decision

We use `typing.Protocol` with `@runtime_checkable` for all extension point
interfaces:

- `GovernanceEventSink` -- `emit(events: Sequence[GovernanceEvent]) -> SinkExportResult`
- `AuditBackend` -- `write(entry: AuditEntry) -> None`, `flush() -> None`
- `AuditSource` -- `query_by_trace(trace_id)`, `query_by_agent(agent_id, start, end)`
- `TrustSource` -- `get_score_at(agent_id, timestamp)`, `get_score_history(...)`
- `PolicySource` -- `get_evaluations(trace_id)`, `get_active_policies_at(timestamp)`
- `TraceSource` -- `get_spans(trace_id)`, `get_span_tree(trace_id)`

All are decorated with `@runtime_checkable` so `isinstance()` works for
validation without requiring inheritance.

## Consequences

- External sink/source packages have zero dependency on agent-os
- Any object with the right method signatures satisfies the protocol
- `isinstance()` checks work at runtime for validation
- IDE type checking catches protocol mismatches at development time
- Slightly weaker guarantees than ABCs (no enforcement of method implementation
  at class definition time -- only at call time or explicit isinstance check)
- Consistent pattern across all AGT extension points

## References

- `agent-governance-python/agent-os/src/agent_os/event_sink.py` (GovernanceEventSink)
- `agent-governance-python/agent-os/src/agent_os/audit_logger.py` (AuditBackend)
- `agent-governance-python/agent-mesh/src/agentmesh/governance/decision_bom.py` (AuditSource, TrustSource, PolicySource, TraceSource)
- `docs/specs/AUDIT-COMPLIANCE-1.0.md` Sections 10, 17
- PEP 544 -- Protocols: Structural subtyping
