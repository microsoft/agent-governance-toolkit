# ADR-0021: CloudEvents Envelope for Mesh Audit

## Status

Accepted

## Context

AgentMesh audit entries needed a standardized serialization format for export
to external systems. Options considered:

1. **Custom JSON schema** -- simple but requires consumers to learn a bespoke format
2. **OpenTelemetry LogRecord** -- good for observability but not designed for
   event-driven architectures
3. **CloudEvents** (CNCF specification) -- industry standard for event
   interoperability, supported by Azure Event Grid, AWS EventBridge, Knative,
   and most message brokers

## Decision

We adopted CloudEvents v1.0 as the envelope format for mesh audit entry export
via `AuditEntry.to_cloudevent()`. The mapping:

| CloudEvents attribute | Value |
|---|---|
| `specversion` | `"1.0"` |
| `type` | `"ai.agentmesh.{event_type}"` |
| `source` | Agent DID URI |
| `id` | `entry_id` |
| `time` | Entry timestamp (RFC 3339) |
| `datacontenttype` | `"application/json"` |
| `data` | Full audit entry as JSON |

Custom extension attributes use the `ai.agentmesh.*` namespace prefix.

## Consequences

- Audit entries can be routed through any CloudEvents-compatible broker
- Standard SDKs in multiple languages can parse the events
- Azure Event Grid native support enables direct SIEM integration
- The `ai.agentmesh.*` namespace avoids collision with other event producers
- Slightly larger payload than raw JSON (CloudEvents envelope overhead)

## References

- `agent-governance-python/agent-mesh/src/agentmesh/governance/audit.py` (`to_cloudevent()`)
- `agent-governance-python/agent-mesh/docs/CLOUDEVENTS_SCHEMA.md`
- `docs/specs/AUDIT-COMPLIANCE-1.0.md` Section 14
- CNCF CloudEvents Specification v1.0
