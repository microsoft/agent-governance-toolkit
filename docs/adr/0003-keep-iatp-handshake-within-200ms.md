# ADR 0003: Keep the IATP trust handshake within a 200ms SLA

- Status: accepted
- Date: 2026-03-26

## Context

IATP trust handshakes sit directly in the path of agent-to-agent communication.
The protocol spec requires capability discovery and local policy validation
before work starts, and repository examples show handshakes happening before
delegation or collaboration is accepted. AgentMesh planning docs, release
notes, and examples already treat `<200ms` as the target for this step. If the
handshake becomes materially slower, every cross-agent interaction pays the
penalty and the trust layer stops feeling safe to use in interactive flows.

## Decision

Set a 200ms service-level target for the trust handshake so identity checks,
manifest validation, and local policy decisions remain a lightweight gate in
front of real work instead of becoming the dominant latency cost.

## Consequences

This target keeps trust verification compatible with chatty multi-agent systems
and forces the protocol to prefer compact manifests, bounded checks, and local
decision making. It also creates a clear performance budget for future changes.
The tradeoff is that expensive remote lookups and heavyweight negotiation must
stay out of the critical path or be handled through caching and asynchronous
follow-up signals.
