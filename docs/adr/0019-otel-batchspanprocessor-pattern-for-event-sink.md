# ADR-0019: OTel BatchSpanProcessor Pattern for Event Sink

## Status

Accepted

## Context

The Governance Event Sink needed to route structured governance events to
external systems (SIEM, XDR, observability platforms, message buses) without
blocking the governance decision hot path. Requirements:

- Async delivery to avoid adding latency to policy evaluation
- Batching to reduce network round-trips
- Fan-out to multiple sinks simultaneously
- Resilience to sink failures (one failing sink must not block others)
- Bounded memory usage under backpressure

The OpenTelemetry SDK's `BatchSpanProcessor` solves an analogous problem for
trace spans and is battle-tested across thousands of production deployments.

## Decision

We adopted the OTel `BatchSpanProcessor` architecture for `GovernanceEventProcessor`:

- **Bounded queue** (default 1024 events) with drop-on-full semantics
- **Background thread** drains the queue on a schedule (default 2000ms)
- **Batch size cap** (default 100 events per export call)
- **Export timeout** (default 10000ms) per sink call
- **Fan-out**: each registered `GovernanceEventSink` receives the same batch
- **Circuit breaker**: after N consecutive failures (default 5), a sink is
  bypassed for a cooldown period (default 60s)

The `GovernanceEventSink` protocol uses structural typing (Protocol) so external
packages can implement it without importing agent-os as a dependency.

## Consequences

- Zero-latency impact on governance decisions (events are enqueued, not sent inline)
- Predictable memory usage via bounded queue
- Graceful degradation -- circuit breaker prevents cascading failures
- External sinks are decoupled (structural typing, no import dependency)
- Events can be dropped under extreme backpressure (acceptable tradeoff for governance where the audit log is the source of truth)

## References

- `agent-governance-python/agent-os/src/agent_os/event_sink.py`
- `docs/specs/AUDIT-COMPLIANCE-1.0.md` Section 11
- PR #2362 (GovernanceEventSink SPI)
- OpenTelemetry SDK BatchSpanProcessor specification
