# ADR-0020: Circuit Breaker for Event Sink Delivery

## Status

Accepted

## Context

Governance event sinks connect to external systems (Splunk, Sentinel, Kafka,
etc.) that may become temporarily unavailable. Without protection, repeated
failed deliveries would:

- Consume export timeout budget on every batch (10s default)
- Accumulate retry overhead in the background thread
- Potentially cause queue overflow as delivery stalls

A circuit breaker pattern was needed to fail-fast when a sink is known to be
unhealthy, then automatically retry after a cooldown.

## Decision

Each sink tracked by `GovernanceEventProcessor` has an independent circuit
breaker with:

- **Threshold**: 5 consecutive failures to trip OPEN
- **Cooldown**: 60 seconds in OPEN state before transitioning to HALF_OPEN
- **HALF_OPEN**: allows one probe batch through; success resets to CLOSED,
  failure returns to OPEN
- **CLOSED**: normal operation, failure counter increments on each failure

The `HALF_OPEN` state is documented as a reserved forward-compatibility surface
(PR #2192) -- current implementation transitions directly from OPEN to a probe
attempt, but the state enum is reserved for future use.

## Consequences

- Failing sinks are bypassed within 5 batches (10s at default schedule)
- Healthy sinks continue receiving events unaffected
- Automatic recovery when external systems come back online
- No manual intervention required for transient outages
- Queue overflow risk is reduced since the background thread is not blocked
  waiting on timeouts for known-bad sinks

## References

- `agent-governance-python/agent-os/src/agent_os/event_sink.py`
- `docs/specs/AUDIT-COMPLIANCE-1.0.md` Section 11
- PR #2192 (HALF_OPEN reserved surface)
- PR #2202 (.NET CircuitBreaker OperationCanceledException fix)
