# IATP-002: Reversibility & Compensating Transactions

**Status:** Draft  
**Author:** Inter-Agent Trust Protocol Team  
**Created:** 2026-01-23  
**Updated:** 2026-01-23

## Abstract

This document defines how agents declare and implement reversibility guarantees for transactions. Reversibility is critical for safe agent-to-agent collaboration, as it enables recovery from errors, miscommunication, or changing requirements.

## 1. Introduction

### 1.1 The Reversibility Problem

In traditional microservices, failures are handled through:
- Database transactions (ACID properties)
- Distributed transactions (2PC, Saga pattern)
- Idempotent APIs

For AI agents, the problem is harder:
- Agents may interact with external APIs (flights, payments)
- Side effects can't always be rolled back (email sent, ML model trained)
- Users may change their mind after the fact
- Errors may not be detected immediately

### 1.2 The IATP Solution

IATP introduces three concepts:
1. **Reversibility Levels** - What guarantees an agent provides
2. **Compensation Methods** - How undo is implemented
3. **Undo Windows** - Time limits for reversal

## 2. Reversibility Levels

### 2.1 Full Reversibility

**Definition:** The agent can completely undo the operation, restoring the system to its exact prior state.

**Example:** Database writes, file system operations, in-memory state

**Manifest Declaration:**
```json
{
  "reversibility": {
    "level": "full",
    "undo_window_seconds": 0,
    "compensation_method": "rollback",
    "compensation_sla_ms": 100
  }
}
```

**Requirements:**
- MUST guarantee 100% restoration
- SHOULD use transactional storage
- MUST NOT have side effects outside the undo scope

### 2.2 Partial Reversibility

**Definition:** The agent can undo most effects, but some side effects remain.

**Example:** Flight booking (refundable, but with cancellation fee)

**Manifest Declaration:**
```json
{
  "reversibility": {
    "level": "partial",
    "undo_window_seconds": 3600,
    "compensation_method": "refund_minus_fee",
    "compensation_sla_ms": 5000,
    "compensation_notes": "24-hour cancellation window. $50 fee applies."
  }
}
```

**Requirements:**
- MUST document what cannot be undone
- SHOULD minimize irreversible side effects
- MUST honor the undo window

### 2.3 No Reversibility

**Definition:** The operation cannot be undone once executed.

**Example:** Sending an email, deploying to production, training an ML model

**Manifest Declaration:**
```json
{
  "reversibility": {
    "level": "none",
    "undo_window_seconds": 0,
    "compensation_method": null,
    "compensation_notes": "Operation is irreversible. Consider carefully before proceeding."
  }
}
```

**Requirements:**
- MUST clearly document irreversibility in the manifest
- SHOULD require explicit user confirmation (handled by sidecar)
- MUST log the operation permanently

## 3. Compensation Methods

### 3.1 Standard Methods

| Method | Description | Use Case |
|--------|-------------|----------|
| `rollback` | Database-style transaction rollback | Database writes, config changes |
| `delete` | Delete the created resource | File creation, object storage |
| `refund` | Full monetary refund | Payment processing |
| `refund_minus_fee` | Partial refund with cancellation fee | Bookings, reservations |
| `compensating_transaction` | New transaction that undoes effects | Financial systems |
| `manual_intervention` | Requires human action | Complex workflows |
| `best_effort` | Attempt undo, no guarantees | Distributed systems |

### 3.2 Custom Compensation Logic

Agents MAY define custom compensation methods:

```json
{
  "reversibility": {
    "level": "partial",
    "compensation_method": "custom:email_recall",
    "compensation_endpoint": "POST /compensate/{transaction_id}",
    "compensation_notes": "Attempts to recall email if not yet read."
  }
}
```

**Compensation Endpoint Contract:**
```http
POST /compensate/{transaction_id}
Content-Type: application/json

{
  "reason": "user_requested",
  "timestamp": "2026-01-23T12:34:56Z"
}
```

**Response:**
```json
{
  "success": true,
  "compensation_applied": "refund_minus_fee",
  "amount_returned": 150.00,
  "fee_charged": 50.00,
  "completion_time_ms": 2341
}
```

## 4. Undo Window

### 4.1 Time-Based Windows

**Definition:** A time limit after which undo is no longer possible.

```json
{
  "undo_window_seconds": 3600  // 1 hour
}
```

**Values:**
- `0` = No time limit (undo always possible)
- `N` = Undo possible for N seconds after execution
- Recommend: 3600 (1 hour), 86400 (24 hours), 604800 (7 days)

### 4.2 State-Based Windows

**Definition:** Undo possible until a certain state is reached.

```json
{
  "undo_window_seconds": 3600,
  "undo_conditions": {
    "until_state": "shipped",
    "check_endpoint": "GET /orders/{order_id}/status"
  }
}
```

**Example:** An order can be cancelled until it ships, regardless of time.

## 5. The Saga Pattern for Agents

### 5.1 Multi-Agent Transactions

When Agent A calls Agent B, which calls Agent C, failures must propagate backwards:

```
Agent A → Agent B → Agent C
  ✓        ✓        ✗ (fails)
  
Compensation Flow:
  ←        ←        ✗
  undo     undo     (failed state)
```

### 5.2 Compensation Chain

Each sidecar MUST track the compensation chain:

```json
{
  "trace_id": "abc-123",
  "compensation_chain": [
    {
      "agent_id": "agent-c",
      "transaction_id": "txn-789",
      "compensation_method": "rollback",
      "status": "failed"
    },
    {
      "agent_id": "agent-b",
      "transaction_id": "txn-456",
      "compensation_method": "delete",
      "status": "compensated"
    },
    {
      "agent_id": "agent-a",
      "transaction_id": "txn-123",
      "compensation_method": "refund",
      "status": "compensated"
    }
  ]
}
```

### 5.3 Orchestration vs. Choreography

**Orchestration (Recommended):**
- Central coordinator (Agent A's sidecar) manages compensation
- Simpler reasoning about state
- Single point of failure

**Choreography:**
- Each sidecar detects failure and compensates locally
- More resilient to failures
- Harder to reason about

## 6. Implementation Guidelines

### 6.1 Idempotency

All operations SHOULD be idempotent:
- Same request executed twice = same result
- Use idempotency keys: `X-Idempotency-Key: <uuid>`

```json
{
  "capabilities": {
    "idempotency": true,
    "idempotency_duration_seconds": 86400
  }
}
```

### 6.2 State Tracking

Sidecars MUST log:
- Original request (scrubbed of sensitive data)
- Response (success/failure)
- Compensation attempts (if any)
- Final state (completed, compensated, failed)

### 6.3 Timeouts and Retries

**Timeouts:**
- Execution timeout: `sla_latency_ms` from manifest
- Compensation timeout: `compensation_sla_ms` from manifest

**Retries:**
- Idempotent operations: Retry with exponential backoff
- Non-idempotent: Do NOT retry (risk double execution)

## 7. Testing Reversibility

### 7.1 The "Chaos Monkey" Test

Randomly inject failures to test compensation:

```python
# Test setup
agent = UntrustedAgent(fail_rate=0.5)
sidecar = IATPSidecar(agent)

# Execute 100 transactions
for i in range(100):
    result = sidecar.execute(task="book_flight")
    if result.failed:
        assert sidecar.compensate(result.trace_id).success
        assert agent.state == initial_state
```

### 7.2 Undo Window Testing

```python
# Test undo within window
result = sidecar.execute(task="book_flight")
time.sleep(30)  # Within 1-hour window
assert sidecar.compensate(result.trace_id).success

# Test undo outside window
result = sidecar.execute(task="book_flight")
time.sleep(3700)  # Outside 1-hour window
assert sidecar.compensate(result.trace_id).success == False
assert "undo window expired" in sidecar.compensate(result.trace_id).error
```

## 8. Security Considerations

### 8.1 Unauthorized Undo

Prevent malicious actors from undoing legitimate transactions:
- Require authentication token for compensation endpoint
- Match trace_id to original requester
- Rate limit compensation attempts

### 8.2 Audit Trail

All undo operations MUST be logged:
```json
{
  "event": "compensation_attempted",
  "trace_id": "abc-123",
  "requested_by": "user-456",
  "reason": "user_requested",
  "result": "success",
  "timestamp": "2026-01-23T12:34:56Z"
}
```

## 9. Examples

### 9.1 Banking Transfer (Full Reversibility)

```json
{
  "reversibility": {
    "level": "full",
    "undo_window_seconds": 300,
    "compensation_method": "rollback",
    "compensation_notes": "5-minute fraud detection window. After that, contact support."
  }
}
```

### 9.2 Flight Booking (Partial Reversibility)

```json
{
  "reversibility": {
    "level": "partial",
    "undo_window_seconds": 86400,
    "compensation_method": "refund_minus_fee",
    "compensation_notes": "Free cancellation within 24 hours. After 24h: $150 fee."
  }
}
```

### 9.3 Email Sending (No Reversibility)

```json
{
  "reversibility": {
    "level": "none",
    "undo_window_seconds": 0,
    "compensation_method": null,
    "compensation_notes": "Emails cannot be recalled once sent."
  }
}
```

## 10. Future Work

- **IATP-007:** Distributed saga coordination
- **IATP-008:** Compensation cost estimation
- **IATP-009:** Cross-organization compensation

## 11. References

- Saga pattern: https://microservices.io/patterns/data/saga.html
- ACID properties: https://en.wikipedia.org/wiki/ACID
- Event sourcing: https://martinfowler.com/eaaDev/EventSourcing.html

---

**Document Status:** This is a living document. Feedback welcome via GitHub issues.
