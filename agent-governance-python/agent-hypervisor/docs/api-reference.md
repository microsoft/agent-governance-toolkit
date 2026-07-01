# Agent Hypervisor API Reference

Complete reference for the implemented REST API and Python SDK surface.
Run the server with `uvicorn hypervisor.api.server:app`.

**Base URL:** `http://localhost:8000`

## REST API

### Health

#### `GET /health`

Returns a liveness response.

```bash
curl http://localhost:8000/health
```

```json
{ "status": "ok", "version": "0.1.0" }
```

#### `GET /api/v1/stats`

Returns aggregate session, participant, saga, and event counts.

```bash
curl http://localhost:8000/api/v1/stats
```

```json
{
  "version": "0.1.0",
  "total_sessions": 3,
  "active_sessions": 1,
  "total_participants": 7,
  "active_sagas": 2,
  "event_count": 42
}
```

### Sessions

#### `POST /api/v1/sessions`

Create a new shared session.

```bash
curl -X POST http://localhost:8000/api/v1/sessions \
  -H "Content-Type: application/json" \
  -d '{
    "creator_did": "did:example:alice",
    "consistency_mode": "eventual",
    "max_participants": 5,
    "max_duration_seconds": 3600,
    "min_eff_score": 0.60,
    "enable_audit": true
  }'
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `creator_did` | string | required | DID of the session creator |
| `consistency_mode` | string | `eventual` | `strong` or `eventual` |
| `max_participants` | integer | `10` | Maximum agents allowed |
| `max_duration_seconds` | integer | `3600` | Session timeout in seconds |
| `min_eff_score` | number | `0.60` | Minimum effective score for admission |
| `enable_audit` | boolean | `true` | Enable hash-chained delta audit |

```json
{
  "session_id": "ss-a1b2c3d4",
  "state": "created",
  "consistency_mode": "eventual",
  "created_at": "2025-01-15T10:30:00+00:00"
}
```

#### `GET /api/v1/sessions`

List sessions, optionally filtered by state.

```bash
curl "http://localhost:8000/api/v1/sessions?state=active"
```

#### `GET /api/v1/sessions/{session_id}`

Get detailed session information, participants, and saga summaries.

```bash
curl http://localhost:8000/api/v1/sessions/ss-a1b2c3d4
```

#### `POST /api/v1/sessions/{session_id}/join`

Join an agent to a session and assign an execution ring from its score.

```bash
curl -X POST http://localhost:8000/api/v1/sessions/ss-a1b2c3d4/join \
  -H "Content-Type: application/json" \
  -d '{
    "agent_did": "did:example:bob",
    "sigma_raw": 0.65,
    "actions": []
  }'
```

```json
{
  "agent_did": "did:example:bob",
  "session_id": "ss-a1b2c3d4",
  "assigned_ring": 2,
  "ring_name": "RING_2_STANDARD"
}
```

#### `POST /api/v1/sessions/{session_id}/activate`

Transition a session from handshaking to active.

```bash
curl -X POST http://localhost:8000/api/v1/sessions/ss-a1b2c3d4/activate
```

#### `POST /api/v1/sessions/{session_id}/terminate`

Terminate a session and return the audit hash-chain root.

```bash
curl -X POST http://localhost:8000/api/v1/sessions/ss-a1b2c3d4/terminate
```

```json
{
  "session_id": "ss-a1b2c3d4",
  "state": "archived",
  "hash_chain_root": "sha256:9f86d08..."
}
```

### Rings

#### `GET /api/v1/sessions/{session_id}/rings`

Get the ring distribution for all participants in a session.

```bash
curl http://localhost:8000/api/v1/sessions/ss-a1b2c3d4/rings
```

#### `GET /api/v1/agents/{agent_did}/ring`

Get an agent's current ring across active sessions.

```bash
curl http://localhost:8000/api/v1/agents/did:example:bob/ring
```

#### `POST /api/v1/rings/check`

Check whether an action is allowed for a ring and effective score.

```bash
curl -X POST http://localhost:8000/api/v1/rings/check \
  -H "Content-Type: application/json" \
  -d '{
    "agent_ring": 2,
    "action": {
      "action_id": "deploy-model",
      "name": "Deploy ML Model",
      "execute_api": "/models/deploy",
      "reversibility": "partial",
      "is_read_only": false,
      "is_admin": false
    },
    "eff_score": 0.78,
    "has_consensus": false,
    "has_sre_witness": false
  }'
```

```json
{
  "allowed": true,
  "required_ring": 2,
  "agent_ring": 2,
  "eff_score": 0.78,
  "reason": "Action allowed at current ring level"
}
```

### Sagas

#### `POST /api/v1/sessions/{session_id}/sagas`

Create a new saga inside a session.

```bash
curl -X POST http://localhost:8000/api/v1/sessions/ss-a1b2c3d4/sagas
```

#### `GET /api/v1/sessions/{session_id}/sagas`

List sagas in a session.

```bash
curl http://localhost:8000/api/v1/sessions/ss-a1b2c3d4/sagas
```

#### `GET /api/v1/sagas/{saga_id}`

Get saga state and steps.

```bash
curl http://localhost:8000/api/v1/sagas/saga-e5f6a7b8
```

#### `POST /api/v1/sagas/{saga_id}/steps`

Add a step with an optional undo endpoint.

```bash
curl -X POST http://localhost:8000/api/v1/sagas/saga-e5f6a7b8/steps \
  -H "Content-Type: application/json" \
  -d '{
    "action_id": "provision-vm",
    "agent_did": "did:example:alice",
    "execute_api": "/infra/provision",
    "undo_api": "/infra/deprovision",
    "timeout_seconds": 120,
    "max_retries": 2
  }'
```

#### `POST /api/v1/sagas/{saga_id}/steps/{step_id}/execute`

Execute a pending saga step.

```bash
curl -X POST http://localhost:8000/api/v1/sagas/saga-e5f6a7b8/steps/step-001/execute
```

### Events

#### `GET /api/v1/events`

Query the in-memory event bus with optional filters.

```bash
curl "http://localhost:8000/api/v1/events?event_type=session.created&limit=10"
```

| Parameter | Description |
|-----------|-------------|
| `event_type` | Filter by event type |
| `session_id` | Filter by session ID |
| `agent_did` | Filter by agent DID |
| `limit` | Maximum number of events |

Common event families include `session.*`, `ring.*`, `saga.*`, `vfs.*`, `security.*`, `audit.*`, and `verification.*`.

#### `GET /api/v1/events/stats`

Get event counts grouped by type.

```bash
curl http://localhost:8000/api/v1/events/stats
```

### Verification

#### `POST /api/v1/verify/history`

Verify an agent's claimed transaction history against known session records.

```bash
curl -X POST http://localhost:8000/api/v1/verify/history \
  -H "Content-Type: application/json" \
  -d '{
    "agent_did": "did:example:bob",
    "transactions": [
      {
        "session_id": "ss-a1b2c3d4",
        "summary_hash": "sha256:abc123...",
        "timestamp": "2025-01-15T10:30:00Z",
        "participant_count": 3
      }
    ]
  }'
```

#### `DELETE /api/v1/verify/cache/{agent_did}`

Clear cached history verification for an agent.

```bash
curl -X DELETE http://localhost:8000/api/v1/verify/cache/did:example:bob
```

## Python SDK

### `Hypervisor`

Top-level orchestrator for sessions, rings, reversibility, saga execution, audit, and history verification.

```python
from hypervisor import Hypervisor, SessionConfig

hv = Hypervisor()
managed = await hv.create_session(SessionConfig(enable_audit=True), "did:example:alice")
ring = await hv.join_session(managed.sso.session_id, "did:example:bob", sigma_raw=0.72)
await hv.activate_session(managed.sso.session_id)
hash_root = await hv.terminate_session(managed.sso.session_id)
```

Optional constructor adapters:

| Parameter | Description |
|-----------|-------------|
| `nexus` | External trust scoring adapter |
| `policy_check` | External behavior check hook |
| `iatp` | Capability manifest adapter |

### Session classes

| Class | Purpose |
|-------|---------|
| `SessionConfig` | Session limits, consistency mode, and audit setting |
| `SharedSessionObject` | Lifecycle state and participant registry |
| `SessionVFS` | Per-session virtual file system with snapshots |
| `VectorClock` | Causal ordering for shared state updates |
| `IsolationLevel` | Isolation mode for state reads and writes |

### Ring classes

| Class | Purpose |
|-------|---------|
| `ExecutionRing` | Ring 0 through Ring 3 privilege levels |
| `ActionClassifier` | Computes required ring and risk weight from action metadata |
| `RingEnforcer` | Checks whether an agent ring may run an action |
| `RingElevationManager` | Issues and revokes time-bounded ring elevation records |
| `RingBreachDetector` | Detects anomalous ring-boundary activity |

### Saga classes

| Class | Purpose |
|-------|---------|
| `SagaOrchestrator` | Creates sagas, adds ordered steps, executes steps, and compensates committed work |
| `SagaState` | Saga lifecycle states |
| `StepState` | Step lifecycle states |
| `SagaTimeoutError` | Raised when a step exceeds its configured timeout |

```python
from hypervisor import SagaOrchestrator

orch = SagaOrchestrator()
saga = orch.create_saga("ss-a1b2c3d4")
step = orch.add_step(
    saga.saga_id,
    "provision-vm",
    "did:example:alice",
    execute_api="/infra/provision",
    undo_api="/infra/deprovision",
)
await orch.execute_step(saga.saga_id, step.step_id, executor=provision)
await orch.compensate(saga.saga_id, compensator)
```

### Reversibility and audit

| Class | Purpose |
|-------|---------|
| `ReversibilityRegistry` | Registers action execute and undo metadata |
| `DeltaEngine` | Captures VFS deltas and maintains a hash chain |

### Security controls

| Class | Purpose |
|-------|---------|
| `KillSwitch` | Terminates an agent, records the kill event, and can hand off in-flight work |
| `AgentRateLimiter` | Per-agent token bucket limits keyed by ring and session |
| `RateLimitExceeded` | Raised when a checked request exceeds available tokens |

### Verification and observability

| Class | Purpose |
|-------|---------|
| `TransactionHistoryVerifier` | Verifies claimed transaction history |
| `HypervisorEventBus` | Emits, stores, and queries hypervisor events |
| `EventType` | Enumerates event names used by the event bus |
| `HypervisorEvent` | Immutable event payload |
| `CausalTraceId` | Correlates events across related operations |

## Error responses

The API uses standard FastAPI error payloads:

```json
{ "detail": "Session ss-unknown not found" }
```

Common status codes are `400` for invalid state or request data, `404` for missing sessions or sagas, and `500` for unexpected server errors.
