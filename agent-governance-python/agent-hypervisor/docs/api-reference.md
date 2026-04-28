# Agent Hypervisor — API Reference

> Complete reference for the REST API and Python SDK.
> Run the server with `uvicorn hypervisor.api.server:app`.

**Base URL:** `http://localhost:8000`

---

## Table of Contents

- [REST API](#rest-api)
  - [Health](#health)
  - [Sessions](#sessions)
  - [Rings](#rings)
  - [Sagas](#sagas)
  - [Liability](#liability)
  - [Events](#events)
  - [Audit](#audit)
  - [Verification](#verification)
- [Python SDK](#python-sdk)
  - [Agent Lifecycle](#agent-lifecycle) — Hypervisor, ExecutionRing, AgentConfig
  - [Saga Engine](#saga-engine) — SagaOrchestrator, SagaDSLParser, CheckpointManager
  - [Kill Switch](#kill-switch) — KillSwitch, BreachDetector
  - [Rate Limiter](#rate-limiter) — AgentRateLimiter, TokenBucket
  - [Audit & Observability](#audit--observability) — HypervisorEventBus, CausalTraceId
  - [Joint Liability](#joint-liability) — VouchingEngine, SlashingEngine, LiabilityLedger
  - [Classification](#classification) — ActionClassifier, RingEnforcer

---

## REST API

### Health

#### `GET /health`

Basic liveness check.

```bash
curl http://localhost:8000/health
```

**Response** `200 OK`

```json
{
  "status": "ok",
  "version": "0.1.0"
}
```

---

#### `GET /api/v1/stats`

Aggregate statistics for the running hypervisor instance.

```bash
curl http://localhost:8000/api/v1/stats
```

**Response** `200 OK`

```json
{
  "version": "0.1.0",
  "total_sessions": 3,
  "active_sessions": 1,
  "total_participants": 7,
  "active_sagas": 2,
  "total_vouches": 4,
  "event_count": 42
}
```

---

### Sessions

#### `POST /api/v1/sessions`

Create a new Shared Session.

```bash
curl -X POST http://localhost:8000/api/v1/sessions \
  -H "Content-Type: application/json" \
  -d '{
    "creator_did": "did:example:alice",
    "consistency_mode": "eventual",
    "max_participants": 5,
    "max_duration_seconds": 3600,
    "min_eff_score": 0.60,
    "enable_audit": true,
    "enable_blockchain_commitment": false
  }'
```

**Request Body**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `creator_did` | string | *required* | DID of the session creator |
| `consistency_mode` | string | `"eventual"` | `"strong"` or `"eventual"` |
| `max_participants` | int | `10` | Maximum agents allowed |
| `max_duration_seconds` | int | `3600` | Session timeout in seconds |
| `min_eff_score` | float | `0.60` | Minimum effective reputation score |
| `enable_audit` | bool | `true` | Enable hash-chained audit trail |
| `enable_blockchain_commitment` | bool | `false` | Commit audit root to blockchain |

**Response** `201 Created`

```json
{
  "session_id": "ss-a1b2c3d4",
  "state": "created",
  "consistency_mode": "eventual",
  "created_at": "2025-01-15T10:30:00+00:00"
}
```

---

#### `GET /api/v1/sessions`

List all sessions, optionally filtered by state.

```bash
curl "http://localhost:8000/api/v1/sessions?state=active"
```

**Query Parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `state` | string | Filter by state: `created`, `handshaking`, `active`, `terminating`, `archived` |

**Response** `200 OK`

```json
[
  {
    "session_id": "ss-a1b2c3d4",
    "state": "active",
    "consistency_mode": "eventual",
    "participant_count": 3,
    "created_at": "2025-01-15T10:30:00+00:00"
  }
]
```

---

#### `GET /api/v1/sessions/{session_id}`

Get detailed session information including participants and sagas.

```bash
curl http://localhost:8000/api/v1/sessions/ss-a1b2c3d4
```

**Response** `200 OK`

```json
{
  "session_id": "ss-a1b2c3d4",
  "state": "active",
  "consistency_mode": "eventual",
  "creator_did": "did:example:alice",
  "participant_count": 2,
  "participants": [
    {
      "agent_did": "did:example:alice",
      "ring": 1,
      "sigma_raw": 0.92,
      "eff_score": 0.92,
      "joined_at": "2025-01-15T10:30:00+00:00",
      "is_active": true
    },
    {
      "agent_did": "did:example:bob",
      "ring": 2,
      "sigma_raw": 0.65,
      "eff_score": 0.78,
      "joined_at": "2025-01-15T10:31:00+00:00",
      "is_active": true
    }
  ],
  "created_at": "2025-01-15T10:30:00+00:00",
  "terminated_at": null,
  "sagas": []
}
```

**Error** `404 Not Found`

```json
{ "detail": "Session ss-unknown not found" }
```

---

#### `POST /api/v1/sessions/{session_id}/join`

Join an agent to a session. The agent is assigned an Execution Ring based on its
trust score (`sigma_raw`) and any sponsorship bonds.

```bash
curl -X POST http://localhost:8000/api/v1/sessions/ss-a1b2c3d4/join \
  -H "Content-Type: application/json" \
  -d '{
    "agent_did": "did:example:bob",
    "sigma_raw": 0.65,
    "actions": [
      {
        "action_id": "read-data",
        "name": "Read Dataset",
        "execute_api": "/data/read",
        "reversibility": "full",
        "is_read_only": true
      }
    ]
  }'
```

**Request Body**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `agent_did` | string | *required* | DID of the joining agent |
| `sigma_raw` | float | `0.0` | Agent's raw reputation score (0–1) |
| `actions` | list | `null` | Action descriptors the agent can perform |

**Response** `200 OK`

```json
{
  "agent_did": "did:example:bob",
  "session_id": "ss-a1b2c3d4",
  "assigned_ring": 2,
  "ring_name": "RING_2_STANDARD"
}
```

---

#### `POST /api/v1/sessions/{session_id}/activate`

Transition a session from `handshaking` to `active`.

```bash
curl -X POST http://localhost:8000/api/v1/sessions/ss-a1b2c3d4/activate
```

**Response** `200 OK`

```json
{ "session_id": "ss-a1b2c3d4", "state": "active" }
```

---

#### `POST /api/v1/sessions/{session_id}/terminate`

Terminate a session, commit the audit trail, and release bonds.

```bash
curl -X POST http://localhost:8000/api/v1/sessions/ss-a1b2c3d4/terminate
```

**Response** `200 OK`

```json
{
  "session_id": "ss-a1b2c3d4",
  "state": "archived",
  "hash_chain_root": "sha256:9f86d08..."
}
```

---

### Rings

#### `GET /api/v1/sessions/{session_id}/rings`

Get the ring distribution for all participants in a session.

```bash
curl http://localhost:8000/api/v1/sessions/ss-a1b2c3d4/rings
```

**Response** `200 OK`

```json
{
  "session_id": "ss-a1b2c3d4",
  "distribution": {
    "RING_1_PRIVILEGED": ["did:example:alice"],
    "RING_2_STANDARD": ["did:example:bob"],
    "RING_3_SANDBOX": ["did:example:carol"]
  }
}
```

---

#### `GET /api/v1/agents/{agent_did}/ring`

Get an agent's current ring across all active sessions.

```bash
curl http://localhost:8000/api/v1/agents/did:example:bob/ring
```

**Response** `200 OK`

```json
{
  "agent_did": "did:example:bob",
  "ring": 2,
  "ring_name": "RING_2_STANDARD",
  "session_id": "ss-a1b2c3d4"
}
```

**Error** `404 Not Found`

```json
{ "detail": "Agent did:example:bob not found in any session" }
```

---

#### `POST /api/v1/rings/check`

Check whether an action is allowed for a given ring level and reputation score.

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

**Response** `200 OK`

```json
{
  "allowed": true,
  "required_ring": 2,
  "agent_ring": 2,
  "eff_score": 0.78,
  "reason": "Action allowed at current ring level",
  "requires_consensus": false,
  "requires_sre_witness": false
}
```

---

### Sagas

#### `POST /api/v1/sessions/{session_id}/sagas`

Create a new saga (multi-step transaction) within a session.

```bash
curl -X POST http://localhost:8000/api/v1/sessions/ss-a1b2c3d4/sagas
```

**Response** `201 Created`

```json
{
  "saga_id": "saga-e5f6a7b8",
  "session_id": "ss-a1b2c3d4",
  "state": "running",
  "created_at": "2025-01-15T10:35:00+00:00"
}
```

---

#### `GET /api/v1/sessions/{session_id}/sagas`

List all sagas in a session.

```bash
curl http://localhost:8000/api/v1/sessions/ss-a1b2c3d4/sagas
```

**Response** `200 OK`

```json
[
  {
    "saga_id": "saga-e5f6a7b8",
    "session_id": "ss-a1b2c3d4",
    "state": "running",
    "created_at": "2025-01-15T10:35:00+00:00",
    "completed_at": null,
    "error": null,
    "steps": [
      {
        "step_id": "step-001",
        "action_id": "provision-vm",
        "agent_did": "did:example:alice",
        "state": "committed",
        "error": null
      }
    ]
  }
]
```

---

#### `GET /api/v1/sagas/{saga_id}`

Get detailed saga information including all steps and state.

```bash
curl http://localhost:8000/api/v1/sagas/saga-e5f6a7b8
```

**Response** `200 OK`

```json
{
  "saga_id": "saga-e5f6a7b8",
  "session_id": "ss-a1b2c3d4",
  "state": "completed",
  "created_at": "2025-01-15T10:35:00+00:00",
  "completed_at": "2025-01-15T10:36:00+00:00",
  "error": null,
  "steps": [
    {
      "step_id": "step-001",
      "action_id": "provision-vm",
      "agent_did": "did:example:alice",
      "state": "committed",
      "error": null
    },
    {
      "step_id": "step-002",
      "action_id": "deploy-app",
      "agent_did": "did:example:bob",
      "state": "committed",
      "error": null
    }
  ]
}
```

---

#### `POST /api/v1/sagas/{saga_id}/steps`

Add a step to an existing saga.

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

**Request Body**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `action_id` | string | *required* | Unique action identifier |
| `agent_did` | string | *required* | DID of the agent executing this step |
| `execute_api` | string | *required* | Forward-action endpoint |
| `undo_api` | string | `null` | Compensating-action endpoint |
| `timeout_seconds` | int | `300` | Step execution timeout |
| `max_retries` | int | `0` | Retry count before failure |

**Response** `201 Created`

```json
{
  "step_id": "step-001",
  "saga_id": "saga-e5f6a7b8",
  "action_id": "provision-vm",
  "state": "pending"
}
```

---

#### `POST /api/v1/sagas/{saga_id}/steps/{step_id}/execute`

Execute a pending saga step.

```bash
curl -X POST http://localhost:8000/api/v1/sagas/saga-e5f6a7b8/steps/step-001/execute
```

**Response** `200 OK`

```json
{
  "step_id": "step-001",
  "saga_id": "saga-e5f6a7b8",
  "state": "committed",
  "error": null
}
```

**Error** `400 Bad Request` (e.g., step already executed)

```json
{ "detail": "Step step-001 is not in PENDING state" }
```

---

### Liability

#### `POST /api/v1/sessions/{session_id}/sponsor`

Create a sponsorship bond between two agents. The voucher stakes a percentage
of their reputation to back the vouchee.

```bash
curl -X POST http://localhost:8000/api/v1/sessions/ss-a1b2c3d4/sponsor \
  -H "Content-Type: application/json" \
  -d '{
    "voucher_did": "did:example:alice",
    "vouchee_did": "did:example:bob",
    "voucher_sigma": 0.92,
    "bond_pct": 0.10
  }'
```

**Request Body**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `voucher_did` | string | *required* | DID of the sponsoring agent |
| `vouchee_did` | string | *required* | DID of the agent being sponsored |
| `voucher_sigma` | float | *required* | Sponsor's raw reputation score |
| `bond_pct` | float | `null` | Fraction of reputation to bond (0–1) |
| `expiry` | string | `null` | ISO 8601 expiry timestamp |

**Response** `201 Created`

```json
{
  "vouch_id": "vouch-x9y8z7",
  "voucher_did": "did:example:alice",
  "vouchee_did": "did:example:bob",
  "session_id": "ss-a1b2c3d4",
  "bonded_amount": 0.092,
  "bonded_sigma_pct": 0.10,
  "is_active": true
}
```

---

#### `GET /api/v1/sessions/{session_id}/sponsors`

List all sponsorship bonds in a session.

```bash
curl http://localhost:8000/api/v1/sessions/ss-a1b2c3d4/sponsors
```

**Response** `200 OK`

```json
[
  {
    "vouch_id": "vouch-x9y8z7",
    "voucher_did": "did:example:alice",
    "vouchee_did": "did:example:bob",
    "session_id": "ss-a1b2c3d4",
    "bonded_amount": 0.092,
    "bonded_sigma_pct": 0.10,
    "is_active": true
  }
]
```

---

#### `GET /api/v1/agents/{agent_did}/liability`

Get an agent's total liability exposure across all sessions.

```bash
curl http://localhost:8000/api/v1/agents/did:example:alice/liability
```

**Response** `200 OK`

```json
{
  "agent_did": "did:example:alice",
  "vouches_given": [
    {
      "vouch_id": "vouch-x9y8z7",
      "voucher_did": "did:example:alice",
      "vouchee_did": "did:example:bob",
      "session_id": "ss-a1b2c3d4",
      "bonded_amount": 0.092,
      "bonded_sigma_pct": 0.10,
      "is_active": true
    }
  ],
  "vouches_received": [],
  "total_exposure": 0.092
}
```

---

### Events

#### `GET /api/v1/events`

Query the event bus with optional filters.

```bash
curl "http://localhost:8000/api/v1/events?event_type=session.created&limit=10"
```

**Query Parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `event_type` | string | Filter by event type (see [Event Types](#event-types)) |
| `session_id` | string | Filter by session ID |
| `agent_did` | string | Filter by agent DID |
| `limit` | int | Maximum number of events to return |

**Response** `200 OK`

```json
[
  {
    "event_id": "evt-123",
    "event_type": "session.created",
    "timestamp": "2025-01-15T10:30:00+00:00",
    "session_id": "ss-a1b2c3d4",
    "agent_did": "did:example:alice",
    "causal_trace_id": null,
    "payload": { "consistency_mode": "eventual" }
  }
]
```

##### Event Types

| Event Type | Description |
|------------|-------------|
| `session.created` | Session created |
| `session.joined` | Agent joined a session |
| `session.activated` | Session activated |
| `session.terminated` | Session terminated |
| `ring.assigned` | Ring assigned to agent |
| `ring.demoted` | Agent demoted to lower ring |
| `ring.breach` | Ring breach detected |
| `liability.vouch_created` | Sponsorship bond created |
| `liability.slash` | Reputation slashed |
| `liability.quarantine` | Agent quarantined |
| `saga.created` | Saga created |
| `saga.step_committed` | Saga step committed |
| `saga.step_failed` | Saga step failed |
| `saga.compensating` | Saga compensation started |
| `saga.completed` | Saga completed |
| `security.kill` | Agent killed via kill switch |
| `security.rate_limited` | Agent rate-limited |
| `audit.commitment` | Audit trail committed |

---

#### `GET /api/v1/events/stats`

Get event counts grouped by type.

```bash
curl http://localhost:8000/api/v1/events/stats
```

**Response** `200 OK`

```json
{
  "total_events": 42,
  "by_type": {
    "session.created": 3,
    "session.joined": 7,
    "ring.assigned": 7,
    "saga.step_committed": 12,
    "liability.vouch_created": 4
  }
}
```

---

### Audit

#### `GET /api/v1/audit/commitments`

List all session audit-trail commitments.

```bash
curl http://localhost:8000/api/v1/audit/commitments
```

**Response** `200 OK`

```json
[
  {
    "session_id": "ss-a1b2c3d4",
    "hash_chain_root": "sha256:9f86d081884c...",
    "participant_dids": ["did:example:alice", "did:example:bob"],
    "delta_count": 15,
    "committed_at": "2025-01-15T11:00:00+00:00",
    "committed_to": "local",
    "blockchain_tx_id": null
  }
]
```

---

#### `GET /api/v1/audit/commitments/{session_id}`

Get the audit commitment for a specific session.

```bash
curl http://localhost:8000/api/v1/audit/commitments/ss-a1b2c3d4
```

**Response** `200 OK`

```json
{
  "session_id": "ss-a1b2c3d4",
  "hash_chain_root": "sha256:9f86d081884c...",
  "participant_dids": ["did:example:alice", "did:example:bob"],
  "delta_count": 15,
  "committed_at": "2025-01-15T11:00:00+00:00",
  "committed_to": "local",
  "blockchain_tx_id": null
}
```

---

#### `POST /api/v1/audit/verify/{session_id}`

Verify a session's audit-log root hash matches its commitment.

```bash
curl -X POST "http://localhost:8000/api/v1/audit/verify/ss-a1b2c3d4?expected_root=sha256:9f86d081884c..."
```

**Query Parameters**

| Parameter | Type | Description |
|-----------|------|-------------|
| `expected_root` | string | *required* — The expected hash-chain root to verify against |

**Response** `200 OK`

```json
{
  "session_id": "ss-a1b2c3d4",
  "valid": true,
  "committed_root": "sha256:9f86d081884c...",
  "expected_root": "sha256:9f86d081884c..."
}
```

---

### Verification

#### `POST /api/v1/verify/history`

Verify an agent's claimed transaction history against the hypervisor's records.

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

**Response** `200 OK`

```json
{
  "agent_did": "did:example:bob",
  "status": "verified",
  "transactions_checked": 1,
  "transactions_found": 1,
  "inconsistencies": [],
  "is_trustworthy": true,
  "cached": false
}
```

---

#### `DELETE /api/v1/verify/cache/{agent_did}`

Clear the cached verification result for an agent.

```bash
curl -X DELETE http://localhost:8000/api/v1/verify/cache/did:example:bob
```

**Response** `200 OK`

```json
{ "status": "cleared", "agent_did": "did:example:bob" }
```

---

## Python SDK

### Agent Lifecycle

#### `Hypervisor`

The central orchestrator that manages sessions, agents, rings, and all
sub-systems.

```python
from hypervisor import Hypervisor
from hypervisor.models import SessionConfig, ConsistencyMode

hv = Hypervisor(
    max_exposure=5.0,   # cap total liability per voucher
)

# Create a session
config = SessionConfig(
    consistency_mode=ConsistencyMode.EVENTUAL,
    max_participants=5,
    max_duration_seconds=3600,
    min_eff_score=0.60,
    enable_audit=True,
)
managed = await hv.create_session(config=config, creator_did="did:example:alice")
session_id = managed.sso.session_id

# Join agents
ring = await hv.join_session(
    session_id=session_id,
    agent_did="did:example:bob",
    sigma_raw=0.72,
)
print(ring)  # ExecutionRing.RING_2_STANDARD

# Activate and later terminate
await hv.activate_session(session_id)
hash_root = await hv.terminate_session(session_id)
```

**Constructor Parameters**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `retention_policy` | `RetentionPolicy` | `None` | Delta retention settings |
| `max_exposure` | `float` | `None` | Maximum liability exposure per voucher |
| `nexus` | `Any` | `None` | Nexus trust-scoring adapter |
| `policy_check` | `Any` | `None` | External policy check hook |
| `iatp` | `Any` | `None` | IATP manifest adapter |

**Key Methods**

| Method | Returns | Description |
|--------|---------|-------------|
| `create_session(config, creator_did)` | `ManagedSession` | Create a new session |
| `join_session(session_id, agent_did, ...)` | `ExecutionRing` | Join agent and assign ring |
| `activate_session(session_id)` | `None` | Transition session to active |
| `terminate_session(session_id)` | `str` | Terminate and return audit hash root |
| `get_session(session_id)` | `ManagedSession | None` | Retrieve session by ID |
| `verify_behavior(session_id, agent_did, ...)` | `Any` | Verify agent behavioral drift |

---

#### `ExecutionRing`

Hardware-inspired privilege levels (0 = most privileged, 3 = sandbox).

```python
from hypervisor.models import ExecutionRing

# Derive ring from effective reputation score
ring = ExecutionRing.from_eff_score(0.85, has_consensus=False)
print(ring)  # ExecutionRing.RING_1_PRIVILEGED

# Ring values
ExecutionRing.RING_0_ROOT          # 0 — reserved, always denied
ExecutionRing.RING_1_PRIVILEGED    # 1 — high-trust agents (σ_eff ≥ 0.70)
ExecutionRing.RING_2_STANDARD      # 2 — normal agents
ExecutionRing.RING_3_SANDBOX       # 3 — untrusted / new agents
```

---

#### `SessionConfig`

Configuration dataclass for session creation.

```python
from hypervisor.models import SessionConfig, ConsistencyMode

config = SessionConfig(
    consistency_mode=ConsistencyMode.STRONG,
    max_participants=10,
    max_duration_seconds=7200,
    min_eff_score=0.50,
    enable_audit=True,
    enable_blockchain_commitment=False,
)
```

---

#### `ActionDescriptor`

Describes an action an agent can perform, including its reversibility and
risk properties.

```python
from hypervisor.models import ActionDescriptor, ReversibilityLevel

action = ActionDescriptor(
    action_id="deploy-model",
    name="Deploy ML Model",
    execute_api="/models/deploy",
    undo_api="/models/rollback",
    reversibility=ReversibilityLevel.PARTIAL,
    undo_window_seconds=300,
    is_read_only=False,
    is_admin=False,
)

print(action.risk_weight)    # Computed from reversibility level
print(action.required_ring)  # Minimum ring needed
```

---

### Saga Engine

#### `SagaOrchestrator`

Manages multi-step transactions with automatic compensation on failure.

```python
from hypervisor.saga import SagaOrchestrator

orch = SagaOrchestrator()

# Create a saga
saga = orch.create_saga(session_id="ss-a1b2c3d4")

# Add steps with compensation
step1 = orch.add_step(
    saga_id=saga.saga_id,
    action_id="provision-vm",
    agent_did="did:example:alice",
    execute_api="/infra/provision",
    undo_api="/infra/deprovision",
    timeout_seconds=120,
    max_retries=2,
)

step2 = orch.add_step(
    saga_id=saga.saga_id,
    action_id="deploy-app",
    agent_did="did:example:bob",
    execute_api="/app/deploy",
    undo_api="/app/undeploy",
)

# Execute steps with custom executors
async def provision():
    return {"vm_id": "vm-123"}

await orch.execute_step(saga.saga_id, step1.step_id, provision)

# On failure, compensate all committed steps in reverse order
async def compensator(step):
    print(f"Rolling back {step.action_id}")

compensated = await orch.compensate(saga.saga_id, compensator)
```

**Key Methods**

| Method | Returns | Description |
|--------|---------|-------------|
| `create_saga(session_id)` | `Saga` | Create a new saga |
| `add_step(saga_id, action_id, ...)` | `SagaStep` | Add a step with optional undo |
| `execute_step(saga_id, step_id, executor)` | `Any` | Execute with timeout & retry |
| `compensate(saga_id, compensator)` | `list[SagaStep]` | Roll back committed steps |
| `get_saga(saga_id)` | `Saga | None` | Retrieve saga by ID |

---

#### `SagaDSLParser`

Define sagas declaratively with a JSON/dict DSL.

```python
from hypervisor.saga import SagaDSLParser

parser = SagaDSLParser()

definition = {
    "name": "deploy-pipeline",
    "session_id": "ss-a1b2c3d4",
    "steps": [
        {
            "id": "provision",
            "action_id": "provision-vm",
            "agent": "did:example:alice",
            "execute_api": "/infra/provision",
            "undo_api": "/infra/deprovision",
            "timeout": 120,
            "retries": 2,
        },
        {
            "id": "deploy",
            "action_id": "deploy-app",
            "agent": "did:example:bob",
            "execute_api": "/app/deploy",
            "undo_api": "/app/undeploy",
        },
    ],
}

# Validate before parsing
errors = parser.validate(definition)
assert errors == []

# Parse into a SagaDefinition
saga_def = parser.parse(definition)
steps = parser.to_saga_steps(saga_def)
```

---

#### `CheckpointManager`

Semantic checkpoints for saga progress tracking.

```python
from hypervisor.saga import CheckpointManager

mgr = CheckpointManager()

# Save a checkpoint after a step succeeds
cp = mgr.save(
    saga_id="saga-001",
    step_id="step-001",
    goal_description="VM provisioned successfully",
    state_snapshot={"vm_id": "vm-123"},
)

# Get all checkpoints for a saga
checkpoints = mgr.get_saga_checkpoints("saga-001")

# Build a replay plan (skip already-achieved goals)
replay = mgr.get_replay_plan("saga-001", steps=["step-001", "step-002"])
```

---

#### `FanOutOrchestrator`

Execute saga branches in parallel with configurable completion policies.

```python
from hypervisor.saga import FanOutOrchestrator, FanOutPolicy

fan = FanOutOrchestrator()

# Create a fan-out group
group = fan.create_group(
    saga_id="saga-001",
    policy=FanOutPolicy.MAJORITY_MUST_SUCCEED,
)

# Add parallel branches
fan.add_branch(group.group_id, step_a)
fan.add_branch(group.group_id, step_b)
fan.add_branch(group.group_id, step_c)

# Execute all branches
result = await fan.execute(
    group.group_id,
    executors={"step-a": exec_a, "step-b": exec_b, "step-c": exec_c},
    timeout_seconds=300,
)
print(result.policy_satisfied)  # True if majority succeeded
```

**Fan-Out Policies**

| Policy | Description |
|--------|-------------|
| `ALL_MUST_SUCCEED` | Every branch must complete successfully |
| `MAJORITY_MUST_SUCCEED` | More than half must succeed |
| `ANY_MUST_SUCCEED` | At least one branch must succeed |

---

### Kill Switch

#### `KillSwitch`

Gracefully terminate an agent — hands off in-flight work to substitutes and
triggers saga compensation.

```python
from hypervisor.security import KillSwitch, KillReason

ks = KillSwitch()

# Register a substitute that can take over work
ks.register_substitute(session_id="ss-a1b2c3d4", agent_did="did:example:backup")

# Kill an agent
result = ks.kill(
    agent_did="did:example:bad-actor",
    session_id="ss-a1b2c3d4",
    reason=KillReason.BEHAVIORAL_DRIFT,
    in_flight_steps=[step1, step2],
    details="Embedding drift exceeded 0.3 threshold",
)

print(result.kill_id)                  # Unique kill event ID
print(result.handoff_success_count)    # Steps handed off to substitutes
print(result.compensation_triggered)   # True if saga compensation needed

# Review kill history
for kill in ks.kill_history:
    print(f"{kill.agent_did}: {kill.reason.value}")
```

**Kill Reasons**

| Reason | Description |
|--------|-------------|
| `BEHAVIORAL_DRIFT` | Agent embedding diverged from declared intent |
| `RATE_LIMIT` | Agent exceeded rate limits |
| `RING_BREACH` | Agent attempted actions above its ring |
| `MANUAL` | Operator-initiated kill |
| `QUARANTINE_TIMEOUT` | Agent exceeded quarantine duration |
| `SESSION_TIMEOUT` | Session duration exceeded |

---

#### `RingBreachDetector`

Detects anomalous ring-boundary crossings. Public preview provides stubs;
full anomaly scoring available in the enterprise edition.

```python
from hypervisor.rings import RingBreachDetector, BreachSeverity

detector = RingBreachDetector(window_seconds=60)

# Record a ring call (returns BreachEvent if anomaly detected)
breach = detector.record_call(
    agent_did="did:example:bob",
    session_id="ss-a1b2c3d4",
    ring=2,
    action_id="admin-action",
)

if breach:
    print(breach.severity)       # BreachSeverity enum
    print(breach.anomaly_score)  # 0.0–1.0

print(detector.breach_count)
```

---

### Rate Limiter

#### `AgentRateLimiter`

Per-agent, per-ring token-bucket rate limiting.

```python
from hypervisor.security import AgentRateLimiter, RateLimitExceeded
from hypervisor.models import ExecutionRing

limiter = AgentRateLimiter(
    ring_limits={
        ExecutionRing.RING_1_PRIVILEGED: {"capacity": 100, "refill_rate": 10.0},
        ExecutionRing.RING_2_STANDARD:   {"capacity": 50,  "refill_rate": 5.0},
        ExecutionRing.RING_3_SANDBOX:    {"capacity": 10,  "refill_rate": 1.0},
    }
)

# Check rate limit (raises RateLimitExceeded if rejected)
try:
    limiter.check(
        agent_did="did:example:bob",
        session_id="ss-a1b2c3d4",
        ring=ExecutionRing.RING_2_STANDARD,
        cost=1.0,
    )
except RateLimitExceeded as e:
    print(f"Rate limited: {e}")

# Non-throwing variant
allowed = limiter.try_check(
    agent_did="did:example:bob",
    session_id="ss-a1b2c3d4",
    ring=ExecutionRing.RING_2_STANDARD,
)

# Update ring when agent is promoted/demoted
limiter.update_ring(
    agent_did="did:example:bob",
    session_id="ss-a1b2c3d4",
    new_ring=ExecutionRing.RING_1_PRIVILEGED,
)

# Inspect stats
stats = limiter.get_stats("did:example:bob", "ss-a1b2c3d4")
if stats:
    print(f"Requests: {stats.total_requests}, Rejected: {stats.rejected_requests}")
    print(f"Tokens: {stats.tokens_available}/{stats.capacity}")
```

---

#### `TokenBucket`

Low-level token-bucket used internally by `AgentRateLimiter`.

```python
from hypervisor.security.rate_limiter import TokenBucket

bucket = TokenBucket(capacity=50, tokens=50, refill_rate=5.0)

success = bucket.consume(tokens=1.0)  # True if tokens available
print(bucket.available)               # Current token count
```

---

### Audit & Observability

#### `HypervisorEventBus`

Centralized event bus for all hypervisor events. Subscribe to events or query
the event log.

```python
from hypervisor.observability import HypervisorEventBus, EventType, HypervisorEvent

bus = HypervisorEventBus()

# Subscribe to specific event types
def on_kill(event: HypervisorEvent):
    print(f"Agent killed: {event.agent_did}")

bus.subscribe(event_type=EventType.SECURITY_KILL, handler=on_kill)

# Emit events (usually done by hypervisor internals)
bus.emit(HypervisorEvent(
    event_type=EventType.SESSION_CREATED,
    session_id="ss-a1b2c3d4",
    agent_did="did:example:alice",
    payload={"consistency_mode": "eventual"},
))

# Query events
events = bus.query(
    event_type=EventType.SESSION_CREATED,
    session_id="ss-a1b2c3d4",
    limit=10,
)

# Aggregate stats
print(bus.event_count)
print(bus.type_counts())
```

---

#### `CausalTraceId`

Distributed-tracing–style causal trace IDs for correlating events across
agents and steps.

```python
from hypervisor.observability import CausalTraceId

# Create a root trace
root = CausalTraceId()
print(root.full_id)  # "trace_id:span_id"

# Create child and sibling spans
child = root.child()       # Same trace_id, new span_id, depth + 1
sibling = root.sibling()   # Same trace_id, new span_id, same depth

# Check ancestry
assert root.is_ancestor_of(child)

# Serialize / deserialize
s = root.full_id
restored = CausalTraceId.from_string(s)
```

---

### Joint Liability

#### `VouchingEngine`

Manages sponsorship bonds where trusted agents vouch for newcomers by staking
a fraction of their reputation.

```python
from hypervisor.liability import VouchingEngine

vouching = VouchingEngine(max_exposure=5.0)

# Create a sponsorship bond
record = vouching.vouch(
    voucher_did="did:example:alice",
    vouchee_did="did:example:bob",
    session_id="ss-a1b2c3d4",
    voucher_sigma=0.92,
    bond_pct=0.10,
)
print(record.bonded_amount)  # 0.092 (10% of 0.92)

# Compute the vouchee's effective reputation
eff = vouching.compute_eff_score(
    vouchee_did="did:example:bob",
    session_id="ss-a1b2c3d4",
    vouchee_sigma=0.40,
    risk_weight=0.5,
)
print(eff)  # Boosted score thanks to sponsorship

# Check exposure
exposure = vouching.get_total_exposure("did:example:alice", "ss-a1b2c3d4")

# Release bonds after clean session
released = vouching.release_session_bonds("ss-a1b2c3d4")
```

---

#### `SlashingEngine`

Penalizes misbehaving agents and cascades penalties to their vouchers.

```python
from hypervisor.liability import SlashingEngine

slashing = SlashingEngine(vouching_engine=vouching)

result = slashing.slash(
    vouchee_did="did:example:bad-actor",
    session_id="ss-a1b2c3d4",
    vouchee_sigma=0.60,
    risk_weight=0.8,
    reason="Behavioral drift detected",
    agent_scores={"did:example:bad-actor": 0.60},
    cascade_depth=1,
)

print(result.vouchee_penalty)
for clip in result.voucher_clips:
    print(f"  Voucher {clip.voucher_did} lost {clip.clipped_amount}")
```

---

#### `LiabilityLedger`

Append-only ledger tracking vouches, slashes, quarantines, and clean sessions
per agent. Used for admission control and risk profiling.

```python
from hypervisor.liability import LiabilityLedger, LedgerEntryType

ledger = LiabilityLedger()

# Record events
ledger.record(
    agent_did="did:example:bob",
    entry_type=LedgerEntryType.SLASH_RECEIVED,
    session_id="ss-a1b2c3d4",
    severity=0.8,
    details="Behavioral drift",
)

# Compute risk profile
profile = ledger.compute_risk_profile("did:example:bob")
print(profile.total_slashes)
print(profile.risk_score)

# Admission check
admitted, reason = ledger.should_admit("did:example:bob")
if not admitted:
    print(f"Denied: {reason}")
```

---

#### `QuarantineManager`

Isolates misbehaving agents with optional auto-release timers.

```python
from hypervisor.liability import QuarantineManager, QuarantineReason

qm = QuarantineManager()

# Quarantine an agent
record = qm.quarantine(
    agent_did="did:example:bad-actor",
    session_id="ss-a1b2c3d4",
    reason=QuarantineReason.BEHAVIORAL_DRIFT,
    details="Embedding drift exceeded threshold",
    duration_seconds=300,
)

# Check status
print(qm.is_quarantined("did:example:bad-actor", "ss-a1b2c3d4"))  # True

# Tick to auto-release expired quarantines
expired = qm.tick()

# Manual release
qm.release("did:example:bad-actor", "ss-a1b2c3d4")
```

---

### Classification

#### `ActionClassifier`

Classifies actions into ring levels and risk weights based on their properties.

```python
from hypervisor.rings import ActionClassifier

classifier = ActionClassifier()

result = classifier.classify(
    action_id="deploy-model",
    name="Deploy ML Model",
    execute_api="/models/deploy",
    reversibility="partial",
    is_read_only=False,
    is_admin=False,
)

print(result.ring)           # Required ring level
print(result.risk_weight)    # 0.0–1.0
print(result.reversibility)  # ReversibilityLevel
print(result.confidence)     # Classification confidence

# Override classification for a session
classifier.set_override(
    session_id="ss-a1b2c3d4",
    action_id="deploy-model",
    ring=1,
    risk_weight=0.9,
)
```

---

#### `RingEnforcer`

Validates whether an agent's ring permits a given action.

```python
from hypervisor.rings import RingEnforcer
from hypervisor.models import ExecutionRing, ActionDescriptor, ReversibilityLevel

enforcer = RingEnforcer()

action = ActionDescriptor(
    action_id="delete-data",
    name="Delete Dataset",
    execute_api="/data/delete",
    reversibility=ReversibilityLevel.NONE,
    is_read_only=False,
)

result = enforcer.check(
    agent_ring=ExecutionRing.RING_2_STANDARD,
    action=action,
    eff_score=0.65,
)

print(result.allowed)        # False — irreversible action requires Ring 1
print(result.required_ring)  # ExecutionRing.RING_1_PRIVILEGED
print(result.reason)         # Human-readable explanation
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HYPERVISOR_HOST` | `0.0.0.0` | API server bind address |
| `HYPERVISOR_PORT` | `8000` | API server port |
| `HYPERVISOR_LOG_LEVEL` | `INFO` | Logging level |

### Running the Server

```bash
# Development
uvicorn hypervisor.api.server:app --reload

# Production
uvicorn hypervisor.api.server:app --host 0.0.0.0 --port 8000 --workers 4

# Docker
docker compose up
```

### OpenAPI / Swagger

Interactive API documentation is available at:

- **Swagger UI:** `http://localhost:8000/docs`
- **ReDoc:** `http://localhost:8000/redoc`
