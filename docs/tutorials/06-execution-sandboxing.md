# 🛡️ Tutorial 06 — Execution Sandboxing

**Isolate AI agents at runtime using privilege rings, saga transactions, and kill switches.**

See also: [Deployment Guide](../deployment/README.md) | [Agent Runtime README](../../packages/agent-runtime/README.md)

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Quick Start: Ring-Based Access Control](#2-quick-start-ring-based-access-control)
3. [The 4-Ring Model](#3-the-4-ring-model)
4. [Capability Guards](#4-capability-guards)
5. [Saga Orchestration](#5-saga-orchestration)
6. [Session Isolation](#6-session-isolation)
7. [Emergency Controls](#7-emergency-controls)
8. [Production Deployment](#8-production-deployment)

---

## 1. Introduction

AI agents that can read files, call APIs, and execute code need strict boundaries.
Without sandboxing, a misbehaving agent can:

- **Exfiltrate data** — read secrets and send them to external endpoints.
- **Corrupt state** — write to databases or files it should never touch.
- **Consume resources** — spin up infinite loops that exhaust CPU and memory.
- **Cascade failures** — a failed step in a multi-agent workflow leaves the system in a broken half-finished state.

The **Agent Runtime** (`pip install agentmesh-runtime`) solves this with four
layers of defense:

```
┌─────────────────────────────────────────────────┐
│             Execution Ring Model                │
│  Ring 0 (Root) → Ring 3 (Sandbox)               │
├─────────────────────────────────────────────────┤
│           Capability Guards                     │
│  Per-agent tool allow/deny lists                │
├─────────────────────────────────────────────────┤
│          Saga Orchestration                     │
│  Multi-step transactions with auto-rollback     │
├─────────────────────────────────────────────────┤
│          Session Isolation                      │
│  VFS namespacing, vector clocks, intent locks   │
├─────────────────────────────────────────────────┤
│          Emergency Controls                     │
│  Kill switch, rate limiting, breach detection   │
└─────────────────────────────────────────────────┘
```

### Prerequisites

- Python ≥ 3.11
- `pip install agentmesh-runtime` (v2.0.2+)
- For capability guards: `pip install agent-os-kernel`

---

## 2. Quick Start: Ring-Based Access Control

Get sandboxing running in under 20 lines:

```python
from hypervisor import Hypervisor, ExecutionRing
from hypervisor.rings.classifier import ActionClassifier
from hypervisor.rings.enforcer import RingEnforcer

# 1. Create the runtime
hv = Hypervisor()

# 2. Classify an action — the classifier maps actions to rings
classifier = ActionClassifier()
result = classifier.classify_action_id("file.read")
print(result.ring)        # ExecutionRing.RING_3_SANDBOX
print(result.risk_weight) # 0.1

result = classifier.classify_action_id("deploy.k8s")
print(result.ring)        # ExecutionRing.RING_1_PRIVILEGED
print(result.risk_weight) # 0.9

# 3. Enforce the ring — block agents that lack privilege
enforcer = RingEnforcer()
agent_ring = ExecutionRing.from_eff_score(eff_score=0.72)
print(agent_ring)  # ExecutionRing.RING_2_STANDARD

# Agent in Ring 2 tries a Ring 1 action → blocked
# Agent in Ring 2 tries a Ring 3 action → allowed
```

That's it. The classifier decides which ring an action belongs to, and the
enforcer checks whether the agent's effective score grants sufficient privilege.

---

## 3. The 4-Ring Model

The runtime uses a hardware-inspired 4-ring privilege model. Each ring
defines what an agent can do, how many calls it can make, and what level of
trust is required.

```
        ┌───────────────────────┐
        │   Ring 0 — Root       │  eff_score: N/A (SRE Witness required)
        │   Runtime config,     │  Penalty/slashing operations
        │   penalty ops         │  Rate: unlimited
        ├───────────────────────┤
        │   Ring 1 — Privileged │  eff_score ≥ 0.95 + consensus
        │   Non-reversible ops  │  Write, deploy, delete
        │   (deploy, delete)    │  Rate: 1000 calls/min
        ├───────────────────────┤
        │   Ring 2 — Standard   │  eff_score ≥ 0.60
        │   Reversible actions  │  Read + limited write
        │   (write files, APIs) │  Rate: 100 calls/min
        ├───────────────────────┤
        │   Ring 3 — Sandbox    │  Default for unknown agents
        │   Read-only, research │  No network, no writes
        │   (safe exploration)  │  Rate: 10 calls/min
        └───────────────────────┘
```

### 3.1 Ring Assignment from Effective Score

The `ExecutionRing` enum maps directly from an agent's **effective score**
(`eff_score`), which combines trust, reputation, and behavioral signals:

```python
from hypervisor.models import ExecutionRing

# Ring assignment is automatic based on eff_score
ring = ExecutionRing.from_eff_score(eff_score=0.98, has_consensus=True)
assert ring == ExecutionRing.RING_1_PRIVILEGED

ring = ExecutionRing.from_eff_score(eff_score=0.75)
assert ring == ExecutionRing.RING_2_STANDARD

ring = ExecutionRing.from_eff_score(eff_score=0.40)
assert ring == ExecutionRing.RING_3_SANDBOX
```

> **Note:** Ring 0 is never assigned by score alone — it requires an SRE
> Witness attestation and is reserved for runtime-level configuration.

### 3.2 Action Classification

Every action is classified by **risk weight** and **reversibility** to determine
which ring it requires:

```python
from hypervisor.rings.classifier import ActionClassifier, ClassificationResult
from hypervisor.models import ReversibilityLevel

classifier = ActionClassifier()

# Read operations → Ring 3 (low risk, fully reversible)
result = classifier.classify_action_id("file.read")
assert result.ring == ExecutionRing.RING_3_SANDBOX
assert result.reversibility == ReversibilityLevel.REVERSIBLE

# Write operations → Ring 2 (medium risk, reversible with effort)
result = classifier.classify_action_id("file.write")
assert result.ring == ExecutionRing.RING_2_STANDARD

# Deployments → Ring 1 (high risk, non-reversible)
result = classifier.classify_action_id("deploy.k8s")
assert result.ring == ExecutionRing.RING_1_PRIVILEGED
assert result.reversibility == ReversibilityLevel.NON_REVERSIBLE

# Override classification for custom actions
classifier.set_override("my_custom.action", ring=ExecutionRing.RING_2_STANDARD, risk_weight=0.5)
```

### 3.3 Ring Elevation (Privilege Escalation)

Sometimes an agent needs temporary access to a higher ring. The
`RingElevationManager` handles time-bounded privilege escalation:

```python
from hypervisor.rings.elevation import (
    RingElevationManager,
    RingElevation,
    ElevationDenialReason,
)

manager = RingElevationManager()

# Request elevation from Ring 2 → Ring 1
elevation = manager.request_elevation(
    agent_did="did:example:agent-42",
    session_id="session-001",
    current_ring=ExecutionRing.RING_2_STANDARD,
    target_ring=ExecutionRing.RING_1_PRIVILEGED,
    ttl_seconds=300,  # 5-minute window (max: 3600s)
    reason="Deploying approved release v2.1.0",
    attestation="signed-approval-token-from-sre",
)

if elevation.is_active:
    # Agent now has Ring 1 privileges for 5 minutes
    effective = manager.get_effective_ring(
        agent_did="did:example:agent-42",
        session_id="session-001",
        base_ring=ExecutionRing.RING_2_STANDARD,
    )
    assert effective == ExecutionRing.RING_1_PRIVILEGED

# Revoke early if needed
manager.revoke_elevation(elevation.elevation_id)
```

> **Community Edition:** Elevation requests are always denied. The denial
> reason is `ElevationDenialReason.COMMUNITY_EDITION`. Upgrade to Enterprise
> for dynamic ring escalation.

### 3.4 Breach Detection

The `RingBreachDetector` monitors for agents attempting actions above their
ring level:

```python
from hypervisor.rings.breach_detector import (
    RingBreachDetector,
    BreachEvent,
    BreachSeverity,
)

detector = RingBreachDetector()

# The detector fires events when an agent in Ring 3 attempts a Ring 1 action
# Severity depends on the gap between agent ring and action ring:
#   1-ring gap  → WARNING
#   2-ring gap  → HIGH
#   3-ring gap  → CRITICAL (Ring 3 agent trying Ring 0 action)
```

---

## 4. Capability Guards

While rings control *privilege levels*, **Capability Guards** control *which
specific tools* an agent can call. This is a second, orthogonal layer of defense.

The `CapabilityGuardMiddleware` (from `agent-os`) enforces per-agent tool
allow/deny lists:

```python
from agent_os.integrations.maf_adapter import (
    CapabilityGuardMiddleware,
    GovernancePolicyMiddleware,
    create_governance_middleware,
)

# Option 1: Explicit allow list (whitelist) — only these tools are permitted
guard = CapabilityGuardMiddleware(
    allowed_tools=["web_search", "file_read", "calculator"],
)

# Option 2: Deny list (blacklist) — everything except these tools
guard = CapabilityGuardMiddleware(
    denied_tools=["execute_code", "delete_file", "send_email"],
)

# Option 3: Factory function for full governance stack
middleware = create_governance_middleware(
    policy_directory="policies/",
    allowed_tools=["web_search", "file_read"],
    denied_tools=["execute_code", "delete_file"],
    enable_rogue_detection=True,
)
```

### 4.1 Per-Ring Tool Restrictions

Combine rings with capability guards for defense-in-depth:

```python
from hypervisor.models import ExecutionRing
from agent_os.integrations.maf_adapter import CapabilityGuardMiddleware

# Define tool sets per ring
RING_TOOL_POLICIES = {
    ExecutionRing.RING_3_SANDBOX: CapabilityGuardMiddleware(
        allowed_tools=["web_search", "file_read"],
    ),
    ExecutionRing.RING_2_STANDARD: CapabilityGuardMiddleware(
        allowed_tools=["web_search", "file_read", "file_write", "api_call"],
        denied_tools=["delete_file", "execute_code"],
    ),
    ExecutionRing.RING_1_PRIVILEGED: CapabilityGuardMiddleware(
        denied_tools=["drop_database"],  # everything else allowed
    ),
    ExecutionRing.RING_0_ROOT: CapabilityGuardMiddleware(
        # No restrictions — full access
    ),
}

def get_guard_for_agent(eff_score: float) -> CapabilityGuardMiddleware:
    """Return the capability guard matching an agent's privilege ring."""
    ring = ExecutionRing.from_eff_score(eff_score)
    return RING_TOOL_POLICIES[ring]
```

### 4.2 Integrating with an Agent Framework

```python
from agent_os.integrations.maf_adapter import (
    create_governance_middleware,
    AuditTrailMiddleware,
    RogueDetectionMiddleware,
)

# Full governance middleware stack: policy + capability guard + audit + rogue detection
middleware = create_governance_middleware(
    policy_directory="policies/",
    allowed_tools=["web_search", "file_read"],
    denied_tools=["execute_code"],
    enable_rogue_detection=True,
)

# Attach to your agent framework — the middleware intercepts every tool call
# and blocks anything not in the allow list (or in the deny list)
```

---

## 5. Saga Orchestration

Multi-step agent workflows are dangerous: if step 3 of 5 fails, you're left
with a half-finished state. The **Saga Orchestrator** wraps multi-step
workflows in transactions with automatic compensation (rollback).

### 5.1 Core Concepts

```
Step 1: Create PR          ──→  Compensate: Close PR
Step 2: Run tests          ──→  Compensate: Cancel test run
Step 3: Deploy to staging  ──→  Compensate: Rollback deployment
Step 4: Notify team        ──→  Compensate: Send failure notice

If Step 3 fails:
  → Compensate Step 2 (cancel tests)
  → Compensate Step 1 (close PR)
  → Saga state: COMPENSATING → FAILED
```

### 5.2 Creating a Saga

```python
from hypervisor.saga.orchestrator import SagaOrchestrator
from hypervisor.saga.state_machine import SagaState, StepState

orchestrator = SagaOrchestrator()

# Create a new saga for this session
saga = orchestrator.create_saga(session_id="session-deploy-42")

# Add steps with execute and undo APIs
orchestrator.add_step(
    saga_id=saga.saga_id,
    action_id="pr.create",
    agent_did="did:example:dev-agent",
    execute_api="/api/pr/create",
    undo_api="/api/pr/close",        # compensation action
    timeout_seconds=60,
    max_retries=2,
)

orchestrator.add_step(
    saga_id=saga.saga_id,
    action_id="tests.run",
    agent_did="did:example:ci-agent",
    execute_api="/api/tests/run",
    undo_api="/api/tests/cancel",
    timeout_seconds=300,
    max_retries=1,
)

orchestrator.add_step(
    saga_id=saga.saga_id,
    action_id="deploy.staging",
    agent_did="did:example:deploy-agent",
    execute_api="/api/deploy/staging",
    undo_api="/api/deploy/rollback",
    timeout_seconds=600,
)
```

### 5.3 Step and Saga State Machines

Each step transitions through a well-defined state machine:

```
StepState flow:
  PENDING → EXECUTING → COMMITTED
                     ↘ FAILED → COMPENSATING → COMPENSATED
                                            ↘ COMPENSATION_FAILED
```

The saga itself tracks the aggregate state:

```python
from hypervisor.saga.state_machine import SagaState, StepState, STEP_TRANSITIONS

# Valid step transitions are enforced — invalid transitions raise errors
step = SagaStep(step_id="s1", action_id="pr.create", ...)
step.transition(StepState.EXECUTING)   # PENDING → EXECUTING ✓
step.transition(StepState.COMMITTED)   # EXECUTING → COMMITTED ✓
# step.transition(StepState.PENDING)   # COMMITTED → PENDING ✗ (raises error)
```

Saga-level states:

| State | Meaning |
|-------|---------|
| `RUNNING` | Steps are being executed sequentially |
| `COMPENSATING` | A step failed; compensation is running in reverse |
| `COMPLETED` | All steps committed successfully |
| `FAILED` | All compensation finished (or some compensation failed) |
| `ESCALATED` | Compensation itself failed; human intervention required |

### 5.4 Declarative Sagas with the DSL

For complex workflows, define sagas declaratively:

```python
from hypervisor.saga.dsl import SagaDSLParser, SagaDefinition

saga_yaml = """
saga:
  id: deploy-pipeline
  steps:
    - id: create-pr
      action_id: pr.create
      agent: did:example:dev-agent
      execute_api: /api/pr/create
      undo_api: /api/pr/close
      timeout: 60
      retries: 2

    - id: run-tests
      action_id: tests.run
      agent: did:example:ci-agent
      execute_api: /api/tests/run
      undo_api: /api/tests/cancel
      timeout: 300
      depends_on: [create-pr]

    - id: deploy-staging
      action_id: deploy.staging
      agent: did:example:deploy-agent
      execute_api: /api/deploy/staging
      undo_api: /api/deploy/rollback
      timeout: 600
      depends_on: [run-tests]
      checkpoint_goal: "Staging deployment matches PR diff"
"""

parser = SagaDSLParser()
definition: SagaDefinition = parser.parse(saga_yaml)
```

### 5.5 Semantic Checkpoints

Checkpoints verify that each step actually achieved its goal, not just that
it returned HTTP 200:

```python
from hypervisor.saga.checkpoint import CheckpointManager, SemanticCheckpoint

checkpoint_mgr = CheckpointManager()

# After a deploy step, verify the deployment actually happened
checkpoint = SemanticCheckpoint(
    step_id="deploy-staging",
    goal="Staging deployment matches PR diff",
)
# The checkpoint manager evaluates whether the goal was met
```

### 5.6 Fan-Out Orchestration

For parallel step execution (e.g., deploy to multiple regions simultaneously):

```python
from hypervisor.saga.fan_out import FanOutOrchestrator, FanOutPolicy

fan_out = FanOutOrchestrator()

# Execute the same action across multiple agents in parallel
# with configurable failure policies (fail-fast, best-effort, quorum)
```

---

## 6. Session Isolation

When multiple agents collaborate in a shared session, each agent gets an
**isolated view** of the workspace. No agent can read or modify another agent's
files without explicit sharing.

### 6.1 Virtual File System (VFS) Namespacing

The `SessionVFS` provides per-agent isolated file views within a shared session:

```python
from hypervisor.session.sso import SessionVFS, VFSPermissionError

vfs = SessionVFS()

# Agent A writes a file — only Agent A can see it
vfs.write(path="/workspace/plan.md", agent_did="did:agent-a", value="# My Plan")

# Agent A reads its own file — works fine
content = vfs.read(path="/workspace/plan.md", agent_did="did:agent-a")
assert content == "# My Plan"

# Agent B tries to read Agent A's file — blocked
try:
    vfs.read(path="/workspace/plan.md", agent_did="did:agent-b")
except VFSPermissionError:
    print("Access denied: Agent B cannot read Agent A's namespace")

# Agent B writes to the same path — it gets its own copy
vfs.write(path="/workspace/plan.md", agent_did="did:agent-b", value="# Different Plan")

# Each agent sees its own version
assert vfs.read("/workspace/plan.md", "did:agent-a") == "# My Plan"
assert vfs.read("/workspace/plan.md", "did:agent-b") == "# Different Plan"

# Delete is also scoped
vfs.delete(path="/workspace/plan.md", agent_did="did:agent-a")
```

### 6.2 Isolation Levels

Choose the right isolation level based on your consistency requirements:

```python
from hypervisor.session.isolation import IsolationLevel

# Snapshot — each agent sees a consistent snapshot (cheapest)
level = IsolationLevel.SNAPSHOT
assert not level.requires_vector_clocks
assert not level.requires_intent_locks
assert level.allows_concurrent_writes
assert level.coordination_cost == "low"

# Read Committed — agents see committed writes from others
level = IsolationLevel.READ_COMMITTED
assert level.requires_vector_clocks
assert not level.requires_intent_locks

# Serializable — strongest consistency (most expensive)
level = IsolationLevel.SERIALIZABLE
assert level.requires_vector_clocks
assert level.requires_intent_locks
assert not level.allows_concurrent_writes
assert level.coordination_cost == "high"
```

### 6.3 Vector Clocks for Causal Ordering

When agents produce concurrent writes, vector clocks establish a causal order:

```python
from hypervisor.session.vector_clock import VectorClockManager, CausalViolationError

clock_mgr = VectorClockManager()

# Each agent gets its own logical clock
clock_a = clock_mgr.create_clock("did:agent-a")
clock_b = clock_mgr.create_clock("did:agent-b")

# Agent A performs an action
clock_mgr.increment("did:agent-a")

# Check causal ordering — did A's action happen before B's?
happened_before = clock_mgr.happens_before(clock_a, clock_b)
```

### 6.4 Intent Locks for Concurrency Control

Prevent conflicting concurrent operations with intent locks:

```python
from hypervisor.session.intent_locks import IntentLockManager, LockIntent, DeadlockError

lock_mgr = IntentLockManager()

# Agent A acquires a write lock on the session
lock_mgr.acquire_lock(
    session_id="session-001",
    agent_did="did:agent-a",
    intent=LockIntent.WRITE,
)

# Agent B tries an exclusive lock — blocked until A releases
try:
    lock_mgr.acquire_lock(
        session_id="session-001",
        agent_did="did:agent-b",
        intent=LockIntent.EXCLUSIVE,
    )
except DeadlockError:
    print("Deadlock detected — aborting Agent B's operation")

# Release when done
lock_mgr.release_lock(session_id="session-001", agent_did="did:agent-a")
```

### 6.5 Full Session Configuration

Bring it all together with a `SharedSessionObject`:

```python
from hypervisor.session import SharedSessionObject
from hypervisor.models import SessionConfig, ConsistencyMode

config = SessionConfig(
    consistency_mode=ConsistencyMode.SERIALIZABLE,
    max_participants=5,
    max_duration_seconds=3600,  # 1 hour
    min_eff_score=0.60,         # minimum trust to join
)

session = SharedSessionObject(
    session_id="session-deploy-42",
    config=config,
)

# Session provides:
#   session.vfs           — SessionVFS (isolated file views)
#   session.vector_clocks — VectorClockManager (causal ordering)
#   session.intent_locks  — IntentLockManager (concurrency control)
```

---

## 7. Emergency Controls

When an agent goes rogue, you need to stop it *immediately* — not after the
next polling interval.

### 7.1 Kill Switch

The `KillSwitch` terminates an agent and triggers saga compensation for any
in-flight work:

```python
from hypervisor.security.kill_switch import KillSwitch, KillReason, KillResult

kill_switch = KillSwitch()

# Immediate termination — all in-flight saga steps are compensated
result: KillResult = kill_switch.kill(
    agent_did="did:example:rogue-agent",
    session_id="session-001",
    reason=KillReason.BEHAVIORAL_DRIFT,
    details="Agent started accessing files outside its namespace",
)

print(f"Kill ID:              {result.kill_id}")
print(f"Compensation triggered: {result.compensation_triggered}")
print(f"Handoffs succeeded:    {result.handoff_success_count}")
print(f"Timestamp:             {result.timestamp}")
```

Available kill reasons:

| Reason | When to use |
|--------|-------------|
| `BEHAVIORAL_DRIFT` | Agent deviates from expected behavior patterns |
| `RATE_LIMIT` | Agent exceeded its rate limit repeatedly |
| `RING_BREACH` | Agent attempted actions above its ring level |
| `MANUAL` | Human operator triggered the kill |
| `QUARANTINE_TIMEOUT` | Agent was quarantined and didn't recover |
| `SESSION_TIMEOUT` | Session exceeded its `max_duration_seconds` |

### 7.2 Graceful Shutdown with Handoff

Before killing, you can register substitute agents to take over in-flight work:

```python
from hypervisor.security.kill_switch import KillSwitch, HandoffStatus

kill_switch = KillSwitch()

# Register a substitute agent that can take over work
kill_switch.register_substitute(
    session_id="session-001",
    agent_did="did:example:backup-agent",
)

# Now when the primary agent is killed, its saga steps are handed off
result = kill_switch.kill(
    agent_did="did:example:primary-agent",
    session_id="session-001",
    reason=KillReason.MANUAL,
    details="Planned maintenance rotation",
)

# Check handoff results
for handoff in result.handoffs:
    print(f"Step {handoff.step_id}: {handoff.status}")
    # HandoffStatus: PENDING, HANDED_OFF, FAILED, COMPENSATED

# Review kill history
history = kill_switch.get_kill_history(agent_did="did:example:primary-agent")
```

### 7.3 Rate Limiting

Prevent resource exhaustion with per-agent rate limits:

```python
from hypervisor.security.rate_limiter import AgentRateLimiter, RateLimitExceeded

# Ring 3 agents: 10 calls per minute
sandbox_limiter = AgentRateLimiter(
    window_seconds=60.0,
    max_calls=10,
)

# Ring 2 agents: 100 calls per minute
standard_limiter = AgentRateLimiter(
    window_seconds=60.0,
    max_calls=100,
)

# Check before each action
status = sandbox_limiter.check_rate_limit(agent_did="did:example:new-agent")
if not status.allowed:
    print(f"Rate limited — retry after {status.retry_after_seconds}s")

# Reset limits (e.g., after an agent is promoted)
sandbox_limiter.reset(agent_did="did:example:new-agent")
```

### 7.4 Quarantine

Quarantine isolates an agent without killing it — useful for investigation:

```python
from hypervisor.liability.quarantine import QuarantineManager, QuarantineReason

quarantine = QuarantineManager()

# Quarantine a suspect agent — it can't take new actions but existing
# saga steps are preserved for forensic analysis
```

### 7.5 Breach Detection Pipeline

Wire breach detection into your kill switch for automated response:

```python
from hypervisor.rings.breach_detector import RingBreachDetector, BreachSeverity
from hypervisor.security.kill_switch import KillSwitch, KillReason
from hypervisor.security.rate_limiter import AgentRateLimiter

detector = RingBreachDetector()
kill_switch = KillSwitch()
limiter = AgentRateLimiter(window_seconds=60.0, max_calls=100)

async def on_agent_action(agent_did: str, session_id: str, action_id: str):
    """Example enforcement pipeline for every agent action."""

    # Layer 1: Rate limit check
    status = limiter.check_rate_limit(agent_did)
    if not status.allowed:
        kill_switch.kill(agent_did, session_id, KillReason.RATE_LIMIT)
        return

    # Layer 2: Ring enforcement (breach detection)
    # If a breach is CRITICAL severity → kill immediately
    # If WARNING → log and allow (the agent might be testing boundaries)

    # Layer 3: Capability guard check (handled by middleware)
    # Layer 4: Saga step execution (handled by orchestrator)
```

---

## 8. Production Deployment

### 8.1 Running the Runtime API Server

The runtime includes a FastAPI server for HTTP-based enforcement:

```bash
# Install with API extras
pip install "agentmesh-runtime[api]"

# Start the server
hypervisor serve --host 0.0.0.0 --port 8000
```

### 8.2 Docker Container

```dockerfile
FROM python:3.11-slim

WORKDIR /app

RUN pip install "agentmesh-runtime[full,api]"

EXPOSE 8000

CMD ["hypervisor", "serve", "--host", "0.0.0.0", "--port", "8000"]
```

Build and run:

```bash
docker build -t agent-runtime:latest .
docker run -p 8000:8000 agent-runtime:latest
```

### 8.3 Kubernetes Deployment

Deploy the runtime as a sidecar alongside your agent pods:

```yaml
# runtime-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agent-runtime
  labels:
    app: agent-runtime
spec:
  replicas: 2
  selector:
    matchLabels:
      app: agent-runtime
  template:
    metadata:
      labels:
        app: agent-runtime
    spec:
      containers:
        - name: runtime
          image: agent-runtime:latest
          ports:
            - containerPort: 8000
          resources:
            requests:
              memory: "256Mi"
              cpu: "250m"
            limits:
              memory: "512Mi"
              cpu: "500m"
          readinessProbe:
            httpGet:
              path: /health
              port: 8000
            initialDelaySeconds: 5
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /health
              port: 8000
            initialDelaySeconds: 10
            periodSeconds: 30
          env:
            - name: HYPERVISOR_LOG_LEVEL
              value: "INFO"
---
apiVersion: v1
kind: Service
metadata:
  name: agent-runtime
spec:
  selector:
    app: agent-runtime
  ports:
    - port: 8000
      targetPort: 8000
```

### 8.4 Sidecar Pattern

For fine-grained per-pod enforcement, run the runtime as a sidecar:

```yaml
# agent-pod-with-sidecar.yaml
apiVersion: v1
kind: Pod
metadata:
  name: agent-worker
spec:
  containers:
    # Your agent container
    - name: agent
      image: my-agent:latest
      env:
        - name: HYPERVISOR_URL
          value: "http://localhost:8000"

    # Runtime sidecar — enforces sandboxing for this pod
    - name: runtime-sidecar
      image: agent-runtime:latest
      ports:
        - containerPort: 8000
      resources:
        requests:
          memory: "128Mi"
          cpu: "100m"
        limits:
          memory: "256Mi"
          cpu: "250m"
```

### 8.5 Helm Chart Values

Create a values file for parameterized deployments:

```yaml
# values.yaml
replicaCount: 2

image:
  repository: agent-runtime
  tag: "latest"
  pullPolicy: IfNotPresent

service:
  type: ClusterIP
  port: 8000

resources:
  requests:
    memory: "256Mi"
    cpu: "250m"
  limits:
    memory: "512Mi"
    cpu: "500m"

runtime:
  logLevel: INFO
  rateLimiting:
    ring3MaxCalls: 10
    ring2MaxCalls: 100
    ring1MaxCalls: 1000
    windowSeconds: 60
  session:
    maxDurationSeconds: 3600
    maxParticipants: 10
    defaultIsolation: snapshot
  saga:
    defaultTimeoutSeconds: 300
    maxRetries: 2
```

### 8.6 Observability

Monitor your runtime with the built-in event bus:

```python
from hypervisor.observability.event_bus import HypervisorEventBus, EventType
from hypervisor.observability.causal_trace import CausalTraceId

event_bus = HypervisorEventBus()

# Subscribe to security events
@event_bus.subscribe(EventType.RING_BREACH)
async def on_breach(event):
    print(f"BREACH: {event.agent_did} attempted {event.action_id}")

@event_bus.subscribe(EventType.KILL_SWITCH)
async def on_kill(event):
    print(f"KILLED: {event.agent_did} — reason: {event.reason}")

# Trace causality across distributed saga steps
trace_id = CausalTraceId.generate()
```

---

## Summary

| Layer | Component | What It Does |
|-------|-----------|--------------|
| **Privilege** | `ExecutionRing` | 4-tier access model based on trust score |
| **Privilege** | `ActionClassifier` | Maps actions to rings by risk/reversibility |
| **Privilege** | `RingElevationManager` | Temporary privilege escalation with TTL |
| **Detection** | `RingBreachDetector` | Alerts on ring boundary violations |
| **Tools** | `CapabilityGuardMiddleware` | Per-agent tool allow/deny lists |
| **Transactions** | `SagaOrchestrator` | Multi-step workflows with auto-rollback |
| **Isolation** | `SessionVFS` | Per-agent virtual file system namespacing |
| **Isolation** | `IntentLockManager` | Concurrency control with intent locks |
| **Isolation** | `VectorClockManager` | Causal ordering of concurrent operations |
| **Emergency** | `KillSwitch` | Immediate agent termination |
| **Emergency** | `AgentRateLimiter` | Per-agent call rate enforcement |
| **Emergency** | `QuarantineManager` | Agent isolation for investigation |
| **Observability** | `HypervisorEventBus` | Real-time event streaming |

---

## Next Steps

- **Audit trails:** Explore `CommitmentEngine` and `DeltaEngine` for hash-chained, tamper-evident logging.
- **Liability:** See `LiabilityMatrix`, `CausalAttributor`, and `SlashingEngine` for agent accountability.
- **Deployment:** Read the [Azure Container Apps guide](../deployment/azure-container-apps.md) for cloud-native deployment patterns.
