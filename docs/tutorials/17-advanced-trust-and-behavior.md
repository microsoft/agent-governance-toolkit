# Tutorial 17 — Advanced Trust & Behavior Monitoring

> **Package:** `agentmesh-platform` · **Time:** 35 minutes · **Prerequisites:** Python 3.11+

---

## Dynamic Trust Management Through Observed Behavior

**Prerequisites:** `pip install agentmesh-platform`
**Modules:** `agentmesh.services.reward_engine`, `agentmesh.services.behavior_monitor`, `agentmesh.governance.trust_policy`, `agentmesh.services.audit`, `agentmesh.services.registry`

---

## What You'll Learn

Tutorial 02 introduced trust scores and identity. This tutorial goes further —
trust is no longer a static value an operator assigns. It is a **living metric**
that rises and falls with every tool call, policy check, handshake, and security
event the agent produces.

| Topic | What It Covers |
|-------|---------------|
| **RewardService** | Five-dimension scoring engine; task success/failure; automatic revocation |
| **AgentBehaviorMonitor** | Burst detection, consecutive-failure tracking, capability-denial quarantine |
| **TrustPolicyEngine** | Declarative YAML rules with condition operators and priority ordering |
| **Shadow Mode** | Simulate agent execution without side effects; capture reasoning chains |
| **AuditService & AuditChain** | Merkle-tree audit log with hash-chained, tamper-proof entries |
| **AgentRegistry** | Persistent agent metadata with trust tiers and aggregate statistics |
| **NetworkTrustEngine** | Temporal decay, trust propagation across agent graphs, regime detection |

By the end you will be able to wire these components together so that agent
trust adjusts in real time, risky agents are quarantined automatically, and
every decision is captured in a cryptographically verifiable audit trail.

---

## Installation

```bash
pip install agentmesh-platform
```

All modules used in this tutorial ship with the `agentmesh-platform` package.
No additional dependencies are required.

---

## 1. Quick Start — Monitor Behavior and Update Trust

```python
from agentmesh.services.reward_engine import RewardService
from agentmesh.services.behavior_monitor import AgentBehaviorMonitor
from agentmesh.services.audit import AuditService

AGENT = "did:mesh:analyst-001"

# --- Behavior monitor: detects anomalous runtime patterns ---
monitor = AgentBehaviorMonitor(
    burst_threshold=100,           # max calls per window
    burst_window_seconds=60,       # sliding window size
    consecutive_failure_threshold=20,
    capability_denial_threshold=10,
)

# --- Reward service: multi-dimension trust scoring ---
reward = RewardService()

# --- Audit service: tamper-proof event log ---
audit = AuditService()

# Record a successful tool invocation
monitor.record_tool_call(AGENT, "file_read", success=True)
reward.record_task_success(AGENT, task_id="task-42")
audit.log_action(AGENT, action="file_read", outcome="success")

score = reward.get_score(AGENT)
print(score.total_score)  # 500+ (default boosted by success signals)
print(score.tier)         # "standard"

# Record a failure — score decreases
reward.record_task_failure(AGENT, reason="timeout")
monitor.record_tool_call(AGENT, "db_write", success=False)
audit.log_action(AGENT, action="db_write", outcome="failure")

print(reward.get_score(AGENT).total_score)  # slightly lower
```

That is the core loop: **observe → score → audit**. The following sections
explain each component in detail.

---

## 2. RewardService — Trust Scores from Behavioral Signals

The `RewardService` is a convenience wrapper around the lower-level
`RewardEngine`. It exposes simple methods for common events while the engine
handles the multi-dimensional math underneath.

### 2.1 Architecture

Five dimensions feed the score, each with a configurable weight:

| Dimension | Weight | Signal Source |
|-----------|--------|---------------|
| `POLICY_COMPLIANCE` | 0.25 | Policy engine evaluations |
| `RESOURCE_EFFICIENCY` | 0.15 | Token/compute budget adherence |
| `OUTPUT_QUALITY` | 0.20 | Downstream consumer acceptance |
| `SECURITY_POSTURE` | 0.25 | Boundary-crossing security events |
| `COLLABORATION_HEALTH` | 0.15 | Peer handshake success rate |

Individual dimension scores use an **exponential moving average** (EMA, α = 0.1),
giving recent signals more influence while smoothing over noise.

### 2.2 Creating a RewardService

```python
from agentmesh.services.reward_engine import RewardService
from agentmesh.reward.engine import RewardConfig

config = RewardConfig(
    revocation_threshold=300,        # auto-revoke below this score
    warning_threshold=500,           # emit warnings below this score
    policy_compliance_weight=0.25,
    resource_efficiency_weight=0.15,
    output_quality_weight=0.20,
    security_posture_weight=0.25,
    collaboration_health_weight=0.15,
)

reward = RewardService(config=config)
```

### 2.3 Recording Signals

```python
AGENT = "did:mesh:worker-007"

reward.record_task_success(AGENT, task_id="task-99")        # policy + quality ↑
reward.record_task_failure(AGENT, reason="Rate limit exceeded")  # quality ↓
reward.record_policy_violation(AGENT, policy_name="no-external-api")
reward.record_handshake(AGENT, peer_did="did:mesh:peer-003", success=True)
reward.record_security_event(AGENT, within_boundary=True, event_type="data_access")
reward.record_security_event(AGENT, within_boundary=False, event_type="egress_attempt")
```

Under the hood, `record_task_success` sends **two** positive signals —
`POLICY_COMPLIANCE(1.0)` and `OUTPUT_QUALITY(1.0)`. A failure sends one
negative signal — `OUTPUT_QUALITY(0.0)` with the rejection reason.

### 2.4 Reading Scores and Explanations

```python
score = reward.get_score(AGENT)

print(score.total_score)     # 0–1000
print(score.tier)            # "verified_partner" | "trusted" | "standard"
                             # | "probationary" | "untrusted"
print(score.score_change)    # delta since last calculation

# Detailed breakdown
explanation = reward.engine.get_score_explanation(AGENT)
for dim_name, dim_info in explanation["dimensions"].items():
    print(f"  {dim_name}: score={dim_info['score']:.1f}  "
          f"signals={dim_info['signal_count']}  "
          f"contribution={dim_info['contribution']:.1f}")

print(f"Trend: {explanation['trend']}")  # "improving" | "stable" | "degrading"
```

### 2.5 Trust Tier Thresholds

| Tier | Score Range | Meaning |
|------|-------------|---------|
| `verified_partner` | ≥ 900 | Highly trusted; extended capabilities |
| `trusted` | 700 – 899 | Strong track record |
| `standard` | 400 – 699 | Default starting tier |
| `probationary` | 200 – 399 | Under observation |
| `untrusted` | 0 – 199 | Capabilities restricted |

When a score drops below the **revocation threshold** (default 300) the engine
automatically marks the agent as revoked and fires any registered callbacks:

```python
def on_agent_revoked(agent_did: str, reason: str):
    print(f"REVOKED: {agent_did} — {reason}")

reward.on_revocation(on_agent_revoked)
```

### 2.6 Querying At-Risk Agents

```python
# Agents approaching revocation
at_risk = reward.engine.get_agents_at_risk()
print(at_risk)  # ["did:mesh:risky-agent"]

# Agents already below a custom threshold
below = reward.agents_below_threshold(threshold=400)

# Full summary across all tracked agents
summary = reward.summary()
print(summary)
# {"total_agents": 12, "avg_score": 623.4, "min_score": 310, "max_score": 890}
```

### 2.7 Health Reports

```python
report = reward.engine.get_health_report(days=7)

print(report["total_agents"])
print(report["revoked_agents"])
print(report["at_risk_agents"])

for did, info in report["agents"].items():
    print(f"{did}: current={info['current_score']}  "
          f"trend={info['trend']}  revoked={info['revoked']}")
```

---

## 3. AgentBehaviorMonitor — Runtime Anomaly Detection

While the `RewardService` evaluates *quality* signals, the
`AgentBehaviorMonitor` catches *operational anomalies* — patterns that indicate
a misbehaving or compromised agent.

### 3.1 What It Tracks

| Signal | Detection Method | Quarantine Trigger |
|--------|------------------|--------------------|
| **Tool-call bursts** | Rolling timestamp window | Exceeds `burst_threshold` calls in `burst_window_seconds` |
| **Consecutive failures** | Counter; resets on success | Reaches `consecutive_failure_threshold` |
| **Capability denials** | Cumulative counter | Reaches `capability_denial_threshold` |

### 3.2 Creating a Monitor

```python
from datetime import timedelta
from agentmesh.services.behavior_monitor import AgentBehaviorMonitor

monitor = AgentBehaviorMonitor(
    burst_window_seconds=60,
    burst_threshold=100,
    consecutive_failure_threshold=20,
    capability_denial_threshold=10,
    quarantine_duration=timedelta(minutes=15),
    max_tracked_agents=50_000,  # LRU eviction when exceeded
)
```

### 3.3 Recording Events

```python
AGENT = "did:mesh:worker-007"

# Successful tool call — resets consecutive-failure counter
monitor.record_tool_call(AGENT, "file_read", success=True)

# Failed tool call — increments consecutive-failure counter
monitor.record_tool_call(AGENT, "db_write", success=False)

# Capability denial — agent tried to access something it shouldn't
monitor.record_capability_denial(AGENT, capability="write:secrets")
```

### 3.4 Quarantine

When any threshold is breached the agent is automatically quarantined:

```python
# Simulate 21 consecutive failures
for _ in range(21):
    monitor.record_tool_call(AGENT, "flaky_api", success=False)

print(monitor.is_quarantined(AGENT))  # True

metrics = monitor.get_metrics(AGENT)
print(metrics.quarantine_reason)
# "Consecutive failure threshold breached (21 >= 20)"
print(metrics.quarantined_at)
# 2025-01-15T10:32:00+00:00
```

Quarantines auto-release after `quarantine_duration` (default 15 minutes).
You can also release manually:

```python
monitor.release_quarantine(AGENT)
print(monitor.is_quarantined(AGENT))  # False
```

### 3.5 Burst Detection

The monitor keeps a **rolling window** of call timestamps. Old timestamps
outside the window are pruned on each call:

```python
# If an agent fires 101 calls in 60 seconds:
for i in range(101):
    monitor.record_tool_call(AGENT, "search", success=True)

print(monitor.is_quarantined(AGENT))  # True
metrics = monitor.get_metrics(AGENT)
print(metrics.quarantine_reason)
# "Burst threshold breached (101 calls in 60s)"
```

### 3.6 Listing Quarantined Agents

```python
quarantined = monitor.get_quarantined_agents()
for m in quarantined:
    print(f"{m.agent_did}: {m.quarantine_reason}")
```

### 3.7 Connecting the Monitor to the Reward Engine

The two systems are intentionally decoupled — the monitor detects anomalies and
the reward engine adjusts trust. You wire them together in your application:

```python
def on_quarantine(agent_did: str, reason: str):
    """When the monitor quarantines an agent, notify the reward engine."""
    reward.record_policy_violation(agent_did, policy_name=f"quarantine:{reason}")
    audit.log_action(agent_did, action="quarantine", outcome="failure",
                     data={"reason": reason})

# Example: check after each tool call
def handle_tool_call(agent_did: str, tool: str, success: bool):
    monitor.record_tool_call(agent_did, tool, success=success)

    if monitor.is_quarantined(agent_did):
        metrics = monitor.get_metrics(agent_did)
        on_quarantine(agent_did, metrics.quarantine_reason)
    elif success:
        reward.record_task_success(agent_did)
    else:
        reward.record_task_failure(agent_did, reason=f"{tool} failed")
```

---

## 4. TrustPolicyEngine — Declarative Policy Evaluation

Trust policies let you define **rules** that map runtime context to governance
decisions without writing procedural code.

### 4.1 YAML Policy Format

```yaml
# policies/high-risk-operations.yaml
name: high-risk-operations
version: "1.0"
description: "Restrict high-risk operations to trusted agents"

defaults:
  min_trust_score: 500
  max_delegation_depth: 3
  allowed_namespaces: ["*"]
  require_handshake: true

rules:
  - name: block-untrusted-writes
    description: "Deny write operations for agents below 700 trust"
    condition:
      field: trust_score
      operator: lt
      value: 700
    action: deny
    priority: 10        # lower = evaluated first

  - name: warn-on-delegation
    description: "Warn when delegation depth exceeds 2"
    condition:
      field: delegation_depth
      operator: gt
      value: 2
    action: warn
    priority: 50

  - name: allow-verified-partners
    description: "Allow verified partners unconditionally"
    condition:
      field: trust_tier
      operator: eq
      value: verified_partner
    action: allow
    priority: 1         # highest priority
```

### 4.2 Loading and Evaluating Policies

```python
from agentmesh.governance.trust_policy import TrustPolicy, load_policies

# Load a single policy
policy = TrustPolicy.from_yaml("policies/high-risk-operations.yaml")

# Load all policies from a directory (sorted alphabetically)
policies = load_policies("policies/")

# Evaluate a rule's condition against a runtime context
context = {
    "trust_score": 650,
    "trust_tier": "standard",
    "delegation_depth": 1,
    "agent": {"namespace": "analytics"},
}

for rule in sorted(policy.rules, key=lambda r: r.priority):
    if rule.condition.evaluate(context):
        print(f"Rule '{rule.name}' matched → action: {rule.action}")
        break
else:
    print("No rule matched — applying defaults")
    print(f"  min_trust_score: {policy.defaults.min_trust_score}")
    print(f"  require_handshake: {policy.defaults.require_handshake}")
```

### 4.3 Condition Operators

The `TrustCondition` class supports nine operators:

| Operator | Example | Notes |
|----------|---------|-------|
| `eq` | `trust_tier == "trusted"` | Equality check |
| `ne` | `status != "revoked"` | Inequality |
| `gt` | `trust_score > 700` | Greater than |
| `gte` | `trust_score >= 700` | Greater than or equal |
| `lt` | `trust_score < 300` | Less than |
| `lte` | `delegation_depth <= 2` | Less than or equal |
| `in` | `namespace in ["core", "analytics"]` | Membership test |
| `not_in` | `tier not_in ["untrusted"]` | Exclusion test |
| `matches` | `name matches "^report-.*"` | Regex (ReDoS-protected; max 200 chars) |

### 4.4 Nested Field Access

Conditions support **dot-notated paths** to reach nested context values:

```yaml
rules:
  - name: restrict-external-namespace
    condition:
      field: agent.namespace       # resolves context["agent"]["namespace"]
      operator: not_in
      value: ["internal", "core"]
    action: deny
    priority: 20
```

If a path does not exist in the context the condition evaluates to `False`,
which means the rule is skipped — a safe default.

### 4.5 Serialization Round-Trip

```python
# Save to YAML
policy.to_yaml("policies/exported.yaml")

# Re-load and verify
reloaded = TrustPolicy.from_yaml("policies/exported.yaml")
assert reloaded.name == policy.name
assert len(reloaded.rules) == len(policy.rules)
```

---

## 5. Shadow Mode — Test Trust Policies Without Enforcement

Shadow Mode lets you run agent requests through the governance pipeline
**without executing any real actions**. Agents "think" they are operating, but
the Control Plane intercepts every request, logs intent, validates against
constraint graphs, and returns simulated results.

### 5.1 Concepts

```
Agent Request ──► ShadowModeExecutor
                      │
                      ├─ _validate_request()   → SimulationOutcome
                      ├─ _simulate_execution()  → Fake result per action type
                      ├─ _analyze_impact()       → Side-effect analysis
                      │
                      └─ SimulationResult (logged, never executed)
```

| Class | Purpose |
|-------|---------|
| `ShadowModeConfig` | Enable/disable reasoning capture, constraint validation, safe-action passthrough |
| `ShadowModeExecutor` | Intercepts requests, simulates, and logs |
| `SimulationResult` | Outcome, simulated result, impact analysis, reasoning chain |
| `SimulationOutcome` | `WOULD_SUCCEED`, `WOULD_FAIL`, `POLICY_VIOLATION`, `RISK_TOO_HIGH`, `PERMISSION_DENIED` |
| `ReasoningStep` | Single step in an agent's reasoning chain (step number, action, parameters, decision) |

### 5.2 Configuring Shadow Mode

```python
from agent_control_plane.shadow_mode import (
    ShadowModeConfig,
    ShadowModeExecutor,
    SimulationOutcome,
    add_reasoning_step,
)

config = ShadowModeConfig(
    enabled=True,
    log_reasoning=True,          # capture reasoning chains
    simulate_results=True,       # generate fake outputs per action type
    validate_constraints=True,   # check against constraint graphs
    intercept_all=True,          # full shadow mode — nothing executes
    allow_safe_actions=False,    # even reads are simulated
)

shadow = ShadowModeExecutor(config)
```

### 5.3 Running a Simulated Execution

```python
from agent_control_plane.agent_kernel import ExecutionRequest, ActionType

# Build a request (normally done by the agent kernel)
request = ExecutionRequest(
    request_id="req-001",
    agent_context=agent_ctx,
    action_type=ActionType.FILE_WRITE,
    parameters={"path": "/data/report.csv", "content": "..."},
    risk_score=0.3,
)

# Build a reasoning chain (optional)
chain = []
add_reasoning_step(chain, "Analyze data sources", ActionType.FILE_READ,
                   {"path": "/data/input.csv"}, "Need raw data first")
add_reasoning_step(chain, "Write output report", ActionType.FILE_WRITE,
                   {"path": "/data/report.csv"}, "Deliver results")

# Execute in shadow mode
result = shadow.execute_in_shadow(request, reasoning_chain=chain)

print(result.outcome)           # SimulationOutcome.WOULD_SUCCEED
print(result.simulated_result)
# {"action": "file_write", "path": "/data/report.csv",
#  "bytes_written": 3, "note": "... shadow mode simulation ..."}

print(result.actual_impact)
# {"action_type": "file_write", "side_effects": [
#    {"type": "file_system_modification", "path": "/data/report.csv",
#     "reversible": true}]}
```

### 5.4 Querying Shadow Mode Statistics

```python
stats = shadow.get_statistics()

print(stats["total_simulations"])   # 42
print(stats["success_rate"])        # 0.85
print(stats["policy_violations"])   # 3
print(stats["risk_denials"])        # 2
print(stats["outcome_distribution"])
# {"would_succeed": 36, "policy_violation": 3, "risk_too_high": 2, ...}
```

### 5.5 Reviewing Policy Violations

```python
violations = shadow.get_policy_violations()
for v in violations:
    print(f"{v.request_id}: {v.outcome.value}")
    for note in v.validation_notes:
        print(f"  - {note}")
```

### 5.6 Progressive Rollouts (AgentMesh Shadow)

The `agentmesh.governance` module extends shadow mode with **progressive
rollouts** — a staged deployment strategy:

```
PENDING → SHADOW → CANARY → PROMOTING → COMPLETE
                                    ↘ ROLLED_BACK / FAILED
```

Each rollout step defines a traffic weight, duration, and analysis criteria
that must pass before promoting to the next stage:

```python
from agentmesh.governance._shadow_impl import (
    DeploymentStrategy,
    RolloutStep,
    AnalysisCriterion,
)

steps = [
    RolloutStep(
        name="shadow-phase",
        weight=0.0,                  # 0% real traffic
        duration_seconds=3600,
        analysis=[
            AnalysisCriterion(metric="error_rate", threshold=0.01, comparator="lte"),
            AnalysisCriterion(metric="latency_p99", threshold=500, comparator="lte"),
        ],
    ),
    RolloutStep(
        name="canary-phase",
        weight=0.05,                 # 5% real traffic
        duration_seconds=1800,
        analysis=[
            AnalysisCriterion(metric="error_rate", threshold=0.02, comparator="lte"),
        ],
    ),
    RolloutStep(
        name="full-rollout",
        weight=1.0,                  # 100% traffic
        manual_gate=True,            # requires human approval
    ),
]
```

---

## 6. Task Success/Failure Recording

The `RewardService` provides two convenience methods that map task outcomes to
the appropriate trust dimensions.

### 6.1 Success Path

```python
reward.record_task_success(agent_did, task_id="task-77")
```

Internally this records **two** positive signals:

1. `POLICY_COMPLIANCE → 1.0` (the agent followed rules)
2. `OUTPUT_QUALITY → 1.0` (the output was accepted)

### 6.2 Failure Path

```python
reward.record_task_failure(agent_did, reason="Output rejected by reviewer")
```

This records **one** negative signal:

1. `OUTPUT_QUALITY → 0.0` with the rejection reason

The asymmetry is intentional: a success reinforces *both* compliance and
quality, while a failure only penalizes output quality — the agent may still
have followed policies correctly.

### 6.3 Connecting to the Audit Trail

Always pair reward signals with audit entries so trust changes are traceable:

```python
reward.record_task_success(AGENT, task_id="t-100")
audit.log_trust_change(
    AGENT,
    old_score=reward.get_score_value(AGENT) - 5,
    new_score=reward.get_score_value(AGENT),
    reason="task-100 completed successfully",
)
```

---

## 7. Security Event Recording

Security events track whether agents stay within their designated boundaries.

### 7.1 Recording Events

```python
# Agent accessed only authorized resources
reward.record_security_event(
    AGENT,
    within_boundary=True,
    event_type="data_read",
)

# Agent attempted to access an external endpoint (boundary violation)
reward.record_security_event(
    AGENT,
    within_boundary=False,
    event_type="egress_attempt",
)
```

Each call creates a `SECURITY_POSTURE` dimension signal:

- `within_boundary=True` → value **1.0** (good)
- `within_boundary=False` → value **0.0** (bad)

Because `SECURITY_POSTURE` carries a weight of 0.25 (the highest alongside
`POLICY_COMPLIANCE`), boundary violations have an outsized impact on the
overall trust score.

### 7.2 Lower-Level Security Signals

For granular control, use the engine directly:

```python
from agentmesh.reward.scoring import DimensionType

reward.engine.record_signal(
    agent_did=AGENT,
    dimension=DimensionType.SECURITY_POSTURE,
    value=0.5,              # partial violation
    source="network_monitor",
    details="Attempted DNS resolution for unapproved domain",
)
```

---

## 8. AgentRegistry — Persistent Agent Metadata with Trust

The `AgentRegistry` stores the complete profile for every agent in the mesh —
identity, capabilities, credentials, trust score, and status.

### 8.1 Registering an Agent

```python
import asyncio
from datetime import datetime, timedelta
from agentmesh.services.registry import AgentRegistry, AgentRegistryEntry

registry = AgentRegistry()

entry = AgentRegistryEntry(
    did="did:mesh:analyst-001",
    name="DataAnalyst",
    description="Runs SQL queries and generates reports",
    organization="Analytics",
    sponsor_email="alice@company.com",
    sponsor_verified=True,
    capabilities=["read:data", "write:reports"],
    supported_protocols=["agentmesh/v1"],
    trust_score=500,                                  # default
    trust_tier="standard",
    public_key_fingerprint="sha256:abc123...",
    svid_serial_number="svid-00001",
    current_credential_expires_at=datetime.utcnow() + timedelta(minutes=15),
    delegation_depth=0,
)

asyncio.run(registry.register(entry))
```

### 8.2 Updating Trust Scores

```python
async def update_trust():
    await registry.update_trust_score("did:mesh:analyst-001", new_score=720)

    agent = await registry.get("did:mesh:analyst-001")
    print(agent.trust_score)  # 720
    print(agent.trust_tier)   # "trusted" (>= 700)

asyncio.run(update_trust())
```

The registry automatically maps scores to tiers:

| Score Range | Tier |
|-------------|------|
| ≥ 900 | `verified_partner` |
| 700 – 899 | `trusted` |
| 400 – 699 | `standard` |
| 200 – 399 | `probationary` |
| 0 – 199 | `untrusted` |

### 8.3 Managing Agent Status

```python
async def suspend_agent():
    await registry.update_status(
        "did:mesh:analyst-001",
        status="suspended",
        reason="Under investigation for data exfiltration",
    )

    # Heartbeat tracking
    await registry.record_activity("did:mesh:analyst-001")

asyncio.run(suspend_agent())
```

### 8.4 Querying Agents

```python
async def query():
    # List all active agents with trust score >= 700
    trusted = await registry.list_agents(status="active", min_trust_score=700)
    for a in trusted:
        print(f"{a.did}: {a.trust_tier} ({a.trust_score})")

    # Count agents by status
    total = await registry.count_agents()
    suspended = await registry.count_agents(status="suspended")
    print(f"{suspended}/{total} agents suspended")

asyncio.run(query())
```

---

## 9. Trust Statistics — Aggregate Metrics Across the Mesh

### 9.1 Registry-Level Statistics

```python
async def stats():
    stats = await registry.get_trust_statistics()
    print(stats)
    # {
    #     "total_agents": 42,
    #     "average_trust_score": 623.4,
    #     "min_trust_score": 210,
    #     "max_trust_score": 950,
    #     "tier_distribution": {
    #         "verified_partner": 3,
    #         "trusted": 12,
    #         "standard": 20,
    #         "probationary": 5,
    #         "untrusted": 2,
    #     }
    # }

asyncio.run(stats())
```

### 9.2 RewardService Summary

```python
summary = reward.summary()
print(summary)
# {"total_agents": 42, "avg_score": 623.4,
#  "min_score": 210, "max_score": 950}
```

### 9.3 Engine-Level Health Report

```python
report = reward.engine.get_health_report(days=7)

print(f"Revoked: {report['revoked_agents']}")
print(f"At risk: {report['at_risk_agents']}")

# Per-agent breakdown
for did, info in report["agents"].items():
    trend = info["trend"]  # "improving" | "stable" | "degrading"
    print(f"  {did}: {info['current_score']}  [{trend}]")
```

---

## 10. AuditService & AuditChain — Tamper-Proof Audit Logs

Every trust decision, policy evaluation, and security event should be logged to
an append-only, hash-chained audit trail.

### 10.1 Architecture

```
  AuditService            AuditLog              MerkleAuditChain
  ┌──────────┐       ┌──────────────┐       ┌──────────────────┐
  │ log_*()  │──────►│ Indexes:     │──────►│ Entries[]        │
  │ query_*()│       │   by_agent   │       │ Merkle Tree      │
  │ verify() │       │   by_type    │       │ Root Hash        │
  │ summary()│       │ Sink (opt.)  │       │ Inclusion Proofs │
  └──────────┘       └──────────────┘       └──────────────────┘
```

### 10.2 Logging Events

```python
from agentmesh.services.audit import AuditService

audit = AuditService()

# Log an action
entry = audit.log_action(
    agent_did="did:mesh:worker-007",
    action="file_write",
    outcome="success",
    resource="/data/report.csv",
    data={"bytes_written": 4096},
    trace_id="trace-abc-123",
)
print(entry.entry_id)     # "audit_a1b2c3d4..."
print(entry.entry_hash)   # SHA-256 hash
print(entry.previous_hash)  # hash of previous entry (chain link)

# Log a policy decision
audit.log_policy_decision(
    agent_did="did:mesh:worker-007",
    action="db_write",
    decision="deny",
    policy_name="read-only-agents",
)

# Log a trust handshake
audit.log_handshake(
    initiator_did="did:mesh:worker-007",
    responder_did="did:mesh:peer-003",
    success=True,
)

# Log a trust score change
audit.log_trust_change(
    agent_did="did:mesh:worker-007",
    old_score=500.0,
    new_score=650.0,
    reason="Completed 10 tasks without violations",
)
```

### 10.3 Hash-Chain Integrity

Every `AuditEntry` stores:

- **`entry_hash`**: SHA-256 of its canonical fields (entry_id, timestamp,
  event_type, agent_did, action, resource, data, outcome, previous_hash)
- **`previous_hash`**: the `entry_hash` of the preceding entry

Tampering with any entry breaks the chain:

```python
# Verify the entire chain
is_valid = audit.verify_chain()
print(is_valid)  # True

# Get a summary
summary = audit.summary()
print(summary)
# {"total_entries": 128, "chain_valid": True,
#  "root_hash": "a3f8b2c1d4e5..."}
```

### 10.4 Merkle Inclusion Proofs

The `MerkleAuditChain` builds a Merkle tree over all entries, enabling O(log n)
**inclusion proofs** — you can prove a specific entry exists without revealing
the entire log:

```python
# Get an inclusion proof for a specific entry
proof_data = audit.chain._log.get_proof(entry.entry_id)
# Returns: {"entry": {...}, "merkle_proof": [...], "merkle_root": "...",
#           "verified": True}

# Verify the proof independently
chain = audit.chain
proof = chain.get_proof(entry.entry_id)
root = chain.get_root_hash()
is_included = chain.verify_proof(entry.entry_hash, proof, root)
print(is_included)  # True
```

### 10.5 Querying Audit Entries

```python
# By agent
entries = audit.query_by_agent("did:mesh:worker-007")

# By event type
policy_entries = audit.query_by_type("policy_decision")

# Advanced: use the underlying AuditLog for complex queries
from datetime import datetime, timezone

results = audit._log.query(
    agent_did="did:mesh:worker-007",
    event_type="agent_action",
    start_time=datetime(2025, 1, 1, tzinfo=timezone.utc),
    outcome="failure",
    limit=50,
)
```

### 10.6 File-Based Audit Sink (Persistent Storage)

For production use, attach a `FileAuditSink` that writes HMAC-signed,
hash-chained JSONL to disk:

```python
from agentmesh.governance.audit_backends import FileAuditSink, HashChainVerifier

sink = FileAuditSink(
    path="audit/events.jsonl",
    secret_key=b"your-256-bit-secret-key",
    max_file_size=10 * 1024 * 1024,  # 10 MB — auto-rotates
)

# Create an AuditLog with the sink attached
from agentmesh.governance.audit import AuditLog

log = AuditLog(sink=sink)
log.log("agent_action", "did:mesh:worker-007", "file_read",
        resource="/data/input.csv")

# Each line in audit/events.jsonl includes:
# - content_hash (SHA-256 of canonical payload)
# - previous_hash (chain link to prior entry)
# - signature (HMAC-SHA256 using your secret key)

# Verify the entire file
verifier = HashChainVerifier()
is_valid, errors = verifier.verify_file("audit/events.jsonl",
                                         secret_key=b"your-256-bit-secret-key")
print(is_valid)  # True
print(errors)    # [] (empty if valid)

# Read entries back
entries = sink.read_entries()
for e in entries:
    assert e.verify(b"your-256-bit-secret-key")

# Close when done
sink.close()
```

### 10.7 CloudEvents Export

Audit entries can be exported as [CloudEvents v1.0](https://cloudevents.io/)
for integration with external SIEM or observability systems:

```python
events = audit._log.export_cloudevents()
for ce in events:
    print(ce["type"])    # e.g., "ai.agentmesh.tool.invoked"
    print(ce["source"])  # "agentmesh"
    print(ce["data"])    # entry payload
```

CloudEvent type mapping:

| Event Type | CloudEvent Type |
|------------|----------------|
| `tool_invocation` | `ai.agentmesh.tool.invoked` |
| `tool_blocked` | `ai.agentmesh.tool.blocked` |
| `policy_evaluation` | `ai.agentmesh.policy.evaluation` |
| `policy_violation` | `ai.agentmesh.policy.violation` |
| `trust_handshake` | `ai.agentmesh.trust.handshake` |
| `trust_score_updated` | `ai.agentmesh.trust.score.updated` |
| `agent_registered` | `ai.agentmesh.agent.registered` |

---

## 11. RateLimiter — Throttle Agent Requests

The `RateLimiter` uses a **dual token-bucket** design (global + per-agent) to
prevent any single agent from overwhelming the mesh.

### 11.1 Configuration

```python
from agentmesh.services.rate_limiter import RateLimiter, RateLimitConfig

config = RateLimitConfig(
    global_rate=100.0,            # tokens/second (global)
    global_capacity=200,          # max burst (global)
    per_agent_rate=10.0,          # tokens/second (per agent)
    per_agent_capacity=20,        # max burst (per agent)
    backpressure_threshold=0.8,   # signal backpressure at 80% usage
)

limiter = RateLimiter(
    global_rate=config.global_rate,
    global_capacity=config.global_capacity,
    per_agent_rate=config.per_agent_rate,
    per_agent_capacity=config.per_agent_capacity,
    backpressure_threshold=config.backpressure_threshold,
)
```

### 11.2 Checking and Enforcing Limits

```python
AGENT = "did:mesh:worker-007"

# Simple allow/deny check
if limiter.allow(AGENT):
    print("Request allowed")
else:
    print("Rate limited")

# Detailed check with retry information
result = limiter.check(AGENT)
print(result.allowed)              # True / False
print(result.remaining_tokens)     # tokens left
print(result.retry_after_seconds)  # seconds to wait (if denied)
print(result.backpressure)         # True if approaching limit
```

### 11.3 Status and Reset

```python
# Global + per-agent status
status = limiter.get_status(agent_did=AGENT)
print(status)
# {"global_tokens": 195.3, "global_capacity": 200,
#  "agent_tokens": 18.7, "agent_capacity": 20}

# Reset a single agent's bucket
limiter.reset(agent_did=AGENT)

# Reset everything
limiter.reset()
```

---

## 12. NetworkTrustEngine — Decay, Propagation, and Regime Detection

The `NetworkTrustEngine` adds three advanced trust dynamics that go beyond
per-agent scoring:

1. **Temporal decay** — scores drift downward without positive reinforcement
2. **Network propagation** — trust events ripple across agent interaction graphs
3. **Regime detection** — KL divergence identifies behavioral shifts

### 12.1 Setup

```python
from agentmesh.reward.trust_decay import NetworkTrustEngine, TrustEvent

network = NetworkTrustEngine(
    decay_rate=2.0,           # score points lost per hour of inactivity
    propagation_factor=0.3,   # fraction of impact propagated to neighbors
    propagation_depth=2,      # hops
    regime_threshold=0.5,     # KL divergence threshold for alerts
)
```

### 12.2 Recording Interactions

```python
AGENT_A = "did:mesh:agent-a"
AGENT_B = "did:mesh:agent-b"

network.set_score(AGENT_A, 800)
network.set_score(AGENT_B, 750)

# Record interactions to build the agent graph
network.record_interaction(AGENT_A, AGENT_B)
network.record_interaction(AGENT_B, AGENT_A)
```

### 12.3 Trust Events with Network Propagation

```python
event = TrustEvent(
    agent_did=AGENT_A,
    event_type="policy_violation",
    severity_weight=0.5,         # 0.0 = minor, 1.0 = critical
    details="Attempted unauthorized API call",
)

deltas = network.process_trust_event(event)
print(deltas)
# {"did:mesh:agent-a": -50.0, "did:mesh:agent-b": -7.5}
# Agent A lost 50 points; Agent B (neighbor) lost 7.5 (propagated)
```

### 12.4 Temporal Decay

```python
# Apply decay — agents without recent positive signals lose trust
deltas = network.apply_temporal_decay()
for did, loss in deltas.items():
    print(f"{did}: {loss:.1f}")  # e.g., "did:mesh:agent-a: -4.0"

# Positive signals reset the decay clock
network.record_positive_signal(AGENT_A, bonus=5.0)
```

### 12.5 Regime Detection (Behavioral Anomaly)

The engine detects **behavioral regime changes** by comparing an agent's recent
action distribution against its historical baseline using KL divergence:

```python
# Record a variety of actions to build a baseline
for _ in range(50):
    network.record_action(AGENT_A, "file_read")
    network.record_action(AGENT_A, "db_query")

# Suddenly the agent shifts behavior
for _ in range(20):
    network.record_action(AGENT_A, "api_call")  # new dominant action

alert = network.detect_regime_change(AGENT_A)
if alert:
    print(f"Regime change detected!")
    print(f"  KL divergence: {alert.kl_divergence:.3f}")
    print(f"  Threshold: {alert.threshold}")
    print(f"  Recent: {alert.recent_distribution}")
    print(f"  Historical: {alert.historical_distribution}")
```

---

## 13. Putting It All Together

Here is a complete integration showing all components working in concert:

```python
import asyncio
from datetime import datetime, timedelta
from agentmesh.services.reward_engine import RewardService
from agentmesh.services.behavior_monitor import AgentBehaviorMonitor
from agentmesh.services.audit import AuditService
from agentmesh.services.rate_limiter import RateLimiter
from agentmesh.services.registry import AgentRegistry, AgentRegistryEntry
from agentmesh.governance.trust_policy import TrustPolicy


class GovernanceOrchestrator:
    """Wires together all trust and behavior components."""

    def __init__(self):
        self.reward = RewardService()
        self.monitor = AgentBehaviorMonitor(
            burst_threshold=50,
            consecutive_failure_threshold=10,
        )
        self.audit = AuditService()
        self.limiter = RateLimiter()
        self.registry = AgentRegistry()
        self.policy = TrustPolicy.from_yaml("policies/default.yaml")

    async def handle_request(self, agent_did: str, tool: str) -> bool:
        """Process an agent tool-call request through the governance stack."""

        # 1. Rate limit
        limit_result = self.limiter.check(agent_did)
        if not limit_result.allowed:
            self.audit.log_action(agent_did, tool, outcome="denied",
                                  data={"reason": "rate_limited"})
            return False

        # 2. Check quarantine
        if self.monitor.is_quarantined(agent_did):
            self.audit.log_action(agent_did, tool, outcome="denied",
                                  data={"reason": "quarantined"})
            return False

        # 3. Check trust score against policy
        score = self.reward.get_score(agent_did)
        context = {
            "trust_score": score.total_score,
            "trust_tier": score.tier,
        }
        for rule in sorted(self.policy.rules, key=lambda r: r.priority):
            if rule.condition.evaluate(context):
                if rule.action == "deny":
                    self.audit.log_policy_decision(
                        agent_did, tool, decision="deny",
                        policy_name=rule.name)
                    return False
                break

        # 4. Execute (simulated here)
        success = True  # replace with real execution

        # 5. Record outcome
        self.monitor.record_tool_call(agent_did, tool, success=success)
        if success:
            self.reward.record_task_success(agent_did)
        else:
            self.reward.record_task_failure(agent_did, reason=f"{tool} failed")

        # 6. Update registry
        new_score = self.reward.get_score(agent_did).total_score
        await self.registry.update_trust_score(agent_did, new_score)

        # 7. Audit
        self.audit.log_action(agent_did, tool,
                              outcome="success" if success else "failure")
        return success
```

---

## 14. Cross-References

| Topic | Tutorial | What It Covers |
|-------|----------|---------------|
| Agent identity, DIDs, basic trust scores | [Tutorial 02 — Trust and Identity](02-trust-and-identity.md) | `AgentIdentity`, `AgentDID`, `HumanSponsor`, `RiskScorer`, Ed25519 keys, delegation chains |
| Liability allocation for multi-agent failures | [Tutorial 04 — Audit and Compliance](04-audit-and-compliance.md) | Compliance gates, Merkle-chain audit logging, CI/CD integration |
| Agent reliability, rogue detection, circuit breakers | [Tutorial 05 — Agent Reliability](05-agent-reliability.md) | SRE practices, cost controls, chaos testing, behavioral drift detection |

---

## Next Steps

- **Reward distribution**: Explore `agentmesh.reward.distribution` for
  strategies that split rewards among collaborating agents (equal, trust-weighted,
  hierarchical, contribution-based).
- **Custom dimensions**: Call `reward.engine.record_signal()` directly to add
  domain-specific trust dimensions beyond the built-in five.
- **Custom audit sinks**: Implement the `AuditSink` protocol to write audit
  entries to your SIEM, database, or cloud storage.
- **Policy-as-code CI**: Load policies with `load_policies()` in your CI
  pipeline and validate them against test contexts before deployment.
- **Network trust graphs**: Use `NetworkTrustEngine` to model trust
  propagation across your entire agent fleet and detect coordinated attacks.
