# Trust Scoring API Reference

> **API reference for AgentMesh's trust scoring classes, methods, and configuration.**

This document covers the Python SDK trust scoring API. For the conceptual guide, see [Understanding the 5-Dimension Trust Model](./trust-model-guide.md).

---

## Table of Contents

- [Quick Start](#quick-start)
- [Core Classes](#core-classes)
  - [RewardEngine](#rewardengine)
  - [TrustScore](#trustscore)
  - [RewardSignal](#rewardsignal)
  - [RewardDimension](#rewarddimension)
  - [DimensionType](#dimensiontype)
  - [ScoreThresholds](#scorethresholds)
  - [NetworkTrustEngine](#networktrustengine)
  - [TrustEvent](#trustevent)
- [Configuration](#configuration)
  - [RewardConfig](#rewardconfig)
  - [Constants](#constants)
  - [Customizing Weights](#customizing-weights)
- [Common Operations](#common-operations)
- [TypeScript SDK](#typescript-sdk)

---

## Quick Start

```python
from agentmesh.reward.engine import RewardEngine
from agentmesh.reward.scoring import DimensionType

# 1. Create the engine
engine = RewardEngine()

# 2. Record signals as agents operate
agent = "did:mesh:my-agent-01"

engine.record_policy_compliance(agent, compliant=True)
engine.record_output_quality(agent, accepted=True, consumer="did:mesh:peer")
engine.record_resource_usage(agent, tokens_used=500, tokens_budget=1000,
                             compute_ms=200, compute_budget_ms=500)
engine.record_security_event(agent, within_boundary=True, event_type="normal")
engine.record_collaboration(agent, handoff_successful=True, peer_did="did:mesh:peer")

# 3. Query the score
score = engine.get_agent_score(agent)
print(f"{score.total_score}/1000 — {score.tier}")
# 500/1000 — standard
```

---

## Core Classes

### RewardEngine

**Module:** `agentmesh.reward.engine`

The central orchestrator for trust scoring. Manages per-agent state, processes signals, recalculates scores, and triggers revocations.

```python
from agentmesh.reward.engine import RewardEngine, RewardConfig

engine = RewardEngine(config=RewardConfig())
```

#### Methods

##### `get_agent_score(agent_did: str) → TrustScore`

Returns the current trust score for an agent.

```python
score = engine.get_agent_score("did:mesh:agent-01")
print(score.total_score)  # 500
print(score.tier)          # "standard"
```

##### `record_signal(agent_did, dimension, value, source, details=None)`

Record a raw reward signal. This is the low-level method — prefer the typed convenience methods below.

| Parameter | Type | Description |
|-----------|------|-------------|
| `agent_did` | `str` | Agent's DID (must match `did:mesh:*`) |
| `dimension` | `DimensionType` | Which dimension this affects |
| `value` | `float` | Signal value: 0.0 (bad) to 1.0 (good) |
| `source` | `str` | Origin of the signal |
| `details` | `str \| None` | Optional context |

> **Note:** Signals with `value < 0.3` trigger immediate score recalculation.

```python
engine.record_signal(
    agent_did="did:mesh:agent-01",
    dimension=DimensionType.OUTPUT_QUALITY,
    value=0.8,
    source="validation_pipeline",
    details="Output passed schema validation",
)
```

##### `record_policy_compliance(agent_did, compliant, policy_name=None)`

Record a policy compliance signal.

```python
engine.record_policy_compliance(
    "did:mesh:agent-01",
    compliant=True,
    policy_name="data-retention-policy",
)
```

##### `record_resource_usage(agent_did, tokens_used, tokens_budget, compute_ms, compute_budget_ms)`

Record resource efficiency. Efficiency is calculated as the average of token and compute ratios.

```python
engine.record_resource_usage(
    "did:mesh:agent-01",
    tokens_used=3000,
    tokens_budget=5000,
    compute_ms=800,
    compute_budget_ms=2000,
)
```

##### `record_output_quality(agent_did, accepted, consumer, rejection_reason=None)`

Record whether a downstream consumer accepted or rejected the agent's output.

```python
engine.record_output_quality(
    "did:mesh:agent-01",
    accepted=False,
    consumer="did:mesh:consumer-02",
    rejection_reason="Schema validation failed",
)
```

##### `record_security_event(agent_did, within_boundary, event_type)`

Record a security posture signal.

```python
engine.record_security_event(
    "did:mesh:agent-01",
    within_boundary=True,
    event_type="credential_rotation",
)
```

##### `record_collaboration(agent_did, handoff_successful, peer_did)`

Record a collaboration handoff outcome.

```python
engine.record_collaboration(
    "did:mesh:agent-01",
    handoff_successful=True,
    peer_did="did:mesh:partner-03",
)
```

##### `get_score_explanation(agent_did: str) → dict`

Returns a fully explainable breakdown of the agent's score with dimension contributions, recent signals, and trend.

```python
explanation = engine.get_score_explanation("did:mesh:agent-01")
# Returns:
# {
#     "agent_did": "did:mesh:agent-01",
#     "total_score": 780,
#     "dimensions": {
#         "policy_compliance": {"score": 85.0, "signal_count": 42, "weight": 0.25, "contribution": 21.25},
#         ...
#     },
#     "recent_signals": [...],
#     "trend": "stable",
#     "revoked": False,
#     "revocation_reason": None,
# }
```

##### `update_weights(**kwargs) → bool`

Update dimension weights at runtime. Changes take effect within 60 seconds.

```python
engine.update_weights(
    policy_compliance=0.30,
    security_posture=0.30,
    output_quality=0.15,
    resource_efficiency=0.10,
    collaboration_health=0.15,
)
```

##### `get_agents_at_risk() → list[str]`

Returns agent DIDs with scores below the warning threshold.

```python
at_risk = engine.get_agents_at_risk()
```

##### `get_health_report(days: int = 7) → dict`

Returns a longitudinal health report with per-agent score statistics.

```python
report = engine.get_health_report(days=30)
```

##### `on_revocation(callback: Callable) → None`

Register a callback invoked when an agent's credentials are automatically revoked.

```python
def handle_revocation(agent_did: str, reason: str):
    print(f"REVOKED: {agent_did} — {reason}")

engine.on_revocation(handle_revocation)
```

##### `start_background_updates() → Coroutine`

Start periodic background score recalculation (async).

```python
import asyncio
asyncio.create_task(engine.start_background_updates())
```

##### `stop_background_updates() → None`

Stop the background update loop.

---

### TrustScore

**Module:** `agentmesh.reward.scoring`

Represents a complete trust score for an agent.

```python
from agentmesh.reward.scoring import TrustScore

score = TrustScore(agent_did="did:mesh:agent-01")
```

#### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `agent_did` | `str` | required | Agent DID (must match `did:mesh:*`) |
| `total_score` | `int` | 500 | Composite score (0–1000) |
| `tier` | `str` | `"standard"` | Auto-calculated tier |
| `dimensions` | `dict[str, RewardDimension]` | `{}` | Per-dimension scores |
| `calculated_at` | `datetime` | now | Last calculation time |
| `previous_score` | `int \| None` | `None` | Previous score value |
| `score_change` | `int` | 0 | Delta from previous |

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `meets_threshold(threshold)` | `bool` | Check if score ≥ threshold |
| `update(new_score, dimensions)` | `None` | Update score and recalculate tier |
| `to_dict()` | `dict` | Serializable dictionary |

---

### RewardSignal

**Module:** `agentmesh.reward.scoring`

A single behavioral signal feeding into a dimension score.

```python
from agentmesh.reward.scoring import RewardSignal, DimensionType

signal = RewardSignal(
    dimension=DimensionType.OUTPUT_QUALITY,
    value=0.9,
    source="validation_pipeline",
    details="All assertions passed",
    weight=1.0,
)
```

#### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `dimension` | `DimensionType` | required | Target dimension |
| `value` | `float` | required | 0.0 (bad) to 1.0 (good) |
| `source` | `str` | required | Signal origin |
| `details` | `str \| None` | `None` | Context |
| `trace_id` | `str \| None` | `None` | Distributed trace ID |
| `timestamp` | `datetime` | now | When signal was emitted |
| `weight` | `float` | 1.0 | Importance multiplier |

---

### RewardDimension

**Module:** `agentmesh.reward.scoring`

Score state for a single dimension.

#### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | `str` | required | Dimension name |
| `score` | `float` | 50.0 | Current score (0–100) |
| `signal_count` | `int` | 0 | Total signals received |
| `positive_signals` | `int` | 0 | Signals ≥ 0.5 |
| `negative_signals` | `int` | 0 | Signals < 0.5 |
| `trend` | `str` | `"stable"` | `improving`, `degrading`, or `stable` |

#### Methods

##### `add_signal(signal: RewardSignal) → None`

Update the dimension score using EMA:

```
new_score = score × 0.9 + (signal.value × 100) × 0.1
```

---

### DimensionType

**Module:** `agentmesh.reward.scoring`

Enum of the 5 trust dimensions.

```python
from agentmesh.reward.scoring import DimensionType

DimensionType.POLICY_COMPLIANCE       # "policy_compliance"
DimensionType.SECURITY_POSTURE        # "security_posture"
DimensionType.OUTPUT_QUALITY          # "output_quality"
DimensionType.RESOURCE_EFFICIENCY     # "resource_efficiency"
DimensionType.COLLABORATION_HEALTH    # "collaboration_health"
```

---

### ScoreThresholds

**Module:** `agentmesh.reward.scoring`

Configurable threshold definitions for tiers and actions.

```python
from agentmesh.reward.scoring import ScoreThresholds

thresholds = ScoreThresholds(
    verified_partner=900,
    trusted=700,
    standard=500,
    probationary=300,
    allow_threshold=500,
    warn_threshold=400,
    revocation_threshold=300,
)
```

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `get_tier(score)` | `str` | Returns tier name for a score |
| `should_allow(score)` | `bool` | True if score ≥ allow_threshold |
| `should_warn(score)` | `bool` | True if score < warn_threshold |
| `should_revoke(score)` | `bool` | True if score < revocation_threshold |

---

### NetworkTrustEngine

**Module:** `agentmesh.reward.trust_decay`

Handles temporal trust decay and trust event processing.

```python
from agentmesh.reward.trust_decay import NetworkTrustEngine

trust_engine = NetworkTrustEngine(
    decay_rate=2.0,          # Points lost per hour
    propagation_factor=0.3,  # Reserved for future use
    propagation_depth=2,     # Reserved for future use
)
```

#### Methods

| Method | Returns | Description |
|--------|---------|-------------|
| `get_score(agent_did)` | `float` | Current score (default: 500) |
| `set_score(agent_did, score)` | `None` | Set score (clamped to 0–1000) |
| `record_positive_signal(agent_did, bonus=5.0)` | `None` | Bump score + reset decay timer |
| `process_trust_event(event)` | `dict[str, float]` | Apply trust event, return deltas |
| `apply_temporal_decay(now=None)` | `dict[str, float]` | Apply decay to all agents |
| `on_score_change(handler)` | `None` | Register score change callback |
| `get_health_report()` | `dict` | Summary of all scores and events |

---

### TrustEvent

**Module:** `agentmesh.reward.trust_decay`

A trust-relevant event that impacts an agent's score.

```python
from agentmesh.reward.trust_decay import TrustEvent

event = TrustEvent(
    agent_did="did:mesh:agent-01",
    event_type="policy_violation",
    severity_weight=0.5,  # 0.0 (minor) to 1.0 (critical)
    details="Accessed restricted resource without authorization",
)
```

#### Impact Formula

```
score_delta = -(severity_weight × 100)
```

A `severity_weight=0.5` event reduces the score by 50 points.

---

## Configuration

### RewardConfig

```python
from agentmesh.reward.engine import RewardConfig

config = RewardConfig(
    update_interval_seconds=30,    # Background update frequency
    revocation_threshold=300,      # Auto-revoke below this
    warning_threshold=500,         # Alert below this
    policy_compliance_weight=0.25,
    resource_efficiency_weight=0.15,
    output_quality_weight=0.20,
    security_posture_weight=0.25,
    collaboration_health_weight=0.15,
    trust_score=0.5,               # Initial trust (0.0–1.0)
)
```

### Constants

All defaults are defined in `agentmesh.constants`:

```python
from agentmesh.constants import (
    TRUST_SCORE_DEFAULT,            # 500
    TRUST_SCORE_MAX,                # 1000
    TRUST_REVOCATION_THRESHOLD,     # 300
    TRUST_WARNING_THRESHOLD,        # 500
    TIER_VERIFIED_PARTNER_THRESHOLD, # 900
    TIER_TRUSTED_THRESHOLD,         # 700
    TIER_STANDARD_THRESHOLD,        # 500
    TIER_PROBATIONARY_THRESHOLD,    # 300
    WEIGHT_POLICY_COMPLIANCE,       # 0.25
    WEIGHT_SECURITY_POSTURE,        # 0.25
    WEIGHT_OUTPUT_QUALITY,          # 0.20
    WEIGHT_RESOURCE_EFFICIENCY,     # 0.15
    WEIGHT_COLLABORATION_HEALTH,    # 0.15
    REWARD_UPDATE_INTERVAL_SECONDS, # 30
)
```

### Customizing Weights

Weights can be adjusted at runtime to match your deployment's priorities:

```python
# Security-critical deployment
engine.update_weights(
    policy_compliance=0.20,
    security_posture=0.40,
    output_quality=0.15,
    resource_efficiency=0.10,
    collaboration_health=0.15,
)

# Quality-focused deployment
engine.update_weights(
    policy_compliance=0.15,
    security_posture=0.15,
    output_quality=0.40,
    resource_efficiency=0.15,
    collaboration_health=0.15,
)

# Cost-sensitive deployment
engine.update_weights(
    policy_compliance=0.15,
    security_posture=0.15,
    output_quality=0.15,
    resource_efficiency=0.40,
    collaboration_health=0.15,
)
```

---

## Common Operations

### Gate an operation on trust score

```python
score = engine.get_agent_score("did:mesh:agent-01")
if score.meets_threshold(700):
    # Allow privileged operation
    ...
```

### Check if an agent should be restricted

```python
from agentmesh.reward.scoring import ScoreThresholds

thresholds = ScoreThresholds()
score_val = engine.get_agent_score("did:mesh:agent-01").total_score

if thresholds.should_revoke(score_val):
    revoke_credentials(agent_did)
elif thresholds.should_warn(score_val):
    send_alert(agent_did)
```

### Run periodic decay

```python
import time
from agentmesh.reward.trust_decay import NetworkTrustEngine

trust_engine = NetworkTrustEngine(decay_rate=2.0)

# Call periodically (e.g., every 60 seconds)
deltas = trust_engine.apply_temporal_decay()
for agent_did, delta in deltas.items():
    print(f"{agent_did}: {delta:+.1f} points")
```

### Export score for observability

```python
score = engine.get_agent_score("did:mesh:agent-01")
metrics = score.to_dict()
# Send to your observability platform
# {
#     "agent_did": "did:mesh:agent-01",
#     "total_score": 780,
#     "tier": "trusted",
#     "dimensions": {...},
#     "calculated_at": "2025-01-15T10:30:00"
# }
```

---

## TypeScript SDK

The TypeScript SDK provides a simpler trust model suitable for client-side use.

```typescript
import { TrustManager } from '@microsoft/agentmesh-sdk';

const manager = new TrustManager({
  initialScore: 0.5,
  decayFactor: 0.95,
  thresholds: {
    untrusted: 0.0,
    provisional: 0.3,
    trusted: 0.6,
    verified: 0.85,
  },
});
```

### Key Methods

| Method | Description |
|--------|-------------|
| `getTrustScore(agentId)` | Returns `{ overall, dimensions, tier }` |
| `recordSuccess(agentId, reward?)` | Record successful interaction (default reward: 0.05) |
| `recordFailure(agentId, penalty?)` | Record failed interaction (default penalty: 0.1) |
| `verifyPeer(peerId, peerIdentity)` | Verify identity + return trust result |

### Trust Tiers (TypeScript)

| Tier | Score Range |
|------|------------|
| Untrusted | 0.0–0.29 |
| Provisional | 0.3–0.59 |
| Trusted | 0.6–0.84 |
| Verified | 0.85–1.0 |

---

## Further Reading

- [Understanding the 5-Dimension Trust Model](./trust-model-guide.md) — Conceptual guide
- [Zero-Trust Architecture](./zero-trust.md) — Cryptographic identity layer
- [API Reference](./api-reference.md) — Full AgentMesh API docs
