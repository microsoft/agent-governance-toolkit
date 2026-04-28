# Tutorial 14 — Kill Switch & Rate Limiting

> **Package:** `agentmesh-runtime` · **Time:** 20 minutes · **Prerequisites:** Python 3.11+

---

## What You'll Learn

- Emergency termination with KillSwitch and audit trails
- Rate limiting with per-agent token bucket enforcement
- Ring elevation and breach detection

---

**Emergency controls for autonomous agents — the "big red button", rate governors, and ring-breach detection.**

See also: [Tutorial 05 — Agent Reliability](05-agent-reliability.md) | [Tutorial 06 — Execution Sandboxing](06-execution-sandboxing.md) | [Deployment Guide](../deployment/README.md)

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Quick Start: Your First Kill Switch](#2-quick-start-your-first-kill-switch)
3. [KillSwitch — Immediate Termination](#3-killswitch--immediate-termination)
4. [AgentRateLimiter — Per-Ring Token Buckets](#4-agentratelimiter--per-ring-token-buckets)
5. [RateLimiter (Agent Mesh) — HTTP Service Limits](#5-ratelimiter-agent-mesh--http-service-limits)
6. [RateLimitMiddleware — HTTP Edge Enforcement](#6-ratelimitmiddleware--http-edge-enforcement)
7. [RingElevationManager — Temporary Privilege Escalation](#7-ringelevationmanager--temporary-privilege-escalation)
8. [RingBreachDetector — Anomaly Detection](#8-ringbreachdetector--anomaly-detection)
9. [Combining Controls — Defense in Depth](#9-combining-controls--defense-in-depth)
10. [Next Steps](#10-next-steps)

---

**What you'll learn:**

| Topic | Component | Package |
|-------|-----------|---------|
| Immediate agent termination with audit trail | `KillSwitch` | `agent-hypervisor` |
| Per-agent, per-ring rate limiting | `AgentRateLimiter` | `agent-hypervisor` |
| Service-layer token-bucket rate limiting | `RateLimiter` | `agent-mesh` |
| HTTP middleware for rate-limit headers | `RateLimitMiddleware` | `agent-mesh` |
| Temporary privilege escalation with TTL | `RingElevationManager` | `agent-hypervisor` |
| Behavioral anomaly detection for rogue agents | `RingBreachDetector` | `agent-hypervisor` |
| Wiring all layers into a defense-in-depth pipeline | — | — |

---

## 1. Introduction

Autonomous agents can go rogue. A coding agent might enter an infinite
tool-call loop; a research agent might start accessing privileged APIs it has no
business touching. When that happens, you need controls that work **immediately**
— not on the next polling interval, not after a human reviews a dashboard.

This tutorial covers the three layers of emergency control in the Agent
Governance Toolkit:

```
┌─────────────────────────────────────────────────────┐
│  Layer 1: Kill Switch                               │
│  Immediate termination + saga compensation          │
├─────────────────────────────────────────────────────┤
│  Layer 2: Rate Limiting                             │
│  Token-bucket governors at runtime + HTTP edge      │
├─────────────────────────────────────────────────────┤
│  Layer 3: Ring Enforcement                          │
│  Elevation control + breach detection + circuit     │
│  breakers that auto-trip on anomalous behavior      │
└─────────────────────────────────────────────────────┘
```

### Prerequisites

- Python ≥ 3.11
- `pip install agent-hypervisor` (kill switch, agent rate limiter, rings)
- `pip install agent-mesh` (service-level rate limiter, HTTP middleware)

---

## 2. Quick Start: Your First Kill Switch

Get an agent kill switch running in under 10 lines:

```python
from hypervisor.security.kill_switch import KillSwitch, KillReason

# Create a kill switch
kill_switch = KillSwitch()

# Kill an agent immediately
result = kill_switch.kill(
    agent_did="did:example:rogue-agent",
    session_id="session-001",
    reason=KillReason.MANUAL,
    details="Agent exceeded budget and began accessing unauthorized APIs",
)

print(f"Kill ID:     {result.kill_id}")       # kill:a3f8c912
print(f"Agent:       {result.agent_did}")      # did:example:rogue-agent
print(f"Reason:      {result.reason}")         # manual
print(f"Timestamp:   {result.timestamp}")      # 2025-01-15 14:32:01+00:00
print(f"Total kills: {kill_switch.total_kills}")  # 1
```

That's it — the agent is terminated, and the kill is recorded in an auditable
history. The rest of this tutorial covers every component in detail.

---

## 3. KillSwitch — Immediate Termination

**Source:** `agent-governance-python/agent-hypervisor/src/hypervisor/security/kill_switch.py`

The `KillSwitch` provides immediate, hard termination of an agent with a full
audit trail. In the public preview, all in-flight saga steps are
automatically compensated (rolled back) — there is no handoff to substitute
agents.

### 3.1 Kill Reasons

Every kill must include a reason from the `KillReason` enum. This creates a
searchable, auditable record of *why* each termination happened.

```python
from hypervisor.security.kill_switch import KillReason

# All available reasons:
print(list(KillReason))
```

| Reason | Value | When to Use |
|--------|-------|-------------|
| `BEHAVIORAL_DRIFT` | `"behavioral_drift"` | Agent deviates from expected behavior patterns |
| `RATE_LIMIT` | `"rate_limit"` | Agent exceeded rate limits repeatedly |
| `RING_BREACH` | `"ring_breach"` | Agent attempted actions above its ring level |
| `MANUAL` | `"manual"` | Human operator triggered the kill |
| `QUARANTINE_TIMEOUT` | `"quarantine_timeout"` | Agent was quarantined and didn't recover |
| `SESSION_TIMEOUT` | `"session_timeout"` | Session exceeded its `max_duration_seconds` |

### 3.2 Kill with In-Flight Saga Steps

When you kill an agent that has in-flight saga steps (partially completed
multi-step workflows), the kill switch compensates each step automatically:

```python
from hypervisor.security.kill_switch import (
    KillSwitch,
    KillReason,
    KillResult,
    HandoffStatus,
)

kill_switch = KillSwitch()

# These are the saga steps the agent was in the middle of executing
in_flight_steps = [
    {"step_id": "create-pr",    "saga_id": "deploy-pipeline-42"},
    {"step_id": "run-tests",    "saga_id": "deploy-pipeline-42"},
    {"step_id": "deploy-staging", "saga_id": "deploy-pipeline-42"},
]

result: KillResult = kill_switch.kill(
    agent_did="did:example:deploy-agent",
    session_id="session-deploy-42",
    reason=KillReason.RING_BREACH,
    in_flight_steps=in_flight_steps,
    details="Agent attempted Ring 0 operation from Ring 2",
)

# Every in-flight step is compensated (rolled back)
print(f"Handoffs:              {len(result.handoffs)}")           # 3
print(f"Compensation triggered: {result.compensation_triggered}")  # True
print(f"Handoff successes:     {result.handoff_success_count}")    # 0 (public preview)

for handoff in result.handoffs:
    print(f"  Step {handoff.step_id}: {handoff.status}")
    # Step create-pr: compensated
    # Step run-tests: compensated
    # Step deploy-staging: compensated
    assert handoff.status == HandoffStatus.COMPENSATED
    assert handoff.from_agent == "did:example:deploy-agent"
    assert handoff.to_agent is None  # public preview: no handoff
```

### 3.3 Handoff Status Lifecycle

Each `StepHandoff` tracks the status of a saga step during termination:

| Status | Value | Meaning |
|--------|-------|---------|
| `PENDING` | `"pending"` | Handoff initiated, not yet processed |
| `HANDED_OFF` | `"handed_off"` | Step transferred to substitute agent (enterprise) |
| `FAILED` | `"failed"` | Handoff attempt failed |
| `COMPENSATED` | `"compensated"` | Step rolled back via compensation action |

In the public preview, all steps are always `COMPENSATED` — there is no
substitute agent handoff. This is the safe default: roll back everything.

### 3.4 Substitute Agent Registration

You can register backup agents that could take over work (enterprise edition
enables actual handoff):

```python
kill_switch = KillSwitch()

# Register a backup agent for this session
kill_switch.register_substitute(
    session_id="session-001",
    agent_did="did:example:backup-agent",
)

# Kill the primary agent — in public preview, steps are
# still compensated (not handed off), but the substitute is
# unregistered as part of the kill cleanup
result = kill_switch.kill(
    agent_did="did:example:backup-agent",
    session_id="session-001",
    reason=KillReason.MANUAL,
)

# Unregister a substitute manually
kill_switch.unregister_substitute(
    session_id="session-001",
    agent_did="did:example:another-backup",
)
```

### 3.5 Audit Trail — Kill History

Every kill is recorded and queryable:

```python
kill_switch = KillSwitch()

# Perform several kills
kill_switch.kill("agent-a", "s1", KillReason.RATE_LIMIT)
kill_switch.kill("agent-b", "s1", KillReason.RING_BREACH)
kill_switch.kill("agent-c", "s2", KillReason.BEHAVIORAL_DRIFT)

# Query the full history (returns a copy — safe to iterate)
history = kill_switch.kill_history
print(f"Total kills: {kill_switch.total_kills}")  # 3

for entry in history:
    print(f"  [{entry.timestamp}] {entry.agent_did} — {entry.reason}")

# In public preview, handoff count is always 0
print(f"Total handoffs: {kill_switch.total_handoffs}")  # 0
```

### 3.6 KillResult Reference

The `KillResult` dataclass is returned from every `kill()` call:

| Field | Type | Description |
|-------|------|-------------|
| `kill_id` | `str` | Unique ID, e.g. `"kill:a3f8c912"` |
| `agent_did` | `str` | DID of the killed agent |
| `session_id` | `str` | Session the agent was operating in |
| `reason` | `KillReason` | Why the agent was killed |
| `timestamp` | `datetime` | UTC timestamp of the kill |
| `handoffs` | `list[StepHandoff]` | In-flight saga steps and their disposition |
| `handoff_success_count` | `int` | How many steps were successfully handed off |
| `compensation_triggered` | `bool` | `True` if any step was compensated |
| `details` | `str` | Free-text details about the kill |

---

## 4. AgentRateLimiter — Per-Ring Token Buckets

**Source:** `agent-governance-python/agent-hypervisor/src/hypervisor/security/rate_limiter.py`

The `AgentRateLimiter` enforces per-agent, per-ring rate limits inside the
hypervisor runtime layer using the token bucket algorithm. Higher-privilege rings
get more generous limits.

### 4.1 How Token Buckets Work

```
Token Bucket Algorithm:
┌──────────────────────────────────┐
│  Bucket: capacity=40, rate=20/s  │
│  ████████████████░░░░░░░░░░░░░░  │  ← 16 tokens available
│                                  │
│  Refill: 20 tokens added/second  │
│  Consume: 1 token per request    │
│  If empty → request REJECTED     │
└──────────────────────────────────┘
```

The bucket starts full. Each request consumes tokens. Tokens refill at a
constant rate. If the bucket is empty, the request is rejected. This allows
short bursts (up to bucket capacity) while enforcing a sustained rate.

### 4.2 Default Ring Limits

Each execution ring has default rate limits (tokens per second, burst capacity):

| Ring | Rate (req/s) | Burst Capacity | Use Case |
|------|-------------|----------------|----------|
| Ring 0 (Root) | 100.0 | 200 | Kernel/infrastructure operations |
| Ring 1 (Privileged) | 50.0 | 100 | High-trust agents with consensus |
| Ring 2 (Standard) | 20.0 | 40 | Default for most agents |
| Ring 3 (Sandbox) | 5.0 | 10 | Untrusted / new agents |
| Fallback | 20.0 | 40 | Same as Ring 2 |

Ring 3 (sandbox) agents get 5 requests/second with a burst of 10 — meaning a
new, untrusted agent can make at most 10 rapid-fire calls before being
throttled to a sustained 5/second. Ring 0 agents get 20× that allowance.

### 4.3 Basic Usage

```python
from hypervisor.models import ExecutionRing
from hypervisor.security.rate_limiter import AgentRateLimiter, RateLimitExceeded

# Create a limiter with default ring limits
limiter = AgentRateLimiter()

# Check if an agent can make a request (raises on rejection)
try:
    limiter.check(
        agent_did="did:example:research-agent",
        session_id="session-001",
        ring=ExecutionRing.RING_3_SANDBOX,
        cost=1.0,  # default cost per request
    )
    print("Request allowed")
except RateLimitExceeded as e:
    print(f"Rate limited: {e}")
```

### 4.4 Non-Raising Check

If you prefer a boolean return instead of an exception:

```python
limiter = AgentRateLimiter()

# try_check returns False instead of raising RateLimitExceeded
allowed = limiter.try_check(
    agent_did="did:example:research-agent",
    session_id="session-001",
    ring=ExecutionRing.RING_3_SANDBOX,
)

if not allowed:
    print("Agent is rate limited — back off")
```

### 4.5 Custom Ring Limits

Override the default limits for specific rings:

```python
from hypervisor.models import ExecutionRing
from hypervisor.security.rate_limiter import AgentRateLimiter

# Strict sandbox: 1 request/second, burst of 2
# Generous privileged: 200 requests/second, burst of 500
custom_limits = {
    ExecutionRing.RING_3_SANDBOX:    (1.0, 2.0),    # (rate, capacity)
    ExecutionRing.RING_2_STANDARD:   (10.0, 20.0),
    ExecutionRing.RING_1_PRIVILEGED: (200.0, 500.0),
    ExecutionRing.RING_0_ROOT:       (500.0, 1000.0),
}

limiter = AgentRateLimiter(ring_limits=custom_limits)

# Sandbox agent — very restrictive
assert limiter.try_check("agent-a", "s1", ExecutionRing.RING_3_SANDBOX)  # True
assert limiter.try_check("agent-a", "s1", ExecutionRing.RING_3_SANDBOX)  # True
assert limiter.try_check("agent-a", "s1", ExecutionRing.RING_3_SANDBOX)  # False — exhausted
```

### 4.6 Ring Promotion/Demotion

When an agent's ring changes (e.g., trust score improves), update its rate
limit bucket. The bucket is recreated with the new ring's limits, starting full:

```python
limiter = AgentRateLimiter()

# Agent starts in sandbox
limiter.check("agent-a", "s1", ExecutionRing.RING_3_SANDBOX)

# Agent earns trust and is promoted to Ring 2
limiter.update_ring("agent-a", "s1", ExecutionRing.RING_2_STANDARD)

# Now gets Ring 2 limits (20 req/s, burst 40) — bucket starts full
assert limiter.try_check("agent-a", "s1", ExecutionRing.RING_2_STANDARD)
```

### 4.7 Statistics

Track rate-limiting metrics per agent:

```python
limiter = AgentRateLimiter()

# Generate some traffic
for _ in range(5):
    limiter.check("agent-a", "s1", ExecutionRing.RING_2_STANDARD)

# Get stats
stats = limiter.get_stats("agent-a", "s1")
if stats:
    print(f"Agent DID:        {stats.agent_did}")          # agent-a
    print(f"Ring:             {stats.ring}")                # ExecutionRing.RING_2_STANDARD
    print(f"Total requests:   {stats.total_requests}")     # 5
    print(f"Rejected:         {stats.rejected_requests}")  # 0
    print(f"Tokens available: {stats.tokens_available}")   # ~35.0
    print(f"Bucket capacity:  {stats.capacity}")           # 40.0

# Unknown agents return None
assert limiter.get_stats("unknown-agent", "s1") is None

# Check how many agents are being tracked
print(f"Tracked agents: {limiter.tracked_agents}")  # 1
```

### 4.8 TokenBucket Internals

The `TokenBucket` dataclass is the core primitive:

```python
from hypervisor.security.rate_limiter import TokenBucket

bucket = TokenBucket(
    capacity=10.0,      # maximum tokens
    tokens=10.0,        # current tokens (starts full)
    refill_rate=5.0,    # tokens added per second
)

# Consume a token
assert bucket.consume(1.0) is True   # 9 tokens remaining

# Check available without consuming
print(f"Available: {bucket.available}")  # ~9.0 (plus time-based refill)

# Consuming more than available fails (returns False, no partial consume)
bucket.tokens = 0.0
assert bucket.consume(1.0) is False
```

---

## 5. RateLimiter (Agent Mesh) — HTTP Service Limits

**Source:** `agent-governance-python/agent-mesh/src/agentmesh/services/rate_limiter.py`

While `AgentRateLimiter` operates inside the hypervisor runtime, the Agent Mesh
`RateLimiter` applies limits at the trust-proxy service layer. It uses two
layers of token buckets — per-agent **and** global — with backpressure
signaling.

### 5.1 Two-Tier Limiting

```
Incoming request from Agent A:
┌──────────────────────────────────────────┐
│  1. Per-Agent Bucket                     │
│     Rate: 10 req/s, Capacity: 20        │
│     ✓ Agent A has tokens                 │
├──────────────────────────────────────────┤
│  2. Global Bucket                        │
│     Rate: 100 req/s, Capacity: 200      │
│     ✓ System-wide capacity available     │
├──────────────────────────────────────────┤
│  → Request ALLOWED                       │
└──────────────────────────────────────────┘

If EITHER bucket is empty → Request DENIED
```

### 5.2 Basic Usage

```python
from agentmesh.services.rate_limiter import RateLimiter

# Create with default limits
limiter = RateLimiter(
    global_rate=100,         # 100 tokens/second globally
    global_capacity=200,     # burst up to 200
    per_agent_rate=10,       # 10 tokens/second per agent
    per_agent_capacity=20,   # burst up to 20 per agent
)

# Simple allow/deny check
if limiter.allow("did:mesh:agent-1"):
    print("Request allowed")
else:
    print("Rate limited")
```

### 5.3 Structured Check with Backpressure

The `check()` method returns a `RateLimitResult` with retry information:

```python
from agentmesh.services.rate_limiter import RateLimiter, RateLimitResult

limiter = RateLimiter(
    global_rate=100,
    global_capacity=200,
    per_agent_rate=5,
    per_agent_capacity=5,
    backpressure_threshold=0.8,  # signal at 80% usage
)

result: RateLimitResult = limiter.check("did:mesh:agent-1")

print(f"Allowed:          {result.allowed}")             # True/False
print(f"Remaining tokens: {result.remaining_tokens}")    # tokens left
print(f"Retry after:      {result.retry_after_seconds}") # seconds to wait (if denied)
print(f"Backpressure:     {result.backpressure}")        # True if nearing capacity
```

**Backpressure** is an early warning signal. When an agent has consumed more than
`backpressure_threshold` (default 80%) of its capacity, `backpressure=True`
tells the caller to slow down *before* hitting a hard rejection:

```python
limiter = RateLimiter(
    per_agent_rate=10,
    per_agent_capacity=10,
    backpressure_threshold=0.5,  # signal at 50% usage
)

# Consume 6 of 10 tokens
for _ in range(6):
    limiter.allow("did:mesh:agent-1")

result = limiter.check("did:mesh:agent-1")
assert result.backpressure is True  # usage > 50% → slow down
```

### 5.4 Configuration Model

Use `RateLimitConfig` for structured configuration:

```python
from agentmesh.services.rate_limiter import RateLimitConfig, RateLimiter

config = RateLimitConfig(
    global_rate=100.0,
    global_capacity=200,
    per_agent_rate=10.0,
    per_agent_capacity=20,
    backpressure_threshold=0.8,   # must be 0.0–1.0
)

limiter = RateLimiter(
    global_rate=config.global_rate,
    global_capacity=config.global_capacity,
    per_agent_rate=config.per_agent_rate,
    per_agent_capacity=config.per_agent_capacity,
    backpressure_threshold=config.backpressure_threshold,
)
```

### 5.5 Per-Agent Isolation

Each agent gets its own independent token bucket. One agent burning through
its tokens does not affect another:

```python
limiter = RateLimiter(
    global_rate=1000,
    global_capacity=2000,
    per_agent_rate=5,
    per_agent_capacity=5,
)

# Exhaust agent-1's tokens
for _ in range(5):
    limiter.allow("did:mesh:agent-1")
assert limiter.allow("did:mesh:agent-1") is False  # agent-1 blocked

# agent-2 is completely unaffected
assert limiter.allow("did:mesh:agent-2") is True   # agent-2 still fine
```

### 5.6 Global Limits

The global bucket caps total system throughput — even if individual agents have
tokens remaining:

```python
limiter = RateLimiter(
    global_rate=1,
    global_capacity=3,       # system-wide burst of 3
    per_agent_rate=100,
    per_agent_capacity=100,  # generous per-agent
)

assert limiter.allow("did:mesh:a") is True   # global: 2 left
assert limiter.allow("did:mesh:b") is True   # global: 1 left
assert limiter.allow("did:mesh:c") is True   # global: 0 left
assert limiter.allow("did:mesh:d") is False  # global exhausted!
```

### 5.7 Status and Reset

```python
limiter = RateLimiter()

# Global status
status = limiter.get_status()
print(f"Global tokens:   {status['global_tokens']}")
print(f"Global capacity: {status['global_capacity']}")

# Per-agent status
status = limiter.get_status("did:mesh:agent-1")
print(f"Agent tokens:    {status['agent_tokens']}")
print(f"Agent capacity:  {status['agent_capacity']}")

# Reset a single agent (bucket refilled to capacity)
limiter.reset("did:mesh:agent-1")

# Reset everything (all agents + global bucket)
limiter.reset()
```

### 5.8 Agent Bucket Eviction

The `RateLimiter` automatically evicts the oldest per-agent bucket when the
`max_agent_buckets` limit (default: 100,000) is reached. This prevents unbounded
memory growth in high-cardinality environments:

```python
limiter = RateLimiter(max_agent_buckets=10)

# After 10 unique agents, the 11th evicts the oldest bucket
for i in range(11):
    limiter.allow(f"did:mesh:agent-{i}")
```

### 5.9 Thread Safety

The Agent Mesh `TokenBucket` and `RateLimiter` are thread-safe — all token
operations use `threading.Lock`. This is important for service-layer usage
where multiple HTTP handler threads may be checking limits concurrently.

---

## 6. RateLimitMiddleware — HTTP Edge Enforcement

**Source:** `agent-governance-python/agent-mesh/src/agentmesh/services/rate_limit_middleware.py`

The `RateLimitMiddleware` integrates rate limiting with HTTP request handling.
It extracts agent identity from request headers, checks limits, and decorates
responses with standard rate-limit headers.

### 6.1 Request/Response Flow

```
Incoming HTTP Request
  │
  ├─ Extract agent DID from X-Agent-DID header
  │
  ├─ Check per-agent + global rate limits
  │
  ├─ If DENIED:
  │     → 429 Too Many Requests
  │     → Retry-After header
  │     → X-RateLimit-Remaining: 0
  │
  └─ If ALLOWED:
        → Forward to handler
        → Add rate-limit headers to response
        → X-RateLimit-Remaining: N
        → X-Backpressure: true (if nearing capacity)
```

### 6.2 Basic Setup

```python
from agentmesh.services.rate_limiter import RateLimiter
from agentmesh.services.rate_limit_middleware import (
    RateLimitMiddleware,
    SimpleRequest,
    SimpleResponse,
    HEADER_AGENT_DID,
    HEADER_RATELIMIT_REMAINING,
    HEADER_RETRY_AFTER,
    HEADER_BACKPRESSURE,
)

# Create rate limiter and middleware
limiter = RateLimiter(
    global_rate=100,
    global_capacity=200,
    per_agent_rate=10,
    per_agent_capacity=20,
)
middleware = RateLimitMiddleware(limiter)

# Define your handler
def my_handler(request: SimpleRequest) -> SimpleResponse:
    return SimpleResponse(status_code=200, body={"message": "Hello, Agent!"})

# Process a request through the middleware
request = SimpleRequest(
    headers={HEADER_AGENT_DID: "did:mesh:agent-1"},
    path="/api/actions",
    method="POST",
)

response = middleware.handle(request, my_handler)

print(f"Status: {response.status_code}")                           # 200
print(f"Remaining: {response.headers[HEADER_RATELIMIT_REMAINING]}")  # 18
```

### 6.3 Handling 429 Responses

When an agent exceeds its rate limit, the middleware returns a 429 with
retry information:

```python
limiter = RateLimiter(per_agent_rate=1, per_agent_capacity=1)
middleware = RateLimitMiddleware(limiter)

request = SimpleRequest(headers={HEADER_AGENT_DID: "did:mesh:agent-1"})

# First request — allowed
resp1 = middleware.handle(request, my_handler)
assert resp1.status_code == 200

# Second request — rejected (bucket exhausted)
resp2 = middleware.handle(request, my_handler)
assert resp2.status_code == 429
assert resp2.body == {"error": "Too Many Requests", "retry_after": float(resp2.headers[HEADER_RETRY_AFTER])}

# The Retry-After header tells the agent how long to wait
retry_seconds = float(resp2.headers[HEADER_RETRY_AFTER])
print(f"Retry after: {retry_seconds}s")
```

### 6.4 Anonymous / Default Agent DID

When no `X-Agent-DID` header is present, the middleware falls back to a
configurable default:

```python
# Requests without X-Agent-DID get treated as "anonymous"
middleware = RateLimitMiddleware(limiter, default_agent_did="anonymous")

request = SimpleRequest()  # no DID header
response = middleware.handle(request, my_handler)
assert response.status_code == 200
```

### 6.5 HTTP Headers Reference

| Header | Direction | Description |
|--------|-----------|-------------|
| `X-Agent-DID` | Request | Agent identity for per-agent limiting |
| `X-RateLimit-Remaining` | Response | Tokens remaining (floor integer) |
| `X-RateLimit-Reset` | Response | Seconds until tokens replenish |
| `Retry-After` | Response (429) | Seconds the agent should wait |
| `X-Backpressure` | Response | `"true"` when nearing capacity |

---

## 7. RingElevationManager — Temporary Privilege Escalation

**Source:** `agent-governance-python/agent-hypervisor/src/hypervisor/rings/elevation.py`

The `RingElevationManager` controls temporary ring elevation — allowing an
agent to operate at a higher privilege level for a limited time. In the
public preview, all elevation requests are denied by design.

### 7.1 The 4-Ring Model (Recap)

```
Ring 0 (Root)       — Kernel-only. Never granted via API.
Ring 1 (Privileged) — High-trust agents with consensus attestation.
Ring 2 (Standard)   — Default ring for most agents.
Ring 3 (Sandbox)    — Untrusted, new, or research-only agents.

Lower number = higher privilege.
```

Agents are assigned to rings based on their trust score (see
[Tutorial 06](06-execution-sandboxing.md)). The `RingElevationManager` allows
temporary movement *upward* (toward Ring 0).

### 7.2 Requesting Elevation

```python
from hypervisor.models import ExecutionRing
from hypervisor.rings.elevation import (
    RingElevationManager,
    RingElevationError,
    ElevationDenialReason,
)

manager = RingElevationManager()

# Request elevation from Ring 3 → Ring 2
try:
    elevation = manager.request_elevation(
        agent_did="did:example:new-agent",
        session_id="session-001",
        current_ring=ExecutionRing.RING_3_SANDBOX,
        target_ring=ExecutionRing.RING_2_STANDARD,
        ttl_seconds=300,                    # 5 minutes
        attestation="task-requires-write",  # justification
        reason="Agent needs to write deployment configs",
    )
except RingElevationError as e:
    print(f"Elevation denied!")
    print(f"  Current ring:  {e.current_ring}")    # RING_3_SANDBOX
    print(f"  Target ring:   {e.target_ring}")     # RING_2_STANDARD
    print(f"  Denial reason: {e.denial_reason}")   # community_edition
```

### 7.3 Denial Reasons

Every elevation denial includes a structured reason and remediation guidance:

| Reason | Description | Remediation |
|--------|-------------|-------------|
| `COMMUNITY_EDITION` | Feature not available in free tier | Upgrade to Enterprise |
| `INVALID_TARGET` | Target ring is not higher-privilege | Request a lower-numbered ring |
| `RING_0_FORBIDDEN` | Ring 0 cannot be requested via API | Requires SRE Witness attestation |
| `INSUFFICIENT_TRUST` | Agent's trust score too low | Improve trust through successful operations |
| `NO_SPONSORSHIP` | No Ring 0/1 agent vouched for this | Get sponsorship from privileged agent |
| `EXPIRED_TTL` | TTL exceeded maximum (3600s) | Submit new request with valid TTL |

### 7.4 Validation Rules

The elevation manager enforces strict validation *before* reaching the edition
check:

```python
manager = RingElevationManager()

# Rule 1: Target must be higher privilege (lower value) than current
try:
    manager.request_elevation(
        agent_did="agent-1",
        session_id="s1",
        current_ring=ExecutionRing.RING_2_STANDARD,
        target_ring=ExecutionRing.RING_3_SANDBOX,    # lower privilege!
    )
except RingElevationError as e:
    assert e.denial_reason == ElevationDenialReason.INVALID_TARGET

# Rule 2: Ring 0 is never available via standard API
try:
    manager.request_elevation(
        agent_did="agent-1",
        session_id="s1",
        current_ring=ExecutionRing.RING_2_STANDARD,
        target_ring=ExecutionRing.RING_0_ROOT,       # forbidden!
    )
except RingElevationError as e:
    assert e.denial_reason == ElevationDenialReason.RING_0_FORBIDDEN
```

### 7.5 Error Messages

Elevation errors include structured, actionable messages:

```
Ring elevation denied: Ring 3 (Sandbox) -> Ring 2 (Standard)
  Agent: did:example:new-agent
  Reason: community_edition
  Remediation: Upgrade to the Enterprise edition to enable ring elevation,
    or request access from your organization admin.
  Docs: https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/rings.md
```

### 7.6 RingElevation Data Model

When an elevation *is* granted (enterprise edition), it produces a
`RingElevation` record:

| Field | Type | Description |
|-------|------|-------------|
| `elevation_id` | `str` | Unique ID, e.g. `"elev:b2c9f401"` |
| `agent_did` | `str` | Agent that received the elevation |
| `session_id` | `str` | Session scope of the elevation |
| `original_ring` | `ExecutionRing` | Agent's ring before elevation |
| `elevated_ring` | `ExecutionRing` | Temporary elevated ring |
| `granted_at` | `datetime` | When the elevation was granted |
| `expires_at` | `datetime` | When the elevation expires (TTL) |
| `attestation` | `str \| None` | Justification / attestation string |
| `reason` | `str` | Why elevation was requested |
| `is_active` | `bool` | Whether the elevation is currently active |

### 7.7 Other Manager Methods

```python
manager = RingElevationManager()

# Get the effective ring (considers active elevations)
effective = manager.get_effective_ring(
    agent_did="agent-1",
    session_id="s1",
    base_ring=ExecutionRing.RING_3_SANDBOX,
)
# In public preview, always returns base_ring

# Check for active elevation
elevation = manager.get_active_elevation("agent-1", "s1")
# In public preview, always returns None

# List all active elevations
active = manager.active_elevations  # always [] in public preview

# Tick — expire elapsed elevations (returns revoked list)
revoked = manager.tick()  # always [] in public preview

# Child agent ring assignment: children get demoted one ring from parent
child_ring = manager.register_child(
    parent_did="did:example:parent",
    child_did="did:example:child",
    parent_ring=ExecutionRing.RING_2_STANDARD,
)
assert child_ring == ExecutionRing.RING_3_SANDBOX  # parent Ring 2 → child Ring 3

# Max elevation TTL
print(RingElevationManager.MAX_ELEVATION_TTL)   # 3600 seconds
print(RingElevationManager.DEFAULT_TTL)          # 300 seconds
```

---

## 8. RingBreachDetector — Anomaly Detection

**Source:** `agent-governance-python/agent-hypervisor/src/hypervisor/rings/breach_detector.py`

The `RingBreachDetector` monitors agent behavior for two classes of anomaly:

1. **Tool-call frequency spikes** — an agent's call rate inside a sliding
   window exceeds the baseline by a severity-dependent multiplier.
2. **Privilege-escalation attempts** — a low-privilege agent (Ring 3)
   repeatedly calls into higher-privilege rings (Ring 0/1). The *ring distance*
   amplifies the anomaly score.

When a HIGH or CRITICAL breach is detected, the internal circuit breaker trips
and blocks the agent until explicitly reset.

### 8.1 Anomaly Scoring

The anomaly score combines call rate and ring distance:

```
anomaly_score = (actual_rate / baseline_rate) × ring_distance_amplifier

Where:
  actual_rate      = calls_in_window / window_seconds
  baseline_rate    = expected calls/second (configurable)
  ring_distance    = agent_ring - called_ring (positive = escalation)
  amplifier        = max(ring_distance, 1)
```

Example: A Ring 3 agent calling Ring 0 at 2× the baseline rate:

```
ring_distance = 3 - 0 = 3
anomaly_score = 2.0 × 3 = 6.0  → MEDIUM severity
```

The same rate from a Ring 2 agent calling Ring 2:

```
ring_distance = 2 - 2 = 0 → amplifier = 1
anomaly_score = 2.0 × 1 = 2.0  → LOW severity
```

### 8.2 Severity Thresholds

| Anomaly Score | Severity | Circuit Breaker |
|---------------|----------|-----------------|
| ≥ 20.0 | `CRITICAL` | **Trips** |
| ≥ 10.0 | `HIGH` | **Trips** |
| ≥ 5.0 | `MEDIUM` | No |
| ≥ 2.0 | `LOW` | No |
| < 2.0 | `NONE` | No |

HIGH and CRITICAL breaches automatically trip the circuit breaker for that
agent. Once tripped, the agent is blocked until an operator calls
`reset_breaker()`.

### 8.3 Basic Usage

```python
from hypervisor.models import ExecutionRing
from hypervisor.rings.breach_detector import (
    RingBreachDetector,
    BreachEvent,
    BreachSeverity,
)

# Create a detector with a 60-second window and 10 calls/sec baseline
detector = RingBreachDetector(
    window_seconds=60,
    baseline_rate=10.0,
    max_events_per_agent=1_000,
    max_breach_history=10_000,
)

# Record a normal same-ring call — returns None (no anomaly)
event = detector.record_call(
    agent_did="did:example:agent-1",
    session_id="session-001",
    agent_ring=ExecutionRing.RING_2_STANDARD,
    called_ring=ExecutionRing.RING_2_STANDARD,
)
assert event is None  # normal behavior
```

### 8.4 Detecting Frequency Spikes

```python
# Low baseline to demonstrate breach detection
detector = RingBreachDetector(
    window_seconds=60,
    baseline_rate=0.1,  # expect 0.1 calls/second
)

# Rapid-fire 30 calls — well above baseline
breach = None
for _ in range(30):
    result = detector.record_call(
        agent_did="did:example:chatty-agent",
        session_id="session-001",
        agent_ring=ExecutionRing.RING_2_STANDARD,
        called_ring=ExecutionRing.RING_2_STANDARD,
    )
    if result is not None:
        breach = result

# A breach was detected
assert breach is not None
print(f"Severity:     {breach.severity}")          # low/medium/high/critical
print(f"Anomaly score: {breach.anomaly_score}")    # ratio × amplifier
print(f"Actual rate:  {breach.actual_rate}/s")     # much higher than 0.1
print(f"Expected:     {breach.expected_rate}/s")   # 0.1
print(f"Calls in window: {breach.call_count_window}")
print(f"Details:      {breach.details}")
# "rate=5.00/s (baseline=0.10/s), ring_distance=0, amplifier=1×, score=50.00"
```

### 8.5 Privilege Escalation Amplification

When a low-privilege agent calls into a higher-privilege ring, the anomaly score
is multiplied by the ring distance:

```python
# Ring 3 → Ring 0 (distance = 3) vs Ring 2 → Ring 2 (distance = 0)
detector_same = RingBreachDetector(window_seconds=60, baseline_rate=0.05)
detector_escalate = RingBreachDetector(window_seconds=60, baseline_rate=0.05)

breach_same = None
breach_escalate = None

for _ in range(20):
    r1 = detector_same.record_call(
        "did:example:a", "s1",
        ExecutionRing.RING_2_STANDARD,    # same ring
        ExecutionRing.RING_2_STANDARD,
    )
    r2 = detector_escalate.record_call(
        "did:example:a", "s1",
        ExecutionRing.RING_3_SANDBOX,     # sandbox → root!
        ExecutionRing.RING_0_ROOT,
    )
    if r1: breach_same = r1
    if r2: breach_escalate = r2

# The escalation path produces a much higher anomaly score
assert breach_escalate.anomaly_score > breach_same.anomaly_score
print(f"Same-ring score:    {breach_same.anomaly_score}")
print(f"Escalation score:   {breach_escalate.anomaly_score}")
```

### 8.6 Circuit Breaker

The detector includes an automatic circuit breaker that trips on HIGH or
CRITICAL severity:

```python
detector = RingBreachDetector(window_seconds=60, baseline_rate=0.01)

# Initially not tripped
assert detector.is_breaker_tripped("did:example:agent-1", "session-001") is False

# Generate enough anomalous calls to trip the breaker
for _ in range(50):
    detector.record_call(
        "did:example:agent-1", "session-001",
        ExecutionRing.RING_3_SANDBOX,
        ExecutionRing.RING_0_ROOT,
    )

# Breaker is now tripped — this agent should be blocked
assert detector.is_breaker_tripped("did:example:agent-1", "session-001") is True

# Other agents are unaffected
assert detector.is_breaker_tripped("did:example:agent-2", "session-001") is False
```

### 8.7 Resetting the Breaker

After investigating the breach, an operator can reset the breaker. This also
clears the call window, giving the agent a clean slate:

```python
# Reset the breaker and call window
detector.reset_breaker("did:example:agent-1", "session-001")

assert detector.is_breaker_tripped("did:example:agent-1", "session-001") is False

# The agent can resume normal operations
result = detector.record_call(
    "did:example:agent-1", "session-001",
    ExecutionRing.RING_2_STANDARD,
    ExecutionRing.RING_2_STANDARD,
)
assert result is None  # normal — no breach
```

### 8.8 Breach History

All breach events are stored in a bounded history:

```python
detector = RingBreachDetector(
    window_seconds=60,
    baseline_rate=0.01,
    max_breach_history=10_000,  # bounded to prevent memory growth
)

# Generate some breaches
for _ in range(20):
    detector.record_call(
        "did:example:a", "s1",
        ExecutionRing.RING_3_SANDBOX,
        ExecutionRing.RING_0_ROOT,
    )

# Query history (returns a copy)
history = detector.breach_history
print(f"Total breach events: {detector.breach_count}")

for event in history:
    print(f"  [{event.timestamp}] {event.agent_did} "
          f"severity={event.severity} score={event.anomaly_score}")
```

### 8.9 BreachEvent Reference

| Field | Type | Description |
|-------|------|-------------|
| `agent_did` | `str` | Agent that triggered the breach |
| `session_id` | `str` | Session where the breach occurred |
| `severity` | `BreachSeverity` | `NONE`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `anomaly_score` | `float` | Computed anomaly score |
| `call_count_window` | `int` | Total calls in the current sliding window |
| `expected_rate` | `float` | Baseline calls/second |
| `actual_rate` | `float` | Observed calls/second |
| `timestamp` | `datetime` | When the breach was detected |
| `details` | `str` | Human-readable breakdown of the score |

### 8.10 Bounded Memory Usage

Both the per-agent call window and global breach history are bounded to prevent
unbounded memory growth:

```python
detector = RingBreachDetector(
    window_seconds=3600,           # 1-hour window
    baseline_rate=100.0,
    max_events_per_agent=50,       # bounded per-agent deque
    max_breach_history=10_000,     # bounded global history
)

# Even with 200 calls, the per-agent window holds at most 50
for _ in range(200):
    detector.record_call(
        "did:example:a", "s1",
        ExecutionRing.RING_2_STANDARD,
        ExecutionRing.RING_2_STANDARD,
    )
```

---

## 9. Combining Controls — Defense in Depth

The real power of these components comes from wiring them together into a
multi-layer enforcement pipeline. Here's a complete example:

### 9.1 Architecture

```
Agent Request
  │
  ▼
┌─────────────────────────┐
│ HTTP Middleware          │  RateLimitMiddleware
│ (Agent Mesh edge)       │  → 429 if over global/per-agent limit
├─────────────────────────┤
│ Ring Breach Detection   │  RingBreachDetector
│ (Behavioral analysis)   │  → Circuit breaker if anomalous
├─────────────────────────┤
│ Agent Rate Limiter      │  AgentRateLimiter
│ (Per-ring enforcement)  │  → RateLimitExceeded if over ring limit
├─────────────────────────┤
│ Ring Elevation Check    │  RingElevationManager
│ (Privilege escalation)  │  → Effective ring for this request
├─────────────────────────┤
│ Kill Switch             │  KillSwitch
│ (Emergency termination) │  → Hard kill + saga compensation
└─────────────────────────┘
```

### 9.2 Complete Enforcement Pipeline

```python
from hypervisor.models import ExecutionRing
from hypervisor.security.kill_switch import KillSwitch, KillReason
from hypervisor.security.rate_limiter import AgentRateLimiter, RateLimitExceeded
from hypervisor.rings.breach_detector import RingBreachDetector, BreachSeverity
from hypervisor.rings.elevation import RingElevationManager

# --- Initialize all components ---

kill_switch = KillSwitch()

rate_limiter = AgentRateLimiter()

breach_detector = RingBreachDetector(
    window_seconds=60,
    baseline_rate=10.0,
)

elevation_manager = RingElevationManager()


def enforce_action(
    agent_did: str,
    session_id: str,
    agent_ring: ExecutionRing,
    target_ring: ExecutionRing,
    in_flight_steps: list[dict] | None = None,
) -> bool:
    """
    Multi-layer enforcement pipeline.
    Returns True if the action is allowed, False if blocked.
    """

    # --- Layer 1: Check circuit breaker (breach detector) ---
    if breach_detector.is_breaker_tripped(agent_did, session_id):
        # Agent has a tripped breaker — kill immediately
        kill_switch.kill(
            agent_did=agent_did,
            session_id=session_id,
            reason=KillReason.RING_BREACH,
            in_flight_steps=in_flight_steps,
            details="Circuit breaker tripped — agent blocked",
        )
        return False

    # --- Layer 2: Rate limit check ---
    if not rate_limiter.try_check(agent_did, session_id, agent_ring):
        # Rate limit exceeded — kill if persistent offender
        stats = rate_limiter.get_stats(agent_did, session_id)
        if stats and stats.rejected_requests > 10:
            kill_switch.kill(
                agent_did=agent_did,
                session_id=session_id,
                reason=KillReason.RATE_LIMIT,
                in_flight_steps=in_flight_steps,
                details=f"Rate limit exceeded {stats.rejected_requests} times",
            )
        return False

    # --- Layer 3: Record call for breach detection ---
    breach = breach_detector.record_call(
        agent_did=agent_did,
        session_id=session_id,
        agent_ring=agent_ring,
        called_ring=target_ring,
    )

    if breach and breach.severity in (BreachSeverity.HIGH, BreachSeverity.CRITICAL):
        # Severe breach detected — kill immediately
        kill_switch.kill(
            agent_did=agent_did,
            session_id=session_id,
            reason=KillReason.RING_BREACH,
            in_flight_steps=in_flight_steps,
            details=f"Breach detected: {breach.details}",
        )
        return False

    # --- Layer 4: Check effective ring (considering elevations) ---
    effective_ring = elevation_manager.get_effective_ring(
        agent_did, session_id, agent_ring
    )

    if effective_ring.value > target_ring.value:
        # Agent doesn't have sufficient privilege even with elevation
        return False

    # --- All checks passed ---
    return True


# --- Usage ---

# Normal agent action — allowed
allowed = enforce_action(
    agent_did="did:example:good-agent",
    session_id="session-001",
    agent_ring=ExecutionRing.RING_2_STANDARD,
    target_ring=ExecutionRing.RING_2_STANDARD,
)
print(f"Normal action allowed: {allowed}")  # True

# Check kill history after enforcement
print(f"Total kills: {kill_switch.total_kills}")
print(f"Breach events: {breach_detector.breach_count}")
```

### 9.3 Adding HTTP Edge Protection

Wrap the enforcement pipeline with the Agent Mesh middleware for HTTP services:

```python
from agentmesh.services.rate_limiter import RateLimiter
from agentmesh.services.rate_limit_middleware import (
    RateLimitMiddleware,
    SimpleRequest,
    SimpleResponse,
    HEADER_AGENT_DID,
)

# HTTP-layer rate limiting (outer perimeter)
http_limiter = RateLimiter(
    global_rate=100,
    global_capacity=200,
    per_agent_rate=10,
    per_agent_capacity=20,
    backpressure_threshold=0.8,
)
http_middleware = RateLimitMiddleware(http_limiter)

# Inner enforcement using the pipeline from §9.2
def agent_action_handler(request: SimpleRequest) -> SimpleResponse:
    agent_did = request.headers.get(HEADER_AGENT_DID, "anonymous")
    session_id = request.headers.get("X-Session-ID", "default")

    allowed = enforce_action(
        agent_did=agent_did,
        session_id=session_id,
        agent_ring=ExecutionRing.RING_2_STANDARD,
        target_ring=ExecutionRing.RING_2_STANDARD,
    )

    if not allowed:
        return SimpleResponse(status_code=403, body={"error": "Action denied"})

    return SimpleResponse(status_code=200, body={"result": "success"})

# HTTP request flows through both layers:
#   1. RateLimitMiddleware (HTTP edge) → 429 if over limit
#   2. enforce_action (runtime enforcement) → 403 if ring/breach/kill
request = SimpleRequest(
    headers={HEADER_AGENT_DID: "did:mesh:agent-1", "X-Session-ID": "s1"},
    path="/api/actions",
    method="POST",
)

response = http_middleware.handle(request, agent_action_handler)
print(f"Response: {response.status_code}")  # 200
```

### 9.4 Monitoring the Pipeline

After your pipeline is running, query each component for status:

```python
# Kill switch audit trail
for kill in kill_switch.kill_history:
    print(f"KILL: {kill.agent_did} — {kill.reason} at {kill.timestamp}")
    if kill.compensation_triggered:
        for h in kill.handoffs:
            print(f"  Step {h.step_id}: {h.status}")

# Rate limiter stats
stats = rate_limiter.get_stats("did:example:agent-1", "session-001")
if stats:
    print(f"RATE: {stats.total_requests} requests, "
          f"{stats.rejected_requests} rejected, "
          f"{stats.tokens_available:.1f}/{stats.capacity:.0f} tokens")

# Breach detector history
for event in breach_detector.breach_history[-5:]:  # last 5
    print(f"BREACH: [{event.severity}] {event.agent_did} "
          f"score={event.anomaly_score} — {event.details}")

# HTTP limiter status
http_status = http_limiter.get_status("did:mesh:agent-1")
print(f"HTTP: {http_status['agent_tokens']:.0f}/{http_status['agent_capacity']} "
      f"agent tokens, {http_status['global_tokens']:.0f}/{http_status['global_capacity']} global")
```

---

## 10. Next Steps

- **Tutorial 05 — [Agent Reliability](05-agent-reliability.md):** SRE patterns
  including rogue detection, circuit breakers, SLOs, and chaos testing.
- **Tutorial 06 — [Execution Sandboxing](06-execution-sandboxing.md):** Rings,
  saga orchestration, session isolation, and capability guards — the
  foundational layer that kill switch and rate limiting build on.
- **Tutorial 13 — [Observability & Tracing](13-observability-and-tracing.md):**
  Wire kill switch and breach events into your observability pipeline.
- **Tutorial 04 — [Audit & Compliance](04-audit-and-compliance.md):**
  Hash-chained audit trails for kill switch and rate-limit events.
- **Deployment:** See the [Deployment Guide](../deployment/README.md) for
  Kubernetes Helm values that configure ring-based rate limits in production.

---

## Summary

| Layer | Component | What It Does |
|-------|-----------|--------------|
| **Emergency** | `KillSwitch` | Immediate agent termination with audit trail |
| **Emergency** | `KillReason` | Structured kill reasons (6 variants) |
| **Emergency** | `StepHandoff` | Saga step disposition on kill (compensate/handoff) |
| **Runtime Rate Limit** | `AgentRateLimiter` | Per-agent, per-ring token bucket enforcement |
| **Runtime Rate Limit** | `TokenBucket` | Core token-bucket algorithm with time-based refill |
| **Service Rate Limit** | `RateLimiter` | Two-tier (per-agent + global) service-layer limits |
| **Service Rate Limit** | `RateLimitMiddleware` | HTTP edge enforcement with standard headers |
| **Ring Enforcement** | `RingElevationManager` | Temporary privilege escalation with TTL |
| **Ring Enforcement** | `RingBreachDetector` | Behavioral anomaly detection with circuit breaker |
| **Ring Enforcement** | `BreachSeverity` | 5-level severity classification (NONE→CRITICAL) |

---

## Next Steps

- **Execution Sandboxing:** [Tutorial 06 — Execution Sandboxing](06-execution-sandboxing.md)
- **Observability:** [Tutorial 13 — Observability & Distributed Tracing](13-observability-and-tracing.md)
- **Agent Reliability:** [Tutorial 05 — Agent Reliability Engineering](05-agent-reliability.md)
