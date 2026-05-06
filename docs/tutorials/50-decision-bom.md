# Tutorial 50: Decision Bill of Materials (Decision BOM)

Every governance decision has inputs: who requested it, what policies applied,
what the trust score was, what trace it belongs to. The Decision BOM
reconstructs all of these factors on demand, without requiring agents to
report anything extra.

**Prerequisites:** Install AGT with the mesh package:

```bash
pip install agentmesh-platform
```

## Why Decision BOM?

When an auditor asks "Why was this action allowed?", you need more than a
log entry. You need the full picture:

- Which agent requested the action?
- What was their trust score at that moment?
- Which policies were evaluated? What did each one decide?
- Was there a delegation chain involved?
- What was the OTel trace ID for correlation?

The Decision BOM reconstructs this from existing observability signals.
No new data collection required.

## Core Concepts

### Reconstructible View

Unlike approaches that store a pre-built BOM at decision time, AGT reconstructs
the BOM on demand by querying existing data sources:

```
Audit Logs ──┐
Trust Store ──┤── DecisionBOMReconstructor ──> DecisionBOM
Policy Log ───┤
OTel Traces ──┘
```

This is **non-invasive**: agents don't need to change anything. The BOM
infers everything from signals already being collected.

### Signal Sources (Protocols)

The reconstructor uses protocol-based abstractions so any backend can plug in:

| Source | What It Provides |
|--------|-----------------|
| `AuditSource` | Action logs, agent IDs, outcomes, policy decisions |
| `TrustSource` | Trust scores at a point in time, score history |
| `PolicySource` | Which policies evaluated, what they decided |
| `TraceSource` | OTel spans for latency and correlation |

### Completeness Scoring

Every reconstructed BOM gets a completeness score (0.0 to 1.0) based on how
many required fields could be populated. Five fields are required:

1. `agent_identity` - who acted
2. `trust_score_at_decision` - trust level at the time
3. `policy_rules_evaluated` - which policies ran
4. `action_type` - what was attempted
5. `decision_outcome` - allow/deny/alert

## Step 1: Set Up Signal Sources

Create adapters for your existing observability backends:

```python
from datetime import datetime, timedelta, timezone
from agentmesh.governance.decision_bom import (
    DecisionBOMReconstructor,
    BOMFieldCategory,
)

# Example: wrap your audit log backend
class MyAuditSource:
    def __init__(self, audit_log):
        self._log = audit_log

    def query_by_trace(self, trace_id: str) -> list[dict]:
        return self._log.search(trace_id=trace_id)

    def query_by_agent(self, agent_id: str, start: datetime, end: datetime) -> list[dict]:
        return self._log.search(agent_id=agent_id, start=start, end=end)
```

For this tutorial, we will use in-memory mock sources:

```python
class InMemoryAuditSource:
    def __init__(self):
        self.entries = []

    def add(self, entry: dict):
        self.entries.append(entry)

    def query_by_trace(self, trace_id: str) -> list[dict]:
        return [e for e in self.entries if e.get("trace_id") == trace_id]

    def query_by_agent(self, agent_id: str, start: datetime, end: datetime) -> list[dict]:
        return [e for e in self.entries
                if e.get("agent_did") == agent_id
                and start <= e.get("timestamp", start) <= end]
```

## Step 2: Reconstruct a Single Decision

```python
from datetime import datetime, timezone

now = datetime.now(timezone.utc)

# Set up audit source with a recorded decision
audit = InMemoryAuditSource()
audit.add({
    "trace_id": "trace-abc-123",
    "agent_did": "did:mesh:payment-agent",
    "action": "transfer_funds",
    "resource": "account:checking",
    "outcome": "allow",
    "policy_decision": "allow",
    "session_id": "session-42",
    "timestamp": now,
})

# Create reconstructor
reconstructor = DecisionBOMReconstructor(audit_source=audit)

# Reconstruct the decision BOM
bom = reconstructor.reconstruct(trace_id="trace-abc-123")

print(f"Decision:     {bom.decision_id}")
print(f"Agent:        {bom.agent_id}")
print(f"Action:       {bom.action_requested}")
print(f"Outcome:      {bom.outcome}")
print(f"Completeness: {bom.completeness_score:.0%}")
print(f"Sources:      {bom.sources_queried}")
```

Expected output:

```
Decision:     trace-abc-123
Agent:        did:mesh:payment-agent
Action:       transfer_funds
Outcome:      allow
Completeness: 60%
Sources:      ['audit']
```

Completeness is 60% because we have 3 of 5 required fields (agent_identity,
action_type, decision_outcome) but no trust score or policy evaluation data.

## Step 3: Add Trust Context

Add a trust source to increase completeness:

```python
class InMemoryTrustSource:
    def __init__(self):
        self.scores = {}
        self.history = []

    def get_score_at(self, agent_id: str, timestamp: datetime) -> float | None:
        return self.scores.get(agent_id)

    def get_score_history(self, agent_id: str, start: datetime, end: datetime) -> list[dict]:
        return [h for h in self.history if h.get("agent_id") == agent_id]

trust = InMemoryTrustSource()
trust.scores["did:mesh:payment-agent"] = 0.85
trust.history = [
    {"agent_id": "did:mesh:payment-agent", "score": 0.80},
    {"agent_id": "did:mesh:payment-agent", "score": 0.85},
]

reconstructor = DecisionBOMReconstructor(
    audit_source=audit,
    trust_source=trust,
)

bom = reconstructor.reconstruct(trace_id="trace-abc-123")
print(f"Completeness: {bom.completeness_score:.0%}")  # Now 80%

# Inspect trust fields
for f in bom.get_fields_by_category(BOMFieldCategory.TRUST):
    inferred = " (inferred)" if f.inferred else ""
    print(f"  {f.name}: {f.value}{inferred}")
```

Expected output:

```
Completeness: 80%
  trust_score_at_decision: 0.85
  trust_score_trend: 0.05 (inferred)
```

## Step 4: Full BOM with All Sources

Add policy and trace sources for 100% completeness:

```python
class InMemoryPolicySource:
    def __init__(self):
        self.evaluations = []
        self.active_policies = []

    def get_evaluations(self, trace_id: str) -> list[dict]:
        return [e for e in self.evaluations if e.get("trace_id") == trace_id]

    def get_active_policies_at(self, timestamp: datetime) -> list[dict]:
        return self.active_policies

policy = InMemoryPolicySource()
policy.evaluations = [
    {"trace_id": "trace-abc-123", "rule_name": "max-transfer", "decision": "allow"},
    {"trace_id": "trace-abc-123", "rule_name": "rate-limit", "decision": "allow"},
]

reconstructor = DecisionBOMReconstructor(
    audit_source=audit,
    trust_source=trust,
    policy_source=policy,
)

bom = reconstructor.reconstruct(trace_id="trace-abc-123")
print(f"Completeness: {bom.completeness_score:.0%}")  # 100%
print(f"Sources:      {bom.sources_queried}")
```

## Step 5: Batch Reconstruction

Reconstruct all decisions by an agent in a time range:

```python
# Add more audit entries
audit.add({
    "trace_id": "trace-def-456",
    "agent_did": "did:mesh:payment-agent",
    "action": "read_balance",
    "outcome": "allow",
    "timestamp": now - timedelta(seconds=10),
})

boms = reconstructor.reconstruct_batch(
    agent_id="did:mesh:payment-agent",
    start=now - timedelta(minutes=5),
    end=now + timedelta(seconds=1),
)

print(f"\nReconstructed {len(boms)} decisions:")
for bom in boms:
    print(f"  {bom.action_requested}: {bom.outcome} "
          f"(completeness: {bom.completeness_score:.0%})")
```

## Step 6: Export for Audit

The BOM serializes to a dictionary for storage or API responses:

```python
import json

bom_data = bom.to_dict()
print(json.dumps(bom_data, indent=2, default=str))
```

This produces a structured JSON document with all fields, their categories,
sources, confidence levels, and whether they were inferred.

## Field Categories

Every BOM field is categorized for organized audit reporting:

| Category | Fields |
|----------|--------|
| `identity` | agent_identity |
| `trust` | trust_score_at_decision, trust_score_trend |
| `policy` | policy_rules_evaluated, active_policies, policy_decision |
| `action` | action_type, resource_target |
| `context` | session_context, latency_ms |
| `outcome` | decision_outcome |
| `lineage` | delegation_chain, otel_trace_id |

## API Reference

### DecisionBOMReconstructor

| Method | Description |
|--------|-------------|
| `reconstruct(trace_id, agent_id, timestamp)` | Reconstruct a single BOM |
| `reconstruct_batch(agent_id, start, end)` | Reconstruct all BOMs in a range |
| `available_sources` | List configured signal sources |

### DecisionBOM

| Field | Type | Description |
|-------|------|-------------|
| `decision_id` | `str` | Unique identifier (trace_id or agent@time) |
| `timestamp` | `datetime` | When the decision was made |
| `agent_id` | `str` | The agent involved |
| `action_requested` | `str` | What was attempted |
| `outcome` | `str` | allow, deny, or alert |
| `fields` | `list[BOMField]` | All reconstructed fields |
| `completeness_score` | `float` | 0.0 to 1.0 |
| `sources_queried` | `list[str]` | Which backends were used |

## What's Next

- [Tutorial 04 - Audit & Compliance](04-audit-and-compliance.md): Set up the
  audit logs that feed BOM reconstruction
- [Tutorial 13 - Observability & Tracing](13-observability-and-tracing.md):
  Add OTel traces for full lineage correlation
- [Tutorial 48 - Intent-Based Authorization](48-intent-based-authorization.md):
  Combine intent verification with decision BOMs
