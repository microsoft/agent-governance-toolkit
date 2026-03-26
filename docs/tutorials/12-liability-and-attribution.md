# ⚖️ Tutorial 12 — Liability & Attribution

**Track accountability across multi-agent workflows: who vouched for whom, who caused what, and what penalties apply when things go wrong.**

See also: [Trust & Identity (Tutorial 02)](02-trust-and-identity.md) | [Execution Sandboxing (Tutorial 06)](06-execution-sandboxing.md)

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [What You'll Learn](#2-what-youll-learn)
3. [Installation](#3-installation)
4. [Quick Start: Agent A Vouches for Agent B](#4-quick-start-agent-a-vouches-for-agent-b)
5. [VouchingEngine — Sponsorship Protocol](#5-vouchingengine--sponsorship-protocol)
6. [SlashingEngine — Penalty for Misbehavior](#6-slashingengine--penalty-for-misbehavior)
7. [LiabilityMatrix — Joint Liability Graph](#7-liabilitymatrix--joint-liability-graph)
8. [CausalAttributor — Who Caused What](#8-causalattributor--who-caused-what)
9. [QuarantineManager — Isolating Problematic Agents](#9-quarantinemanager--isolating-problematic-agents)
10. [LiabilityLedger — Immutable Audit Trail](#10-liabilityledger--immutable-audit-trail)
11. [Integration with Trust Scoring](#11-integration-with-trust-scoring)
12. [Real-World Example: Multi-Agent Workflow](#12-real-world-example-multi-agent-workflow)
13. [Next Steps](#13-next-steps)

---

## 1. Introduction

When a single agent acts alone, accountability is straightforward — it either
succeeds or it doesn't. But in multi-agent systems, the picture changes
dramatically:

- **Agent A** vouches for **Agent B**, who then vouches for **Agent C**.
- **Agent C** deletes a production database.
- Who is liable? Just C? B for sponsoring C? A for trusting B?

Without a formal liability framework you can't answer these questions. The
Agent Governance Toolkit solves this with six composable components:

```
┌──────────────────────────────────────────────────────────┐
│                  Liability Framework                     │
├──────────────┬───────────────────────────────────────────┤
│  Vouching    │  Agents sponsor each other with bonds     │
│  Engine      │  that create skin-in-the-game incentives  │
├──────────────┼───────────────────────────────────────────┤
│  Slashing    │  Penalties cascade through the vouching   │
│  Engine      │  graph when a sponsored agent misbehaves  │
├──────────────┼───────────────────────────────────────────┤
│  Liability   │  Directed graph tracking sponsor →        │
│  Matrix      │  sponsored relationships and exposure     │
├──────────────┼───────────────────────────────────────────┤
│  Causal      │  Fault attribution via causal chain       │
│  Attributor  │  analysis for saga/workflow failures      │
├──────────────┼───────────────────────────────────────────┤
│  Quarantine  │  Isolate agents pending investigation     │
│  Manager     │  after severe violations                  │
├──────────────┼───────────────────────────────────────────┤
│  Liability   │  Immutable ledger recording every         │
│  Ledger      │  liability event for auditing             │
└──────────────┴───────────────────────────────────────────┘
```

### Prerequisites

- Python ≥ 3.11
- `pip install agentmesh-runtime` (v2.0.2+)

---

## 2. What You'll Learn

| Topic | Skill | Section |
|-------|-------|---------|
| Vouching / Sponsorship | Create bonds where high-trust agents vouch for newcomers | [§5](#5-vouchingengine--sponsorship-protocol) |
| Penalty Slashing | Cascade penalties through the sponsorship graph | [§6](#6-slashingengine--penalty-for-misbehavior) |
| Liability Graphs | Visualize and query sponsor → sponsored relationships | [§7](#7-liabilitymatrix--joint-liability-graph) |
| Causal Attribution | Determine root cause in multi-step workflow failures | [§8](#8-causalattributor--who-caused-what) |
| Agent Quarantine | Isolate agents that violate policies | [§9](#9-quarantinemanager--isolating-problematic-agents) |
| Audit Ledger | Maintain immutable records of all liability events | [§10](#10-liabilityledger--immutable-audit-trail) |
| Trust Integration | Connect liability outcomes to trust scores | [§11](#11-integration-with-trust-scoring) |
| End-to-End Workflow | Full example combining all six components | [§12](#12-real-world-example-multi-agent-workflow) |

---

## 3. Installation

Install the runtime package which re-exports all liability classes from the
hypervisor:

```bash
pip install agentmesh-runtime
```

Verify the installation:

```python
from agent_runtime import (
    VouchingEngine,
    SlashingEngine,
    LiabilityMatrix,
    CausalAttributor,
    QuarantineManager,
    LiabilityLedger,
)

print("Liability framework ready ✓")
```

You can also import directly from the hypervisor package:

```python
from hypervisor import (
    VouchingEngine,
    VouchRecord,
    SlashingEngine,
    LiabilityMatrix,
    CausalAttributor,
    AttributionResult,
    QuarantineManager,
    QuarantineReason,
    LiabilityLedger,
    LedgerEntryType,
)
```

---

## 4. Quick Start: Agent A Vouches for Agent B

Get vouching running in under 15 lines:

```python
from hypervisor import VouchingEngine

# 1. Create the vouching engine
engine = VouchingEngine()

# 2. Agent A (high trust, σ=0.85) vouches for Agent B (newcomer)
record = engine.vouch(
    voucher_did="did:mesh:agent-a",
    vouchee_did="did:mesh:agent-b",
    session_id="session:onboarding-001",
    voucher_sigma=0.85,
)

print(record.vouch_id)      # "vouch:a1b2c3d4"
print(record.voucher_did)   # "did:mesh:agent-a"
print(record.vouchee_did)   # "did:mesh:agent-b"
print(record.is_active)     # True
print(record.is_expired)    # False

# 3. Check who vouches for Agent B
sponsors = engine.get_vouchers_for("did:mesh:agent-b", "session:onboarding-001")
print(f"Agent B has {len(sponsors)} sponsor(s)")  # 1
```

That's it — Agent A has staked its reputation on Agent B. If Agent B
misbehaves, the slashing engine can propagate penalties back to Agent A.

---

## 5. VouchingEngine — Sponsorship Protocol

The `VouchingEngine` implements a sponsorship model inspired by proof-of-stake
systems. High-trust agents "vouch" for lower-trust agents by bonding a
percentage of their own trust score.

### 5.1 Creating a Vouch

```python
from hypervisor import VouchingEngine

engine = VouchingEngine(max_exposure=0.80)

# Vouch with explicit bond percentage and expiry
from datetime import datetime, timedelta, UTC

record = engine.vouch(
    voucher_did="did:mesh:senior-agent",
    vouchee_did="did:mesh:junior-agent",
    session_id="session:data-pipeline",
    voucher_sigma=0.90,
    bond_pct=0.15,                                    # 15% of σ bonded
    expiry=datetime.now(UTC) + timedelta(hours=2),    # Auto-expire after 2h
)

print(record.bonded_sigma_pct)  # 0.15
print(record.bonded_amount)     # 0.135 (0.90 × 0.15)
```

### 5.3 Effective Score Computation

The vouching engine computes an effective score for the vouchee that considers
its own trust score and the sponsorship context:

```python
eff_score = engine.compute_eff_score(
    vouchee_did="did:mesh:junior-agent",
    session_id="session:data-pipeline",
    vouchee_sigma=0.45,
    risk_weight=0.5,
)
print(f"Effective score: {eff_score}")
```

> **Community Edition:** In the community edition, `compute_eff_score` returns
> the vouchee's own sigma directly — sponsor boost is an enterprise feature.
> The vouching graph is still tracked for auditing and liability analysis.

### 5.4 Exposure Tracking

Track how much total reputation a voucher has at risk:

```python
# Agent vouches for multiple agents in the same session
engine.vouch("did:mesh:lead", "did:mesh:worker-1", "session:batch", 0.90)
engine.vouch("did:mesh:lead", "did:mesh:worker-2", "session:batch", 0.90)
engine.vouch("did:mesh:lead", "did:mesh:worker-3", "session:batch", 0.90)

exposure = engine.get_total_exposure("did:mesh:lead", "session:batch")
print(f"Total exposure: {exposure}")  # Sum of bonded amounts
```

### 5.5 Releasing Bonds

Bonds can be released individually or in bulk when a session ends:

```python
# Release a single bond
engine.release_bond(record.vouch_id)
print(record.is_active)  # False

# Release all bonds for a session (call at session cleanup)
count = engine.release_session_bonds("session:batch")
print(f"Released {count} bonds")
```

### 5.6 Configuration Constants

| Constant | Default | Description |
|----------|---------|-------------|
| `SCORE_SCALE` | `1000.0` | Score normalization factor |
| `MIN_VOUCHER_SCORE` | `0.50` | Minimum σ required to vouch for others |
| `DEFAULT_BOND_PCT` | `0.20` | Default bond percentage (20% of σ) |
| `DEFAULT_MAX_EXPOSURE` | `0.80` | Max total exposure per voucher (80% of σ) |

---

## 6. SlashingEngine — Penalty for Misbehavior

When a sponsored agent misbehaves, the `SlashingEngine` applies penalties that
cascade through the vouching graph — penalizing both the offender and its
sponsors.

### 6.1 How Slashing Works

```
Agent A (voucher)                Agent B (vouchee)
   σ = 0.90                        σ = 0.70
       │                               │
       └───── vouches for ─────────────┘
                                       │
                                  B misbehaves
                                       │
                              ┌────────┴────────┐
                              │  SlashingEngine  │
                              ├─────────────────┤
                              │ B: σ 0.70 → ?   │ ← direct penalty
                              │ A: σ 0.90 → ?   │ ← cascade penalty
                              └─────────────────┘
```

### 6.2 Triggering a Slash

```python
from hypervisor import VouchingEngine, SlashingEngine

# Set up the engines
vouching = VouchingEngine()
slashing = SlashingEngine(vouching)

# Agent A vouches for Agent B
vouching.vouch(
    voucher_did="did:mesh:agent-a",
    vouchee_did="did:mesh:agent-b",
    session_id="session:prod-deploy",
    voucher_sigma=0.90,
)

# Agent B performs an unauthorized action → slash
result = slashing.slash(
    vouchee_did="did:mesh:agent-b",
    session_id="session:prod-deploy",
    vouchee_sigma=0.70,
    risk_weight=0.95,
    reason="Unauthorized write to production database",
    agent_scores={"did:mesh:agent-a": 0.90, "did:mesh:agent-b": 0.70},
)

print(result.slash_id)              # "slash:abc123"
print(result.vouchee_did)           # "did:mesh:agent-b"
print(result.vouchee_sigma_before)  # 0.70
print(result.vouchee_sigma_after)   # Reduced score
print(result.reason)                # "Unauthorized write to production database"
print(result.cascade_depth)         # 0 (direct slash)
```

### 6.3 Voucher Clips (Cascade Penalties)

Each slash result includes `voucher_clips` — the penalties applied to sponsors:

```python
for clip in result.voucher_clips:
    print(f"Voucher: {clip.voucher_did}")
    print(f"  σ before: {clip.sigma_before}")
    print(f"  σ after:  {clip.sigma_after}")
    print(f"  Risk weight: {clip.risk_weight}")
    print(f"  Vouch ID: {clip.vouch_id}")
```

> **Community Edition:** In the community edition, slashing is logged but
> scores are not actually modified. The `SlashResult` records are still created
> for auditing. Enterprise editions enforce real score deductions.

### 6.4 Cascade Depth

The slashing engine limits cascade depth to prevent runaway penalty chains:

```python
# MAX_CASCADE_DEPTH = 2
# Penalties propagate at most 2 levels up the sponsorship graph:
#   Agent C (offender) → Agent B (direct sponsor) → Agent A (indirect sponsor)

# SIGMA_FLOOR = 0.05
# No agent's score is slashed below 0.05 — prevents permanent exclusion
```

### 6.5 Slash History

Review all past slashing events:

```python
for entry in slashing.history:
    print(f"[{entry.timestamp}] {entry.vouchee_did}: {entry.reason}")
    print(f"  σ {entry.vouchee_sigma_before:.2f} → {entry.vouchee_sigma_after:.2f}")
    print(f"  Vouchers affected: {len(entry.voucher_clips)}")
```

---

## 7. LiabilityMatrix — Joint Liability Graph

The `LiabilityMatrix` models the sponsor → sponsored relationships as a
directed graph. It's the data structure that answers "if this agent fails, who
else is liable?"

### 7.1 Building the Graph

```python
from hypervisor import LiabilityMatrix

matrix = LiabilityMatrix(session_id="session:data-pipeline")

# Agent A sponsors Agent B and Agent C
matrix.add_edge("did:mesh:agent-a", "did:mesh:agent-b", bonded_amount=0.18, vouch_id="v1")
matrix.add_edge("did:mesh:agent-a", "did:mesh:agent-c", bonded_amount=0.15, vouch_id="v2")

# Agent B sponsors Agent D
matrix.add_edge("did:mesh:agent-b", "did:mesh:agent-d", bonded_amount=0.10, vouch_id="v3")
```

This creates the following liability graph:

```
        Agent A (σ bonded: 0.33)
       ╱         ╲
      ↓           ↓
  Agent B       Agent C
  (0.18)        (0.15)
      │
      ↓
  Agent D
  (0.10)
```

### 7.2 Querying the Graph

```python
# Who sponsors Agent D?
sponsors = matrix.who_vouches_for("did:mesh:agent-d")
for edge in sponsors:
    print(f"{edge.voucher_did} → {edge.vouchee_did} ({edge.bonded_amount})")
# Output: did:mesh:agent-b → did:mesh:agent-d (0.10)

# Who does Agent A sponsor?
sponsored = matrix.who_is_vouched_by("did:mesh:agent-a")
for edge in sponsored:
    print(f"{edge.voucher_did} → {edge.vouchee_did}")
# Output:
#   did:mesh:agent-a → did:mesh:agent-b
#   did:mesh:agent-a → did:mesh:agent-c

# Total exposure for Agent A
exposure = matrix.total_exposure("did:mesh:agent-a")
print(f"Agent A total exposure: {exposure}")  # 0.33
```

### 7.3 Cascade Path Analysis

Find all paths through which penalties would propagate if an agent is slashed:

```python
# If Agent D misbehaves, who is affected?
paths = matrix.cascade_path("did:mesh:agent-b", max_depth=2)
print(paths)
# Returns all DFS paths from agent-b through sponsored agents
# e.g., [["did:mesh:agent-b", "did:mesh:agent-d"]]
```

### 7.4 Cycle Detection

Circular vouching (A sponsors B, B sponsors A) creates infinite cascade risk.
The matrix detects this:

```python
# Detect circular dependencies
matrix_risky = LiabilityMatrix(session_id="session:test")
matrix_risky.add_edge("did:a", "did:b", 0.2, "v1")
matrix_risky.add_edge("did:b", "did:a", 0.2, "v2")  # Creates a cycle!

assert matrix_risky.has_cycle() is True

# Safe graph — no cycles
matrix_safe = LiabilityMatrix(session_id="session:test-safe")
matrix_safe.add_edge("did:a", "did:b", 0.2, "v1")
matrix_safe.add_edge("did:b", "did:c", 0.2, "v2")

assert matrix_safe.has_cycle() is False
```

### 7.5 Session Cleanup

Release all bonds when a session ends:

```python
# View current edges
print(f"Active edges: {len(matrix.edges)}")  # 3

# Clear everything
matrix.clear()
print(f"Active edges: {len(matrix.edges)}")  # 0
```

---

## 8. CausalAttributor — Who Caused What

When a multi-step saga fails, the `CausalAttributor` traces the causal chain
to determine which agent is responsible — and how much liability each
participant bears.

### 8.1 How Causal Attribution Works

In a saga (multi-step workflow), each agent performs actions. When a step fails,
the attributor:

1. Identifies the **failure step** and the **failure agent** (direct cause).
2. Traces the **causal chain** — which preceding actions contributed.
3. Assigns a **liability score** to each involved agent.

```
Saga: data-pipeline-001
  Step 1: Agent A → fetch data      ✓
  Step 2: Agent B → transform data  ✓
  Step 3: Agent C → write to DB     ✗ FAILED
  Step 4: Agent D → notify          (skipped)

Attribution:
  Agent C → liability: 1.0 (direct cause)
  Agent B → liability: 0.0 (not at fault)
  Agent A → liability: 0.0 (not at fault)
```

### 8.2 Running an Attribution

```python
from hypervisor import CausalAttributor

attributor = CausalAttributor()

# Define what each agent did in the saga
agent_actions = {
    "did:mesh:fetcher": [
        {"step_id": "step-1", "action": "fetch_data", "status": "success"},
    ],
    "did:mesh:transformer": [
        {"step_id": "step-2", "action": "transform", "status": "success"},
    ],
    "did:mesh:writer": [
        {"step_id": "step-3", "action": "write_db", "status": "failed"},
    ],
}

result = attributor.attribute(
    saga_id="saga:pipeline-001",
    session_id="session:nightly-run",
    agent_actions=agent_actions,
    failure_step_id="step-3",
    failure_agent_did="did:mesh:writer",
    risk_weights={"did:mesh:writer": 0.95, "did:mesh:transformer": 0.5},
)

print(result.attribution_id)    # "attr:a1b2c3d4"
print(result.saga_id)           # "saga:pipeline-001"
print(result.root_cause_agent)  # "did:mesh:writer"
print(result.causal_chain_length)
print(result.agents_involved)   # ["did:mesh:fetcher", "did:mesh:transformer", "did:mesh:writer"]
```

### 8.3 Reading Fault Attributions

Each `AttributionResult` contains a list of `FaultAttribution` objects:

```python
for attr in result.attributions:
    print(f"Agent: {attr.agent_did}")
    print(f"  Liability score:      {attr.liability_score}")
    print(f"  Causal contribution:  {attr.causal_contribution}")
    print(f"  Direct cause:         {attr.is_direct_cause}")
    print(f"  Reason:               {attr.reason}")

# Get liability for a specific agent
writer_liability = result.get_liability("did:mesh:writer")
print(f"Writer liability: {writer_liability}")  # 1.0 (full liability)
```

### 8.4 Attribution History

Review all past attributions:

```python
for past in attributor.attribution_history:
    print(f"[{past.timestamp}] Saga: {past.saga_id}")
    print(f"  Root cause: {past.root_cause_agent}")
    print(f"  Agents involved: {', '.join(past.agents_involved)}")
```

---

## 9. QuarantineManager — Isolating Problematic Agents

When an agent's behavior becomes dangerous — repeated slashing, ring breaches,
or rate-limit abuse — the `QuarantineManager` isolates it from the system.

### 9.1 Quarantine Reasons

```python
from hypervisor import QuarantineReason

# All possible quarantine reasons:
QuarantineReason.BEHAVIORAL_DRIFT    # Agent deviated from expected behavior
QuarantineReason.LIABILITY_VIOLATION  # Exceeded liability thresholds
QuarantineReason.RING_BREACH         # Attempted action above privilege level
QuarantineReason.RATE_LIMIT_EXCEEDED # Too many calls in time window
QuarantineReason.MANUAL              # Human operator decision
QuarantineReason.CASCADE_SLASH       # Quarantined as part of slash cascade
```

### 9.2 Quarantining an Agent

```python
from hypervisor import QuarantineManager, QuarantineReason

qm = QuarantineManager()

# Quarantine Agent C for a ring breach
record = qm.quarantine(
    agent_did="did:mesh:agent-c",
    session_id="session:prod-deploy",
    reason=QuarantineReason.RING_BREACH,
    details="Attempted Ring 1 action with Ring 3 credentials",
    duration_seconds=600,       # 10-minute quarantine
    forensic_data={
        "attempted_action": "deploy.k8s",
        "agent_ring": 3,
        "required_ring": 1,
    },
)

print(record.quarantine_id)  # "quar:a1b2c3d4"
print(record.reason)         # QuarantineReason.RING_BREACH
print(record.is_active)      # True
print(record.expires_at)     # ~10 minutes from now
print(record.forensic_data)  # The evidence dict
```

### 9.3 Checking Quarantine Status

```python
# Is this agent quarantined?
is_quarantined = qm.is_quarantined("did:mesh:agent-c", "session:prod-deploy")
print(is_quarantined)  # True or False

# Get the active quarantine record
active = qm.get_active_quarantine("did:mesh:agent-c", "session:prod-deploy")
if active:
    print(f"Quarantined since: {active.entered_at}")
    print(f"Expires at: {active.expires_at}")
    print(f"Duration: {active.duration_seconds}s")
```

> **Community Edition:** In the community edition, `is_quarantined()` always
> returns `False` and `active_quarantines` is always empty. Quarantine records
> are still created for auditing. Enterprise editions enforce actual isolation.

### 9.4 Releasing from Quarantine

```python
# Manual release (e.g., after investigation)
released = qm.release("did:mesh:agent-c", "session:prod-deploy")
if released:
    print(f"Released at: {released.released_at}")

# Automatic expiry — call tick() periodically to process expirations
expired_records = qm.tick()
for record in expired_records:
    print(f"Auto-released: {record.agent_did}")
```

### 9.5 Quarantine History

```python
# Get all quarantine records (active + expired + released)
all_history = qm.get_history()
print(f"Total quarantine events: {len(all_history)}")

# Filter by agent
agent_history = qm.get_history(agent_did="did:mesh:agent-c")

# Filter by session
session_history = qm.get_history(session_id="session:prod-deploy")

# Current quarantine stats
print(f"Active quarantines: {qm.quarantine_count}")
print(f"Active records: {qm.active_quarantines}")
```

### 9.6 Default Quarantine Duration

If no `duration_seconds` is specified, the default is **300 seconds** (5 minutes):

```python
# QuarantineManager.DEFAULT_QUARANTINE_SECONDS = 300

record = qm.quarantine(
    agent_did="did:mesh:agent-x",
    session_id="session:test",
    reason=QuarantineReason.MANUAL,
    details="Under investigation",
    # duration_seconds omitted → defaults to 300s
)
```

---

## 10. LiabilityLedger — Immutable Audit Trail

The `LiabilityLedger` records every liability event — vouches given, slashes
received, quarantine entries — into an append-only log. This is the
authoritative source for an agent's liability history.

### 10.1 Event Types

```python
from hypervisor import LedgerEntryType

# All event types recorded in the ledger:
LedgerEntryType.VOUCH_GIVEN          # Agent vouched for another
LedgerEntryType.VOUCH_RECEIVED       # Agent received a vouch
LedgerEntryType.VOUCH_RELEASED       # Vouch bond was released
LedgerEntryType.SLASH_RECEIVED       # Agent was directly slashed
LedgerEntryType.SLASH_CASCADED       # Agent penalized via cascade
LedgerEntryType.QUARANTINE_ENTERED   # Agent entered quarantine
LedgerEntryType.QUARANTINE_RELEASED  # Agent released from quarantine
LedgerEntryType.FAULT_ATTRIBUTED     # Agent received fault attribution
LedgerEntryType.CLEAN_SESSION        # Agent completed a session cleanly
```

### 10.2 Recording Events

```python
from hypervisor import LiabilityLedger, LedgerEntryType

ledger = LiabilityLedger()

# Record a vouch event
entry = ledger.record(
    agent_did="did:mesh:agent-a",
    entry_type=LedgerEntryType.VOUCH_GIVEN,
    session_id="session:pipeline",
    severity=0.0,
    details="Vouched for did:mesh:agent-b with 20% bond",
    related_agent="did:mesh:agent-b",
)
print(entry.entry_id)    # "a1b2c3d4e5f6"
print(entry.timestamp)   # datetime

# Record a slash event
ledger.record(
    agent_did="did:mesh:agent-b",
    entry_type=LedgerEntryType.SLASH_RECEIVED,
    session_id="session:pipeline",
    severity=0.8,
    details="Unauthorized database write",
)

# Record a clean session (positive signal)
ledger.record(
    agent_did="did:mesh:agent-a",
    entry_type=LedgerEntryType.CLEAN_SESSION,
    session_id="session:pipeline",
    severity=0.0,
    details="Completed session without incidents",
)
```

### 10.3 Agent History

```python
# Get full history for an agent
history = ledger.get_agent_history("did:mesh:agent-a")
for entry in history:
    print(f"[{entry.timestamp}] {entry.entry_type.value}: {entry.details}")

# Ledger statistics
print(f"Total entries: {ledger.total_entries}")
print(f"Tracked agents: {ledger.tracked_agents}")
```

### 10.4 Risk Profiles

The ledger computes an `AgentRiskProfile` — a summary of an agent's liability
track record:

```python
profile = ledger.compute_risk_profile("did:mesh:agent-b")

print(f"Agent: {profile.agent_did}")
print(f"Total entries:      {profile.total_entries}")
print(f"Slash count:        {profile.slash_count}")
print(f"Quarantine count:   {profile.quarantine_count}")
print(f"Clean sessions:     {profile.clean_session_count}")
print(f"Avg fault score:    {profile.fault_score_avg:.2f}")
print(f"Risk score:         {profile.risk_score:.2f}")
print(f"Recommendation:     {profile.recommendation}")  # "admit", "probation", or "deny"
```

### 10.5 Admission Decisions

The ledger can recommend whether an agent should be admitted to new sessions
based on its track record:

```python
should_admit, reason = ledger.should_admit("did:mesh:agent-b")
print(f"Admit: {should_admit}")  # True/False
print(f"Reason: {reason}")       # "admit" / "probation" / "deny"
```

> **Community Edition:** `should_admit()` always returns `(True, "admit")`.
> The risk profile is still computed for visibility. Enterprise editions enforce
> admission gates.

### 10.6 Thresholds

| Constant | Value | Description |
|----------|-------|-------------|
| `PROBATION_THRESHOLD` | `0.3` | Risk score ≥ 0.3 triggers probation recommendation |
| `DENY_THRESHOLD` | `0.6` | Risk score ≥ 0.6 triggers deny recommendation |

---

## 11. Integration with Trust Scoring

The liability framework connects directly to the trust and identity system
described in [Tutorial 02 — Trust & Identity](02-trust-and-identity.md). Here's
how the pieces fit together:

### 11.1 Trust → Liability Flow

```
┌───────────────┐     ┌──────────────┐     ┌───────────────────┐
│ Trust Score    │────▶│ Vouching     │────▶│ Liability Matrix  │
│ (σ = 0.85)    │     │ Engine       │     │ (graph edges)     │
└───────────────┘     └──────────────┘     └───────────────────┘
                            │
                            ▼
┌───────────────┐     ┌──────────────┐     ┌───────────────────┐
│ Effective     │◀────│ Bond Amount  │     │ Slash Cascade     │
│ Score         │     │ (σ × bond%)  │     │ (depth ≤ 2)       │
└───────────────┘     └──────────────┘     └───────────────────┘
```

### 11.2 Vouching Requires Minimum Trust

Only agents above the minimum voucher score threshold can sponsor others:

```python
from hypervisor import VouchingEngine

engine = VouchingEngine()

# MIN_VOUCHER_SCORE = 0.50
# Agent with σ = 0.85 → can vouch ✓
record = engine.vouch(
    voucher_did="did:mesh:trusted",
    vouchee_did="did:mesh:newcomer",
    session_id="session:test",
    voucher_sigma=0.85,
)
print(f"Vouch created: {record.is_active}")
```

### 11.3 Slashing Affects Trust Scores

When the hypervisor detects behavioral drift, it automatically slashes the
offending agent — which feeds back into the trust system:

```python
from hypervisor import Hypervisor

hv = Hypervisor()

# The verify_behavior() method checks for drift and auto-slashes:
# result = await hv.verify_behavior(
#     session_id="session:prod",
#     agent_did="did:mesh:agent-b",
#     claimed_embedding=claimed,
#     observed_embedding=observed,
# )
# If drift_score exceeds the threshold, the hypervisor calls:
#   hv.slashing.slash(...)
# which reduces the agent's score and cascades to its sponsors.
```

### 11.4 Ledger → Ring Assignment

An agent's liability history influences its trust score, which determines its
execution ring (see [Tutorial 06 — Execution Sandboxing](06-execution-sandboxing.md)):

```
Liability Ledger    →    Risk Profile    →    Trust Score (σ)    →    Ring
  3 clean sessions        risk: 0.1            σ = 0.82              Ring 2
  0 slashes               recommend: admit
```

```python
# Check if an agent's liability record supports admission
admit, reason = ledger.should_admit("did:mesh:agent-b")

if admit and reason == "admit":
    # Full access — score maps to Ring 2 or above
    pass
elif admit and reason == "probation":
    # Limited access — restrict to Ring 3 sandbox
    pass
else:
    # Deny — agent has too many violations
    pass
```

---

## 12. Real-World Example: Multi-Agent Workflow

Let's combine all six components in a realistic scenario: a **data pipeline**
where three agents collaborate, one of them fails, and the system traces
liability end-to-end.

### Scenario

- **Fetcher** (high trust, σ=0.90) — retrieves data from external API
- **Transformer** (medium trust, σ=0.65) — processes and cleans data
- **Writer** (lower trust, σ=0.50) — writes results to database

Fetcher vouches for Transformer, Transformer vouches for Writer. During
execution, Writer attempts an unauthorized schema migration and fails.

### Full Implementation

```python
from datetime import datetime, UTC
from hypervisor import (
    VouchingEngine,
    SlashingEngine,
    LiabilityMatrix,
    CausalAttributor,
    QuarantineManager,
    QuarantineReason,
    LiabilityLedger,
    LedgerEntryType,
)

SESSION = "session:nightly-pipeline-2025-07-22"

# ── 1. Initialize all engines ────────────────────────────────────────────

vouching = VouchingEngine(max_exposure=0.80)
slashing = SlashingEngine(vouching)
matrix   = LiabilityMatrix(session_id=SESSION)
attributor = CausalAttributor()
quarantine = QuarantineManager()
ledger     = LiabilityLedger()

# ── 2. Establish vouching chain ──────────────────────────────────────────

# Fetcher (σ=0.90) vouches for Transformer
v1 = vouching.vouch(
    voucher_did="did:mesh:fetcher",
    vouchee_did="did:mesh:transformer",
    session_id=SESSION,
    voucher_sigma=0.90,
    bond_pct=0.20,
)
matrix.add_edge("did:mesh:fetcher", "did:mesh:transformer", v1.bonded_amount, v1.vouch_id)

ledger.record("did:mesh:fetcher", LedgerEntryType.VOUCH_GIVEN, SESSION,
              details="Vouched for transformer", related_agent="did:mesh:transformer")
ledger.record("did:mesh:transformer", LedgerEntryType.VOUCH_RECEIVED, SESSION,
              details="Vouched by fetcher", related_agent="did:mesh:fetcher")

# Transformer (σ=0.65) vouches for Writer
v2 = vouching.vouch(
    voucher_did="did:mesh:transformer",
    vouchee_did="did:mesh:writer",
    session_id=SESSION,
    voucher_sigma=0.65,
    bond_pct=0.15,
)
matrix.add_edge("did:mesh:transformer", "did:mesh:writer", v2.bonded_amount, v2.vouch_id)

ledger.record("did:mesh:transformer", LedgerEntryType.VOUCH_GIVEN, SESSION,
              details="Vouched for writer", related_agent="did:mesh:writer")
ledger.record("did:mesh:writer", LedgerEntryType.VOUCH_RECEIVED, SESSION,
              details="Vouched by transformer", related_agent="did:mesh:transformer")

print("Vouching chain established:")
print(f"  Fetcher → Transformer (bond: {v1.bonded_amount:.3f})")
print(f"  Transformer → Writer  (bond: {v2.bonded_amount:.3f})")
print(f"  Cycle detected: {matrix.has_cycle()}")  # False

# ── 3. Simulate pipeline execution ──────────────────────────────────────

agent_actions = {
    "did:mesh:fetcher": [
        {"step_id": "step-1", "action": "fetch_api", "status": "success"},
    ],
    "did:mesh:transformer": [
        {"step_id": "step-2", "action": "clean_data", "status": "success"},
        {"step_id": "step-3", "action": "validate_schema", "status": "success"},
    ],
    "did:mesh:writer": [
        {"step_id": "step-4", "action": "write_results", "status": "success"},
        {"step_id": "step-5", "action": "migrate_schema", "status": "failed"},
    ],
}

# ── 4. Writer fails at step 5 → Run causal attribution ──────────────────

attribution = attributor.attribute(
    saga_id="saga:nightly-pipeline",
    session_id=SESSION,
    agent_actions=agent_actions,
    failure_step_id="step-5",
    failure_agent_did="did:mesh:writer",
    risk_weights={
        "did:mesh:fetcher": 0.3,
        "did:mesh:transformer": 0.5,
        "did:mesh:writer": 0.95,
    },
)

print(f"\nCausal attribution:")
print(f"  Root cause: {attribution.root_cause_agent}")
for attr in attribution.attributions:
    marker = "← DIRECT CAUSE" if attr.is_direct_cause else ""
    print(f"  {attr.agent_did}: liability={attr.liability_score:.2f} {marker}")

# Record attribution in ledger
ledger.record("did:mesh:writer", LedgerEntryType.FAULT_ATTRIBUTED, SESSION,
              severity=attribution.get_liability("did:mesh:writer"),
              details="Root cause of schema migration failure")

# ── 5. Slash the offending agent ─────────────────────────────────────────

slash_result = slashing.slash(
    vouchee_did="did:mesh:writer",
    session_id=SESSION,
    vouchee_sigma=0.50,
    risk_weight=0.95,
    reason="Unauthorized schema migration in production",
    agent_scores={
        "did:mesh:fetcher": 0.90,
        "did:mesh:transformer": 0.65,
        "did:mesh:writer": 0.50,
    },
)

print(f"\nSlashing result:")
print(f"  Writer σ: {slash_result.vouchee_sigma_before:.2f} → {slash_result.vouchee_sigma_after:.2f}")
for clip in slash_result.voucher_clips:
    print(f"  Cascade → {clip.voucher_did}: σ {clip.sigma_before:.2f} → {clip.sigma_after:.2f}")

ledger.record("did:mesh:writer", LedgerEntryType.SLASH_RECEIVED, SESSION,
              severity=0.95, details="Unauthorized schema migration")
for clip in slash_result.voucher_clips:
    ledger.record(clip.voucher_did, LedgerEntryType.SLASH_CASCADED, SESSION,
                  severity=clip.risk_weight,
                  details=f"Cascade from writer slash",
                  related_agent="did:mesh:writer")

# ── 6. Quarantine the offender ───────────────────────────────────────────

q_record = quarantine.quarantine(
    agent_did="did:mesh:writer",
    session_id=SESSION,
    reason=QuarantineReason.LIABILITY_VIOLATION,
    details="Unauthorized schema migration caused pipeline failure",
    duration_seconds=3600,  # 1-hour quarantine
    forensic_data={
        "saga_id": "saga:nightly-pipeline",
        "failed_step": "step-5",
        "attribution_id": attribution.attribution_id,
        "slash_id": slash_result.slash_id,
    },
)

ledger.record("did:mesh:writer", LedgerEntryType.QUARANTINE_ENTERED, SESSION,
              severity=1.0, details="Quarantined for liability violation")

print(f"\nQuarantine:")
print(f"  Agent: {q_record.agent_did}")
print(f"  Reason: {q_record.reason.value}")
print(f"  Duration: {q_record.forensic_data}")

# ── 7. Record clean sessions for well-behaved agents ────────────────────

for good_agent in ["did:mesh:fetcher", "did:mesh:transformer"]:
    ledger.record(good_agent, LedgerEntryType.CLEAN_SESSION, SESSION,
                  details="Completed pipeline steps without incidents")

# ── 8. Review risk profiles ─────────────────────────────────────────────

print(f"\n{'='*60}")
print("Risk Profiles")
print(f"{'='*60}")

for agent in ["did:mesh:fetcher", "did:mesh:transformer", "did:mesh:writer"]:
    profile = ledger.compute_risk_profile(agent)
    admit, reason = ledger.should_admit(agent)
    print(f"\n  {agent}:")
    print(f"    Slashes: {profile.slash_count}  |  Quarantines: {profile.quarantine_count}")
    print(f"    Clean sessions: {profile.clean_session_count}")
    print(f"    Risk score: {profile.risk_score:.2f}  |  Recommendation: {profile.recommendation}")
    print(f"    Admit to next session: {admit} ({reason})")

# ── 9. Session cleanup ──────────────────────────────────────────────────

released = vouching.release_session_bonds(SESSION)
matrix.clear()
print(f"\nSession cleanup: released {released} bonds, cleared liability matrix")
```

### Expected Output

```
Vouching chain established:
  Fetcher → Transformer (bond: 0.180)
  Transformer → Writer  (bond: 0.098)
  Cycle detected: False

Causal attribution:
  Root cause: did:mesh:writer
  did:mesh:writer: liability=1.00 ← DIRECT CAUSE
  ...

Slashing result:
  Writer σ: 0.50 → ...
  ...

Quarantine:
  Agent: did:mesh:writer
  Reason: liability_violation
  ...

============================================================
Risk Profiles
============================================================
  did:mesh:fetcher:
    Slashes: 0  |  Quarantines: 0
    Clean sessions: 1
    Risk score: 0.00  |  Recommendation: admit
    Admit to next session: True (admit)

  did:mesh:transformer:
    Slashes: 0  |  Quarantines: 0
    Clean sessions: 1
    Risk score: 0.00  |  Recommendation: admit
    Admit to next session: True (admit)

  did:mesh:writer:
    Slashes: 1  |  Quarantines: 1
    Clean sessions: 0
    Risk score: ...  |  Recommendation: ...
    Admit to next session: ...

Session cleanup: released 2 bonds, cleared liability matrix
```

---

## 13. Next Steps

- **Trust & Identity:** Deepen your understanding of trust scores and DIDs
  in [Tutorial 02 — Trust & Identity](02-trust-and-identity.md).
- **Execution Sandboxing:** Learn how trust scores map to privilege rings and
  capability guards in [Tutorial 06 — Execution Sandboxing](06-execution-sandboxing.md).
- **Audit & Compliance:** Explore how liability ledger entries integrate with
  `CommitmentEngine` and `DeltaEngine` for tamper-evident audit logs in
  [Tutorial 04 — Audit & Compliance](04-audit-and-compliance.md).
- **REST API:** Use the `/api/v1/sessions/{session_id}/sponsor` endpoint to
  create vouches via HTTP — see the API reference documentation.
- **Enterprise Features:** Upgrade to the enterprise edition for enforced
  bonding, real slashing penalties, quarantine enforcement, and admission
  gates based on `LiabilityLedger` risk profiles.
