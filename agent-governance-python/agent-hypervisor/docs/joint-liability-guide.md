# Understanding Joint Liability for AI Agents

> **Edition:** Public Preview APIs only.
> Module path: `src/hypervisor/liability/`

## Table of Contents

- [What Is Joint Liability?](#what-is-joint-liability)
- [Why AI Agents Need Joint Liability](#why-ai-agents-need-joint-liability)
- [Vouching: Staking Reputation for Another Agent](#vouching-staking-reputation-for-another-agent)
- [The Effective Score Formula](#the-effective-score-formula)
- [Slashing: What Happens When an Agent Misbehaves](#slashing-what-happens-when-an-agent-misbehaves)
- [Cascade Effects](#cascade-effects)
- [Real-World Analogy: Co-Signing a Loan](#real-world-analogy-co-signing-a-loan)
- [Code Examples](#code-examples)
- [Key Classes Reference](#key-classes-reference)

---

## What Is Joint Liability?

Joint liability is a mechanism where one agent (the **voucher**) stakes a portion
of its own reputation to sponsor another agent (the **vouchee**) into a shared
session. If the vouchee misbehaves, both agents face consequences — the vouchee
is penalized directly and the voucher's bonded reputation is clipped.

This creates a web of accountability: agents don't operate in isolation but are
connected through a **liability graph** of sponsor → sponsored relationships.

## Why AI Agents Need Joint Liability

In a multi-agent system, agents from different providers collaborate inside
shared sessions. Without accountability:

- A rogue agent can disrupt an entire session with no consequence.
- There is no incentive for agents to vet who they collaborate with.
- Trust decisions fall entirely on the hypervisor, creating a bottleneck.

Joint liability solves this by making agents **co-responsible**. An agent that
vouches for a bad actor shares in the penalty, creating a decentralized trust
network where agents self-police.

## Vouching: Staking Reputation for Another Agent

Vouching is the act of a trusted agent sponsoring a less-established agent.
The voucher bonds a percentage of its reputation score (σ) as collateral.

Key concepts:

| Term | Description |
|------|-------------|
| **Voucher** | The sponsoring agent (`voucher_did`) |
| **Vouchee** | The sponsored agent (`vouchee_did`) |
| **Bond** | The amount of σ the voucher stakes (`bonded_amount`) |
| **Bond %** | Percentage of voucher's σ that is bonded (`bonded_sigma_pct`) |
| **Vouch ID** | Unique identifier for the sponsorship record |

The `VouchingEngine` manages these relationships:

```python
from hypervisor.liability.vouching import VouchingEngine

engine = VouchingEngine()

# Agent A vouches for Agent B in a session
record = engine.vouch(
    voucher_did="did:mesh:agent-a",
    vouchee_did="did:mesh:agent-b",
    session_id="session-123",
    voucher_sigma=0.85,       # Voucher's current reputation score
    bond_pct=0.20,            # Bond 20% of reputation (optional)
)

print(record.vouch_id)        # "sponsor:<uuid>"
print(record.is_active)       # True
```

### Constraints

The `VouchingEngine` enforces several safeguards (configurable via class constants):

- **Minimum voucher score** (`MIN_VOUCHER_SCORE = 0.50`): Only agents with σ ≥ 0.50 may vouch.
- **Default bond percentage** (`DEFAULT_BOND_PCT = 0.20`): 20% of the voucher's σ is bonded by default.
- **Maximum exposure** (`DEFAULT_MAX_EXPOSURE = 0.80`): A voucher cannot bond more than 80% of its σ across all active vouches.

> **Public Preview note:** The Public Preview approves all vouch requests
> and does not enforce bonding. The API surface is identical — constraints are
> enforced in the full edition.

## The Effective Score Formula

When an agent is vouched for, its **effective reputation score** (σ\_eff)
combines its own score with the voucher's backing:

```
σ_eff = σ_L + (ω × σ_H)
```

Where:

| Symbol | Meaning |
|--------|---------|
| **σ\_L** | The vouchee's own reputation score (low-trust agent) |
| **ω** | Risk weight — how much of the voucher's bond translates to trust (0.0–1.0) |
| **σ\_H** | The voucher's bonded reputation amount (high-trust agent's stake) |

This formula lets a new agent with low reputation (σ\_L = 0.30) participate
meaningfully when backed by a trusted agent (σ\_H = 0.85, ω = 0.5):

```
σ_eff = 0.30 + (0.5 × 0.85) = 0.725
```

The `compute_eff_score` method computes this:

```python
eff = engine.compute_eff_score(
    vouchee_did="did:mesh:agent-b",
    session_id="session-123",
    vouchee_sigma=0.30,    # σ_L
    risk_weight=0.5,       # ω
)
```

> **Public Preview note:** `compute_eff_score` returns the vouchee's own
> score (`vouchee_sigma`) without the voucher boost. The formula above is
> applied in the full edition.

## Slashing: What Happens When an Agent Misbehaves

When a vouchee violates policies — behavioral drift, ring breach, rate limit
abuse — the **SlashingEngine** penalizes both the offender and its vouchers.

A slash operation produces a `SlashResult` containing:

- The vouchee's σ before and after the penalty
- A list of `VoucherClip` records — each voucher that had collateral clipped
- The reason for the penalty
- The cascade depth (how far the penalty propagated)

```python
from hypervisor.liability.slashing import SlashingEngine

slasher = SlashingEngine(vouching_engine=engine)

result = slasher.slash(
    vouchee_did="did:mesh:agent-b",
    session_id="session-123",
    vouchee_sigma=0.72,
    risk_weight=0.5,
    reason="behavioral_drift",
    agent_scores={"did:mesh:agent-a": 0.85, "did:mesh:agent-b": 0.72},
)

print(result.slash_id)              # "penalize:<uuid>"
print(result.vouchee_sigma_before)  # 0.72
print(result.vouchee_sigma_after)   # Reduced (full edition)
print(result.voucher_clips)         # List of VoucherClip records
print(result.reason)                # "behavioral_drift"
```

### Slashing Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_CASCADE_DEPTH` | 2 | Maximum depth for cascade penalties |
| `SIGMA_FLOOR` | 0.05 | Minimum σ — an agent is never penalized below this |

> **Public Preview note:** `slash` logs the penalty event but does not
> reduce any scores. `vouchee_sigma_after` equals `vouchee_sigma_before` and
> `voucher_clips` is empty.

## Cascade Effects

Penalties don't stop at the direct offender. If Agent C misbehaves and Agent B
vouched for C, Agent B's score is clipped. If Agent A vouched for Agent B,
Agent A may also be affected — up to `MAX_CASCADE_DEPTH = 2` levels.

The `LiabilityMatrix` models these cascades:

```python
from hypervisor.liability import LiabilityMatrix

matrix = LiabilityMatrix(session_id="session-123")

# Build the liability graph
matrix.add_edge("did:mesh:agent-a", "did:mesh:agent-b", bonded_amount=0.17, vouch_id="v1")
matrix.add_edge("did:mesh:agent-b", "did:mesh:agent-c", bonded_amount=0.10, vouch_id="v2")

# Find cascade paths starting from Agent C
paths = matrix.cascade_path("did:mesh:agent-c", max_depth=2)
# paths might be: [["did:mesh:agent-c"]] — C is a leaf
# Reverse direction: query who vouches for C
vouchers = matrix.who_vouches_for("did:mesh:agent-c")
# Returns edges where vouchee_did == agent-c

# Check total exposure for Agent A
exposure = matrix.total_exposure("did:mesh:agent-a")
print(f"Agent A has {exposure}σ bonded across all vouchees")
```

### Cycle Detection

The liability graph must be a **directed acyclic graph (DAG)**. Cycles would
create infinite cascade loops. The `has_cycle()` method detects this:

```python
matrix.add_edge("did:mesh:agent-c", "did:mesh:agent-a", bonded_amount=0.05, vouch_id="v3")
print(matrix.has_cycle())  # True — A→B→C→A forms a cycle
```

### The Liability Ledger

All vouching, slashing, and quarantine events are recorded in the
`LiabilityLedger` — an append-only audit log:

```python
from hypervisor.liability.ledger import LiabilityLedger, LedgerEntryType

ledger = LiabilityLedger()

# Record a vouch event
ledger.record(
    agent_did="did:mesh:agent-a",
    entry_type=LedgerEntryType.VOUCH_GIVEN,
    session_id="session-123",
    details="Vouched for did:mesh:agent-b",
    related_agent="did:mesh:agent-b",
)

# Record a slash event
ledger.record(
    agent_did="did:mesh:agent-b",
    entry_type=LedgerEntryType.SLASH_RECEIVED,
    session_id="session-123",
    severity=0.4,
    details="behavioral_drift detected",
)

# Query history
history = ledger.get_agent_history("did:mesh:agent-b")
profile = ledger.compute_risk_profile("did:mesh:agent-b")
print(profile.recommendation)  # "admit" (Public Preview always admits)
```

Ledger entry types include:

| Entry Type | Description |
|------------|-------------|
| `VOUCH_GIVEN` | Agent vouched for another |
| `VOUCH_RECEIVED` | Agent was vouched for |
| `VOUCH_RELEASED` | Vouch bond was released |
| `SLASH_RECEIVED` | Agent was directly penalized |
| `SLASH_CASCADED` | Agent was penalized via cascade |
| `QUARANTINE_ENTERED` | Agent entered quarantine |
| `QUARANTINE_RELEASED` | Agent released from quarantine |
| `FAULT_ATTRIBUTED` | Fault was attributed to agent |
| `CLEAN_SESSION` | Agent completed a session cleanly |

## Real-World Analogy: Co-Signing a Loan

Joint liability for AI agents works like **co-signing a loan**:

| Loan Co-Signing | Agent Joint Liability |
|-----------------|----------------------|
| You (co-signer) trust a friend to repay a loan | Agent A (voucher) trusts Agent B to behave properly |
| You pledge your credit score as collateral | Agent A bonds a portion of its σ score |
| If your friend defaults, the bank comes after you too | If Agent B misbehaves, Agent A's bonded σ is clipped |
| Your credit score drops | Agent A's reputation score decreases |
| You're less likely to co-sign for strangers | Agents become selective about who they vouch for |
| The bank won't let you co-sign too many loans | `max_exposure` limits how much σ an agent can bond |

Just as reckless co-signing destroys your credit, recklessly vouching for
unreliable agents erodes an agent's own reputation — creating a natural
incentive for agents to be diligent about who they sponsor.

## Code Examples

### End-to-End: Vouching, Faulting, and Slashing

```python
from hypervisor.liability.vouching import VouchingEngine
from hypervisor.liability.slashing import SlashingEngine
from hypervisor.liability import LiabilityMatrix
from hypervisor.liability.ledger import LiabilityLedger, LedgerEntryType
from hypervisor.liability.attribution import CausalAttributor

# --- Setup ---
vouching = VouchingEngine(max_exposure=0.80)
slashing = SlashingEngine(vouching_engine=vouching)
matrix = LiabilityMatrix(session_id="session-42")
ledger = LiabilityLedger()
attributor = CausalAttributor()

SESSION = "session-42"
AGENT_A = "did:mesh:senior-agent"
AGENT_B = "did:mesh:junior-agent"

# --- Step 1: Agent A vouches for Agent B ---
vouch = vouching.vouch(
    voucher_did=AGENT_A,
    vouchee_did=AGENT_B,
    session_id=SESSION,
    voucher_sigma=0.90,
)
matrix.add_edge(AGENT_A, AGENT_B, bonded_amount=0.18, vouch_id=vouch.vouch_id)
ledger.record(AGENT_A, LedgerEntryType.VOUCH_GIVEN, SESSION, details=f"Vouched for {AGENT_B}")
ledger.record(AGENT_B, LedgerEntryType.VOUCH_RECEIVED, SESSION, related_agent=AGENT_A)

# --- Step 2: Agent B does work; something goes wrong ---
attribution = attributor.attribute(
    saga_id="saga-7",
    session_id=SESSION,
    agent_actions={AGENT_A: [{"step": "review"}], AGENT_B: [{"step": "execute"}]},
    failure_step_id="execute",
    failure_agent_did=AGENT_B,
)
print(f"Root cause: {attribution.root_cause_agent}")
print(f"Agent B liability: {attribution.get_liability(AGENT_B)}")  # 1.0

# --- Step 3: Slash Agent B ---
slash = slashing.slash(
    vouchee_did=AGENT_B,
    session_id=SESSION,
    vouchee_sigma=0.45,
    risk_weight=0.5,
    reason="saga failure in saga-7",
    agent_scores={AGENT_A: 0.90, AGENT_B: 0.45},
)
ledger.record(AGENT_B, LedgerEntryType.SLASH_RECEIVED, SESSION, severity=0.4)

# --- Step 4: Check exposure ---
exposure = matrix.total_exposure(AGENT_A)
print(f"Agent A total exposure: {exposure}σ")

# --- Step 5: Release bonds at session end ---
released = vouching.release_session_bonds(SESSION)
matrix.clear()
print(f"Released {released} bond(s)")
```

### Querying the Liability Graph

```python
from hypervisor.liability import LiabilityMatrix

matrix = LiabilityMatrix(session_id="session-99")

# Three-agent chain: A → B → C
matrix.add_edge("did:mesh:a", "did:mesh:b", 0.15, "v1")
matrix.add_edge("did:mesh:b", "did:mesh:c", 0.10, "v2")

# Who vouches for C?
for edge in matrix.who_vouches_for("did:mesh:c"):
    print(f"{edge.voucher_did} vouches for C with {edge.bonded_amount}σ bonded")

# Who does A vouch for?
for edge in matrix.who_is_vouched_by("did:mesh:a"):
    print(f"A vouches for {edge.vouchee_did}")

# Total exposure for B
print(f"B's total exposure: {matrix.total_exposure('did:mesh:b')}σ")

# Cascade paths from B (B vouches for C, so slashing B cascades to C)
for path in matrix.cascade_path("did:mesh:b"):
    print(f"Cascade path: {' → '.join(path)}")

# Cycle check
print(f"Has cycle: {matrix.has_cycle()}")  # False
```

## Key Classes Reference

| Class | Module | Purpose |
|-------|--------|---------|
| `VouchingEngine` | `liability.vouching` | Create, query, and release vouch bonds |
| `VouchRecord` | `liability.vouching` | Data class for a single vouch relationship |
| `SlashingEngine` | `liability.slashing` | Penalize misbehaving agents and their vouchers |
| `SlashResult` | `liability.slashing` | Result of a slash operation |
| `VoucherClip` | `liability.slashing` | Collateral clip applied to a single voucher |
| `LiabilityMatrix` | `liability` | Directed graph of sponsor → sponsored bonds |
| `LiabilityEdge` | `liability` | A single edge in the liability graph |
| `LiabilityLedger` | `liability.ledger` | Append-only audit log of all liability events |
| `LedgerEntryType` | `liability.ledger` | Enum of event types recorded in the ledger |
| `AgentRiskProfile` | `liability.ledger` | Risk profile computed from an agent's history |
| `CausalAttributor` | `liability.attribution` | Assigns fault to the direct-cause agent |
| `QuarantineManager` | `liability.quarantine` | Manages agent quarantine (no-op in community) |

---

> **Further reading:** See the [tutorials/](../tutorials/) directory for
> hands-on notebooks, and the [README](../README.md) for the full feature
> overview.
