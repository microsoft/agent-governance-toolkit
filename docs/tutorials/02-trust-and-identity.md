# Tutorial 02 — Trust and Identity

> **Package:** `agentmesh-platform` · **Time:** 30 minutes · **Prerequisites:** Python 3.11+

---

## What You'll Learn

- Ed25519 credentials and cryptographic agent identity
- Decentralized Identifiers (DIDs) for agent verification
- SPIFFE/SVID integration for workload identity
- Trust scoring on a continuous 0–1000 scale

---

## Building Verifiable Agent Identity and Dynamic Trust

**Prerequisites:** `pip install agentmesh-platform`
**Modules:** `agentmesh.identity`, `agentmesh.trust`, `agentmesh.governance`

---

## 1. Introduction — Why Agent Identity Matters

In a multi-agent system, any agent can claim to be anything. Without
cryptographic identity and continuous trust evaluation, you have no way to
answer three critical questions:

1. **Who is this agent?** — Verified identity via decentralized identifiers (DIDs)
2. **Should I trust it?** — Dynamic trust scoring based on observed behavior
3. **What can it do?** — Capability-scoped, time-limited credentials

The Agent Governance Toolkit solves this with three layers:

| Layer | Purpose | Key Classes |
|-------|---------|-------------|
| **Identity** | Cryptographic agent IDs, Ed25519 keys, human sponsors | `AgentIdentity`, `AgentDID`, `HumanSponsor` |
| **Trust** | Handshake protocol, peer verification, capability scoping | `TrustHandshake`, `TrustBridge`, `CapabilityRegistry` |
| **Governance** | Policy enforcement, risk scoring, audit trail | `RiskScorer`, `TrustPolicy`, `AuditLog` |

Every agent gets a `did:mesh:*` identifier bound to an Ed25519 key pair,
a human sponsor for accountability, and short-lived credentials (15-minute TTL)
that auto-rotate and can be revoked instantly.

---

## 2. Quick Start — Register an Agent and Get a Trust Score

```python
from agentmesh import AgentIdentity, RiskScorer

# Create an agent with a human sponsor
agent = AgentIdentity.create(
    name="DataProcessor",
    sponsor="alice@company.com",
    capabilities=["read:data", "write:reports"],
    organization="Analytics",
)

print(agent.did)          # did:mesh:a1b2c3d4e5f6...
print(agent.public_key)   # Base64-encoded Ed25519 public key
print(agent.status)       # "active"

# Check the agent's risk score (0-1000, higher = safer)
scorer = RiskScorer()
score = scorer.get_score(str(agent.did))

print(score.total_score)  # 500 (default starting score)
print(score.risk_level)   # "medium"
```

That's it — your agent now has a cryptographic identity and a baseline trust
score. The rest of this tutorial explains how each piece works.

---

## 3. DID and Key Management

### 3.1 Decentralized Identifiers

Every agent receives a DID in the format `did:mesh:<unique-id>`, where the
unique ID is a SHA-256 hash derived from the agent's name and organization.

```python
from agentmesh import AgentDID

# Generate a DID
did = AgentDID.generate(name="ReportWriter", org="Analytics")
print(did)  # did:mesh:7f3a...

# Parse an existing DID string
did = AgentDID.from_string("did:mesh:7f3a9b2c...")
print(did.method)     # "mesh"
print(did.unique_id)  # "7f3a9b2c..."
```

### 3.2 Ed25519 Key Pairs

Agent identities are backed by Ed25519 elliptic curve keys. The private key
never leaves the agent; only the public key is shared.

```python
agent = AgentIdentity.create(
    name="Signer",
    sponsor="bob@company.com",
)

# Sign data
signature = agent.sign(b"payload to authenticate")

# Verify signature (any party with the public key can do this)
is_valid = agent.verify_signature(b"payload to authenticate", signature)
print(is_valid)  # True

# Export as JWK (JSON Web Key) for interoperability
jwk = agent.to_jwk(include_private=False)

# Export as a W3C DID Document
did_doc = agent.to_did_document()
```

### 3.3 Human Sponsors

Every agent must have a human sponsor — the person accountable for the agent's
behavior. This prevents "orphan agents" from operating without oversight.

```python
from agentmesh import HumanSponsor

sponsor = HumanSponsor.create(
    email="alice@company.com",
    name="Alice",
    organization="Analytics",
    allowed_capabilities=["read:data", "write:reports", "execute:analysis"],
)

# Verify the sponsor (typically via email or SSO)
sponsor.verify(method="email")

# Sponsors have limits
print(sponsor.max_agents)           # 10
print(sponsor.max_delegation_depth) # 3

# Check before creating a new agent
if sponsor.can_sponsor_agent():
    agent = AgentIdentity.create(
        name="NewAgent",
        sponsor=sponsor.email,
        capabilities=["read:data"],
    )
```

### 3.4 Delegation — Creating Child Agents

An agent can delegate a subset of its capabilities to a child agent.
Capabilities can only **narrow**, never expand.

```python
# Parent agent with broad capabilities
parent = AgentIdentity.create(
    name="OrchestratorAgent",
    sponsor="alice@company.com",
    capabilities=["read:data", "write:reports", "execute:analysis"],
)

# Delegate a narrower set to a child
child = parent.delegate(
    name="ReportWriter",
    capabilities=["write:reports"],  # Must be a subset of parent's
)

print(child.parent_did)                    # Parent's DID
print(child.has_capability("write:reports"))  # True
print(child.has_capability("read:data"))      # False — not delegated
```

---

## 4. Trust Scoring System

### 4.1 Risk Score Components

Trust is measured through a `RiskScore` on a 0–1000 scale (higher = safer).
The score is composed of four weighted dimensions:

| Component | Weight | What It Measures |
|-----------|--------|-----------------|
| `identity_score` | 25% | Identity verification strength, sponsor status |
| `behavior_score` | 20% | Behavioral patterns, anomaly detection |
| `network_score` | 15% | Network activity, communication patterns |
| `compliance_score` | 25% | Regulatory compliance, policy adherence |

```python
from agentmesh import RiskScorer, RiskScore

scorer = RiskScorer()

# Get or create a score for an agent
score = scorer.get_score("did:mesh:abc123...")

print(score.total_score)      # 500 (default)
print(score.identity_score)   # 0-100 component
print(score.behavior_score)   # 0-100 component
print(score.compliance_score) # 0-100 component
print(score.risk_level)       # "critical" | "high" | "medium" | "low" | "minimal"
```

### 4.2 Trust Tiers (Ring Model)

Scores map to access tiers that control what an agent can do:

| Tier | Score Range | Trust Level | Access |
|------|------------|-------------|--------|
| **Ring 0** | ≥ 900 | `verified_partner` | Full access, cross-mesh federation |
| **Ring 1** | ≥ 700 | `trusted` | Standard operations, peer communication |
| **Ring 2** | ≥ 500 | `standard` | Limited operations, monitored |
| **Ring 3** | < 500 | `untrusted` / `probationary` | Restricted, requires approval |

```
Ring 0 (≥900)  ████████████████████████████████████████  Full Trust
Ring 1 (≥700)  ██████████████████████████████            Trusted
Ring 2 (≥500)  ████████████████████                      Standard
Ring 3 (<500)  ██████████                                Restricted
               0    200    400    600    800    1000
```

Key thresholds from `agentmesh.constants`:

```python
TRUST_SCORE_DEFAULT = 500           # Starting score
TRUST_WARNING_THRESHOLD = 500       # Below this triggers warnings
TRUST_REVOCATION_THRESHOLD = 300    # Below this triggers revocation
RISK_CRITICAL_THRESHOLD = 200       # Immediate action required
```

### 4.3 Risk Signals and Scoring

Trust scores change based on **risk signals** — events that indicate positive
or negative agent behavior. Signals are weighted by severity:

| Severity | Weight | Example |
|----------|--------|---------|
| `critical` | 1.0 | Credential compromise detected |
| `high` | 0.75 | Unauthorized resource access attempt |
| `medium` | 0.5 | Unusual request pattern |
| `low` | 0.25 | Minor policy deviation |
| `info` | 0.1 | Routine activity logged |

```python
from agentmesh.identity import RiskSignal

# Report a risk signal
scorer.add_signal(
    agent_did="did:mesh:abc123...",
    signal=RiskSignal(
        signal_type="behavior.anomaly",
        severity="high",
        value=0.8,
        source="anomaly_detector",
        details="Unusual data access pattern detected",
    ),
)

# Score recalculates automatically (every ≤30 seconds)
updated_score = scorer.recalculate("did:mesh:abc123...")
print(updated_score.risk_level)  # May have changed

# Register an alert callback for critical events
def handle_alert(alert: dict):
    if alert["type"] == "critical_risk":
        print(f"ALERT: Agent {alert['agent_did']} is high risk!")

scorer.on_alert(handle_alert)
```

### 4.4 Trust Decay

Scores degrade over time without positive signals. An agent that stops
producing positive behavioral evidence will see its score drift downward.
The `RiskScorer` recalculates every 30 seconds, factoring in signal
recency and the absence of fresh positive signals.

```python
# Find agents whose scores have decayed into high-risk territory
high_risk_agents = scorer.get_high_risk_agents(threshold=400)
for agent_score in high_risk_agents:
    print(f"{agent_score.agent_did}: {agent_score.total_score}")

# After remediation, clear old signals to allow recovery
scorer.clear_signals("did:mesh:abc123...")
```

---

## 5. Credential Lifecycle

### 5.1 Issuing Credentials

Credentials are short-lived tokens (default 15-minute TTL) scoped to specific
capabilities and resources. They are the runtime proof that an agent is
authorized to act.

```python
from agentmesh import Credential, CredentialManager

manager = CredentialManager(default_ttl=900)  # 15 minutes

# Issue a credential
cred = manager.issue(
    agent_did="did:mesh:abc123...",
    capabilities=["read:data"],
    resources=["dataset_sales", "dataset_inventory"],
    ttl_seconds=900,
)

print(cred.credential_id)   # "cred_a1b2c3..."
print(cred.status)           # "active"
print(cred.time_remaining()) # ~15 minutes
print(cred.to_bearer_token()) # "Bearer <token>"
```

### 5.2 Validation

Incoming tokens are validated by hashing and comparing against stored
credential records:

```python
# Validate an incoming token
incoming_token = request.headers["Authorization"].removeprefix("Bearer ")
cred = manager.validate(incoming_token)

if cred and cred.is_valid():
    if cred.has_capability("read:data"):
        if cred.can_access_resource("dataset_sales"):
            # Authorized — proceed
            ...
```

### 5.3 Rotation

Credentials auto-rotate before expiry. The rotation threshold is 60 seconds —
when a credential is within 60 seconds of expiring, calling `rotate_if_needed`
issues a fresh one and marks the old credential as `"rotated"`.

```python
# Check and rotate if needed
cred = manager.rotate_if_needed(cred.credential_id)
# Returns the same credential if not expiring, or a new one if it is

# Force rotation (e.g., after a capability change)
new_cred = manager.rotate(cred.credential_id)
print(new_cred.previous_credential_id)  # Links to the old credential
print(new_cred.rotation_count)          # Incremented
```

### 5.4 Revocation

Revocation is immediate and propagates within ≤5 seconds. Use it when an
agent is compromised or a policy violation is detected.

```python
# Revoke a single credential
manager.revoke(cred.credential_id, reason="Suspected compromise")

# Revoke ALL credentials for a compromised agent
count = manager.revoke_all_for_agent(
    agent_did="did:mesh:compromised...",
    reason="Agent suspended pending investigation",
)
print(f"Revoked {count} credentials")

# Register a callback for revocation events
def on_revocation(event):
    print(f"Credential {event['credential_id']} revoked: {event['reason']}")

manager.on_revocation(on_revocation)

# Cleanup expired credentials periodically
expired_count = manager.cleanup_expired()
```

### 5.5 Credential Status Flow

```
  issue()          rotate()           revoke()
    │                  │                  │
    ▼                  ▼                  ▼
 ┌────────┐      ┌─────────┐       ┌─────────┐
 │ active │─────▶│ rotated │       │ revoked │
 └────────┘      └─────────┘       └─────────┘
    │                                    ▲
    │         TTL expires                │
    ▼                                    │
 ┌─────────┐     policy violation ───────┘
 │ expired │
 └─────────┘
```

---

## 6. Trust-Based Access Control

### 6.1 Capability Grants

Capabilities follow the format `action:resource[:qualifier]`. Grants are
scoped to specific agents and optionally limited to specific resource IDs.

```python
from agentmesh import CapabilityRegistry

registry = CapabilityRegistry()

# Grant scoped capability
grant = registry.grant(
    capability="read:data",
    to_agent="did:mesh:child...",
    from_agent="did:mesh:parent...",
    resource_ids=["dataset_sales", "dataset_inventory"],
)

# Check capability (with resource scoping)
can_read = registry.check(
    agent_did="did:mesh:child...",
    capability="read:data",
    resource_id="dataset_sales",  # Specific resource
)
print(can_read)  # True

# Agent cannot access ungranted resources
can_read_hr = registry.check(
    agent_did="did:mesh:child...",
    capability="read:data",
    resource_id="dataset_hr",
)
print(can_read_hr)  # False
```

### 6.2 Linking Trust Scores to Permissions

Use trust policies to enforce score-based access control. Policies are
defined in YAML and evaluated at runtime:

```yaml
# policies/trust-access.yaml
name: "Trust-Based Access Control"
version: "1.0"
description: "Map trust tiers to allowed operations"

defaults:
  min_trust_score: 500
  max_delegation_depth: 3
  require_handshake: true

rules:
  - name: "Block Low-Trust Agents"
    description: "Deny agents below Ring 3 threshold"
    condition:
      field: "trust_score"
      operator: "lt"
      value: 400
    action: "deny"
    priority: 10

  - name: "Require Approval for PII Access"
    description: "Ring 2+ agents need sponsor approval for PII"
    condition:
      field: "action.type"
      operator: "eq"
      value: "access_pii"
    action: "require_approval"
    priority: 20

  - name: "Allow Ring 0 Full Access"
    description: "Verified partners can access all resources"
    condition:
      field: "trust_score"
      operator: "gte"
      value: 900
    action: "allow"
    priority: 5
```

```python
from agentmesh.governance import TrustPolicy, PolicyEvaluator

# Load policies from YAML
policy = TrustPolicy.from_yaml("policies/trust-access.yaml")
evaluator = PolicyEvaluator([policy])

# Evaluate an agent's request
decision = evaluator.evaluate({
    "trust_score": 450,
    "action": {"type": "read_data"},
    "agent": {"did": "did:mesh:abc123..."},
})

print(decision.allowed)        # True (score ≥ 400)
print(decision.action)         # "allow"
print(decision.matched_rules)  # Rules that fired

# Low-trust agent trying to access PII
decision = evaluator.evaluate({
    "trust_score": 350,
    "action": {"type": "access_pii"},
})

print(decision.allowed)  # False
print(decision.action)   # "deny" (score < 400, highest priority rule)
```

### 6.3 Scope Chains for Delegation Auditing

When agents delegate to other agents, a `ScopeChain` tracks the full
delegation path and ensures capabilities only narrow:

```python
from agentmesh import ScopeChain, DelegationLink

# Create a root chain from a human sponsor
chain, root_link = ScopeChain.create_root(
    sponsor_email="alice@company.com",
    root_agent_did="did:mesh:root...",
    capabilities=["read:data", "write:reports", "execute:analysis"],
    sponsor_verified=True,
)

# Verify the entire chain is intact
is_valid, error = chain.verify()
print(is_valid)  # True

# Trace how a specific capability was granted
trace = chain.trace_capability("write:reports")
# Returns the full delegation path for that capability
```

---

## 7. Multi-Agent Trust Mesh

### 7.1 Trust Handshake Protocol

Before two agents communicate, they perform a cryptographic handshake:
challenge-response with nonce verification, trust score exchange, and
capability negotiation.

```python
import asyncio
from agentmesh import TrustHandshake, AgentIdentity

# Agent A creates a handshake initiator
agent_a = AgentIdentity.create(
    name="AgentA",
    sponsor="alice@company.com",
    capabilities=["read:data", "write:reports"],
)

handshake_a = TrustHandshake(
    agent_did=str(agent_a.did),
    identity=agent_a,
    timeout_seconds=30.0,
)

# Agent A initiates a handshake with Agent B
result = asyncio.run(handshake_a.initiate(
    peer_did="did:mesh:agent_b...",
    required_trust_score=700,           # Minimum Ring 1
    required_capabilities=["read:data"],
))

if result.verified:
    print(f"Peer: {result.peer_did}")
    print(f"Trust Level: {result.trust_level}")  # "trusted"
    print(f"Trust Score: {result.trust_score}")
    print(f"Latency: {result.latency_ms}ms")
    # Proceed with secure communication
else:
    print(f"Rejected: {result.rejection_reason}")
```

### 7.2 Responding to Handshakes

On the receiving side, the agent responds to the challenge:

```python
# Agent B receives a challenge and responds
agent_b_handshake = TrustHandshake(
    agent_did=str(agent_b.did),
    identity=agent_b,
)

response = asyncio.run(agent_b_handshake.respond(
    challenge=incoming_challenge,
    my_capabilities=["read:data", "execute:analysis"],
    my_trust_score=800,
    identity=agent_b,
))
# Response is sent back to Agent A for verification
```

### 7.3 Trust Bridge for Persistent Peers

For agents that communicate frequently, a `TrustBridge` maintains verified
peer state and caches handshake results (default 15-minute cache TTL):

```python
from agentmesh import TrustBridge

bridge = TrustBridge(
    agent_did=str(agent_a.did),
    default_trust_threshold=700,
)

# Register known peers
bridge.register_peer(
    peer_did="did:mesh:agent_b...",
    peer_name="DataAnalyzer",
    protocol="iatp",
)

# Verify a peer (uses cached result if available)
result = asyncio.run(bridge.verify_peer(
    peer_did="did:mesh:agent_b...",
    required_trust_score=700,
    required_capabilities=["read:data"],
))

# Quick trust check
is_trusted = asyncio.run(bridge.is_peer_trusted(
    peer_did="did:mesh:agent_b...",
    required_score=700,
))
```

### 7.4 Agent Cards for Discovery

`TrustedAgentCard` objects serve as verifiable business cards for agents —
other agents can discover and verify peers through a `CardRegistry`:

```python
from agentmesh.trust import TrustedAgentCard, CardRegistry

card_registry = CardRegistry()

# Cards are created automatically during registration
# Other agents can look up cards to discover peers
```

### 7.5 Audit Trail

Every trust operation is logged to a tamper-evident audit chain backed by
Merkle tree hashing:

```python
from agentmesh import AuditLog

log = AuditLog()

# Log a trust handshake
entry = log.add_entry(
    event_type="trust_handshake",
    agent_did="did:mesh:agent_a...",
    action="initiate_handshake",
    resource="did:mesh:agent_b...",
    data={"trust_score": 800, "protocol": "iatp"},
    outcome="success",
)

# Verify the entire audit chain hasn't been tampered with
is_intact = log.verify_integrity()
print(is_intact)  # True

# Query audit history for an agent
entries = log.get_entries(
    agent_did="did:mesh:agent_a...",
    event_type="trust_handshake",
    limit=50,
)
```

---

## Summary

| Concept | Key Class | What It Does |
|---------|-----------|-------------|
| Agent DID | `AgentDID` | `did:mesh:*` identifier bound to Ed25519 keys |
| Identity | `AgentIdentity` | Creates agents, signs data, manages delegation |
| Sponsor | `HumanSponsor` | Human accountability for every agent |
| Credentials | `CredentialManager` | 15-min TTL tokens with auto-rotation |
| Risk Scoring | `RiskScorer` | 0–1000 continuous trust assessment |
| Trust Tiers | Ring 0–3 | Score-based access control |
| Handshake | `TrustHandshake` | Cryptographic peer verification |
| Trust Bridge | `TrustBridge` | Persistent peer trust with caching |
| Capabilities | `CapabilityRegistry` | Fine-grained, scoped permission grants |
| Policies | `TrustPolicy` | YAML-based declarative trust rules |
| Audit | `AuditLog` | Tamper-evident Merkle-chained event log |

---

## Next Steps

- **Policy Engine:** [Tutorial 01 — Policy Engine](01-policy-engine.md)
- **Framework Integrations:** [Tutorial 03 — Framework Integrations](03-framework-integrations.md)
- **Advanced Trust:** [Tutorial 17 — Advanced Trust & Behavior Monitoring](17-advanced-trust-and-behavior.md)
