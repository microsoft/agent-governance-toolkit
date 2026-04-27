# Structural Authorization Gates — AgentMesh Adapter

AgentMesh adapter that consumes external policy decisions, trust grades, and delegation scope chains as AGT trust signals. Provides Ed25519 signature verification for incoming trust artifacts.

## Features

- **TrustGrade**: Six-level external grade enum (`VERIFIED` → `REVOKED`) mapped to AGT scores (0–1000)
- **TrustArtifact**: Signed external policy decision with Ed25519 verification and canonical JSON payload
- **DelegationChain**: Multi-hop scope chain validation (contiguity, scope narrowing, cycle detection, expiry)
- **AuthzGate**: Trust-gated task authorization consuming artifacts and delegation chains
- **TrustTracker**: Tracks agent trust scores from external authorization outcomes

## Installation

```bash
# Without cryptographic verification (limited — verify_signature() returns False)
pip install structural-authz-agentmesh

# With Ed25519 signing and verification (recommended)
pip install 'structural-authz-agentmesh[crypto]'
```

## Quick Start

```python
from datetime import datetime, timedelta, timezone
from structural_authz_agentmesh import (
    AgentProfile, AuthzGate, TrustArtifact, TrustGrade, generate_keypair,
)

# Generate keys (dev/test only — use your PKI in production)
authority_priv, authority_pub = generate_keypair()

# Define an agent
agent = AgentProfile(
    did="did:authz:analyst",
    name="Data Analyst",
    capabilities=["read:data", "analyze:reports"],
    trust_score=700,
)

# Issue a signed trust artifact from your external authority
artifact = TrustArtifact.sign(
    did=agent.did,
    grade=TrustGrade.TRUSTED,
    scopes=["read:data", "analyze:reports"],
    expires_at=datetime.now(timezone.utc) + timedelta(hours=8),
    private_key_b64=authority_priv,
    issuer_public_key_b64=authority_pub,
    issuer_id="my-policy-authority",
)

# Evaluate authorization
gate = AuthzGate(min_trust_score=500)
decision = gate.evaluate(
    agent=agent,
    task="Generate quarterly report",
    artifact=artifact,
    required_scopes=["read:data", "analyze:reports"],
)

print(decision.allowed)   # True
print(decision.artifact_grade)  # TrustGrade.TRUSTED
```

## Delegation Scope Chains

```python
from structural_authz_agentmesh import DelegationChain, DelegationLink

chain = DelegationChain(
    root_did="did:authz:analyst",
    root_scopes=["read:data", "analyze:reports"],
)

link = DelegationLink(
    delegator_did="did:authz:analyst",
    delegatee_did="did:authz:sub-analyst",
    scopes=["read:data"],          # must be a subset of root scopes
    delegator_public_key=analyst_pub,
    signature="...",               # Ed25519 signature from delegator
    expires_at=datetime.now(timezone.utc) + timedelta(hours=2),
)
chain.add_link(link)

valid, reason = chain.validate(required_scopes=["read:data"])
```

## Trust Score Tracking

```python
from structural_authz_agentmesh import TrustTracker

tracker = TrustTracker(success_reward=10, failure_penalty=50)
tracker.record_success(agent, task="Generate quarterly report")
tracker.record_failure(agent, task="Delete records", reason="Unauthorized scope")

history = tracker.get_history(did=agent.did)
```

## Trust Grade → AGT Score Mapping

| Grade | AGT Score | Meaning |
|-------|-----------|---------|
| `VERIFIED` | 950 | Fully attested, cryptographically proven |
| `TRUSTED` | 750 | Policy-approved, no flags |
| `PROVISIONAL` | 500 | Conditionally approved, pending attestation |
| `RESTRICTED` | 300 | Allowed but scope-limited |
| `UNTRUSTED` | 100 | Policy denied |
| `REVOKED` | 0 | Previously trusted, now invalidated — always blocked |


## Running Tests

```bash
pip install -e '.[dev]'
pytest
```
