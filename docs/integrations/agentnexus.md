<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# AgentNexus: Third-Party Identity and Governance Attestation

This guide shows how to integrate AgentNexus as an external identity verification
and governance attestation provider for the Agent Governance Toolkit. AgentNexus
provides W3C-compliant DID resolution, multi-issuer governance attestations, and
cross-verified trust scoring.

---

## Why AgentNexus Complements AGT

The Agent Governance Toolkit provides built-in Ed25519 identity and trust scoring.
AgentNexus extends this with:

1. **W3C DID Resolution** — `did:agentnexus` method with multi-method resolver
2. **Multi-Issuer Governance Attestations** — MolTrust, APS, and custom evaluators
3. **Cross-Verified Trust Scoring** — aggregate trust from multiple independent issuers
4. **Enclave Collaboration** — role-based permissions and playbook attestation

This enables agents to carry verifiable, issuer-agnostic governance credentials
that any AGT deployment can verify without trusting a single authority.

---

## Architecture Overview

```
┌───────────────────────────────────────────────────────────────────┐
│  Agent Governance Toolkit (AGT)                                   │
│  ► Policy enforcement                                             │
│  ► Execution sandboxing                                           │
│  ► Built-in Ed25519 identity                                      │
└───────────────┬───────────────────────────────────────────────────┘
                │
                ▼
┌───────────────────────────────────────────────────────────────────┐
│  AgentNexus Identity Layer                                        │
│  ► W3C DID Resolution (did:agentnexus, did:key, did:web)          │
│  ► GovernanceAttestation aggregation                              │
│  ► JWS verification against issuer JWKS                           │
└───────────────┬───────────────────────────────────────────────────┘
                │
                ▼
┌───────────────────────────────────────────────────────────────────┐
│  External Governance Providers                                    │
│  ► MolTrust (api.moltrust.ch)                                     │
│  ► APS (gateway.aeoess.com)                                       │
│  ► Custom evaluators                                              │
└───────────────────────────────────────────────────────────────────┘
```

---

## Integration Steps

### Step 1: Resolve Agent Identity

AgentNexus provides W3C-compliant DID resolution for multiple methods:

```python
from agent_net.common.did import DIDResolver

# Resolve did:agentnexus
resolver = DIDResolver()
result = await resolver.resolve("did:agentnexus:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK")

# Extract Ed25519 public key
public_key = result.public_key_hex
```

Supported methods:
- `did:agentnexus` — AgentNexus native (multibase Ed25519)
- `did:key` — Pure cryptographic resolution
- `did:web` — HTTPS endpoint resolution
- `did:meeet` — MEEET platform bridge

### Step 2: Fetch Governance Attestations

Governance attestations provide signed, verifiable trust decisions from
external evaluators:

```python
from agent_net.common.governance import (
    GovernanceRegistry,
    MolTrustClient,
    APSClient,
    CapabilityRequest,
)

# Configure registry
registry = GovernanceRegistry()
registry.register("moltrust", MolTrustClient(api_key="mt_..."))
registry.register("aps", APSClient())

# Validate capabilities
results = await registry.validate_capabilities(
    agent_did="did:agentnexus:...",
    requested=[CapabilityRequest(scope="data:read")],
)

# Get highest trust decision
best = registry.get_highest_trust(results)
```

### Step 3: Verify JWS Signatures

Each attestation is JWS-signed by the issuer. Verify offline:

```python
# Verify MolTrust attestation
valid = await registry.verify_attestation(results["moltrust"], "moltrust")
if valid:
    print(f"Decision: {results['moltrust'].decision}")
    print(f"Trust Score: {results['moltrust'].trust_score}")
```

JWS verification uses EdDSA against the issuer's published JWKS:

| Issuer | JWKS Endpoint | Key ID |
|--------|---------------|--------|
| MolTrust | `api.moltrust.ch/.well-known/jwks.json` | `did:web:moltrust.ch#moltguard-key-1` |
| APS | `gateway.aeoess.com/.well-known/jwks.json` | `gateway-v1` |

### Step 4: Map to AGT Trust Score

AgentNexus L-tier system maps to AGT trust score:

| L-Tier | AgentNexus Base Score | AGT Trust Score Range |
|--------|----------------------|----------------------|
| L1 | 15 | 0-20 |
| L2 | 40 | 20-50 |
| L3 | 70 | 50-80 |
| L4 | 95 | 80-100 |

```python
# AgentNexus trust score
trust_score = best.trust_score

# Map to AGT ring (optional)
agt_ring = 1 if trust_score < 20 else 2 if trust_score < 50 else 3 if trust_score < 80 else 4
```

---

## Governance Attestation Schema

Each attestation follows the `governance_attestation` signal type:

```json
{
  "signal_type": "governance_attestation",
  "iss": "api.moltrust.ch",
  "sub": "did:agentnexus:...",
  "decision": "conditional",
  "trust_score": 60,
  "active_constraints": {
    "scope": ["data:read", "commerce:checkout"],
    "spend_limit": 1000,
    "passport_grade": 2,
    "validity_window": {
      "not_before": "2026-04-13T12:55:49.403Z",
      "not_after": "2026-04-13T13:55:49.403Z"
    }
  },
  "expires_at": "2026-04-13T13:55:49.403Z",
  "jws": "eyJhbGciOiJFZERTQSIs..."
}
```

Decision types:
- `permit` — Full authorization
- `conditional` — Authorized within constraints
- `deny` — Authorization rejected

---

## Cross-Verification Example

Multiple issuers can attest to the same agent independently:

```python
# Parallel attestation from MolTrust + APS
results = await registry.validate_capabilities(agent_did, requested)

# Cross-verify both signatures
moltrust_valid = await registry.verify_attestation(results["moltrust"], "moltrust")
aps_valid = await registry.verify_attestation(results["aps"], "aps")

# Aggregate trust
if moltrust_valid and aps_valid:
    avg_score = (results["moltrust"].trust_score + results["aps"].trust_score) / 2
    print(f"Cross-verified trust: {avg_score}")
```

This enables zero-coupling between issuers — each signs independently,
consumers verify each signature against the issuer's JWKS.

---

## Enclave Collaboration Model

AgentNexus Enclave provides role-based constraint enforcement:

```
┌───────────────────────────────────────────────────────────────────┐
│  Enclave (Project Group)                                          │
│  ► Members + Roles (architect, developer, reviewer)               │
│  ► Permissions (r, rw, admin)                                     │
│  ► VaultBackend (Git, Local, S3)                                  │
│  ► Playbook Engine (stage-gated workflow)                         │
└───────────────────────────────────────────────────────────────────┘
```

Constraint evaluation occurs at:
- **Pre-execution**: Playbook stage assignment
- **Post-execution**: `notify_state` receipt for completed/rejected transitions

This aligns with AGT's deterministic pre-execution enforcement model.

---

## SDK Integration

```bash
pip install agentnexus-sdk
```

```python
import agentnexus

# Connect with identity
nexus = await agentnexus.connect("MyAgent", caps=["Chat", "Search"])

# Send attestation-aware message
await nexus.send(to_did="...", content="...", governance_metadata={
    "trust_score": 60,
    "passport_grade": 2,
})

# Verify peer
result = await nexus.verify("did:agentnexus:...")
```

---

## Vocabulary Crosswalk

AgentNexus terminology maps to the canonical governance vocabulary:

| AgentNexus | Canonical |
|------------|-----------|
| `L-tier` | `trust_floor` |
| `GovernanceAttestation` | `governance_attestation` signal type |
| `permissions` | `active_constraints.scope` |
| `spend_limit` | `active_constraints.spend_limit` |
| `Playbook receipt` | `AuthorizationWitness` |

See [agent-governance-vocabulary](https://github.com/aeoess/agent-governance-vocabulary)
for the full crosswalk specification.

---

## Production Status

AgentNexus is production-ready:

- **Tests**: 352 passed, 45 online tests
- **DID Methods**: 4 supported (agentnexus, key, web, meeet)
- **Governance Providers**: 2 integrated (MolTrust, APS)
- **MCP Tools**: 33 tools for agent integration

Repository: https://github.com/kevinkaylie/AgentNexus

---

## References

- [AgentNexus ADR-012: Push Gateway](https://github.com/kevinkaylie/AgentNexus/blob/main/docs/adr/012-push-gateway-and-mcp-collaboration.md)
- [AgentNexus ADR-013: Enclave Architecture](https://github.com/kevinkaylie/AgentNexus/blob/main/docs/adr/013-enclave-collaboration-architecture.md)
- [AgentNexus ADR-014: Governance Integration](https://github.com/kevinkaylie/AgentNexus/blob/main/docs/adr/014-governance-trust-network.md)
- [Governance Attestation Schema](https://github.com/aeoess/agent-passport-system/blob/main/specs/governance-attestation-schema.md)