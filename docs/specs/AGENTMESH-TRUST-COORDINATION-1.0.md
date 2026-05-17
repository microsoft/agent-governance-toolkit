<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# AgentMesh Trust and Coordination -- Version 1.0

> **Status:** Draft · **Date:** 2025-07-28 · **Authors:** Agent Governance Toolkit team
>
> This specification defines the trust and coordination model for
> AgentMesh, including trust scoring, handshake protocol, trust bridges,
> endorsement registries, capability scoping, agent cards, protocol
> bridging, rate limiting, behavior monitoring, and failure semantics.
> All SDK implementations MUST conform to this specification.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in
[RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119) and
[RFC 8174](https://datatracker.ietf.org/doc/html/rfc8174).

---

## Table of Contents

1.  [Introduction](#1-introduction)
2.  [Terminology](#2-terminology)
3.  [Trust Score Model](#3-trust-score-model)
4.  [Trust Tiers](#4-trust-tiers)
5.  [Handshake Protocol](#5-handshake-protocol)
6.  [Trust Bridge](#6-trust-bridge)
7.  [Endorsement Registry](#7-endorsement-registry)
8.  [Capability Scoping](#8-capability-scoping)
9.  [Agent Cards](#9-agent-cards)
10. [Protocol Bridge](#10-protocol-bridge)
11. [A2A Adapter](#11-a2a-adapter)
12. [MCP Adapter](#12-mcp-adapter)
13. [Rate Limiting](#13-rate-limiting)
14. [Rate Limit Middleware](#14-rate-limit-middleware)
15. [Behavior Monitoring](#15-behavior-monitoring)
16. [mTLS Security](#16-mtls-security)
17. [Trust Propagation](#17-trust-propagation)
18. [Service Discovery](#18-service-discovery)
19. [Failure Semantics](#19-failure-semantics)
20. [Security Considerations](#20-security-considerations)
21. [Conformance Requirements](#21-conformance-requirements)
22. [References](#22-references)

---

## 1. Introduction

### 1.1 Purpose

AgentMesh provides a trust-first coordination layer for multi-agent
systems. Just as mTLS establishes transport-level trust between
services, AgentMesh establishes identity-level and capability-level
trust between AI agents -- enabling agents to verify each other's
identity, negotiate capabilities, and communicate across heterogeneous
protocols with cryptographic assurance.

### 1.2 Scope

This specification covers:

- **Trust Score Model:** A numeric 0--1000 score with five trust tiers
  that gate access to mesh operations.
- **Handshake Protocol:** Ed25519 challenge/response protocol for
  mutual agent verification.
- **Trust Bridge:** Central coordination point for peer trust
  management with HMAC integrity checks.
- **Endorsement Registry:** RFC 9334--aligned endorsement system for
  third-party trust attestations.
- **Capability Scoping:** Fine-grained `action:resource[:qualifier]`
  capability grants with deny lists and revocation.
- **Agent Cards:** Cryptographically signed discovery cards for agent
  advertisement and verification.
- **Protocol Bridge:** Translation layer supporting A2A, MCP, IATP,
  and ACP protocols.
- **Rate Limiting:** Token bucket rate limiting at per-agent and global
  levels with backpressure signaling.
- **Behavior Monitoring:** Runtime anomaly detection with automatic
  quarantine for misbehaving agents.

### 1.3 Relationship to Other Specifications

| Specification | Relationship |
| --- | --- |
| Agent Hypervisor Execution Control 1.0 | Ring assignment consumes trust scores; rate limiting complements hypervisor rate limits |
| Agent OS Policy Engine 1.0 | Policy decisions may feed endorsements or capability revocation |
| AgentMesh Identity and Trust 1.0 | Identity layer provides Ed25519 keys and DID resolution used by the handshake |

### 1.4 Design Principles

1. **Zero trust by default.** Unknown agents receive a default score
   and MUST complete a handshake before participating in mesh
   operations.
2. **Fail closed.** Every enforcement check MUST deny access on
   failure, never silently permit.
3. **Protocol agnostic.** The trust model is independent of the
   communication protocol; trust decisions apply uniformly across
   A2A, MCP, IATP, and ACP.
4. **Endorsement over assertion.** Self-reported claims are
   informational only; trust decisions SHOULD prefer registry-backed
   endorsements over self-attestation.
5. **Least privilege.** Capability grants MUST be scoped to the
   narrowest required action and resource.

---

## 2. Terminology

| Term | Definition |
| --- | --- |
| **Trust Score** | Integer in the range [0, 1000] representing an agent's trustworthiness. |
| **Trust Tier** | One of five named levels derived from a trust score: verified_partner, trusted, standard, probationary, untrusted. |
| **DID** | Decentralized Identifier in the format `did:mesh:{hex}`, derived from the agent's Ed25519 public key. |
| **Handshake** | An Ed25519 challenge/response protocol that mutually verifies agent identity and trust. |
| **Trust Bridge** | The central coordination component that manages peer trust state with HMAC integrity protection. |
| **Endorsement** | An RFC 9334 attestation by one entity about another's capability, integrity, or compliance. |
| **Capability Grant** | A scoped permission in the format `action:resource[:qualifier]` issued by one agent to another. |
| **Agent Card** | A cryptographically signed metadata record that advertises an agent's identity and capabilities. |
| **Protocol Bridge** | A translation layer that converts messages between A2A, MCP, IATP, and ACP protocols. |
| **Token Bucket** | A rate limiting algorithm with a refill rate (tokens/second) and burst capacity. |
| **Backpressure** | A signal indicating that a rate limit bucket is nearing exhaustion. |
| **Quarantine** | Temporary isolation of a misbehaving agent from mesh operations. |
| **PeerInfo** | A Pydantic model storing per-peer trust metadata including DID, protocol, score, and capabilities. |
| **HMAC Integrity Check** | An in-process SHA-256 HMAC over peer records to detect accidental corruption. |
| **Freshness Nonce** | An RFC 9334 nonce included in a handshake challenge to prove Evidence liveness. |

---

## 3. Trust Score Model

### 3.1 Score Range

Trust scores MUST be integers in the range [0, 1000] inclusive.
Implementations MUST reject scores outside this range.
**[Pure Specification]**

### 3.2 Score Constants

| Constant | Value | Description |
| --- | --- | --- |
| `TRUST_SCORE_MIN` | 0 | Minimum possible trust score |
| `TRUST_SCORE_MAX` | 1000 | Maximum possible trust score |
| `TRUST_SCORE_DEFAULT` | 500 | Score assigned to newly registered agents |
| `TRUST_REVOCATION_THRESHOLD` | 300 | Score at or below which trust MAY be revoked |
| `TRUST_WARNING_THRESHOLD` | 500 | Score at or below which warnings are emitted |

**[Default Implementation]**

### 3.3 Trust Dimension Weights

Trust scores are computed from five weighted dimensions that MUST sum
to 1.0:

| Dimension | Weight | Description |
| --- | --- | --- |
| Policy Compliance | 0.25 | Adherence to governance policies |
| Resource Efficiency | 0.15 | Efficient use of allocated resources |
| Output Quality | 0.20 | Quality and accuracy of agent outputs |
| Security Posture | 0.25 | Security hygiene and vulnerability exposure |
| Collaboration Health | 0.15 | Behavior in multi-agent interactions |

**[Default Implementation]**

### 3.4 Score Validation

Implementations MUST validate that all trust score fields use the
`ge=0, le=1000` constraint. Pydantic `Field(default=0, ge=0, le=1000)`
or an equivalent runtime check MUST be applied. Scores received from
untrusted peers MUST NOT be used directly; the registry-backed score
MUST be authoritative. **[Pure Specification]**

---

## 4. Trust Tiers

### 4.1 Tier Definitions

The `trust_level_for_score()` function MUST map a numeric score to
exactly one of the following tier labels:

| Tier | Threshold | Label | Description |
| --- | --- | --- | --- |
| Verified Partner | score >= 900 | `verified_partner` | Highest trust; fully vetted partner agents |
| Trusted | score >= 700 | `trusted` | High trust; verified through handshake and endorsements |
| Standard | score >= 500 | `standard` | Moderate trust; default for newly registered agents |
| Probationary | score >= 300 | `probationary` | Low trust; agent under observation |
| Untrusted | score < 300 | `untrusted` | No trust; agent has not been verified or has been demoted |

**[Pure Specification]**

### 4.2 Tier Threshold Constants

| Constant | Value |
| --- | --- |
| `TIER_VERIFIED_PARTNER_THRESHOLD` | 900 |
| `TIER_TRUSTED_THRESHOLD` | 700 |
| `TIER_STANDARD_THRESHOLD` | 500 |
| `TIER_PROBATIONARY_THRESHOLD` | 300 |

**[Default Implementation]**

### 4.3 Tier Resolution Algorithm

```
function trust_level_for_score(score: int) -> str:
    if score >= TIER_VERIFIED_PARTNER_THRESHOLD: return "verified_partner"
    if score >= TIER_TRUSTED_THRESHOLD:          return "trusted"
    if score >= TIER_STANDARD_THRESHOLD:         return "standard"
    if score >= TIER_PROBATIONARY_THRESHOLD:      return "probationary"
    return "untrusted"
```

Tier resolution MUST be deterministic -- the same score MUST always
produce the same tier label. **[Pure Specification]**

### 4.4 Tier-Based Access Defaults

| Tier | Default Trust Threshold Met | Bridge Communication | Endorsement Weight |
| --- | --- | --- | --- |
| verified_partner | Yes | Full | High |
| trusted | Yes | Full | Medium |
| standard | No (below 700 default) | Restricted | Low |
| probationary | No | Denied | None |
| untrusted | No | Denied | None |

**[Default Implementation]**

#### Worked Example -- Tier Resolution

```
Given: score = 750
When:  trust_level_for_score(750)
Then:  "trusted"  (750 >= 700 but < 900)

Given: score = 299
When:  trust_level_for_score(299)
Then:  "untrusted"  (299 < 300)

Given: score = 500
When:  trust_level_for_score(500)
Then:  "standard"  (500 >= 500 but < 700)
```

---

## 5. Handshake Protocol

### 5.1 Overview

The handshake protocol provides mutual agent verification using
Ed25519 challenge/response. Both the initiator and responder MUST
possess Ed25519 key pairs managed by the AgentMesh identity layer.
**[Pure Specification]**

### 5.2 HandshakeChallenge

A HandshakeChallenge MUST contain the following fields:

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `challenge_id` | string | Yes | Generated | Format: `challenge_{hex(8)}` |
| `nonce` | string | Yes | Generated | 32-byte hex-encoded random value |
| `freshness_nonce` | string or null | No | null | RFC 9334 freshness nonce; 16-byte hex when present |
| `timestamp` | datetime | Yes | now(UTC) | Must be timezone-aware UTC |
| `expires_in_seconds` | int | Yes | 30 | Challenge TTL in seconds |

**[Pure Specification]**

#### 5.2.1 Challenge Generation

The `HandshakeChallenge.generate()` class method MUST:

1. Generate a unique `challenge_id` using `secrets.token_hex(8)`.
2. Generate a cryptographically random `nonce` using
   `secrets.token_hex(32)`.
3. If `require_freshness=True`, generate a `freshness_nonce` using
   `secrets.token_hex(16)`.
4. Record the current UTC timestamp.
5. Set `expires_in_seconds` to 30.

**[Pure Specification]**

#### 5.2.2 Challenge Expiry

A challenge is expired when:

```
elapsed = (now_utc - challenge.timestamp).total_seconds()
expired = elapsed > challenge.expires_in_seconds
```

Expired challenges MUST be rejected during response verification.
**[Pure Specification]**

### 5.3 HandshakeResponse

A HandshakeResponse MUST contain the following fields:

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `challenge_id` | string | Yes | -- | Must match the challenge |
| `response_nonce` | string | Yes | -- | 16-byte hex random value |
| `agent_did` | string | Yes | -- | Responder's DID (`did:mesh:*`) |
| `capabilities` | list[string] | No | [] | Responder's capability attestations |
| `trust_score` | int | No | 0 | Self-reported score (0--1000); informational only |
| `signature` | string | Yes | -- | Base64 Ed25519 signature over payload |
| `public_key` | string | Yes | -- | Base64 Ed25519 public key |
| `freshness_nonce` | string or null | No | null | Echoed from challenge |
| `user_context` | dict or null | No | null | End-user context for OBO flows |
| `timestamp` | datetime | Yes | now(UTC) | Response timestamp |

**[Pure Specification]**

#### 5.3.1 Signature Payload

The signed payload MUST be constructed as:

```
payload = "{challenge_id}:{challenge_nonce}:{response_nonce}:{agent_did}"
```

If the challenge contains a `freshness_nonce`, it MUST be appended:

```
payload = "{challenge_id}:{challenge_nonce}:{response_nonce}:{agent_did}:{freshness_nonce}"
```

The payload MUST be signed using the responder's Ed25519 private key.
**[Pure Specification]**

### 5.4 HandshakeResult

A HandshakeResult MUST contain the following fields:

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `verified` | bool | Yes | -- | Whether the handshake succeeded |
| `peer_did` | string | Yes | -- | Peer's DID |
| `peer_name` | string or null | No | null | Human-readable peer name |
| `trust_score` | int | Yes | 0 | Registry-authoritative score (0--1000) |
| `trust_level` | string | Yes | "untrusted" | One of: verified_partner, trusted, standard, untrusted |
| `capabilities` | list[string] | No | [] | Verified capabilities |
| `user_context` | UserContext or null | No | null | Propagated OBO user context |
| `handshake_started` | datetime | Yes | now(UTC) | Start timestamp |
| `handshake_completed` | datetime or null | No | null | Completion timestamp |
| `latency_ms` | int or null | No | null | Handshake duration in milliseconds |
| `rejection_reason` | string or null | No | null | Reason for failure (if `verified=false`) |

**[Pure Specification]**

### 5.5 TrustHandshake

The `TrustHandshake` class orchestrates the full handshake lifecycle.

#### 5.5.1 Configuration

| Parameter | Type | Default | Constraints |
| --- | --- | --- | --- |
| `agent_did` | string | Required | Must match `did:mesh:*`; must not be empty |
| `identity` | AgentIdentity or null | null | Ed25519 identity for signing |
| `registry` | IdentityRegistry or null | null | Authoritative identity resolution |
| `cache_ttl_seconds` | int | 900 | Must be >= 0; verification result cache TTL |
| `timeout_seconds` | float | 30.0 | Must be > 0; overall handshake timeout |

**[Default Implementation]**

#### 5.5.2 Handshake Flow

The `initiate()` method MUST perform the following steps in order:

1. **Cache check:** If `use_cache=True` and `require_freshness=False`,
   return a cached result if one exists and is within the TTL window.
2. **Challenge generation:** Generate a `HandshakeChallenge` with
   optional freshness nonce.
3. **Pending challenge tracking:** Store the challenge. If the
   pending challenge count exceeds `_max_pending_challenges` (1000),
   return a failure result.
4. **Peer resolution:** Resolve the peer's identity from the
   `IdentityRegistry`. If the registry is not configured, or the peer
   DID is not registered, or the peer identity is not active, return
   a failure result.
5. **Response generation:** The peer signs the challenge payload with
   their Ed25519 private key.
6. **Verification:** Verify the response (see Section 5.5.3).
7. **Cache result:** On success, cache the result for future lookups.
8. **Cleanup:** Remove the pending challenge from the tracking map.

**[Pure Specification]**

#### 5.5.3 Verification Checks

Response verification MUST perform the following checks in order. If
any check fails, the handshake MUST be rejected with a descriptive
reason:

1. **Challenge ID match:** Response `challenge_id` MUST equal the
   original challenge's `challenge_id`.
2. **Expiry check:** The challenge MUST NOT be expired.
3. **DID binding:** If an `expected_peer_did` was provided, the
   response `agent_did` MUST match.
4. **Registry membership:** The response `agent_did` MUST be
   registered and active in the `IdentityRegistry`.
5. **Ed25519 signature:** The signature MUST be valid against the
   registered public key.
6. **Public key match:** The response `public_key` MUST match the
   registry's stored public key.
7. **Trust score threshold:** The registry-authoritative trust score
   (never the self-reported score) MUST meet the
   `required_trust_score`.
8. **Capability attestation:** The registry-authoritative capabilities
   MUST include all `required_capabilities` (if specified).

**[Pure Specification]**

#### 5.5.4 Timeout Enforcement

The entire handshake MUST complete within `timeout_seconds` (default:
30.0s). If the timeout is exceeded, a `HandshakeTimeoutError` MUST be
raised. A performance budget of `MAX_HANDSHAKE_MS = 200` is advisory.
**[Default Implementation]**

#### 5.5.5 Concurrency Safety

Implementations MUST serialize mutations on pending challenges and
verified peers using appropriate locking primitives (e.g.,
`asyncio.Lock` for async Python). The purge-check-insert sequence for
pending challenges MUST be atomic. **[Pure Specification]**

#### Worked Example -- Handshake

```
Given: initiator = did:mesh:aaa, peer = did:mesh:bbb
       registry has did:mesh:bbb with trust_score=500, capabilities=["read:data"]

Step 1: initiator generates HandshakeChallenge
        challenge_id = "challenge_f3a9b2c1"
        nonce = "a1b2c3d4..." (64 hex chars)
        expires_in_seconds = 30

Step 2: peer signs payload
        payload = "challenge_f3a9b2c1:{nonce}:{response_nonce}:did:mesh:bbb"
        signature = Ed25519.sign(private_key, payload.encode())

Step 3: initiator verifies
        - challenge_id matches ✓
        - not expired ✓
        - did:mesh:bbb is registered and active ✓
        - Ed25519 signature valid against registered public key ✓
        - registry trust score 500 >= required 700? ✗

Result: HandshakeResult(verified=false, rejection_reason="Trust score
        500 below required 700")
```

---

## 6. Trust Bridge

### 6.1 Overview

The `TrustBridge` is the central coordination point for managing peer
trust relationships. It integrates with the handshake protocol,
endorsement registry, and identity system. **[Pure Specification]**

### 6.2 TrustBridge Schema

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `agent_did` | string | Yes | -- | This agent's DID; must match `did:mesh:*` |
| `default_trust_threshold` | int | No | 700 | Range [0, 1000]; default threshold for peer trust checks |
| `peers` | dict[string, PeerInfo] | No | {} | Map of peer DID to PeerInfo records |

**[Default Implementation]**

### 6.3 PeerInfo Schema

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `peer_did` | string | Yes | -- | Peer's decentralized identifier |
| `peer_name` | string or null | No | null | Human-readable name |
| `protocol` | string | Yes | -- | One of: `"a2a"`, `"mcp"`, `"iatp"`, `"acp"` |
| `trust_score` | int | No | 0 | Range [0, 1000] |
| `trust_verified` | bool | No | false | Whether the peer has been verified via handshake |
| `last_verified` | datetime or null | No | null | Timestamp of last verification |
| `capabilities` | list[string] | No | [] | Capability strings the peer holds |
| `endpoint` | string or null | No | null | Network endpoint URL |
| `connected_at` | datetime or null | No | null | Connection establishment timestamp |

**[Pure Specification]**

### 6.4 HMAC Integrity Check

The `TrustBridge` MUST protect peer records with an in-process HMAC
integrity check to detect accidental corruption.

#### 6.4.1 Key Generation

On construction, the `TrustBridge` MUST generate a 32-byte random
HMAC key using `os.urandom(32)`. This key is stored in process memory
only and MUST NOT be serialized or persisted. **[Default Implementation]**

#### 6.4.2 Signing

The HMAC payload for a peer MUST be:

```
payload = "{peer_did}:{trust_score}:{trust_verified}:{comma_joined_capabilities}"
```

The HMAC MUST be computed using SHA-256:

```
signature = HMAC-SHA256(key, payload.encode())
```

**[Pure Specification]**

#### 6.4.3 Verification

Before trusting a cached peer score, `is_peer_trusted()` MUST verify
the HMAC. If the integrity check fails, the implementation MUST:

1. Log a warning.
2. Delete the corrupted peer record.
3. Delete the associated HMAC signature.
4. Return `false` (fail closed).

**[Pure Specification]**

#### 6.4.4 Security Limitations

The HMAC key, peer data, and signatures reside in the same process
memory. This check guards only against accidental in-process corruption
(bit flips, programmer error). An attacker with write access to
`TrustBridge` state can forge valid HMACs. For real tamper-resistance,
move the HMAC key and signature store off-process -- to a sidecar,
TEE (SGX/SEV), or remote signing service. **[Pure Specification]**

### 6.5 verify_peer

The `verify_peer()` method MUST:

1. Determine the effective trust threshold (use `required_trust_score`
   if provided, otherwise `default_trust_threshold`).
2. Initiate a handshake via the internal `TrustHandshake` instance.
3. On success, create a `PeerInfo` record with the handshake results,
   store it in the peers map, and compute an HMAC signature.
4. Return the `HandshakeResult`.

**[Pure Specification]**

### 6.6 is_peer_trusted

The `is_peer_trusted()` method MUST:

1. Look up the peer in the peers map.
2. If not found or `trust_verified` is false, return false.
3. Verify the peer record's HMAC integrity (Section 6.4.3).
4. Compare the peer's `trust_score` against the effective threshold.
5. Return true only if the integrity check passes AND the score meets
   the threshold.

**[Pure Specification]**

### 6.7 revoke_peer_trust

The `revoke_peer_trust()` method MUST:

1. Look up the peer by DID.
2. Set `trust_verified` to false.
3. Set `trust_score` to 0.
4. Return true if the peer existed, false otherwise.

Note: revocation does NOT delete the peer record -- the peer remains
in the map with zero trust for auditability. **[Pure Specification]**

### 6.8 get_endorsements

The `get_endorsements()` method MUST resolve endorsements on demand
from the `EndorsementRegistry` rather than caching them on `PeerInfo`.
This avoids HMAC integrity gaps where endorsement changes would
invalidate the peer record signature. If no endorsement registry is
configured, the method MUST return an empty list.
**[Pure Specification]**

#### Worked Example -- Trust Bridge

```
Given: bridge with agent_did="did:mesh:alpha", default_trust_threshold=700

Step 1: verify_peer("did:mesh:beta", protocol="a2a")
        -> handshake succeeds, trust_score=800
        -> PeerInfo stored, HMAC computed

Step 2: is_peer_trusted("did:mesh:beta")
        -> HMAC verified ✓
        -> 800 >= 700 ✓
        -> returns true

Step 3: revoke_peer_trust("did:mesh:beta", reason="compromised")
        -> trust_verified = false, trust_score = 0
        -> returns true

Step 4: is_peer_trusted("did:mesh:beta")
        -> trust_verified is false
        -> returns false
```

---

## 7. Endorsement Registry

### 7.1 Overview

The `EndorsementRegistry` implements the Endorser role from
[RFC 9334](https://datatracker.ietf.org/doc/html/rfc9334) (Remote
Attestation Procedures Architecture). An endorsement is a first-class
metadata artifact where one entity vouches for another's capability,
integrity, or compliance. **[Pure Specification]**

### 7.2 EndorsementType Enum

| Value | String | Description |
| --- | --- | --- |
| `CAPABILITY` | `"capability"` | Vouches that the agent possesses specific capabilities |
| `INTEGRITY` | `"integrity"` | Vouches for the agent's code/runtime integrity |
| `COMPLIANCE` | `"compliance"` | Vouches for regulatory or policy compliance |
| `IDENTITY` | `"identity"` | Vouches for the agent's identity binding |
| `REFERENCE_VALUE` | `"reference_value"` | Provides known-good reference values for appraisal |

**[Pure Specification]**

### 7.3 Endorsement Schema

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `endorser_did` | string | Yes | -- | DID of the endorsing entity |
| `target_did` | string | Yes | -- | DID of the agent being endorsed |
| `endorsement_type` | EndorsementType | Yes | -- | Category of endorsement |
| `claims` | dict[string, Any] | No | {} | Key-value pairs describing what is endorsed |
| `issued_at` | string | No | now(UTC).isoformat() | ISO 8601 issuance timestamp |
| `expires_at` | string or null | No | null | ISO 8601 expiry timestamp; null means no expiry |
| `metadata` | dict[string, Any] | No | {} | Additional context (audit trail, source system) |

**[Pure Specification]**

### 7.4 Endorsement Expiry

An endorsement MUST be considered expired when:

```
if expires_at is None:
    return False
expiry = parse_iso8601(expires_at)
return now_utc > expiry
```

If `expires_at` cannot be parsed, the endorsement MUST be treated as
expired (fail closed). **[Pure Specification]**

### 7.5 Registry Operations

#### 7.5.1 add

The `add()` method MUST reject expired endorsements with a warning log.
Non-expired endorsements MUST be stored keyed by `target_did`.
**[Pure Specification]**

#### 7.5.2 get_endorsements

The `get_endorsements()` method MUST:

1. Retrieve all endorsements for the given `target_did`.
2. Filter out expired endorsements.
3. Optionally filter by `endorsement_type`.
4. Purge expired entries from storage as a side effect.
5. Return results sorted by `issued_at` descending (newest first).

**[Pure Specification]**

#### 7.5.3 get_endorsers

The `get_endorsers()` method MUST return a deduplicated list of
endorser DIDs for a given target, preserving the order from
`get_endorsements()`. **[Pure Specification]**

#### 7.5.4 has_endorsement

The `has_endorsement()` method MUST return true if at least one valid
(non-expired) endorsement of the specified type exists for the target.
An optional `endorser_did` filter MUST further restrict the check to
endorsements from that specific endorser. **[Pure Specification]**

#### 7.5.5 revoke

The `revoke()` method MUST remove all endorsements from a specific
endorser for a given target. It MUST return the count of endorsements
removed and MUST log the revocation at INFO level.
**[Pure Specification]**

#### 7.5.6 clear

The `clear()` method MUST clear all endorsements for a specific target,
or all endorsements globally if no target is specified.
**[Pure Specification]**

### 7.6 Signature Verification

Current scope is unsigned metadata endorsements. Cryptographic
signature verification is deferred to a future iteration. Consumers
SHOULD treat endorsements as informational signals, not as proof of
claims, until signature verification is implemented.
**[Default Implementation]**

#### Worked Example -- Endorsement

```
Given: registry = EndorsementRegistry()

Step 1: Add compliance endorsement
        endorsement = Endorsement(
            endorser_did="did:mesh:compliance-authority",
            target_did="did:mesh:agent-alpha",
            endorsement_type=EndorsementType.COMPLIANCE,
            claims={"framework": "EU AI Act", "risk_level": "limited"},
        )
        registry.add(endorsement)

Step 2: Query endorsements
        result = registry.get_endorsements("did:mesh:agent-alpha")
        -> [Endorsement(endorser_did="did:mesh:compliance-authority", ...)]

Step 3: Check for endorsement
        registry.has_endorsement(
            "did:mesh:agent-alpha",
            EndorsementType.COMPLIANCE,
            endorser_did="did:mesh:compliance-authority",
        )
        -> True

Step 4: Revoke
        registry.revoke("did:mesh:agent-alpha", "did:mesh:compliance-authority")
        -> 1 (one endorsement removed)
```

---

## 8. Capability Scoping

### 8.1 Overview

Capability scoping provides fine-grained access control through
`action:resource[:qualifier]` capability strings. Each grant is
tracked with metadata (grantor, expiry, resource IDs) and can be
revoked individually or in bulk. **[Pure Specification]**

### 8.2 Capability String Format

Capabilities MUST follow the format:

```
action:resource[:qualifier]
```

Where:

- `action` is the verb (e.g., `read`, `write`, `execute`, `admin`).
- `resource` is the target resource (e.g., `data`, `reports`, `tools`).
- `qualifier` is an optional sub-resource (e.g., `calculator`).

Examples:

- `read:data` -- read access to data resources.
- `write:reports` -- write access to reports.
- `execute:tools:calculator` -- execute the calculator tool.
- `admin:*` -- administrative wildcard.

**[Pure Specification]**

### 8.3 CapabilityGrant Schema

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `grant_id` | string | No | Auto-generated | Format: `grant_{uuid_hex[:12]}` |
| `capability` | string | Yes | -- | Capability string (e.g., `read:data`) |
| `action` | string | Yes | -- | Action component parsed from capability |
| `resource` | string | Yes | -- | Resource component parsed from capability |
| `qualifier` | string or null | No | null | Optional qualifier component |
| `granted_to` | string | Yes | -- | DID of the grantee agent |
| `granted_by` | string | Yes | -- | DID of the grantor agent |
| `resource_ids` | list[string] | No | [] | Specific resource IDs this grant applies to |
| `conditions` | dict | No | {} | Additional conditions for this grant |
| `granted_at` | datetime | No | now(UTC) | Timestamp of grant creation |
| `expires_at` | datetime or null | No | null | Expiry timestamp; null means no expiry |
| `active` | bool | No | true | Whether the grant is currently active |
| `revoked_at` | datetime or null | No | null | Timestamp of revocation |

**[Pure Specification]**

### 8.4 Grant Validity

A grant is valid when:

```
grant.active == true AND (grant.expires_at is None OR now_utc <= grant.expires_at)
```

**[Pure Specification]**

### 8.5 Capability Matching

The `matches()` method MUST evaluate capability matching in order:

1. **Exact match or global wildcard:** If `grant.capability == "*"` or
   `grant.capability == requested`, the grant matches.
2. **Prefix wildcard:** If `grant.capability` ends with `:*`, the
   prefix (without `*`) MUST be a prefix of `requested`.
3. **Colon-boundary prefix:** If the grant capability is a
   colon-delimited prefix of the requested capability, the grant
   matches. This prevents `read` from matching `readwrite:secret`.
4. **Component matching fallback:** Parse both capability strings and
   compare action, resource, and qualifier independently. Wildcard
   `*` in any component matches any value. Malformed requests (no
   colon) MUST fail closed (return false).
5. **Resource ID scoping:** If `resource_ids` is non-empty and a
   `resource_id` is provided, the requested resource ID MUST be
   present in the grant's `resource_ids`.

**[Pure Specification]**

### 8.6 CapabilityScope

The `CapabilityScope` aggregates all grants for a single agent and
provides the primary access check interface.

#### 8.6.1 has_capability

The `has_capability()` method MUST:

1. Check the deny list first. If the requested capability is in the
   `denied` list, return false immediately.
2. Iterate through all grants and return true if any valid grant
   matches the requested capability.
3. Return false if no matching grant is found (fail closed).

**[Pure Specification]**

#### 8.6.2 deny

The `deny()` method MUST add a capability string to the deny list.
Denied capabilities take precedence over any matching grants.
**[Pure Specification]**

#### 8.6.3 revoke_all

The `revoke_all()` method MUST revoke all active grants in the scope,
setting `active=false` and recording `revoked_at`. It MUST return the
count of revoked grants. **[Pure Specification]**

### 8.7 CapabilityRegistry

The `CapabilityRegistry` is the central registry for capability grants
across the mesh.

#### 8.7.1 grant

The `grant()` method MUST:

1. Create a `CapabilityGrant` via `CapabilityGrant.create()`.
2. Add the grant to the grantee's `CapabilityScope`.
3. Track the grant by grantor for bulk revocation.
4. Return the created grant.

**[Pure Specification]**

#### 8.7.2 check

The `check()` method MUST look up the agent's scope and delegate to
`CapabilityScope.has_capability()`. If no scope exists for the agent,
return false (fail closed). **[Pure Specification]**

#### 8.7.3 revoke_all_from

The `revoke_all_from()` method MUST revoke all grants issued by a
specific grantor across all agent scopes. This is the emergency
revocation path when a grantor agent is compromised. It MUST return
the total number of grants revoked. **[Pure Specification]**

#### Worked Example -- Capability Check

```
Given: registry = CapabilityRegistry()

Step 1: Grant capabilities
        registry.grant("read:data", to_agent="did:mesh:bob",
                        from_agent="did:mesh:alice")
        registry.grant("execute:tools:calculator", to_agent="did:mesh:bob",
                        from_agent="did:mesh:alice")

Step 2: Check access
        registry.check("did:mesh:bob", "read:data")     -> True
        registry.check("did:mesh:bob", "write:data")     -> False  (no grant)
        registry.check("did:mesh:bob", "execute:tools")  -> True   (prefix match)
        registry.check("did:mesh:carol", "read:data")    -> False  (unknown agent)

Step 3: Grantor compromised -- revoke all grants from alice
        registry.revoke_all_from("did:mesh:alice")  -> 2

Step 4: Re-check
        registry.check("did:mesh:bob", "read:data")      -> False  (revoked)
```

---

## 9. Agent Cards

### 9.1 Overview

`TrustedAgentCard` provides a signed metadata record that agents use
for discovery and mutual verification. Cards are cryptographically
signed with Ed25519 to prevent impersonation. **[Pure Specification]**

### 9.2 TrustedAgentCard Schema

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `name` | string | Yes | -- | Agent name |
| `description` | string | No | "" | Human-readable description |
| `capabilities` | list[string] | No | [] | Advertised capabilities |
| `agent_did` | string or null | No | null | Agent's DID (set during signing) |
| `public_key` | string or null | No | null | Base64 Ed25519 public key |
| `trust_score` | float | No | 1.0 | Range [0.0, 1.0]; normalized trust score |
| `card_signature` | string or null | No | null | Base64 Ed25519 signature over card content |
| `signature_timestamp` | datetime or null | No | null | When the card was signed |
| `metadata` | dict[string, Any] | No | {} | Additional metadata |
| `created_at` | datetime | No | now(UTC) | Card creation timestamp |

**[Pure Specification]**

### 9.3 Card Signing

The `sign()` method MUST:

1. Set `agent_did` to the identity's DID.
2. Set `public_key` to the identity's public key.
3. Compute deterministic signable content by JSON-serializing the
   core fields (`name`, `description`, sorted `capabilities`,
   `trust_score`, `agent_did`, `public_key`) with sorted keys and
   compact separators.
4. Sign the content bytes with the identity's Ed25519 private key.
5. Record the `signature_timestamp`.

**[Pure Specification]**

### 9.4 Card Verification

The `verify_signature()` method MUST follow this verification
authority precedence (highest first):

1. **Explicit identity:** If an `identity` parameter is provided,
   verify against its public key. This is authoritative.
2. **Identity registry:** If an `identity_registry` is provided and
   the card's `agent_did` is registered, verify against the
   registry's public key. If the DID is NOT registered, verification
   MUST fail -- the embedded key is NOT consulted.
3. **Embedded public key (self-attesting):** Verify using the card's
   own `public_key`. This is trust-on-first-use only; an attacker
   can mint a card with their own key and a matching signature.

If neither `card_signature` nor `public_key` is present, verification
MUST return false. **[Pure Specification]**

### 9.5 CardRegistry

The `CardRegistry` provides discovery and caching of verified cards.

#### 9.5.1 Configuration

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `cache_ttl_seconds` | int | 900 | Verification cache TTL (15 minutes) |
| `revocation_list` | RevocationList or null | null | Optional revocation list integration |
| `identity_registry` | IdentityRegistry or null | null | Authoritative identity resolution |

**[Default Implementation]**

#### 9.5.2 register

The `register()` method MUST verify the card's signature before
storing. If verification fails, the card MUST NOT be stored and the
method MUST return false. On success, the card is stored keyed by
`agent_did` and a verification cache entry is created.
**[Pure Specification]**

#### 9.5.3 is_verified

The `is_verified()` method MUST:

1. **Revocation check:** If a `RevocationList` is configured and the
   DID is revoked, return false immediately. Revocation checks are
   NOT cached -- they always run.
2. **Card lookup:** If no card is registered, return false.
3. **Content hash:** Compute a SHA-256 hash over the card's signable
   content and signature. This pins the cache verdict to the exact
   content.
4. **Cache check:** If a cache entry exists with a matching content
   hash and the TTL has not expired, return the cached verdict.
5. **Re-verify:** Otherwise, re-verify the signature and update the
   cache.

**[Pure Specification]**

#### 9.5.4 Cache Invalidation

The cache MUST be invalidated when:

- The `revocation_list` property is changed (calls `clear_cache()`).
- The card's signable content or signature changes (content hash
  mismatch).
- The cache TTL expires.

**[Pure Specification]**

#### Worked Example -- Agent Card

```
Given: identity = AgentIdentity(name="analysis-bot", ...)

Step 1: Create signed card
        card = TrustedAgentCard.from_identity(identity)
        -> card.agent_did = "did:mesh:abc..."
        -> card.card_signature = "base64-ed25519-sig..."

Step 2: Register in CardRegistry
        registry = CardRegistry(identity_registry=identity_registry)
        registry.register(card)  -> True

Step 3: Verify
        registry.is_verified("did:mesh:abc...")  -> True (cached)

Step 4: Revoke the identity
        revocation_list.revoke("did:mesh:abc...")
        registry.is_verified("did:mesh:abc...")  -> False (revocation
        check runs before cache)
```

---

## 10. Protocol Bridge

### 10.1 Overview

The `ProtocolBridge` enables agents using different communication
protocols to interoperate. It supports `a2a` (Google Agent-to-Agent),
`mcp` (Anthropic Model Context Protocol), `iatp` (Inter-Agent Trust
Protocol), and `acp` (Agent Communication Protocol).
**[Pure Specification]**

### 10.2 ProtocolBridge Schema

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `agent_did` | string | Yes | -- | This agent's DID |
| `trust_bridge` | TrustBridge or null | No | Auto-created | Trust management instance |
| `supported_protocols` | list[string] | No | ["a2a", "mcp", "iatp", "acp"] | Supported protocols |

**[Default Implementation]**

### 10.3 Message Flow

The `send_message()` method MUST:

1. **Trust check:** Verify the peer is trusted via the `TrustBridge`.
   If not trusted, initiate a handshake. If the handshake fails,
   raise `PermissionError`.
2. **Protocol resolution:** Determine the target protocol from the
   explicit parameter or the peer's registered protocol.
3. **Translation:** If source and target protocols differ, translate
   the message.
4. **Send:** Dispatch the message via the protocol handler.

**[Pure Specification]**

### 10.4 Protocol Translation

#### 10.4.1 A2A to MCP

An A2A task message MUST be translated to an MCP tool call:

```
Input (A2A):
{
    "task_type": "analyze",
    "parameters": {"data": "..."}
}

Output (MCP):
{
    "method": "tools/call",
    "params": {
        "name": "analyze",
        "arguments": {"data": "..."}
    }
}
```

**[Default Implementation]**

#### 10.4.2 MCP to A2A

An MCP tool call MUST be translated to an A2A task message:

```
Input (MCP):
{
    "method": "tools/call",
    "params": {
        "name": "analyze",
        "arguments": {"data": "..."}
    }
}

Output (A2A):
{
    "task_type": "analyze",
    "parameters": {"data": "..."}
}
```

**[Default Implementation]**

#### 10.4.3 IATP Passthrough

IATP messages MUST pass through without translation, as IATP can wrap
any protocol. **[Default Implementation]**

#### 10.4.4 Default Passthrough

Unrecognized protocol combinations MUST pass through without
translation. **[Default Implementation]**

### 10.5 Verification Footer

The `add_verification_footer()` method MAY append a human-readable
verification footer to content, including:

- Trust score (out of 1000).
- Agent DID (truncated to 40 characters).
- Optional policy, audit, and view-log metadata.

**[Default Implementation]**

---

## 11. A2A Adapter

### 11.1 Overview

The `A2AAdapter` provides an interface to the Google A2A
(Agent-to-Agent) protocol with governance enforcement via the
`TrustBridge`. **[Pure Specification]**

### 11.2 Configuration

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `agent_did` | string | Yes | This agent's DID |
| `trust_bridge` | TrustBridge | Yes | Trust management instance |

**[Default Implementation]**

### 11.3 discover_agent

The `discover_agent()` method accepts an endpoint URL and returns an
A2A Agent Card dictionary containing `name`, `description`, and
`capabilities`. **[Default Implementation]**

### 11.4 create_task

The `create_task()` method MUST:

1. Verify the peer is trusted via `TrustBridge.is_peer_trusted()`.
2. If not trusted, raise `PermissionError("Peer not trusted")`.
3. Return a task descriptor with a unique `task_id`, `status`, and
   `type`.

**[Pure Specification]**

### 11.5 get_task_status

The `get_task_status()` method accepts a `peer_did` and `task_id` and
returns the current task status. **[Default Implementation]**

---

## 12. MCP Adapter

### 12.1 Overview

The `MCPAdapter` provides an interface to the Anthropic MCP (Model
Context Protocol) with governance enforcement. Tool calls are gated
by both trust checks and capability verification.
**[Pure Specification]**

### 12.2 Configuration

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `agent_did` | string | Yes | This agent's DID |
| `trust_bridge` | TrustBridge | Yes | Trust management instance |

**[Default Implementation]**

### 12.3 register_tool

The `register_tool()` method registers a tool with the adapter:

| Parameter | Type | Required | Description |
| --- | --- | --- | --- |
| `name` | string | Yes | Tool name |
| `description` | string | Yes | Tool description |
| `input_schema` | dict | Yes | JSON Schema for tool inputs |
| `required_capability` | string or null | No | Capability the caller must hold |

**[Default Implementation]**

### 12.4 call_tool

The `call_tool()` method MUST:

1. Verify the peer is trusted via `TrustBridge.is_peer_trusted()`.
   If not trusted, raise
   `PermissionError("Peer not trusted for MCP tool call")`.
2. Look up the peer's `PeerInfo` to access their capabilities.
3. If the tool has a `required_capability` and the peer's capabilities
   list does not contain it, raise
   `PermissionError("Peer lacks capability: {capability}")`.
4. Execute the tool and return the result with `governed=True`.

**[Pure Specification]**

### 12.5 list_tools

The `list_tools()` method MUST return all registered tools as a list
of dictionaries. **[Pure Specification]**

#### Worked Example -- MCP Tool Call

```
Given: adapter with registered tool "sql_query"
       required_capability = "execute:tools:sql"
       peer did:mesh:bob has capabilities = ["read:data"]

Step 1: call_tool("did:mesh:bob", "sql_query", {"query": "SELECT 1"})

Step 2: Trust check
        is_peer_trusted("did:mesh:bob") -> True  (score 800 >= 700)

Step 3: Capability check
        "execute:tools:sql" in ["read:data"]? -> False

Result: PermissionError("Peer lacks capability: execute:tools:sql")
```

---

## 13. Rate Limiting

### 13.1 Overview

AgentMesh provides token bucket rate limiting at both per-agent and
global levels to protect the mesh from abuse and resource exhaustion.
**[Pure Specification]**

### 13.2 TokenBucket Algorithm

The `TokenBucket` MUST implement:

1. **Initialization:** Start with `tokens = capacity` (full bucket).
2. **Refill:** On each operation, add `elapsed_seconds * rate` tokens,
   capped at `capacity`.
3. **Consume:** If `tokens >= requested`, subtract and return true.
   Otherwise return false.
4. **Thread safety:** All operations MUST be thread-safe using a lock.

**[Pure Specification]**

### 13.3 RateLimitConfig Schema

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `global_rate` | float | No | 100.0 | Global tokens per second |
| `global_capacity` | int | No | 200 | Global maximum burst size |
| `per_agent_rate` | float | No | 10.0 | Per-agent tokens per second |
| `per_agent_capacity` | int | No | 20 | Per-agent maximum burst |
| `backpressure_threshold` | float | No | 0.8 | Range [0.0, 1.0]; usage ratio at which backpressure is signaled |

**[Default Implementation]**

### 13.4 RateLimitResult Schema

| Field | Type | Required | Default | Constraints |
| --- | --- | --- | --- | --- |
| `allowed` | bool | Yes | -- | Whether the request was allowed |
| `remaining_tokens` | float | Yes | -- | Tokens remaining (minimum of per-agent and global) |
| `retry_after_seconds` | float or null | No | null | Seconds until tokens are available (if denied) |
| `backpressure` | bool | Yes | -- | Whether the backpressure threshold has been reached |

**[Pure Specification]**

### 13.5 RateLimiter

The `RateLimiter` MUST maintain:

- One global `TokenBucket`.
- One per-agent `TokenBucket` created on demand, keyed by agent DID.

#### 13.5.1 allow

The `allow()` method MUST check both per-agent and global limits:

1. Consume from the per-agent bucket. If denied, return false.
2. Consume from the global bucket. If denied, return false.
3. Return true only if both succeed.

**[Pure Specification]**

#### 13.5.2 check

The `check()` method MUST return a `RateLimitResult` with:

- `allowed`: Result of the `allow()` check.
- `remaining_tokens`: Minimum of per-agent and global available tokens.
- `retry_after_seconds`: Maximum of per-agent and global time until
  next token (if denied).
- `backpressure`: True when the usage ratio
  `(1.0 - remaining / per_agent_capacity)` meets or exceeds the
  `backpressure_threshold`.

**[Pure Specification]**

#### 13.5.3 Bucket Eviction

To prevent memory exhaustion from many unique agent DIDs, the
`RateLimiter` MUST enforce a maximum bucket count
(`max_agent_buckets`, default 100,000). When the limit is reached,
the oldest bucket MUST be evicted. **[Default Implementation]**

#### Worked Example -- Rate Limiting

```
Given: per_agent_rate=10.0, per_agent_capacity=20, backpressure_threshold=0.8

Step 1: Agent "did:mesh:alpha" sends first request
        allow("did:mesh:alpha") -> True
        remaining = 19.0, backpressure = False

Step 2: Agent sends 15 more requests rapidly
        remaining = 4.0
        usage_ratio = 1.0 - (4.0 / 20) = 0.8
        backpressure = True (0.8 >= 0.8)

Step 3: Agent sends 5 more requests (exhausts bucket)
        allow() -> False
        retry_after_seconds = 0.1 (1 token / 10.0 rate)
```

---

## 14. Rate Limit Middleware

### 14.1 Overview

The `RateLimitMiddleware` integrates token bucket rate limiting with
HTTP request handling. It extracts agent identity from request headers
and decorates responses with standard rate limit headers.
**[Pure Specification]**

### 14.2 Request Headers

| Header | Purpose | Default |
| --- | --- | --- |
| `X-Agent-DID` | Agent's decentralized identifier | `"anonymous"` |

**[Pure Specification]**

### 14.3 Response Headers

| Header | Type | When Set | Description |
| --- | --- | --- | --- |
| `X-RateLimit-Remaining` | int | Always | Remaining tokens (floor) |
| `X-RateLimit-Reset` | float | When retry_after > 0 | Seconds until next token |
| `Retry-After` | float | On 429 response | Standard retry header |
| `X-Backpressure` | string | When backpressure = true | Value: `"true"` |

**[Pure Specification]**

### 14.4 Middleware Flow

The `handle()` method MUST:

1. Extract the agent DID from the `X-Agent-DID` request header. If
   absent, use the configured `default_agent_did` (default:
   `"anonymous"`).
2. Call `RateLimiter.check()` with the agent DID.
3. If `result.allowed` is false, return a `429 Too Many Requests`
   response with `Retry-After` header and rate limit headers.
4. If allowed, delegate to the handler, then decorate the response
   with rate limit headers.

**[Pure Specification]**

### 14.5 429 Response Body

When rate limited, the response body MUST contain:

```json
{
    "error": "Too Many Requests",
    "retry_after": <seconds>
}
```

**[Default Implementation]**

---

## 15. Behavior Monitoring

### 15.1 Overview

The `AgentBehaviorMonitor` tracks per-agent runtime metrics and
automatically quarantines agents that exhibit anomalous behavior.
Monitored signals include tool call frequency, consecutive failure
rate, and capability escalation attempts. **[Pure Specification]**

### 15.2 AgentMetrics Schema

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `agent_did` | string | -- | Agent's DID |
| `total_calls` | int | 0 | Total tool invocations |
| `failed_calls` | int | 0 | Total failed invocations |
| `consecutive_failures` | int | 0 | Current consecutive failure streak |
| `capability_denials` | int | 0 | Denied capability check count |
| `last_activity` | datetime or null | null | Timestamp of last activity |
| `quarantined` | bool | false | Whether the agent is quarantined |
| `quarantine_reason` | string or null | null | Reason for quarantine |
| `quarantined_at` | datetime or null | null | When quarantine was imposed |
| `call_timestamps` | list[datetime] | [] | Rolling window for burst detection |

**[Pure Specification]**

### 15.3 Configuration

| Parameter | Type | Default | Description |
| --- | --- | --- | --- |
| `burst_window_seconds` | int | 60 | Time window for burst detection |
| `burst_threshold` | int | 100 | Max calls in the burst window before quarantine |
| `consecutive_failure_threshold` | int | 20 | Consecutive failures before quarantine |
| `capability_denial_threshold` | int | 10 | Capability denials before quarantine |
| `quarantine_duration` | timedelta | 15 minutes | Auto-quarantine duration |
| `max_tracked_agents` | int | 50,000 | Evict oldest agents beyond this limit |

**[Default Implementation]**

### 15.4 record_tool_call

The `record_tool_call()` method MUST:

1. Increment `total_calls`.
2. Record `last_activity`.
3. If `success=True`, reset `consecutive_failures` to 0.
4. If `success=False`:
   a. Increment `failed_calls` and `consecutive_failures`.
   b. If `consecutive_failures >= consecutive_failure_threshold`,
      quarantine the agent.
5. **Burst detection:** Trim `call_timestamps` to the burst window,
   append the current timestamp, and if the count exceeds
   `burst_threshold`, quarantine the agent.

**[Pure Specification]**

### 15.5 record_capability_denial

The `record_capability_denial()` method MUST increment
`capability_denials`. If the count reaches
`capability_denial_threshold`, the agent MUST be quarantined with
the reason including the denied capability name.
**[Pure Specification]**

### 15.6 Quarantine

#### 15.6.1 Automatic Quarantine

When a threshold is breached, the monitor MUST:

1. Set `quarantined = true`.
2. Record `quarantine_reason` with the specific threshold breached.
3. Record `quarantined_at` timestamp.
4. Log at WARNING level: `"QUARANTINE agent {did}: {reason}"`.

If the agent is already quarantined, the method MUST be idempotent
(no duplicate logging). **[Pure Specification]**

#### 15.6.2 Auto-Release

The `is_quarantined()` method MUST check whether the quarantine
duration has elapsed. If so, the agent MUST be automatically released
by calling `release_quarantine()`. **[Default Implementation]**

#### 15.6.3 Manual Release

The `release_quarantine()` method MUST:

1. Set `quarantined = false`.
2. Clear `quarantine_reason` and `quarantined_at`.
3. Reset `consecutive_failures` and `capability_denials` to 0.
4. Log at INFO level: `"Released agent {did} from quarantine"`.

**[Pure Specification]**

### 15.7 Agent Eviction

When the tracked agent count reaches `max_tracked_agents`, the agent
with the oldest `last_activity` MUST be evicted to make room for new
entries. **[Default Implementation]**

#### Worked Example -- Behavior Quarantine

```
Given: monitor with consecutive_failure_threshold=20

Step 1: Agent "did:mesh:rogue" makes 19 consecutive failed tool calls
        consecutive_failures = 19, quarantined = false

Step 2: 20th consecutive failure
        consecutive_failures = 20
        20 >= 20 -> quarantine triggered
        quarantine_reason = "Consecutive failure threshold breached
                            (20 failures)"

Step 3: is_quarantined("did:mesh:rogue") -> True

Step 4: 15 minutes later
        is_quarantined("did:mesh:rogue")
        -> quarantine_duration elapsed -> auto-release
        -> False
```

---

## 16. mTLS Security

### 16.1 Transport Security

Implementations SHOULD support mutual TLS (mTLS) for all inter-agent
communication. When mTLS is enabled:

1. Both the initiator and responder MUST present valid X.509
   certificates.
2. The certificate's Subject Alternative Name (SAN) SHOULD contain
   the agent's DID for identity binding.
3. Certificate revocation MUST be checked against the
   `RevocationList` maintained by the identity layer.

**[Pure Specification]**

### 16.2 Relationship to Trust Handshake

mTLS provides transport-level authentication. The trust handshake
(Section 5) provides application-level trust verification. Both
layers SHOULD be used together:

- mTLS establishes that the transport peer holds a valid certificate.
- The handshake establishes that the application peer meets trust
  score and capability requirements.

**[Pure Specification]**

### 16.3 Certificate Pinning

For high-trust tiers (verified_partner, trusted), implementations
SHOULD support certificate pinning where the peer's certificate
fingerprint is recorded on first successful handshake and verified
on subsequent connections. **[Default Implementation]**

---

## 17. Trust Propagation

### 17.1 Transitive Trust

Trust MUST NOT propagate transitively by default. If Agent A trusts
Agent B and Agent B trusts Agent C, Agent A MUST NOT automatically
trust Agent C. Each peer relationship MUST be established through an
independent handshake. **[Pure Specification]**

### 17.2 Endorsement-Based Propagation

Trust MAY be influenced (but not granted) by endorsements.
If Agent A has a `verified_partner` endorsement from a trusted
authority, other agents MAY use this as a signal to lower their
required trust threshold for Agent A. However, the handshake MUST
still complete successfully. **[Pure Specification]**

### 17.3 Score Decay

Implementations SHOULD support trust score decay over time.
If an agent has not been re-verified within a configurable window,
its effective trust score SHOULD decrease. The decay function and
parameters are implementation-specific. **[Default Implementation]**

---

## 18. Service Discovery

### 18.1 Agent Discovery

Agents SHOULD advertise their presence through signed Agent Cards
(Section 9) registered in a `CardRegistry`. Discovery clients MUST:

1. Retrieve the agent card from the registry.
2. Verify the card's signature.
3. Check the card's `agent_did` against the `RevocationList`.
4. Initiate a handshake if the card is verified.

**[Pure Specification]**

### 18.2 Capability-Based Discovery

The `CardRegistry.find_by_capability()` method MUST return all
registered cards that advertise a specific capability. This enables
capability-based agent discovery without requiring prior knowledge
of agent DIDs. **[Pure Specification]**

### 18.3 Protocol-Based Discovery

Agents SHOULD advertise their supported protocols in their
capabilities list (e.g., `"protocol:a2a"`, `"protocol:mcp"`). The
`ProtocolBridge` SHOULD use this information to determine the
appropriate communication protocol for each peer.
**[Default Implementation]**

---

## 19. Failure Semantics

### 19.1 Fail Closed

All enforcement operations MUST fail closed:

| Operation | Failure Behavior |
| --- | --- |
| Handshake challenge expired | Reject handshake |
| Handshake signature invalid | Reject handshake |
| Handshake timeout exceeded | Raise `HandshakeTimeoutError` |
| Peer DID not in registry | Reject handshake |
| Peer identity not active | Reject handshake |
| Trust score below threshold | Reject handshake |
| HMAC integrity check failed | Delete peer record, return false |
| Capability not granted | Return false |
| Malformed capability string | Return false (no match) |
| Rate limit exhausted | Return 429 response |
| Endorsement expired | Exclude from results |
| Endorsement parse error | Treat as expired |
| Card signature invalid | Reject registration |
| Card DID revoked | Return false on is_verified |
| Agent quarantined | Block all mesh operations |
| Unknown protocol combination | Passthrough (no translation) |
| Missing `X-Agent-DID` header | Use `"anonymous"` default |

### 19.2 Error Types

Implementations MUST define the following error types:

| Error | Context |
| --- | --- |
| `HandshakeError` | General handshake failure (empty DID, invalid format) |
| `HandshakeTimeoutError` | Handshake exceeded `timeout_seconds` |
| `PermissionError` | Peer not trusted or lacks required capability |
| `ValueError` | Invalid configuration (negative TTL, expired challenge) |

**[Pure Specification]**

### 19.3 Idempotency

The following operations MUST be idempotent:

- `EndorsementRegistry.revoke()` with no matching endorsements.
- `CapabilityScope.deny()` with an already-denied capability.
- `AgentBehaviorMonitor._quarantine()` on an already-quarantined
  agent.
- `CardRegistry.clear_cache()` on an empty cache.

**[Pure Specification]**

---

## 20. Security Considerations

### 20.1 Self-Reported Trust Scores

Agents include a self-reported `trust_score` in `HandshakeResponse`.
This value MUST NOT be used for access decisions. The registry-backed
trust score is authoritative. Self-reported scores are informational
metadata only. **[Pure Specification]**

### 20.2 Handshake DoS Prevention

The `TrustHandshake` MUST limit pending challenges to prevent
memory exhaustion from unanswered challenges. The default limit is
1,000 pending challenges. Expired challenges MUST be purged before
checking the limit. **[Default Implementation]**

### 20.3 HMAC Limitations

The in-process HMAC integrity check on peer records (Section 6.4)
guards against accidental corruption only. The HMAC key, data, and
signatures all reside in the same process memory. An attacker with
write access to `TrustBridge` state can forge valid HMACs. For
tamper-resistance against adversaries with code execution, the HMAC
key and signature store MUST be moved off-process -- to a sidecar
with restricted IPC, to a TEE (SGX/SEV), or to a remote signing
service.

### 20.4 Endorsement Trust

Current endorsements are unsigned metadata. Consumers MUST treat
endorsements as informational signals, not as cryptographic proof
of claims. Malicious endorsers can fabricate claims. Signature
verification for endorsements is planned for a future iteration.

### 20.5 Card Self-Attestation

When verifying a card using only the embedded public key
(no registry, no explicit identity), the verification proves only
that the bearer signed the card, not ownership of the claimed DID.
An attacker can mint a card with their own key. Registry-backed
verification SHOULD always be preferred. **[Pure Specification]**

### 20.6 Rate Limiter Memory

Per-agent token buckets are created on demand and can be used as
an attack vector for memory exhaustion. The `max_agent_buckets`
limit (default 100,000) MUST be enforced. Similarly, the behavior
monitor's `max_tracked_agents` limit (default 50,000) MUST be
enforced. Both use FIFO eviction. **[Default Implementation]**

### 20.7 Capability String Injection

Capability strings MUST be validated at the colon-boundary level.
The matching algorithm MUST NOT allow `read` to match
`readwrite:secret` -- only colon-delimited prefix matching is
permitted. Malformed requests (no colon separator) MUST fail closed.
**[Pure Specification]**

### 20.8 Freshness Nonce Replay

When `require_freshness=True`, the handshake bypasses the result
cache, ensuring every verification produces fresh Evidence. The
freshness nonce MUST be included in the signed payload so that
replayed responses are detectable. **[Pure Specification]**

---

## 21. Conformance Requirements

### 21.1 MUST Requirements

An implementation is conformant if it satisfies all MUST requirements:

1.  Trust scores are integers in the range [0, 1000].
2.  Trust tier resolution follows the five-tier threshold table.
3.  Handshake challenges expire after `expires_in_seconds`.
4.  Handshake signatures use Ed25519 over the specified payload format.
5.  Handshake verification checks are performed in the specified order.
6.  Registry-backed trust scores are authoritative; self-reported
    scores are never used for access decisions.
7.  `TrustBridge` protects peer records with HMAC integrity checks.
8.  HMAC verification failures result in peer record deletion and
    fail-closed denial.
9.  Endorsements are filtered by expiry; expired endorsements are
    purged and rejected on add.
10. Capability matching respects deny lists (deny before grant check).
11. Capability matching uses colon-boundary prefix rules.
12. Agent card verification follows the three-level authority
    precedence.
13. `CardRegistry.is_verified()` checks revocation before cache.
14. Rate limiting uses token bucket at both per-agent and global
    levels.
15. Rate limit middleware returns 429 with `Retry-After` header on
    denial.
16. Behavior monitor quarantines agents that breach configured
    thresholds.
17. All enforcement operations fail closed.
18. Trust does not propagate transitively.

### 21.2 Test Coverage

Conformance tests MUST cover:

- Trust tier resolution from scores at boundary values (299, 300,
  499, 500, 699, 700, 899, 900).
- Handshake challenge generation and expiry.
- Handshake Ed25519 signature creation and verification.
- Handshake failure modes (expired challenge, DID mismatch, invalid
  signature, insufficient score, missing capabilities).
- Handshake timeout enforcement.
- Trust bridge peer verification and HMAC integrity.
- Trust bridge revocation and fail-closed on corruption.
- Endorsement add, query, expiry, and revocation.
- Capability grant, check, deny, and revoke_all_from.
- Capability matching with wildcards, prefixes, and malformed inputs.
- Agent card signing, verification, and registry caching.
- Card verification with revocation list integration.
- Protocol bridge A2A-to-MCP and MCP-to-A2A translation.
- Rate limiter token consumption, exhaustion, and backpressure.
- Rate limit middleware 429 response and header decoration.
- Behavior monitor quarantine on consecutive failures, burst
  detection, and capability denial.
- Behavior monitor auto-release after quarantine duration.

---

## 22. References

- [RFC 2119: Key words for use in RFCs](https://datatracker.ietf.org/doc/html/rfc2119)
- [RFC 8174: Ambiguity of Uppercase vs Lowercase in RFC 2119](https://datatracker.ietf.org/doc/html/rfc8174)
- [RFC 9334: Remote Attestation Procedures (RATS) Architecture](https://datatracker.ietf.org/doc/html/rfc9334)
- [Google A2A Protocol](https://github.com/google/A2A)
- [Anthropic Model Context Protocol (MCP)](https://modelcontextprotocol.io/)
- [Agent Hypervisor Execution Control Specification v1.0](./AGENT-HYPERVISOR-EXECUTION-CONTROL-1.0.md)
- [Agent OS Policy Engine Specification v1.0](./AGENT-OS-POLICY-ENGINE-1.0.md)
- [AgentMesh Identity and Trust Specification v1.0](./AGENTMESH-IDENTITY-TRUST-1.0.md)
