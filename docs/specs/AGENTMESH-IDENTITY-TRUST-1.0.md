<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# AgentMesh Identity and Trust -- Version 1.0

> **Status:** Draft · **Date:** 2026-05-17 · **Authors:** Agent Governance Toolkit team
>
> This specification defines the identity model, trust scoring, credential
> lifecycle, key management, delegation chains, and trust handshake protocol
> for AgentMesh. All SDK implementations (Python, TypeScript, Rust, .NET, Go)
> MUST conform to this specification.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in
[RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119) and
[RFC 8174](https://datatracker.ietf.org/doc/html/rfc8174).

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [Agent DID Schema](#3-agent-did-schema)
4. [Agent Identity Model](#4-agent-identity-model)
5. [Identity Lifecycle](#5-identity-lifecycle)
6. [Cryptographic Primitives](#6-cryptographic-primitives)
7. [Human Sponsor Binding](#7-human-sponsor-binding)
8. [Credential Lifecycle](#8-credential-lifecycle)
9. [Trust Score Model](#9-trust-score-model)
10. [Trust Tiers](#10-trust-tiers)
11. [Reward Dimensions](#11-reward-dimensions)
12. [Trust Decay and Network Propagation](#12-trust-decay-and-network-propagation)
13. [Regime Detection](#13-regime-detection)
14. [Trust Handshake Protocol (IATP)](#14-trust-handshake-protocol-iatp)
15. [Delegation and Scope Chains](#15-delegation-and-scope-chains)
16. [Trust Ceiling Propagation](#16-trust-ceiling-propagation)
17. [Key Rotation](#17-key-rotation)
18. [Identity Revocation](#18-identity-revocation)
19. [SPIFFE/SVID Integration](#19-spiffesvid-integration)
20. [JWK/JWKS Serialization](#20-jwkjwks-serialization)
21. [DID Document Export](#21-did-document-export)
22. [Identity Registry](#22-identity-registry)
23. [Failure Semantics](#23-failure-semantics)
24. [Security Considerations](#24-security-considerations)
25. [Conformance Requirements](#25-conformance-requirements)
26. [Worked Examples](#26-worked-examples)
27. [References](#27-references)

---

## 1. Introduction

### 1.1 Purpose

This specification defines how AI agents are identified, authenticated,
and trust-scored within AgentMesh. Every agent operating in a governed
mesh MUST possess a cryptographically bound identity tied to a human
sponsor. Trust is not binary: it is a continuously computed score that
reflects behavioral history across five dimensions, decays over time
without positive signals, and propagates through interaction networks.

### 1.2 Scope

This specification covers:

- **Identity:** DID generation, Ed25519 keypair binding, sponsor
  accountability, status lifecycle.
- **Credentials:** Short-lived bearer tokens scoped to capabilities and
  resources, with rotation and revocation.
- **Trust scoring:** 0-1000 integer scale, five reward dimensions,
  tier classification, ceiling propagation.
- **Trust dynamics:** Temporal decay, network contagion, behavioral
  regime detection via KL divergence.
- **Authentication:** Challenge-response handshake protocol (IATP) with
  Ed25519 signatures, RFC 9334 freshness support.
- **Delegation:** Scope chains with monotonic capability narrowing, hash
  chain integrity, depth limits.
- **Key management:** Rotation with cryptographic proofs, history
  retention, SPIFFE/SVID integration, JWK export.

### 1.3 Relationship to Other Specifications

| Specification | Relationship |
| --- | --- |
| Agent OS Policy Engine 1.0 | Trust scores feed policy conditions; policy violations generate negative trust signals |
| Agent Hypervisor (planned) | Execution rings enforce trust-tier access boundaries |
| Agent SRE (planned) | SLO breaches generate trust events; circuit breakers use trust scores |

### 1.4 Design Principles

1. **Every agent has a human sponsor.** No orphan agents. Accountability
   traces to a verified person.
2. **Trust is earned, not declared.** Initial scores are defaults; only
   behavioral signals move them.
3. **Scope chains only narrow.** Delegation can never grant more
   capabilities than the parent holds.
4. **Fail closed.** Any identity or trust verification failure MUST
   result in denial, not fallback to a permissive default.
5. **Cryptographic binding.** Identity claims are backed by Ed25519
   signatures; no unsigned assertions are trusted.

---

## 2. Terminology

| Term | Definition |
| --- | --- |
| **AgentDID** | Decentralized Identifier in the format `did:mesh:<unique-id>`, uniquely identifying an agent within the mesh. |
| **AgentIdentity** | The full identity record binding a DID, Ed25519 keypair, human sponsor, capabilities, and status. |
| **Credential** | A short-lived bearer token scoped to a subset of an agent's capabilities and resources. |
| **Trust Score** | An integer from 0 to 1000 representing an agent's aggregate behavioral trustworthiness. |
| **Trust Tier** | A named classification derived from the trust score: verified_partner, trusted, standard, probationary, untrusted. |
| **Reward Dimension** | One of five behavioral categories that feed the aggregate trust score. |
| **Trust Decay** | Automatic reduction of trust scores when no positive signals are received. |
| **Trust Contagion** | Propagation of trust impact through the interaction graph when a connected agent fails. |
| **Regime Change** | A sudden behavioral shift detected via KL divergence between recent and historical action distributions. |
| **IATP** | Inter-Agent Trust Protocol: the Ed25519 challenge-response handshake used for mutual authentication. |
| **Scope Chain** | An ordered sequence of delegation links from a root sponsor to a leaf agent, each narrowing capabilities. |
| **Trust Ceiling** | Maximum trust score a delegated agent can reach, set by its parent at delegation time. |
| **Rotation Proof** | A cryptographic proof linking an old key to a new key during key rotation, signed by the old key. |
| **SVID** | SPIFFE Verifiable Identity Document, used for workload identity in mTLS contexts. |
| **OBO** | On-Behalf-Of: a delegation pattern where an agent acts with end-user context propagated through the chain. |

---

## 3. Agent DID Schema

### 3.1 Format

An Agent DID MUST conform to the following format:

```
did:mesh:<unique-id>
```

Where `<unique-id>` is a hex-encoded string. **[Pure Specification]**

### 3.2 Generation

Implementations MUST generate the `unique-id` using at least 128 bits
of cryptographically secure randomness. **[Pure Specification]**

**[Default Implementation]** The reference implementation uses
`secrets.token_hex(16)` producing 32 hex characters (128 bits).

### 3.3 Parsing

Implementations MUST accept any string matching the pattern
`did:mesh:<hex-string>`. A DID string that does not start with
`did:mesh:` MUST be rejected with an error. **[Pure Specification]**

### 3.4 Equality and Hashing

Two AgentDID values are equal if and only if their string
representations are byte-identical. Implementations MUST provide
deterministic hashing consistent with equality. **[Pure Specification]**

### 3.5 Migration Path

> **Note:** The canonical wire format for DIDs is planned to migrate to
> `did:agentmesh:<fingerprint>` in a future version. Implementations
> SHOULD be prepared to accept both `did:mesh:` and `did:agentmesh:`
> prefixes in DID parsing, but MUST generate `did:mesh:` format in
> version 1.0.

---

## 4. Agent Identity Model

### 4.1 Required Fields

An AgentIdentity record MUST contain the following fields:

| Field | Type | Description |
| --- | --- | --- |
| `did` | AgentDID | The agent's decentralized identifier |
| `name` | string | Human-readable name; MUST NOT be empty or whitespace-only |
| `public_key` | string | Base64-encoded Ed25519 public key |
| `verification_key_id` | string | Key identifier derived from the public key |
| `sponsor_email` | string | Email of the human sponsor; MUST contain `@` |
| `status` | enum | One of: `active`, `suspended`, `revoked` |

### 4.2 Optional Fields

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `description` | string | null | Free-text description |
| `organization` | string | null | Organization name |
| `organization_id` | string | null | Organization identifier |
| `capabilities` | list\[string\] | \[\] | Granted capabilities |
| `sponsor_verified` | bool | false | Whether sponsor identity is verified |
| `created_at` | datetime | now(UTC) | Creation timestamp |
| `updated_at` | datetime | now(UTC) | Last modification timestamp |
| `expires_at` | datetime | null | Identity expiration (null = no expiry) |
| `revocation_reason` | string | null | Reason for revocation or suspension |
| `parent_did` | string | null | Parent agent DID if this is a delegated identity |
| `delegation_depth` | int | 0 | Depth in the delegation chain (0 = root) |
| `max_initial_trust_score` | int | null | Trust ceiling for Sybil resistance |

### 4.3 Validation Rules

1. `name` MUST NOT be empty or whitespace-only. **[Pure Specification]**
2. `public_key` MUST NOT be empty or whitespace-only. **[Pure Specification]**
3. `sponsor_email` MUST NOT be empty and MUST contain `@`. **[Pure Specification]**
4. If `parent_did` is not null, it MUST match the `did:mesh:` prefix. **[Pure Specification]**
5. `delegation_depth` MUST be >= 0. **[Pure Specification]**

### 4.4 Verification Key ID

The `verification_key_id` MUST be derived from the SHA-256 hash of the
raw public key bytes. **[Pure Specification]**

**[Default Implementation]** Format: `key-<first-16-hex-chars-of-SHA256>`.

### 4.5 Factory Method

Implementations MUST provide a factory method that:

1. Generates an Ed25519 keypair.
2. Encodes the public key as base64 (standard, not URL-safe).
3. Generates a DID via `AgentDID.generate()`.
4. Derives the verification key ID from the public key hash.
5. Stores the private key in a non-serialized field.

The private key MUST NOT appear in any serialized representation of the
identity (JSON, dict export, logging). **[Pure Specification]**

---

## 5. Identity Lifecycle

### 5.1 Status Transitions

```
                 ┌──────────┐
   create() ────►│  active   │
                 └─────┬─────┘
                       │
              ┌────────┼────────┐
              ▼        ▼        │
        ┌──────────┐  ┌────────────┐
        │suspended │  │  revoked   │
        └─────┬────┘  └────────────┘
              │              ▲
              │ reactivate() │
              └──────────────┤
                             │
              (if security   │
               suspension:   │
               requires      │
               override)     │
```

### 5.2 Transition Rules

1. **active -> suspended:** The `suspend(reason)` method MUST set
   `status` to `"suspended"` and record the reason. **[Pure Specification]**

2. **active -> revoked:** The `revoke(reason)` method MUST set `status`
   to `"revoked"` and record the reason. **[Pure Specification]**

3. **suspended -> active:** The `reactivate()` method MUST restore
   `status` to `"active"`. If the `revocation_reason` contains the
   substring `"security"` (case-insensitive), reactivation MUST require
   an explicit `override_reason=True` flag; without it, reactivation
   MUST be rejected. **[Pure Specification]**

4. **revoked -> any:** A revoked identity MUST NOT be reactivated.
   Attempts MUST raise an error. **[Pure Specification]**

5. **suspended -> revoked:** A suspended identity MAY be revoked.
   **[Pure Specification]**

### 5.3 Activity Check

An identity is considered active if and only if:

1. `status` equals `"active"`, AND
2. `expires_at` is null OR `expires_at` is in the future.

**[Pure Specification]**

---

## 6. Cryptographic Primitives

### 6.1 Signature Algorithm

All agent identity signatures MUST use Ed25519
(Edwards-curve Digital Signature Algorithm, EdDSA on Curve25519).
**[Pure Specification]**

### 6.2 Signing

The `sign(data: bytes)` method MUST:

1. Verify that a private key is available; if not, raise an error.
2. Sign the data using the Ed25519 private key.
3. Return the signature as a base64-encoded string.

**[Pure Specification]**

### 6.3 Verification

The `verify_signature(data: bytes, signature: string)` method MUST:

1. Decode the base64-encoded public key to raw bytes.
2. Reconstruct the Ed25519 public key object.
3. Decode the base64-encoded signature.
4. Verify the signature against the data.
5. Return `true` on success, `false` on any failure.

Verification failures MUST NOT raise exceptions. They MUST be logged at
DEBUG level only. Logging verification failures at WARNING or higher
enables log-flooding attacks by any peer that can send messages.
**[Pure Specification]**

---

## 7. Human Sponsor Binding

### 7.1 Requirement

Every AgentIdentity MUST be bound to a human sponsor via
`sponsor_email`. **[Pure Specification]**

### 7.2 Rationale

AI agents cannot be held legally or organizationally accountable.
The sponsor binding ensures that every agent action traces to a
responsible person. This is the foundational accountability mechanism.

### 7.3 Verification

The `sponsor_verified` flag indicates whether the sponsor's identity
has been independently verified (e.g., via email confirmation, SSO,
or organizational directory). Implementations SHOULD verify sponsors
before granting trust scores above the `standard` tier.

### 7.4 Delegation Inheritance

When an agent delegates to a child, the child MUST inherit the parent's
`sponsor_email`. This ensures the accountability chain is unbroken
from root sponsor to leaf agent. **[Pure Specification]**

---

## 8. Credential Lifecycle

### 8.1 Credential Schema

A Credential MUST contain the following fields:

| Field | Type | Description |
| --- | --- | --- |
| `credential_id` | string | Unique identifier (format: `cred_<hex>`) |
| `agent_did` | string | DID of the owning agent |
| `token` | string | Bearer token (URL-safe base64, 32 bytes) |
| `token_hash` | string | SHA-256 hex digest of the token |
| `capabilities` | list\[string\] | Scoped capabilities |
| `resources` | list\[string\] | Scoped resource identifiers |
| `status` | enum | One of: `active`, `rotated`, `revoked`, `expired` |
| `issued_at` | datetime | Issuance timestamp (UTC) |
| `expires_at` | datetime | Expiration timestamp (UTC) |
| `ttl_seconds` | int | Time-to-live used at issuance |

### 8.2 Optional Credential Fields

| Field | Type | Default | Description |
| --- | --- | --- | --- |
| `issued_for` | string | null | Purpose or context |
| `revoked_at` | datetime | null | Revocation timestamp |
| `revocation_reason` | string | null | Reason for revocation |
| `previous_credential_id` | string | null | ID of predecessor (rotation chain) |
| `rotation_count` | int | 0 | Number of rotations from original |

### 8.3 Issuance

The `issue()` factory method MUST:

1. Generate a token using `secrets.token_urlsafe(32)`.
2. Compute `token_hash` as `SHA-256(token).hexdigest()`.
3. Generate a unique `credential_id`.
4. Set `expires_at` to `issued_at + ttl_seconds`.
5. Set `status` to `"active"`.

**[Default Implementation]** Default `ttl_seconds` is 900 (15 minutes).

### 8.4 Validation

A credential is valid if and only if:

1. `status` equals `"active"`, AND
2. The current UTC time is before `expires_at`.

**[Pure Specification]**

### 8.5 Token Verification

Token verification MUST use constant-time comparison of SHA-256 hashes
to prevent timing side-channel attacks. Implementations MUST use
`hmac.compare_digest` or equivalent. **[Pure Specification]**

The raw token MUST NOT be stored after issuance. Only the `token_hash`
is retained for verification. The token is returned to the caller at
issuance time and MUST be treated as a secret.

### 8.6 Expiring Soon Check

Implementations MUST provide a method to check whether a credential
expires within a configurable threshold. **[Pure Specification]**

**[Default Implementation]** The threshold defaults to 60 seconds
(`CREDENTIAL_ROTATION_THRESHOLD_SECONDS`).

### 8.7 Rotation

Credential rotation MUST:

1. Set the old credential's status to `"rotated"`.
2. Issue a new credential with the same `agent_did`, `capabilities`,
   `resources`, `ttl_seconds`, and `issued_for`.
3. Set `previous_credential_id` on the new credential to the old
   credential's `credential_id`.
4. Increment `rotation_count` by 1.

The old credential remains valid (status `"rotated"`, not `"revoked"`)
to allow a brief overlap period for zero-downtime rotation.
**[Pure Specification]**

### 8.8 Revocation

Credential revocation MUST:

1. Set `status` to `"revoked"`.
2. Record `revoked_at` as the current UTC time.
3. Record the `revocation_reason`.

A revoked credential MUST fail all subsequent validity checks.
**[Pure Specification]**

### 8.9 Capability Matching

Capability checks on credentials MUST support three matching modes:

1. **Exact match:** `capability == requested_capability`.
2. **Wildcard:** If any capability is `"*"`, all requests match.
3. **Prefix wildcard:** A capability `"prefix:*"` matches any
   `"prefix:<suffix>"` request.

**[Pure Specification]**

### 8.10 Resource Access

If a credential has an empty `resources` list, all resource access
requests MUST be allowed (open scope). If `resources` is non-empty,
only listed resources are accessible. **[Pure Specification]**

---

## 9. Trust Score Model

### 9.1 Scale

Trust scores operate on an integer scale from 0 to 1000 inclusive.
Implementations MUST clamp scores to this range on every update.
**[Pure Specification]**

### 9.2 Default Score

New agents MUST receive an initial trust score of 500
(`TRUST_SCORE_DEFAULT`). **[Pure Specification]**

### 9.3 Trust Score Record

A TrustScore record MUST contain:

| Field | Type | Description |
| --- | --- | --- |
| `agent_did` | string | The agent's DID (MUST match `did:mesh:` prefix) |
| `total_score` | int | Aggregate score (0-1000) |
| `tier` | string | Current trust tier |
| `dimensions` | map | Per-dimension breakdown |
| `calculated_at` | datetime | Last calculation timestamp |

### 9.4 Score Updates

When updating a trust score, implementations MUST:

1. Clamp the new score to `[0, 1000]`.
2. If a `trust_ceiling` is set, clamp to `min(score, ceiling)`.
3. Record `previous_score` and compute `score_change`.
4. Recalculate the trust tier (see Section 10).

**[Pure Specification]**

### 9.5 Trust Ceiling

A trust ceiling is an upper bound on an agent's trust score, typically
set at delegation time. **[Pure Specification]**

1. If `trust_ceiling` is not null, the effective score is
   `min(computed_score, trust_ceiling)`.
2. Trust ceilings MUST be respected on every score update, including
   initial score assignment.
3. Trust ceilings MAY be read from the environment variable
   `AGT_TRUST_CEILING` if not explicitly set. **[Default Implementation]**

### 9.6 Dual Trust Score Systems

AgentMesh maintains two trust score systems for different contexts:

| System | Scale | Location | Purpose |
| --- | --- | --- | --- |
| Integration TrustScore | 0.0 - 1.0 (float) | `trust_types.py` | Lightweight tracking for integration plugins |
| Reward TrustScore | 0 - 1000 (int) | `reward/scoring.py` | Full multi-dimensional scoring for mesh operations |

The integration TrustScore uses a `score >= 0.5` threshold for
`is_trusted`. The reward TrustScore uses tier thresholds defined in
Section 10. Implementations MUST NOT conflate these two systems.
**[Pure Specification]**

---

## 10. Trust Tiers

### 10.1 Tier Thresholds

Trust tiers MUST be computed from the total score using the following
thresholds:

| Tier | Minimum Score | Description |
| --- | --- | --- |
| `verified_partner` | 900 | Highest trust, verified partner agent |
| `trusted` | 700 | Trusted agent with good track record |
| `standard` | 500 | Default tier for new agents |
| `probationary` | 300 | Below-normal trust, under observation |
| `untrusted` | 0 | No trust, should be restricted or quarantined |

**[Pure Specification]**

### 10.2 Tier Computation

Tier assignment MUST use a descending threshold check: the first
threshold met (highest score first) determines the tier. An agent with
score exactly equal to a threshold MUST be assigned the corresponding
tier. **[Pure Specification]**

### 10.3 Action Thresholds

Implementations SHOULD define action thresholds for operational
decisions:

| Action | Threshold | Description |
| --- | --- | --- |
| Allow | >= 500 | Actions generally permitted |
| Warn | < 400 | Trigger warnings and enhanced monitoring |
| Revoke | < 300 | Trigger automatic credential revocation |

**[Default Implementation]**

### 10.4 Risk Score Thresholds

Complementary to trust tiers, risk thresholds provide an inverse scale:

| Risk Level | Threshold | Description |
| --- | --- | --- |
| Minimal | >= 800 | Very low risk |
| Alert | >= 600 | Elevated monitoring |
| High | >= 400 | Significant risk |
| Critical | < 200 | Immediate intervention required |

**[Default Implementation]**

---

## 11. Reward Dimensions

### 11.1 Dimensions

Trust scores are composed from five reward dimensions:

| Dimension | Weight | Description |
| --- | --- | --- |
| `policy_compliance` | 0.25 | Adherence to governance policies |
| `resource_efficiency` | 0.15 | Efficient use of compute, memory, API calls |
| `output_quality` | 0.20 | Quality of agent outputs and results |
| `security_posture` | 0.25 | Security behavior, credential handling, input validation |
| `collaboration_health` | 0.15 | Quality of interactions with other agents |

Dimension weights MUST sum to 1.0. **[Pure Specification]**

### 11.2 Reward Signals

A reward signal MUST contain:

| Field | Type | Constraint | Description |
| --- | --- | --- | --- |
| `dimension` | DimensionType | required | Which dimension this signal affects |
| `value` | float | [0.0, 1.0] | Signal value (0 = bad, 1 = good) |
| `source` | string | required | Origin of the signal |
| `weight` | float | >= 0.0, default 1.0 | Importance weight |

### 11.3 Dimension Score Update

When a signal is received for a dimension, the dimension score MUST
be updated using an exponential moving average:

```
new_score = current_score * (1 - alpha) + (signal_value * 100) * alpha
```

**[Default Implementation]** `alpha = 0.1` (smoothing factor).

A signal with `value >= 0.5` MUST increment `positive_signals`.
A signal with `value < 0.5` MUST increment `negative_signals`.
**[Pure Specification]**

### 11.4 Trend Detection

After each score update, the trend MUST be classified:

- `"improving"` if `score - previous_score > 5`
- `"degrading"` if `score - previous_score < -5`
- `"stable"` otherwise

**[Default Implementation]**

---

## 12. Trust Decay and Network Propagation

### 12.1 Temporal Decay

Trust scores MUST decay over time when no positive signals are
received. **[Pure Specification]**

**[Default Implementation]** Linear decay at `decay_rate` points per
hour since the last positive signal. Decay MUST NOT reduce a score
below 100.

```
effective_decay = min(decay_rate * hours_since_positive, max(0, score - 100))
```

Default `decay_rate` is 2.0 points per hour.

### 12.2 Network Propagation (Trust Contagion)

When a trust event occurs for agent A, the impact MUST propagate to
agents that have interacted with A. **[Pure Specification]**

**[Default Implementation]** Propagation parameters:

| Parameter | Default | Description |
| --- | --- | --- |
| `propagation_factor` | 0.3 | Fraction of impact transmitted to neighbors |
| `propagation_depth` | 2 | Maximum hops for propagation |
| Hop diminishing | `0.5^depth` | Impact halves at each hop |

The propagation algorithm MUST:

1. Apply direct impact: `score -= severity_weight * 100`.
2. For each neighbor within `propagation_depth` hops:
   a. Compute neighbor impact:
      `severity * interaction_weight * propagation_factor * 100 * (0.5^depth)`.
   b. Reduce the neighbor's score by the computed impact.
3. Track visited agents to prevent cycles.

### 12.3 Interaction Weight

Interaction weight between two agents is computed as:

```
weight = min(1.0, interaction_count / 100)
```

This saturates at 100 interactions to prevent unbounded influence.
**[Default Implementation]**

### 12.4 Positive Signals

Recording a positive signal MUST:

1. Update the last-positive-signal timestamp for the agent.
2. Add a configurable bonus to the agent's score (default: 5.0).

**[Default Implementation]**

---

## 13. Regime Detection

### 13.1 Purpose

Regime detection identifies sudden behavioral shifts that may indicate
compromise, misconfiguration, or adversarial takeover.

### 13.2 Algorithm

Implementations MUST provide behavioral regime detection using
KL divergence between recent and historical action distributions.
**[Pure Specification]**

**[Default Implementation]**

1. Collect all recorded actions for the agent.
2. Partition into "recent" (last `history_window_hours` hours, default 1)
   and "baseline" (last `baseline_days` days, default 30).
3. Require at least 10 total actions, 5 recent, and 5 baseline to proceed.
4. Compute the action frequency distribution for each partition.
5. Compute `KL(recent || baseline)` with Laplace smoothing (`eps = 1e-10`).
6. If `KL > regime_threshold` (default 0.5), emit a `RegimeChangeAlert`.

### 13.3 Regime Change Alert

A RegimeChangeAlert MUST contain:

| Field | Type | Description |
| --- | --- | --- |
| `agent_did` | string | Agent whose behavior shifted |
| `kl_divergence` | float | Computed KL divergence value |
| `threshold` | float | Threshold that was exceeded |
| `recent_distribution` | map | Action frequencies in the recent window |
| `historical_distribution` | map | Action frequencies in the baseline window |
| `detected_at` | float | Unix timestamp of detection |

### 13.4 Callbacks

Implementations MUST support registering callbacks for regime change
events and score change events. Callback failures MUST be caught and
silently ignored to prevent cascade failures. **[Pure Specification]**

---

## 14. Trust Handshake Protocol (IATP)

### 14.1 Overview

The Inter-Agent Trust Protocol (IATP) is a challenge-response
handshake that establishes mutual authentication and trust level
between two agents.

### 14.2 Challenge

A HandshakeChallenge MUST contain:

| Field | Type | Description |
| --- | --- | --- |
| `challenge_id` | string | Unique identifier (format: `challenge_<hex>`) |
| `nonce` | string | Hex-encoded random nonce (256 bits) |
| `freshness_nonce` | string or null | RFC 9334 freshness nonce for Evidence liveness |
| `timestamp` | datetime | Challenge creation time (UTC) |
| `expires_in_seconds` | int | TTL for the challenge (default: 30) |

A challenge is expired when `elapsed_seconds > expires_in_seconds`.
Expired challenges MUST be rejected. **[Pure Specification]**

### 14.3 Response

A HandshakeResponse MUST contain:

| Field | Type | Description |
| --- | --- | --- |
| `challenge_id` | string | Must match the challenge |
| `response_nonce` | string | Responder's own nonce |
| `agent_did` | string | Responder's DID |
| `capabilities` | list\[string\] | Attested capabilities |
| `trust_score` | int | Self-reported trust score (0-1000) |
| `signature` | string | Ed25519 signature over the payload |
| `public_key` | string | Responder's base64 public key |
| `freshness_nonce` | string or null | Echoed freshness nonce |
| `user_context` | dict or null | OBO user context if applicable |

### 14.4 Signature Payload

The signed payload MUST be constructed as:

```
{challenge_id}:{challenge_nonce}:{response_nonce}:{agent_did}
```

If a freshness nonce is present, it MUST be appended:

```
{challenge_id}:{challenge_nonce}:{response_nonce}:{agent_did}:{freshness_nonce}
```

The signature MUST be produced using the responder's Ed25519 private
key. **[Pure Specification]**

### 14.5 Verification

The initiator MUST verify:

1. The `challenge_id` matches a pending challenge.
2. The challenge has not expired.
3. The `response_nonce` matches the original challenge nonce.
4. The `agent_did` in the response matches the expected peer DID.
5. The Ed25519 signature is valid over the constructed payload.
6. If a registry is available: the peer is registered and active.
7. If a registry is available: the peer's registered public key matches.
8. If `freshness_nonce` was required: it is present and matches.
9. The peer's trust score meets the `required_trust_score` threshold.
10. The peer has all `required_capabilities` (if specified).

Any verification failure MUST result in a `HandshakeResult` with
`verified = false` and a `rejection_reason`. **[Pure Specification]**

### 14.6 Result

A HandshakeResult MUST contain:

| Field | Type | Description |
| --- | --- | --- |
| `verified` | bool | Whether the handshake succeeded |
| `peer_did` | string | Peer's DID |
| `peer_name` | string or null | Peer's human-readable name |
| `trust_score` | int | Verified trust score (0-1000) |
| `trust_level` | string | One of: verified_partner, trusted, standard, untrusted |
| `capabilities` | list\[string\] | Verified capabilities |
| `user_context` | UserContext or null | OBO context if present |
| `handshake_started` | datetime | Start timestamp |
| `handshake_completed` | datetime or null | Completion timestamp |
| `latency_ms` | int or null | Round-trip latency |
| `rejection_reason` | string or null | Reason for failure |

### 14.7 Trust Level Assignment in Results

The trust level in the HandshakeResult MUST be assigned as:

| Score Range | Trust Level |
| --- | --- |
| >= 900 | `verified_partner` |
| >= 700 | `trusted` |
| >= 400 | `standard` |
| < 400 | `untrusted` |

Note: the `standard` threshold in HandshakeResult (400) differs from
the tier threshold (500) in TrustScore. This is intentional: handshake
results use a lower bar because the peer has already passed
cryptographic verification. **[Pure Specification]**

### 14.8 Caching

Implementations SHOULD cache successful handshake results. Cached
results MUST be invalidated after a configurable TTL. **[Pure Specification]**

**[Default Implementation]** Cache TTL is 900 seconds (15 minutes).

When `require_freshness` is true, the cache MUST be bypassed entirely:
every call produces a fresh verification. **[Pure Specification]**

### 14.9 Timeout

Implementations MUST enforce a timeout on the handshake. If the peer
does not respond within the timeout, the handshake MUST fail with a
`HandshakeTimeoutError`. **[Pure Specification]**

**[Default Implementation]** Default timeout is 30 seconds.
Performance target: handshakes SHOULD complete within 200ms
(`MAX_HANDSHAKE_MS`).

### 14.10 DoS Protection

Implementations MUST limit the number of pending (unanswered)
challenges to prevent memory exhaustion. When the limit is reached,
new challenges MUST be rejected. Expired challenges MUST be purged
before checking the limit. **[Pure Specification]**

**[Default Implementation]** Maximum pending challenges: 1000.

### 14.11 Concurrency

Challenge creation, lookup, and cleanup MUST be serialized to prevent
race conditions where concurrent handshakes bypass the pending
challenge limit. **[Pure Specification]**

Peer cache reads and writes MUST be serialized to prevent TTL-delete
races. **[Pure Specification]**

---

## 15. Delegation and Scope Chains

### 15.1 Delegation from Identity

An AgentIdentity MUST support delegating to a child agent via a
`delegate()` method. **[Pure Specification]**

Delegation MUST enforce:

1. **Depth limit:** `delegation_depth` MUST NOT exceed
   `MAX_DELEGATION_DEPTH`. **[Default Implementation]**
   Default: 10.
2. **No wildcard propagation:** Delegating the `"*"` capability MUST be
   rejected. Capabilities MUST be explicitly listed.
3. **Subset enforcement:** Every delegated capability MUST exist in the
   parent's capability set.
4. **Sponsor inheritance:** The child MUST inherit `sponsor_email` from
   the parent.
5. **Depth increment:** The child's `delegation_depth` MUST equal
   `parent.delegation_depth + 1`.

### 15.2 Scope Chain Model

A ScopeChain represents the full delegation path from a root sponsor
to a leaf agent. It MUST contain:

| Field | Type | Description |
| --- | --- | --- |
| `chain_id` | string | Unique chain identifier |
| `max_depth` | int | Maximum allowed depth (default: 5) |
| `root_sponsor_email` | string | Human sponsor at the root |
| `root_capabilities` | list\[string\] | Capabilities granted by sponsor |
| `links` | list\[DelegationLink\] | Ordered delegation links |
| `leaf_did` | string | DID of the terminal agent |
| `leaf_capabilities` | list\[string\] | Effective capabilities at the leaf |
| `chain_hash` | string | SHA-256 hash of the entire chain |

### 15.3 Delegation Link

Each link in the chain MUST contain:

| Field | Type | Description |
| --- | --- | --- |
| `link_id` | string | Unique link identifier |
| `depth` | int | Position in chain (0-indexed) |
| `parent_did` | string | Delegating agent's DID |
| `child_did` | string | Receiving agent's DID |
| `parent_capabilities` | list\[string\] | Parent's capabilities at delegation time |
| `delegated_capabilities` | list\[string\] | Capabilities granted to child |
| `parent_signature` | string | Parent's Ed25519 signature |
| `link_hash` | string | SHA-256 hash of this link |
| `previous_link_hash` | string or null | Hash of the preceding link |

### 15.4 Chain Invariants

The following invariants MUST hold for a valid scope chain:

1. **Monotonic narrowing:** At each link, `delegated_capabilities` MUST
   be a subset of `parent_capabilities`. Subset includes exact match
   and prefix-wildcard narrowing (e.g., `read:data` is a subset of
   `read:*`). **[Pure Specification]**

2. **Hash chain integrity:** Each link's `previous_link_hash` MUST
   equal the preceding link's `link_hash`. The first link's
   `previous_link_hash` MUST be null. **[Pure Specification]**

3. **Depth consistency:** Link at index `i` MUST have `depth == i`.
   **[Pure Specification]**

4. **Connectivity:** Each link's `parent_did` MUST equal the previous
   link's `child_did`. **[Pure Specification]**

5. **Depth limit:** `len(links)` MUST NOT exceed `max_depth`.
   Attempts to exceed MUST raise `DelegationDepthError`.
   **[Pure Specification]**

### 15.5 Chain Verification

The `verify()` method MUST check all invariants in Section 15.4.
Signature checks are compatibility-mode and best-effort: if the parent
identity is not available in `known_identities`, the signature check
MUST be skipped (not failed). **[Pure Specification]**

### 15.6 OBO (On-Behalf-Of) Context

A `UserContext` MAY be attached to delegation links to propagate
end-user identity through the chain. **[Pure Specification]**

UserContext MUST contain:

| Field | Type | Description |
| --- | --- | --- |
| `user_id` | string | Unique user identifier |
| `user_email` | string or null | User email for audit |
| `roles` | list\[string\] | User roles for RBAC |
| `permissions` | list\[string\] | Fine-grained permissions |
| `issued_at` | datetime | Context creation time |
| `expires_at` | datetime or null | Context expiration |

UserContext is valid if `expires_at` is null or in the future.
Permission check MUST support wildcard `"*"`. **[Pure Specification]**

### 15.7 Capability Tracing

Implementations MUST provide a method to trace how a specific
capability was granted through the chain, producing an audit trail from
root sponsor to leaf agent. **[Pure Specification]**

---

## 16. Trust Ceiling Propagation

### 16.1 Invariant

When a parent delegates to a child and sets `max_initial_trust_score`,
the child's effective trust score MUST NOT exceed
`min(parent_ceiling, requested_ceiling)`. This provides monotonic
narrowing of trust through the delegation chain.
**[Pure Specification]**

### 16.2 Sybil Resistance

Trust ceilings prevent trust washing: an attacker cannot spawn
sub-agents to obtain higher trust scores than the parent. The child's
initial trust score is capped by the parent's ceiling.
**[Pure Specification]**

### 16.3 Enforcement

Trust ceilings MUST be enforced:

1. At identity creation time (initial score clamped to ceiling).
2. On every trust score update.
3. Across delegation chains (child ceiling <= parent ceiling).

**[Pure Specification]**

---

## 17. Key Rotation

### 17.1 Purpose

Long-lived agents MUST support key rotation to limit the impact of key
compromise. Key rotation replaces the Ed25519 keypair while preserving
the agent's DID. **[Pure Specification]**

### 17.2 Rotation Process

The rotation MUST:

1. Generate a new Ed25519 keypair.
2. Create a rotation proof: the old private key signs a message
   containing both the old and new public keys.
3. Store the old public key, old verification key ID, rotation timestamp,
   and rotation proof in the key history.
4. Update the identity's `public_key`, `verification_key_id`, and
   `_private_key` to the new values.
5. Preserve the agent's DID unchanged.

**[Pure Specification]**

### 17.3 Rotation Proof Format

The rotation proof MUST contain:

| Field | Type | Description |
| --- | --- | --- |
| `old_public_key` | string | Base64 old public key |
| `new_public_key` | string | Base64 new public key |
| `message` | string | `"rotate:{old_key_b64}:{new_key_b64}"` |
| `signature` | string | Base64 Ed25519 signature of the message by the old key |
| `timestamp` | string | ISO 8601 timestamp |

### 17.4 Rotation Proof Verification

To verify a rotation proof:

1. Confirm `old_public_key` and `new_public_key` match the proof fields.
2. Reconstruct the Ed25519 public key from `old_public_key`.
3. Verify the `signature` over `message` using the old public key.
4. Return `true` if valid, `false` on any failure.

**[Pure Specification]**

### 17.5 Key History

Implementations MUST retain a configurable number of previous keys
for backward verification of signatures made with old keys.
**[Pure Specification]**

**[Default Implementation]** Maximum history: 5 entries.

### 17.6 TTL-Based Auto-Rotation

Implementations MUST provide a method to check whether rotation is
needed based on elapsed time since last rotation. **[Pure Specification]**

**[Default Implementation]** Rotation TTL: 86400 seconds (24 hours).

### 17.7 Prerequisites

Key rotation MUST require access to the current private key. Attempts
to manage rotation without a private key MUST be rejected.
**[Pure Specification]**

---

## 18. Identity Revocation

### 18.1 Revocation Entry

A revocation entry MUST contain:

| Field | Type | Description |
| --- | --- | --- |
| `agent_did` | string | DID of the revoked agent |
| `revoked_at` | datetime | Revocation timestamp (UTC) |
| `reason` | string | Human-readable reason |
| `revoked_by` | string or null | DID of the revoking entity |
| `expires_at` | datetime or null | Expiry for temporary revocations |

### 18.2 Permanent vs Temporary Revocation

If `expires_at` is null, the revocation is permanent. If `expires_at`
is set and the current time exceeds it, the revocation is automatically
lifted and the entry is removed. **[Pure Specification]**

### 18.3 Revocation Check

The `is_revoked(agent_did)` method MUST:

1. If no entry exists for the DID, return `false`.
2. If an entry exists with `expires_at` in the past, delete the entry
   and return `false`.
3. Otherwise, return `true`.

**[Pure Specification]**

### 18.4 Unrevocation

An explicit `unrevoke(agent_did)` method MUST be provided to manually
remove a revocation entry. It MUST return `true` if the entry existed,
`false` otherwise. **[Pure Specification]**

### 18.5 Persistence

Implementations MUST support both in-memory and file-backed storage
for the revocation list. File-backed storage MUST auto-persist on
every mutation. **[Pure Specification]**

### 18.6 Cleanup

Implementations MUST provide a method to remove all expired temporary
revocations. **[Pure Specification]**

---

## 19. SPIFFE/SVID Integration

### 19.1 Purpose

SPIFFE (Secure Production Identity Framework for Everyone) integration
enables AgentMesh identities to participate in standard workload
identity ecosystems. This provides mutual TLS (mTLS) for agent-to-agent
transport.

### 19.2 SPIFFE ID Format

SPIFFE IDs MUST follow the format:

```
spiffe://{trust_domain}/agentmesh[/{organization}]/{agent_name}
```

**[Default Implementation]** Default trust domain: `agentmesh.local`.

### 19.3 SVID Model

An SVID (SPIFFE Verifiable Identity Document) MUST contain:

| Field | Type | Description |
| --- | --- | --- |
| `spiffe_id` | string | Full SPIFFE ID |
| `svid_type` | string | `"x509"` or `"jwt"` |
| `trust_domain` | string | SPIFFE trust domain |
| `issued_at` | datetime | Issuance timestamp |
| `expires_at` | datetime | Expiration timestamp |
| `agent_did` | string | Bound AgentMesh DID |

### 19.4 SVID Validity

An SVID is valid when `issued_at <= now < expires_at`.
**[Pure Specification]**

### 19.5 SVID Rotation

SVID rotation SHOULD be triggered when the time remaining until expiry
falls below a configurable threshold. **[Default Implementation]**
Default threshold: 10 minutes. Default SVID TTL: 1 hour.

### 19.6 SVID Validation

SVID validation MUST check:

1. Temporal validity (`is_valid()`).
2. Trust domain matches the registry's trust domain.
3. The agent is registered in the SPIFFE registry.

**[Pure Specification]**

---

## 20. JWK/JWKS Serialization

### 20.1 JWK Format

Agent identities MUST support export as JWK
([RFC 7517](https://datatracker.ietf.org/doc/html/rfc7517)) with the
following parameters:

| Parameter | Value | Description |
| --- | --- | --- |
| `kty` | `"OKP"` | Key type: Octet Key Pair |
| `crv` | `"Ed25519"` | Curve: Ed25519 |
| `x` | base64url | Public key (no padding) |
| `kid` | string | DID string as key identifier |
| `use` | `"sig"` | Key use: signature |

### 20.2 Private Key Export

The private key parameter `d` MUST only be included when explicitly
requested via `include_private=True`. Implementations MUST NOT include
private keys by default. **[Pure Specification]**

### 20.3 Base64url Encoding

JWK key material MUST use base64url encoding without padding, per
[RFC 7515](https://datatracker.ietf.org/doc/html/rfc7515).
**[Pure Specification]**

### 20.4 JWK Import

When importing from JWK:

1. `kty` MUST be `"OKP"`. Other values MUST be rejected.
2. `crv` MUST be `"Ed25519"`. Other values MUST be rejected.
3. `x` (public key) MUST be present and valid base64url.
4. If `kid` starts with `did:mesh:`, it MUST be used as the identity DID.
5. If `kid` is absent or does not match, a new DID MUST be generated.
6. If `d` (private key) is present, it MUST be restored as the
   identity's private key.

**[Pure Specification]**

### 20.5 JWKS (JWK Set)

The JWKS format wraps one or more JWKs in a `{"keys": [...]}` object.
Import from JWKS MUST support filtering by `kid`. If no `kid` is
specified, the first key MUST be used. An empty `keys` array MUST be
rejected. **[Pure Specification]**

---

## 21. DID Document Export

### 21.1 W3C DID Document

Implementations MUST support exporting an AgentIdentity as a
W3C DID Document with the following structure:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:mesh:<unique-id>",
  "verificationMethod": [{
    "id": "did:mesh:<unique-id>#<key-id>",
    "type": "Ed25519VerificationKey2020",
    "controller": "did:mesh:<unique-id>",
    "publicKeyBase64": "<base64-public-key>"
  }],
  "authentication": ["did:mesh:<unique-id>#<key-id>"],
  "service": [{
    "id": "did:mesh:<unique-id>#agentmesh",
    "type": "AgentMeshIdentity",
    "serviceEndpoint": "https://mesh.agentmesh.dev/v1"
  }]
}
```

**[Pure Specification]**

---

## 22. Identity Registry

### 22.1 Purpose

The Identity Registry provides centralized lookup and management of
agent identities within a mesh.

### 22.2 Operations

Implementations MUST support the following operations:

| Operation | Description |
| --- | --- |
| `register(identity)` | Add an identity to the registry |
| `get(did)` | Retrieve an identity by DID string |
| `get_by_sponsor(email)` | List identities by sponsor email |
| `list_active()` | List all active identities |
| `unregister(did)` | Remove an identity |
| `revoke(did, reason)` | Revoke an identity |

### 22.3 Registration Rules

1. An identity with a duplicate DID MUST be rejected.
   **[Pure Specification]**
2. The registry MAY require attestation before registration
   (configurable via `require_attestation`).
3. Registration MUST index by both DID and sponsor email.

### 22.4 Delegation Chain Verification

The registry MUST support verifying delegation chains by walking
`parent_did` links, checking at each level:

1. The parent exists in the registry.
2. The parent is active.
3. The child's capabilities are a subset of the parent's.
4. Delegation depth is consistent (`child.depth == parent.depth + 1`).
5. No circular references exist.

**[Pure Specification]**

---

## 23. Failure Semantics

### 23.1 Fail Closed

All identity and trust operations MUST fail closed:

| Operation | Failure Behavior |
| --- | --- |
| DID parsing | Reject with error |
| Identity validation | Reject with error |
| Signature verification | Return `false` (never raise) |
| Handshake | Return `HandshakeResult(verified=false)` |
| Credential validation | Return `false` |
| Delegation | Raise error |
| Revocation check | Return `false` (not revoked) on missing entry |
| Trust score lookup | Return default score (500) |

### 23.2 Error Types

Implementations MUST define the following error types:

| Error | Context |
| --- | --- |
| `IdentityError` | DID parsing, key operations, JWK errors |
| `HandshakeError` | Handshake protocol errors |
| `HandshakeTimeoutError` | Handshake timeout (extends HandshakeError) |
| `DelegationError` | Scope chain and delegation errors |
| `DelegationDepthError` | Depth limit exceeded (extends DelegationError) |
| `TrustError` | Trust score computation errors |

---

## 24. Security Considerations

### 24.1 Private Key Protection

Private keys MUST NOT appear in:

- Serialized identity records (JSON, dict, model dump).
- Log output at any level.
- API responses.
- Error messages.

### 24.2 Timing Side Channels

Token verification MUST use constant-time comparison (e.g.,
`hmac.compare_digest`). Implementations MUST NOT use standard
string equality for token comparison.

### 24.3 Log Flooding

Signature verification failures MUST be logged at DEBUG level only.
WARNING-level logging of verification failures enables log-flooding
attacks by any peer that can submit messages.

### 24.4 Nonce Entropy

Challenge nonces MUST use at least 256 bits of cryptographically
secure randomness. Response nonces MUST use at least 128 bits.
**[Pure Specification]**

### 24.5 DoS Resistance

- Pending challenge count MUST be bounded.
- Expired challenges MUST be purged before admitting new ones.
- Challenge creation, lookup, and cleanup MUST be atomic to prevent
  race conditions that bypass limits.

### 24.6 Sybil Resistance

- Trust ceilings on delegated agents prevent trust washing.
- Wildcard capability `"*"` MUST NOT be delegated.
- Maximum delegation depth limits chain length.
- Initial trust scores for delegated agents are capped by parent
  ceilings.

### 24.7 Replay Protection

Challenge nonces are single-use: each challenge MUST be removed from
the pending set after use (success or failure). The combination of
`challenge_id`, `nonce`, and `response_nonce` ensures uniqueness.

### 24.8 Credential Security

- Tokens are generated with `secrets.token_urlsafe(32)` (256 bits).
- Only the SHA-256 hash is stored; the raw token is returned once.
- Credentials have short TTLs (default 15 minutes).
- Rotation provides zero-downtime credential refresh.

---

## 25. Conformance Requirements

### 25.1 MUST Requirements

An implementation is conformant if it satisfies all MUST and MUST NOT
requirements in this specification. The following is a summary of
critical conformance points:

1. DID format MUST be `did:mesh:<unique-id>` with >= 128 bits of
   randomness.
2. Ed25519 MUST be the signature algorithm.
3. Private keys MUST NOT appear in serialized output.
4. Every identity MUST have a human sponsor.
5. Trust scores MUST be clamped to [0, 1000].
6. Trust ceilings MUST be enforced on every score update.
7. Scope chain capabilities MUST only narrow, never widen.
8. Wildcard `"*"` MUST NOT be delegated.
9. Handshake challenges MUST expire and be cleaned up.
10. Token verification MUST use constant-time comparison.
11. Signature verification failures MUST NOT raise exceptions.
12. Revoked identities MUST NOT be reactivated.
13. Key rotation MUST produce verifiable proofs.
14. JWK export MUST NOT include private keys by default.

### 25.2 Test Coverage

Conformance tests MUST cover:

- DID generation and parsing.
- Identity creation, validation, and lifecycle transitions.
- Credential issuance, validation, rotation, and revocation.
- Trust score computation, tier assignment, and ceiling enforcement.
- Trust decay and network propagation.
- Handshake challenge-response flow.
- Delegation chain construction and verification.
- Key rotation with proof verification.
- JWK round-trip (export/import).
- Revocation list operations.

---

## 26. Worked Examples

### 26.1 Agent Identity Creation

```
Given: name="data-analyst", sponsor="alice@contoso.com"
When:  AgentIdentity.create(name, sponsor) is called
Then:
  - did matches /did:mesh:[0-9a-f]{32}/
  - public_key is non-empty base64
  - verification_key_id matches /key-[0-9a-f]{16}/
  - sponsor_email == "alice@contoso.com"
  - status == "active"
  - delegation_depth == 0
  - Private key is available for signing
  - Private key does NOT appear in model_dump()
```

### 26.2 Credential Rotation

```
Given: An active credential C1 for did:mesh:abc with capabilities=["read:data"]
When:  C1.rotate() is called
Then:
  - C1.status == "rotated" (not "revoked" -- zero-downtime overlap)
  - New credential C2 is returned
  - C2.agent_did == C1.agent_did
  - C2.capabilities == C1.capabilities
  - C2.previous_credential_id == C1.credential_id
  - C2.rotation_count == C1.rotation_count + 1
  - C2.status == "active"
```

### 26.3 Trust Score with Ceiling

```
Given: Agent with trust_ceiling = 600, current score = 500
When:  update(new_score=800, dimensions={...}) is called
Then:
  - total_score == 600 (clamped to ceiling)
  - tier == "standard" (600 >= 500 but < 700)
```

### 26.4 Delegation Chain Narrowing

```
Given: Parent agent with capabilities=["read:*", "write:data"]
When:  Parent delegates ["read:data"] to child
Then:
  - Child receives capabilities=["read:data"]
  - "read:data" is a valid narrowing of "read:*"
  - Child cannot access "write:data"
  - Child cannot delegate "write:data" further
```

### 26.5 Key Rotation Proof

```
Given: Agent with keypair (old_priv, old_pub)
When:  KeyRotationManager.rotate() is called
Then:
  - New keypair (new_priv, new_pub) is generated
  - Rotation proof: old_priv signs "rotate:{old_pub_b64}:{new_pub_b64}"
  - verify_rotation(old_pub, new_pub, proof) returns true
  - Agent DID is unchanged
  - Old key is in key_history
```

### 26.6 Handshake with Freshness

```
Given: Two agents A and B with registered identities
When:  A initiates handshake with B, require_freshness=true
Then:
  - Challenge includes freshness_nonce
  - B signs payload including freshness_nonce
  - A verifies freshness_nonce matches
  - Result is NOT cached (freshness bypasses cache)
```

---

## 27. References

- [RFC 2119: Key words for use in RFCs](https://datatracker.ietf.org/doc/html/rfc2119)
- [RFC 8174: Ambiguity of Uppercase vs Lowercase in RFC 2119](https://datatracker.ietf.org/doc/html/rfc8174)
- [RFC 7517: JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)
- [RFC 7515: JSON Web Signature (JWS)](https://datatracker.ietf.org/doc/html/rfc7515)
- [RFC 9334: Remote ATtestation procedureS (RATS)](https://datatracker.ietf.org/doc/html/rfc9334)
- [RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)](https://datatracker.ietf.org/doc/html/rfc8032)
- [W3C DID Core 1.0](https://www.w3.org/TR/did-core/)
- [SPIFFE: Secure Production Identity Framework for Everyone](https://spiffe.io/)
- [Agent OS Policy Engine Specification v1.0](./AGENT-OS-POLICY-ENGINE-1.0.md)
