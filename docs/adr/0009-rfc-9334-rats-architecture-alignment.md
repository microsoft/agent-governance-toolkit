# ADR 0009: RFC 9334 (RATS) Architecture Alignment

- Status: accepted
- Date: 2025-07-17
- Deciders: @imran-siddique

## Context

IETF RFC 9334 defines the **Remote ATtestation procedureS (RATS) Architecture**,
a standard framework for verifying the trustworthiness of remote peers through
Evidence, Attestation Results, and Endorsements. The Agent Governance Toolkit
already implements many RATS concepts (Attester, Verifier, Evidence, Attestation
Results) through its IATP trust handshake, but gaps remain in three areas:

1. **Endorser role**: RFC 9334 section 3.3 defines an Endorser that vouches for
   an Attester's integrity/capabilities, distinct from the Attester itself. AGT
   had no mechanism for third-party endorsements.

2. **Freshness nonce**: RFC 9334 section 10 describes freshness mechanisms
   (nonce, timestamp, epoch) to prove Evidence liveness. AGT's challenge nonce
   binds the response to a specific challenge but does not provide explicit
   Evidence freshness proof as defined in the RFC.

3. **Explicit RATS role mapping**: No documentation mapped AGT components to
   RATS roles, making it harder for standards-aware adopters to evaluate
   alignment.

## Decision

We add three backward-compatible features to align AGT with RFC 9334:

### 1. EndorsementRegistry (RFC 9334 Endorser role)

A new `agentmesh.trust.endorsement` module provides:

- `EndorsementType` enum: COMPLIANCE, CAPABILITY, INTEGRITY, IDENTITY,
  REFERENCE_VALUE (maps to RATS Reference Values and Endorsements)
- `Endorsement` dataclass with endorser_did, target_did, type, claims, expiry,
  metadata, and serialization
- `EndorsementRegistry` for CRUD operations, type filtering, expiry validation,
  and revocation

Design constraints (from rubber-duck critique):

- Endorsements are **unsigned metadata only** for now: no `signature` field is
  exposed until cryptographic verification of endorsers is implemented
- Endorsements are resolved **on demand** from the registry, not stored on
  PeerInfo, to avoid HMAC integrity gaps in TrustBridge._sign_peer()
- The registry lives in its own file (`trust/endorsement.py`) since it is
  stateful, not alongside the lightweight types in `trust_types.py`

### 2. Freshness nonce in IATP handshake

- `HandshakeChallenge` gains an optional `freshness_nonce` field
- `HandshakeChallenge.generate(require_freshness=True)` produces a 16-byte hex
  freshness nonce alongside the existing challenge nonce
- `HandshakeResponse` echoes `freshness_nonce` and includes it in the Ed25519
  signed payload
- `_verify_response()` rejects mismatched freshness nonces before signature
  verification
- `initiate(require_freshness=True)` bypasses the handshake result cache,
  ensuring every call produces a fresh Evidence verification
- `create_challenge(require_freshness=True)` passes through to generate()

The existing `nonce` (challenge-binding token) and the new `freshness_nonce`
(verifier-supplied Evidence liveness proof) are semantically distinct per
RFC 9334 section 10.

### 3. This ADR

Documents the mapping between AGT concepts and RATS roles/artifacts for
standards-aware adopters.

## RATS Role Mapping

| RATS Role | AGT Component | Notes |
|-----------|--------------|-------|
| Attester | AgentIdentity + TrustHandshake.respond() | Produces Evidence (signed challenge response) |
| Verifier | TrustHandshake._verify_response() | Appraises Evidence against Appraisal Policy |
| Relying Party | TrustBridge.verify_peer() callers | Consumes Attestation Results (HandshakeResult) |
| Endorser | EndorsementRegistry | Third-party vouching for Attester properties |
| Reference Value Provider | GovernanceEngine policy definitions | Supplies reference values for appraisal |

## RATS Artifact Mapping

| RATS Artifact | AGT Equivalent |
|---------------|---------------|
| Evidence | HandshakeResponse (Ed25519 signed payload) |
| Attestation Results | HandshakeResult |
| Endorsements | Endorsement records in EndorsementRegistry |
| Reference Values | Policy rules, capability requirements, trust thresholds |
| Appraisal Policy | required_trust_score, required_capabilities, registry checks |

## Topological Pattern

AGT primarily follows the **Background-Check Model** (RFC 9334 section 5.2):
the Relying Party (caller of verify_peer) delegates Evidence appraisal to the
Verifier (_verify_response), which returns Attestation Results. The handshake
result cache adds a Passport Model optimization where cached results serve as
pre-computed attestation results.

## Explicit Gaps (Not Addressed)

These areas are documented for future work:

- **Cryptographic endorsement verification**: Endorsements are unsigned metadata.
  Future work could add endorser signature verification using the same Ed25519
  infrastructure.
- **Epoch-based freshness**: Only nonce-based freshness is implemented.
  Timestamp-based and epoch-based freshness models are not yet supported.
- **Formal Conceptual Messages**: RFC 9334 section 8 defines formal message
  formats. AGT uses Pydantic models that carry equivalent information but do not
  use the exact wire format.
- **Multi-verifier topologies**: The current architecture assumes a single
  verifier co-located with the relying party.

## Consequences

- **Backward compatible**: All changes are additive. Existing code that does not
  use `require_freshness` or `endorsement_registry` continues to work unchanged.
- **Standards alignment**: Adopters evaluating AGT against RATS can point to this
  ADR and the role mapping table.
- **Foundation for future work**: The EndorsementRegistry provides the extension
  point for cryptographic endorser verification when needed.
- **No performance impact**: Freshness nonce adds one extra field to
  challenge/response. Endorsement lookup is O(n) in endorsements per target,
  which is acceptable for typical deployment sizes.
