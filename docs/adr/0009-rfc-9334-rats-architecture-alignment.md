# ADR 0009: RFC 9334 RATS Architecture Alignment

- Status: accepted
- Date: 2026-04-26

## Context

RFC 9334 (Remote ATtestation procedureS Architecture) defines a standard architecture for remote attestation: how one entity (Attester) produces Evidence about its state, how a Verifier appraises that Evidence against Reference Values, and how a Relying Party consumes the resulting Attestation Results to make trust decisions. The specification formalizes five roles (Attester, Verifier, Relying Party, Endorser, Reference Value Provider), four artifact types (Evidence, Attestation Results, Endorsements, Reference Values), two topological patterns (Passport Model, Background-Check Model), and three freshness mechanisms (nonce, timestamp, epoch ID).

The Agent Governance Toolkit already implements most of these concepts across its Python SDK (`agent-compliance`), TypeScript SDK (`agent-governance-typescript`), and AgentMesh runtime (`agent-mesh`), but the mapping is implicit. Components were built to solve governance problems, not to conform to RATS terminology. This ADR formalizes the alignment, identifies gaps, and documents the changes made to close the highest-priority gaps.

## Decision

### Role Mapping

AGT components map to RFC 9334 roles as follows:

| RFC 9334 Role | AGT Component(s) | Notes |
|---|---|---|
| **Attester** | Agent runtime, `RuntimeEvidence` producer, physical/cognitive attestation examples | Agents produce Evidence about their state (trust scores, integrity reports, compliance data) |
| **Verifier** | `GovernanceVerifier`, `IntegrityVerifier`, Hypervisor `verification_adapter`, Nexus Arbiter | Appraiser logic that evaluates Evidence against policies and produces Attestation Results |
| **Relying Party** | `governance-attestation` GitHub Action, Orchestrator, callers of `TrustBridge.verify_peer()` | Entities that consume `HandshakeResult` / `GovernanceAttestation` to make authorization decisions |
| **Endorser** | `EndorsementRegistry` (new), Nexus manifest signatures, SBOM/Sigstore provenance | Entities that vouch for agent capabilities, integrity, or compliance |
| **Reference Value Provider** | Integrity manifests (expected hashes), policy files (deny-by-default baselines) | Sources of known-good values used during Evidence appraisal |
| **Verifier Owner** | Policy file authors, CI pipeline configurators | Not explicitly modeled as a distinct role |
| **Relying Party Owner** | Not modeled | RFC 9334 separates policy owners from RP instances; AGT conflates these |

### Artifact Mapping

| RFC 9334 Artifact | AGT Implementation |
|---|---|
| **Evidence** | `RuntimeEvidence`, `IntegrityReport` inputs, heartbeat payloads (DID + timestamp + delegation chain hash), sensor data in physical attestation examples |
| **Attestation Results** | `GovernanceAttestation`, `IntegrityReport`, `DriftCheckResult`, `HandshakeResult`, trust scores (0-1000) |
| **Endorsements** | `Endorsement` dataclass (new), Nexus `attestation_signature`, SBOM signatures, compliance `nexus_signature` |
| **Reference Values** | Integrity manifest hashes, critical function bytecode fingerprints, policy baselines |
| **Appraisal Policy** | Deny-by-default policy evaluation, PR governance checklist, inline rule sets |

### Topological Patterns

**Background-Check Model** (primary pattern in AGT):
The Relying Party forwards Evidence to the Verifier for appraisal. This is the dominant pattern in `GovernanceVerifier.verify_evidence()`, `IntegrityVerifier.verify()`, and `TrustHandshake.initiate()` where the initiator sends a challenge, receives Evidence (the signed response), and verifies it locally.

**Passport Model** (also supported):
The Attester obtains an Attestation Result and presents it directly to the Relying Party. Examples include:
- ADR-0005 liveness attestation: `HandshakeResult` gains a `liveness` field that agents carry.
- Signet attestation: signed receipts carry policy attestation inside the artifact.
- Physical attestation: offline-verifiable signed receipts embedded in sensor data.

### Freshness Mechanisms

RFC 9334 Section 10 defines three freshness approaches:

| Mechanism | AGT Support | Implementation |
|---|---|---|
| **Nonce-based** | Supported (new) | `HandshakeChallenge.freshness_nonce` provides a verifier-supplied nonce that must be echoed in the signed Evidence. Requests with `require_freshness=True` bypass the result cache. |
| **Timestamp-based** | Supported (existing) | Liveness attestation (ADR-0005), evidence timestamps, attestation expiry fields |
| **Epoch ID** | Not implemented | No current use case; agents do not operate in synchronized epoch windows |

The existing `HandshakeChallenge.nonce` serves as the challenge-binding token (proving the response corresponds to a specific challenge). The new `freshness_nonce` is semantically distinct: it binds Evidence to a specific verification request, ensuring the Evidence was produced *after* the verifier asked for it. This distinction matters when attestation evidence is produced asynchronously or cached by intermediaries.

### Changes Made

1. **Endorsement module** (`agent-mesh/src/agentmesh/trust/endorsement.py`): New `Endorsement` dataclass and `EndorsementRegistry` implementing the RFC 9334 Endorser role. Currently unsigned metadata; cryptographic signature verification is deferred (see Gaps).

2. **Freshness nonce** (`agent-mesh/src/agentmesh/trust/handshake.py`): Optional `freshness_nonce` field on `HandshakeChallenge` and `HandshakeResponse`. When present, it is included in the Ed25519 signature payload and verified during response validation. `initiate()` accepts `require_freshness=True` which bypasses the result cache.

3. **TrustBridge endorsement integration** (`agent-mesh/src/agentmesh/trust/bridge.py`): Optional `endorsement_registry` parameter threaded through `TrustBridge` and `ProtocolBridge`. Endorsements resolved on demand via `get_endorsements()` rather than cached on `PeerInfo` to avoid HMAC integrity gaps.

### Explicit Gaps (Not Addressed)

These gaps are documented for transparency. They do not block the alignment but should be addressed in future iterations:

1. **Endorsement signature verification**: The `EndorsementRegistry` validates expiry but does not verify cryptographic signatures. Endorsements are treated as informational metadata, not cryptographic proofs. A future `EndorsementVerifier` should verify Ed25519 signatures against a trusted endorser identity source.

2. **Verifier Owner / Relying Party Owner**: RFC 9334 separates policy owners from the roles that execute policies. AGT conflates these. Separating them would enable delegated policy management.

3. **Composite Device attestation**: RFC 9334 Section 3.3 defines composite attestation for systems with multiple sub-attesters. AGT's multi-agent orchestration does not model this explicitly, though delegation chains provide a partial analogue.

4. **Epoch-based freshness**: Not implemented. Would be useful for batch attestation scenarios where multiple agents attest within the same time window.

5. **Formal Conceptual Message types**: The protocol exchanges between roles are not formalized as RATS "Conceptual Messages." IATP messages carry the equivalent data but do not use RATS-defined message structures.

## Consequences

**Benefits:**
- AGT's trust architecture is now explicitly documented against a recognized IETF standard, strengthening the project's credibility for standards-aligned adopters.
- The Endorser role is a first-class concept, enabling third-party vouching workflows (compliance authorities, SBOM signing services, identity providers).
- Nonce-based freshness provides replay protection beyond timestamp validation, closing a gap for time-sensitive attestation scenarios.
- All changes are additive and backward-compatible: no existing API signatures changed, no new required dependencies.

**Tradeoffs:**
- The `freshness_nonce` adds a field to the handshake models that most callers will not use. The overhead is minimal (one optional string field).
- Endorsements without signature verification could create a false sense of trust if consumers treat them as authoritative. The module documentation and this ADR explicitly state they are unsigned metadata.

**Follow-up work:**
- Implement `EndorsementVerifier` with Ed25519 signature verification against a trusted endorser registry.
- Evaluate whether CBOR-encoded Evidence (RFC 9334 recommends CBOR for wire efficiency) would benefit high-throughput AgentMesh deployments.
- Consider aligning IATP message structures with EAT (Entity Attestation Token, RFC 9711) for interoperability with hardware attestation ecosystems.
