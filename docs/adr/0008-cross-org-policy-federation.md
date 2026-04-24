# ADR 0008: Cross-org policy federation above identity

- Status: proposed
- Date: 2026-04-24

## Context

ADR-0007 establishes cross-org identity federation via DNS-anchored JWKS and
short-lived Ed25519 tokens. It answers *who is this agent and which
organization does it belong to*. With identity solved, a harder question
surfaces: when agents from different organizations interact, whose policies
govern the interaction?

Five concrete problems motivate this ADR. They were identified in [issue
#1386](https://github.com/microsoft/agent-governance-toolkit/issues/1386) and
refined in the subsequent discussion:

1. **Policy precedence.** Org X's agent-side policy and Org Y's tool-side
   policy both apply to a cross-org invocation. No mechanism exists to
   evaluate them jointly or resolve conflicts.

2. **Evidence correlation.** Both organizations emit attestations for the same
   tool call. There is no specified way to link them cryptographically across
   org boundaries for audit or compliance purposes.

3. **Policy-change propagation.** ADR-0007's 15-minute token TTL handles
   identity revocation. Policy changes — especially tightening — have
   different propagation semantics that are not addressed.

4. **Cross-org consent and data boundaries.** Tool arguments crossing org
   boundaries carry data subject to purpose-binding, residency, and
   record-keeping obligations (EU AI Act Article 12, enforcement
   2026-08-02).

5. **Trust-tier composition.** ADR-0007 defines bilateral federation. When
   agent chains span three or more organizations, the trust model for the
   transitive case is undefined.

This ADR proposes concrete answers for problems 1–3 and framing decisions for
4–5. It sits strictly above ADR-0007: the identity layer provides the key
infrastructure (Ed25519, JWKS discovery, `did:web`), and this ADR builds the
policy layer on top of it.

### Design constraints

- **Deterministic evaluation.** ADR-0004 requires that policy evaluation
  remain deterministic and outside LLM control loops. Cross-org policy
  evaluation must satisfy the same constraint.
- **200ms handshake budget.** ADR-0003 caps the trust handshake at 200ms.
  Policy evaluation must not blow this budget.
- **No shared state.** Cross-org policy federation must not require a shared
  policy store, shared database, or bilateral synchronization protocol.
  Each organization controls its own policies independently.
- **Compatible attestation primitives.** The ecosystem is converging on
  Ed25519 + RFC 8785 JCS + SHA-256 for attestations. This ADR adopts those
  primitives rather than introducing new ones.

## Decision

Add a cross-org policy federation layer to AGT, consisting of three
mechanisms: bilateral policy evaluation with intersection semantics, content-
hash-chained attestations for evidence correlation, and asymmetric propagation
for policy changes.

### 1. Policy precedence: intersection with structured denial

When Agent A (Org X) invokes Tool B (Org Y), both organizations' policies
apply. The default resolution is **intersection**: the invocation is permitted
only if both the agent-side policy (Org X) and the tool-side policy (Org Y)
independently allow it.

```
Agent A (Org X)                              Tool B (Org Y)
     │                                            │
     ├─ Org X agent-side policy: ALLOW? ──┐       │
     │                                    │       │
     │                              ┌─────▼─────┐ │
     │                              │ INTERSECT │ │
     │                              └─────▲─────┘ │
     │                                    │       │
     │       Org Y tool-side policy: ALLOW? ──────┤
     │                                            │
     ▼ Permitted only if BOTH allow               │
```

**Why intersection.** Neither organization should be able to unilaterally
override the other's policies. The tool owner governs access to their resource;
the agent principal governs what their agent may do. This matches the
established pattern in cross-org API integrations and aligns with
AGT's existing default-deny posture (ADR-0004).

**Structured denial.** When policies conflict — both individually satisfiable
but jointly contradictory — the intersection produces a deny. To make denials
debuggable without leaking policy internals across boundaries, the evaluating
side returns a structured denial reason:

```python
class PolicyDenialReason(BaseModel):
    """Returned when cross-org policy intersection denies an invocation."""
    code: Literal[
        "agent_policy_deny",     # Agent-side policy forbids
        "tool_policy_deny",      # Tool-side policy forbids
        "policy_conflict",       # Both allow individually but conflict jointly
        "policy_unavailable",    # Could not evaluate (timeout, fetch failure)
    ]
    # Human-readable hint — MUST NOT expose policy rule details
    message: str
    # Unique denial ID for cross-org debugging via side-channel
    denial_id: str
    timestamp: datetime
```

The `denial_id` allows operators on both sides to correlate a denial in their
respective logs without exchanging policy content. An operator who sees a
`policy_conflict` denial can contact their counterpart with the `denial_id` to
resolve the conflict through a side-channel.

**Evaluation location.** Policy intersection is evaluated at the tool side
(Org Y). The agent presents its identity token (ADR-0007), and optionally a
signed policy-claims JWT asserting agent-side constraints. The tool side
evaluates its own policy, evaluates the agent's policy claims, and computes
the intersection. This avoids requiring the tool to expose its policy
externally while allowing the agent to declare its constraints.

```python
class AgentPolicyClaims(BaseModel):
    """Signed claims attached to the invocation request, asserting the
    agent-side policy constraints that apply to this invocation."""
    # Purposes the agent is authorized for
    permitted_purposes: list[str]
    # Data residency constraints (ISO 3166-1 alpha-2)
    data_residency: list[str] | None = None
    # Maximum trust tier the agent may operate at
    max_trust_tier: str
    # Expiry — matches the identity token TTL
    exp: int
    # Signed by Org X's key (same Ed25519 infrastructure as ADR-0007)
    iss: str  # did:web of the issuing org
```

### 2. Evidence correlation: content-hash-chained attestations

Cross-org attestations reference each other by **content hash**, not by
signature. This separation is a deliberate design choice:

- **Content hashes prove causal ordering.** H(attestation_X) included in
  attestation_Y proves Y was created after X, without requiring Y's verifier
  to trust X's signing key.
- **Signatures prove authorship.** They answer *who created this attestation*,
  which is an orthogonal question.
- **Mixing them kills composability.** A signature-based reference couples the
  ordering proof to the trust proof, which fails in the cross-org case where
  the verifier may not have a trust relationship with both signers.

**Attestation format:**

```python
class CrossOrgAttestation(BaseModel):
    """Attestation emitted by each org for a cross-org invocation."""
    # Unique attestation ID
    attestation_id: str
    # Trace ID — UUIDv7, minted by the calling agent for temporal ordering
    trace_id: str
    # Content hash of this attestation's payload (SHA-256 over JCS canonical form)
    content_hash: str
    # Reference to the counterpart attestation (if available)
    references: list[AttestationReference] = []
    # Ed25519 signature over the JCS-canonicalized payload
    signature: str
    # Signing key ID (references the org's JWKS)
    kid: str
    # Timestamp
    created_at: datetime
    # Org identity
    issuer: str  # did:web of the attesting org


class AttestationReference(BaseModel):
    """Reference to another attestation by content hash."""
    # SHA-256 content hash of the referenced attestation
    content_hash: str
    # Relationship type
    relationship: Literal[
        "request",    # This attestation is for the response to this request
        "response",   # This attestation is for the request that got this response
        "delegation", # This attestation delegates authority referenced here
    ]
```

**Correlation mechanism:**

1. The calling agent (Org X) mints a UUIDv7 trace ID and includes it in the
   request.
2. Org X emits an attestation for the outbound request.
3. The callee (Org Y) derives an independent correlation key from the request
   content hash — it does not blindly trust the caller's trace ID.
4. Org Y emits its own attestation, referencing Org X's attestation by content
   hash.
5. Both attestations include the trace ID for operational observability.
   The content hash provides cryptographic correlation. For honest
   participants, both converge. Divergence is a signal.

**Canonical record: no single owner.**

Each org stores its own attestations. Cross-org compliance queries resolve by
following the hash chain: Org X presents their attestation, which references
Org Y's by content hash, and an auditor verifies both independently. This
keeps data residency clean — no org is forced to export attestation payloads
to a counterpart.

**Transparency log integration (optional).**

For non-repudiation, organizations may publish attestation summaries to a
public transparency log (e.g., Sigstore Rekor):

```
Published to log:  H(attestation) || timestamp || signing_identity
Kept org-local:    Full attestation payload
```

This Certificate Transparency–style split provides non-repudiation (the log
proves the attestation existed at time T) without forcing disclosure of
commercially sensitive payloads. An auditor who needs the full content
requests it from the relevant org under existing regulatory channels and
verifies the content hash against the log entry.

This structure aligns with EU AI Act Article 12(2) requirements: the log entry
satisfies post-market monitoring traceability obligations, while the org-local
payload store satisfies content access under regulatory authority.

### 3. Policy-change propagation: asymmetric by direction

Identity revocation and policy changes have different semantics. Identity is
binary (valid/revoked). Policy is a constraint set that changes in complex
ways, and the direction of change matters for safety.

**Asymmetric propagation:**

| Direction | Mechanism | Rationale |
|-----------|-----------|-----------|
| **Tightening** (adding restrictions) | Immediate propagation. Agents must revalidate on next invocation. Active invocations may complete but cannot be extended. | Fail-safe. A known-denied action must not remain executable due to cache staleness. |
| **Loosening** (removing restrictions) | Respects standard cache TTL. | Fail-safe. A newly-permitted action arriving late is a usability issue, not a security issue. |

**Discovery and caching:**

Tool-side policy metadata is published at a well-known endpoint alongside the
JWKS endpoint (ADR-0007):

```
https://org-y.example.com/.well-known/agent-policy.json
```

```python
class PolicyMetadata(BaseModel):
    """Published policy metadata for federation partners."""
    # Policy version — monotonically increasing
    version: int
    # Cache TTL for this policy (seconds)
    max_age: int = 300
    # Minimum policy version accepted — agents with cached policy
    # below this version MUST revalidate before invoking
    min_version: int
    # Policy content hash — agents can skip re-fetch if hash unchanged
    content_hash: str
    # Last modified timestamp
    last_modified: datetime
    # List of supported purposes (for agent-side pre-filtering)
    supported_purposes: list[str] = []
    # Data processing regions (ISO 3166-1 alpha-2)
    processing_regions: list[str] = []
```

**Propagation mechanism:**

- The `version` field is monotonically increasing. Agents cache policy
  metadata with the advertised `max_age`.
- On tightening, the org bumps `min_version` to the new version. Agents
  whose cached version is below `min_version` receive a `412 Precondition
  Failed` on invocation, forcing a re-fetch.
- This composes with ADR-0007's 5-minute JWKS cache TTL — policy metadata
  can be co-located at the same endpoint cadence.
- Push-based notification (webhook, SSE) is a reasonable v2 addition for
  real-time tightening propagation but not required for v1. The
  `min_version` check provides a synchronous safety net regardless.

**In-flight invocations:**

Policy changes do not retroactively invalidate in-flight invocations. The
contract: policy is evaluated at invocation time and honored for the duration
of that invocation. For long-running or streaming invocations that exceed the
policy TTL, the tool side may reject continuation with a `policy_expired`
error, requiring the agent to re-authenticate and re-evaluate policy.

```python
class PolicyExpiredError(BaseModel):
    """Returned when an in-flight invocation outlasts its policy window."""
    code: Literal["policy_expired"]
    cached_version: int
    current_version: int
    # The agent should re-fetch policy and retry if still permitted
    retry_after_seconds: int = 0
```

### 4. Cross-org consent and data boundaries (framing)

This section establishes the framing for cross-org data handling. A full
specification is deferred to a follow-up ADR but the structural decisions
are recorded here to constrain the design space.

**Purpose binding at the boundary.** Purpose belongs in the request envelope,
not the tool schema. The `AgentPolicyClaims` (section 1) includes a
`permitted_purposes` field. The tool-side policy specifies which purposes it
accepts. The intersection check validates purpose alignment before any data
crosses the boundary.

**Data residency as federation metadata.** The `PolicyMetadata` (section 3)
includes `processing_regions`. Agent-side policy can enforce residency
constraints *before* the call — rejecting invocations to tools that process
data outside permitted regions. This is pre-flight enforcement, not
post-hoc detection.

**Record-keeping under Article 12.** Both organizations need records, but of
different things:
- Org X records what data left and why (purpose, destination, timestamp).
- Org Y records what data arrived and what was done with it.

The attestation mechanism (section 2) provides the cryptographic substrate
for both records. The transparency log integration provides third-party
verifiability without forced disclosure.

### 5. Trust-tier composition: non-transitive by default

**Default: bilateral only.** Federation relationships are bilateral edges in
the trust graph. X→Y federation at tier 2 does not imply X→Z trust if Y has
federated with Z. Transitive trust in identity systems is where security
models fail. The intermediary (Y) must not be able to grant transitivity
unilaterally.

**Explicit opt-in for managed transitivity.** For use cases where transitive
delegation is needed (large consortia, shared infrastructure, task-scoped
agent chains):

- Both endpoints (X and Z) must consent to the transitive relationship.
- The intermediary (Y) facilitates the introduction but does not authorize it.
- A depth limit is enforced (maximum 2 hops for v1).
- The trust tier at each hop is the minimum of the chain — if X→Y is tier 2
  and Y→Z is tier 3, X's effective tier toward Z is tier 3 (least privileged).

```python
class FederationEdge(BaseModel):
    """A bilateral federation relationship."""
    source_domain: str
    target_domain: str
    trust_tier: str
    # Whether this edge permits introduction to third parties
    allows_introduction: bool = False
    # Maximum transitive depth (0 = no transitivity)
    max_depth: int = 0
    # Both endpoints must have matching edges for transitivity to activate
```

Full multi-hop composition semantics are deferred to a follow-up ADR. The
structural decision recorded here — non-transitive by default, bilateral
consent required for exceptions — constrains the design space.

## Consequences

**Benefits:**

- Cross-org policy evaluation without shared policy stores or bilateral
  synchronization. Each organization maintains full sovereignty over its
  policies.
- Intersection semantics align with AGT's default-deny posture and with
  established patterns in B2B API integrations.
- Content-hash-chained attestations provide cryptographic audit trails across
  org boundaries without coupling ordering proofs to trust proofs.
- Asymmetric propagation ensures fail-safe behavior for policy tightening
  while avoiding unnecessary disruption for loosening.
- The transparency log split satisfies EU AI Act Article 12 obligations
  without forcing disclosure of commercially sensitive attestation payloads.
- All mechanisms compose with existing ADRs: Ed25519 key infrastructure
  (ADR-0001), 200ms handshake budget (ADR-0003), deterministic policy
  evaluation (ADR-0004), liveness attestation (ADR-0005), and identity
  federation (ADR-0007).

**Tradeoffs:**

- Intersection semantics can produce opaque denials when policies conflict.
  Structured denial reasons mitigate this but debugging still requires
  side-channel communication between operators.
- Policy metadata endpoints add a new endpoint that federation partners must
  publish and maintain. This is additional operational surface.
- The asymmetric propagation model requires tool-side implementations to
  distinguish between tightening and loosening changes, adding complexity to
  policy management tooling.
- Non-transitive default means multi-org agent chains require explicit
  bilateral federation at each hop, which does not scale to large open
  ecosystems without the managed transitivity extension.

**Follow-up work:**

- **Implementation PR:** `PolicyFederationProvider` in
  `agentmesh/core/policy/` alongside the existing Rego and Cedar evaluators.
- **Cross-org attestation SDK:** Content-hash-chaining utilities for the
  Python, .NET, Go, and Rust SDKs.
- **Article 12 compliance guide:** Mapping of attestation and transparency
  log mechanisms to specific Article 12(2) obligations.
- **Full data-boundary ADR:** Expanding section 4 into a standalone ADR
  covering purpose binding, data residency enforcement, and cross-org
  consent flows.
- **Multi-hop composition ADR:** Expanding section 5 into a standalone ADR
  with formal trust-tier algebra for transitive delegation.
- **Push-based policy propagation:** Webhook/SSE mechanism for real-time
  tightening propagation (v2).

**Prior art and references:**

- [ADR-0007](0007-external-jwks-federation-for-cross-org-identity.md) —
  identity federation via JWKS, the prerequisite layer for this ADR
- [ADR-0004](0004-keep-policy-evaluation-deterministic.md) — deterministic
  policy evaluation constraint
- [Issue #1386](https://github.com/microsoft/agent-governance-toolkit/issues/1386)
  — original discussion thread with technical analysis from @piiiico,
  @desiorac, and @Knapp-Kevin
- [RFC 8785](https://datatracker.ietf.org/doc/html/rfc8785) — JSON
  Canonicalization Scheme (JCS) for deterministic hashing
- [Sigstore Rekor](https://docs.sigstore.dev/logging/overview/) —
  transparency log for attestation non-repudiation
- [Certificate Transparency (RFC 6962)](https://datatracker.ietf.org/doc/html/rfc6962)
  — the hash-to-log, payload-local split model
- [EU AI Act Article 12](https://artificialintelligenceact.eu/article/12/) —
  record-keeping obligations for high-risk AI systems
- [OpenID Federation](https://openid.net/specs/openid-federation-1_0.html) —
  entity trust and metadata discovery patterns
