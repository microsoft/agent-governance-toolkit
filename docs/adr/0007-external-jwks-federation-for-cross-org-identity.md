# ADR 0007: External JWKS federation for cross-org agent identity

- Status: proposed
- Date: 2026-04-23

## Context

AGT's identity model (`did:agentmesh:` + Ed25519 keypairs, per ADR-0001) works well within a single governance domain. The `IdentityRegistry` maintains all known agents, the `TrustHandshake` verifies peers via challenge/response against that registry, and the `AgentRegistry` service tracks trust scores and capabilities. This is a sound single-org architecture.

The gap is **cross-organizational agent interaction**. When Org A's agents interact with Org B's agents — via A2A, MCP, or direct API — AGT has no protocol for verifying an agent whose DID is not in the local registry. The handshake falls back to infrastructure-level identity (API keys, mTLS), which proves *which machine* is calling but not *which agent* with *what delegated authority*.

This gap becomes structural as agent ecosystems grow. Three real scenarios expose it:

1. **Supply-chain agents.** Org A deploys a procurement agent that negotiates with Org B's sales agent. Both organizations run AGT, but neither has the other's agents in their registry. The agents must establish trust without pre-shared credentials.

2. **Platform agents.** A SaaS platform hosts agents on behalf of multiple tenants. Each tenant's agents need to interact with agents from other platforms. The platform cannot pre-register every possible counterparty.

3. **Open federation.** Independent agent operators (like [AgentLair](https://agentlair.dev)) issue identities to agents that interact with enterprise-governed agents. No bilateral agreement exists in advance.

### Existing cross-org paths

**Entra Agent ID bridge** (Tutorial 31) already handles cross-tenant federation within the Microsoft ecosystem via workload identity federation. This works well when both organizations use Entra ID — the bridge maps `did:agentmesh:` to Entra object IDs, and Conditional Access policies govern cross-tenant interactions.

External JWKS federation addresses the cases Entra cannot: agents outside the Microsoft identity ecosystem, agents from organizations without Entra subscriptions, and agents from independent platforms where bilateral tenant configuration is impractical.

The two mechanisms are complementary, not competing:

| Scenario | Recommended path |
|----------|-----------------|
| Both orgs use Entra ID | Entra Agent ID bridge (Tutorial 31) |
| One or both orgs outside Entra | External JWKS federation (this ADR) |
| Independent agent platforms | External JWKS federation (this ADR) |
| Mixed — Entra org + external platform | Both — Entra for internal, JWKS for external |

## Decision

Add an external JWKS federation layer to AGT's identity model as an opt-in identity provider, alongside the existing SPIFFE/SVID and Entra modules in `agentmesh/core/identity/`. The layer enables cross-org agent verification without requiring a shared registry or centralized authority.

### Architecture: provider-based identity resolution

Rather than hardcoding JWKS verification into the handshake path, the design introduces an `IdentityProvider` abstraction at the boundary between `TrustHandshake` and identity resolution. This allows multiple identity backends — local registry, SPIFFE, Entra, external JWKS — to coexist behind a common interface.

```
                    TrustHandshake.verify_peer()
                            │
                    IdentityProviderChain
                    ┌───────┼───────────────────┐
                    │       │                   │
             LocalRegistry  EntraBridge   ExternalJWKS
             (did:agentmesh) (Entra OID)  (did:web + JWKS)
```

The `TrustHandshake` tries providers in order. For agents with `did:agentmesh:` DIDs, the local `IdentityRegistry` resolves them as today. For agents presenting `did:web:` DIDs or JWTs with an `iss` claim pointing to an external JWKS URL, the `ExternalJWKSProvider` handles verification.

This keeps the abstraction at the **provider boundary**, not the wire format — operators can plug in any identity backend that satisfies the interface, including hosted federation operators or custom trust anchors.

### Discovery: DNS-based, following OpenID Federation

**Recommended approach: DNS-anchored `/.well-known/` discovery.**

Each organization publishes a JWKS endpoint at a well-known URL under its domain:

```
https://org-a.example.com/.well-known/jwks.json
https://agentlair.dev/.well-known/jwks.json
```

This follows the pattern established by:
- **OpenID Federation** — entity configuration at `/.well-known/openid-federation`
- **SPIFFE trust domains** — trust domain roots anchored to DNS names
- **did:web** — DID resolution via HTTPS under the domain authority

Benefits:
- **One dereference hop.** Resolve the domain, fetch the JWKS. No intermediary.
- **DNS-anchored trust.** The domain's TLS certificate provides the trust anchor — the same model that secures the web. DNSSEC adds an additional verification layer where available.
- **No coordination overhead.** Organizations publish their JWKS independently. No registry to join, no bilateral agreements to sign.

A lightweight **discovery registry** can layer on top for discoverability (finding *which* organizations participate in federation) without becoming the trust source. The registry answers "who's out there?" while DNS answers "is this really them?"

### Trust anchoring: WebPKI + explicit federation policy

**Recommended approach: DNS/WebPKI as the default trust anchor, with explicit federation policy for production deployments.**

The trust anchoring question has three dimensions:

**1. Key provenance — who signs the JWKS?**

| Approach | When to use |
|----------|------------|
| **DNS/WebPKI (default)** | `did:web` + JWKS served over HTTPS. The domain's TLS certificate is the trust anchor. This is what the web runs on — well-understood, operationally simple, no new infrastructure. |
| **CA-backed with CT-log** | High-assurance deployments. Certificate Transparency logs provide auditability. Pairs well with DNSSEC. |
| **Blockchain-anchored** | Not recommended for v1. Adds operational complexity (chain liveness dependency, gas costs) without proportional trust improvement for the cross-org agent case. |

**2. Partner trust — who do we federate with?**

Organizations need control over which external JWKS endpoints they trust. Three tiers:

| Tier | Policy | Use case |
|------|--------|----------|
| **Explicit allowlist** | Operator configures trusted JWKS URLs | Production — known partners |
| **Domain-scoped TOFU** | First contact from a domain is logged and trusted; subsequent contacts verified against the cached JWKS | Development, low-stakes interactions |
| **Open federation** | Any valid `did:web` + JWKS is accepted | Public agent marketplaces, open ecosystems |

The default should be **explicit allowlist** — operators opt in to each federation partner. This matches the security posture of AGT's existing default-deny policy model.

**3. Configuration:**

```python
# Federation policy configuration
federation_config = FederationPolicy(
    # Trusted JWKS endpoints (explicit allowlist)
    trusted_endpoints=[
        TrustedEndpoint(
            domain="agentlair.dev",
            jwks_url="https://agentlair.dev/.well-known/jwks.json",
            trust_tier="verified_partner",  # maps to existing trust tiers
        ),
        TrustedEndpoint(
            domain="partner-corp.example.com",
            jwks_url="https://partner-corp.example.com/.well-known/jwks.json",
            trust_tier="trusted",
        ),
    ],
    # Default policy for unknown endpoints
    unknown_endpoint_policy="deny",  # "deny" | "tofu" | "open"
    # JWKS cache TTL
    jwks_cache_ttl_seconds=300,
    # Require DNSSEC validation
    require_dnssec=False,
)
```

### Revocation propagation

Revocation in a federated JWKS model operates at two levels: **key rotation** (routine) and **agent revocation** (urgent).

**Routine key rotation:**

- JWKS endpoints publish keys with `kid` (key ID) fields. Rotation adds a new key and removes the old one.
- Verifiers cache JWKS responses with a TTL (default: 5 minutes). On cache expiry, the verifier re-fetches.
- Short-lived agent tokens (15-minute TTL, matching AGT's existing credential lifecycle) limit the window of exposure — even if a verifier has a stale JWKS cache, the token itself expires quickly.

**Urgent revocation (compromised key):**

- The JWKS endpoint removes the compromised key immediately.
- Verifiers that cache the old JWKS will accept the compromised key until cache expiry (up to 5 minutes with default TTL).
- For faster propagation: a co-located **revocation list endpoint** at `/.well-known/jwks-revoked.json` lists revoked `kid` values with timestamps. Verifiers check this endpoint on every verification (it's a small, cacheable document).

```python
# Revocation check flow
async def verify_external_token(token: str, jwks_url: str) -> VerificationResult:
    # 1. Check revocation list (fast — small document, aggressive caching)
    revoked_kids = await fetch_revocation_list(jwks_url)
    token_kid = extract_kid(token)
    if token_kid in revoked_kids:
        return VerificationResult(verified=False, reason="key_revoked")

    # 2. Fetch JWKS (cached with TTL)
    jwks = await fetch_jwks(jwks_url, cache_ttl=300)

    # 3. Verify signature
    return await verify_signature(token, jwks)
```

**Push-based notification** (webhook or SSE for real-time revocation propagation) is a reasonable v2 addition but not required for v1. The combination of short-lived tokens + pull-based revocation list provides adequate security for most cross-org scenarios.

### Integration with existing AGT components

**`HandshakeResult` extension:**

```python
class HandshakeResult(BaseModel):
    verified: bool
    peer_did: str
    peer_name: Optional[str] = None
    trust_score: int = Field(default=0, ge=0, le=1000)
    trust_level: Literal["verified_partner", "trusted", "standard", "untrusted"]

    # New: external identity (present only for cross-org agents)
    external_identity: Optional[ExternalIdentity] = None


class ExternalIdentity(BaseModel):
    """Identity verified via external JWKS federation."""
    did_web: str                    # e.g., "did:web:agentlair.dev:agents:abc123"
    jwks_url: str                   # The JWKS endpoint used for verification
    issuer_domain: str              # DNS domain of the issuing organization
    federation_tier: str            # "verified_partner" | "trusted" | "tofu"
    verified_at: datetime
    token_expires_at: datetime
    delegation_claims: dict = {}    # Scoped capabilities from the issuer
```

**`IdentityRegistry` extension:**

The existing `AgentRegistryEntry` gains an optional `external_source` field for agents first seen via federation. This allows the trust scoring system to track external agents over time without requiring pre-registration.

**ADR-0003 (200ms handshake SLA) compliance:**

- JWKS fetches are cached (5-minute TTL). After the first fetch, verification adds only the signature check latency (~1ms for Ed25519).
- Cold-cache JWKS fetch is an HTTPS round-trip (typically 50–150ms). For the first interaction with a new federation partner, the handshake may approach the 200ms budget. Subsequent handshakes are well within budget.
- Operators can pre-warm the JWKS cache for known partners at startup.

**ADR-0005 (liveness attestation) composition:**

External agents that support liveness attestation can participate in the heartbeat protocol. The `delegation_chain_hash` in the heartbeat payload works regardless of whether the identity was resolved locally or via JWKS — it binds to the delegation, not the identity provider. Cross-bridge liveness propagation (identified as follow-up work in ADR-0005) composes naturally with JWKS federation — a TrustBridge can query another bridge's liveness records using the `did:web` identifier.

### Working example

[AgentLair](https://agentlair.dev) currently issues Ed25519 JWTs (AATs — Agent Authentication Tokens) verified via a JWKS endpoint:

```
GET https://agentlair.dev/.well-known/jwks.json

{
  "keys": [{
    "kty": "OKP",
    "crv": "Ed25519",
    "x": "KEVRJiCKuLXJ_R85_h-26tsA-Ng0DOUTqnbt1PfInmk",
    "kid": "ab0502f7",
    "use": "sig",
    "alg": "EdDSA"
  }]
}
```

This aligns with ADR-0001 (Ed25519 for agent identity) — the same key type and algorithm. Two independent projects ([springdrift](https://github.com/seamus-brady/springdrift/pull/38), [task-orchestrator](https://github.com/jpicklyk/task-orchestrator)) have independently adopted this verification pattern, suggesting the approach is practical and interoperable.

## Consequences

**Benefits:**

- Cross-org agent identity verification without a centralized registry or shared governance domain.
- Complements the Entra Agent ID bridge — covers agents outside the Microsoft identity ecosystem.
- Provider-based architecture allows future identity backends (DIF MCP-I, OpenID Federation entity statements) without modifying the handshake protocol.
- DNS-anchored trust reuses existing WebPKI infrastructure — no new certificate authorities or blockchain dependencies.
- Short-lived tokens + pull-based revocation provide defense-in-depth against key compromise.

**Tradeoffs:**

- Adds a new identity provider to the resolution chain. Operators must understand when to use local registry vs. Entra bridge vs. JWKS federation.
- Cold-cache JWKS fetch may approach the 200ms handshake SLA. Pre-warming mitigates this but adds startup complexity.
- Explicit-allowlist default means operators must configure each federation partner. This is intentionally conservative but adds operational overhead for large federations.
- DNS/WebPKI trust anchor inherits the web's trust model, including its limitations (CA compromise, domain hijacking). DNSSEC and Certificate Transparency mitigate but do not eliminate these risks.

**Follow-up work:**

- **Implementation PR:** `ExternalJWKSProvider` in `agentmesh/core/identity/` alongside the existing SPIFFE and Entra modules.
- **Federation policy configuration:** YAML/JSON schema for `FederationPolicy`, loadable from AGT's existing config system.
- **Discovery registry:** Optional lightweight service for publishing and discovering federation endpoints across the ecosystem.
- **DIF MCP-I alignment:** Map the provider interface to DIF's Mandatory DID + VC delegation chain (L2 standard) as that specification stabilizes.
- **Cross-bridge liveness propagation:** Extend ADR-0005's follow-up to use `did:web` as the cross-bridge identifier for federated liveness queries.

**Prior art and references:**

- [OpenID Federation](https://openid.net/specs/openid-federation-1_0.html) — entity statement chains, trust marks, and `/.well-known/` discovery
- [SPIFFE](https://spiffe.io/) — trust domain model and workload identity federation
- [did:web specification](https://w3c-ccg.github.io/did-method-web/) — DNS-anchored decentralized identifiers
- [AgentLair JWKS](https://agentlair.dev/.well-known/jwks.json) — production Ed25519 JWKS endpoint for agent identity
- [springdrift PR #38](https://github.com/seamus-brady/springdrift/pull/38) — JWKS gate handler integration, merged
- [task-orchestrator v3.2.0](https://github.com/jpicklyk/task-orchestrator) — independent JWKS ActorVerifier adoption
- AGT Tutorial 31 — Entra Agent ID bridge for cross-tenant federation within the Microsoft ecosystem
