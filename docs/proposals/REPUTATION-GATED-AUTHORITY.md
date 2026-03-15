# Proposal: Reputation-Gated Authority

> Compose trust scoring with delegation chains so that effective authority is resolved component-wise at execution time.

**Author:** Tymofii Pidlisnyi (@aeoess) — Agent Passport System  
**References:** #140  
**Status:** Draft  
**Date:** 2026-03-15  

---

## Summary

This proposal adds a mechanism to compose AgentMesh's TrustManager trust scoring with its delegation system. The result is **reputation-gated authority**: an agent's effective permissions are the intersection of what it was delegated and what its earned trust tier allows.

## Motivation

Delegation alone is insufficient for safe multi-agent systems. A principal may delegate broad capabilities to an agent, but that agent should not exercise all of them until it has demonstrated reliability. Current delegation systems are binary (has delegation or doesn't). Reputation-gated authority adds a gradient.

## Core Concept

```
effectiveAuthority = resolveAuthority(delegation, trustTier)
```

Resolution is **component-wise narrowing**:

| Component | Resolution Rule |
|-----------|----------------|
| Capability scope | delegation ∩ tier-allowed capabilities |
| Spend limit | min(delegation_limit, tier_cap) |
| Enforcement mode | policy-selected per capability class |

## Formal Invariants

1. **No widening**: effectiveAuthority ⊆ delegation (trust can only narrow, never expand)
2. **Trust monotonicity**: if tier(A) < tier(B), then effectiveAuthority(A) ⊆ effectiveAuthority(B) for the same delegation
3. **Revocation precedence**: if delegation is revoked, effectiveAuthority = ∅ regardless of trust
4. **Enforcement freshness**: trust score used for resolution must be ≤ T_stale seconds old (configurable, default 30s)
5. **Deterministic resolution**: same (delegation, trustScore, policy) → same effectiveAuthority
6. **Lineage bound**: child agent initial trust ≤ min(default_trust, parent_trust)

## Capability Matching Semantics

Capabilities are hierarchical strings with namespace separation:

```
commerce:purchase:supplies    covers    commerce:purchase:supplies:office
commerce:purchase:supplies    does NOT cover    commerce:purchase:hardware
```

Rules:
- **Wildcards expand at load time**, not at match time (`admin:*` → `admin:observability`, `admin:policy`, `admin:identity`)
- **Deny precedence**: explicit deny overrides any allow
- **Split admin capabilities**: never use `admin:*` in tier mappings — split into `admin:observability`, `admin:policy`, `admin:identity`

## Tier-Capability Mappings

| Tier | Trust Range (μ) | Example Allowed Capabilities |
|------|----------------|------------------------------|
| 0 (Untrusted) | μ < 0.2 | read-only, no external calls |
| 1 (Provisional) | 0.2 ≤ μ < 0.5 | read + limited writes, no commerce |
| 2 (Established) | 0.5 ≤ μ < 0.8 | most capabilities, spend-capped |
| 3 (Trusted) | 0.8 ≤ μ < 0.95 | full delegation scope, high spend caps |
| 4 (Verified) | μ ≥ 0.95, σ < 0.05 | full scope including admin capabilities |

## Data Model

```typescript
interface AuthorityResolution {
  agentId: string;
  delegationId: string;
  trustTier: number;
  trustScore: { mu: number; sigma: number };
  
  // Resolved authority
  allowedCapabilities: string[];      // delegation ∩ tier capabilities
  deniedCapabilities: string[];       // explicitly denied by tier
  effectiveSpendLimit: number;        // min(delegation, tier cap)
  enforcementMode: Map<string, 'block' | 'warn' | 'audit'>;
  
  // Decision
  decision: 'allow' | 'allow_narrowed' | 'deny' | 'audit';
  narrowedFrom?: string[];            // capabilities removed by tier gating
  
  // Metadata
  resolvedAt: string;                 // ISO 8601
  staleAfter: string;                 // resolvedAt + T_stale
}
```

## Decision Types

| Decision | Meaning |
|----------|---------|
| `allow` | All requested capabilities are within both delegation and tier |
| `allow_narrowed` | Some capabilities were removed by tier gating; remaining are allowed |
| `deny` | No requested capabilities survive tier gating, or delegation is revoked |
| `audit` | Allowed but flagged for review (graduated enforcement) |

## Integration Points with AgentMesh

1. **TrustManager** → provides trust score (μ, σ) for tier calculation
2. **IdentityRegistry** → provides delegation chain and revocation status
3. **PolicyEngine** → provides enforcement mode mappings per capability class
4. **Gateway/Middleware** → calls `resolveAuthority()` before executing tool calls

## Event-Driven Cache Invalidation

Trust scores change. The resolution cache must be invalidated on:
- Trust score update (new observation recorded)
- Delegation revocation (immediate, not lazy)
- Policy change (enforcement mode update)
- Tier boundary crossing (score crosses a threshold)

Implementation: event bus subscription, not polling. Cache TTL as fallback (default 30s).

## Trust Feedback Isolation

**Critical**: authority-gate denials MUST NOT feed back as negative trust events. If an agent is denied because its tier is too low, that denial should not further lower its trust score. Otherwise: denial → lower score → more denials → death spiral.

Denials are logged for audit but excluded from TrustManager observation input.

## Bootstrap / Cold-Start Behavior

New agents start at Tier 0 (untrusted) with:
- `mu = 0.3` (slight benefit of the doubt)
- `sigma = 0.25` (high uncertainty)

**Lineage-bound initial trust**: if a parent agent spawns a child, the child's initial trust is `min(default_trust, parent_trust)`. This prevents trust washing — a low-trust agent cannot spawn children with higher trust.

## Reference Implementation

The Agent Passport System (Apache 2.0) has a working implementation:
- `resolve_authority()` in the ProxyGateway module
- Bayesian trust scoring with cryptographic scarring
- 534 tests covering the authority resolution pipeline
- SDK: https://github.com/aeoess/agent-passport-system
- Spec: https://aeoess.com/llms-full.txt

## Open Questions

1. Should tier boundaries be configurable per-deployment, or standardized across AgentMesh?
2. How should authority resolution interact with multi-agent coordination (agent A delegates to B delegates to C — does C get min of all three trust scores)?
3. Should there be a "probationary" mode where a newly-promoted agent gets tier N capabilities but with enhanced logging for the first K actions?
