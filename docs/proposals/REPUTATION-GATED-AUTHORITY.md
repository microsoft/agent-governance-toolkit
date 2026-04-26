# Proposal: Reputation-Gated Authority

**Status:** Proposed
**Author:** Tymofii Pidlisnyi (@aeoess)
**Date:** 2026-03-15
**Related:** [#140](https://github.com/microsoft/agent-governance-toolkit/issues/140), [Agent Passport System](https://github.com/aeoess/agent-passport-system)

## Summary

Compose AgentMesh's trust scoring (`TrustManager`, 0-1000 scale) with its delegation system (`identity.delegate()`) so that an agent's effective authority is resolved component-wise: capability scope is the intersection of delegated and tier-allowed capabilities, spend limits take the numeric minimum, and enforcement mode is policy-selected. Trust can only narrow authority, never widen it.

## Core Principle

> Effective authority is resolved component-wise at execution time by intersecting delegated scope with trust-tier limits. Trust may narrow authority but never expand it.

## Invariants

These invariants must hold for any conforming implementation:

1. **No widening.** Effective authority must never exceed delegated authority. Trust scoring can restrict what a delegation grants; it cannot add capabilities the delegation does not contain.
2. **Trust monotonicity.** Lowering an agent's trust score must never increase its effective authority. Raising trust can restore authority up to the delegation ceiling, never beyond it.
3. **Revocation precedence.** Revoked delegations always deny, regardless of trust score. Revocation is not subject to trust-tier override.
4. **Enforcement freshness.** Effective authority must be derived from current trust score and current revocation status at execution time, not from a cached prior decision.
5. **Deterministic resolution.** For the same identity, delegation, trust score, and action context, resolution must produce the same result.
6. **Lineage bound.** A child agent's initial trust score must not exceed its parent's current trust score at delegation time. This prevents trust washing via sub-agent spawning.

## Context

AgentMesh currently has two independent subsystems:

1. **Delegation** (`identity/delegation.py`) — Cryptographic delegation chains where a parent identity delegates scoped capabilities to a child. Child capabilities must be a subset of the parent's. Cascade revocation via `IdentityRegistry.revoke()`.

2. **Trust scoring** (`trust/scoring.py`, `TrustManager`) — Bayesian trust model scoring agents 0-1000 across five tiers. Score changes driven by policy compliance history, task completions, and boundary violations. Default: 500 (Standard).

These systems operate independently. A delegation grants capabilities; the trust score tracks reputation. But there is no composition point where trust constrains delegation at enforcement time. An agent with a freshly minted delegation and a minimal trust history can exercise the full scope of its granted capabilities immediately.

The gap: **delegation defines what an agent *may* do; trust scoring tracks what an agent *should* be allowed to do. Neither alone is sufficient. The composition is the missing piece.**

### Prior art

The Agent Passport System implements this composition via `resolve_authority()` in its ProxyGateway enforcement boundary. This proposal adapts that pattern to AgentMesh's architecture and addresses additional edge cases identified through peer review.

## Decision

### Component-wise authority resolution

Effective authority is not a single value. It is resolved across three independent dimensions, each with its own narrowing operation:

| Dimension | Narrowing Operation | Example |
|-----------|-------------------|---------|
| Capability scope | Set intersection: `delegation.capabilities ∩ tier_allowed_capabilities` | Delegation grants `write:*`, tier allows `write:own` only → effective = `write:own` |
| Spend limit | Numeric minimum: `min(delegation.spend_limit, tier.max_spend)` | Delegation allows $1000, tier caps at $100 → effective = $100 |
| Enforcement mode | Policy-selected per capability class | Financial actions → `block`; informational reads → `warn` |

### Core algorithm

```python
def resolve_effective_authority(
    identity: AgentIdentity,
    delegation: Delegation,
    trust_manager: TrustManager,
    action: ActionRequest,
) -> AuthorityDecision:
    """
    Compute effective authority by composing delegation scope
    with trust tier limits, component-wise.
    """
    # 1. Revocation check (always first — Invariant 3)
    if delegation.is_revoked():
        return AuthorityDecision(decision="deny", reason="delegation_revoked")

    # 2. Delegation chain verification
    if not delegation.verify(identity):
        return AuthorityDecision(decision="deny", reason="invalid_delegation")

    # 3. Resolve trust tier from current score (Invariant 4: live, not cached)
    score = trust_manager.get_score(identity.id)
    tier = score_to_tier(score)

    # 4. Component-wise narrowing
    tier_capabilities = TIER_CAPABILITY_MAP[tier]
    effective_scope = resolve_capability_intersection(
        delegation.capabilities, tier_capabilities
    )
    effective_spend = min(
        delegation.spend_limit or float('inf'),
        tier.max_spend or float('inf'),
    )

    # 5. Check requested action against effective authority
    if not action_is_authorized(action, effective_scope, effective_spend):
        return AuthorityDecision(
            decision="deny",
            effective_scope=effective_scope,
            effective_spend_limit=effective_spend,
            narrowing_reason=f"action '{action.name}' exceeds tier '{tier.name}' limits",
            trust_tier=tier.name,
        )

    # 6. Check if action was narrowed (e.g., requested $500, capped to $100)
    if action_was_narrowed(action, effective_scope, effective_spend):
        return AuthorityDecision(
            decision="allow_narrowed",
            effective_scope=effective_scope,
            effective_spend_limit=effective_spend,
            narrowing_reason=f"narrowed by tier '{tier.name}'",
            trust_tier=tier.name,
        )

    return AuthorityDecision(
        decision="allow",
        effective_scope=effective_scope,
        effective_spend_limit=effective_spend,
        trust_tier=tier.name,
    )
```

### Capability matching semantics

Capability resolution is the most security-sensitive part of this proposal. The following rules govern how capabilities are matched and intersected:

**Exact match.** `write:reports` matches `write:reports` only.

**Namespace wildcards.** `read:*` matches any capability in the `read:` namespace at one level of depth. `read:*` covers `read:data` but does NOT cover `read:data:sensitive` unless the wildcard is `read:**` (recursive).

**No implicit semantic inheritance.** `admin:*` does not imply `read:*`. Each namespace is independent. Capability relationships must be explicitly configured.

**Expansion at evaluation time.** Wildcards in tier capability maps should be expanded to concrete capability lists during policy loading, not resolved dynamically at evaluation time. This prevents future capability names from being silently covered by existing wildcards.

**Explicit deny precedence.** If a deny rule exists for a capability, it overrides any allow, regardless of source.

**Versioning.** New capability names added to the system are not covered by existing wildcard rules until the tier mapping is explicitly updated. This is a safety-by-default choice.

### Trust tier capability map

Maps AgentMesh's existing five tiers to capability families. These are **illustrative defaults** — deployments must configure their own mappings appropriate to their security requirements.

| Tier | Score Range | Capability Families | Spend Cap |
|------|-------------|-------------------|-----------|
| Untrusted | 0-199 | `read:own` | $0 |
| Limited | 200-399 | `read:*`, `write:own` | $10/action |
| Standard | 400-599 | `read:*`, `write:shared`, `execute:bounded` | $100/action |
| Trusted | 600-799 | Above + `financial:low`, `admin:observability` | $1,000/action |
| Privileged | 800-1000 | Above + `admin:policy`, `admin:identity`, `financial:high` | Delegation limit |

Key design choices in this mapping:

- **Admin capabilities are split**, not a single `admin:*` bucket. `admin:observability` (read logs, metrics) unlocks earlier than `admin:policy` (change rules) or `admin:identity` (revoke agents).
- **Financial capabilities are tiered.** Low-value transactions unlock at Trusted; high-value requires Privileged.
- **No tier grants capabilities the delegation doesn't contain.** A tier mapping that includes `admin:policy` has no effect if the delegation never granted `admin:policy` in the first place (Invariant 1).

### Bootstrap and cold-start behavior

New agents default to 500 (Standard) in AgentMesh. This default may be too permissive for reputation-gated authority, since it grants meaningful capability access before an agent has demonstrated any trustworthy behavior.

**Lineage-bound initial trust (Invariant 6).** When Agent A delegates to Agent B, Agent B's initial trust score is `min(default_score, Agent_A.current_score)`. This prevents a low-trust agent from spawning children with higher effective authority.

**Deployment-configurable initial trust.** Operators may set the default initial trust score lower than 500 (e.g., 300 / Limited) for stricter environments. The initial trust level materially affects the security value of the entire system and should be a prominent configuration option.

### Decision types

The enforcement boundary returns one of four decision types:

| Decision | Meaning | Caller behavior |
|----------|---------|-----------------|
| `allow` | Action permitted as requested | Proceed |
| `allow_narrowed` | Action permitted but parameters were capped (e.g., spend reduced) | Proceed with narrowed parameters; log the narrowing |
| `deny` | Action blocked by trust-tier or delegation limits | Return error to agent with `narrowing_reason` |
| `audit` | Action permitted but logged for review (shadow mode) | Proceed; write audit record |

The distinction between `allow` and `allow_narrowed` prevents callers from treating all permitted actions identically when some were silently constrained.

### Enforcement point

`resolve_effective_authority()` is called at the enforcement boundary — the point where an agent action is intercepted before execution. In the Agent Governance Toolkit, this maps to the Agent OS Kernel's policy evaluation pipeline:

```
Agent requests action
  → PolicyEngine.evaluate()           # existing
    → resolve_effective_authority()    # NEW: trust-gated check
      → delegation.verify()           # existing
      → trust_manager.get_score()     # existing
      → resolve component-wise        # NEW
    → capability_model.check()        # existing (may accept effective_scope override)
  → allow / allow_narrowed / deny / audit
```

### Live recheck and performance

Trust scores can change during a session (e.g., an agent violates a policy and its score drops). The enforcement boundary must recheck trust at execution time.

**Event-driven invalidation (recommended approach).** Rather than zero caching (which creates lock contention under high concurrency) or TTL caching (which creates stale windows):

1. Cache the `AuthorityDecision` per agent with a short TTL (e.g., 5 seconds).
2. Have `TrustManager` emit a `TrustScoreDegraded` event that instantly invalidates the cache for that specific `agent_id`.
3. Score increases do NOT invalidate the cache (they can wait for TTL expiry). This is safe because delayed trust increases only restrict, never widen.
4. Revocation events always invalidate immediately.

**Full boundary cost.** The performance concern is not just trust score lookup (which is cheap). Full effective authority resolution includes delegation chain verification, revocation checks, capability matching, and audit logging. Mitigation: cache parsed policy structures and delegation chain validation results (these change infrequently), but never cache final authority decisions across actions beyond the event-invalidated TTL.

### Multi-step workflow behavior

Live rechecks can cause a multi-step workflow to partially complete if an agent's trust drops mid-execution.

**v1 position: per-action live recheck always wins.** Partial completion is the safer default. If an agent's trust drops between step 2 and step 3 of a workflow, step 3 is blocked. The agent receives a denial with an explanation. The partially completed state is the caller's responsibility to handle (rollback, retry, escalate).

This is an intentional safety tradeoff. The alternative — granting transactional authority snapshots — creates windows where degraded trust is ignored, which undermines the core principle.

### Trust score feedback isolation

When an action is denied due to trust-tier narrowing, that denial must NOT feed back into `TrustManager` as a "boundary violation" that further lowers the agent's score. Otherwise, a newly minted agent trying to do its job will get blocked, lose points for being blocked, and spiral to zero trust.

The feedback rule: only actions the agent actually *executed* (allowed or allow_narrowed) can produce trust score events. Denials at the authority gate are logged but do not affect the score.

### Data model

```python
@dataclass
class AuthorityDecision:
    decision: str  # "allow" | "allow_narrowed" | "deny" | "audit"
    effective_scope: list[str] = field(default_factory=list)
    effective_spend_limit: float | None = None
    narrowing_reason: str | None = None
    trust_tier: str = "unknown"
    timestamp: datetime = field(default_factory=datetime.utcnow)

@dataclass
class TierCapabilityConfig:
    tier_name: str
    score_range: tuple[int, int]
    allowed_capability_families: list[str]  # Expanded at policy load time
    max_spend_per_action: float | None
    default_enforcement_mode: str = "block"  # block | warn | audit
```

### Integration with existing AgentMesh components

| Component | Change Required |
|-----------|----------------|
| `identity/delegation.py` | Add lineage trust bound: child initial score = min(default, parent score) |
| `trust/scoring.py` | Add `TrustScoreDegraded` event emission on score decrease |
| `TrustManager` | Emit cache invalidation events; add `get_score_sync()` for non-async paths |
| `PolicyEngine` | Add `resolve_effective_authority()` in evaluation pipeline |
| `CapabilityModel` | Optional: accept `effective_scope` override from authority resolution |
| Trust feedback loop | Ensure authority-gate denials do not generate negative score events |

## Consequences

### What becomes easier

- **Progressive trust.** New agents start restricted and earn their way to full authority. No manual tier management needed.
- **Defense in depth.** Even if a delegation is overly broad (common in practice), trust scoring provides a second safety net.
- **Incident response.** Dropping an agent's trust score immediately restricts its authority without requiring delegation revocation.
- **Shadow mode deployment.** Operators can enable reputation-gating in audit mode to understand the impact before enforcing.
- **Sybil resistance.** Lineage-bound initial trust prevents trust washing through sub-agent spawning.

### What becomes harder

- **Full boundary evaluation cost.** Each action requires trust lookup, delegation verification, capability matching, and audit logging. Mitigation: event-driven cache invalidation for trust; cache parsed policy structures; never cache final decisions.
- **Debugging.** When an action is denied, the reason could be delegation scope, trust tier, or their intersection. The `AuthorityDecision` struct with `narrowing_reason` provides full explainability.
- **Configuration complexity.** Operators need to define tier-capability family mappings. Mitigation: ship illustrative defaults; require explicit configuration for production.
- **Partial workflow completion.** Multi-step operations may fail partway through if trust changes mid-execution. This is an intentional safety tradeoff.

### What this does NOT change

- Delegation chain semantics (narrowing, cascade revocation)
- Trust scoring algorithm (Bayesian model, score events)
- Policy engine rule evaluation logic
- Existing `CapabilityModel` enforcement

## Future Extensions

These are explicitly out of scope for v1 but are natural next steps:

- **Context-aware narrowing.** The resolution function accepts context (environment, resource sensitivity, time-of-day, incident mode). v1 does not use it. Future versions may map the same trust tier to different effective limits depending on context.
- **Recovery hysteresis.** v1 allows immediate upward recovery when trust score rises. Deployments may want cooldown periods, sticky downgrades, or manual approval for privilege restoration above certain thresholds.
- **Bounded transactional authority.** Short-TTL authority snapshots for multi-step workflows with mandatory audit trails.
- **Minimum trust for delegation creation.** Requiring a minimum trust tier to create (not just exercise) delegations. The runtime composition already limits some of this risk, but explicit creation gates add defense in depth.
- **Cross-protocol trust bridging.** Foreign trust scores as advisory input to local enforcement, with explicit trust translation policies.
- **Delegation chain lineage scoring.** Evaluate the trust score of the entire delegation chain, taking the minimum across all ancestors, for maximum Sybil resistance in deep delegation trees.

## Answers to Open Questions from #140

**Q1: Per-deployment or per-delegation tier mappings?**
Per-deployment for v1. Per-delegation mappings create too much policy surface and make debugging harder. Later, if needed, allow delegation metadata to reference a named policy profile rather than arbitrary inline mappings.

**Q2: Cross-mesh authority?**
Local enforcement boundary's trust score governs. Foreign trust scores can be input, signal, or evidence, but never override local enforcement. This is the zero-trust position.

**Q3: Minimum trust score for delegation creation?**
Out of scope for v1. The lineage-bound initial trust (Invariant 6) and runtime composition already limit the risk of low-trust agents creating powerful delegations. Explicit creation gates are a natural future extension.

## References

- Agent Passport System: `resolve_authority()` implementation — [source](https://github.com/aeoess/agent-passport-system)
- Monotonic Narrowing paper — [Zenodo](https://doi.org/10.5281/zenodo.18749779)
- AgentMesh trust scoring — `agent-governance-python/agent-mesh/docs/TRUST-SCORING.md`
- OWASP ASI-03 (Identity & Privilege Abuse) — directly addressed by this proposal
