# ADR 0016: Trust ceiling propagation for delegated agents

- Status: accepted
- Date: 2026-05-16

## Context

AgentMesh uses numeric trust scores (0-1000) to gate agent capabilities.
When a parent agent delegates work to a child agent, the child previously
started at the default score (500) and could potentially reach 1000 through
good behavior. This broke the principle that delegated authority should never
exceed the delegator's own authority: a parent with trust 300 could spawn a
child that accumulates higher trust than the parent itself.

This is analogous to capability-based security systems where a process cannot
grant more capabilities than it holds. Without ceiling propagation, the
delegation chain becomes a privilege escalation vector.

## Decision

Trust ceiling propagation is enforced on all delegation paths. When a parent
agent delegates to a child, the parent's current trust score becomes a hard
ceiling on the child's trust. The child's initial score is clamped to
`min(initial_score, ceiling)`, and all subsequent score updates respect the
ceiling as an upper bound.

For multi-level delegation, ceilings propagate monotonically: each level takes
`min(parent_ceiling, requested_ceiling)`, ensuring trust can only narrow as
delegation depth increases.

The ceiling can also be set via the `AGT_TRUST_CEILING` environment variable
for containerized deployments where the orchestrator sets trust boundaries at
the infrastructure level.

## Consequences

Delegation chains cannot be used for privilege escalation. A child agent's
trust is always bounded by its parent's trust at delegation time. The tradeoff
is that child agents in trusted environments may be artificially constrained
if their parent happens to have a low score. This is acceptable because the
alternative (unbounded child trust) is a security violation, and operators can
adjust parent scores or set explicit ceilings when higher child trust is
genuinely needed.
