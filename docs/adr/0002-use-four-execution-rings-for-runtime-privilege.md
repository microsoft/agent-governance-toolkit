# ADR 0002: Use four execution rings instead of RBAC for runtime privilege

- Status: accepted
- Date: 2026-03-26

## Context

The runtime needs to decide what an agent may do while code is executing, not
just what role it belongs to. Repository docs describe a four-ring model with a
default sandbox tier, trust-score thresholds, rate limits, reversible versus
non-reversible actions, and temporary elevation for exceptional cases. RBAC
still exists elsewhere in the repository for human-facing administration,
compliance mappings, and IATP scopes, but static roles alone do not model
runtime risk, reversibility, or trust decay. The runtime needs a smaller,
predictable privilege lattice that maps directly to blast radius.

## Decision

Use four execution rings as the primary runtime privilege model. Preserve RBAC
and scoped capabilities as complementary controls, but do not make them the
main mechanism for sandboxing live agent execution.

## Consequences

The runtime can express graduated access, safe defaults for unknown agents, and
clear escalation rules without inventing many agent-specific roles. That makes
policy explanations and breach detection simpler. The tradeoff is that rings are
coarser than full role modeling, so detailed authorization still has to be
handled by capability policies, scopes, and approval workflows layered on top.
