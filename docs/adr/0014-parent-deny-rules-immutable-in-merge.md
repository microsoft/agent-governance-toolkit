# ADR 0014: Parent deny rules are immutable in policy merge

- Status: accepted
- Date: 2026-04-10

## Context

AGT supports folder-level governance policies where child directories can
refine or specialize parent policies. During merge, a child rule with
`override: true` and the same name as a parent rule replaces the parent.
This raises a security question: should a child policy be able to override a
parent deny rule with an allow?

In Azure Policy, deny assignments are immutable at a given scope. XACML
deny-overrides is a standard combining algorithm that prevents lower-priority
allow rules from defeating higher-scoped denies. The principle is the same:
security-critical restrictions set at a higher organizational level should
not be circumventable by more specific policies.

Without this invariant, a team-level `governance.yaml` could neutralize an
org-level deny by declaring `override: true` with a higher priority, defeating
the purpose of centralized security governance.

## Decision

Parent deny rules cannot be overridden by child rules during folder-level
policy merge. When a child rule declares `override: true` with the same name
as a parent deny rule, the child rule is silently dropped and a warning is
logged. The parent deny remains in effect regardless of the child's priority
value.

This invariant is enforced in the `merge_policies()` function and is tested by
the spec conformance suite.

## Consequences

Organizations can set security boundaries at the root level with confidence
that no subdirectory policy can weaken them. The tradeoff is reduced
flexibility: if a team legitimately needs an exception to an org-level deny,
the exception must be granted at the org level itself (by modifying the parent
policy), not worked around at the team level. This is intentional and follows
the principle of least surprise for security-critical governance.
