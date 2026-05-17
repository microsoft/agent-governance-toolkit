# ADR 0013: Fail closed on policy evaluation errors

- Status: accepted
- Date: 2026-04-10

## Context

The policy engine evaluates governance rules against agent actions at runtime.
When evaluation encounters an unexpected error (malformed context, backend
timeout, regex compilation failure, or any unhandled exception), the engine
must choose between two failure modes: fail-open (allow the action) or
fail-closed (deny the action).

Fail-open is simpler and avoids false-positive denials, but it creates an
exploitable attack surface. An adversary who can trigger evaluation errors
(e.g., by injecting malformed context fields or causing resource exhaustion)
could bypass all governance controls. In enterprise and multi-tenant
deployments, a single fail-open path can undermine the entire trust model.

## Decision

The policy engine fails closed on all evaluation errors. Any unhandled
exception during rule matching, backend consultation, or condition evaluation
results in an immediate deny with action `"deny"`, a reason indicating policy
evaluation error, and an audit entry with `error: true`. The exception is
logged at ERROR level with full stack trace and context snapshot.

This applies uniformly to flat evaluation, folder-scoped evaluation, and
external backend consultation. There are no configuration flags to switch to
fail-open behavior.

## Consequences

Governance guarantees are maintained even during partial system failures.
Operators can trust that a passing policy check genuinely means the rules were
evaluated, not that evaluation was skipped due to an error. The tradeoff is
that bugs in policy configuration (e.g., invalid regex patterns, misconfigured
backends) will cause legitimate actions to be denied until the configuration is
fixed. This is acceptable because it creates immediate, visible feedback that
drives rapid correction, whereas fail-open errors are silent and may go
undetected.
