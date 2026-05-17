# ADR 0015: Pluggable external policy backends via protocol interface

- Status: accepted
- Date: 2026-05-16

## Context

AGT's policy engine originally supported only native YAML/JSON rules. As
adoption grew, users needed to integrate existing policy investments written
in OPA/Rego and Cedar. The initial OPA and Cedar integrations used completely
different interfaces, return types, and method signatures, making it
impossible to write backend-agnostic governance code or add new backends
without reverse-engineering existing implementations.

A unified interface was needed so that: (1) YAML rules and external backends
compose cleanly in a single evaluation pipeline, (2) new backends can be added
without modifying the evaluator, and (3) backend results are normalized to a
common decision type with consistent audit metadata.

## Decision

Define `ExternalPolicyBackend` as a runtime-checkable Protocol with two
requirements: a `name` property returning a human-readable identifier, and an
`evaluate(context)` method accepting an execution context dict and returning a
`BackendDecision` dataclass. Backend results carry `allowed`, `action`,
`reason`, `backend` name, `evaluation_ms`, and an `error` field.

Backends are consulted only when no YAML rule matches. They are evaluated in
registration order and the first non-error result determines the decision.
Convenience methods (`load_rego()`, `load_cedar()`) simplify common setups.

## Consequences

Adding a new policy backend (e.g., Sentinel, custom gRPC service) requires
implementing a two-method protocol and registering it with the evaluator. No
core evaluator code changes are needed. The evaluation pipeline has a clear
priority order: YAML rules first, then external backends, then defaults. The
tradeoff is that all backends must normalize their native decision formats to
`BackendDecision`, which may lose backend-specific metadata unless it is
stashed in the audit entry.
