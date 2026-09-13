---
title: "ADR 0033: DecisionAssure Impact – Counterfactual Governance Replay"
status: proposed
date: 2026-09-03
authors: ["@a1k7"]
---

# ADR 0033: DecisionAssure Impact – Counterfactual Governance Replay

## Context

AGT records decisions via `MerkleAuditChain` and `AuditEntry`, but does not
provide a way to predict the effect of governance changes on historical
decisions. This ADR introduces a standalone module, `agent-decisionassure`,
that replays recorded decision traces against proposed policy/authority
changes and quantifies the impact.

The module is a **new, optional package**. It does **not** modify
`agentmesh`, `agent_os`, or any existing governance interface. It consumes
JSONL trace files exported from AGT audit logs (a documented export format,
not the `AuditEntry` object model).

## Decision

Add `agent-governance-python/agent-decisionassure/` with:

- A **data DSL** for policy conditions (`all`/`any`/`not`/`eq`/`lte`/`in`/…).
  The DSL is pure data; it never executes Python.
- A **counterfactual replay engine** that evaluates each decision against a
  baseline and proposed governance state.
- A CLI (`decisionassure`) with `impact` and `detect-drift` subcommands.
- Fail-closed defaults: missing model, stale evidence, malformed policy, and
  empty input are treated as inadmissible / non-zero exit.
- Examples and fixtures under `examples/decisionassure/`.

## Consequences

- The module cannot regress existing behavior because it is a new package.
- Docs and DSL must stay in sync; the DSL is the only supported policy format.
- The module does not import or depend on `decisionassure_continuity`.

## Related

- ADR 0032 (TRACE v0.1)

## Signed-off-by

Akhilesh Warik <akhilesh.warik@example.com>
