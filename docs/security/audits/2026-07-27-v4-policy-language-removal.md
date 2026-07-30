# 2026-07-27 — Removing the v4 policy language

PR: [microsoft/agent-governance-toolkit#3444](https://github.com/microsoft/agent-governance-toolkit/pull/3444)

## What changed and why

The ACS port left a compatibility bridge in place. Callers could still author a
v4 policy document, and the bridge translated it into an ACS v5 manifest at
evaluation time. Two policy languages were live at once: the ACS manifest the
engine evaluates, and the v4 document the bridge accepted on its behalf.

This change deletes the bridge and moves every runtime caller onto ACS. The
adapters, the policy result model, and the mesh and compliance call sites now
build ACS input directly. The v4 syntax survives in one place: the one-way tool
that converts a v4 manifest to ACS v5.

## Threat model impact

A translation layer in front of an authorization decision is a trust boundary.
The bridge had to reproduce the engine's semantics for every field it mapped,
and any drift between the two became an authorization difference that no single
test suite covered: a policy could deny through the ACS path and allow through
the bridge, or the reverse. Removing the bridge removes that class of
divergence, because there is now one path from policy text to verdict.

The change does not widen any surface. It deletes code and narrows what the
runtime accepts. Input that used to be accepted as a v4 document is now
rejected before evaluation rather than translated, which fails closed.

The migration resolver is the one component that still reads v4 input. It moves
under the CLI as a private package so the runtime cannot import it, and a test
asserts that boundary. It runs offline against files the user already has, and
it produces a manifest for review; it never participates in an authorization
decision.

### Fail-closed behavior

Default-deny is unchanged. The adapters present the pre-attempt tool-call count
to the budget evaluator, so a call that would exceed a budget is denied before
it runs rather than counted after. Denials still raise through the same
exception path the adapters used before.

## Test coverage

- Adapter mediation contracts assert that every adapter routes through the
  native session and surfaces denials, per intervention point.
- Scenario suites cover allow, deny, and transform outcomes for each adapter
  against real ACS manifests evaluated by the engine.
- `test_migration_boundary.py` asserts the migration resolver is not importable
  from the runtime package.
- The removal ratchet counts every surviving v4 marker in the tree and fails if
  the count rises. It reaches zero in this stack, so no non-migration file can
  reintroduce v4 policy language without failing CI.

## Residual risk

Consumers pinned to the v4 document format break at upgrade. That is the
intended breaking change; `BREAKING_CHANGES.md` lists each removed symbol and
its replacement, and `agt migrate` converts existing manifests.
