---
title: "2026-07-31 - Context accumulation: gate on evaluated restrictions (agent-os)"
last_reviewed: 2026-08-06
owner: agt-maintainers
---

# 2026-07-31 - Context accumulation: gate on evaluated restrictions (agent-os)

PR: microsoft/agent-governance-toolkit#3523

Follow-up to [`2026-06-03-context-accumulation-governance.md`](2026-06-03-context-accumulation-governance.md),
which introduced `decide_next`. This corrects two fail-open defects in that gate.

> These are the author's own security notes for the change - a **self-review,
> not an independent security audit**. The tests referenced under "Test
> coverage" ship in this same PR. Maintainer review is welcome, in particular
> on the compatibility judgement in the last section.

## What changed and why

`decide_next` re-runs `evaluate_aggregation` on the envelope, then gates the
requested action. Two of its three reads went to the wrong restriction set.

`evaluate_aggregation` seeds its result from `env.restrictions`
(`context_aggregation.py:72`) and then unions in the restrictions of every rule
whose labels match. So `agg.restrictions` is always a superset of
`env.restrictions`, and the two differ exactly when a rule fires during
`decide_next` that no prior `accumulate()` has folded into the envelope.

| Read | Before | After |
|------|--------|-------|
| Gate: is this action's restriction token present? | `env.restrictions` | `agg.restrictions` |
| Obligations attached to a `CONSTRAIN` | `env.restrictions` | `agg.restrictions`, plus the gating token when the floor is what fired |

### Defect 1: a rule-added restriction did not gate below the sensitivity floor

`decide_next` gates on two independent triggers: the action's restriction token
being present (a hard gate), or `aggregate_sensitivity` reaching
`restricted_floor` (RESTRICTED by default).

A rule that adds a gating token *without* lifting sensitivity to the floor
satisfied neither. The token was in `agg.restrictions` but not yet in
`env.restrictions`, so the hard gate did not see it; sensitivity was below the
floor, so the floor did not fire. The outcome was `ALLOW`.

This is reachable with a single ordinary rule. In the regression test, a
`{pii, location}` rule sets CONFIDENTIAL and adds `no_external_export`; an
`export` requested against that envelope was previously allowed, in spite of a
matching rule that exists to forbid exactly that.

It required no prior `accumulate()`, which is the normal state for the first
gated action in a workflow, and for any host that calls `decide_next` on an
envelope it assembled rather than one it accumulated.

### Defect 2: `CONSTRAIN` could carry zero obligations

When the sensitivity floor fired on an envelope with no restrictions recorded,
the decision was `CONSTRAIN` with an empty `ObligationSet`. Every governance
signal was present in `outcome` and `reason` only.

A host that enforces by iterating obligations - the contract the `constrain`
outcome exists to carry - had nothing to enforce and proceeded. The decision was
correct and unenforceable at the same time. `CONSTRAIN` now always names at
least the gating token for the action being constrained.

## Threat model impact

No new inputs, network exposure, secrets, or trust decisions. No default is
changed: `_RESTRICTED_ACTIONS`, `restricted_floor`, the rule schema and the
`ObligationSet` shape are all untouched. The change is 6 lines of policy logic.

| Dimension | Direction |
|-----------|-----------|
| Action gating | Fail-open to fail-closed. `restriction_present` can now be `True` where it was `False`; because `agg.restrictions ⊇ env.restrictions` it can never go the other way. `CONSTRAIN` can replace `ALLOW`; `ALLOW` can never replace `CONSTRAIN`. |
| Obligations | Strictly a superset, by the same containment. A key already emitted is never dropped and never substituted. An empty obligation set on a `CONSTRAIN` is no longer reachable. |
| Enforcement reachability | Strengthened. Defect 2 meant an obligation-driven host silently under-enforced a decision the policy engine had already made. |
| Escalation path | Untouched. The `agg.escalate` early return runs before this code and is unmodified. |
| Over-gating risk | The gate stays per-action: only the token `_RESTRICTED_ACTIONS` maps for the requested action can gate it. A restriction belonging to a different action does not constrain this one. Pinned by a test. |
| Untrusted input reachability | Unchanged. The labels and rules feeding `evaluate_aggregation` are the same values the pre-existing floor trigger already consumed; this change reads an existing result more completely, it does not widen what reaches the policy. |
| New attack surface | None. |

The direction is worth stating plainly: the risk in this PR is on the side of
constraining an action that previously ran, not of admitting one. The
`Refs`-only alternative - shipping the current behaviour - leaves an action that
a matching rule forbids in the `ALLOW` state.

## Test coverage

`agent-governance-python/agent-os/tests/policies`: **29 passed**.

Each regression test below was verified against the base `decide_next` by
reverting only `context_accumulation.py` to `origin/main`: 4 fail on base and
pass on the fix.

| Test | Validates | On base |
|------|-----------|---------|
| `test_rule_added_restriction_gates_below_the_floor` | Defect 1 directly: a rule adds `no_external_export` at CONFIDENTIAL, below the floor. `export` must be `CONSTRAIN`. | fails (`ALLOW`) |
| `test_floor_gated_decision_always_names_an_obligation` | Defect 2: floor fires with no accumulated restrictions; obligations must name the gating token. | fails (empty set) |
| `test_floor_gated_decision_reports_newly_triggered_restrictions` | Obligations name the restriction the rule just triggered, not the envelope's stale set. | fails |
| `test_obligations_keep_envelope_restrictions_and_add_new_ones` | The superset property: a pre-existing envelope restriction survives alongside a newly triggered one. | fails |
| `test_unrelated_action_is_not_gated_by_someone_elses_restriction` | The gate stays per-action - a non-matching restriction token must not constrain `memory_write`. | passes (guards against over-gating introduced here) |

The six pre-existing tests in the module - including
`test_floor_triggers_flow_action_without_explicit_restriction`, which pins the
floor trigger itself - are unmodified and still pass.

## Compatibility

Flagged High by the breaking-change detector on both reads, correctly: this is
an observable behaviour change in a public function. Both changes are monotone
in the safe direction, so the surface that breaks is narrow and specific - code
depending on the under-enforcement:

1. A caller asserting an exact obligation set that could previously be empty.
   That assertion encodes "gated, with nothing to satisfy".
2. A caller relying on `ALLOW` for an action whose gating token a rule had
   already added below the floor.

For a governance policy both read as bugs rather than contracts, but that is a
maintainer call. The two changes are separable if they warrant different
timelines: the gate fix (defect 1) and the never-empty obligation set (defect 2)
touch adjacent but independent lines.
