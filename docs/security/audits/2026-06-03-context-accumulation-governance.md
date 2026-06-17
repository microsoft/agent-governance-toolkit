# 2026-06-03 - Context Accumulation Governance (v1)

PR: feat: govern accumulated context across delegated agent workflows (#2800)

Closes #2797.

> These are the author's own security design notes and threat model for the
> change — a **self-review, not an independent security audit**. The "Test
> coverage" column references tests that ship in this same PR. An independent
> review by a second maintainer is welcome.
>
> The full design rationale and threat model live in
> [`../context-accumulation-governance.md`](../context-accumulation-governance.md);
> this file is the dated audit-gate record and summarizes the same content.

## What changed and why

Adds a first cut of context accumulation governance: a `ContextEnvelope` that
tracks the labels and sensitivity a workflow has accumulated and gates later
actions and delegations against that running state, rather than evaluating each
action in isolation. This closes the gap where individually permitted actions
aggregate into sensitive context, and where a delegated agent can quietly lose
the constraints its parent carried.

New types and helpers (`agent_os.policies`):

- `ContextEnvelope`: immutable, versioned value. Aggregate sensitivity is a
  max-lattice over the existing `DataClassification`; restrictions are a
  grow-only set.
- `evaluate_aggregation` plus `AggregationRule`/`AggregationRuleSet`:
  organization-authored rules over label combinations, with a monotone backstop
  that escalates combinations no rule covers.
- `accumulate`, `decide_next`, `to_policy_action` (`context_accumulation`):
  post-execution accumulation of an action's actual `result_labels`, then gating
  of the next action.
- `Obligation`/`ObligationSet`: the obligations a `constrain` outcome carries
  forward.
- `merge_restrictions` (`context_delegation`) and the additive
  `DelegationChain.effective_restrictions`: grow-only restriction inheritance on
  delegation (a **union** of parent + child-declared restrictions).
- `context_event` plus `CONTEXT_*` kinds (`context_audit`): transition events,
  each classified at least as high as the envelope it describes.

Reuses the existing `DataClassification`/`DataLabel`/`ABACPolicy` types and the
policy-engine `result_labels`, and adds no new dependencies.

## Threat model impact

This is a governance control, so the relevant risk is whether the control can
fail open or silently weaken an existing guarantee, not classic injection or
memory safety. A pure-logic review (no subprocess, deserialization, filesystem,
network, or crypto in any new file) confirmed no classic vulnerability surface.

| Risk | Mitigation | Test coverage (this PR) |
|------|-----------|-------------|
| Constrain allows without an obligation channel | `to_policy_action` maps constrain to DENY absent a channel | `test_python_path_constrain_fails_closed` |
| Empty obligation set grants allow via vacuous truth | Empty obligations do not satisfy the allow condition | `test_empty_obligation_constrain_fails_closed` |
| Explicit restriction ignored below the floor | A present restriction gates regardless of sensitivity | `test_explicit_restriction_gates_below_floor` |
| Aggregate sensitivity lowered | Max-lattice join never decreases | `test_sensitivity_is_max_lattice`, `test_accumulation_never_lowers` |
| Delegated child drops a parent restriction | Grow-only union on inheritance | `test_child_cannot_drop_parent_restriction`, `test_effective_restrictions_union_along_chain` |
| Combination not covered by a rule slips through | Monotone backstop escalates for review | `test_backstop_escalates_on_n_distinct_categories` |
| `validate()` behavior regressed | Additive method only; validate untouched | `test_validate_signature_and_reasons_unchanged` plus the existing `test_structural_authz.py` suite |

### Out of scope for this first cut

The control governs non-adversarial aggregation within instrumented,
single-writer, in-process paths. These are deliberately deferred and documented
so a deployer does not over-rely on the guarantees:

- Accumulation across sibling agents, sessions, or separate workflows (needs a
  per-principal register).
- Signing and versioning envelopes that cross a trust boundary; until that
  exists, anything riding on an envelope across the mesh is advisory.
- Labeling on ingest to catch laundering through an unlabeled store or by
  paraphrasing restricted content into new text.
- Detecting an undeclared sensitive inference, which is undecidable in general.
  An artifact produced while the envelope is already sensitive inherits that
  classification.

### Existing security properties preserved

- `DelegationChain.validate()` and its scope, cycle, expiry, and signature
  checks are unchanged; the existing delegation test suite stays green.
- No new dependencies, no network or filesystem access, no crypto or secret
  handling in any new file.
- The envelope stores category labels and classification levels, not raw
  personal data, which keeps its own confidentiality footprint small.

## Test coverage

- 24 new unit tests across the envelope laws (commutative and idempotent
  folding, sensitivity never lowers, restrictions never drop), aggregation and
  the escalation backstop, the fail-closed `constrain` mapping, delegation
  restriction inheritance, and audit event shape.
- The existing `DelegationChain` suite (`test_structural_authz.py`) runs as a
  regression gate and stays green, with an explicit test that `validate()`'s
  return shape and reason strings are unchanged.
- 181 existing policy tests confirm the new package exports do not break
  existing importers.
- All tests run in standard CI with no special hardware or external services.
