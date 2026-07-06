# Security Design Notes: Context Accumulation Governance (v1)

**Date:** 2026-06-03
**PR:** feat: govern accumulated context across delegated agent workflows
**Scope:** `agent_os.policies.context_envelope`, `context_aggregation`, `context_accumulation`, `obligations`, `context_delegation`, `context_audit`; `structural_authz_agentmesh.trust.DelegationChain.effective_restrictions`
**Author:** Knapp-Kevin

> These are the author's own security design notes and threat model for the
> change — a self-review, not an independent security audit. The "Test coverage"
> column references tests that ship in this same PR. An independent review by a
> second maintainer is welcome and has not yet taken place.

## What changed and why

Adds a first cut of context accumulation governance: a `ContextEnvelope` that tracks the labels and sensitivity a workflow has accumulated and gates later actions and delegations against that running state, rather than evaluating each action in isolation. This closes the gap where individually permitted actions aggregate into sensitive context, and where a delegated agent can quietly lose the constraints its parent carried.

New types and helpers:

- `ContextEnvelope`: immutable, versioned value. Aggregate sensitivity is a max-lattice over the existing `DataClassification`; restrictions are a grow-only set.
- `evaluate_aggregation` plus `AggregationRule`/`AggregationRuleSet`: organization-authored rules over label combinations, with a monotone backstop that escalates combinations no rule covers.
- `accumulate`, `decide_next`, `to_policy_action` (`context_accumulation`): post-execution accumulation of an action's actual `result_labels`, then gating of the next action.
- `Obligation`/`ObligationSet`: the obligations a `constrain` outcome carries forward.
- `merge_restrictions` (`context_delegation`) and the additive `DelegationChain.effective_restrictions`: grow-only restriction inheritance on delegation.
- `context_event` plus `CONTEXT_*` kinds (`context_audit`): transition events, each classified at the envelope sensitivity.

The change reuses the existing `DataClassification`/`DataLabel`/`ABACPolicy` types and the policy-engine `result_labels`, and adds no new dependencies.

## Threat model impact

This is a governance control, so the relevant risk is whether the control can fail open or silently weaken an existing guarantee, not classic injection or memory safety. A pure-logic review (no subprocess, deserialization, filesystem, network, or crypto in any new file) confirmed no classic vulnerability surface.

### New attack surface and mitigations

1. **Constrain fails open on a path that cannot carry obligations.** The declarative `PolicyAction` enum has no obligation channel, so a `constrain` outcome could degrade to allow.

   **Mitigation:** `to_policy_action` maps `constrain` to `DENY` when there is no obligation channel, and the empty `ObligationSet` case is guarded so that a vacuous `all_satisfied` cannot grant allow. Fail-closed by construction.

2. **An explicit restriction is ignored below a sensitivity threshold.** An envelope can hold a hard restriction (for example `no_external_export`) while aggregate sensitivity sits below the configured floor.

   **Mitigation:** a present restriction gates its action regardless of sensitivity. The floor is an additional, independent trigger, never a suppressor of an explicit restriction.

3. **Sensitivity is lowered during accumulation.** A later low-sensitivity input could otherwise reduce the envelope classification.

   **Mitigation:** aggregate sensitivity is a max-lattice over `DataClassification`. Folding and aggregation only ever raise it.

4. **A delegated child drops a parent restriction.** A child could otherwise escape a restriction the parent carried.

   **Mitigation:** restriction inheritance is a grow-only union (parent restrictions plus child-declared). A child can add but never remove.

5. **Regression of the existing delegation validator.** Restriction inheritance is added near `DelegationChain.validate()`.

   **Mitigation:** the inheritance logic is a new, separate method (`effective_restrictions`) and a pure free function. `validate()` is unchanged byte for byte; its signature, return type, and reason strings are asserted unchanged by test.

### Out of scope for this first cut

The control governs non-adversarial aggregation within instrumented, single-writer, in-process paths. The following are deliberately deferred and documented so a deployer does not over-rely on the guarantees:

- Accumulation across sibling agents, sessions, or separate workflows (needs a per-principal register).
- Labeling on ingest to catch laundering through an unlabeled store or by paraphrasing restricted content into new text.
- Detecting an undeclared sensitive inference, which is undecidable in general. An artifact produced while the envelope is already sensitive inherits that classification.

#### Envelope to evidence-receipt boundary

Signed and versioned envelopes across a trust boundary are deferred; until they exist, anything riding on an envelope across the mesh is advisory, since a peer could present a weaker one. The shape of that boundary, however, is settled. A receipt that references governance context holds an opaque `envelope_id` plus at most a coarse, non-sensitive sensitivity tier or governance label — never the envelope contents. The `envelope_reference` helper is the sanctioned projection: it carries only the id and the aggregate-sensitivity tier, so the in-process `ContextEnvelope` shape can evolve without changing what a receipt commits to. The issuer of the reference owns retention and resolvability; a consumer that hits an expired or unresolved reference treats that as a verification outcome, not a receipt-schema failure. The cross-boundary work is therefore a *responsibilities contract* — issuer identity, version and monotonicity assertion, replay and downgrade rejection, and where verification happens — rather than a serialized downstream schema. Holding the id opaque keeps the receipt a small, stable join point and leaves AGT free to define the envelope shape internally.

#### Envelope lifecycle and retention (open)

The version chain is not assumed unbounded, and the accumulated chain is itself a sensitive artifact (it is simultaneously the best audit trail and the softest target). This first cut does not settle a lifecycle, but it leaves room for one. The ratchet is a property of the head: the latest version already carries the joined labels, sensitivity, and grow-only restrictions, so intermediate versions can be compacted without changing what gets enforced, and keeping the full trail becomes an audit choice rather than a correctness requirement. Declassification steps act as compaction boundaries — compacting across one would resurrect what the downgrade removed — so a downgrade is a hard boundary for any future pruning. The minimum that must survive pruning is the active restrictions plus a reason anchor that explains why each restriction holds. A checkpoint that folds a prefix needs a *verifiable* summary of what it folds, not merely a signature attesting who wrote it; signing proves authorship, not faithfulness. No compaction or checkpoint record is implemented here; this is a documented extension point so the schema is not committed to an unbounded chain.

### Existing security properties preserved

- `DelegationChain.validate()` and its scope, cycle, expiry, and signature checks are unchanged; the existing delegation test suite stays green.
- No new dependencies, no network or filesystem access, no crypto or secret handling in any new file.
- The envelope stores category labels and classification levels, not raw personal data, which keeps its own confidentiality footprint small.

## Mitigations

| Risk | Mitigation | Test coverage (this PR) |
|------|-----------|-------------|
| Constrain allows without an obligation channel | `to_policy_action` maps constrain to DENY absent a channel | `test_python_path_constrain_fails_closed` |
| Empty obligation set grants allow via vacuous truth | Empty obligations do not satisfy the allow condition | `test_empty_obligation_constrain_fails_closed` |
| Explicit restriction ignored below the floor | A present restriction gates regardless of sensitivity | `test_explicit_restriction_gates_below_floor` |
| Aggregate sensitivity lowered | Max-lattice join never decreases | `test_sensitivity_is_max_lattice`, `test_accumulation_never_lowers` |
| Delegated child drops a parent restriction | Grow-only union on inheritance | `test_child_cannot_drop_parent_restriction`, `test_effective_restrictions_union_along_chain` |
| Combination not covered by a rule slips through | Monotone backstop escalates for review | `test_backstop_escalates_on_n_distinct_categories` |
| `validate()` behavior regressed | Additive method only; validate untouched | `test_validate_signature_and_reasons_unchanged` plus the existing `test_structural_authz.py` suite |

## Test coverage

- 24 new unit tests across the envelope laws (commutative and idempotent folding, sensitivity never lowers, restrictions never drop), aggregation and the escalation backstop, the fail-closed `constrain` mapping, delegation restriction inheritance, and audit event shape.
- The existing `DelegationChain` suite (`test_structural_authz.py`) runs as a regression gate and stays green, with an explicit test that `validate()`'s return shape and reason strings are unchanged.
- 181 existing policy tests confirm the new package exports do not break existing importers.
- All tests run in standard CI with no special hardware or external services.
