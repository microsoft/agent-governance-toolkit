# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Behavioral tests for post-execution accumulation and next-action gating."""

from agent_os.policies.context_accumulation import (
    ContextOutcome,
    accumulate,
    decide_next,
)
from agent_os.policies.context_aggregation import (
    AggregationRule,
    AggregationRuleSet,
)
from agent_os.policies.context_envelope import ContextEnvelope
from agent_os.policies.data_classification import DataClassification as DC

RULESET = AggregationRuleSet(
    rules=(
        AggregationRule(
            name="pii_financial_restricted",
            all_labels=frozenset({"pii", "financial"}),
            sets_sensitivity=DC.RESTRICTED,
            adds_restrictions=frozenset({"no_external_export"}),
        ),
    )
)


def _env(labels=frozenset(), sens=DC.INTERNAL, restrictions=frozenset()) -> ContextEnvelope:
    return ContextEnvelope(
        envelope_id="e",
        workflow_id="w",
        labels=frozenset(labels),
        aggregate_sensitivity=sens,
        restrictions=restrictions,
    )


def test_accumulate_folds_result_labels():
    e = _env({"pii"}, DC.INTERNAL)
    out = accumulate(e, {"financial"}, DC.CONFIDENTIAL, RULESET, n_category_threshold=99)
    assert "financial" in out.labels
    # rule fires once both labels present -> RESTRICTED + restriction
    assert out.aggregate_sensitivity == DC.RESTRICTED
    assert "no_external_export" in out.restrictions


def test_next_action_gated_on_accumulated_state():
    e = _env({"pii"}, DC.INTERNAL)
    acc = accumulate(e, {"financial"}, DC.CONFIDENTIAL, RULESET, 99)
    decision = decide_next(acc, "export", RULESET, 99)
    assert decision.outcome == ContextOutcome.CONSTRAIN
    assert any(o.key == "no_external_export" for o in decision.obligations.obligations)


def test_accumulation_never_lowers():
    e = _env({"pii"}, DC.RESTRICTED)
    out = accumulate(e, {"misc"}, DC.PUBLIC, RULESET, 99)
    assert out.aggregate_sensitivity == DC.RESTRICTED


def test_explicit_restriction_gates_below_floor():
    # An envelope holding `no_external_export` must gate `export` even when
    # aggregate sensitivity is BELOW the RESTRICTED floor (the restriction is a
    # hard constraint; it must not fail open below the floor).
    e = _env({"pii"}, sens=DC.CONFIDENTIAL, restrictions=frozenset({"no_external_export"}))
    decision = decide_next(e, "export", RULESET, 99)
    assert decision.outcome == ContextOutcome.CONSTRAIN


def test_floor_triggers_flow_action_without_explicit_restriction():
    # At/above the floor, a flow-bearing action with no explicit restriction is
    # still gated (defense in depth), not silently allowed.
    e = _env({"pii"}, sens=DC.RESTRICTED)
    decision = decide_next(e, "export", RULESET, 99)
    assert decision.outcome == ContextOutcome.CONSTRAIN


def test_floor_gated_decision_reports_newly_triggered_restrictions():
    # The labels satisfy the rule, but no accumulate() has run so the
    # restriction was never folded into the envelope. decide_next re-evaluates
    # aggregation, so the gate fires via the sensitivity floor -- and the
    # obligations must name the restriction the rule just triggered rather than
    # the envelope's (still empty) restriction set. Otherwise the caller is told
    # to constrain the action without being told what to satisfy.
    e = _env({"pii", "financial"}, sens=DC.CONFIDENTIAL)
    decision = decide_next(e, "export", RULESET, 99)
    assert decision.outcome == ContextOutcome.CONSTRAIN
    assert {o.key for o in decision.obligations.obligations} == {"no_external_export"}


def test_obligations_keep_envelope_restrictions_and_add_new_ones():
    # evaluate_aggregation seeds from env.restrictions before unioning rule
    # restrictions, so reading obligations off the aggregation result is a
    # superset -- an existing restriction is never dropped.
    e = _env({"pii", "financial"}, sens=DC.CONFIDENTIAL, restrictions=frozenset({"no_print"}))
    decision = decide_next(e, "export", RULESET, 99)
    assert {o.key for o in decision.obligations.obligations} == {
        "no_print",
        "no_external_export",
    }
