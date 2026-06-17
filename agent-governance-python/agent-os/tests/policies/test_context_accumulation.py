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
