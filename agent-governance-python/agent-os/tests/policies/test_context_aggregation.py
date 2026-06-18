# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Behavioral tests for aggregation evaluation and the monotone backstop."""

from agent_os.policies.context_aggregation import (
    AggregationRule,
    AggregationRuleSet,
    evaluate_aggregation,
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


def _env(labels, sens=DC.INTERNAL, restrictions=frozenset()) -> ContextEnvelope:
    return ContextEnvelope(
        envelope_id="e",
        workflow_id="w",
        labels=frozenset(labels),
        aggregate_sensitivity=sens,
        restrictions=restrictions,
    )


def test_rule_fires_on_label_combination():
    res = evaluate_aggregation(_env({"pii", "financial"}), RULESET, n_category_threshold=99)
    assert res.aggregate_sensitivity == DC.RESTRICTED
    assert "no_external_export" in res.restrictions
    assert "pii_financial_restricted" in res.rules_applied


def test_growth_without_rule_keeps_classification():
    # rule needs pii+financial; envelope has pii+behavioral -> no match
    res = evaluate_aggregation(_env({"pii", "behavioral"}, sens=DC.INTERNAL), RULESET, 99)
    assert res.aggregate_sensitivity == DC.INTERNAL
    assert res.rules_applied == ()


def test_monotone_backstop_floor():
    res = evaluate_aggregation(_env({"x"}, sens=DC.CONFIDENTIAL), RULESET, 99)
    assert res.aggregate_sensitivity >= DC.CONFIDENTIAL


def test_backstop_escalates_on_n_distinct_categories():
    res = evaluate_aggregation(_env({"a", "b", "c"}, sens=DC.INTERNAL), RULESET, n_category_threshold=3)
    assert res.escalate is True
