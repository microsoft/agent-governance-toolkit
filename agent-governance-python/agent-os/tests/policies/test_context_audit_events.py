# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Behavioral tests for context transition audit events."""

from agent_os.policies.context_audit import (
    CONTEXT_AGGREGATION_ELEVATED,
    CONTEXT_ENVELOPE_UPDATED,
    context_event,
)
from agent_os.policies.context_envelope import ContextEnvelope
from agent_os.policies.data_classification import DataClassification as DC


def test_aggregation_elevated_event_shape():
    before = ContextEnvelope(
        envelope_id="e",
        workflow_id="w",
        labels=frozenset({"pii"}),
        aggregate_sensitivity=DC.CONFIDENTIAL,
    )
    after = ContextEnvelope(
        envelope_id="e",
        workflow_id="w",
        labels=frozenset({"pii", "financial"}),
        aggregate_sensitivity=DC.RESTRICTED,
        restrictions=frozenset({"no_external_export"}),
    )
    ev = context_event(
        CONTEXT_AGGREGATION_ELEVATED,
        "agent.customer-success",
        before,
        after,
        rules_applied=("pii_financial_restricted",),
    )
    assert ev.previous_sensitivity == DC.CONFIDENTIAL
    assert ev.new_sensitivity == DC.RESTRICTED
    assert ev.labels_added == frozenset({"financial"})
    assert ev.restrictions_added == frozenset({"no_external_export"})
    assert ev.rules_applied == ("pii_financial_restricted",)


def test_event_carries_classification_floor():
    before = ContextEnvelope(
        envelope_id="e", workflow_id="w", aggregate_sensitivity=DC.CONFIDENTIAL
    )
    after = ContextEnvelope(
        envelope_id="e", workflow_id="w", aggregate_sensitivity=DC.RESTRICTED
    )
    ev = context_event(CONTEXT_ENVELOPE_UPDATED, "a", before, after)
    assert ev.classification >= after.aggregate_sensitivity
