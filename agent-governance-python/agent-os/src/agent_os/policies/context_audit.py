# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Audit events for context envelope transitions.

Emits ``CONTEXT_*`` events describing how an envelope changed across an action
or delegation. A transition event is itself sensitive (it names which labels
and restrictions accumulated), so every event carries its own classification
floor — at least the envelope's aggregate sensitivity.
"""

from __future__ import annotations

from dataclasses import dataclass

from .context_envelope import ContextEnvelope
from .data_classification import DataClassification

CONTEXT_ENVELOPE_CREATED = "CONTEXT_ENVELOPE_CREATED"
CONTEXT_ENVELOPE_UPDATED = "CONTEXT_ENVELOPE_UPDATED"
CONTEXT_AGGREGATION_ELEVATED = "CONTEXT_AGGREGATION_ELEVATED"
CONTEXT_DELEGATED = "CONTEXT_DELEGATED"
CONTEXT_REDACTED = "CONTEXT_REDACTED"
DERIVED_ARTIFACT_LABELED = "DERIVED_ARTIFACT_LABELED"


@dataclass(frozen=True)
class ContextEvent:
    """A recorded transition between two envelope versions."""

    event_type: str
    agent_id: str
    context_envelope_id: str
    previous_sensitivity: DataClassification
    new_sensitivity: DataClassification
    labels_added: frozenset[str]
    rules_applied: tuple[str, ...]
    restrictions_added: frozenset[str]
    classification: DataClassification


def context_event(
    event_type: str,
    agent_id: str,
    before: ContextEnvelope,
    after: ContextEnvelope,
    rules_applied: tuple[str, ...] = (),
) -> ContextEvent:
    """Build a ``ContextEvent`` describing the transition ``before`` -> ``after``.

    The event's own ``classification`` is the max of the two envelopes'
    sensitivities, so the event is never less protected than the data it
    describes.
    """
    classification = max(before.aggregate_sensitivity, after.aggregate_sensitivity)
    return ContextEvent(
        event_type=event_type,
        agent_id=agent_id,
        context_envelope_id=after.envelope_id,
        previous_sensitivity=before.aggregate_sensitivity,
        new_sensitivity=after.aggregate_sensitivity,
        labels_added=after.labels - before.labels,
        rules_applied=rules_applied,
        restrictions_added=after.restrictions - before.restrictions,
        classification=classification,
    )
