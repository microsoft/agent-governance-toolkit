# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Aggregation evaluation for Context Accumulation Governance.

Applies organization-authored rules over *combinations* of accumulated labels,
plus a monotone backstop so that combinations not covered by a rule escalate for review
rather than passing silently. The framework supplies the evaluation hook; the
specific combination rules are authored per organization.

Aggregation (a collection of declared labels crossing a threshold) is distinct
from inference (semantic derivation of new sensitivity); this module governs
the former. Inference detection is out of scope for v1.
"""

from __future__ import annotations

from dataclasses import dataclass

from .context_envelope import ContextEnvelope
from .data_classification import DataClassification


@dataclass(frozen=True)
class AggregationRule:
    """One organization-authored rule over a label combination.

    When every label in ``all_labels`` is present in an envelope, the rule
    raises sensitivity to at least ``sets_sensitivity`` and adds
    ``adds_restrictions``.
    """

    name: str
    all_labels: frozenset[str]
    sets_sensitivity: DataClassification
    adds_restrictions: frozenset[str] = frozenset()


@dataclass(frozen=True)
class AggregationRuleSet:
    """An ordered collection of aggregation rules."""

    rules: tuple[AggregationRule, ...] = ()


@dataclass(frozen=True)
class AggregationResult:
    """Outcome of evaluating an envelope against a rule set."""

    aggregate_sensitivity: DataClassification
    restrictions: frozenset[str]
    escalate: bool
    rules_applied: tuple[str, ...]


def evaluate_aggregation(
    env: ContextEnvelope,
    ruleset: AggregationRuleSet,
    n_category_threshold: int,
) -> AggregationResult:
    """Evaluate ``env`` against ``ruleset`` and apply the monotone backstop.

    The result sensitivity is the max of the envelope's current sensitivity
    (already the running max of folded per-datum classifications) and every
    matching rule's ``sets_sensitivity`` — so an envelope that grows without
    crossing a declared combination keeps its current classification.

    Escalation fires when no rule governs the envelope yet it has accumulated
    at least ``n_category_threshold`` distinct labels — the conservative
    backstop for combinations not covered by a rule.
    """
    sensitivity = env.aggregate_sensitivity
    restrictions: set[str] = set(env.restrictions)
    applied: list[str] = []

    for rule in ruleset.rules:
        if rule.all_labels <= env.labels:
            sensitivity = max(sensitivity, rule.sets_sensitivity)
            restrictions |= set(rule.adds_restrictions)
            applied.append(rule.name)

    escalate = not applied and len(env.labels) >= n_category_threshold
    return AggregationResult(
        aggregate_sensitivity=sensitivity,
        restrictions=frozenset(restrictions),
        escalate=escalate,
        rules_applied=tuple(applied),
    )
