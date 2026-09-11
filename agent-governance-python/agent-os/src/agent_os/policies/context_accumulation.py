# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Post-execution accumulation and decision integration for CAG.

Sensitivity accumulates from the *actual* labels an action produced (its
``result_labels``), never from a projection of an output that has not run yet.
After folding, the next action is gated against the accumulated envelope.

The governance-level ``constrain`` outcome carries explicit obligations for the
host to enforce before the next action.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Iterable

from .context_aggregation import AggregationRuleSet, evaluate_aggregation
from .context_envelope import ContextEnvelope, apply_restrictions, fold
from .data_classification import DataClassification
from .obligations import Obligation, ObligationSet

# Action token -> the restriction that, when present, gates it.
_RESTRICTED_ACTIONS: dict[str, str] = {
    "export": "no_external_export",
    "delegate": "no_external_delegation",
    "memory_write": "no_memory_write",
}


class ContextOutcome(str, Enum):
    """Governance-level outcome of a context-aware decision."""

    ALLOW = "allow"
    CONSTRAIN = "constrain"
    DENY = "deny"
    ESCALATE = "escalate"


@dataclass(frozen=True)
class ContextDecision:
    """A context-aware decision plus any obligations it carries."""

    outcome: ContextOutcome
    obligations: ObligationSet
    aggregate_sensitivity: DataClassification
    reason: str = ""


def accumulate(
    env: ContextEnvelope,
    result_labels: Iterable[str],
    result_sensitivity: DataClassification,
    ruleset: AggregationRuleSet,
    n_category_threshold: int,
) -> ContextEnvelope:
    """Fold an action's actual result into ``env`` and re-run aggregation.

    Returns the next envelope with updated sensitivity and grow-only
    restrictions. This runs AFTER the action executes (post-execution
    accumulation), so it folds real labels rather than projected ones.
    """
    folded = fold(env, result_labels, result_sensitivity)
    agg = evaluate_aggregation(folded, ruleset, n_category_threshold)
    raised = replace(folded, aggregate_sensitivity=agg.aggregate_sensitivity)
    return apply_restrictions(raised, agg.restrictions)


def decide_next(
    env: ContextEnvelope,
    action: str,
    ruleset: AggregationRuleSet,
    n_category_threshold: int,
    restricted_floor: DataClassification = DataClassification.RESTRICTED,
) -> ContextDecision:
    """Gate ``action`` against the already-accumulated ``env``."""
    agg = evaluate_aggregation(env, ruleset, n_category_threshold)

    if agg.escalate:
        return ContextDecision(
            ContextOutcome.ESCALATE,
            ObligationSet(result_labels=env.labels),
            agg.aggregate_sensitivity,
            reason="aggregation threshold crossed with no governing rule",
        )

    gating = _RESTRICTED_ACTIONS.get(action)
    # An explicit restriction token is a HARD gate: it must be enforced
    # regardless of the current aggregate sensitivity and must never be
    # suppressed below the floor. The floor is an additional, independent
    # trigger for flow-bearing actions once sensitivity is high.
    #
    # Both the gate and the obligations read the *evaluated* restriction set,
    # not the envelope's. evaluate_aggregation seeds from env.restrictions, so
    # this is a superset -- it can only ever gate more, never less. Reading the
    # envelope here let a rule that adds a gating token without pushing
    # sensitivity to the floor slip through: the token existed in agg but not
    # yet in env, so neither trigger fired.
    effective_restrictions = agg.restrictions
    restriction_present = gating is not None and gating in effective_restrictions
    floor_triggered = gating is not None and agg.aggregate_sensitivity >= restricted_floor
    if restriction_present or floor_triggered:
        # A CONSTRAIN carrying no obligations is a no-op for any host that
        # enforces through them. When the floor fires on an envelope with no
        # restrictions recorded, the gating token for the action is the
        # constraint being applied, so name it.
        obligation_keys = set(effective_restrictions)
        if floor_triggered and gating is not None:
            obligation_keys.add(gating)
        obligations = ObligationSet(
            obligations=tuple(Obligation(key=r, satisfied=False) for r in sorted(obligation_keys)),
            result_labels=env.labels,
        )
        reason = (
            f"action {action!r} restricted by {gating!r}"
            if restriction_present
            else f"action {action!r} gated by sensitivity floor"
        )
        return ContextDecision(
            ContextOutcome.CONSTRAIN,
            obligations,
            agg.aggregate_sensitivity,
            reason=reason,
        )

    return ContextDecision(
        ContextOutcome.ALLOW,
        ObligationSet(result_labels=env.labels),
        agg.aggregate_sensitivity,
    )
