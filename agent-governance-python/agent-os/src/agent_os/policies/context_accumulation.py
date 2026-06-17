# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Post-execution accumulation and decision integration for CAG.

Sensitivity accumulates from the *actual* labels an action produced (its
``result_labels``), never from a projection of an output that has not run yet.
After folding, the next action is gated against the accumulated envelope.

The governance-level ``constrain`` outcome is realized as allow-with-obligations
and collapses to a concrete ``PolicyAction`` via :func:`to_policy_action`, which
fails closed on a path that cannot carry obligations.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from typing import Iterable

from .context_aggregation import AggregationRuleSet, evaluate_aggregation
from .context_envelope import ContextEnvelope, apply_restrictions, fold
from .data_classification import DataClassification
from .obligations import Obligation, ObligationSet
from .schema import PolicyAction

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
    restriction_present = gating is not None and gating in env.restrictions
    floor_triggered = gating is not None and agg.aggregate_sensitivity >= restricted_floor
    if restriction_present or floor_triggered:
        obligations = ObligationSet(
            obligations=tuple(
                Obligation(key=r, satisfied=False) for r in sorted(env.restrictions)
            ),
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


def to_policy_action(
    decision: ContextDecision,
    has_obligation_channel: bool,
) -> PolicyAction:
    """Collapse a ``ContextDecision`` onto the declarative ``PolicyAction`` enum.

    ``PolicyAction`` has no ``constrain`` member and no obligation channel of
    its own, so ``constrain`` maps to ``ALLOW`` only when the host can carry the
    obligations (``has_obligation_channel``) or every obligation is already
    satisfied; otherwise it FAILS CLOSED to ``DENY``. ``escalate`` maps to
    ``BLOCK`` (the nearest stop-and-review action on this path).
    """
    if decision.outcome == ContextOutcome.ALLOW:
        return PolicyAction.ALLOW
    if decision.outcome == ContextOutcome.DENY:
        return PolicyAction.DENY
    if decision.outcome == ContextOutcome.ESCALATE:
        return PolicyAction.BLOCK
    # CONSTRAIN: allow only if the host can carry the obligations, or every
    # obligation is already satisfied. An EMPTY obligation set does not grant
    # allow on a channel-less path (vacuous all_satisfied must not fail open).
    if has_obligation_channel:
        return PolicyAction.ALLOW
    if decision.obligations.obligations and decision.obligations.all_satisfied:
        return PolicyAction.ALLOW
    return PolicyAction.DENY
