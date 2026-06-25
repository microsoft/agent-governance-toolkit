# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""
Action Risk Classifier

Classifies actions into ring levels and risk weights.
"""

from __future__ import annotations

from dataclasses import dataclass

from hypervisor.models import ActionDescriptor, ExecutionRing, ReversibilityLevel


@dataclass
class ClassificationResult:
    """Result of classifying an action."""

    action_id: str
    ring: ExecutionRing
    risk_weight: float
    reversibility: ReversibilityLevel
    confidence: float = 1.0


class ActionClassifier:
    """
    Classifies actions into ring levels and risk weights.

    Classification rules:
    - Has Undo_API → reversible → Ring 2 minimum
    - No Undo_API + destructive → non-reversible → Ring 1 minimum
    - Config/admin operations → Ring 0
    - Read-only operations → Ring 3

    Classification is a pure function of the action's attributes, so results
    are not cached. action_id is not unique to a behaviour: distinct actions
    (e.g. a read-only fetch and a destructive admin op) can legitimately share
    a stable tool id, so caching on it risked leaking one action's
    ring/risk_weight label to a different action that reused its id. Computing
    the result on each call removes that hazard; session-level overrides are
    the only retained state.
    """

    def __init__(self) -> None:
        self._overrides: dict[str, ClassificationResult] = {}

    def classify(self, action: ActionDescriptor) -> ClassificationResult:
        """Classify an action.

        A session-level override for the action's id takes precedence;
        otherwise the result is computed directly from the action's
        attributes. Two actions sharing an id but differing in privilege are
        classified independently.
        """
        if action.action_id in self._overrides:
            return self._overrides[action.action_id]

        return ClassificationResult(
            action_id=action.action_id,
            ring=action.required_ring,
            risk_weight=action.risk_weight,
            reversibility=action.reversibility,
        )

    def set_override(
        self,
        action_id: str,
        ring: ExecutionRing | None = None,
        risk_weight: float | None = None,
    ) -> None:
        """Set a session-level override for action classification.

        The override is keyed on ``action_id`` and takes precedence over
        attribute-based classification, so it applies to EVERY action sharing
        this id. Unspecified ``ring``/``risk_weight`` fall back to
        RING_3_SANDBOX/0.5 and ``reversibility`` is always ``NONE``; pass both
        ``ring`` and ``risk_weight`` to pin a precise result.
        """
        self._overrides[action_id] = ClassificationResult(
            action_id=action_id,
            # Guard with `is not None`, not `or`: ExecutionRing.RING_0_ROOT == 0
            # and risk_weight 0.0 are falsy, so `x or default` would silently
            # drop a deliberate Ring 0 / zero-risk pin back to the default.
            ring=ring if ring is not None else ExecutionRing.RING_3_SANDBOX,
            risk_weight=risk_weight if risk_weight is not None else 0.5,
            reversibility=ReversibilityLevel.NONE,
            confidence=0.9,  # overrides have slightly lower confidence
        )
