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
    """

    def __init__(self) -> None:
        self._cache: dict[str, ClassificationResult] = {}
        self._overrides: dict[str, ClassificationResult] = {}

    def classify(self, action: ActionDescriptor) -> ClassificationResult:
        """Classify an action and cache the result."""
        if action.action_id in self._overrides:
            return self._overrides[action.action_id]

        if action.action_id in self._cache:
            return self._cache[action.action_id]

        result = ClassificationResult(
            action_id=action.action_id,
            ring=action.required_ring,
            risk_weight=action.risk_weight,
            reversibility=action.reversibility,
        )
        self._cache[action.action_id] = result
        return result

    def set_override(
        self,
        action_id: str,
        ring: ExecutionRing | None = None,
        risk_weight: float | None = None,
    ) -> None:
        """Set a session-level override for action classification."""
        existing = self._cache.get(action_id)
        self._overrides[action_id] = ClassificationResult(
            action_id=action_id,
            ring=ring or (existing.ring if existing else ExecutionRing.RING_3_SANDBOX),
            risk_weight=risk_weight or (existing.risk_weight if existing else 0.5),
            reversibility=existing.reversibility if existing else ReversibilityLevel.NONE,
            confidence=0.9,  # overrides have slightly lower confidence
        )

    def clear_cache(self) -> None:
        """Clear classification cache (e.g., on manifest update)."""
        self._cache.clear()
