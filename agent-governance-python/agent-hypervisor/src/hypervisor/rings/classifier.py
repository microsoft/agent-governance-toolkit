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

# A classification is fully determined by these four fields, so they form the
# cache key. See ActionClassifier.classify for why action_id alone is unsafe.
_CacheKey = tuple[str, ExecutionRing, float, ReversibilityLevel]


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

    # The cache is keyed on the full classification fingerprint rather than on
    # action_id alone. action_id is not unique to a behaviour: distinct actions
    # (e.g. a read-only fetch and a destructive admin op) can legitimately share
    # a stable tool id. Keying on the fields that fully determine the result
    # guarantees a cache hit only when the produced classification is identical,
    # so one action's ring/risk_weight label can never leak to a different action
    # that happens to reuse its id (e.g. a destructive op inheriting a prior
    # read-only RING_3_SANDBOX/0.2 entry, or the reverse).
    def __init__(self) -> None:
        self._cache: dict[_CacheKey, ClassificationResult] = {}
        self._overrides: dict[str, ClassificationResult] = {}

    @staticmethod
    def _cache_key(action: ActionDescriptor) -> _CacheKey:
        """Build the fingerprint that fully determines an action's classification."""
        return (
            action.action_id,
            action.required_ring,
            action.risk_weight,
            action.reversibility,
        )

    def _cached_for_id(self, action_id: str) -> ClassificationResult | None:
        """Return the most recently cached result for ``action_id``, if any.

        Used by overrides, which are keyed on action_id rather than on the full
        fingerprint. When multiple attribute variants share an id, the latest is
        returned.
        """
        latest: ClassificationResult | None = None
        for result in self._cache.values():
            if result.action_id == action_id:
                latest = result
        return latest

    def classify(self, action: ActionDescriptor) -> ClassificationResult:
        """Classify an action and cache the result.

        The cache key is the action's classification fingerprint, not its
        action_id, so two actions sharing an id but differing in privilege are
        classified independently. Callers do not need to call ``clear_cache()``
        to avoid stale results after an action's attributes change.
        """
        if action.action_id in self._overrides:
            return self._overrides[action.action_id]

        key = self._cache_key(action)
        cached = self._cache.get(key)
        if cached is not None:
            return cached

        result = ClassificationResult(
            action_id=action.action_id,
            ring=action.required_ring,
            risk_weight=action.risk_weight,
            reversibility=action.reversibility,
        )
        self._cache[key] = result
        return result

    def set_override(
        self,
        action_id: str,
        ring: ExecutionRing | None = None,
        risk_weight: float | None = None,
    ) -> None:
        """Set a session-level override for action classification."""
        existing = self._cached_for_id(action_id)
        self._overrides[action_id] = ClassificationResult(
            action_id=action_id,
            # Guard with `is not None`, not `or`: ExecutionRing.RING_0_ROOT == 0
            # and risk_weight 0.0 are falsy, so `x or default` would silently
            # drop a deliberate Ring 0 / zero-risk pin back to the default.
            ring=ring if ring is not None else (existing.ring if existing else ExecutionRing.RING_3_SANDBOX),
            risk_weight=(
                risk_weight
                if risk_weight is not None
                else (existing.risk_weight if existing else 0.5)
            ),
            reversibility=existing.reversibility if existing else ReversibilityLevel.NONE,
            confidence=0.9,  # overrides have slightly lower confidence
        )

    def clear_cache(self) -> None:
        """Clear the classification cache.

        No longer required for correctness: results are keyed on the action's
        classification fingerprint, so changed attributes produce a new entry
        automatically. Use this only to bound memory (e.g. on manifest reload).
        """
        self._cache.clear()
