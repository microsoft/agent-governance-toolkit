# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Reversibility Registry

Maps every declared action to its Execute_API and Undo_API,
populated during the IATP handshake.
"""

from __future__ import annotations

from dataclasses import dataclass

from hypervisor.models import ActionDescriptor, ReversibilityLevel


@dataclass
class ReversibilityEntry:
    """An entry in the reversibility registry."""

    action_id: str
    execute_api: str
    undo_api: str | None
    reversibility: ReversibilityLevel
    undo_window_seconds: int
    compensation_method: str | None
    risk_weight: float
    undo_api_healthy: bool = True
    last_health_check: str | None = None


class ReversibilityRegistry:
    """
    Session-scoped registry of action reversibility mappings.

    Auto-populated from IATP Capability Manifests during handshake.
    Provides lookup for the Saga orchestrator during rollback.
    """

    def __init__(self, session_id: str) -> None:
        self.session_id = session_id
        self._entries: dict[str, ReversibilityEntry] = {}

    def register(self, action: ActionDescriptor) -> ReversibilityEntry:
        """Register an action from a capability manifest."""
        entry = ReversibilityEntry(
            action_id=action.action_id,
            execute_api=action.execute_api,
            undo_api=action.undo_api,
            reversibility=action.reversibility,
            undo_window_seconds=action.undo_window_seconds,
            compensation_method=action.compensation_method,
            risk_weight=action.risk_weight,
        )
        self._entries[action.action_id] = entry
        return entry

    def register_from_manifest(self, actions: list[ActionDescriptor]) -> int:
        """Register all actions from a manifest. Returns count registered."""
        for action in actions:
            self.register(action)
        return len(actions)

    def get(self, action_id: str) -> ReversibilityEntry | None:
        """Look up an action's reversibility entry."""
        return self._entries.get(action_id)

    def get_undo_api(self, action_id: str) -> str | None:
        """Get the Undo_API for an action, if any."""
        entry = self._entries.get(action_id)
        return entry.undo_api if entry else None

    def is_reversible(self, action_id: str) -> bool:
        """Check if an action has any reversibility."""
        entry = self._entries.get(action_id)
        if not entry:
            return False
        return entry.reversibility != ReversibilityLevel.NONE

    def get_risk_weight(self, action_id: str) -> float:
        """Get the risk weight ω for an action."""
        entry = self._entries.get(action_id)
        return entry.risk_weight if entry else ReversibilityLevel.NONE.default_risk_weight

    def has_non_reversible_actions(self) -> bool:
        """Check if any registered action is non-reversible."""
        return any(
            e.reversibility == ReversibilityLevel.NONE
            for e in self._entries.values()
        )

    def mark_undo_unhealthy(self, action_id: str) -> None:
        """Mark an Undo_API as unhealthy (failed health check)."""
        entry = self._entries.get(action_id)
        if entry:
            entry.undo_api_healthy = False

    @property
    def entries(self) -> list[ReversibilityEntry]:
        return list(self._entries.values())

    @property
    def non_reversible_actions(self) -> list[str]:
        return [
            e.action_id
            for e in self._entries.values()
            if e.reversibility == ReversibilityLevel.NONE
        ]
