# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""
Execution Checkpoints — stub implementation.

Public Preview: checkpoints are recorded but replay/skip logic is removed.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class SemanticCheckpoint:
    """A checkpoint record (Public Preview: stored but not used for replay)."""

    checkpoint_id: str = field(default_factory=lambda: f"ckpt:{uuid.uuid4().hex[:8]}")
    saga_id: str = ""
    step_id: str = ""
    goal_description: str = ""
    goal_hash: str = ""
    achieved_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    state_snapshot: dict[str, Any] = field(default_factory=dict)
    is_valid: bool = True
    invalidated_reason: str | None = None

    @staticmethod
    def compute_goal_hash(goal: str, step_id: str) -> str:
        """Compute deterministic hash for a goal."""
        content = f"{goal}:{step_id}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]


class CheckpointManager:
    """
    Checkpoint stub (Public Preview: saves checkpoints but no replay logic).
    """

    def __init__(self) -> None:
        self._checkpoints: dict[str, list[SemanticCheckpoint]] = {}
        self._by_goal_hash: dict[str, SemanticCheckpoint] = {}

    def save(
        self,
        saga_id: str,
        step_id: str,
        goal_description: str,
        state_snapshot: dict | None = None,
    ) -> SemanticCheckpoint:
        """Save a checkpoint record."""
        goal_hash = SemanticCheckpoint.compute_goal_hash(goal_description, step_id)
        checkpoint = SemanticCheckpoint(
            saga_id=saga_id,
            step_id=step_id,
            goal_description=goal_description,
            goal_hash=goal_hash,
            state_snapshot=state_snapshot or {},
        )
        self._checkpoints.setdefault(saga_id, []).append(checkpoint)
        self._by_goal_hash[goal_hash] = checkpoint
        return checkpoint

    def is_achieved(
        self,
        saga_id: str,
        goal_description: str,
        step_id: str,
    ) -> bool:
        """Always returns False (Public Preview: no skip-on-replay)."""
        return False

    def get_checkpoint(
        self,
        saga_id: str,
        goal_description: str,
        step_id: str,
    ) -> SemanticCheckpoint | None:
        """Returns None (Public Preview: no replay support)."""
        return None

    def invalidate(
        self,
        saga_id: str,
        step_id: str,
        reason: str = "",
    ) -> int:
        """No-op in Public Preview."""
        return 0

    def get_saga_checkpoints(self, saga_id: str) -> list[SemanticCheckpoint]:
        """Get all checkpoints for a saga."""
        return list(self._checkpoints.get(saga_id, []))

    def get_replay_plan(self, saga_id: str, steps: list[str]) -> list[str]:
        """All steps need execution (Public Preview: no skip logic)."""
        return list(steps)

    @property
    def total_checkpoints(self) -> int:
        return sum(len(v) for v in self._checkpoints.values())

    @property
    def valid_checkpoints(self) -> int:
        return self.total_checkpoints
