# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Saga State Machine

Formal state tracking for individual saga steps and overall saga lifecycle,
with persistence support for crash recovery.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any


class StepState(str, Enum):
    """State of an individual saga step."""

    PENDING = "pending"
    EXECUTING = "executing"
    COMMITTED = "committed"
    COMPENSATING = "compensating"
    COMPENSATED = "compensated"
    COMPENSATION_FAILED = "compensation_failed"
    FAILED = "failed"


class SagaState(str, Enum):
    """State of the overall saga."""

    RUNNING = "running"
    COMPENSATING = "compensating"
    COMPLETED = "completed"
    FAILED = "failed"
    ESCALATED = "escalated"


# Valid state transitions
STEP_TRANSITIONS: dict[StepState, set[StepState]] = {
    StepState.PENDING: {StepState.EXECUTING},
    StepState.EXECUTING: {StepState.COMMITTED, StepState.FAILED},
    StepState.COMMITTED: {StepState.COMPENSATING},
    StepState.COMPENSATING: {StepState.COMPENSATED, StepState.COMPENSATION_FAILED},
    StepState.COMPENSATED: set(),
    StepState.COMPENSATION_FAILED: set(),
    StepState.FAILED: set(),
}

SAGA_TRANSITIONS: dict[SagaState, set[SagaState]] = {
    SagaState.RUNNING: {SagaState.COMPENSATING, SagaState.COMPLETED, SagaState.FAILED},
    SagaState.COMPENSATING: {SagaState.COMPLETED, SagaState.FAILED, SagaState.ESCALATED},
    SagaState.COMPLETED: set(),
    SagaState.FAILED: set(),
    SagaState.ESCALATED: set(),
}


@dataclass
class SagaStep:
    """A single step in a saga."""

    step_id: str
    action_id: str
    agent_did: str
    execute_api: str
    undo_api: str | None = None
    state: StepState = StepState.PENDING
    execute_result: Any | None = None
    compensation_result: Any | None = None
    error: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    timeout_seconds: int = 300
    max_retries: int = 0
    retry_count: int = 0

    def transition(self, new_state: StepState) -> None:
        """Transition to a new state, enforcing valid transitions."""
        allowed = STEP_TRANSITIONS.get(self.state, set())
        if new_state not in allowed:
            raise SagaStateError(
                f"Invalid step transition: {self.state.value} → {new_state.value}. "
                f"Allowed: {[s.value for s in allowed]}"
            )
        self.state = new_state
        now = datetime.now(UTC)
        if new_state == StepState.EXECUTING:
            self.started_at = now
        elif new_state in (
            StepState.COMMITTED,
            StepState.COMPENSATED,
            StepState.COMPENSATION_FAILED,
            StepState.FAILED,
        ):
            self.completed_at = now


@dataclass
class Saga:
    """A saga consisting of ordered steps."""

    saga_id: str
    session_id: str
    steps: list[SagaStep] = field(default_factory=list)
    state: SagaState = SagaState.RUNNING
    created_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    error: str | None = None

    def transition(self, new_state: SagaState) -> None:
        """Transition the saga to a new state."""
        allowed = SAGA_TRANSITIONS.get(self.state, set())
        if new_state not in allowed:
            raise SagaStateError(
                f"Invalid saga transition: {self.state.value} → {new_state.value}. "
                f"Allowed: {[s.value for s in allowed]}"
            )
        self.state = new_state
        if new_state in (SagaState.COMPLETED, SagaState.FAILED, SagaState.ESCALATED):
            self.completed_at = datetime.now(UTC)

    @property
    def committed_steps(self) -> list[SagaStep]:
        """Steps that completed execution (need compensation on rollback)."""
        return [s for s in self.steps if s.state == StepState.COMMITTED]

    @property
    def committed_steps_reversed(self) -> list[SagaStep]:
        """Committed steps in reverse order for rollback."""
        return list(reversed(self.committed_steps))

    def to_dict(self) -> dict:
        """Serialize for VFS persistence."""
        return {
            "saga_id": self.saga_id,
            "session_id": self.session_id,
            "state": self.state.value,
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error": self.error,
            "steps": [
                {
                    "step_id": s.step_id,
                    "action_id": s.action_id,
                    "agent_did": s.agent_did,
                    "state": s.state.value,
                    "error": s.error,
                }
                for s in self.steps
            ],
        }


class SagaStateError(Exception):
    """Raised for invalid saga state transitions."""
