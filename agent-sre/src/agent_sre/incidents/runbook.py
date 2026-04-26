# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""Runbook models — dataclasses for scripted incident response."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable


class ExecutionStatus(Enum):
    """Status of a runbook execution."""

    PENDING = "pending"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class StepStatus(Enum):
    """Status of a single runbook step."""

    PENDING = "pending"
    RUNNING = "running"
    WAITING_APPROVAL = "waiting_approval"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    ROLLED_BACK = "rolled_back"


@dataclass
class RunbookStep:
    """A single step in a runbook.

    Args:
        name: Human-readable step name.
        action: Callable returning a string result, or a string command description.
        timeout_seconds: Maximum time allowed for this step.
        requires_approval: Whether this step needs human approval before executing.
        rollback_action: Optional callable/command to undo this step on failure.
    """

    name: str
    action: Callable[..., str] | str
    timeout_seconds: int = 300
    requires_approval: bool = False
    rollback_action: Callable[..., str] | str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "action": self.action if isinstance(self.action, str) else self.action.__name__,
            "timeout_seconds": self.timeout_seconds,
            "requires_approval": self.requires_approval,
            "has_rollback": self.rollback_action is not None,
        }


@dataclass
class StepResult:
    """Result of executing a single runbook step."""

    step_name: str
    status: StepStatus = StepStatus.PENDING
    output: str = ""
    started_at: float | None = None
    completed_at: float | None = None
    error: str = ""

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "step_name": self.step_name,
            "status": self.status.value,
            "output": self.output,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error": self.error,
            "duration_seconds": self.duration_seconds,
        }


@dataclass
class Runbook:
    """An executable runbook for incident response.

    Args:
        id: Unique identifier for this runbook.
        name: Human-readable name.
        description: What this runbook does.
        trigger_conditions: List of dicts with 'type' and/or 'severity' keys
            that auto-trigger this runbook when an incident matches.
        steps: Ordered list of RunbookStep to execute.
        labels: Arbitrary metadata labels.
    """

    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    name: str = ""
    description: str = ""
    trigger_conditions: list[dict[str, str]] = field(default_factory=list)
    steps: list[RunbookStep] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "trigger_conditions": self.trigger_conditions,
            "steps": [s.to_dict() for s in self.steps],
            "labels": self.labels,
        }


@dataclass
class RunbookExecution:
    """Tracks the execution of a runbook against an incident."""

    runbook_id: str
    incident_id: str
    execution_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    started_at: float | None = None
    completed_at: float | None = None
    status: ExecutionStatus = ExecutionStatus.PENDING
    step_results: list[StepResult] = field(default_factory=list)

    @property
    def duration_seconds(self) -> float | None:
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "execution_id": self.execution_id,
            "runbook_id": self.runbook_id,
            "incident_id": self.incident_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "status": self.status.value,
            "duration_seconds": self.duration_seconds,
            "step_results": [r.to_dict() for r in self.step_results],
        }
