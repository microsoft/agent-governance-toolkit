# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic implementation
"""Runbook executor — basic step execution.

Automated execution with approval gates and rollback is not available
in Community Edition.
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable

    from agent_sre.incidents.detector import Incident

from agent_sre.incidents.runbook import (
    ExecutionStatus,
    Runbook,
    RunbookExecution,
    RunbookStep,
    StepResult,
)

logger = logging.getLogger(__name__)


class RunbookExecutor:
    """Executes runbook steps sequentially against an incident.

    Supports human-in-the-loop approval gates, automatic rollback on failure,
    and audit-trail logging for each step.
    """

    def __init__(self) -> None:
        self._executions: list[RunbookExecution] = []
        self._event_log: list[dict[str, Any]] = []

    def execute(
        self,
        runbook: Runbook,
        incident: Incident,
        approve_callback: Callable[[RunbookStep, Incident], bool] | None = None,
    ) -> RunbookExecution:
        """Execute a runbook — not available in Community Edition."""
        raise NotImplementedError(
            "Automated runbook execution is not available in Community Edition"
        )

    def _rollback(
        self,
        completed_steps: list[tuple[RunbookStep, StepResult]],
        execution: RunbookExecution,
        incident: Incident,
    ) -> None:
        """Run rollback actions in reverse order for completed steps."""
        for step, _result in reversed(completed_steps):
            if step.rollback_action is None:
                continue

            self._emit_event("rollback_started", step=step, incident=incident)
            try:
                if callable(step.rollback_action):
                    step.rollback_action(incident)
                # String rollback actions are logged but not executed
                self._emit_event("rollback_completed", step=step, incident=incident)
            except Exception as exc:
                logger.warning("Rollback failed for step '%s': %s", step.name, exc)
                self._emit_event(
                    "rollback_failed", step=step, incident=incident, error=str(exc)
                )

        if any(s.rollback_action is not None for s, _ in completed_steps):
            execution.status = ExecutionStatus.ROLLED_BACK

    def _emit_event(self, event_type: str, **kwargs: Any) -> None:
        """Emit an audit event."""
        entry: dict[str, Any] = {
            "event": event_type,
            "timestamp": time.time(),
        }
        if "runbook" in kwargs:
            entry["runbook_id"] = kwargs["runbook"].id
            entry["runbook_name"] = kwargs["runbook"].name
        if "incident" in kwargs:
            entry["incident_id"] = kwargs["incident"].incident_id
        if "step" in kwargs:
            entry["step_name"] = kwargs["step"].name
        if "output" in kwargs:
            entry["output"] = str(kwargs["output"])
        if "error" in kwargs:
            entry["error"] = str(kwargs["error"])

        self._event_log.append(entry)
        logger.info("runbook event: %s", entry)

    @property
    def event_log(self) -> list[dict[str, Any]]:
        """Return the full audit trail."""
        return self._event_log

    @property
    def executions(self) -> list[RunbookExecution]:
        """Return all executions."""
        return self._executions
