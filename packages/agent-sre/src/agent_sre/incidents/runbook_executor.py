# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic implementation
"""Runbook executor — step execution with approval gates and rollback.

Executes runbook steps sequentially with human-in-the-loop approval,
automatic rollback on failure, and audit-trail logging.
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
    StepStatus,
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
        """Execute a runbook's steps sequentially against an incident.

        Args:
            runbook: The runbook to execute.
            incident: The incident context.
            approve_callback: Optional callback for approval gates.
                If a step requires approval and no callback is provided,
                the execution pauses with WAITING_APPROVAL status.

        Returns:
            RunbookExecution with results for each step.
        """
        execution = RunbookExecution(
            runbook_id=runbook.id,
            incident_id=incident.incident_id,
        )
        execution.started_at = time.time()
        execution.status = ExecutionStatus.RUNNING
        self._emit_event("execution_started", runbook=runbook, incident=incident)

        completed_steps: list[tuple[RunbookStep, StepResult]] = []

        for step in runbook.steps:
            # Check approval gate
            if step.requires_approval:
                if approve_callback is None:
                    # No callback — pause execution
                    step_result = StepResult(
                        step_name=step.name,
                        status=StepStatus.WAITING_APPROVAL,
                    )
                    execution.step_results.append(step_result)
                    execution.status = ExecutionStatus.WAITING_APPROVAL
                    self._emit_event("approval_waiting", step=step, incident=incident)
                    execution.completed_at = time.time()
                    self._executions.append(execution)
                    return execution
                elif not approve_callback(step, incident):
                    # Denied — skip step
                    step_result = StepResult(
                        step_name=step.name,
                        status=StepStatus.SKIPPED,
                        output="Approval denied",
                    )
                    execution.step_results.append(step_result)
                    self._emit_event("approval_denied", step=step, incident=incident)
                    continue

            # Execute the step
            step_result = StepResult(step_name=step.name)
            step_result.started_at = time.time()
            step_result.status = StepStatus.RUNNING
            self._emit_event("step_started", step=step, incident=incident)

            try:
                if callable(step.action):
                    output = step.action(incident)
                else:
                    # String actions are logged but treated as descriptive
                    output = f"[command] {step.action}"

                step_result.output = str(output) if output else ""
                step_result.status = StepStatus.SUCCESS
                step_result.completed_at = time.time()
                self._emit_event(
                    "step_completed", step=step, incident=incident, output=output
                )
                completed_steps.append((step, step_result))
            except Exception as exc:
                step_result.status = StepStatus.FAILED
                step_result.error = str(exc)
                step_result.completed_at = time.time()
                self._emit_event(
                    "step_failed", step=step, incident=incident, error=str(exc)
                )
                execution.step_results.append(step_result)
                execution.status = ExecutionStatus.FAILED

                # Trigger rollback for completed steps
                self._rollback(completed_steps, execution, incident)
                execution.completed_at = time.time()
                self._executions.append(execution)
                return execution

            execution.step_results.append(step_result)

        execution.status = ExecutionStatus.COMPLETED
        execution.completed_at = time.time()
        self._emit_event("execution_completed", runbook=runbook, incident=incident)
        self._executions.append(execution)
        return execution

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
