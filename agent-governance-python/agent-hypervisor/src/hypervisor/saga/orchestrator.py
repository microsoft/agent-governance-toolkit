# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""
Semantic Saga Orchestrator

Sequential step execution with reverse-order compensation on failure.
"""

from __future__ import annotations

import asyncio
import uuid
from collections.abc import Callable
from typing import Any

from hypervisor.constants import (
    SAGA_DEFAULT_MAX_RETRIES,
    SAGA_DEFAULT_RETRY_DELAY_SECONDS,
    SAGA_DEFAULT_STEP_TIMEOUT_SECONDS,
)
from hypervisor.saga.state_machine import (
    Saga,
    SagaState,
    SagaStateError,
    SagaStep,
    StepState,
)


class SagaTimeoutError(Exception):
    """Raised when a saga step exceeds its timeout."""


class SagaOrchestrator:
    """
    Orchestrates multi-step agent transactions with saga semantics.

    Forward execution records each step. On failure, the orchestrator
    iterates the Reversibility Registry in reverse order, calling
    Undo_API for each committed step. If any Undo_API fails,
    Joint Liability penalty is triggered.
    """

    DEFAULT_MAX_RETRIES = SAGA_DEFAULT_MAX_RETRIES
    DEFAULT_RETRY_DELAY_SECONDS = SAGA_DEFAULT_RETRY_DELAY_SECONDS

    def __init__(self) -> None:
        self._sagas: dict[str, Saga] = {}

    def create_saga(self, session_id: str) -> Saga:
        """Create a new saga for a session."""
        saga = Saga(
            saga_id=f"saga:{uuid.uuid4()}",
            session_id=session_id,
        )
        self._sagas[saga.saga_id] = saga
        return saga

    def add_step(
        self,
        saga_id: str,
        action_id: str,
        agent_did: str,
        execute_api: str,
        undo_api: str | None = None,
        timeout_seconds: int = SAGA_DEFAULT_STEP_TIMEOUT_SECONDS,
        max_retries: int = 0,
    ) -> SagaStep:
        """Add a step to a saga."""
        saga = self._get_saga(saga_id)
        step = SagaStep(
            step_id=f"step:{uuid.uuid4()}",
            action_id=action_id,
            agent_did=agent_did,
            execute_api=execute_api,
            undo_api=undo_api,
            timeout_seconds=timeout_seconds,
            max_retries=max_retries,
        )
        saga.steps.append(step)
        return step

    async def execute_step(
        self,
        saga_id: str,
        step_id: str,
        executor: Callable[..., Any],
    ) -> Any:
        """
        Execute a single saga step with timeout and retry support.

        Args:
            saga_id: Saga identifier
            step_id: Step identifier
            executor: Async callable that performs the action

        Returns:
            Result from the executor

        Raises:
            SagaStateError: If step is not in PENDING state
            SagaTimeoutError: If step exceeds its timeout
        """
        saga = self._get_saga(saga_id)
        step = self._get_step(saga, step_id)

        last_error: Exception | None = None
        attempts = 1 + step.max_retries

        for attempt in range(attempts):
            step.retry_count = attempt
            step.transition(StepState.EXECUTING)
            try:
                result = await asyncio.wait_for(
                    executor(),
                    timeout=step.timeout_seconds,
                )
                step.execute_result = result
                step.transition(StepState.COMMITTED)
                return result
            except TimeoutError:
                last_error = SagaTimeoutError(
                    f"Step {step_id} timed out after {step.timeout_seconds}s "
                    f"(attempt {attempt + 1}/{attempts})"
                )
                step.error = str(last_error)
                step.transition(StepState.FAILED)
                if attempt < attempts - 1:
                    # Reset to PENDING for retry
                    step.state = StepState.PENDING
                    step.error = None
                    await asyncio.sleep(
                        self.DEFAULT_RETRY_DELAY_SECONDS * (attempt + 1)
                    )
            except Exception as e:
                last_error = e
                step.error = str(e)
                step.transition(StepState.FAILED)
                if attempt < attempts - 1:
                    step.state = StepState.PENDING
                    step.error = None
                    await asyncio.sleep(
                        self.DEFAULT_RETRY_DELAY_SECONDS * (attempt + 1)
                    )

        # All retries exhausted
        if last_error:
            raise last_error
        raise SagaStateError("Step execution failed with no error captured")

    async def compensate(
        self,
        saga_id: str,
        compensator: Callable[[SagaStep], Any],
    ) -> list[SagaStep]:
        """
        Run compensation (rollback) for all committed steps in reverse order.

        Args:
            saga_id: Saga identifier
            compensator: Async callable that takes a SagaStep and calls its Undo_API

        Returns:
            List of steps that failed compensation (empty = full success)
        """
        saga = self._get_saga(saga_id)
        saga.transition(SagaState.COMPENSATING)

        failed_compensations: list[SagaStep] = []

        for step in saga.committed_steps_reversed:
            if not step.undo_api:
                step.state = StepState.COMPENSATION_FAILED
                step.error = "No Undo_API available"
                failed_compensations.append(step)
                continue

            step.transition(StepState.COMPENSATING)
            try:
                result = await asyncio.wait_for(
                    compensator(step),
                    timeout=step.timeout_seconds,
                )
                step.compensation_result = result
                step.transition(StepState.COMPENSATED)
            except TimeoutError:
                step.error = f"Compensation timed out after {step.timeout_seconds}s"
                step.transition(StepState.COMPENSATION_FAILED)
                failed_compensations.append(step)
            except Exception as e:
                step.error = f"Compensation failed: {e}"
                step.transition(StepState.COMPENSATION_FAILED)
                failed_compensations.append(step)

        if failed_compensations:
            saga.transition(SagaState.ESCALATED)
            saga.error = (
                f"{len(failed_compensations)} step(s) failed compensation — "
                "Joint Liability penalty triggered"
            )
        else:
            saga.transition(SagaState.COMPLETED)

        return failed_compensations

    def get_saga(self, saga_id: str) -> Saga | None:
        """Get a saga by ID."""
        return self._sagas.get(saga_id)

    @property
    def active_sagas(self) -> list[Saga]:
        """Get all non-terminal sagas."""
        return [
            s for s in self._sagas.values()
            if s.state in (SagaState.RUNNING, SagaState.COMPENSATING)
        ]

    def _get_saga(self, saga_id: str) -> Saga:
        saga = self._sagas.get(saga_id)
        if not saga:
            raise SagaStateError(f"Saga {saga_id} not found")
        return saga

    def _get_step(self, saga: Saga, step_id: str) -> SagaStep:
        for step in saga.steps:
            if step.step_id == step_id:
                return step
        raise SagaStateError(f"Step {step_id} not found in saga {saga.saga_id}")
