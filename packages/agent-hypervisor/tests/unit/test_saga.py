# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for saga orchestrator and state machine."""

import pytest

from hypervisor.saga.orchestrator import SagaOrchestrator
from hypervisor.saga.state_machine import (
    Saga,
    SagaState,
    SagaStateError,
    SagaStep,
    StepState,
)


class TestStepStateMachine:
    def test_valid_transitions(self):
        step = SagaStep(step_id="s1", action_id="a1", agent_did="did:a", execute_api="/api")
        step.transition(StepState.EXECUTING)
        assert step.state == StepState.EXECUTING
        assert step.started_at is not None
        step.transition(StepState.COMMITTED)
        assert step.state == StepState.COMMITTED
        assert step.completed_at is not None

    def test_invalid_transition(self):
        step = SagaStep(step_id="s1", action_id="a1", agent_did="did:a", execute_api="/api")
        with pytest.raises(SagaStateError, match="Invalid step transition"):
            step.transition(StepState.COMMITTED)  # skip EXECUTING

    def test_compensation_flow(self):
        step = SagaStep(step_id="s1", action_id="a1", agent_did="did:a", execute_api="/api")
        step.transition(StepState.EXECUTING)
        step.transition(StepState.COMMITTED)
        step.transition(StepState.COMPENSATING)
        step.transition(StepState.COMPENSATED)
        assert step.state == StepState.COMPENSATED


class TestSagaStateMachine:
    def test_valid_saga_transitions(self):
        saga = Saga(saga_id="saga:1", session_id="session:1")
        saga.transition(SagaState.COMPENSATING)
        saga.transition(SagaState.COMPLETED)
        assert saga.completed_at is not None

    def test_invalid_saga_transition(self):
        saga = Saga(saga_id="saga:1", session_id="session:1")
        with pytest.raises(SagaStateError):
            saga.transition(SagaState.ESCALATED)  # can't escalate from RUNNING

    def test_committed_steps_reversed(self):
        saga = Saga(saga_id="saga:1", session_id="session:1")
        for i in range(3):
            step = SagaStep(
                step_id=f"s{i}", action_id=f"a{i}", agent_did="did:a", execute_api="/api"
            )
            step.transition(StepState.EXECUTING)
            step.transition(StepState.COMMITTED)
            saga.steps.append(step)

        reversed_steps = saga.committed_steps_reversed
        assert [s.step_id for s in reversed_steps] == ["s2", "s1", "s0"]

    def test_to_dict(self):
        saga = Saga(saga_id="saga:1", session_id="session:1")
        d = saga.to_dict()
        assert d["saga_id"] == "saga:1"
        assert d["state"] == "running"


class TestSagaOrchestrator:
    def setup_method(self):
        self.orchestrator = SagaOrchestrator()

    def test_create_saga(self):
        saga = self.orchestrator.create_saga("session:1")
        assert saga.state == SagaState.RUNNING

    def test_add_step(self):
        saga = self.orchestrator.create_saga("session:1")
        step = self.orchestrator.add_step(
            saga.saga_id, "action:1", "did:a", "/api/execute", "/api/undo"
        )
        assert step.action_id == "action:1"
        assert step.undo_api == "/api/undo"

    @pytest.mark.asyncio
    async def test_execute_step_success(self):
        saga = self.orchestrator.create_saga("session:1")
        step = self.orchestrator.add_step(
            saga.saga_id, "a1", "did:a", "/api/exec"
        )

        async def executor():
            return "done"

        result = await self.orchestrator.execute_step(
            saga.saga_id, step.step_id, executor=executor
        )

        assert result == "done"
        assert step.state == StepState.COMMITTED

    @pytest.mark.asyncio
    async def test_execute_step_failure(self):
        saga = self.orchestrator.create_saga("session:1")
        step = self.orchestrator.add_step(
            saga.saga_id, "a1", "did:a", "/api/exec"
        )

        async def failing_executor():
            raise RuntimeError("boom")

        with pytest.raises(RuntimeError):
            await self.orchestrator.execute_step(
                saga.saga_id, step.step_id, executor=failing_executor
            )

        assert step.state == StepState.FAILED

    @pytest.mark.asyncio
    async def test_compensate_all_steps(self):
        saga = self.orchestrator.create_saga("session:1")

        # Add and commit 3 steps
        for i in range(3):
            step = self.orchestrator.add_step(
                saga.saga_id, f"a{i}", "did:a", "/exec", f"/undo/{i}"
            )
            async def ok_executor():
                return "ok"

            await self.orchestrator.execute_step(
                saga.saga_id, step.step_id, executor=ok_executor
            )

        # Compensate all
        async def compensator(step):
            return "compensated"

        failed = await self.orchestrator.compensate(saga.saga_id, compensator)
        assert len(failed) == 0
        assert saga.state == SagaState.COMPLETED

    @pytest.mark.asyncio
    async def test_compensate_with_failure_escalates(self):
        saga = self.orchestrator.create_saga("session:1")
        step = self.orchestrator.add_step(
            saga.saga_id, "a1", "did:a", "/exec", "/undo"
        )
        async def ok_executor():
            return "ok"

        await self.orchestrator.execute_step(
            saga.saga_id, step.step_id, executor=ok_executor
        )

        async def failing_compensator(step):
            raise RuntimeError("undo failed")

        failed = await self.orchestrator.compensate(saga.saga_id, failing_compensator)
        assert len(failed) == 1
        assert saga.state == SagaState.ESCALATED
