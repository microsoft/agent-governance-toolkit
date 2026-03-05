# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the Mute Agent (Face/Hands) kernel primitives."""

import asyncio
import pytest
from agent_os.mute import (
    ActionStep,
    ActionStatus,
    CapabilityViolation,
    ExecutionPlan,
    PipelineResult,
    StepResult,
    face_agent,
    mute_agent,
    pipe,
)


# =============================================================================
# Test Fixtures — sample Face and Mute agents
# =============================================================================


@face_agent(capabilities=["db.read", "db.write", "file.read"])
async def sample_face(task: str) -> ExecutionPlan:
    """A simple face agent that produces a plan based on keywords."""
    steps = []
    if "read" in task.lower():
        steps.append(ActionStep(action="db.read", params={"query": task}))
    if "write" in task.lower():
        steps.append(ActionStep(
            action="db.write",
            params={"data": "test"},
            depends_on=[0] if steps else [],
        ))
    if "file" in task.lower():
        steps.append(ActionStep(action="file.read", params={"path": "/tmp/test"}))
    if not steps:
        steps.append(ActionStep(action="db.read", params={"query": "SELECT 1"}))
    return ExecutionPlan(steps=steps, metadata={"original_task": task})


@mute_agent(capabilities=["db.read", "db.write", "file.read"])
async def sample_mute(step: ActionStep) -> dict:
    """A simple mute agent that executes steps and returns structured data."""
    if step.action == "db.read":
        return {"rows": [{"id": 1, "name": "test"}], "count": 1}
    elif step.action == "db.write":
        return {"affected_rows": 1}
    elif step.action == "file.read":
        return {"content": "file data", "size": 9}
    return {"status": "ok"}


# =============================================================================
# ExecutionPlan tests
# =============================================================================


class TestExecutionPlan:
    def test_empty_plan(self):
        plan = ExecutionPlan()
        assert plan.steps == []
        assert plan.actions_used == set()
        assert len(plan.plan_id) == 12

    def test_plan_with_steps(self):
        plan = ExecutionPlan(steps=[
            ActionStep(action="db.read", params={"q": "test"}),
            ActionStep(action="db.write", params={"d": "x"}),
        ])
        assert len(plan.steps) == 2
        assert plan.actions_used == {"db.read", "db.write"}

    def test_plan_metadata(self):
        plan = ExecutionPlan(
            steps=[ActionStep(action="a")],
            metadata={"source": "test"},
        )
        assert plan.metadata["source"] == "test"

    def test_plan_rejects_non_list_steps(self):
        with pytest.raises(TypeError):
            ExecutionPlan(steps="not a list")

    def test_action_step_defaults(self):
        step = ActionStep(action="do_thing")
        assert step.params == {}
        assert step.description == ""
        assert step.depends_on == []


# =============================================================================
# @face_agent tests
# =============================================================================


class TestFaceAgent:
    def test_decorator_sets_role(self):
        assert sample_face._agent_role == "face"
        assert sample_face._capabilities == {"db.read", "db.write", "file.read"}

    @pytest.mark.asyncio
    async def test_face_returns_plan(self):
        plan = await sample_face("read data")
        assert isinstance(plan, ExecutionPlan)
        assert len(plan.steps) >= 1
        assert plan.steps[0].action == "db.read"

    @pytest.mark.asyncio
    async def test_face_rejects_non_plan_return(self):
        @face_agent(capabilities=["x"])
        async def bad_face(task: str) -> ExecutionPlan:
            return "not a plan"  # type: ignore

        with pytest.raises(TypeError, match="must return ExecutionPlan"):
            await bad_face("test")

    @pytest.mark.asyncio
    async def test_face_validates_capabilities(self):
        @face_agent(capabilities=["db.read"])
        async def restricted_face(task: str) -> ExecutionPlan:
            return ExecutionPlan(steps=[
                ActionStep(action="db.delete", params={}),  # Not allowed
            ])

        with pytest.raises(CapabilityViolation):
            await restricted_face("test")

    @pytest.mark.asyncio
    async def test_face_no_capabilities_skips_validation(self):
        @face_agent()
        async def open_face(task: str) -> ExecutionPlan:
            return ExecutionPlan(steps=[
                ActionStep(action="anything_goes"),
            ])

        plan = await open_face("test")
        assert plan.steps[0].action == "anything_goes"

    @pytest.mark.asyncio
    async def test_face_with_multiple_steps(self):
        plan = await sample_face("read and write data")
        assert len(plan.steps) == 2
        assert plan.steps[0].action == "db.read"
        assert plan.steps[1].action == "db.write"


# =============================================================================
# @mute_agent tests
# =============================================================================


class TestMuteAgent:
    def test_decorator_sets_role(self):
        assert sample_mute._agent_role == "mute"
        assert sample_mute._capabilities == {"db.read", "db.write", "file.read"}

    @pytest.mark.asyncio
    async def test_mute_executes_step(self):
        step = ActionStep(action="db.read", params={"query": "SELECT 1"})
        result = await sample_mute(step)
        assert result["count"] == 1

    @pytest.mark.asyncio
    async def test_mute_rejects_non_step_input(self):
        with pytest.raises(TypeError, match="receives ActionStep"):
            await sample_mute("not a step")

    @pytest.mark.asyncio
    async def test_mute_enforces_capabilities(self):
        @mute_agent(capabilities=["db.read"])
        async def read_only_mute(step: ActionStep) -> dict:
            return {}

        step = ActionStep(action="db.delete", params={})
        with pytest.raises(CapabilityViolation):
            await read_only_mute(step)

    @pytest.mark.asyncio
    async def test_mute_no_capabilities_allows_anything(self):
        @mute_agent()
        async def open_mute(step: ActionStep) -> dict:
            return {"done": True}

        step = ActionStep(action="anything")
        result = await open_mute(step)
        assert result["done"] is True


# =============================================================================
# pipe() tests
# =============================================================================


class TestPipe:
    @pytest.mark.asyncio
    async def test_basic_pipeline(self):
        result = await pipe(sample_face, sample_mute, "read data")
        assert isinstance(result, PipelineResult)
        assert result.success is True
        assert len(result.step_results) >= 1
        assert result.step_results[0].status == ActionStatus.EXECUTED
        assert result.total_duration_ms > 0

    @pytest.mark.asyncio
    async def test_pipeline_audit_log(self):
        result = await pipe(sample_face, sample_mute, "read data")
        events = [e["event"] for e in result.audit_log]
        assert "start" in events
        assert "plan_produced" in events
        assert "step_executed" in events
        assert "complete" in events

    @pytest.mark.asyncio
    async def test_pipeline_denies_out_of_scope_actions(self):
        @face_agent(capabilities=["db.read", "db.delete"])
        async def delete_face(task: str) -> ExecutionPlan:
            return ExecutionPlan(steps=[
                ActionStep(action="db.delete", params={"table": "users"}),
            ])

        @mute_agent(capabilities=["db.read"])  # Cannot delete!
        async def read_mute(step: ActionStep) -> dict:
            return {}

        result = await pipe(delete_face, read_mute, "delete users")
        assert result.success is False
        assert len(result.denied_steps) == 1
        assert result.step_results[0].status == ActionStatus.DENIED

    @pytest.mark.asyncio
    async def test_pipeline_with_dependencies(self):
        @face_agent(capabilities=["a", "b"])
        async def dep_face(task: str) -> ExecutionPlan:
            return ExecutionPlan(steps=[
                ActionStep(action="a", params={"step": 0}),
                ActionStep(action="b", params={"step": 1}, depends_on=[0]),
            ])

        @mute_agent(capabilities=["a", "b"])
        async def dep_mute(step: ActionStep) -> dict:
            return {"step": step.params["step"]}

        result = await pipe(dep_face, dep_mute, "run with deps")
        assert result.success is True
        assert len(result.step_results) == 2
        assert all(r.status == ActionStatus.EXECUTED for r in result.step_results)

    @pytest.mark.asyncio
    async def test_pipeline_dependency_failure(self):
        @face_agent(capabilities=["a", "b"])
        async def dep_face(task: str) -> ExecutionPlan:
            return ExecutionPlan(steps=[
                ActionStep(action="a"),
                ActionStep(action="b", depends_on=[0]),
            ])

        @mute_agent(capabilities=["a", "b"])
        async def failing_mute(step: ActionStep) -> dict:
            if step.action == "a":
                raise RuntimeError("step a failed")
            return {}

        result = await pipe(dep_face, failing_mute, "test")
        assert result.success is False
        assert result.step_results[0].status == ActionStatus.FAILED
        assert result.step_results[1].status == ActionStatus.FAILED
        assert "Dependency" in result.step_results[1].error

    @pytest.mark.asyncio
    async def test_pipeline_rejects_non_face(self):
        async def plain_fn(task):
            return ExecutionPlan()

        with pytest.raises(TypeError, match="@face_agent"):
            await pipe(plain_fn, sample_mute, "test")

    @pytest.mark.asyncio
    async def test_pipeline_rejects_non_mute(self):
        async def plain_fn(step):
            return {}

        with pytest.raises(TypeError, match="@mute_agent"):
            await pipe(sample_face, plain_fn, "test")

    @pytest.mark.asyncio
    async def test_pipeline_data_property(self):
        result = await pipe(sample_face, sample_mute, "read data")
        assert len(result.data) >= 1
        assert isinstance(result.data[0], dict)

    @pytest.mark.asyncio
    async def test_pipeline_halt_on_error(self):
        @face_agent(capabilities=["a", "b"])
        async def multi_face(task: str) -> ExecutionPlan:
            return ExecutionPlan(steps=[
                ActionStep(action="a"),
                ActionStep(action="b"),
            ])

        @mute_agent(capabilities=["a", "b"])
        async def fail_first(step: ActionStep) -> dict:
            if step.action == "a":
                raise RuntimeError("boom")
            return {}

        result = await pipe(
            multi_face, fail_first, "test", halt_on_error=True
        )
        assert result.success is False
        assert len(result.step_results) == 1  # Halted after first failure

    @pytest.mark.asyncio
    async def test_pipeline_continues_on_error(self):
        @face_agent(capabilities=["a", "b"])
        async def multi_face(task: str) -> ExecutionPlan:
            return ExecutionPlan(steps=[
                ActionStep(action="a"),
                ActionStep(action="b"),
            ])

        @mute_agent(capabilities=["a", "b"])
        async def fail_first(step: ActionStep) -> dict:
            if step.action == "a":
                raise RuntimeError("boom")
            return {"ok": True}

        result = await pipe(
            multi_face, fail_first, "test", halt_on_error=False
        )
        assert result.success is False
        assert len(result.step_results) == 2
        assert result.step_results[0].status == ActionStatus.FAILED
        assert result.step_results[1].status == ActionStatus.EXECUTED

    @pytest.mark.asyncio
    async def test_face_error_produces_empty_result(self):
        @face_agent(capabilities=["x"])
        async def error_face(task: str) -> ExecutionPlan:
            raise ValueError("planning failed")

        # CapabilityViolation and TypeError are caught, but ValueError is not
        # Let's test a CapabilityViolation
        @face_agent(capabilities=["db.read"])
        async def bad_plan_face(task: str) -> ExecutionPlan:
            return ExecutionPlan(steps=[ActionStep(action="nope")])

        result = await pipe(bad_plan_face, sample_mute, "test")
        assert result.success is False
        assert len(result.step_results) == 0

    @pytest.mark.asyncio
    async def test_file_operations_pipeline(self):
        result = await pipe(sample_face, sample_mute, "read file data")
        assert result.success is True
        # Should have db.read + file.read
        actions = [r.action for r in result.step_results]
        assert "db.read" in actions
        assert "file.read" in actions


# =============================================================================
# CapabilityViolation tests
# =============================================================================


class TestCapabilityViolation:
    def test_message_format(self):
        exc = CapabilityViolation("mute", "db.delete", {"db.read"})
        assert "mute" in str(exc)
        assert "db.delete" in str(exc)
        assert "db.read" in str(exc)

    def test_attributes(self):
        exc = CapabilityViolation("face", "x", {"a", "b"})
        assert exc.agent_role == "face"
        assert exc.action == "x"
        assert exc.allowed == {"a", "b"}
