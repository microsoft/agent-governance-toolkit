# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for saga fan-out, execution checkpoints, and declarative DSL."""


import pytest

from hypervisor.saga.checkpoint import (
    CheckpointManager,
    SemanticCheckpoint,
)
from hypervisor.saga.dsl import (
    SagaDSLError,
    SagaDSLParser,
)
from hypervisor.saga.fan_out import (
    FanOutGroup,
    FanOutOrchestrator,
    FanOutPolicy,
)
from hypervisor.saga.state_machine import SagaStep

# ── Fan-Out Tests ───────────────────────────────────────────────


class TestFanOut:
    @pytest.fixture
    def steps(self):
        return [
            SagaStep(step_id="s1", action_id="a1", agent_did="d1", execute_api="/api/1"),
            SagaStep(step_id="s2", action_id="a2", agent_did="d2", execute_api="/api/2"),
            SagaStep(step_id="s3", action_id="a3", agent_did="d3", execute_api="/api/3"),
        ]

    async def test_all_succeed_policy(self, steps):
        fan = FanOutOrchestrator()
        group = fan.create_group("saga-1", FanOutPolicy.ALL_MUST_SUCCEED)
        for s in steps:
            fan.add_branch(group.group_id, s)

        async def success():
            return "ok"

        executors = {s.step_id: success for s in steps}
        result = await fan.execute(group.group_id, executors)

        assert result.resolved
        assert result.policy_satisfied
        assert result.success_count == 3
        assert len(result.compensation_needed) == 0

    async def test_all_succeed_policy_fails(self, steps):
        fan = FanOutOrchestrator()
        group = fan.create_group("saga-1", FanOutPolicy.ALL_MUST_SUCCEED)
        for s in steps:
            fan.add_branch(group.group_id, s)

        call_count = 0

        async def sometimes_fail():
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise ValueError("step failed")
            return "ok"

        executors = {s.step_id: sometimes_fail for s in steps}
        result = await fan.execute(group.group_id, executors)

        assert result.resolved
        assert not result.policy_satisfied
        assert result.failure_count == 1
        assert len(result.compensation_needed) > 0

    @pytest.mark.skip("Feature not available in Public Preview")
    async def test_majority_policy_succeeds(self, steps):
        pass

    @pytest.mark.skip("Feature not available in Public Preview")
    async def test_any_policy_succeeds(self, steps):
        pass

    async def test_all_fail_any_policy(self, steps):
        fan = FanOutOrchestrator()
        group = fan.create_group("saga-1", FanOutPolicy.ANY_MUST_SUCCEED)
        for s in steps:
            fan.add_branch(group.group_id, s)

        async def always_fail():
            raise ValueError("all fail")

        executors = {s.step_id: always_fail for s in steps}
        result = await fan.execute(group.group_id, executors)

        assert not result.policy_satisfied

    def test_group_check_policy_empty(self):
        group = FanOutGroup(policy=FanOutPolicy.ALL_MUST_SUCCEED)
        # With 0 branches, 0 == 0 is True for ALL_MUST_SUCCEED (vacuously true)
        assert group.check_policy()

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_group_check_policy_any_empty(self):
        pass

    def test_active_groups(self, steps):
        fan = FanOutOrchestrator()
        g1 = fan.create_group("saga-1")
        assert len(fan.active_groups) == 1
        g1.resolved = True
        assert len(fan.active_groups) == 0


# ── Checkpoint Tests ────────────────────────────────────────────


class TestCheckpoints:
    @pytest.mark.skip("Feature not available in Public Preview")
    def test_save_and_check(self):
        mgr = CheckpointManager()
        ckpt = mgr.save("saga-1", "s1", "Database migrated", {"version": 5})
        assert ckpt.is_valid
        assert mgr.is_achieved("saga-1", "Database migrated", "s1")

    def test_not_achieved_without_save(self):
        mgr = CheckpointManager()
        assert not mgr.is_achieved("saga-1", "Database migrated", "s1")

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_invalidate_checkpoint(self):
        mgr = CheckpointManager()
        mgr.save("saga-1", "s1", "Schema created")
        count = mgr.invalidate("saga-1", "s1", "Schema changed")
        assert count == 1
        assert not mgr.is_achieved("saga-1", "Schema created", "s1")

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_get_checkpoint(self):
        pass

    def test_get_saga_checkpoints(self):
        mgr = CheckpointManager()
        mgr.save("saga-1", "s1", "Step 1 done")
        mgr.save("saga-1", "s2", "Step 2 done")
        mgr.save("saga-2", "s1", "Other saga")

        ckpts = mgr.get_saga_checkpoints("saga-1")
        assert len(ckpts) == 2

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_replay_plan(self):
        pass

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_total_and_valid_counts(self):
        pass

    def test_goal_hash_deterministic(self):
        h1 = SemanticCheckpoint.compute_goal_hash("Deploy", "s1")
        h2 = SemanticCheckpoint.compute_goal_hash("Deploy", "s1")
        h3 = SemanticCheckpoint.compute_goal_hash("Deploy", "s2")
        assert h1 == h2
        assert h1 != h3


# ── DSL Parser Tests ────────────────────────────────────────────


class TestSagaDSL:
    def test_parse_valid_definition(self):
        parser = SagaDSLParser()
        defn = parser.parse({
            "name": "deploy-model",
            "session_id": "sess-1",
            "steps": [
                {
                    "id": "validate",
                    "action_id": "model.validate",
                    "agent": "did:mesh:validator",
                    "execute_api": "/api/validate",
                    "undo_api": "/api/rollback",
                },
                {
                    "id": "deploy",
                    "action_id": "model.deploy",
                    "agent": "did:mesh:deployer",
                    "execute_api": "/api/deploy",
                    "timeout": 600,
                    "retries": 2,
                },
            ],
        })
        assert defn.name == "deploy-model"
        assert len(defn.steps) == 2
        assert defn.steps[1].timeout == 600
        assert defn.steps[1].retries == 2

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_parse_with_fan_out(self):
        pass

    def test_parse_missing_name(self):
        parser = SagaDSLParser()
        with pytest.raises(SagaDSLError, match="name"):
            parser.parse({"session_id": "s1", "steps": [{"id": "s", "action_id": "a", "agent": "x"}]})

    def test_parse_missing_session_id(self):
        parser = SagaDSLParser()
        with pytest.raises(SagaDSLError, match="session_id"):
            parser.parse({"name": "x", "steps": [{"id": "s", "action_id": "a", "agent": "x"}]})

    def test_parse_empty_steps(self):
        parser = SagaDSLParser()
        with pytest.raises(SagaDSLError, match="step"):
            parser.parse({"name": "x", "session_id": "s1", "steps": []})

    def test_parse_duplicate_step_ids(self):
        parser = SagaDSLParser()
        with pytest.raises(SagaDSLError, match="Duplicate"):
            parser.parse({
                "name": "x",
                "session_id": "s1",
                "steps": [
                    {"id": "dup", "action_id": "a1", "agent": "x"},
                    {"id": "dup", "action_id": "a2", "agent": "y"},
                ],
            })

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_parse_invalid_fan_out_policy(self):
        pass

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_parse_fan_out_invalid_branch(self):
        pass

    @pytest.mark.skip("Feature not available in Public Preview")
    def test_parse_fan_out_too_few_branches(self):
        pass

    def test_to_saga_steps(self):
        parser = SagaDSLParser()
        defn = parser.parse({
            "name": "x",
            "session_id": "s1",
            "steps": [
                {"id": "s1", "action_id": "a1", "agent": "x", "execute_api": "/run"},
            ],
        })
        steps = parser.to_saga_steps(defn)
        assert len(steps) == 1
        assert steps[0].step_id == "s1"
        assert steps[0].execute_api == "/run"

    def test_validate_errors(self):
        parser = SagaDSLParser()
        errors = parser.validate({})
        assert "Missing 'name'" in errors
        assert "Missing 'session_id'" in errors
        assert "Missing 'steps'" in errors

    def test_validate_valid(self):
        parser = SagaDSLParser()
        errors = parser.validate({
            "name": "x",
            "session_id": "s1",
            "steps": [{"id": "a", "action_id": "b", "agent": "c"}],
        })
        assert errors == []

    def test_sequential_steps(self):
        parser = SagaDSLParser()
        defn = parser.parse({
            "name": "x",
            "session_id": "s1",
            "steps": [
                {"id": "seq1", "action_id": "a", "agent": "x"},
                {"id": "par1", "action_id": "b", "agent": "y"},
                {"id": "par2", "action_id": "c", "agent": "z"},
            ],
            "fan_out": [{"policy": "all_must_succeed", "branches": ["par1", "par2"]}],
        })
        # Public Preview: all steps are sequential (fan_out ignored)
        assert len(defn.sequential_steps) == 3
