# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Intent-Based Authorization (agent_os.intent)."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta

import pytest

from agent_os.intent import (
    DEFAULT_DRIFT_PENALTY,
    DriftEvent,
    DriftPolicy,
    ExecutionIntent,
    ExecutionRecord,
    IntentAction,
    IntentCheckResult,
    IntentManager,
    IntentNotFoundError,
    IntentScopeError,
    IntentState,
    IntentStateError,
    IntentVerification,
    IntentVersionConflict,
    _hash_params,
)
from agent_os.stateless import ExecutionContext, MemoryBackend, StatelessKernel


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def backend():
    return MemoryBackend()


@pytest.fixture
def manager(backend):
    return IntentManager(backend=backend)


def _run(coro):
    """Helper to run async in sync tests."""
    return asyncio.get_event_loop().run_until_complete(coro)


# ---------------------------------------------------------------------------
# IntentAction Tests
# ---------------------------------------------------------------------------

class TestIntentAction:
    def test_matches_same_action(self):
        ia = IntentAction(action="database_query")
        assert ia.matches("database_query")

    def test_no_match_different_action(self):
        ia = IntentAction(action="database_query")
        assert not ia.matches("file_write")

    def test_matches_with_params_schema(self):
        ia = IntentAction(action="database_query", params_schema={"mode": "read"})
        assert ia.matches("database_query", {"mode": "read", "query": "SELECT 1"})

    def test_no_match_wrong_param(self):
        ia = IntentAction(action="database_query", params_schema={"mode": "read"})
        assert not ia.matches("database_query", {"mode": "write"})

    def test_roundtrip_dict(self):
        ia = IntentAction(action="file_read", params_schema={"path": "/tmp"})
        restored = IntentAction.from_dict(ia.to_dict())
        assert restored.action == ia.action
        assert restored.params_schema == ia.params_schema


# ---------------------------------------------------------------------------
# ExecutionRecord Tests
# ---------------------------------------------------------------------------

class TestExecutionRecord:
    def test_roundtrip_dict(self):
        rec = ExecutionRecord(
            action="database_query",
            agent_id="a1",
            request_id="r1",
            was_planned=True,
            outcome="executed",
        )
        restored = ExecutionRecord.from_dict(rec.to_dict())
        assert restored.action == rec.action
        assert restored.was_planned == rec.was_planned


# ---------------------------------------------------------------------------
# DriftEvent Tests
# ---------------------------------------------------------------------------

class TestDriftEvent:
    def test_roundtrip_dict(self):
        evt = DriftEvent(
            intent_id="intent:abc",
            agent_id="a1",
            request_id="r1",
            action_attempted="file_write",
            was_planned=False,
            drift_policy_applied=DriftPolicy.SOFT_BLOCK,
            result="allowed_with_penalty",
            trust_penalty=50.0,
        )
        restored = DriftEvent.from_dict(evt.to_dict())
        assert restored.intent_id == evt.intent_id
        assert restored.drift_policy_applied == DriftPolicy.SOFT_BLOCK


# ---------------------------------------------------------------------------
# ExecutionIntent Tests
# ---------------------------------------------------------------------------

class TestExecutionIntent:
    def test_roundtrip_dict(self):
        intent = ExecutionIntent(
            agent_id="a1",
            planned_actions=[IntentAction(action="query")],
            drift_policy=DriftPolicy.HARD_BLOCK,
        )
        restored = ExecutionIntent.from_dict(intent.to_dict())
        assert restored.agent_id == "a1"
        assert restored.drift_policy == DriftPolicy.HARD_BLOCK
        assert len(restored.planned_actions) == 1

    def test_is_terminal(self):
        intent = ExecutionIntent(agent_id="a1", state=IntentState.COMPLETED)
        assert intent.is_terminal

    def test_not_terminal(self):
        intent = ExecutionIntent(agent_id="a1", state=IntentState.DECLARED)
        assert not intent.is_terminal

    def test_planned_action_names(self):
        intent = ExecutionIntent(
            agent_id="a1",
            planned_actions=[
                IntentAction(action="read"),
                IntentAction(action="write"),
            ],
        )
        assert intent.planned_action_names == {"read", "write"}


# ---------------------------------------------------------------------------
# IntentManager Lifecycle Tests
# ---------------------------------------------------------------------------

class TestIntentLifecycle:
    """Full lifecycle: declare -> approve -> execute -> verify."""

    def test_full_lifecycle(self, manager):
        # Declare
        intent = _run(manager.declare_intent(
            agent_id="agent-1",
            planned_actions=[
                IntentAction(action="database_query"),
                IntentAction(action="file_read"),
            ],
        ))
        assert intent.state == IntentState.DECLARED
        assert intent.agent_id == "agent-1"
        assert len(intent.planned_actions) == 2

        # Approve
        intent = _run(manager.approve_intent(intent.intent_id))
        assert intent.state == IntentState.APPROVED
        assert intent.approved_at is not None

        # Execute a planned action
        check = _run(manager.check_action(
            intent.intent_id, "database_query", {}, "agent-1", "req-1"
        ))
        assert check.allowed
        assert check.was_planned

        # Execute another planned action
        check2 = _run(manager.check_action(
            intent.intent_id, "file_read", {}, "agent-1", "req-2"
        ))
        assert check2.allowed
        assert check2.was_planned

        # Verify
        verification = _run(manager.verify_intent(intent.intent_id))
        assert verification.planned_actions == ["database_query", "file_read"]
        assert verification.executed_actions == ["database_query", "file_read"]
        assert verification.unplanned_actions == []
        assert verification.missed_actions == []
        assert verification.total_drift_events == 0
        assert verification.state == IntentState.COMPLETED

    def test_declare_creates_unique_ids(self, manager):
        i1 = _run(manager.declare_intent("a1", [IntentAction(action="x")]))
        i2 = _run(manager.declare_intent("a1", [IntentAction(action="x")]))
        assert i1.intent_id != i2.intent_id


# ---------------------------------------------------------------------------
# Drift Detection Tests
# ---------------------------------------------------------------------------

class TestDriftDetection:
    def test_soft_block_allows_with_penalty(self, manager):
        intent = _run(manager.declare_intent(
            agent_id="a1",
            planned_actions=[IntentAction(action="read")],
            drift_policy=DriftPolicy.SOFT_BLOCK,
        ))
        _run(manager.approve_intent(intent.intent_id))

        # Attempt unplanned action
        check = _run(manager.check_action(
            intent.intent_id, "write", {}, "a1", "r1"
        ))
        assert check.allowed
        assert not check.was_planned
        assert check.trust_penalty == DEFAULT_DRIFT_PENALTY
        assert check.drift_policy_applied == DriftPolicy.SOFT_BLOCK
        assert check.drift_event is not None

    def test_hard_block_denies(self, manager):
        intent = _run(manager.declare_intent(
            agent_id="a1",
            planned_actions=[IntentAction(action="read")],
            drift_policy=DriftPolicy.HARD_BLOCK,
        ))
        _run(manager.approve_intent(intent.intent_id))

        check = _run(manager.check_action(
            intent.intent_id, "write", {}, "a1", "r1"
        ))
        assert not check.allowed
        assert not check.was_planned
        assert check.drift_policy_applied == DriftPolicy.HARD_BLOCK

    def test_re_declare_denies(self, manager):
        intent = _run(manager.declare_intent(
            agent_id="a1",
            planned_actions=[IntentAction(action="read")],
            drift_policy=DriftPolicy.RE_DECLARE,
        ))
        _run(manager.approve_intent(intent.intent_id))

        check = _run(manager.check_action(
            intent.intent_id, "delete", {}, "a1", "r1"
        ))
        assert not check.allowed
        assert check.drift_policy_applied == DriftPolicy.RE_DECLARE

    def test_drift_recorded_in_verification(self, manager):
        intent = _run(manager.declare_intent(
            agent_id="a1",
            planned_actions=[IntentAction(action="read")],
            drift_policy=DriftPolicy.SOFT_BLOCK,
        ))
        _run(manager.approve_intent(intent.intent_id))
        _run(manager.check_action(intent.intent_id, "read", {}, "a1", "r1"))
        _run(manager.check_action(intent.intent_id, "write", {}, "a1", "r2"))  # drift

        v = _run(manager.verify_intent(intent.intent_id))
        assert v.total_drift_events == 1
        assert v.unplanned_actions == ["write"]
        assert v.state == IntentState.VIOLATED


# ---------------------------------------------------------------------------
# Child Intent Tests
# ---------------------------------------------------------------------------

class TestChildIntent:
    def test_child_narrows_scope(self, manager):
        parent = _run(manager.declare_intent(
            agent_id="orchestrator",
            planned_actions=[
                IntentAction(action="read"),
                IntentAction(action="write"),
                IntentAction(action="delete"),
            ],
        ))

        child = _run(manager.create_child_intent(
            parent_intent_id=parent.intent_id,
            agent_id="sub-agent-1",
            planned_actions=[IntentAction(action="read")],
        ))
        assert child.parent_intent_id == parent.intent_id
        assert child.agent_id == "sub-agent-1"
        assert len(child.planned_actions) == 1

    def test_child_cannot_expand_scope(self, manager):
        parent = _run(manager.declare_intent(
            agent_id="orchestrator",
            planned_actions=[IntentAction(action="read")],
        ))

        with pytest.raises(IntentScopeError, match="Excess actions"):
            _run(manager.create_child_intent(
                parent_intent_id=parent.intent_id,
                agent_id="sub-agent",
                planned_actions=[
                    IntentAction(action="read"),
                    IntentAction(action="delete"),
                ],
            ))

    def test_child_inherits_drift_policy(self, manager):
        parent = _run(manager.declare_intent(
            agent_id="orchestrator",
            planned_actions=[IntentAction(action="read")],
            drift_policy=DriftPolicy.HARD_BLOCK,
        ))

        child = _run(manager.create_child_intent(
            parent_intent_id=parent.intent_id,
            agent_id="sub",
            planned_actions=[IntentAction(action="read")],
        ))
        assert child.drift_policy == DriftPolicy.HARD_BLOCK

    def test_child_can_override_drift_policy(self, manager):
        parent = _run(manager.declare_intent(
            agent_id="orch",
            planned_actions=[IntentAction(action="read")],
            drift_policy=DriftPolicy.HARD_BLOCK,
        ))

        child = _run(manager.create_child_intent(
            parent_intent_id=parent.intent_id,
            agent_id="sub",
            planned_actions=[IntentAction(action="read")],
            drift_policy=DriftPolicy.SOFT_BLOCK,
        ))
        assert child.drift_policy == DriftPolicy.SOFT_BLOCK


# ---------------------------------------------------------------------------
# Expiry Tests
# ---------------------------------------------------------------------------

class TestIntentExpiry:
    def test_expired_intent_blocked_on_check(self, manager):
        intent = _run(manager.declare_intent(
            agent_id="a1",
            planned_actions=[IntentAction(action="read")],
            ttl_seconds=0,
        ))
        _run(manager.approve_intent(intent.intent_id))

        # Force expiry by setting expires_at in the past
        loaded = _run(manager.get_intent(intent.intent_id))
        loaded.expires_at = datetime.now(UTC) - timedelta(seconds=10)
        # Save directly via backend
        _run(manager._backend.set(manager._key(loaded.intent_id), loaded.to_dict()))

        check = _run(manager.check_action(
            loaded.intent_id, "read", {}, "a1", "r1"
        ))
        assert not check.allowed
        assert "expired" in check.reason

    def test_ttl_sets_expires_at(self, manager):
        intent = _run(manager.declare_intent(
            agent_id="a1",
            planned_actions=[IntentAction(action="read")],
            ttl_seconds=300,
        ))
        assert intent.expires_at is not None


# ---------------------------------------------------------------------------
# State Machine Tests
# ---------------------------------------------------------------------------

class TestStateMachine:
    def test_cannot_approve_executing_intent(self, manager):
        intent = _run(manager.declare_intent(
            agent_id="a1",
            planned_actions=[IntentAction(action="read")],
        ))
        _run(manager.approve_intent(intent.intent_id))
        _run(manager.check_action(intent.intent_id, "read", {}, "a1", "r1"))

        with pytest.raises(IntentStateError):
            _run(manager.approve_intent(intent.intent_id))

    def test_cannot_check_unapproved_intent(self, manager):
        intent = _run(manager.declare_intent(
            agent_id="a1",
            planned_actions=[IntentAction(action="read")],
        ))
        check = _run(manager.check_action(
            intent.intent_id, "read", {}, "a1", "r1"
        ))
        assert not check.allowed
        assert "declared" in check.reason.lower()

    def test_cannot_verify_completed_intent(self, manager):
        intent = _run(manager.declare_intent(
            agent_id="a1",
            planned_actions=[IntentAction(action="read")],
        ))
        _run(manager.approve_intent(intent.intent_id))
        _run(manager.check_action(intent.intent_id, "read", {}, "a1", "r1"))
        _run(manager.verify_intent(intent.intent_id))

        with pytest.raises(IntentStateError):
            _run(manager.verify_intent(intent.intent_id))


# ---------------------------------------------------------------------------
# Backwards Compatibility Tests
# ---------------------------------------------------------------------------

class TestBackwardsCompat:
    def test_execution_context_without_intent(self):
        """Existing code without intent_id works unchanged."""
        ctx = ExecutionContext(agent_id="a1", policies=["read_only"])
        assert ctx.intent_id is None
        d = ctx.to_dict()
        assert "intent_id" not in d

    def test_execution_context_with_intent(self):
        ctx = ExecutionContext(
            agent_id="a1",
            policies=["read_only"],
            intent_id="intent:abc123",
        )
        assert ctx.intent_id == "intent:abc123"
        d = ctx.to_dict()
        assert d["intent_id"] == "intent:abc123"

    def test_kernel_without_intent_manager(self):
        """Kernel works without intent_manager, just like before."""
        kernel = StatelessKernel()
        assert kernel.intent_manager is None

        result = _run(kernel.execute(
            "database_query",
            {"query": "SELECT 1"},
            ExecutionContext(agent_id="a1"),
        ))
        assert result.success


# ---------------------------------------------------------------------------
# Kernel Integration Tests
# ---------------------------------------------------------------------------

class TestKernelIntegration:
    def test_kernel_with_intent_planned_action(self, backend):
        mgr = IntentManager(backend=backend)
        kernel = StatelessKernel(intent_manager=mgr)

        intent = _run(mgr.declare_intent(
            agent_id="a1",
            planned_actions=[IntentAction(action="database_query")],
        ))
        _run(mgr.approve_intent(intent.intent_id))

        ctx = ExecutionContext(
            agent_id="a1",
            intent_id=intent.intent_id,
        )
        result = _run(kernel.execute("database_query", {"q": "SELECT 1"}, ctx))
        assert result.success
        assert result.metadata.get("intent_drift") is None

    def test_kernel_with_intent_soft_block_drift(self, backend):
        mgr = IntentManager(backend=backend)
        kernel = StatelessKernel(intent_manager=mgr)

        intent = _run(mgr.declare_intent(
            agent_id="a1",
            planned_actions=[IntentAction(action="read")],
            drift_policy=DriftPolicy.SOFT_BLOCK,
        ))
        _run(mgr.approve_intent(intent.intent_id))

        ctx = ExecutionContext(agent_id="a1", intent_id=intent.intent_id)
        result = _run(kernel.execute("write", {}, ctx))
        assert result.success  # soft block allows
        assert result.metadata.get("intent_drift") is True
        assert result.metadata.get("trust_penalty") == DEFAULT_DRIFT_PENALTY

    def test_kernel_with_intent_hard_block_drift(self, backend):
        mgr = IntentManager(backend=backend)
        kernel = StatelessKernel(intent_manager=mgr)

        intent = _run(mgr.declare_intent(
            agent_id="a1",
            planned_actions=[IntentAction(action="read")],
            drift_policy=DriftPolicy.HARD_BLOCK,
        ))
        _run(mgr.approve_intent(intent.intent_id))

        ctx = ExecutionContext(agent_id="a1", intent_id=intent.intent_id)
        result = _run(kernel.execute("write", {}, ctx))
        assert not result.success
        assert result.metadata.get("intent_drift") is True
        assert result.signal == "SIGKILL"

    def test_kernel_intent_id_preserved_in_updated_context(self, backend):
        mgr = IntentManager(backend=backend)
        kernel = StatelessKernel(intent_manager=mgr)

        intent = _run(mgr.declare_intent(
            agent_id="a1",
            planned_actions=[IntentAction(action="chat")],
        ))
        _run(mgr.approve_intent(intent.intent_id))

        ctx = ExecutionContext(agent_id="a1", intent_id=intent.intent_id)
        result = _run(kernel.execute("chat", {}, ctx))
        assert result.success
        assert result.updated_context.intent_id == intent.intent_id

    def test_policy_denied_before_intent_check(self, backend):
        """Action denied by policy should not reach intent check."""
        mgr = IntentManager(backend=backend)
        kernel = StatelessKernel(intent_manager=mgr)

        intent = _run(mgr.declare_intent(
            agent_id="a1",
            planned_actions=[IntentAction(action="file_write")],
        ))
        _run(mgr.approve_intent(intent.intent_id))

        ctx = ExecutionContext(
            agent_id="a1",
            policies=["read_only"],
            intent_id=intent.intent_id,
        )
        result = _run(kernel.execute("file_write", {}, ctx))
        assert not result.success
        assert result.signal == "SIGKILL"
        # Intent should have no execution records (policy blocked first)
        loaded = _run(mgr.get_intent(intent.intent_id))
        assert len(loaded.execution_records) == 0


# ---------------------------------------------------------------------------
# Error Handling Tests
# ---------------------------------------------------------------------------

class TestErrorHandling:
    def test_get_nonexistent_intent(self, manager):
        result = _run(manager.get_intent("intent:doesnotexist"))
        assert result is None

    def test_approve_nonexistent_intent(self, manager):
        with pytest.raises(IntentNotFoundError):
            _run(manager.approve_intent("intent:doesnotexist"))

    def test_check_nonexistent_intent(self, manager):
        with pytest.raises(IntentNotFoundError):
            _run(manager.check_action("intent:nope", "x", {}, "a1", "r1"))


# ---------------------------------------------------------------------------
# Persistence / Round-trip Tests
# ---------------------------------------------------------------------------

class TestPersistence:
    def test_intent_survives_new_manager_instance(self, backend):
        """Intent persisted in backend is accessible from a new manager."""
        mgr1 = IntentManager(backend=backend)
        intent = _run(mgr1.declare_intent(
            agent_id="a1",
            planned_actions=[IntentAction(action="query")],
        ))

        mgr2 = IntentManager(backend=backend)
        loaded = _run(mgr2.get_intent(intent.intent_id))
        assert loaded is not None
        assert loaded.agent_id == "a1"
        assert loaded.planned_actions[0].action == "query"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_hash_params_deterministic(self):
        h1 = _hash_params({"a": 1, "b": 2})
        h2 = _hash_params({"b": 2, "a": 1})
        assert h1 == h2

    def test_hash_params_different_values(self):
        h1 = _hash_params({"a": 1})
        h2 = _hash_params({"a": 2})
        assert h1 != h2
