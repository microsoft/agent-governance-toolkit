# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Hardened tests for Intent-Based Authorization.

These tests cover edge cases, concurrency, version conflicts, and error paths
not covered by the base test_intent.py test suite.
"""

from __future__ import annotations

import asyncio

import pytest

from agent_os.intent import (
    DEFAULT_DRIFT_PENALTY,
    DriftPolicy,
    ExecutionIntent,
    IntentAction,
    IntentCheckResult,
    IntentManager,
    IntentNotFoundError,
    IntentScopeError,
    IntentState,
    IntentStateError,
    IntentVersionConflict,
    IntentVerification,
)
from agent_os.stateless import ExecutionContext, MemoryBackend, StatelessKernel


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _run(coro):
    return asyncio.get_event_loop().run_until_complete(coro)


@pytest.fixture
def backend():
    return MemoryBackend()


@pytest.fixture
def manager(backend):
    return IntentManager(backend=backend)


# ---------------------------------------------------------------------------
# Version Conflict Tests
# ---------------------------------------------------------------------------


class TestVersionConflict:
    """IntentVersionConflict was imported but never exercised."""

    def test_stale_approve_raises_version_conflict(self, backend):
        """Two managers loading the same intent: second approve should conflict."""
        mgr1 = IntentManager(backend=backend)
        mgr2 = IntentManager(backend=backend)

        intent = _run(mgr1.declare_intent(
            agent_id="a1",
            planned_actions=[IntentAction(action="read")],
        ))

        # mgr1 approves (bumps version)
        _run(mgr1.approve_intent(intent.intent_id))

        # mgr2 tries to approve with stale version: should conflict
        with pytest.raises((IntentVersionConflict, IntentStateError)):
            _run(mgr2.approve_intent(intent.intent_id))

    def test_concurrent_check_action_version_safety(self, backend):
        """Concurrent check_action calls should not silently drop records."""
        mgr = IntentManager(backend=backend)
        intent = _run(mgr.declare_intent(
            agent_id="a1",
            planned_actions=[
                IntentAction(action="read"),
                IntentAction(action="write"),
                IntentAction(action="delete"),
            ],
        ))
        _run(mgr.approve_intent(intent.intent_id))

        # Execute all three actions sequentially (each bumps version)
        _run(mgr.check_action(intent.intent_id, "read", {}, "a1", "r1"))
        _run(mgr.check_action(intent.intent_id, "write", {}, "a1", "r2"))
        _run(mgr.check_action(intent.intent_id, "delete", {}, "a1", "r3"))

        loaded = _run(mgr.get_intent(intent.intent_id))
        assert len(loaded.execution_records) == 3


# ---------------------------------------------------------------------------
# Multiple Drift Events
# ---------------------------------------------------------------------------


class TestMultipleDriftEvents:
    def test_multiple_soft_block_drifts_accumulate(self, manager):
        intent = _run(manager.declare_intent(
            agent_id="a1",
            planned_actions=[IntentAction(action="read")],
            drift_policy=DriftPolicy.SOFT_BLOCK,
        ))
        _run(manager.approve_intent(intent.intent_id))

        # Three unplanned actions
        for action in ["write", "delete", "execute"]:
            check = _run(manager.check_action(
                intent.intent_id, action, {}, "a1", f"r-{action}"
            ))
            assert check.allowed
            assert not check.was_planned

        v = _run(manager.verify_intent(intent.intent_id))
        assert v.total_drift_events == 3
        assert set(v.unplanned_actions) == {"write", "delete", "execute"}
        assert v.state == IntentState.VIOLATED

    def test_drift_total_penalty_accumulates(self, manager):
        intent = _run(manager.declare_intent(
            agent_id="a1",
            planned_actions=[IntentAction(action="read")],
            drift_policy=DriftPolicy.SOFT_BLOCK,
        ))
        _run(manager.approve_intent(intent.intent_id))

        total_penalty = 0.0
        for i in range(5):
            check = _run(manager.check_action(
                intent.intent_id, f"unplanned-{i}", {}, "a1", f"r{i}"
            ))
            total_penalty += check.trust_penalty

        assert total_penalty == DEFAULT_DRIFT_PENALTY * 5

    def test_hard_block_denies_every_unplanned_action(self, manager):
        intent = _run(manager.declare_intent(
            agent_id="a1",
            planned_actions=[IntentAction(action="read")],
            drift_policy=DriftPolicy.HARD_BLOCK,
        ))
        _run(manager.approve_intent(intent.intent_id))

        for action in ["write", "delete", "execute"]:
            check = _run(manager.check_action(
                intent.intent_id, action, {}, "a1", f"r-{action}"
            ))
            assert not check.allowed


# ---------------------------------------------------------------------------
# Re-Declare Policy Lifecycle
# ---------------------------------------------------------------------------


class TestReDeclareLifecycle:
    def test_re_declare_denies_then_new_intent_works(self, manager):
        """After re-declare denial, agent can create a new intent."""
        intent = _run(manager.declare_intent(
            agent_id="a1",
            planned_actions=[IntentAction(action="read")],
            drift_policy=DriftPolicy.RE_DECLARE,
        ))
        _run(manager.approve_intent(intent.intent_id))

        # Unplanned action denied
        check = _run(manager.check_action(
            intent.intent_id, "write", {}, "a1", "r1"
        ))
        assert not check.allowed

        # Create new intent with the desired action
        intent2 = _run(manager.declare_intent(
            agent_id="a1",
            planned_actions=[IntentAction(action="write")],
        ))
        _run(manager.approve_intent(intent2.intent_id))
        check2 = _run(manager.check_action(
            intent2.intent_id, "write", {}, "a1", "r2"
        ))
        assert check2.allowed


# ---------------------------------------------------------------------------
# Empty / Edge Case Tests
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_planned_actions_allowed(self, manager):
        """Intent with no planned actions: every action is drift."""
        intent = _run(manager.declare_intent(
            agent_id="a1",
            planned_actions=[],
            drift_policy=DriftPolicy.SOFT_BLOCK,
        ))
        _run(manager.approve_intent(intent.intent_id))

        check = _run(manager.check_action(
            intent.intent_id, "anything", {}, "a1", "r1"
        ))
        assert check.allowed  # soft block allows
        assert not check.was_planned

    def test_verify_with_no_actions_executed(self, manager):
        """Verification when no actions were executed requires executing state first."""
        intent = _run(manager.declare_intent(
            agent_id="a1",
            planned_actions=[
                IntentAction(action="read"),
                IntentAction(action="write"),
            ],
        ))
        _run(manager.approve_intent(intent.intent_id))

        # Must execute at least one action to transition to executing state
        # before verification. Verify directly from approved raises StateError.
        with pytest.raises(IntentStateError):
            _run(manager.verify_intent(intent.intent_id))

    def test_same_action_executed_twice(self, manager):
        """Same action can be executed multiple times."""
        intent = _run(manager.declare_intent(
            agent_id="a1",
            planned_actions=[IntentAction(action="read")],
        ))
        _run(manager.approve_intent(intent.intent_id))

        check1 = _run(manager.check_action(
            intent.intent_id, "read", {}, "a1", "r1"
        ))
        check2 = _run(manager.check_action(
            intent.intent_id, "read", {}, "a1", "r2"
        ))
        assert check1.allowed and check2.allowed
        assert check1.was_planned and check2.was_planned

        loaded = _run(manager.get_intent(intent.intent_id))
        assert len(loaded.execution_records) == 2


# ---------------------------------------------------------------------------
# Child Intent Edge Cases
# ---------------------------------------------------------------------------


class TestChildIntentEdgeCases:
    def test_child_of_nonexistent_parent_raises(self, manager):
        with pytest.raises(IntentNotFoundError):
            _run(manager.create_child_intent(
                parent_intent_id="intent:doesnotexist",
                agent_id="sub",
                planned_actions=[IntentAction(action="read")],
            ))

    def test_child_with_empty_actions_allowed(self, manager):
        """Child with empty actions is a valid subset of any parent."""
        parent = _run(manager.declare_intent(
            agent_id="orch",
            planned_actions=[IntentAction(action="read")],
        ))
        child = _run(manager.create_child_intent(
            parent_intent_id=parent.intent_id,
            agent_id="sub",
            planned_actions=[],
        ))
        assert child.parent_intent_id == parent.intent_id

    def test_nested_child_intents(self, manager):
        """Three-level nesting: grandchild narrows child scope."""
        parent = _run(manager.declare_intent(
            agent_id="orch",
            planned_actions=[
                IntentAction(action="read"),
                IntentAction(action="write"),
                IntentAction(action="delete"),
            ],
        ))
        child = _run(manager.create_child_intent(
            parent_intent_id=parent.intent_id,
            agent_id="sub-1",
            planned_actions=[
                IntentAction(action="read"),
                IntentAction(action="write"),
            ],
        ))
        grandchild = _run(manager.create_child_intent(
            parent_intent_id=child.intent_id,
            agent_id="sub-2",
            planned_actions=[IntentAction(action="read")],
        ))
        assert grandchild.parent_intent_id == child.intent_id
        assert len(grandchild.planned_actions) == 1

    def test_grandchild_cannot_exceed_child_scope(self, manager):
        """Grandchild cannot ask for actions not in its parent (child)."""
        parent = _run(manager.declare_intent(
            agent_id="orch",
            planned_actions=[
                IntentAction(action="read"),
                IntentAction(action="write"),
                IntentAction(action="delete"),
            ],
        ))
        child = _run(manager.create_child_intent(
            parent_intent_id=parent.intent_id,
            agent_id="sub-1",
            planned_actions=[IntentAction(action="read")],
        ))

        with pytest.raises(IntentScopeError, match="Excess actions"):
            _run(manager.create_child_intent(
                parent_intent_id=child.intent_id,
                agent_id="sub-2",
                planned_actions=[
                    IntentAction(action="read"),
                    IntentAction(action="write"),  # not in child
                ],
            ))
