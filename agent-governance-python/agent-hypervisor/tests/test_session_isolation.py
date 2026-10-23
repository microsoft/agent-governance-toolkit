# Copyright (c) Microsoft Corporation. Licensed under the MIT License.
"""Tests for VectorClock and SessionIsolationManager fixes."""

import threading

import pytest

from hypervisor.session.isolation import IsolationLevel, SessionIsolationManager, SessionScope
from hypervisor.session.vector_clock import VectorClock


class TestVectorClockHappensBefore:
    """Verify happens_before implements standard vector clock comparison."""

    def test_empty_clocks_not_happens_before(self):
        a = VectorClock()
        b = VectorClock()
        assert not a.happens_before(b)

    def test_strictly_less_happens_before(self):
        a = VectorClock(clocks={"agent1": 1})
        b = VectorClock(clocks={"agent1": 2})
        assert a.happens_before(b)

    def test_equal_clocks_not_happens_before(self):
        a = VectorClock(clocks={"agent1": 2})
        b = VectorClock(clocks={"agent1": 2})
        assert not a.happens_before(b)

    def test_greater_not_happens_before(self):
        a = VectorClock(clocks={"agent1": 3})
        b = VectorClock(clocks={"agent1": 2})
        assert not a.happens_before(b)

    def test_multi_agent_happens_before(self):
        a = VectorClock(clocks={"agent1": 1, "agent2": 2})
        b = VectorClock(clocks={"agent1": 2, "agent2": 3})
        assert a.happens_before(b)

    def test_multi_agent_not_happens_before_when_any_greater(self):
        a = VectorClock(clocks={"agent1": 3, "agent2": 1})
        b = VectorClock(clocks={"agent1": 2, "agent2": 2})
        assert not a.happens_before(b)

    def test_missing_agent_treated_as_zero(self):
        a = VectorClock(clocks={"agent1": 1})
        b = VectorClock(clocks={"agent1": 1, "agent2": 1})
        assert a.happens_before(b)


class TestVectorClockIsConcurrent:
    """Verify is_concurrent detects when neither clock precedes the other."""

    def test_concurrent_when_diverged(self):
        a = VectorClock(clocks={"agent1": 2, "agent2": 1})
        b = VectorClock(clocks={"agent1": 1, "agent2": 2})
        assert a.is_concurrent(b)

    def test_not_concurrent_when_ordered(self):
        a = VectorClock(clocks={"agent1": 1})
        b = VectorClock(clocks={"agent1": 2})
        assert not a.is_concurrent(b)

    def test_not_concurrent_when_equal(self):
        a = VectorClock(clocks={"agent1": 1})
        b = VectorClock(clocks={"agent1": 1})
        assert not a.is_concurrent(b)

    def test_tick_then_concurrent(self):
        """Two agents ticking independently should produce concurrent clocks."""
        a = VectorClock()
        b = VectorClock()
        a.tick("agent1")
        b.tick("agent2")
        assert a.is_concurrent(b)


def _call_with_timeout(func, timeout=2.0):
    """Run ``func`` in a daemon thread so a deadlock fails the test instead of hanging it."""
    result = {}

    def target():
        result["value"] = func()

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    thread.join(timeout)
    assert not thread.is_alive(), "call did not return (deadlock)"
    return result["value"]


class TestVectorClockSelfComparison:
    """Comparing or merging a clock with itself must not deadlock on its own lock."""

    def test_equal_to_itself(self):
        a = VectorClock(clocks={"agent1": 2})
        assert _call_with_timeout(lambda: a == a) is True

    def test_does_not_happen_before_itself(self):
        a = VectorClock(clocks={"agent1": 2})
        assert _call_with_timeout(lambda: a.happens_before(a)) is False

    def test_not_concurrent_with_itself(self):
        a = VectorClock(clocks={"agent1": 2})
        assert _call_with_timeout(lambda: a.is_concurrent(a)) is False

    def test_merge_with_itself(self):
        a = VectorClock(clocks={"agent1": 2, "agent2": 1})
        merged = _call_with_timeout(lambda: a.merge(a))
        assert merged.clocks == {"agent1": 2, "agent2": 1}
        assert merged is not a


class TestSessionIsolationFailClosed:
    """Verify check_access returns False for unscoped sessions."""

    def test_unscoped_session_denied(self):
        mgr = SessionIsolationManager()
        assert (
            mgr.check_access("unknown-session", "/var/agt/sessions/unknown-session/data") is False
        )

    def test_scoped_session_allowed_own_path(self):
        mgr = SessionIsolationManager()
        mgr.create_scope("session-1", "did:mesh:agent-1")
        assert mgr.check_access("session-1", "/var/agt/sessions/session-1/output.json") is True

    def test_scoped_session_denied_other_path(self):
        mgr = SessionIsolationManager()
        mgr.create_scope("session-1", "did:mesh:agent-1")
        assert mgr.check_access("session-1", "/var/agt/sessions/session-2/secret.json") is False

    def test_removed_scope_denied(self):
        mgr = SessionIsolationManager()
        mgr.create_scope("session-1", "did:mesh:agent-1")
        mgr.remove_scope("session-1")
        assert mgr.check_access("session-1", "/var/agt/sessions/session-1/data") is False

    def test_path_traversal_with_relative_segments_denied(self):
        mgr = SessionIsolationManager()
        mgr.create_scope("session-1", "did:mesh:agent-1")
        assert (
            mgr.check_access("session-1", "/var/agt/sessions/session-1/../session-2/secret.json")
            is False
        )
        assert (
            mgr.check_access("session-1", "/var/agt/sessions/session-1/../../etc/passwd") is False
        )

    def test_sibling_prefix_collision_denied(self):
        mgr = SessionIsolationManager()
        mgr.create_scope("session-1", "did:mesh:agent-1")
        assert mgr.check_access("session-1", "/var/agt/sessions/session-1-extra/data.json") is False
        assert mgr.check_access("session-1", "/var/agt/sessions/session-10/data.json") is False

    def test_nested_subdirectories_allowed(self):
        mgr = SessionIsolationManager()
        mgr.create_scope("session-1", "did:mesh:agent-1")
        assert (
            mgr.check_access("session-1", "/var/agt/sessions/session-1/sub/dir/output.json") is True
        )
        assert mgr.check_access("session-1", "/var/agt/sessions/session-1") is True

    def test_granted_session_relative_traversal_denied(self):
        mgr = SessionIsolationManager()
        mgr.create_scope(
            "session-1",
            "did:mesh:agent-1",
            isolation_level=IsolationLevel.READ_COMMITTED,
        )
        mgr.create_scope(
            "session-2",
            "did:mesh:agent-2",
            isolation_level=IsolationLevel.READ_COMMITTED,
        )
        mgr.create_scope(
            "session-3",
            "did:mesh:agent-3",
            isolation_level=IsolationLevel.READ_COMMITTED,
        )
        assert mgr.grant_cross_session_access("session-1", "session-2") is True

        # Valid granted access
        assert mgr.check_access("session-1", "/var/agt/sessions/session-2/data.json") is True
        # Attempt to traverse out of granted session into session-3
        assert (
            mgr.check_access("session-1", "/var/agt/sessions/session-2/../session-3/secret.json")
            is False
        )
        # Sibling collision on granted session
        assert (
            mgr.check_access("session-1", "/var/agt/sessions/session-2-attacker/data.json") is False
        )

    def test_scope_widening_via_traversal_session_id_denied(self):
        """Direct SessionScope with '..' or traversal id cannot widen access to parent directory."""
        scope = SessionScope(
            session_id="..",
            agent_did="did:mesh:a",
            base_path="/var/agt/sessions",
        )
        assert scope.is_path_allowed("/var/agt/secret") is False

        scope_sub = SessionScope(
            session_id="s/../other",
            agent_did="did:mesh:a",
            base_path="/var/agt/sessions",
        )
        assert scope_sub.is_path_allowed("/var/agt/sessions/other/x") is False

    def test_create_scope_invalid_session_ids_rejected(self):
        mgr = SessionIsolationManager()
        for invalid_id in ["..", ".", "s/../other", "s/other", "foo/bar", "", "  "]:
            with pytest.raises(ValueError, match="Invalid session identifier"):
                mgr.create_scope(invalid_id, "did:mesh:agent-1")

    def test_grant_access_invalid_session_ids_rejected(self):
        mgr = SessionIsolationManager()
        mgr.create_scope(
            "session-1",
            "did:mesh:agent-1",
            isolation_level=IsolationLevel.READ_COMMITTED,
        )
        # Manager method returns False
        assert mgr.grant_cross_session_access("session-1", "..") is False
        assert mgr.grant_cross_session_access("session-1", "s/../other") is False
        assert mgr.grant_cross_session_access("session-1", "") is False

        # Direct scope.grant_access raises ValueError
        scope = mgr.get_scope("session-1")
        assert scope is not None
        with pytest.raises(ValueError, match="Invalid session identifier"):
            scope.grant_access("..")
        with pytest.raises(ValueError, match="Invalid session identifier"):
            scope.grant_access("other/session")
