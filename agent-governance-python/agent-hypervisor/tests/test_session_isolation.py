# Copyright (c) Microsoft Corporation. Licensed under the MIT License.
"""Tests for VectorClock and SessionIsolationManager fixes."""

from hypervisor.session.isolation import IsolationLevel, SessionIsolationManager
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
