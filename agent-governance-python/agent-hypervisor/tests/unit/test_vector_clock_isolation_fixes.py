# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for VectorClock causal predicates (issue #2335) and
SessionIsolationManager fail-closed behavior (issue #2336)."""

import logging

import pytest

from hypervisor.session.isolation import (
    IsolationLevel,
    SessionIsolationManager,
    SessionScope,
)
from hypervisor.session.vector_clock import VectorClock, VectorClockManager


# ── VectorClock.happens_before tests (#2335) ──────────────────────────────────


class TestHappensBefore:
    def test_empty_clocks_are_equal_not_ordered(self):
        a = VectorClock()
        b = VectorClock()
        # Two empty clocks are concurrent, neither precedes the other
        assert not a.happens_before(b)
        assert not b.happens_before(a)

    def test_single_tick_creates_ordering(self):
        a = VectorClock()
        b = VectorClock()
        b.tick("agent-1")
        # a has no events so a <= b component-wise, and b has one event a lacks
        assert a.happens_before(b)
        assert not b.happens_before(a)

    def test_multiple_ticks_same_agent(self):
        a = VectorClock(clocks={"agent-1": 1})
        b = VectorClock(clocks={"agent-1": 3})
        assert a.happens_before(b)
        assert not b.happens_before(a)

    def test_ordering_with_multiple_agents(self):
        # a has seen events from both agents; b has seen more from agent-2
        a = VectorClock(clocks={"agent-1": 2, "agent-2": 1})
        b = VectorClock(clocks={"agent-1": 2, "agent-2": 3})
        assert a.happens_before(b)
        assert not b.happens_before(a)

    def test_equal_clocks_do_not_happen_before_each_other(self):
        a = VectorClock(clocks={"agent-1": 2, "agent-2": 1})
        b = VectorClock(clocks={"agent-1": 2, "agent-2": 1})
        assert not a.happens_before(b)
        assert not b.happens_before(a)

    def test_not_reflexive(self):
        a = VectorClock(clocks={"agent-1": 1})
        assert not a.happens_before(a)

    def test_divergent_agents_no_ordering(self):
        # a has events agent-1 has not seen; b has events agent-2 has not seen
        a = VectorClock(clocks={"agent-1": 3, "agent-2": 1})
        b = VectorClock(clocks={"agent-1": 1, "agent-2": 5})
        assert not a.happens_before(b)
        assert not b.happens_before(a)

    def test_happens_before_transitive(self):
        a = VectorClock(clocks={"agent-1": 1})
        b = VectorClock(clocks={"agent-1": 2})
        c = VectorClock(clocks={"agent-1": 3})
        assert a.happens_before(b)
        assert b.happens_before(c)
        assert a.happens_before(c)

    def test_happens_before_sparse_agents(self):
        # a only knows about agent-1; b knows about agent-1 and agent-2
        a = VectorClock(clocks={"agent-1": 1})
        b = VectorClock(clocks={"agent-1": 2, "agent-2": 1})
        assert a.happens_before(b)
        assert not b.happens_before(a)


class TestIsConcurrent:
    def test_divergent_clocks_are_concurrent(self):
        a = VectorClock(clocks={"agent-1": 3, "agent-2": 1})
        b = VectorClock(clocks={"agent-1": 1, "agent-2": 5})
        assert a.is_concurrent(b)
        assert b.is_concurrent(a)

    def test_ordered_clocks_are_not_concurrent(self):
        a = VectorClock(clocks={"agent-1": 1})
        b = VectorClock(clocks={"agent-1": 2})
        assert not a.is_concurrent(b)
        assert not b.is_concurrent(a)

    def test_equal_clocks_are_concurrent(self):
        a = VectorClock(clocks={"agent-1": 2})
        b = VectorClock(clocks={"agent-1": 2})
        assert a.is_concurrent(b)

    def test_empty_clocks_are_concurrent(self):
        a = VectorClock()
        b = VectorClock()
        assert a.is_concurrent(b)

    def test_concurrent_is_symmetric(self):
        a = VectorClock(clocks={"agent-1": 2, "agent-2": 0})
        b = VectorClock(clocks={"agent-1": 0, "agent-2": 3})
        assert a.is_concurrent(b)
        assert b.is_concurrent(a)


class TestVectorClockManagerCausal:
    def test_write_advances_path_clock_for_agent(self):
        mgr = VectorClockManager()
        mgr.write("/data/x", "agent-1")
        clock = mgr.get_path_clock("/data/x")
        assert clock.get("agent-1") == 1

    def test_two_independent_writes_produce_concurrent_clocks(self):
        mgr = VectorClockManager()
        mgr.write("/data/x", "agent-1")
        mgr.write("/data/y", "agent-2")
        cx = mgr.get_path_clock("/data/x")
        cy = mgr.get_path_clock("/data/y")
        # Neither path's clock happened before the other
        assert cx.is_concurrent(cy)

    def test_sequential_writes_on_same_path_produce_ordering(self):
        mgr = VectorClockManager()
        mgr.write("/data/x", "agent-1")
        clock_after_first = mgr.get_path_clock("/data/x").copy()
        mgr.write("/data/x", "agent-1")
        clock_after_second = mgr.get_path_clock("/data/x")
        assert clock_after_first.happens_before(clock_after_second)


# ── SessionIsolationManager fail-closed tests (#2336) ─────────────────────────


class TestCheckAccessFailClosed:
    def test_unknown_session_denied(self):
        mgr = SessionIsolationManager()
        # no scope registered for "ghost-session"
        result = mgr.check_access("ghost-session", "/var/agt/sessions/ghost-session/data")
        assert result is False

    def test_unknown_session_denied_root_path(self):
        mgr = SessionIsolationManager()
        # even a totally benign path is denied when there is no scope
        assert mgr.check_access("ghost-session", "/var/agt/sessions/any/path") is False

    def test_unknown_session_emits_warning(self, caplog):
        mgr = SessionIsolationManager()
        with caplog.at_level(logging.WARNING, logger="hypervisor.session.isolation"):
            mgr.check_access("ghost-session", "/some/path")
        assert "ghost-session" in caplog.text
        assert any("denying" in msg.lower() for msg in caplog.messages)

    def test_scoped_session_allows_own_path(self):
        mgr = SessionIsolationManager()
        mgr.create_scope("sid1", "did:mesh:agent-1", IsolationLevel.SNAPSHOT)
        assert mgr.check_access("sid1", "/var/agt/sessions/sid1/work.txt")

    def test_scoped_session_denies_other_session_path(self):
        mgr = SessionIsolationManager()
        mgr.create_scope("sid1", "did:mesh:agent-1", IsolationLevel.SNAPSHOT)
        mgr.create_scope("sid2", "did:mesh:agent-2", IsolationLevel.SNAPSHOT)
        # SNAPSHOT cannot read across sessions
        assert not mgr.check_access("sid1", "/var/agt/sessions/sid2/secret.txt")

    def test_read_committed_grants_work(self):
        mgr = SessionIsolationManager()
        mgr.create_scope("sid1", "did:mesh:agent-1", IsolationLevel.READ_COMMITTED)
        mgr.create_scope("sid2", "did:mesh:agent-2", IsolationLevel.READ_COMMITTED)
        granted = mgr.grant_cross_session_access("sid1", "sid2")
        assert granted
        assert mgr.check_access("sid1", "/var/agt/sessions/sid2/data")

    def test_scope_removed_then_access_denied(self):
        mgr = SessionIsolationManager()
        mgr.create_scope("sid1", "did:mesh:agent-1", IsolationLevel.SNAPSHOT)
        mgr.remove_scope("sid1")
        # After removal the session is unscoped and should be denied
        assert mgr.check_access("sid1", "/var/agt/sessions/sid1/data") is False

    def test_active_sessions_count_after_removal(self):
        mgr = SessionIsolationManager()
        mgr.create_scope("sid1", "did:mesh:a1")
        mgr.create_scope("sid2", "did:mesh:a2")
        assert mgr.active_sessions == 2
        mgr.remove_scope("sid1")
        assert mgr.active_sessions == 1
