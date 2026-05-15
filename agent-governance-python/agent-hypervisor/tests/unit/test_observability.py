# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the observability event bus and causal trace IDs."""

from datetime import UTC, datetime, timedelta

import pytest

from hypervisor.observability.causal_trace import CausalTraceId
from hypervisor.observability.event_bus import (
    EventType,
    HypervisorEvent,
    HypervisorEventBus,
)

# ── Event Bus Tests ─────────────────────────────────────────────


class TestHypervisorEventBus:
    def test_emit_and_retrieve(self):
        bus = HypervisorEventBus()
        event = HypervisorEvent(
            event_type=EventType.SESSION_CREATED,
            session_id="sess-1",
            agent_did="did:mesh:admin",
        )
        bus.emit(event)
        assert bus.event_count == 1
        assert bus.all_events[0] == event

    def test_query_by_type(self):
        bus = HypervisorEventBus()
        bus.emit(HypervisorEvent(event_type=EventType.SESSION_CREATED, session_id="s1"))
        bus.emit(HypervisorEvent(event_type=EventType.RING_ASSIGNED, session_id="s1"))
        bus.emit(HypervisorEvent(event_type=EventType.SESSION_CREATED, session_id="s2"))

        results = bus.query_by_type(EventType.SESSION_CREATED)
        assert len(results) == 2

    def test_query_by_session(self):
        bus = HypervisorEventBus()
        bus.emit(HypervisorEvent(event_type=EventType.SESSION_CREATED, session_id="s1"))
        bus.emit(HypervisorEvent(event_type=EventType.RING_ASSIGNED, session_id="s1"))
        bus.emit(HypervisorEvent(event_type=EventType.SESSION_CREATED, session_id="s2"))

        results = bus.query_by_session("s1")
        assert len(results) == 2

    def test_query_by_agent(self):
        bus = HypervisorEventBus()
        bus.emit(HypervisorEvent(event_type=EventType.RING_ASSIGNED, agent_did="a1"))
        bus.emit(HypervisorEvent(event_type=EventType.RING_DEMOTED, agent_did="a1"))
        bus.emit(HypervisorEvent(event_type=EventType.RING_ASSIGNED, agent_did="a2"))

        results = bus.query_by_agent("a1")
        assert len(results) == 2

    def test_query_combined_filters(self):
        bus = HypervisorEventBus()
        bus.emit(HypervisorEvent(
            event_type=EventType.RING_ASSIGNED,
            session_id="s1",
            agent_did="a1",
        ))
        bus.emit(HypervisorEvent(
            event_type=EventType.RING_ASSIGNED,
            session_id="s1",
            agent_did="a2",
        ))
        bus.emit(HypervisorEvent(
            event_type=EventType.SLASH_EXECUTED,
            session_id="s1",
            agent_did="a1",
        ))

        results = bus.query(
            event_type=EventType.RING_ASSIGNED,
            session_id="s1",
            agent_did="a1",
        )
        assert len(results) == 1

    def test_subscriber_notification(self):
        bus = HypervisorEventBus()
        received = []
        bus.subscribe(EventType.SLASH_EXECUTED, handler=lambda e: received.append(e))

        bus.emit(HypervisorEvent(event_type=EventType.SESSION_CREATED))
        bus.emit(HypervisorEvent(event_type=EventType.SLASH_EXECUTED))

        assert len(received) == 1
        assert received[0].event_type == EventType.SLASH_EXECUTED

    def test_wildcard_subscriber(self):
        bus = HypervisorEventBus()
        received = []
        bus.subscribe(event_type=None, handler=lambda e: received.append(e))

        bus.emit(HypervisorEvent(event_type=EventType.SESSION_CREATED))
        bus.emit(HypervisorEvent(event_type=EventType.SLASH_EXECUTED))

        assert len(received) == 2

    def test_type_counts(self):
        bus = HypervisorEventBus()
        bus.emit(HypervisorEvent(event_type=EventType.SESSION_CREATED))
        bus.emit(HypervisorEvent(event_type=EventType.SESSION_CREATED))
        bus.emit(HypervisorEvent(event_type=EventType.RING_ASSIGNED))

        counts = bus.type_counts()
        assert counts["session.created"] == 2
        assert counts["ring.assigned"] == 1

    def test_event_to_dict(self):
        event = HypervisorEvent(
            event_type=EventType.SLASH_EXECUTED,
            session_id="s1",
            agent_did="a1",
            payload={"severity": "high"},
        )
        d = event.to_dict()
        assert d["event_type"] == "liability.slash_executed"
        assert d["session_id"] == "s1"
        assert d["payload"]["severity"] == "high"

    def test_clear(self):
        bus = HypervisorEventBus()
        bus.emit(HypervisorEvent(event_type=EventType.SESSION_CREATED))
        assert bus.event_count == 1
        bus._clear()
        assert bus.event_count == 0

    def test_query_with_limit(self):
        bus = HypervisorEventBus()
        for i in range(10):
            bus.emit(HypervisorEvent(event_type=EventType.VFS_WRITE, session_id=f"s{i}"))

        results = bus.query(limit=3)
        assert len(results) == 3

    def test_query_by_time_range(self):
        bus = HypervisorEventBus()
        now = datetime.now(UTC)
        bus.emit(HypervisorEvent(event_type=EventType.SESSION_CREATED))
        results = bus.query_by_time_range(now - timedelta(seconds=1))
        assert len(results) == 1


# ── Causal Trace ID Tests ──────────────────────────────────────


class TestCausalTraceId:
    def test_create(self):
        trace = CausalTraceId()
        assert trace.trace_id
        assert trace.span_id
        assert trace.parent_span_id is None
        assert trace.depth == 0

    def test_child(self):
        parent = CausalTraceId()
        child = parent.child()
        assert child.trace_id == parent.trace_id
        assert child.parent_span_id == parent.span_id
        assert child.depth == 1
        assert child.span_id != parent.span_id

    def test_sibling(self):
        parent = CausalTraceId()
        child1 = parent.child()
        child2 = child1.sibling()
        assert child2.trace_id == parent.trace_id
        assert child2.parent_span_id == child1.parent_span_id
        assert child2.depth == child1.depth

    def test_full_id_format(self):
        trace = CausalTraceId(trace_id="abc", span_id="def")
        assert trace.full_id == "abc/def"

        child = CausalTraceId(trace_id="abc", span_id="ghi", parent_span_id="def")
        assert child.full_id == "abc/ghi/def"

    def test_from_string(self):
        trace = CausalTraceId.from_string("abc/def/ghi")
        assert trace.trace_id == "abc"
        assert trace.span_id == "def"
        assert trace.parent_span_id == "ghi"

    def test_from_string_no_parent(self):
        trace = CausalTraceId.from_string("abc/def")
        assert trace.trace_id == "abc"
        assert trace.span_id == "def"
        assert trace.parent_span_id is None

    def test_from_string_invalid(self):
        with pytest.raises(ValueError):
            CausalTraceId.from_string("abc")

    def test_is_ancestor_of(self):
        root = CausalTraceId()
        child = root.child()
        grandchild = child.child()

        assert root.is_ancestor_of(child)
        assert root.is_ancestor_of(grandchild)
        assert not child.is_ancestor_of(root)
        assert not root.is_ancestor_of(root)

    def test_str(self):
        trace = CausalTraceId(trace_id="abc", span_id="def")
        assert str(trace) == "abc/def"

    def test_deep_nesting(self):
        trace = CausalTraceId()
        for _i in range(5):
            trace = trace.child()
        assert trace.depth == 5


class TestEventBusBounds:
    """Regression: event bus must be bounded and emit must be lock-safe."""

    def test_main_log_capped_by_max_events(self):
        bus = HypervisorEventBus(max_events=10)
        for i in range(25):
            bus.emit(
                HypervisorEvent(
                    event_type=EventType.SESSION_CREATED,
                    session_id=f"sess-{i}",
                )
            )
        # 25 emits, cap 10 -> oldest 15 evicted; newest 10 remain.
        assert bus.event_count == 10
        events = bus.all_events
        assert events[0].session_id == "sess-15"
        assert events[-1].session_id == "sess-24"

    def test_per_type_index_capped(self):
        bus = HypervisorEventBus(max_events=5)
        for i in range(12):
            bus.emit(
                HypervisorEvent(
                    event_type=EventType.SESSION_CREATED,
                    session_id=f"sess-{i}",
                )
            )
        by_type = bus.query_by_type(EventType.SESSION_CREATED)
        assert len(by_type) == 5
        # Oldest entries evicted; newest 5 survive.
        assert by_type[0].session_id == "sess-7"

    def test_per_session_index_capped(self):
        bus = HypervisorEventBus(max_events=4)
        for i in range(20):
            bus.emit(
                HypervisorEvent(
                    event_type=EventType.VFS_WRITE,
                    session_id="busy-session",
                )
            )
        # One chatty session must not starve the index: still capped at 4.
        assert len(bus.query_by_session("busy-session")) == 4

    def test_unbounded_mode_via_none(self):
        bus = HypervisorEventBus(max_events=None)
        for i in range(50):
            bus.emit(HypervisorEvent(event_type=EventType.SESSION_CREATED))
        assert bus.event_count == 50

    def test_emit_is_thread_safe(self):
        import threading

        bus = HypervisorEventBus(max_events=10000)
        N_THREADS, N_PER_THREAD = 8, 250

        def producer(thread_idx: int) -> None:
            for i in range(N_PER_THREAD):
                bus.emit(
                    HypervisorEvent(
                        event_type=EventType.VFS_WRITE,
                        session_id=f"t{thread_idx}",
                        payload={"i": i},
                    )
                )

        threads = [
            threading.Thread(target=producer, args=(t,))
            for t in range(N_THREADS)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Without the lock, the indexes would race and lose entries or
        # store duplicates. The total must match exactly.
        assert bus.event_count == N_THREADS * N_PER_THREAD
        for tidx in range(N_THREADS):
            assert len(bus.query_by_session(f"t{tidx}")) == N_PER_THREAD

    def test_subscriber_re_entry_does_not_deadlock(self):
        """A handler that emits another event must not deadlock the bus."""
        bus = HypervisorEventBus(max_events=100)
        seen: list[HypervisorEvent] = []

        def re_emit_on_first(event: HypervisorEvent) -> None:
            seen.append(event)
            if event.event_type == EventType.SESSION_CREATED:
                # Re-enter: handler emits a follow-up event.
                bus.emit(
                    HypervisorEvent(event_type=EventType.RING_ASSIGNED)
                )

        bus.subscribe(None, re_emit_on_first)
        bus.emit(HypervisorEvent(event_type=EventType.SESSION_CREATED))
        # Both the original and the re-emitted event must be observed,
        # and the call must return.
        assert any(e.event_type == EventType.SESSION_CREATED for e in seen)
        assert any(e.event_type == EventType.RING_ASSIGNED for e in seen)
