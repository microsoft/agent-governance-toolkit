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
        bus.clear()
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
