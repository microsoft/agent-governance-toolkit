# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the event bus abstraction and analytics plane."""

from __future__ import annotations

import asyncio
import time

import pytest

from agentmesh.events import (
    AnalyticsPlane,
    AsyncEventBus,
    Event,
    InMemoryEventBus,
)


class TestEvent:
    """Tests for the Event dataclass."""

    def test_event_creation(self) -> None:
        """Event creates with required fields and sensible defaults."""
        event = Event(event_type="trust.verified", source="did:mesh:abc")
        assert event.event_type == "trust.verified"
        assert event.source == "did:mesh:abc"
        assert event.payload == {}
        assert event.timestamp is not None
        assert event.event_id.startswith("evt-")

    def test_event_with_payload(self) -> None:
        """Event stores arbitrary payload data."""
        event = Event(
            event_type="handshake.completed",
            source="did:mesh:abc",
            payload={"trust_score": 850, "target_did": "did:mesh:xyz"},
        )
        assert event.payload["trust_score"] == 850
        assert event.payload["target_did"] == "did:mesh:xyz"


class TestInMemoryEventBus:
    """Tests for the synchronous in-process event bus."""

    def test_emit_and_subscribe(self) -> None:
        """Subscribed handler receives emitted events."""
        bus = InMemoryEventBus()
        received: list[Event] = []
        bus.subscribe("trust.*", received.append)

        event = Event(event_type="trust.verified", source="did:mesh:a")
        bus.emit(event)

        assert len(received) == 1
        assert received[0] is event

    def test_pattern_matching_glob(self) -> None:
        """Glob-style patterns correctly filter events."""
        bus = InMemoryEventBus()
        trust_events: list[Event] = []
        policy_events: list[Event] = []
        all_events: list[Event] = []

        bus.subscribe("trust.*", trust_events.append)
        bus.subscribe("policy.*", policy_events.append)
        bus.subscribe("*", all_events.append)

        bus.emit(Event(event_type="trust.verified", source="a"))
        bus.emit(Event(event_type="policy.violated", source="b"))
        bus.emit(Event(event_type="agent.registered", source="c"))

        assert len(trust_events) == 1
        assert len(policy_events) == 1
        assert len(all_events) == 3

    def test_pattern_no_match(self) -> None:
        """Handler is not called for non-matching events."""
        bus = InMemoryEventBus()
        received: list[Event] = []
        bus.subscribe("trust.*", received.append)

        bus.emit(Event(event_type="policy.evaluated", source="a"))

        assert len(received) == 0

    def test_unsubscribe(self) -> None:
        """Unsubscribed handler stops receiving events."""
        bus = InMemoryEventBus()
        received: list[Event] = []
        handler = received.append
        bus.subscribe("*", handler)
        bus.emit(Event(event_type="test.event", source="a"))
        assert len(received) == 1

        bus.unsubscribe(handler)
        bus.emit(Event(event_type="test.event", source="b"))
        assert len(received) == 1

    def test_multiple_subscribers(self) -> None:
        """Multiple handlers on the same pattern all receive events."""
        bus = InMemoryEventBus()
        r1: list[Event] = []
        r2: list[Event] = []
        bus.subscribe("trust.*", r1.append)
        bus.subscribe("trust.*", r2.append)

        bus.emit(Event(event_type="trust.verified", source="a"))

        assert len(r1) == 1
        assert len(r2) == 1


class TestAsyncEventBus:
    """Tests for the async queue-based event bus."""

    async def test_async_emit_and_consume(self) -> None:
        """Events emitted are delivered via the async consumer."""
        bus = AsyncEventBus()
        received: list[Event] = []
        bus.subscribe("*", received.append)

        await bus.start()
        bus.emit(Event(event_type="trust.verified", source="a"))
        bus.emit(Event(event_type="policy.evaluated", source="b"))

        # Give consumer time to process
        await asyncio.sleep(0.3)
        await bus.stop()

        assert len(received) == 2

    async def test_async_pattern_matching(self) -> None:
        """Async bus respects glob patterns."""
        bus = AsyncEventBus()
        trust_only: list[Event] = []
        bus.subscribe("trust.*", trust_only.append)

        await bus.start()
        bus.emit(Event(event_type="trust.verified", source="a"))
        bus.emit(Event(event_type="policy.violated", source="b"))

        await asyncio.sleep(0.3)
        await bus.stop()

        assert len(trust_only) == 1
        assert trust_only[0].event_type == "trust.verified"

    async def test_async_stop_drains_queue(self) -> None:
        """Stop drains remaining events from the queue."""
        bus = AsyncEventBus()
        received: list[Event] = []
        bus.subscribe("*", received.append)

        # Emit without starting consumer
        bus.emit(Event(event_type="test.one", source="a"))
        bus.emit(Event(event_type="test.two", source="b"))

        # Stop should drain the queue
        await bus.stop()

        assert len(received) == 2

    async def test_async_queue_full_drops(self) -> None:
        """Events are dropped when queue is full."""
        bus = AsyncEventBus(maxsize=2)
        bus.emit(Event(event_type="e1", source="a"))
        bus.emit(Event(event_type="e2", source="a"))
        bus.emit(Event(event_type="e3", source="a"))  # should be dropped

        assert bus._queue.qsize() == 2


class TestAnalyticsPlane:
    """Tests for the analytics aggregation subscriber."""

    def test_handshake_counting(self) -> None:
        """Analytics tracks handshake events."""
        bus = InMemoryEventBus()
        analytics = AnalyticsPlane(bus)

        for _ in range(5):
            bus.emit(
                Event(
                    event_type="handshake.completed",
                    source="did:mesh:a",
                    payload={"trust_score": 800},
                )
            )

        stats = analytics.get_stats()
        assert stats.total_events == 5
        assert stats.handshakes_per_min_1m > 0

    def test_violation_counting(self) -> None:
        """Analytics tracks policy violations and trust failures."""
        bus = InMemoryEventBus()
        analytics = AnalyticsPlane(bus)

        bus.emit(Event(event_type="policy.violated", source="a"))
        bus.emit(Event(event_type="trust.failed", source="b"))
        bus.emit(Event(event_type="trust.verified", source="c", payload={"trust_score": 700}))

        stats = analytics.get_stats()
        assert stats.total_events == 3
        assert stats.violations_per_min_1m > 0
        assert stats.events_by_type["policy.violated"] == 1
        assert stats.events_by_type["trust.failed"] == 1

    def test_trust_score_averaging(self) -> None:
        """Analytics computes average trust scores."""
        bus = InMemoryEventBus()
        analytics = AnalyticsPlane(bus)

        bus.emit(
            Event(
                event_type="trust.verified",
                source="a",
                payload={"trust_score": 800},
            )
        )
        bus.emit(
            Event(
                event_type="trust.verified",
                source="b",
                payload={"trust_score": 600},
            )
        )

        stats = analytics.get_stats()
        assert stats.avg_trust_score_1m == pytest.approx(700.0)

    def test_events_by_type(self) -> None:
        """Analytics tracks event counts by type."""
        bus = InMemoryEventBus()
        analytics = AnalyticsPlane(bus)

        bus.emit(Event(event_type="agent.registered", source="a"))
        bus.emit(Event(event_type="agent.registered", source="b"))
        bus.emit(Event(event_type="agent.revoked", source="c"))

        stats = analytics.get_stats()
        assert stats.events_by_type["agent.registered"] == 2
        assert stats.events_by_type["agent.revoked"] == 1

    def test_empty_stats(self) -> None:
        """Analytics returns zeroed snapshot when no events received."""
        bus = InMemoryEventBus()
        analytics = AnalyticsPlane(bus)

        stats = analytics.get_stats()
        assert stats.total_events == 0
        assert stats.handshakes_per_min_1m == 0.0
        assert stats.avg_trust_score_1m == 0.0
        assert stats.events_by_type == {}
