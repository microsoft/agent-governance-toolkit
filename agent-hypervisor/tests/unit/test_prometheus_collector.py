# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the Prometheus ring metrics collector."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from hypervisor.observability.event_bus import (
    EventType,
    HypervisorEvent,
    HypervisorEventBus,
)
from hypervisor.observability.prometheus_collector import (
    METRIC_RING_BREACHES_TOTAL,
    METRIC_RING_CURRENT,
    METRIC_RING_ELEVATION_DURATION,
    METRIC_RING_TRANSITIONS_TOTAL,
    RingMetricsCollector,
)


class _FakePrometheusExporter:
    """Minimal fake matching PrometheusExporterProtocol."""

    def __init__(self) -> None:
        self.gauges: list[tuple[str, float, dict]] = []
        self.counters: list[tuple[str, float, dict]] = []

    def set_gauge(
        self, name: str, value: float,
        labels: dict[str, str] | None = None,
        help_text: str = "",
    ) -> None:
        self.gauges.append((name, value, labels or {}))

    def inc_counter(
        self, name: str, value: float = 1.0,
        labels: dict[str, str] | None = None,
        help_text: str = "",
    ) -> None:
        self.counters.append((name, value, labels or {}))


class TestRingMetricsCollector:
    def test_subscribe_ring_events(self):
        """Emitting ring events into EventBus increments collector counters."""
        bus = HypervisorEventBus()
        collector = RingMetricsCollector(bus)

        bus.emit(HypervisorEvent(
            event_type=EventType.RING_ASSIGNED,
            agent_did="agent-1",
            session_id="sess-1",
            payload={"ring": 2},
        ))
        bus.emit(HypervisorEvent(
            event_type=EventType.RING_ASSIGNED,
            agent_did="agent-2",
            session_id="sess-1",
            payload={"ring": 3},
        ))

        snapshot = collector.collect()
        transitions = snapshot[METRIC_RING_TRANSITIONS_TOTAL]
        assert ("ring.assigned", "agent-1", "sess-1") in transitions
        assert transitions[("ring.assigned", "agent-1", "sess-1")] == 1
        assert snapshot["events_processed"] == 2

    def test_metric_labels(self):
        """Verify agent/session/event_type labels are attached to exports."""
        bus = HypervisorEventBus()
        collector = RingMetricsCollector(bus)

        bus.emit(HypervisorEvent(
            event_type=EventType.RING_ELEVATED,
            agent_did="agent-a",
            session_id="sess-x",
            payload={"to_ring": 1},
        ))

        exporter = _FakePrometheusExporter()
        collector.export_to_prometheus(exporter)

        # Should have transition counter + current ring gauge + elevation duration
        counter_names = [c[0] for c in exporter.counters]
        assert METRIC_RING_TRANSITIONS_TOTAL in counter_names

        # Check labels on the counter
        tc = next(c for c in exporter.counters if c[0] == METRIC_RING_TRANSITIONS_TOTAL)
        assert tc[2]["agent_did"] == "agent-a"
        assert tc[2]["session_id"] == "sess-x"
        assert tc[2]["event_type"] == "ring.elevated"

    def test_export_to_prometheus(self):
        """Verify export_to_prometheus() writes correct metrics."""
        bus = HypervisorEventBus()
        collector = RingMetricsCollector(bus)

        bus.emit(HypervisorEvent(
            event_type=EventType.RING_ASSIGNED,
            agent_did="a1",
            session_id="s1",
            payload={"ring": 2},
        ))
        bus.emit(HypervisorEvent(
            event_type=EventType.RING_ASSIGNED,
            agent_did="a1",
            session_id="s1",
            payload={"ring": 2},
        ))

        exporter = _FakePrometheusExporter()
        collector.export_to_prometheus(exporter)

        # Check the counter has the accumulated count
        tc = next(c for c in exporter.counters if c[0] == METRIC_RING_TRANSITIONS_TOTAL)
        assert tc[1] == 2.0

        # Check current ring gauge
        gauge_names = [g[0] for g in exporter.gauges]
        assert METRIC_RING_CURRENT in gauge_names
        rg = next(g for g in exporter.gauges if g[0] == METRIC_RING_CURRENT)
        assert rg[1] == 2.0
        assert rg[2]["agent_did"] == "a1"

    def test_breach_counter(self):
        """Verify breach events increment a separate counter."""
        bus = HypervisorEventBus()
        collector = RingMetricsCollector(bus)

        bus.emit(HypervisorEvent(
            event_type=EventType.RING_BREACH_DETECTED,
            agent_did="bad-agent",
            session_id="sess-1",
        ))
        bus.emit(HypervisorEvent(
            event_type=EventType.RING_BREACH_DETECTED,
            agent_did="bad-agent",
            session_id="sess-1",
        ))

        snapshot = collector.collect()
        breaches = snapshot[METRIC_RING_BREACHES_TOTAL]
        assert breaches[("bad-agent", "sess-1")] == 2

        exporter = _FakePrometheusExporter()
        collector.export_to_prometheus(exporter)
        bc = next(c for c in exporter.counters if c[0] == METRIC_RING_BREACHES_TOTAL)
        assert bc[1] == 2.0

    def test_elevation_duration_tracking(self):
        """Verify elevation duration is tracked between elevated/demoted events."""
        bus = HypervisorEventBus()
        collector = RingMetricsCollector(bus)

        now = datetime.now(UTC)
        bus.emit(HypervisorEvent(
            event_type=EventType.RING_ELEVATED,
            agent_did="agent-1",
            session_id="s1",
            timestamp=now,
            payload={"to_ring": 1},
        ))
        bus.emit(HypervisorEvent(
            event_type=EventType.RING_DEMOTED,
            agent_did="agent-1",
            session_id="s1",
            timestamp=now + timedelta(seconds=30),
            payload={"to_ring": 2},
        ))

        snapshot = collector.collect()
        durations = snapshot[METRIC_RING_ELEVATION_DURATION]
        assert "agent-1" in durations
        assert abs(durations["agent-1"] - 30.0) < 1.0

    def test_current_ring_updates(self):
        """Current ring gauge updates on each transition."""
        bus = HypervisorEventBus()
        collector = RingMetricsCollector(bus)

        bus.emit(HypervisorEvent(
            event_type=EventType.RING_ASSIGNED,
            agent_did="a1",
            payload={"ring": 3},
        ))
        assert collector.collect()[METRIC_RING_CURRENT]["a1"] == 3

        bus.emit(HypervisorEvent(
            event_type=EventType.RING_ELEVATED,
            agent_did="a1",
            payload={"to_ring": 1},
        ))
        assert collector.collect()[METRIC_RING_CURRENT]["a1"] == 1

    def test_reset(self):
        """Reset clears all metrics."""
        bus = HypervisorEventBus()
        collector = RingMetricsCollector(bus)

        bus.emit(HypervisorEvent(
            event_type=EventType.RING_ASSIGNED,
            agent_did="a1",
            payload={"ring": 2},
        ))
        assert collector.collect()["events_processed"] == 1

        collector.reset()
        snapshot = collector.collect()
        assert snapshot["events_processed"] == 0
        assert len(snapshot[METRIC_RING_TRANSITIONS_TOTAL]) == 0

    def test_unknown_agent_defaults(self):
        """Events without agent_did/session_id use 'unknown' labels."""
        bus = HypervisorEventBus()
        collector = RingMetricsCollector(bus)

        bus.emit(HypervisorEvent(
            event_type=EventType.RING_BREACH_DETECTED,
        ))

        snapshot = collector.collect()
        assert ("unknown", "unknown") in snapshot[METRIC_RING_BREACHES_TOTAL]
