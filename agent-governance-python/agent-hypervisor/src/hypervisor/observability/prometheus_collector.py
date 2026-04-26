# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Prometheus metrics collector for Hypervisor ring transitions.

Subscribes to the HypervisorEventBus and maintains in-memory counters
for ring-related events (transitions, breaches, elevations). Metrics
follow the ``agent_hypervisor_ring_*`` prefix convention.

No external dependencies — works standalone or exports to the
``agent-sre`` PrometheusExporter via dependency injection.

Usage::

    from hypervisor.observability import RingMetricsCollector, HypervisorEventBus

    bus = HypervisorEventBus()
    collector = RingMetricsCollector(bus)

    # ... hypervisor operates, ring events flow through the bus ...

    snapshot = collector.collect()
    # {"agent_hypervisor_ring_transitions_total": {"ring.assigned": 5, ...}, ...}

    # Optional: export to agent-sre PrometheusExporter
    from agent_sre.integrations.prometheus import PrometheusExporter
    prom = PrometheusExporter()
    collector.export_to_prometheus(prom)
"""

from __future__ import annotations

import time
from collections import defaultdict
from typing import Any, Protocol

from hypervisor.observability.event_bus import EventType, HypervisorEvent, HypervisorEventBus

# Ring event types that represent transitions
_RING_TRANSITION_EVENTS = frozenset({
    EventType.RING_ASSIGNED,
    EventType.RING_ELEVATED,
    EventType.RING_DEMOTED,
    EventType.RING_ELEVATION_EXPIRED,
})

_RING_BREACH_EVENTS = frozenset({
    EventType.RING_BREACH_DETECTED,
})

_ALL_RING_EVENTS = _RING_TRANSITION_EVENTS | _RING_BREACH_EVENTS


class PrometheusExporterProtocol(Protocol):
    """Protocol for Prometheus exporters — avoids hard dep on agent-sre."""

    def set_gauge(
        self, name: str, value: float,
        labels: dict[str, str] | None = None,
        help_text: str = "",
    ) -> None: ...

    def inc_counter(
        self, name: str, value: float = 1.0,
        labels: dict[str, str] | None = None,
        help_text: str = "",
    ) -> None: ...


# ---------------------------------------------------------------------------
# Metric name constants
# ---------------------------------------------------------------------------

METRIC_RING_TRANSITIONS_TOTAL = "agent_hypervisor_ring_transitions_total"
METRIC_RING_BREACHES_TOTAL = "agent_hypervisor_ring_breaches_total"
METRIC_RING_CURRENT = "agent_hypervisor_ring_current"
METRIC_RING_ELEVATION_DURATION = "agent_hypervisor_ring_elevation_duration_seconds"


class RingMetricsCollector:
    """Collects Prometheus-compatible metrics from hypervisor ring events.

    Subscribes to the ``HypervisorEventBus`` for ring transition and breach
    events. Maintains in-memory counters and gauges that can be exported
    to any :class:`PrometheusExporterProtocol`-compatible exporter.

    Attributes:
        _bus: The event bus this collector is subscribed to.
        _transition_counts: Counter per ``(event_type, agent_did, session_id)``.
        _breach_counts: Counter per ``(agent_did, session_id)``.
        _current_rings: Current ring gauge per ``agent_did``.
        _elevation_start: Timestamp when an agent entered elevated state.
        _elevation_durations: Last known elevation duration per ``agent_did``.
    """

    def __init__(self, bus: HypervisorEventBus) -> None:
        self._bus = bus

        # Counters: (event_type_value, agent_did, session_id) -> count
        self._transition_counts: dict[tuple[str, str, str], int] = defaultdict(int)

        # Breach counter: (agent_did, session_id) -> count
        self._breach_counts: dict[tuple[str, str], int] = defaultdict(int)

        # Current ring per agent: agent_did -> ring_value (int)
        self._current_rings: dict[str, int] = {}

        # Elevation tracking: agent_did -> start timestamp
        self._elevation_start: dict[str, float] = {}

        # Last elevation duration: agent_did -> seconds (float)
        self._elevation_durations: dict[str, float] = {}

        # Total events processed
        self._events_processed: int = 0

        # Subscribe to all ring events
        for event_type in _ALL_RING_EVENTS:
            bus.subscribe(event_type=event_type, handler=self._handle_event)

    def _handle_event(self, event: HypervisorEvent) -> None:
        """Process a ring-related event from the bus."""
        agent_did = event.agent_did or "unknown"
        session_id = event.session_id or "unknown"
        self._events_processed += 1

        if event.event_type in _RING_TRANSITION_EVENTS:
            key = (event.event_type.value, agent_did, session_id)
            self._transition_counts[key] += 1

            # Track current ring from payload
            to_ring = event.payload.get("to_ring") or event.payload.get("ring")
            if to_ring is not None:
                self._current_rings[agent_did] = (
                    to_ring if isinstance(to_ring, int) else int(to_ring)
                )

            # Track elevation timing
            if event.event_type == EventType.RING_ELEVATED:
                self._elevation_start[agent_did] = event.timestamp.timestamp()
            elif event.event_type in (
                EventType.RING_DEMOTED,
                EventType.RING_ELEVATION_EXPIRED,
            ):
                start = self._elevation_start.pop(agent_did, None)
                if start is not None:
                    self._elevation_durations[agent_did] = (
                        event.timestamp.timestamp() - start
                    )

        elif event.event_type in _RING_BREACH_EVENTS:
            self._breach_counts[(agent_did, session_id)] += 1

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def collect(self) -> dict[str, Any]:
        """Return a snapshot of all metrics as a framework-agnostic dict.

        Returns:
            Dictionary with metric names as keys and nested dicts/values:

            - ``agent_hypervisor_ring_transitions_total``:
              ``{(event_type, agent, session): count}``
            - ``agent_hypervisor_ring_breaches_total``:
              ``{(agent, session): count}``
            - ``agent_hypervisor_ring_current``:
              ``{agent: ring_value}``
            - ``agent_hypervisor_ring_elevation_duration_seconds``:
              ``{agent: seconds}``
        """
        return {
            METRIC_RING_TRANSITIONS_TOTAL: dict(self._transition_counts),
            METRIC_RING_BREACHES_TOTAL: dict(self._breach_counts),
            METRIC_RING_CURRENT: dict(self._current_rings),
            METRIC_RING_ELEVATION_DURATION: dict(self._elevation_durations),
            "events_processed": self._events_processed,
        }

    def export_to_prometheus(self, exporter: PrometheusExporterProtocol) -> None:
        """Write all current metrics into a Prometheus-compatible exporter.

        Args:
            exporter: Any object implementing :class:`PrometheusExporterProtocol`
                (e.g. ``agent_sre.integrations.prometheus.PrometheusExporter``).
        """
        # Transition counters
        for (event_type, agent_did, session_id), count in self._transition_counts.items():
            exporter.inc_counter(
                METRIC_RING_TRANSITIONS_TOTAL,
                float(count),
                labels={
                    "event_type": event_type,
                    "agent_did": agent_did,
                    "session_id": session_id,
                },
                help_text="Total ring transition events by type",
            )

        # Breach counters
        for (agent_did, session_id), count in self._breach_counts.items():
            exporter.inc_counter(
                METRIC_RING_BREACHES_TOTAL,
                float(count),
                labels={
                    "agent_did": agent_did,
                    "session_id": session_id,
                },
                help_text="Total ring breach events detected",
            )

        # Current ring gauge
        for agent_did, ring_value in self._current_rings.items():
            exporter.set_gauge(
                METRIC_RING_CURRENT,
                float(ring_value),
                labels={"agent_did": agent_did},
                help_text="Current execution ring for each agent (0=root, 3=sandbox)",
            )

        # Elevation duration gauge
        for agent_did, duration in self._elevation_durations.items():
            exporter.set_gauge(
                METRIC_RING_ELEVATION_DURATION,
                duration,
                labels={"agent_did": agent_did},
                help_text="Duration of the last ring elevation in seconds",
            )

        # Also export any currently-active elevations
        now = time.time()
        for agent_did, start_ts in self._elevation_start.items():
            exporter.set_gauge(
                METRIC_RING_ELEVATION_DURATION,
                now - start_ts,
                labels={"agent_did": agent_did},
                help_text="Duration of the last ring elevation in seconds",
            )

    def reset(self) -> None:
        """Reset all counters (for testing)."""
        self._transition_counts.clear()
        self._breach_counts.clear()
        self._current_rings.clear()
        self._elevation_start.clear()
        self._elevation_durations.clear()
        self._events_processed = 0
