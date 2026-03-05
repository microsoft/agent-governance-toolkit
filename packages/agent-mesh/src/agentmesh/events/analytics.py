# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Analytics plane subscriber for real-time event aggregation.

Subscribes to all AgentMesh events and maintains rolling window
statistics for handshakes/min, violations/min, and average trust scores.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

from .bus import Event, EventBus


@dataclass
class AnalyticsSnapshot:
    """Point-in-time analytics snapshot."""

    handshakes_per_min_1m: float = 0.0
    handshakes_per_min_5m: float = 0.0
    handshakes_per_min_15m: float = 0.0
    violations_per_min_1m: float = 0.0
    violations_per_min_5m: float = 0.0
    violations_per_min_15m: float = 0.0
    avg_trust_score_1m: float = 0.0
    avg_trust_score_5m: float = 0.0
    avg_trust_score_15m: float = 0.0
    total_events: int = 0
    events_by_type: dict[str, int] = field(default_factory=dict)


class AnalyticsPlane:
    """Subscribes to all events and aggregates rolling window statistics.

    Args:
        bus: The event bus to subscribe to.
    """

    # Window durations in seconds
    WINDOW_1M = 60
    WINDOW_5M = 300
    WINDOW_15M = 900

    def __init__(self, bus: EventBus) -> None:
        self._bus = bus
        self._total_events = 0
        self._events_by_type: dict[str, int] = {}

        # Timestamped deques for rolling windows
        self._handshakes: deque[float] = deque()
        self._violations: deque[float] = deque()
        self._trust_scores: deque[tuple[float, float]] = deque()  # (timestamp, score)

        # Subscribe to all events
        self._bus.subscribe("*", self._handle_event)

    def _handle_event(self, event: Event) -> None:
        """Route events to the appropriate aggregator."""
        now = time.monotonic()
        self._total_events += 1
        self._events_by_type[event.event_type] = (
            self._events_by_type.get(event.event_type, 0) + 1
        )

        if event.event_type == "handshake.completed":
            self._handshakes.append(now)
        elif event.event_type in ("policy.violated", "trust.failed"):
            self._violations.append(now)

        if event.event_type in ("trust.verified", "handshake.completed"):
            score = event.payload.get("trust_score")
            if score is not None:
                self._trust_scores.append((now, float(score)))

    def _count_in_window(self, dq: deque[Any], window_seconds: int) -> int:
        """Count entries within the rolling window, pruning expired entries."""
        cutoff = time.monotonic() - window_seconds
        while dq and dq[0] < cutoff:
            dq.popleft()
        return len(dq)

    def _rate_per_min(self, dq: deque[Any], window_seconds: int) -> float:
        """Calculate per-minute rate within the rolling window."""
        count = self._count_in_window(dq, window_seconds)
        window_minutes = window_seconds / 60.0
        return count / window_minutes if window_minutes > 0 else 0.0

    def _avg_score_in_window(self, window_seconds: int) -> float:
        """Calculate average trust score within the rolling window."""
        cutoff = time.monotonic() - window_seconds
        while self._trust_scores and self._trust_scores[0][0] < cutoff:
            self._trust_scores.popleft()
        if not self._trust_scores:
            return 0.0
        total = sum(score for _, score in self._trust_scores)
        return total / len(self._trust_scores)

    def get_stats(self) -> AnalyticsSnapshot:
        """Returns current analytics snapshot across all rolling windows."""
        return AnalyticsSnapshot(
            handshakes_per_min_1m=self._rate_per_min(self._handshakes, self.WINDOW_1M),
            handshakes_per_min_5m=self._rate_per_min(self._handshakes, self.WINDOW_5M),
            handshakes_per_min_15m=self._rate_per_min(self._handshakes, self.WINDOW_15M),
            violations_per_min_1m=self._rate_per_min(self._violations, self.WINDOW_1M),
            violations_per_min_5m=self._rate_per_min(self._violations, self.WINDOW_5M),
            violations_per_min_15m=self._rate_per_min(self._violations, self.WINDOW_15M),
            avg_trust_score_1m=self._avg_score_in_window(self.WINDOW_1M),
            avg_trust_score_5m=self._avg_score_in_window(self.WINDOW_5M),
            avg_trust_score_15m=self._avg_score_in_window(self.WINDOW_15M),
            total_events=self._total_events,
            events_by_type=dict(self._events_by_type),
        )
