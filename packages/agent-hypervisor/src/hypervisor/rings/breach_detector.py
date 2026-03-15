# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Ring Breach Detector — behavioral anomaly detection for rogue agents.

Detects two classes of anomaly:

1. **Tool-call frequency spikes** — an agent's call rate inside a sliding
   window exceeds a configurable baseline by a severity-dependent multiplier.
2. **Privilege-escalation attempts** — a low-privilege agent (Ring 3)
   repeatedly calls into higher-privilege rings (Ring 0/1).  The *ring
   distance* amplifies the anomaly score so that sandbox→root jumps are
   scored more aggressively than standard→privileged ones.

When a HIGH or CRITICAL breach is detected the internal circuit-breaker
trips and ``is_breaker_tripped()`` returns ``True`` until explicitly reset
via ``reset_breaker()``.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum

from hypervisor.models import ExecutionRing


class BreachSeverity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# Multiplier thresholds: actual_rate / baseline_rate
_SEVERITY_THRESHOLDS: list[tuple[float, BreachSeverity]] = [
    (20.0, BreachSeverity.CRITICAL),
    (10.0, BreachSeverity.HIGH),
    (5.0, BreachSeverity.MEDIUM),
    (2.0, BreachSeverity.LOW),
]


@dataclass
class BreachEvent:
    """A detected ring breach anomaly."""

    agent_did: str
    session_id: str
    severity: BreachSeverity
    anomaly_score: float
    call_count_window: int
    expected_rate: float
    actual_rate: float
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))
    details: str = ""


def _agent_key(agent_did: str, session_id: str) -> str:
    """Internal composite key for per-agent tracking."""
    return f"{agent_did}::{session_id}"


class RingBreachDetector:
    """Behavioural anomaly detector for rogue-agent ring abuse.

    Parameters
    ----------
    window_seconds:
        Sliding window (in seconds) over which call rates are measured.
    baseline_rate:
        Expected calls-per-second within the window.  Rates above multiples
        of this value trigger breach events of increasing severity.
    max_events_per_agent:
        Maximum call timestamps retained per agent (bounded ``deque``).
    """

    def __init__(
        self,
        window_seconds: int = 60,
        baseline_rate: float = 10.0,
        max_events_per_agent: int = 1_000,
        max_breach_history: int = 10_000,
    ) -> None:
        self.window_seconds = window_seconds
        self.baseline_rate = baseline_rate
        self.max_events_per_agent = max_events_per_agent

        # Per-agent sliding-window timestamps
        self._call_windows: dict[str, deque[float]] = {}
        # Per-agent circuit-breaker flag
        self._tripped: dict[str, bool] = {}
        # Global breach history (bounded)
        self._breach_history: deque[BreachEvent] = deque(maxlen=max_breach_history)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def record_call(
        self,
        agent_did: str,
        session_id: str,
        agent_ring: ExecutionRing,
        called_ring: ExecutionRing,
    ) -> BreachEvent | None:
        """Record a ring call and return a ``BreachEvent`` if anomalous.

        Returns ``None`` when the call is within normal parameters.
        """
        key = _agent_key(agent_did, session_id)
        now = time.monotonic()

        # --- 1. Track timestamp in bounded deque ---
        if key not in self._call_windows:
            self._call_windows[key] = deque(maxlen=self.max_events_per_agent)
        window = self._call_windows[key]
        window.append(now)

        # --- 2. Prune timestamps outside the sliding window ---
        cutoff = now - self.window_seconds
        while window and window[0] < cutoff:
            window.popleft()

        # --- 3. Compute actual rate (calls / second) ---
        call_count = len(window)
        actual_rate = call_count / self.window_seconds if self.window_seconds > 0 else 0.0

        # --- 4. Ring-distance amplifier ---
        #   Upward calls (low value = higher privilege) are escalations.
        #   ExecutionRing values: 0=root, 1=priv, 2=std, 3=sandbox.
        #   ring_distance > 0 means privilege escalation.
        ring_distance = int(agent_ring) - int(called_ring)
        amplifier = max(ring_distance, 1)  # at least 1× (no reduction)

        # --- 5. Score = (actual / baseline) × amplifier ---
        if self.baseline_rate <= 0:
            ratio = 0.0
        else:
            ratio = actual_rate / self.baseline_rate
        anomaly_score = ratio * amplifier

        # --- 6. Map score → severity ---
        severity = BreachSeverity.NONE
        for threshold, sev in _SEVERITY_THRESHOLDS:
            if anomaly_score >= threshold:
                severity = sev
                break

        if severity == BreachSeverity.NONE:
            return None

        # --- 7. Build event ---
        event = BreachEvent(
            agent_did=agent_did,
            session_id=session_id,
            severity=severity,
            anomaly_score=round(anomaly_score, 4),
            call_count_window=call_count,
            expected_rate=self.baseline_rate,
            actual_rate=round(actual_rate, 4),
            details=(
                f"rate={actual_rate:.2f}/s (baseline={self.baseline_rate:.2f}/s), "
                f"ring_distance={ring_distance}, amplifier={amplifier}×, "
                f"score={anomaly_score:.2f}"
            ),
        )
        self._breach_history.append(event)

        # --- 8. Trip circuit-breaker on HIGH / CRITICAL ---
        if severity in (BreachSeverity.HIGH, BreachSeverity.CRITICAL):
            self._tripped[key] = True

        return event

    def is_breaker_tripped(self, agent_did: str, session_id: str) -> bool:
        """Return ``True`` if the circuit-breaker is tripped for this agent."""
        return self._tripped.get(_agent_key(agent_did, session_id), False)

    def reset_breaker(self, agent_did: str, session_id: str) -> None:
        """Reset the circuit-breaker and clear the call window for this agent."""
        key = _agent_key(agent_did, session_id)
        self._tripped.pop(key, None)
        self._call_windows.pop(key, None)

    # ------------------------------------------------------------------
    # Read-only accessors
    # ------------------------------------------------------------------

    @property
    def breach_history(self) -> list[BreachEvent]:
        return list(self._breach_history)

    @property
    def breach_count(self) -> int:
        return len(self._breach_history)
