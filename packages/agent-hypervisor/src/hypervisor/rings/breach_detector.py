# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic implementation
"""
Ring Breach Detector — stub implementation.

Community edition: breach detection is not available.
All methods return safe defaults.
"""

from __future__ import annotations

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


class RingBreachDetector:
    """Breach detector stub (community edition: no detection)."""

    def __init__(self, window_seconds: int = 60) -> None:
        self._breach_history: list[BreachEvent] = []
        self.window_seconds = window_seconds

    def record_call(
        self,
        agent_did: str,
        session_id: str,
        agent_ring: ExecutionRing,
        called_ring: ExecutionRing,
    ) -> BreachEvent | None:
        """Record a ring call (community edition: no-op, never detects breach)."""
        return None

    def is_breaker_tripped(self, agent_did: str, session_id: str) -> bool:
        return False

    def reset_breaker(self, agent_did: str, session_id: str) -> None:
        pass

    @property
    def breach_history(self) -> list[BreachEvent]:
        return list(self._breach_history)

    @property
    def breach_count(self) -> int:
        return len(self._breach_history)
