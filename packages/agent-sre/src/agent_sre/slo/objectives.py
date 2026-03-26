# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""SLO definitions and Error Budget engine."""

from __future__ import annotations

import collections
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from agent_sre.alerts import Alert, AlertManager, AlertSeverity

if TYPE_CHECKING:
    from agent_sre.slo.indicators import SLI


class ExhaustionAction(Enum):
    """What to do when error budget is exhausted."""

    ALERT = "alert"
    FREEZE_DEPLOYMENTS = "freeze_deployments"
    CIRCUIT_BREAK = "circuit_break"
    THROTTLE = "throttle"


@dataclass
class BurnRateAlert:
    """A burn rate alert threshold."""

    name: str
    rate: float
    severity: str = "warning"  # warning, critical, page
    window_seconds: int = 3600  # 1h fast burn by default

    def is_firing(self, current_burn_rate: float) -> bool:
        """Check if this alert should fire."""
        return current_burn_rate >= self.rate


@dataclass
class ErrorBudget:
    """Tracks error budget consumption for an SLO.

    Error Budget = 1 - SLO target
    Burn Rate = actual error rate / allowed error rate

    Events are stored in a bounded ``deque(maxlen=max_events)`` to
    prevent unbounded memory growth in long-running SLOs.  When the
    buffer is full, the oldest events are silently evicted on append.
    """

    total: float = 0.0  # Set from SLO target
    consumed: float = 0.0
    window_seconds: int = 2592000  # 30 days default
    burn_rate_alert: float = 2.0
    burn_rate_critical: float = 10.0
    exhaustion_action: ExhaustionAction = ExhaustionAction.ALERT
    max_events: int = 100_000
    _events: collections.deque = field(default_factory=lambda: collections.deque(maxlen=100_000))
    _monotonic_offset: float = field(default_factory=lambda: time.time() - time.monotonic())

    def __post_init__(self) -> None:
        """Ensure _events is a bounded deque with the correct maxlen."""
        if not isinstance(self._events, collections.deque) or self._events.maxlen != self.max_events:
            self._events = collections.deque(self._events, maxlen=self.max_events)

    @property
    def remaining(self) -> float:
        """Remaining error budget as a fraction (0.0 to 1.0)."""
        if self.total <= 0:
            return 0.0
        return max(0.0, 1.0 - (self.consumed / self.total))

    @property
    def remaining_percent(self) -> float:
        """Remaining error budget as percentage."""
        return self.remaining * 100.0

    @property
    def is_exhausted(self) -> bool:
        """True if error budget is fully consumed."""
        return self.consumed >= self.total

    def record_event(self, good: bool) -> None:
        """Record a good or bad event against the budget.

        Events are stored in a bounded deque.  When ``max_events`` is
        reached, the oldest event is silently evicted.
        """
        if not good:
            self.consumed += 1.0
        self._events.append({"good": good, "timestamp": time.monotonic()})

    def clear_events(self) -> None:
        """Clear all recorded events (does **not** reset ``consumed``)."""
        self._events.clear()

    @property
    def event_count(self) -> int:
        """Number of events currently in the buffer."""
        return len(self._events)

    def burn_rate(self, window_seconds: int | None = None) -> float:
        """Calculate current burn rate within a time window.

        Burn rate = (actual errors in window / window size) / (budget / total window)
        A burn rate of 1.0 means consuming budget at exactly the expected rate.
        >1.0 means faster than expected.
        """
        window = window_seconds or 3600  # Default 1h window
        cutoff = time.monotonic() - window
        recent_events = [e for e in self._events if e["timestamp"] >= cutoff]
        if not recent_events:
            return 0.0

        errors_in_window = sum(1 for e in recent_events if not e["good"])
        total_in_window = len(recent_events)

        if total_in_window == 0 or self.total <= 0:
            return 0.0

        actual_error_rate = errors_in_window / total_in_window
        allowed_error_rate = self.total / max(self.window_seconds, 1)
        if allowed_error_rate <= 0:
            return float("inf") if errors_in_window > 0 else 0.0

        return actual_error_rate / allowed_error_rate

    def alerts(self) -> list[BurnRateAlert]:
        """Get burn rate alerts (single 24h window)."""
        return [
            BurnRateAlert("burn_rate_warning", self.burn_rate_alert, "warning", 86400),
            BurnRateAlert("burn_rate_critical", self.burn_rate_critical, "critical", 86400),
        ]

    def firing_alerts(self) -> list[BurnRateAlert]:
        """Get alerts that are currently firing."""
        current = self.burn_rate()
        return [a for a in self.alerts() if a.is_firing(current)]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "total": self.total,
            "consumed": self.consumed,
            "remaining_percent": self.remaining_percent,
            "is_exhausted": self.is_exhausted,
            "burn_rate": self.burn_rate(86400),
            "exhaustion_action": self.exhaustion_action.value,
            "firing_alerts": [a.name for a in self.firing_alerts()],
        }


class SLOStatus(Enum):
    """Current SLO health status."""

    HEALTHY = "healthy"  # Within budget, no alerts
    WARNING = "warning"  # Burn rate elevated
    CRITICAL = "critical"  # Burn rate critical, budget at risk
    EXHAUSTED = "exhausted"  # Budget consumed
    UNKNOWN = "unknown"  # Not enough data


class SLO:
    """Service Level Objective for an AI agent.

    Combines multiple SLIs with targets and an error budget to define
    what "reliable" means for this agent.
    """

    def __init__(
        self,
        name: str,
        indicators: list[SLI],
        error_budget: ErrorBudget | None = None,
        description: str = "",
        labels: dict[str, str] | None = None,
        alert_manager: AlertManager | None = None,
        agent_id: str = "",
    ) -> None:
        self.name = name
        self.indicators = indicators
        self.description = description
        self.labels = labels or {}
        self._alert_manager = alert_manager
        self._agent_id = agent_id
        self._last_status: SLOStatus | None = None

        # Calculate total error budget from strictest indicator
        if error_budget is None:
            self.error_budget = ErrorBudget()
        else:
            self.error_budget = error_budget

        if self.error_budget.total == 0 and indicators:
            min_target = min(sli.target for sli in indicators)
            self.error_budget.total = 1.0 - min_target

        self._created_at = time.time()

    _STATUS_SEVERITY: dict[str, int] = {
        "healthy": 0,
        "unknown": 1,
        "warning": 2,
        "critical": 3,
        "exhausted": 4,
    }

    def evaluate(self) -> SLOStatus:
        """Evaluate current SLO status."""
        if self.error_budget.is_exhausted:
            status = SLOStatus.EXHAUSTED
        elif any(a.severity == "critical" for a in self.error_budget.firing_alerts()):
            status = SLOStatus.CRITICAL
        elif any(a.severity == "warning" for a in self.error_budget.firing_alerts()):
            status = SLOStatus.WARNING
        elif not any(sli.current_value() is not None for sli in self.indicators):
            status = SLOStatus.UNKNOWN
        else:
            status = SLOStatus.HEALTHY

        if self._alert_manager is not None:
            self._maybe_fire_alert(status)

        self._last_status = status
        return status

    def _maybe_fire_alert(self, status: SLOStatus) -> None:
        """Send alert if status changed meaningfully."""
        prev = self._last_status
        if prev is None and status == SLOStatus.HEALTHY:
            return

        cur_sev = self._STATUS_SEVERITY.get(status.value, 0)
        prev_sev = self._STATUS_SEVERITY.get(prev.value, 0) if prev else 0

        if cur_sev > prev_sev:
            # Worsened
            severity_map = {
                SLOStatus.EXHAUSTED: AlertSeverity.CRITICAL,
                SLOStatus.CRITICAL: AlertSeverity.CRITICAL,
                SLOStatus.WARNING: AlertSeverity.WARNING,
            }
            alert_severity = severity_map.get(status, AlertSeverity.WARNING)
            self._alert_manager.send(Alert(  # type: ignore[union-attr]
                title=f"SLO Breach: {self.name}",
                message=f"SLO {self.name} status changed to {status.value}",
                severity=alert_severity,
                agent_id=self._agent_id,
                slo_name=self.name,
                dedup_key=f"{self._agent_id}:{self.name}",
                metadata={
                    "remaining_percent": self.error_budget.remaining_percent,
                    "status": status.value,
                },
            ))
        elif status == SLOStatus.HEALTHY and prev is not None and prev != SLOStatus.HEALTHY:
            # Recovered
            self._alert_manager.send(Alert(  # type: ignore[union-attr]
                title=f"SLO Breach: {self.name}",
                message=f"SLO {self.name} recovered to healthy",
                severity=AlertSeverity.RESOLVED,
                agent_id=self._agent_id,
                slo_name=self.name,
                dedup_key=f"{self._agent_id}:{self.name}",
                metadata={
                    "remaining_percent": self.error_budget.remaining_percent,
                    "status": status.value,
                },
            ))

    def record_event(self, good: bool) -> None:
        """Record a good or bad event against the SLO."""
        self.error_budget.record_event(good)
        self.evaluate()

    def indicator_summary(self) -> list[dict[str, Any]]:
        """Get summary of all indicators."""
        return [sli.to_dict() for sli in self.indicators]

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "name": self.name,
            "description": self.description,
            "status": self.evaluate().value,
            "labels": self.labels,
            "error_budget": self.error_budget.to_dict(),
            "indicators": self.indicator_summary(),
        }

    def __repr__(self) -> str:
        status = self.evaluate().value
        remaining = self.error_budget.remaining_percent
        return f"SLO(name={self.name!r}, status={status}, budget={remaining:.1f}%)"
