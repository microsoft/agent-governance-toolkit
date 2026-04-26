# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic implementation
"""Incident detection — alerting with severity levels and alert grouping."""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class IncidentSeverity(Enum):
    """Incident severity levels."""

    P1 = "p1"  # Page immediately
    P2 = "p2"  # Alert
    P3 = "p3"  # Notify
    P4 = "p4"  # Log only


class IncidentState(Enum):
    """Incident lifecycle state."""

    DETECTED = "detected"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    MITIGATING = "mitigating"
    RESOLVED = "resolved"


class SignalType(Enum):
    """Types of signals that can trigger incidents."""

    SLO_BREACH = "slo_breach"
    ERROR_BUDGET_EXHAUSTED = "error_budget_exhausted"
    COST_ANOMALY = "cost_anomaly"
    POLICY_VIOLATION = "policy_violation"
    TRUST_REVOCATION = "trust_revocation"
    TOOL_FAILURE_SPIKE = "tool_failure_spike"
    LATENCY_SPIKE = "latency_spike"


@dataclass
class Signal:
    """A reliability signal that may indicate an incident."""

    signal_type: SignalType
    source: str  # agent ID, SLO name, etc.
    value: float = 0.0
    threshold: float = 0.0
    message: str = ""
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def severity_hint(self) -> IncidentSeverity:
        """Suggest severity based on signal type."""
        critical = {SignalType.ERROR_BUDGET_EXHAUSTED, SignalType.POLICY_VIOLATION, SignalType.TRUST_REVOCATION}
        warning = {SignalType.SLO_BREACH, SignalType.COST_ANOMALY, SignalType.LATENCY_SPIKE}
        if self.signal_type in critical:
            return IncidentSeverity.P1
        if self.signal_type in warning:
            return IncidentSeverity.P2
        return IncidentSeverity.P3

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.signal_type.value,
            "source": self.source,
            "value": self.value,
            "threshold": self.threshold,
            "message": self.message,
            "timestamp": self.timestamp,
        }


@dataclass
class ResponseAction:
    """An action taken in response to an incident."""

    action_type: str  # rollback, circuit_breaker, generate_postmortem, etc.
    executed: bool = False
    result: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action_type": self.action_type,
            "executed": self.executed,
            "result": self.result,
            "timestamp": self.timestamp,
        }


class Incident:
    """A detected reliability incident."""

    def __init__(
        self,
        title: str,
        severity: IncidentSeverity,
        signals: list[Signal] | None = None,
        agent_id: str = "",
    ) -> None:
        self.incident_id = uuid.uuid4().hex[:12]
        self.title = title
        self.severity = severity
        self.state = IncidentState.DETECTED
        self.agent_id = agent_id
        self.signals: list[Signal] = signals or []
        self.actions: list[ResponseAction] = []
        self.detected_at = time.time()
        self.resolved_at: float | None = None
        self.notes: list[str] = []

    @property
    def duration_seconds(self) -> float:
        end = self.resolved_at or time.time()
        return end - self.detected_at

    def acknowledge(self) -> None:
        self.state = IncidentState.ACKNOWLEDGED

    def investigate(self) -> None:
        self.state = IncidentState.INVESTIGATING

    def mitigate(self) -> None:
        self.state = IncidentState.MITIGATING

    def resolve(self, note: str = "") -> None:
        self.state = IncidentState.RESOLVED
        self.resolved_at = time.time()
        if note:
            self.notes.append(note)

    def add_action(self, action_type: str, result: str = "", executed: bool = True) -> ResponseAction:
        action = ResponseAction(action_type=action_type, executed=executed, result=result)
        self.actions.append(action)
        return action

    def add_signal(self, signal: Signal) -> None:
        self.signals.append(signal)

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "severity": self.severity.value,
            "state": self.state.value,
            "agent_id": self.agent_id,
            "detected_at": self.detected_at,
            "resolved_at": self.resolved_at,
            "duration_seconds": round(self.duration_seconds, 1),
            "signals": [s.to_dict() for s in self.signals],
            "actions": [a.to_dict() for a in self.actions],
            "notes": self.notes,
        }


class IncidentDetector:
    """Detects incidents from reliability signals.

    Creates incidents for P1/P2 severity signals with deduplication
    and alert grouping for correlated signals from the same source.
    """

    def __init__(
        self,
        correlation_window_seconds: int = 300,
        dedup_window_seconds: int = 600,
    ) -> None:
        self.correlation_window = correlation_window_seconds
        self.dedup_window = dedup_window_seconds
        self._pending_signals: list[Signal] = []
        self._incidents: list[Incident] = []
        self._response_actions: dict[str, list[str]] = {}

    def register_response(self, signal_type: str, actions: list[str]) -> None:
        """Register automatic response actions for a signal type."""
        self._response_actions[signal_type] = actions

    def ingest_signal(self, signal: Signal) -> Incident | None:
        """Ingest a signal and potentially create an incident.

        Creates incidents for P1/P2 signals. P3/P4 signals are logged only.
        """
        self._pending_signals.append(signal)
        self._prune_old_signals()

        # Check for duplicate
        if self._is_duplicate(signal):
            return None

        # Create incident for critical/warning signals
        if signal.severity_hint in (IncidentSeverity.P1, IncidentSeverity.P2):
            # Try correlation-based grouping first
            correlated = self._find_correlated(signal)
            if correlated:
                return self._create_correlated_incident([signal, *correlated])
            return self._create_incident(signal)

        return None

    def _create_incident(self, signal: Signal) -> Incident:
        """Create an incident from a single signal."""
        incident = Incident(
            title=f"{signal.signal_type.value}: {signal.message or signal.source}",
            severity=signal.severity_hint,
            signals=[signal],
            agent_id=signal.source,
        )

        # Apply auto-responses
        actions = self._response_actions.get(signal.signal_type.value, [])
        for action_type in actions:
            incident.add_action(action_type, executed=True, result="auto-triggered")

        self._incidents.append(incident)
        return incident

    def _create_correlated_incident(self, signals: list[Signal]) -> Incident:
        """Create an incident from multiple correlated signals.

        Groups signals into a single incident, using the highest severity
        among the signals and combining their descriptions.

        Args:
            signals: List of correlated signals to merge into one incident.

        Returns:
            A new ``Incident`` with aggregated severity, combined title,
            and auto-response actions applied for all signal types.
        """
        # Use the highest severity (lowest P-number) among all signals
        severity_order = [IncidentSeverity.P1, IncidentSeverity.P2, IncidentSeverity.P3, IncidentSeverity.P4]
        best_severity = IncidentSeverity.P4
        for sig in signals:
            hint = sig.severity_hint
            if severity_order.index(hint) < severity_order.index(best_severity):
                best_severity = hint

        signal_types = {s.signal_type.value for s in signals}
        primary = signals[0]
        title = f"Correlated: {', '.join(sorted(signal_types))} from {primary.source}"

        incident = Incident(
            title=title,
            severity=best_severity,
            signals=list(signals),
            agent_id=primary.source,
        )

        # Apply auto-responses for all signal types
        applied: set[str] = set()
        for sig in signals:
            actions = self._response_actions.get(sig.signal_type.value, [])
            for action_type in actions:
                if action_type not in applied:
                    incident.add_action(action_type, executed=True, result="auto-triggered")
                    applied.add(action_type)

        self._incidents.append(incident)
        return incident

    def _is_duplicate(self, signal: Signal) -> bool:
        """Check if a similar incident was recently created."""
        cutoff = time.time() - self.dedup_window
        for incident in reversed(self._incidents):
            if incident.detected_at < cutoff:
                break
            if (incident.agent_id == signal.source
                    and any(s.signal_type == signal.signal_type for s in incident.signals)):
                return True
        return False

    def _find_correlated(self, signal: Signal) -> list[Signal]:
        """Find pending signals correlated with the given signal.

        Signals are correlated if they come from the same source and
        fall within the correlation window. Only returns non-duplicate
        signals with distinct signal types.

        Args:
            signal: The incoming signal to find correlates for.

        Returns:
            List of distinct-type signals from the same source that
            arrived within the correlation window. May be empty.
        """
        cutoff = time.time() - self.correlation_window
        seen_types = {signal.signal_type}
        correlated: list[Signal] = []

        for pending in self._pending_signals:
            if pending is signal:
                continue
            if pending.timestamp < cutoff:
                continue
            if pending.source != signal.source:
                continue
            if pending.signal_type in seen_types:
                continue
            seen_types.add(pending.signal_type)
            correlated.append(pending)

        return correlated

    def _prune_old_signals(self) -> None:
        """Remove signals outside the correlation window."""
        cutoff = time.time() - self.correlation_window * 2
        self._pending_signals = [s for s in self._pending_signals if s.timestamp >= cutoff]

    @property
    def open_incidents(self) -> list[Incident]:
        return [i for i in self._incidents if i.state != IncidentState.RESOLVED]

    @property
    def all_incidents(self) -> list[Incident]:
        return self._incidents

    def summary(self) -> dict[str, Any]:
        return {
            "total_incidents": len(self._incidents),
            "open_incidents": len(self.open_incidents),
            "by_severity": {
                sev.value: sum(1 for i in self._incidents if i.severity == sev)
                for sev in IncidentSeverity
            },
            "pending_signals": len(self._pending_signals),
        }
