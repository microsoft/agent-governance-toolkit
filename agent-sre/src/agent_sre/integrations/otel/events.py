# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""OpenTelemetry event logger for Agent SRE.

Exports structured events (incidents, cost alerts, signals, chaos faults)
as OTEL log records using the Events API.

Usage:
    from agent_sre.integrations.otel.events import EventLogger

    event_logger = EventLogger(service_name="my-agent-fleet")
    event_logger.log_incident_detected(incident)
    event_logger.log_cost_alert(alert)
    event_logger.log_signal(signal)
"""

from __future__ import annotations

import logging
from typing import Any

from opentelemetry import trace

from agent_sre.integrations.otel.conventions import (
    AGENT_ID,
    CHAOS_EXPERIMENT_NAME,
    CHAOS_FAULT_TARGET,
    CHAOS_FAULT_TYPE,
    COST_AGENT_ID,
    EVENT_BURN_RATE_ALERT,
    EVENT_CHAOS_COMPLETED,
    EVENT_COST_ALERT,
    EVENT_FAULT_INJECTED,
    EVENT_INCIDENT_DETECTED,
    EVENT_INCIDENT_RESOLVED,
    EVENT_SIGNAL_RECEIVED,
    EVENT_SLO_STATUS_CHANGE,
    INCIDENT_ID,
    INCIDENT_SEVERITY,
    INCIDENT_STATE,
    SIGNAL_SOURCE,
    SIGNAL_TYPE,
    SLO_NAME,
    SLO_STATUS,
)

logger = logging.getLogger(__name__)


class EventLogger:
    """Logs Agent SRE events as structured records.

    Uses Python's logging module with structured attributes that OTEL
    log exporters can pick up, plus adds events to the current span
    when available for trace correlation.
    """

    def __init__(
        self,
        service_name: str = "agent-sre",
        logger_name: str = "agent_sre.events",
    ) -> None:
        self._service_name = service_name
        self._logger = logging.getLogger(logger_name)

    def _current_span(self) -> trace.Span | None:
        """Get the current OTEL span if one is active."""
        span = trace.get_current_span()
        if span and span.is_recording():
            return span
        return None

    def _emit(
        self,
        event_name: str,
        attributes: dict[str, Any],
        level: int = logging.INFO,
        message: str = "",
    ) -> dict[str, Any]:
        """Emit a structured event.

        Logs via Python logging (for OTEL log exporters) and adds
        an event to the current span (for trace correlation).

        Returns:
            The event attributes dict (for testing/inspection)
        """
        full_attrs = {"event.name": event_name, **attributes}

        # Log via Python logging
        self._logger.log(level, message or event_name, extra={"otel_attributes": full_attrs})

        # Add to current span if available
        span = self._current_span()
        if span:
            # Span events only accept str values
            str_attrs = {k: str(v) for k, v in full_attrs.items()}
            span.add_event(event_name, str_attrs)

        return full_attrs

    def log_slo_status_change(
        self,
        slo_name: str,
        old_status: str,
        new_status: str,
        error_budget_remaining: float,
    ) -> dict[str, Any]:
        """Log an SLO status transition.

        Args:
            slo_name: Name of the SLO
            old_status: Previous status
            new_status: New status
            error_budget_remaining: Current remaining budget fraction
        """
        level = logging.WARNING if new_status in ("critical", "exhausted") else logging.INFO
        return self._emit(
            EVENT_SLO_STATUS_CHANGE,
            {
                SLO_NAME: slo_name,
                "agent.sre.slo.old_status": old_status,
                SLO_STATUS: new_status,
                "agent.sre.error_budget.remaining": error_budget_remaining,
            },
            level=level,
            message=f"SLO '{slo_name}' status: {old_status} -> {new_status}",
        )

    def log_burn_rate_alert(
        self,
        slo_name: str,
        alert_name: str,
        burn_rate: float,
        severity: str,
    ) -> dict[str, Any]:
        """Log a burn rate alert firing.

        Args:
            slo_name: Name of the SLO
            alert_name: Name of the alert
            burn_rate: Current burn rate value
            severity: Alert severity (warning, critical, page)
        """
        level = logging.CRITICAL if severity == "critical" else logging.WARNING
        return self._emit(
            EVENT_BURN_RATE_ALERT,
            {
                SLO_NAME: slo_name,
                "agent.sre.alert.name": alert_name,
                "agent.sre.burn_rate": burn_rate,
                "agent.sre.alert.severity": severity,
            },
            level=level,
            message=f"Burn rate alert '{alert_name}' firing: {burn_rate:.1f}x",
        )

    def log_cost_alert(
        self,
        agent_id: str,
        severity: str,
        message: str,
        current_value: float,
        threshold: float,
    ) -> dict[str, Any]:
        """Log a cost alert.

        Args:
            agent_id: Agent identifier
            severity: Alert severity (info, warning, critical)
            message: Alert message
            current_value: Current cost value
            threshold: Threshold that was breached
        """
        level_map = {"info": logging.INFO, "warning": logging.WARNING, "critical": logging.CRITICAL}
        level = level_map.get(severity, logging.WARNING)
        return self._emit(
            EVENT_COST_ALERT,
            {
                COST_AGENT_ID: agent_id,
                "agent.sre.cost.alert_severity": severity,
                "agent.sre.cost.current_value": current_value,
                "agent.sre.cost.threshold": threshold,
            },
            level=level,
            message=f"Cost alert ({severity}): {message}",
        )

    def log_signal(
        self,
        signal_type: str,
        source: str,
        value: float = 0.0,
        message: str = "",
    ) -> dict[str, Any]:
        """Log a reliability signal.

        Args:
            signal_type: Type of signal (e.g., "slo_breach")
            source: Signal source (agent ID, SLO name, etc.)
            value: Signal value
            message: Signal description
        """
        return self._emit(
            EVENT_SIGNAL_RECEIVED,
            {
                SIGNAL_TYPE: signal_type,
                SIGNAL_SOURCE: source,
                "agent.sre.signal.value": value,
            },
            level=logging.WARNING,
            message=message or f"Signal: {signal_type} from {source}",
        )

    def log_incident_detected(
        self,
        incident_id: str,
        title: str,
        severity: str,
        agent_id: str = "",
        signal_count: int = 0,
    ) -> dict[str, Any]:
        """Log an incident detection.

        Args:
            incident_id: Unique incident identifier
            title: Incident title
            severity: Incident severity (p1-p4)
            agent_id: Affected agent
            signal_count: Number of correlated signals
        """
        level = logging.CRITICAL if severity in ("p1", "p2") else logging.WARNING
        attrs: dict[str, Any] = {
            INCIDENT_ID: incident_id,
            INCIDENT_SEVERITY: severity,
            INCIDENT_STATE: "detected",
            "agent.sre.incident.title": title,
            "agent.sre.incident.signal_count": signal_count,
        }
        if agent_id:
            attrs[AGENT_ID] = agent_id
        return self._emit(
            EVENT_INCIDENT_DETECTED,
            attrs,
            level=level,
            message=f"Incident detected ({severity}): {title}",
        )

    def log_incident_resolved(
        self,
        incident_id: str,
        duration_seconds: float,
    ) -> dict[str, Any]:
        """Log an incident resolution.

        Args:
            incident_id: Unique incident identifier
            duration_seconds: Time to resolution in seconds
        """
        return self._emit(
            EVENT_INCIDENT_RESOLVED,
            {
                INCIDENT_ID: incident_id,
                INCIDENT_STATE: "resolved",
                "agent.sre.incident.duration_seconds": duration_seconds,
            },
            level=logging.INFO,
            message=f"Incident {incident_id} resolved in {duration_seconds:.0f}s",
        )

    def log_fault_injected(
        self,
        experiment_name: str,
        fault_type: str,
        target: str,
        applied: bool,
    ) -> dict[str, Any]:
        """Log a chaos fault injection.

        Args:
            experiment_name: Name of the chaos experiment
            fault_type: Type of fault injected
            target: Target of the fault
            applied: Whether the fault was successfully applied
        """
        return self._emit(
            EVENT_FAULT_INJECTED,
            {
                CHAOS_EXPERIMENT_NAME: experiment_name,
                CHAOS_FAULT_TYPE: fault_type,
                CHAOS_FAULT_TARGET: target,
                "agent.sre.chaos.fault_applied": applied,
            },
            level=logging.INFO,
            message=f"Fault injected: {fault_type} -> {target} (applied={applied})",
        )

    def log_chaos_completed(
        self,
        experiment_name: str,
        resilience_score: float,
        agent_id: str = "",
    ) -> dict[str, Any]:
        """Log a chaos experiment completion.

        Args:
            experiment_name: Name of the experiment
            resilience_score: Final fault impact score (0-100)
            agent_id: Target agent identifier
        """
        attrs: dict[str, Any] = {
            CHAOS_EXPERIMENT_NAME: experiment_name,
            "agent.sre.chaos.resilience_score": resilience_score,
        }
        if agent_id:
            attrs[AGENT_ID] = agent_id
        return self._emit(
            EVENT_CHAOS_COMPLETED,
            attrs,
            level=logging.INFO,
            message=f"Chaos experiment '{experiment_name}' completed: score={resilience_score:.0f}/100",
        )
