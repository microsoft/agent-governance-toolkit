# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
PagerDuty integration for SLO breach alerting.

Provides ``PagerDutyAlertConfig`` — a helper that registers a PagerDuty
channel with the ``AlertManager`` and watches SLOs for status transitions.
On breach (CRITICAL / EXHAUSTED) it fires PagerDuty alerts; on recovery
(HEALTHY) it sends resolve events.

No external dependencies — uses the existing ``AlertManager`` http-based
delivery (stdlib ``urllib``).

Usage::

    from agent_sre.integrations.pagerduty import PagerDutyAlertConfig
    from agent_sre.alerts import AlertManager
    from agent_sre.slo.objectives import SLO

    manager = AlertManager()
    pd = PagerDutyAlertConfig(
        alert_manager=manager,
        routing_key="R0XXXXXXXXXXXXXXXXXXXXXXXXX",
    )

    slo = SLO(name="latency-p99", indicators=[...], agent_id="agent-1")
    pd.watch_slo(slo)  # fires if SLO is breached, resolves on recovery
"""

from __future__ import annotations

from agent_sre.alerts import (
    Alert,
    AlertChannel,
    AlertManager,
    AlertSeverity,
    ChannelConfig,
)
from agent_sre.slo.objectives import SLO, SLOStatus

# PagerDuty Events API v2 endpoint
PAGERDUTY_EVENTS_URL = "https://events.pagerduty.com/v2/enqueue"

# Default severity mapping
_DEFAULT_SEVERITY_MAP: dict[SLOStatus, AlertSeverity] = {
    SLOStatus.CRITICAL: AlertSeverity.CRITICAL,
    SLOStatus.EXHAUSTED: AlertSeverity.CRITICAL,
    SLOStatus.WARNING: AlertSeverity.WARNING,
}

# Statuses that trigger an alert
_ALERT_STATUSES = frozenset({SLOStatus.CRITICAL, SLOStatus.EXHAUSTED})


class PagerDutyAlertConfig:
    """Connects SLO evaluations to PagerDuty incident management.

    Registers a PagerDuty channel with the ``AlertManager`` and provides
    ``watch_slo()`` to evaluate an SLO and fire/resolve PagerDuty alerts
    based on status transitions.

    Features:
    - Automatic dedup via ``{slo.name}:{agent_id}`` keys
    - Resolve events on recovery to HEALTHY
    - Configurable severity mapping
    - Tracks last-known status per SLO to avoid redundant alerts

    Attributes:
        _alert_manager: The AlertManager to send alerts through.
        _routing_key: PagerDuty integration/routing key.
        _channel_name: Name of the registered PagerDuty channel.
        _severity_map: Maps SLOStatus to AlertSeverity.
        _last_statuses: Tracks last-known status per SLO name.
    """

    def __init__(
        self,
        alert_manager: AlertManager,
        routing_key: str,
        channel_name: str = "pagerduty-slo",
        severity_map: dict[SLOStatus, AlertSeverity] | None = None,
        url: str = PAGERDUTY_EVENTS_URL,
    ) -> None:
        self._alert_manager = alert_manager
        self._routing_key = routing_key
        self._channel_name = channel_name
        self._severity_map = severity_map or dict(_DEFAULT_SEVERITY_MAP)
        self._last_statuses: dict[str, SLOStatus] = {}

        # Register PagerDuty channel with the AlertManager
        self._alert_manager.add_channel(ChannelConfig(
            channel_type=AlertChannel.PAGERDUTY,
            name=channel_name,
            url=url,
            token=routing_key,
            min_severity=AlertSeverity.WARNING,
            enabled=True,
        ))

    @property
    def channel_name(self) -> str:
        return self._channel_name

    @property
    def last_statuses(self) -> dict[str, SLOStatus]:
        """Last-known SLO statuses (read-only copy)."""
        return dict(self._last_statuses)

    def watch_slo(
        self,
        slo: SLO,
        agent_id: str = "",
    ) -> SLOStatus:
        """Evaluate an SLO and fire/resolve PagerDuty alerts as needed.

        Call this periodically (e.g. after each ``slo.record_event()``)
        or on a schedule.

        Args:
            slo: The SLO to evaluate.
            agent_id: Agent identifier for dedup and alert context.

        Returns:
            The current SLO status after evaluation.
        """
        agent_id = agent_id or getattr(slo, "_agent_id", "") or ""
        status = slo.evaluate()
        prev_status = self._last_statuses.get(slo.name)
        dedup_key = self._make_dedup_key(slo.name, agent_id)

        if status in _ALERT_STATUSES and prev_status != status:
            # Breach — fire alert
            severity = self._severity_map.get(status, AlertSeverity.CRITICAL)
            self._alert_manager.send(Alert(
                title=f"SLO Breach: {slo.name}",
                message=(
                    f"SLO '{slo.name}' status changed to {status.value}. "
                    f"Error budget remaining: {slo.error_budget.remaining_percent:.1f}%"
                ),
                severity=severity,
                source="pagerduty-slo-watcher",
                agent_id=agent_id,
                slo_name=slo.name,
                dedup_key=dedup_key,
                metadata={
                    "slo_name": slo.name,
                    "status": status.value,
                    "remaining_percent": slo.error_budget.remaining_percent,
                    "burn_rate": slo.error_budget.burn_rate(),
                },
            ))
        elif (
            status == SLOStatus.HEALTHY
            and prev_status is not None
            and prev_status != SLOStatus.HEALTHY
        ):
            # Recovery — send resolve
            self._alert_manager.send(Alert(
                title=f"SLO Recovered: {slo.name}",
                message=f"SLO '{slo.name}' recovered to healthy.",
                severity=AlertSeverity.RESOLVED,
                source="pagerduty-slo-watcher",
                agent_id=agent_id,
                slo_name=slo.name,
                dedup_key=dedup_key,
                metadata={
                    "slo_name": slo.name,
                    "status": status.value,
                    "remaining_percent": slo.error_budget.remaining_percent,
                },
            ))

        self._last_statuses[slo.name] = status
        return status

    def remove(self) -> None:
        """Unregister the PagerDuty channel from the AlertManager."""
        self._alert_manager.remove_channel(self._channel_name)

    @staticmethod
    def _make_dedup_key(slo_name: str, agent_id: str) -> str:
        """Generate a stable dedup key for PagerDuty."""
        return f"{slo_name}:{agent_id}" if agent_id else slo_name
