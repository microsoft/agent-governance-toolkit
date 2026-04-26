# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Datadog exporter — metrics and events for LLM monitoring.

Exports Agent-SRE SLO data as Datadog metrics and events.
Operates in two modes:
- **Live mode**: Sends data to Datadog API (when api_key is provided)
- **Offline mode**: Stores records in memory (when api_key is empty)

No Datadog dependency required — uses urllib for HTTP.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class DatadogMetric:
    """A Datadog metric record."""

    name: str
    value: float
    tags: list[str]
    metric_type: str = "gauge"
    timestamp: float = field(default_factory=time.time)


@dataclass
class DatadogEvent:
    """A Datadog event record."""

    title: str
    text: str
    alert_type: str = "info"
    tags: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


class DatadogExporter:
    """Export Agent SRE data to Datadog.

    Provides metrics and event submission for LLM monitoring:
    1. **Metrics**: SLO status, budget remaining, burn rate, cost
    2. **Events**: SLO status changes, incidents

    Args:
        api_key: Datadog API key. Empty string for offline mode.
        site: Datadog site (e.g. datadoghq.com, datadoghq.eu).

    Example:
        from agent_sre.integrations.datadog import DatadogExporter

        exporter = DatadogExporter()
        exporter.submit_metric("agent.latency", 0.45, tags=["agent:bot-1"])
    """

    def __init__(
        self,
        api_key: str = "",
        site: str = "datadoghq.com",
    ) -> None:
        self._api_key = api_key
        self._site = site
        self._offline = not bool(api_key)

        self._metrics: list[DatadogMetric] = []
        self._events: list[DatadogEvent] = []

    @property
    def is_offline(self) -> bool:
        """True if operating in offline/test mode."""
        return self._offline

    @property
    def metrics(self) -> list[DatadogMetric]:
        """Get recorded metrics."""
        return list(self._metrics)

    @property
    def events(self) -> list[DatadogEvent]:
        """Get recorded events."""
        return list(self._events)

    def submit_metric(
        self,
        metric_name: str,
        value: float,
        tags: list[str] | None = None,
        metric_type: str = "gauge",
    ) -> DatadogMetric:
        """Submit a Datadog metric.

        Args:
            metric_name: Metric name (e.g. agent_sre.slo.budget_remaining)
            value: Metric value
            tags: Optional list of tags (e.g. ["agent:bot-1", "slo:latency"])
            metric_type: Metric type (gauge, count, rate)

        Returns:
            The created DatadogMetric
        """
        metric = DatadogMetric(
            name=metric_name,
            value=value,
            tags=tags or [],
            metric_type=metric_type,
        )
        self._metrics.append(metric)

        if not self._offline:
            self._send_metric(metric)

        return metric

    def submit_event(
        self,
        title: str,
        text: str,
        alert_type: str = "info",
        tags: list[str] | None = None,
    ) -> DatadogEvent:
        """Submit a Datadog event.

        Args:
            title: Event title
            text: Event description
            alert_type: Alert type (info, warning, error, success)
            tags: Optional list of tags

        Returns:
            The created DatadogEvent
        """
        event = DatadogEvent(
            title=title,
            text=text,
            alert_type=alert_type,
            tags=tags or [],
        )
        self._events.append(event)

        if not self._offline:
            self._send_event(event)

        return event

    def export_slo(
        self,
        slo: Any,
        agent_id: str = "",
    ) -> list[DatadogMetric]:
        """Export SLO evaluation as Datadog metrics.

        Creates metrics for:
        - agent_sre.slo.status
        - agent_sre.slo.budget_remaining
        - agent_sre.slo.burn_rate

        Args:
            slo: An agent_sre.slo.objectives.SLO instance
            agent_id: Optional agent identifier for tags

        Returns:
            List of DatadogMetric objects created
        """
        from agent_sre.integrations.otel.conventions import SLO_STATUS_CODES

        status = slo.evaluate()
        status_code = SLO_STATUS_CODES.get(status.value, -1)
        burn = slo.error_budget.burn_rate()

        base_tags = [f"slo:{slo.name}"]
        if agent_id:
            base_tags.append(f"agent:{agent_id}")

        metrics = [
            self.submit_metric(
                "agent_sre.slo.status",
                float(status_code),
                tags=base_tags + [f"status:{status.value}"],
            ),
            self.submit_metric(
                "agent_sre.slo.budget_remaining",
                slo.error_budget.remaining,
                tags=base_tags,
            ),
            self.submit_metric(
                "agent_sre.slo.burn_rate",
                burn,
                tags=base_tags,
            ),
        ]

        return metrics

    def export_cost(
        self,
        agent_id: str,
        cost_usd: float,
        task_id: str = "",
        tags: list[str] | None = None,
    ) -> DatadogMetric:
        """Submit cost as a Datadog metric.

        Args:
            agent_id: Agent identifier
            cost_usd: Cost in USD
            task_id: Optional task identifier
            tags: Additional tags

        Returns:
            The created DatadogMetric
        """
        metric_tags = [f"agent:{agent_id}"]
        if task_id:
            metric_tags.append(f"task:{task_id}")
        if tags:
            metric_tags.extend(tags)

        return self.submit_metric(
            "agent_sre.cost.usd",
            cost_usd,
            tags=metric_tags,
        )

    def _send_metric(self, metric: DatadogMetric) -> None:
        """Send metric to Datadog API via urllib."""
        import json
        import urllib.request

        url = f"https://api.{self._site}/api/v2/series"
        payload = {
            "series": [{
                "metric": metric.name,
                "type": 1 if metric.metric_type == "gauge" else 3,
                "points": [{"timestamp": int(metric.timestamp), "value": metric.value}],
                "tags": metric.tags,
            }],
        }
        data = json.dumps(payload).encode()
        req = urllib.request.Request(  # noqa: S310 — Datadog API endpoint URL
            url,
            data=data,
            headers={
                "DD-API-KEY": self._api_key,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            urllib.request.urlopen(req)  # noqa: S310 — Datadog API endpoint URL
        except Exception as e:
            logger.warning(f"Failed to send metric to Datadog: {e}")

    def _send_event(self, event: DatadogEvent) -> None:
        """Send event to Datadog API via urllib."""
        import json
        import urllib.request

        url = f"https://api.{self._site}/api/v1/events"
        payload = {
            "title": event.title,
            "text": event.text,
            "alert_type": event.alert_type,
            "tags": event.tags,
        }
        data = json.dumps(payload).encode()
        req = urllib.request.Request(  # noqa: S310 — Datadog API endpoint URL
            url,
            data=data,
            headers={
                "DD-API-KEY": self._api_key,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            urllib.request.urlopen(req)  # noqa: S310 — Datadog API endpoint URL
        except Exception as e:
            logger.warning(f"Failed to send event to Datadog: {e}")

    def clear(self) -> None:
        """Clear all offline storage."""
        self._metrics.clear()
        self._events.clear()

    def get_stats(self) -> dict[str, Any]:
        """Get statistics about recorded data."""
        return {
            "total_metrics": len(self._metrics),
            "total_events": len(self._events),
            "site": self._site,
        }
