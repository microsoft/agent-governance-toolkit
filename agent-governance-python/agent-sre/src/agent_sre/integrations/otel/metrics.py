# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""OpenTelemetry metrics exporter for Agent SRE.

Exports SLO/SLI metrics, error budget gauges, cost metrics, and incident
counts as native OTEL metrics that any OTLP-compatible backend can ingest.

Usage:
    from agent_sre.integrations.otel.metrics import MetricsExporter

    exporter = MetricsExporter(service_name="my-agent-fleet")
    exporter.record_sli(sli)
    exporter.record_slo(slo)
    exporter.record_cost(agent_id="bot-1", cost_usd=0.35)
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from opentelemetry import metrics

from agent_sre.integrations.otel.conventions import (
    AGENT_ID,
    COST_AGENT_ID,
    METRIC_BURN_RATE,
    METRIC_COST_BUDGET_UTILIZATION,
    METRIC_COST_PER_TASK,
    METRIC_COST_TOTAL,
    METRIC_ERROR_BUDGET_REMAINING,
    METRIC_INCIDENTS_OPEN,
    METRIC_LATENCY,
    METRIC_RESILIENCE_SCORE,
    METRIC_SLI_COMPLIANCE,
    METRIC_SLI_VALUE,
    METRIC_SLO_STATUS,
    SLI_NAME,
    SLI_TARGET,
    SLI_WINDOW,
    SLO_NAME,
    SLO_STATUS_CODES,
)

if TYPE_CHECKING:
    from opentelemetry.metrics import Meter

logger = logging.getLogger(__name__)


class MetricsExporter:
    """Exports Agent SRE metrics via OpenTelemetry Metrics API.

    Registers gauges, counters, and histograms following agent-specific
    semantic conventions. Metrics are exported through whatever
    MeterProvider is configured (OTLP, Prometheus, console, etc.).
    """

    def __init__(
        self,
        service_name: str = "agent-sre",
        meter_provider: metrics.MeterProvider | None = None,
    ) -> None:
        self._service_name = service_name
        if meter_provider:
            self._meter: Meter = meter_provider.get_meter(
                "agent_sre", version="0.1.0"
            )
        else:
            self._meter = metrics.get_meter("agent_sre", version="0.1.0")

        # SLI metrics
        self._sli_value = self._meter.create_gauge(
            METRIC_SLI_VALUE,
            unit="1",
            description="Current SLI value",
        )
        self._sli_compliance = self._meter.create_gauge(
            METRIC_SLI_COMPLIANCE,
            unit="1",
            description="Fraction of measurements meeting target within window",
        )

        # SLO metrics
        self._slo_status = self._meter.create_gauge(
            METRIC_SLO_STATUS,
            unit="1",
            description="SLO status code (0=healthy, 1=warning, 2=critical, 3=exhausted)",
        )
        self._error_budget_remaining = self._meter.create_gauge(
            METRIC_ERROR_BUDGET_REMAINING,
            unit="1",
            description="Error budget remaining fraction (0.0-1.0)",
        )
        self._burn_rate = self._meter.create_gauge(
            METRIC_BURN_RATE,
            unit="1",
            description="Current burn rate (1.0 = expected rate)",
        )

        # Cost metrics
        self._cost_total = self._meter.create_counter(
            METRIC_COST_TOTAL,
            unit="usd",
            description="Total cost in USD",
        )
        self._cost_per_task = self._meter.create_gauge(
            METRIC_COST_PER_TASK,
            unit="usd",
            description="Average cost per task in USD",
        )
        self._cost_utilization = self._meter.create_gauge(
            METRIC_COST_BUDGET_UTILIZATION,
            unit="1",
            description="Cost budget utilization (0.0-1.0)",
        )

        # Latency histogram
        self._latency = self._meter.create_histogram(
            METRIC_LATENCY,
            unit="ms",
            description="Agent response latency in milliseconds",
        )

        # Incident gauge
        self._incidents_open = self._meter.create_gauge(
            METRIC_INCIDENTS_OPEN,
            unit="1",
            description="Number of open incidents",
        )

        # Resilience gauge
        self._resilience_score = self._meter.create_gauge(
            METRIC_RESILIENCE_SCORE,
            unit="1",
            description="Chaos experiment fault impact score (0-100)",
        )

    def record_sli(
        self,
        sli_name: str,
        value: float,
        target: float,
        window: str,
        compliance: float | None = None,
        labels: dict[str, str] | None = None,
    ) -> None:
        """Record an SLI measurement as OTEL metrics.

        Args:
            sli_name: Name of the SLI (e.g., "task_success_rate")
            value: Current SLI value
            target: SLI target value
            window: Time window (e.g., "24h")
            compliance: Fraction meeting target (0.0-1.0)
            labels: Additional labels/attributes
        """
        attrs: dict[str, Any] = {
            SLI_NAME: sli_name,
            SLI_TARGET: target,
            SLI_WINDOW: window,
            **(labels or {}),
        }
        self._sli_value.set(value, attrs)
        if compliance is not None:
            self._sli_compliance.set(compliance, attrs)

    def record_slo(
        self,
        slo_name: str,
        status: str,
        error_budget_remaining: float,
        burn_rate: float,
        labels: dict[str, str] | None = None,
    ) -> None:
        """Record SLO status as OTEL metrics.

        Args:
            slo_name: Name of the SLO
            status: Status string ("healthy", "warning", "critical", "exhausted")
            error_budget_remaining: Remaining budget fraction (0.0-1.0)
            burn_rate: Current burn rate
            labels: Additional labels/attributes
        """
        attrs: dict[str, Any] = {
            SLO_NAME: slo_name,
            **(labels or {}),
        }
        status_code = SLO_STATUS_CODES.get(status, -1)
        self._slo_status.set(status_code, attrs)
        self._error_budget_remaining.set(error_budget_remaining, attrs)
        self._burn_rate.set(burn_rate, attrs)

    def record_slo_from_object(self, slo: Any) -> None:
        """Record metrics directly from an SLO object.

        Args:
            slo: An agent_sre.slo.objectives.SLO instance
        """
        status = slo.evaluate().value
        self.record_slo(
            slo_name=slo.name,
            status=status,
            error_budget_remaining=slo.error_budget.remaining,
            burn_rate=slo.error_budget.burn_rate(),
            labels=slo.labels,
        )

        for indicator in slo.indicators:
            current = indicator.current_value()
            if current is not None:
                self.record_sli(
                    sli_name=indicator.name,
                    value=current,
                    target=indicator.target,
                    window=indicator.window.value,
                    compliance=indicator.compliance(),
                    labels=slo.labels,
                )

    def record_cost(
        self,
        agent_id: str,
        cost_usd: float,
        avg_per_task: float | None = None,
        budget_utilization: float | None = None,
    ) -> None:
        """Record a cost event.

        Args:
            agent_id: Agent identifier
            cost_usd: Cost in USD for this event
            avg_per_task: Average cost per task
            budget_utilization: Budget utilization fraction (0.0-1.0)
        """
        attrs = {COST_AGENT_ID: agent_id}
        self._cost_total.add(cost_usd, attrs)
        if avg_per_task is not None:
            self._cost_per_task.set(avg_per_task, attrs)
        if budget_utilization is not None:
            self._cost_utilization.set(budget_utilization, attrs)

    def record_latency(
        self,
        latency_ms: float,
        agent_id: str | None = None,
        labels: dict[str, str] | None = None,
    ) -> None:
        """Record a latency measurement.

        Args:
            latency_ms: Latency in milliseconds
            agent_id: Optional agent identifier
            labels: Additional labels/attributes
        """
        attrs: dict[str, Any] = {**(labels or {})}
        if agent_id:
            attrs[AGENT_ID] = agent_id
        self._latency.record(latency_ms, attrs)

    def record_incidents_open(self, count: int, labels: dict[str, str] | None = None) -> None:
        """Record the number of open incidents.

        Args:
            count: Number of currently open incidents
            labels: Additional labels/attributes
        """
        self._incidents_open.set(count, {**(labels or {})})

    def record_resilience(
        self,
        experiment_name: str,
        score: float,
        agent_id: str | None = None,
    ) -> None:
        """Record a fault impact score from a chaos experiment.

        Args:
            experiment_name: Name of the chaos experiment
            score: Fault impact score (0-100)
            agent_id: Target agent identifier
        """
        attrs: dict[str, Any] = {"agent.sre.chaos.experiment_name": experiment_name}
        if agent_id:
            attrs[AGENT_ID] = agent_id
        self._resilience_score.set(score, attrs)
