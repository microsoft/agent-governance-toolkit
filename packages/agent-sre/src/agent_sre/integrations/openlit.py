# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""OpenLit convenience exporter for Agent SRE.

Pre-configures OpenTelemetry exporters to send SLI/SLO metrics,
chaos experiment spans, and SRE events to an OpenLit instance.

Usage:
    from agent_sre.integrations.openlit import OpenLitExporter

    exporter = OpenLitExporter(endpoint="http://localhost:4318")
    exporter.record_slo(slo)
    exporter.record_chaos_experiment(experiment)
"""

from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Any

from agent_sre.integrations.otel.conventions import (
    AGENT_ID,
    CHAOS_EXPERIMENT_ID,
    CHAOS_EXPERIMENT_NAME,
    CHAOS_FAULT_TARGET,
    CHAOS_FAULT_TYPE,
    METRIC_BURN_RATE,
    METRIC_ERROR_BUDGET_REMAINING,
    METRIC_RESILIENCE_SCORE,
    METRIC_SLI_VALUE,
    METRIC_SLO_STATUS,
    SLI_NAME,
    SLI_TARGET,
    SLI_WINDOW,
    SLO_NAME,
    SLO_STATUS_CODES,
)

if TYPE_CHECKING:
    from agent_sre.chaos.engine import ChaosExperiment
    from agent_sre.slo.objectives import SLO

logger = logging.getLogger(__name__)


class OpenLitExporter:
    """Convenience exporter that sends Agent SRE telemetry to OpenLit.

    Wraps MetricsExporter and TraceExporter with OpenLit-friendly defaults.
    Supports both gRPC (port 4317) and HTTP (port 4318) OTLP endpoints.
    """

    def __init__(
        self,
        endpoint: str = "http://localhost:4318",
        service_name: str = "agent-sre",
        api_key: str | None = None,
        environment: str = "default",
        application_name: str = "default",
    ) -> None:
        self._endpoint = endpoint
        self._service_name = service_name
        self._api_key = api_key
        self._environment = environment
        self._application_name = application_name
        self._setup_otel()

    def _setup_otel(self) -> None:
        """Configure OTel SDK to export to OpenLit's OTLP endpoint."""
        try:
            from opentelemetry import metrics, trace
            from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
                OTLPMetricExporter,
            )
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
                OTLPSpanExporter,
            )
            from opentelemetry.sdk.metrics import MeterProvider
            from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
            from opentelemetry.sdk.resources import Resource
            from opentelemetry.sdk.trace import TracerProvider
            from opentelemetry.sdk.trace.export import BatchSpanProcessor
        except ImportError as exc:
            raise ImportError(
                "OpenLit integration requires opentelemetry-exporter-otlp-proto-http. "
                "Install with: pip install agent-sre[otel]"
            ) from exc

        headers: dict[str, str] = {}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        resource = Resource.create(
            {
                "service.name": self._service_name,
                "deployment.environment": self._environment,
                "application.name": self._application_name,
            }
        )

        # Traces
        span_exporter = OTLPSpanExporter(
            endpoint=f"{self._endpoint}/v1/traces",
            headers=headers,
        )
        tracer_provider = TracerProvider(resource=resource)
        tracer_provider.add_span_processor(BatchSpanProcessor(span_exporter))
        trace.set_tracer_provider(tracer_provider)
        self._tracer = tracer_provider.get_tracer("agent_sre.openlit", "1.0.0")

        # Metrics
        metric_exporter = OTLPMetricExporter(
            endpoint=f"{self._endpoint}/v1/metrics",
            headers=headers,
        )
        reader = PeriodicExportingMetricReader(metric_exporter, export_interval_millis=10000)
        meter_provider = MeterProvider(resource=resource, metric_readers=[reader])
        metrics.set_meter_provider(meter_provider)

        # Create Agent SRE exporters on top of the configured providers
        from agent_sre.integrations.otel.metrics import MetricsExporter
        from agent_sre.integrations.otel.traces import TraceExporter

        self._metrics = MetricsExporter(
            service_name=self._service_name,
            meter_provider=meter_provider,
        )
        self._traces = TraceExporter(
            service_name=self._service_name,
            tracer_provider=tracer_provider,
        )

        self._tracer_provider = tracer_provider
        self._meter_provider = meter_provider

    @property
    def metrics(self) -> Any:
        """Access the underlying MetricsExporter."""
        return self._metrics

    @property
    def traces(self) -> Any:
        """Access the underlying TraceExporter."""
        return self._traces

    def record_slo(self, slo: SLO) -> None:
        """Record SLO status, error budget, and all SLI values to OpenLit."""
        status = slo.evaluate()
        self._metrics.record_slo(
            slo_name=slo.name,
            status=status.value,
            error_budget_remaining=slo.error_budget.remaining,
            burn_rate=slo.error_budget.burn_rate(),
            labels=slo.labels,
        )
        for indicator in slo.indicators:
            val = indicator.current_value()
            if val is not None:
                self._metrics.record_sli(
                    sli_name=indicator.name,
                    value=val,
                    target=indicator.target,
                    window=indicator.window.value,
                    compliance=indicator.compliance(),
                    labels=slo.labels,
                )

    def record_chaos_experiment(self, experiment: ChaosExperiment) -> None:
        """Record a chaos experiment as an OTel span with fault details."""
        start = experiment.started_at or time.time()
        end = experiment.ended_at or time.time()

        attrs: dict[str, Any] = {
            CHAOS_EXPERIMENT_ID: experiment.experiment_id,
            CHAOS_EXPERIMENT_NAME: experiment.name,
            AGENT_ID: experiment.target_agent,
            "agent.sre.chaos.state": experiment.state.value,
            "agent.sre.chaos.duration_seconds": experiment.duration_seconds,
            "agent.sre.chaos.blast_radius": experiment.blast_radius,
            "agent.sre.chaos.fault_count": len(experiment.faults),
            "agent.sre.chaos.injection_count": len(experiment.injection_events),
            "agent.sre.chaos.resilience_score": experiment.resilience.overall,
            "agent.sre.chaos.resilience_passed": experiment.resilience.passed,
        }

        if experiment.faults:
            attrs[CHAOS_FAULT_TYPE] = experiment.faults[0].fault_type.value
            attrs[CHAOS_FAULT_TARGET] = experiment.faults[0].target

        if experiment.abort_reason:
            attrs["agent.sre.chaos.abort_reason"] = experiment.abort_reason

        span = self._tracer.start_span(
            name=f"chaos.{experiment.name}",
            attributes=attrs,
            start_time=int(start * 1e9),
        )

        from opentelemetry.trace import StatusCode

        if experiment.state.value in ("completed",):
            span.set_status(StatusCode.OK)
        elif experiment.state.value in ("aborted", "failed"):
            span.set_status(StatusCode.ERROR, experiment.abort_reason or "Experiment failed")
        span.end(end_time=int(end * 1e9))

        # Also record resilience as a metric
        self._metrics.record_resilience(
            experiment_name=experiment.name,
            score=experiment.resilience.overall,
            agent_id=experiment.target_agent,
        )

    def shutdown(self) -> None:
        """Flush and shut down exporters."""
        if hasattr(self, "_tracer_provider"):
            self._tracer_provider.force_flush()
            self._tracer_provider.shutdown()
        if hasattr(self, "_meter_provider"):
            self._meter_provider.shutdown()
