# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""OpenTelemetry integration — native OTLP export with agent semantic conventions.

Provides three exporters:
- MetricsExporter: SLI/SLO gauges, cost counters, latency histograms
- TraceExporter: Converts replay traces to OTEL spans
- EventLogger: Structured events for incidents, alerts, signals, chaos

Usage:
    from agent_sre.integrations.otel import MetricsExporter, TraceExporter, EventLogger

    metrics = MetricsExporter(service_name="my-fleet")
    traces = TraceExporter(service_name="my-fleet")
    events = EventLogger(service_name="my-fleet")

Works with any OTLP-compatible backend (Grafana, Jaeger, Prometheus,
Langfuse, Arize, Datadog, etc.).
"""

from agent_sre.integrations.otel.events import EventLogger
from agent_sre.integrations.otel.metrics import MetricsExporter
from agent_sre.integrations.otel.traces import TraceExporter

__all__ = [
    "MetricsExporter",
    "TraceExporter",
    "EventLogger",
]
