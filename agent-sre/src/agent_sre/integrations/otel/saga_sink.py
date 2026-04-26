# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
OTel adapter for hypervisor SagaSpanExporter.

Bridges the hypervisor's ``SpanSink`` protocol into the native
OpenTelemetry SDK via the existing ``TraceExporter.export_span_simple()``.

Usage::

    from agent_sre.integrations.otel.saga_sink import OTelSpanSink
    from agent_sre.integrations.otel.traces import TraceExporter
    from hypervisor.observability import SagaSpanExporter, HypervisorEventBus

    bus = HypervisorEventBus()
    trace_exporter = TraceExporter(service_name="my-agent")
    sink = OTelSpanSink(trace_exporter, agent_id="agent-1")

    saga_exporter = SagaSpanExporter(bus, sink=sink)
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agent_sre.replay.capture import SpanKind, SpanStatus

if TYPE_CHECKING:
    from agent_sre.integrations.otel.traces import TraceExporter

# Map saga span status strings to SRE SpanStatus
_STATUS_MAP: dict[str, SpanStatus] = {
    "ok": SpanStatus.OK,
    "error": SpanStatus.ERROR,
    "compensating": SpanStatus.ERROR,
}


class OTelSpanSink:
    """Concrete SpanSink adapter that bridges into the OTel TraceExporter.

    Implements the ``SpanSink`` protocol defined in
    ``hypervisor.observability.saga_span_exporter`` without importing it
    (structural subtyping via Protocol).

    Each call to ``record_span()`` creates a native OTel span via
    ``TraceExporter.export_span_simple()``.
    """

    def __init__(
        self,
        trace_exporter: TraceExporter,
        agent_id: str = "",
    ) -> None:
        self._trace_exporter = trace_exporter
        self._agent_id = agent_id
        self._spans_exported: int = 0

    def record_span(
        self,
        name: str,
        start_time: float,
        end_time: float,
        attributes: dict[str, Any],
        status: str,
    ) -> None:
        """Record a completed saga span as a native OTel span.

        Args:
            name: Span name (e.g. ``saga.step.validate``).
            start_time: Unix timestamp when the step started.
            end_time: Unix timestamp when the step completed.
            attributes: Saga-specific attributes (``agent.saga.*``).
            status: One of ``"ok"``, ``"error"``, ``"compensating"``.
        """
        sre_status = _STATUS_MAP.get(status, SpanStatus.OK)

        # Merge saga attributes with agent ID
        merged_attrs: dict[str, Any] = dict(attributes)
        if self._agent_id and "agent.id" not in merged_attrs:
            merged_attrs["agent.id"] = self._agent_id

        self._trace_exporter.export_span_simple(
            name=name,
            kind=SpanKind.INTERNAL,
            agent_id=self._agent_id or merged_attrs.get("agent.did", "unknown"),
            start_time=start_time,
            end_time=end_time,
            status=sre_status,
            attributes=merged_attrs,
        )
        self._spans_exported += 1

    @property
    def spans_exported(self) -> int:
        """Total number of spans sent to OTel."""
        return self._spans_exported
