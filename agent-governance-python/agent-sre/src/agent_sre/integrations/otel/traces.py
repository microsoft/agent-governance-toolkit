# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""OpenTelemetry trace exporter for Agent SRE.

Converts Agent SRE replay traces (TraceCapture spans) into native
OpenTelemetry spans, preserving parent-child relationships, timing,
cost, and I/O data as span attributes.

Usage:
    from agent_sre.integrations.otel.traces import TraceExporter

    exporter = TraceExporter(service_name="my-agent")
    exporter.export_trace(captured_trace)
"""

from __future__ import annotations

import json
import logging
from typing import Any

from opentelemetry import trace
from opentelemetry.trace import SpanKind as OtelSpanKind
from opentelemetry.trace import StatusCode, Tracer

from agent_sre.integrations.otel.conventions import (
    AGENT_ID,
    SPAN_COST_USD,
    SPAN_KIND_AGENT,
)
from agent_sre.replay.capture import Span as SreSpan
from agent_sre.replay.capture import SpanKind, SpanStatus, Trace

logger = logging.getLogger(__name__)

# Map agent SRE span kinds to OTEL span kinds
_KIND_MAP = {
    SpanKind.AGENT_TASK: OtelSpanKind.INTERNAL,
    SpanKind.TOOL_CALL: OtelSpanKind.CLIENT,
    SpanKind.LLM_INFERENCE: OtelSpanKind.CLIENT,
    SpanKind.DELEGATION: OtelSpanKind.PRODUCER,
    SpanKind.POLICY_CHECK: OtelSpanKind.INTERNAL,
    SpanKind.INTERNAL: OtelSpanKind.INTERNAL,
}

# Map agent SRE span status to OTEL status
_STATUS_MAP = {
    SpanStatus.OK: StatusCode.OK,
    SpanStatus.ERROR: StatusCode.ERROR,
    SpanStatus.TIMEOUT: StatusCode.ERROR,
}


def _safe_json(data: Any, max_length: int = 4096) -> str:
    """Serialize data to JSON string, truncating if too large."""
    try:
        s = json.dumps(data, default=str)
        if len(s) > max_length:
            return s[:max_length] + "...(truncated)"
        return s
    except (TypeError, ValueError):
        return str(data)[:max_length]


class TraceExporter:
    """Exports Agent SRE traces as native OpenTelemetry spans.

    Each SRE Span becomes an OTEL span with:
    - Correct parent-child relationships
    - Agent-specific attributes (cost, kind, I/O)
    - Proper status mapping
    """

    def __init__(
        self,
        service_name: str = "agent-sre",
        tracer_provider: trace.TracerProvider | None = None,
    ) -> None:
        self._service_name = service_name
        if tracer_provider:
            self._tracer: Tracer = tracer_provider.get_tracer(
                "agent_sre", schema_url="https://agent-sre.dev/schema/v1"
            )
        else:
            self._tracer = trace.get_tracer(
                "agent_sre", schema_url="https://agent-sre.dev/schema/v1"
            )

    def export_trace(self, sre_trace: Trace) -> list[trace.Span]:
        """Export an entire Agent SRE trace as OTEL spans.

        Preserves span hierarchy by building parent-child links.

        Args:
            sre_trace: A captured Agent SRE trace

        Returns:
            List of created OTEL spans (for testing/inspection)
        """
        if not sre_trace.spans:
            return []

        otel_spans: list[trace.Span] = []
        span_context_map: dict[str, trace.Span] = {}

        # Sort spans by start_time to ensure parents are created before children
        sorted_spans = sorted(sre_trace.spans, key=lambda s: s.start_time)

        for sre_span in sorted_spans:
            otel_span = self._export_span(
                sre_span,
                sre_trace,
                span_context_map,
            )
            if otel_span:
                otel_spans.append(otel_span)
                span_context_map[sre_span.span_id] = otel_span

        return otel_spans

    def _export_span(
        self,
        sre_span: SreSpan,
        sre_trace: Trace,
        span_context_map: dict[str, trace.Span],
    ) -> trace.Span | None:
        """Export a single SRE span as an OTEL span.

        Args:
            sre_span: The Agent SRE span to export
            sre_trace: The parent trace (for agent context)
            span_context_map: Map of span_id -> OTEL span for parent linking

        Returns:
            The created OTEL span, or None on error
        """
        # Determine OTEL span kind
        otel_kind = _KIND_MAP.get(sre_span.kind, OtelSpanKind.INTERNAL)

        # Build attributes
        attributes: dict[str, Any] = {
            AGENT_ID: sre_trace.agent_id,
            SPAN_KIND_AGENT: sre_span.kind.value,
        }

        if sre_span.cost_usd > 0:
            attributes[SPAN_COST_USD] = sre_span.cost_usd

        if sre_span.input_data:
            attributes["agent.sre.span.input"] = _safe_json(sre_span.input_data)

        if sre_span.output_data:
            attributes["agent.sre.span.output"] = _safe_json(sre_span.output_data)

        # Copy span-level custom attributes
        for k, v in sre_span.attributes.items():
            attr_key = f"agent.sre.custom.{k}" if not k.startswith("agent.") else k
            if isinstance(v, (str, int, float, bool)):
                attributes[attr_key] = v
            else:
                attributes[attr_key] = str(v)

        # Determine parent context
        context = None
        if sre_span.parent_id and sre_span.parent_id in span_context_map:
            parent_otel_span = span_context_map[sre_span.parent_id]
            parent_ctx = parent_otel_span.get_span_context()
            if parent_ctx and parent_ctx.is_valid:
                context = trace.set_span_in_context(parent_otel_span)

        # Create the OTEL span
        span = self._tracer.start_span(
            name=sre_span.name or sre_span.kind.value,
            kind=otel_kind,
            attributes=attributes,
            start_time=int(sre_span.start_time * 1e9),  # OTEL uses nanoseconds
            context=context,
        )

        # Set status
        otel_status = _STATUS_MAP.get(sre_span.status, StatusCode.UNSET)
        if sre_span.status == SpanStatus.ERROR:
            span.set_status(otel_status, sre_span.error or "Unknown error")
        else:
            span.set_status(otel_status)

        # End the span
        end_time_ns = int((sre_span.end_time or sre_span.start_time) * 1e9)
        span.end(end_time=end_time_ns)

        return span

    def export_span_simple(
        self,
        name: str,
        kind: SpanKind,
        agent_id: str,
        start_time: float,
        end_time: float,
        cost_usd: float = 0.0,
        status: SpanStatus = SpanStatus.OK,
        attributes: dict[str, Any] | None = None,
    ) -> trace.Span:
        """Export a single span without a full trace context.

        Convenience method for ad-hoc span creation.

        Args:
            name: Span name
            kind: Agent SRE span kind
            agent_id: Agent identifier
            start_time: Start time as Unix timestamp
            end_time: End time as Unix timestamp
            cost_usd: Cost in USD
            status: Span status
            attributes: Additional attributes

        Returns:
            The created OTEL span
        """
        otel_kind = _KIND_MAP.get(kind, OtelSpanKind.INTERNAL)
        attrs: dict[str, Any] = {
            AGENT_ID: agent_id,
            SPAN_KIND_AGENT: kind.value,
        }
        if cost_usd > 0:
            attrs[SPAN_COST_USD] = cost_usd
        if attributes:
            attrs.update(attributes)

        span = self._tracer.start_span(
            name=name,
            kind=otel_kind,
            attributes=attrs,
            start_time=int(start_time * 1e9),
        )

        otel_status = _STATUS_MAP.get(status, StatusCode.UNSET)
        span.set_status(otel_status)
        span.end(end_time=int(end_time * 1e9))

        return span
