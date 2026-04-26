# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
A2A/MCP Protocol-Aware Distributed Tracing for Agent-SRE.

Extends the replay trace model with protocol-level context propagation,
enabling end-to-end visibility across agent-to-agent (A2A) and
model-context-protocol (MCP) boundaries.

Also provides OpenTelemetry native export with agent semantic conventions:
- conventions: Custom attribute names and span kind constants
- spans: Helpers to create attributed OTel spans
- metrics: Agent-specific metric instruments
- exporters: OTLP gRPC/HTTP and console exporter setup

Components:
- ProtocolSpan: Enriched span with protocol metadata (A2A task IDs, MCP request IDs)
- TraceContext: W3C-style context propagation for cross-agent traces
- ProtocolTracer: Instruments A2A and MCP calls with correlated spans
- SpanLink: Cross-trace links for fan-out / fan-in patterns
- ProtocolTimeline: Ordered view across protocol boundaries

Usage:
    tracer = ProtocolTracer(agent_id="orchestrator")

    # Trace an A2A call
    with tracer.a2a_call("worker-agent", task="summarize") as span:
        # inject context into outgoing A2A request
        headers = tracer.inject(span)
        response = call_agent(headers=headers)
        span.set_response(response)

    # Trace an MCP tool call
    with tracer.mcp_call("search-server", tool="web_search", params={"q": "test"}) as span:
        result = mcp_client.call_tool("web_search", {"q": "test"})
        span.set_response(result)

    report = tracer.report()
"""

from __future__ import annotations

import hashlib
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from agent_sre.replay.capture import Span, SpanKind, SpanStatus, Trace, TraceCapture

if TYPE_CHECKING:
    from collections.abc import Generator

# ---------------------------------------------------------------------------
# Protocol types
# ---------------------------------------------------------------------------

class ProtocolType(Enum):
    """Supported agent communication protocols."""

    A2A = "a2a"         # Google A2A (Agent-to-Agent)
    MCP = "mcp"         # Model Context Protocol
    INTERNAL = "internal"  # In-process delegation
    HTTP = "http"       # Generic HTTP/REST
    GRPC = "grpc"       # gRPC


class SpanRole(Enum):
    """Role of the current agent in a protocol span."""

    CLIENT = "client"     # Initiator of the call
    SERVER = "server"     # Receiver of the call
    PRODUCER = "producer" # Async message sender
    CONSUMER = "consumer" # Async message receiver


# ---------------------------------------------------------------------------
# W3C-compatible trace context
# ---------------------------------------------------------------------------

@dataclass
class TraceContext:
    """W3C Trace Context propagation header.

    Serialises to/from the ``traceparent`` format:
    ``{version}-{trace_id}-{span_id}-{flags}``
    """

    trace_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    span_id: str = field(default_factory=lambda: uuid.uuid4().hex[:16])
    parent_span_id: str | None = None
    sampled: bool = True
    baggage: dict[str, str] = field(default_factory=dict)

    def to_traceparent(self) -> str:
        """Serialise as W3C traceparent header value."""
        flags = "01" if self.sampled else "00"
        return f"00-{self.trace_id}-{self.span_id}-{flags}"

    @classmethod
    def from_traceparent(cls, value: str) -> TraceContext:
        """Parse a W3C traceparent header value."""
        parts = value.split("-")
        if len(parts) != 4:
            raise ValueError(f"Invalid traceparent: {value}")
        return cls(
            trace_id=parts[1],
            span_id=parts[2],
            sampled=parts[3] == "01",
        )

    def child(self) -> TraceContext:
        """Create a child context linked to this context."""
        return TraceContext(
            trace_id=self.trace_id,
            parent_span_id=self.span_id,
            baggage=dict(self.baggage),
        )

    def to_headers(self) -> dict[str, str]:
        """Export as HTTP headers for injection."""
        headers = {"traceparent": self.to_traceparent()}
        if self.baggage:
            pairs = [f"{k}={v}" for k, v in self.baggage.items()]
            headers["baggage"] = ",".join(pairs)
        return headers

    @classmethod
    def from_headers(cls, headers: dict[str, str]) -> TraceContext:
        """Extract trace context from HTTP headers."""
        ctx = cls.from_traceparent(headers.get("traceparent", ""))
        baggage_str = headers.get("baggage", "")
        if baggage_str:
            for pair in baggage_str.split(","):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    ctx.baggage[k.strip()] = v.strip()
        return ctx


# ---------------------------------------------------------------------------
# Span links (cross-trace correlation)
# ---------------------------------------------------------------------------

@dataclass
class SpanLink:
    """Link between spans across trace boundaries.

    Used for fan-out patterns where one span triggers multiple
    downstream traces (e.g., orchestrator calling 3 workers).
    """

    trace_id: str
    span_id: str
    relationship: str = "follows_from"  # follows_from | caused_by | related_to
    attributes: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "relationship": self.relationship,
            "attributes": self.attributes,
        }


# ---------------------------------------------------------------------------
# Protocol-enriched span
# ---------------------------------------------------------------------------

@dataclass
class ProtocolSpan:
    """A span enriched with protocol-level metadata.

    Wraps the core ``Span`` from replay/capture and adds protocol
    context (A2A task IDs, MCP request IDs, context propagation).
    """

    span: Span
    protocol: ProtocolType = ProtocolType.INTERNAL
    role: SpanRole = SpanRole.CLIENT
    context: TraceContext | None = None
    links: list[SpanLink] = field(default_factory=list)

    # Protocol-specific metadata
    remote_agent_id: str = ""
    remote_agent_url: str = ""

    # A2A-specific
    a2a_task_id: str = ""
    a2a_message_id: str = ""
    a2a_artifact_count: int = 0

    # MCP-specific
    mcp_server_id: str = ""
    mcp_tool_name: str = ""
    mcp_request_id: str = ""

    @property
    def span_id(self) -> str:
        return self.span.span_id

    @property
    def duration_ms(self) -> float | None:
        return self.span.duration_ms

    def set_response(self, response: Any, cost_usd: float = 0.0) -> None:
        """Record a protocol response and finish the span."""
        output: dict[str, Any] = {}
        if isinstance(response, dict):
            output = response
        elif response is not None:
            output = {"result": str(response)}
        self.span.finish(output=output, cost_usd=cost_usd)

    def set_error(self, error: str) -> None:
        """Mark the span as failed."""
        self.span.finish(error=error)

    def add_link(self, trace_id: str, span_id: str, relationship: str = "follows_from") -> None:
        """Add a cross-trace link."""
        self.links.append(SpanLink(
            trace_id=trace_id,
            span_id=span_id,
            relationship=relationship,
        ))

    def to_dict(self) -> dict[str, Any]:
        d = self.span.to_dict()
        d.update({
            "protocol": self.protocol.value,
            "role": self.role.value,
            "remote_agent_id": self.remote_agent_id,
            "remote_agent_url": self.remote_agent_url,
            "links": [lnk.to_dict() for lnk in self.links],
        })
        if self.protocol == ProtocolType.A2A:
            d["a2a_task_id"] = self.a2a_task_id
            d["a2a_message_id"] = self.a2a_message_id
            d["a2a_artifact_count"] = self.a2a_artifact_count
        elif self.protocol == ProtocolType.MCP:
            d["mcp_server_id"] = self.mcp_server_id
            d["mcp_tool_name"] = self.mcp_tool_name
            d["mcp_request_id"] = self.mcp_request_id
        if self.context:
            d["traceparent"] = self.context.to_traceparent()
        return d


# ---------------------------------------------------------------------------
# Protocol timeline
# ---------------------------------------------------------------------------

@dataclass
class ProtocolTimelineEntry:
    """A single event in the protocol timeline."""

    timestamp: float
    agent_id: str
    protocol: ProtocolType
    direction: str  # "send" | "receive"
    peer_agent: str
    span_id: str
    label: str
    duration_ms: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "protocol": self.protocol.value,
            "direction": self.direction,
            "peer_agent": self.peer_agent,
            "span_id": self.span_id,
            "label": self.label,
            "duration_ms": self.duration_ms,
        }


# ---------------------------------------------------------------------------
# Tracing report
# ---------------------------------------------------------------------------

@dataclass
class TracingReport:
    """Summary report from a ProtocolTracer session."""

    agent_id: str
    trace_id: str
    protocol_spans: list[ProtocolSpan] = field(default_factory=list)
    timeline: list[ProtocolTimelineEntry] = field(default_factory=list)
    start_time: float = 0.0
    end_time: float = 0.0

    @property
    def a2a_calls(self) -> int:
        return sum(1 for s in self.protocol_spans if s.protocol == ProtocolType.A2A)

    @property
    def mcp_calls(self) -> int:
        return sum(1 for s in self.protocol_spans if s.protocol == ProtocolType.MCP)

    @property
    def error_count(self) -> int:
        return sum(1 for s in self.protocol_spans if s.span.status == SpanStatus.ERROR)

    @property
    def total_cost_usd(self) -> float:
        return sum(s.span.cost_usd for s in self.protocol_spans)

    @property
    def total_duration_ms(self) -> float | None:
        if self.end_time <= 0:
            return None
        return (self.end_time - self.start_time) * 1000

    def protocol_breakdown(self) -> dict[str, int]:
        """Count of spans per protocol type."""
        counts: dict[str, int] = {}
        for s in self.protocol_spans:
            key = s.protocol.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "trace_id": self.trace_id,
            "a2a_calls": self.a2a_calls,
            "mcp_calls": self.mcp_calls,
            "error_count": self.error_count,
            "total_cost_usd": self.total_cost_usd,
            "total_duration_ms": self.total_duration_ms,
            "protocol_breakdown": self.protocol_breakdown(),
            "spans": [s.to_dict() for s in self.protocol_spans],
            "timeline": [e.to_dict() for e in self.timeline],
        }


# ---------------------------------------------------------------------------
# Protocol tracer
# ---------------------------------------------------------------------------

class ProtocolTracer:
    """Instruments A2A and MCP calls with correlated, protocol-aware spans.

    Provides context managers for tracing individual protocol calls and
    produces a ``TracingReport`` with timeline and cross-trace links.

    Usage:
        tracer = ProtocolTracer(agent_id="orchestrator")

        with tracer.a2a_call("worker", task="summarize") as span:
            headers = tracer.inject(span)
            result = call_a2a_agent(headers=headers)
            span.set_response(result)

        with tracer.mcp_call("search-server", tool="web_search") as span:
            result = mcp.call_tool("web_search", {})
            span.set_response(result)

        report = tracer.report()
    """

    def __init__(
        self,
        agent_id: str,
        parent_context: TraceContext | None = None,
    ) -> None:
        self._agent_id = agent_id
        self._context = parent_context or TraceContext()
        self._trace = Trace(
            trace_id=self._context.trace_id,
            agent_id=agent_id,
        )
        self._protocol_spans: list[ProtocolSpan] = []
        self._start_time = time.time()

    @property
    def trace_id(self) -> str:
        return self._trace.trace_id

    @property
    def agent_id(self) -> str:
        return self._agent_id

    @property
    def context(self) -> TraceContext:
        return self._context

    # -----------------------------------------------------------------------
    # A2A tracing
    # -----------------------------------------------------------------------

    @contextmanager
    def a2a_call(
        self,
        target_agent: str,
        task: str = "",
        target_url: str = "",
        message_id: str = "",
    ) -> Generator[ProtocolSpan, None, None]:
        """Trace an outgoing A2A call.

        Args:
            target_agent: ID of the agent being called.
            task: Task description or A2A task ID.
            target_url: URL of the target agent.
            message_id: A2A message ID for correlation.
        """
        child_ctx = self._context.child()
        task_id = task or uuid.uuid4().hex[:12]

        span = Span(
            trace_id=self._trace.trace_id,
            kind=SpanKind.DELEGATION,
            name=f"a2a:{target_agent}/{task_id}",
            attributes={
                "protocol": "a2a",
                "target_agent": target_agent,
                "a2a.task_id": task_id,
                "a2a.message_id": message_id or uuid.uuid4().hex[:12],
            },
        )
        self._trace.add_span(span)

        pspan = ProtocolSpan(
            span=span,
            protocol=ProtocolType.A2A,
            role=SpanRole.CLIENT,
            context=child_ctx,
            remote_agent_id=target_agent,
            remote_agent_url=target_url,
            a2a_task_id=task_id,
            a2a_message_id=message_id or span.attributes.get("a2a.message_id", ""),
        )
        self._protocol_spans.append(pspan)

        try:
            yield pspan
        except Exception as exc:
            pspan.set_error(str(exc))
            raise
        finally:
            if span.end_time is None:
                span.finish()

    # -----------------------------------------------------------------------
    # MCP tracing
    # -----------------------------------------------------------------------

    @contextmanager
    def mcp_call(
        self,
        server_id: str,
        tool: str = "",
        params: dict[str, Any] | None = None,
        request_id: str = "",
    ) -> Generator[ProtocolSpan, None, None]:
        """Trace an outgoing MCP tool call.

        Args:
            server_id: ID of the MCP server.
            tool: Tool name being invoked.
            params: Tool call parameters.
            request_id: MCP JSON-RPC request ID.
        """
        child_ctx = self._context.child()
        req_id = request_id or uuid.uuid4().hex[:12]

        span = Span(
            trace_id=self._trace.trace_id,
            kind=SpanKind.TOOL_CALL,
            name=f"mcp:{server_id}/{tool}",
            input_data=params or {},
            attributes={
                "protocol": "mcp",
                "mcp.server_id": server_id,
                "mcp.tool": tool,
                "mcp.request_id": req_id,
            },
        )
        self._trace.add_span(span)

        pspan = ProtocolSpan(
            span=span,
            protocol=ProtocolType.MCP,
            role=SpanRole.CLIENT,
            context=child_ctx,
            mcp_server_id=server_id,
            mcp_tool_name=tool,
            mcp_request_id=req_id,
        )
        self._protocol_spans.append(pspan)

        try:
            yield pspan
        except Exception as exc:
            pspan.set_error(str(exc))
            raise
        finally:
            if span.end_time is None:
                span.finish()

    # -----------------------------------------------------------------------
    # Generic HTTP / internal tracing
    # -----------------------------------------------------------------------

    @contextmanager
    def http_call(
        self,
        target: str,
        method: str = "POST",
        path: str = "/",
    ) -> Generator[ProtocolSpan, None, None]:
        """Trace a generic HTTP call."""
        child_ctx = self._context.child()

        span = Span(
            trace_id=self._trace.trace_id,
            kind=SpanKind.DELEGATION,
            name=f"http:{method} {target}{path}",
            attributes={
                "protocol": "http",
                "http.method": method,
                "http.target": target,
                "http.path": path,
            },
        )
        self._trace.add_span(span)

        pspan = ProtocolSpan(
            span=span,
            protocol=ProtocolType.HTTP,
            role=SpanRole.CLIENT,
            context=child_ctx,
            remote_agent_id=target,
        )
        self._protocol_spans.append(pspan)

        try:
            yield pspan
        except Exception as exc:
            pspan.set_error(str(exc))
            raise
        finally:
            if span.end_time is None:
                span.finish()

    # -----------------------------------------------------------------------
    # Context propagation
    # -----------------------------------------------------------------------

    def inject(self, pspan: ProtocolSpan) -> dict[str, str]:
        """Produce propagation headers for an outgoing call.

        Returns a dict suitable for merging into HTTP headers / A2A metadata.
        """
        if pspan.context is None:
            pspan.context = self._context.child()
        return pspan.context.to_headers()

    def extract(self, headers: dict[str, str]) -> TraceContext:
        """Extract a TraceContext from incoming headers.

        Use on the *server* side to correlate incoming spans with the
        caller's trace.
        """
        return TraceContext.from_headers(headers)

    # -----------------------------------------------------------------------
    # Server-side span creation
    # -----------------------------------------------------------------------

    def receive_a2a(
        self,
        caller_agent: str,
        headers: dict[str, str],
        task: str = "",
    ) -> ProtocolSpan:
        """Create a server-side span for an incoming A2A request.

        Call this on the *receiving* agent to link the incoming
        request back to the caller's trace.
        """
        incoming = self.extract(headers)

        span = Span(
            trace_id=self._trace.trace_id,
            kind=SpanKind.AGENT_TASK,
            name=f"a2a:handle:{task}",
            attributes={
                "protocol": "a2a",
                "caller_agent": caller_agent,
                "a2a.task_id": task,
            },
        )
        self._trace.add_span(span)

        pspan = ProtocolSpan(
            span=span,
            protocol=ProtocolType.A2A,
            role=SpanRole.SERVER,
            context=incoming,
            remote_agent_id=caller_agent,
            a2a_task_id=task,
        )
        # Link back to caller's span (span_id in traceparent = caller's span)
        if incoming.span_id:
            pspan.add_link(
                trace_id=incoming.trace_id,
                span_id=incoming.span_id,
                relationship="caused_by",
            )
        self._protocol_spans.append(pspan)
        return pspan

    def receive_mcp(
        self,
        caller_id: str,
        headers: dict[str, str],
        tool: str = "",
    ) -> ProtocolSpan:
        """Create a server-side span for an incoming MCP request."""
        incoming = self.extract(headers)

        span = Span(
            trace_id=self._trace.trace_id,
            kind=SpanKind.TOOL_CALL,
            name=f"mcp:handle:{tool}",
            attributes={
                "protocol": "mcp",
                "caller_id": caller_id,
                "mcp.tool": tool,
            },
        )
        self._trace.add_span(span)

        pspan = ProtocolSpan(
            span=span,
            protocol=ProtocolType.MCP,
            role=SpanRole.SERVER,
            context=incoming,
            mcp_tool_name=tool,
            remote_agent_id=caller_id,
        )
        if incoming.span_id:
            pspan.add_link(
                trace_id=incoming.trace_id,
                span_id=incoming.span_id,
                relationship="caused_by",
            )
        self._protocol_spans.append(pspan)
        return pspan

    # -----------------------------------------------------------------------
    # Timeline & reporting
    # -----------------------------------------------------------------------

    def _build_timeline(self) -> list[ProtocolTimelineEntry]:
        """Build a chronological timeline from protocol spans."""
        entries: list[ProtocolTimelineEntry] = []
        for ps in self._protocol_spans:
            direction = "send" if ps.role in (SpanRole.CLIENT, SpanRole.PRODUCER) else "receive"
            entries.append(ProtocolTimelineEntry(
                timestamp=ps.span.start_time,
                agent_id=self._agent_id,
                protocol=ps.protocol,
                direction=direction,
                peer_agent=ps.remote_agent_id,
                span_id=ps.span.span_id,
                label=ps.span.name,
                duration_ms=ps.duration_ms,
            ))
        entries.sort(key=lambda e: e.timestamp)
        return entries

    def report(self) -> TracingReport:
        """Generate a tracing report with all protocol spans and timeline."""
        end_time = time.time()
        self._trace.finish()
        return TracingReport(
            agent_id=self._agent_id,
            trace_id=self._trace.trace_id,
            protocol_spans=list(self._protocol_spans),
            timeline=self._build_timeline(),
            start_time=self._start_time,
            end_time=end_time,
        )

    @property
    def trace(self) -> Trace:
        """Access the underlying trace object."""
        return self._trace

    @property
    def protocol_spans(self) -> list[ProtocolSpan]:
        """All protocol spans recorded so far."""
        return list(self._protocol_spans)


# ---------------------------------------------------------------------------
# OpenTelemetry native export — public API re-exports
# ---------------------------------------------------------------------------

from agent_sre.tracing.conventions import (  # noqa: E402
    AGENT_DELEGATION_FROM,
    AGENT_DELEGATION_TO,
    AGENT_DID,
    AGENT_MODEL_NAME,
    AGENT_MODEL_PROVIDER,
    AGENT_POLICY_DECISION,
    AGENT_POLICY_NAME,
    AGENT_TASK,
    AGENT_TASK_NAME,
    AGENT_TASK_SUCCESS,
    AGENT_TOOL_NAME,
    AGENT_TOOL_RESULT,
    AGENT_TRUST_SCORE,
    DELEGATION,
    LLM_INFERENCE,
    POLICY_CHECK,
    TOOL_CALL,
)
from agent_sre.tracing.exporters import (  # noqa: E402
    configure_console_exporter,
    configure_otlp_grpc,
    configure_otlp_http,
)
from agent_sre.tracing.metrics import (  # noqa: E402
    AgentMetrics,
    create_agent_metrics,
)
from agent_sre.tracing.spans import (  # noqa: E402
    start_agent_task_span,
    start_delegation_span,
    start_llm_inference_span,
    start_policy_check_span,
    start_tool_call_span,
)

__all__ = [
    # Conventions — attributes
    "AGENT_DID",
    "AGENT_TRUST_SCORE",
    "AGENT_TASK_SUCCESS",
    "AGENT_TASK_NAME",
    "AGENT_TOOL_NAME",
    "AGENT_TOOL_RESULT",
    "AGENT_MODEL_NAME",
    "AGENT_MODEL_PROVIDER",
    "AGENT_DELEGATION_FROM",
    "AGENT_DELEGATION_TO",
    "AGENT_POLICY_NAME",
    "AGENT_POLICY_DECISION",
    # Conventions — span kinds
    "AGENT_TASK",
    "TOOL_CALL",
    "LLM_INFERENCE",
    "DELEGATION",
    "POLICY_CHECK",
    # Span helpers
    "start_agent_task_span",
    "start_tool_call_span",
    "start_llm_inference_span",
    "start_delegation_span",
    "start_policy_check_span",
    # Metrics
    "AgentMetrics",
    "create_agent_metrics",
    # Exporters
    "configure_otlp_grpc",
    "configure_otlp_http",
    "configure_console_exporter",
    # Protocol tracing (existing)
    "ProtocolType",
    "SpanRole",
    "TraceContext",
    "SpanLink",
    "ProtocolSpan",
    "ProtocolTimelineEntry",
    "TracingReport",
    "ProtocolTracer",
]
