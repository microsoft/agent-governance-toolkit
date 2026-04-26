# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for A2A/MCP protocol-aware distributed tracing."""

from __future__ import annotations

import time

import pytest

from agent_sre.replay.capture import SpanKind, SpanStatus
from agent_sre.tracing import (
    ProtocolSpan,
    ProtocolTimelineEntry,
    ProtocolTracer,
    ProtocolType,
    SpanLink,
    SpanRole,
    TraceContext,
)

# ---------------------------------------------------------------------------
# TraceContext
# ---------------------------------------------------------------------------

class TestTraceContext:
    """W3C trace context propagation."""

    def test_to_traceparent_sampled(self):
        ctx = TraceContext(trace_id="abc123", span_id="def456", sampled=True)
        assert ctx.to_traceparent() == "00-abc123-def456-01"

    def test_to_traceparent_not_sampled(self):
        ctx = TraceContext(trace_id="abc123", span_id="def456", sampled=False)
        assert ctx.to_traceparent() == "00-abc123-def456-00"

    def test_from_traceparent(self):
        ctx = TraceContext.from_traceparent("00-abc123-def456-01")
        assert ctx.trace_id == "abc123"
        assert ctx.span_id == "def456"
        assert ctx.sampled is True

    def test_from_traceparent_not_sampled(self):
        ctx = TraceContext.from_traceparent("00-abc123-def456-00")
        assert ctx.sampled is False

    def test_from_traceparent_invalid(self):
        with pytest.raises(ValueError, match="Invalid traceparent"):
            TraceContext.from_traceparent("bad-value")

    def test_child_preserves_trace_id(self):
        parent = TraceContext(trace_id="parent-trace", span_id="parent-span")
        child = parent.child()
        assert child.trace_id == "parent-trace"
        assert child.parent_span_id == "parent-span"
        assert child.span_id != "parent-span"  # new span ID

    def test_child_inherits_baggage(self):
        parent = TraceContext(baggage={"user": "alice", "env": "prod"})
        child = parent.child()
        assert child.baggage == {"user": "alice", "env": "prod"}
        # Mutating child baggage doesn't affect parent
        child.baggage["extra"] = "value"
        assert "extra" not in parent.baggage

    def test_to_headers(self):
        ctx = TraceContext(
            trace_id="tid", span_id="sid", sampled=True,
            baggage={"key1": "val1", "key2": "val2"},
        )
        headers = ctx.to_headers()
        assert headers["traceparent"] == "00-tid-sid-01"
        assert "key1=val1" in headers["baggage"]
        assert "key2=val2" in headers["baggage"]

    def test_to_headers_no_baggage(self):
        ctx = TraceContext(trace_id="tid", span_id="sid")
        headers = ctx.to_headers()
        assert "traceparent" in headers
        assert "baggage" not in headers

    def test_from_headers_roundtrip(self):
        # Use IDs without hyphens (W3C traceparent uses '-' as delimiter)
        original = TraceContext(
            trace_id="abcdef1234567890abcdef1234567890", span_id="1234567890abcdef",
            sampled=True, baggage={"env": "staging"},
        )
        headers = original.to_headers()
        restored = TraceContext.from_headers(headers)
        assert restored.trace_id == "abcdef1234567890abcdef1234567890"
        assert restored.span_id == "1234567890abcdef"
        assert restored.sampled is True
        assert restored.baggage["env"] == "staging"

    def test_default_context_has_ids(self):
        ctx = TraceContext()
        assert len(ctx.trace_id) == 32  # UUID hex
        assert len(ctx.span_id) == 16


# ---------------------------------------------------------------------------
# SpanLink
# ---------------------------------------------------------------------------

class TestSpanLink:
    def test_to_dict(self):
        link = SpanLink(
            trace_id="t1", span_id="s1",
            relationship="caused_by",
            attributes={"source": "test"},
        )
        d = link.to_dict()
        assert d["trace_id"] == "t1"
        assert d["span_id"] == "s1"
        assert d["relationship"] == "caused_by"
        assert d["attributes"]["source"] == "test"


# ---------------------------------------------------------------------------
# ProtocolSpan
# ---------------------------------------------------------------------------

class TestProtocolSpan:
    def test_set_response_dict(self):
        from agent_sre.replay.capture import Span
        span = Span(kind=SpanKind.TOOL_CALL, name="test")
        ps = ProtocolSpan(span=span, protocol=ProtocolType.MCP)
        ps.set_response({"data": 42}, cost_usd=0.01)
        assert span.output_data == {"data": 42}
        assert span.cost_usd == 0.01
        assert span.end_time is not None

    def test_set_response_string(self):
        from agent_sre.replay.capture import Span
        span = Span(kind=SpanKind.DELEGATION, name="test")
        ps = ProtocolSpan(span=span, protocol=ProtocolType.A2A)
        ps.set_response("hello world")
        assert span.output_data == {"result": "hello world"}

    def test_set_error(self):
        from agent_sre.replay.capture import Span
        span = Span(kind=SpanKind.TOOL_CALL, name="test")
        ps = ProtocolSpan(span=span)
        ps.set_error("connection refused")
        assert span.status == SpanStatus.ERROR
        assert span.error == "connection refused"

    def test_add_link(self):
        from agent_sre.replay.capture import Span
        span = Span(kind=SpanKind.INTERNAL, name="test")
        ps = ProtocolSpan(span=span)
        ps.add_link("trace-1", "span-1", "follows_from")
        assert len(ps.links) == 1
        assert ps.links[0].trace_id == "trace-1"

    def test_to_dict_a2a(self):
        from agent_sre.replay.capture import Span
        span = Span(kind=SpanKind.DELEGATION, name="a2a:worker/summarize")
        ps = ProtocolSpan(
            span=span,
            protocol=ProtocolType.A2A,
            role=SpanRole.CLIENT,
            remote_agent_id="worker",
            a2a_task_id="summarize",
            a2a_message_id="msg-1",
        )
        d = ps.to_dict()
        assert d["protocol"] == "a2a"
        assert d["role"] == "client"
        assert d["a2a_task_id"] == "summarize"
        assert d["a2a_message_id"] == "msg-1"
        assert "mcp_server_id" not in d

    def test_to_dict_mcp(self):
        from agent_sre.replay.capture import Span
        span = Span(kind=SpanKind.TOOL_CALL, name="mcp:search/web_search")
        ps = ProtocolSpan(
            span=span,
            protocol=ProtocolType.MCP,
            mcp_server_id="search",
            mcp_tool_name="web_search",
            mcp_request_id="req-1",
        )
        d = ps.to_dict()
        assert d["protocol"] == "mcp"
        assert d["mcp_server_id"] == "search"
        assert d["mcp_tool_name"] == "web_search"
        assert "a2a_task_id" not in d

    def test_span_id_property(self):
        from agent_sre.replay.capture import Span
        span = Span(span_id="test-id", kind=SpanKind.INTERNAL, name="test")
        ps = ProtocolSpan(span=span)
        assert ps.span_id == "test-id"


# ---------------------------------------------------------------------------
# ProtocolTracer — A2A calls
# ---------------------------------------------------------------------------

class TestProtocolTracerA2A:
    def test_a2a_call_creates_span(self):
        tracer = ProtocolTracer(agent_id="orchestrator")
        with tracer.a2a_call("worker", task="summarize") as span:
            assert span.protocol == ProtocolType.A2A
            assert span.role == SpanRole.CLIENT
            assert span.remote_agent_id == "worker"
            assert span.a2a_task_id == "summarize"
        assert span.span.end_time is not None

    def test_a2a_call_with_response(self):
        tracer = ProtocolTracer(agent_id="orchestrator")
        with tracer.a2a_call("worker", task="analyze") as span:
            span.set_response({"summary": "all good"}, cost_usd=0.05)
        assert span.span.output_data["summary"] == "all good"
        assert span.span.cost_usd == 0.05

    def test_a2a_call_error_propagates(self):
        tracer = ProtocolTracer(agent_id="orchestrator")
        with pytest.raises(RuntimeError, match="agent down"), tracer.a2a_call("worker", task="fail") as span:
            raise RuntimeError("agent down")
        assert span.span.status == SpanStatus.ERROR
        assert span.span.error == "agent down"

    def test_a2a_span_has_delegation_kind(self):
        tracer = ProtocolTracer(agent_id="orchestrator")
        with tracer.a2a_call("worker", task="test") as span:
            pass
        assert span.span.kind == SpanKind.DELEGATION

    def test_a2a_context_propagation(self):
        tracer = ProtocolTracer(agent_id="orchestrator")
        with tracer.a2a_call("worker", task="test") as span:
            headers = tracer.inject(span)
        assert "traceparent" in headers
        ctx = TraceContext.from_traceparent(headers["traceparent"])
        assert ctx.trace_id == tracer.trace_id


# ---------------------------------------------------------------------------
# ProtocolTracer — MCP calls
# ---------------------------------------------------------------------------

class TestProtocolTracerMCP:
    def test_mcp_call_creates_span(self):
        tracer = ProtocolTracer(agent_id="agent-1")
        with tracer.mcp_call("search-server", tool="web_search") as span:
            assert span.protocol == ProtocolType.MCP
            assert span.mcp_server_id == "search-server"
            assert span.mcp_tool_name == "web_search"
        assert span.span.end_time is not None

    def test_mcp_call_with_params(self):
        tracer = ProtocolTracer(agent_id="agent-1")
        params = {"query": "test", "limit": 5}
        with tracer.mcp_call("search", tool="search", params=params) as span:
            span.set_response({"results": ["a", "b"]})
        assert span.span.input_data == params
        assert span.span.output_data["results"] == ["a", "b"]

    def test_mcp_call_error(self):
        tracer = ProtocolTracer(agent_id="agent-1")
        with pytest.raises(ConnectionError), tracer.mcp_call("broken-server", tool="fail") as span:
            raise ConnectionError("server unreachable")
        assert span.span.status == SpanStatus.ERROR

    def test_mcp_span_has_tool_call_kind(self):
        tracer = ProtocolTracer(agent_id="agent-1")
        with tracer.mcp_call("server", tool="tool1") as span:
            pass
        assert span.span.kind == SpanKind.TOOL_CALL


# ---------------------------------------------------------------------------
# ProtocolTracer — HTTP calls
# ---------------------------------------------------------------------------

class TestProtocolTracerHTTP:
    def test_http_call_creates_span(self):
        tracer = ProtocolTracer(agent_id="agent-1")
        with tracer.http_call("api.example.com", method="GET", path="/health") as span:
            assert span.protocol == ProtocolType.HTTP
            span.set_response({"status": "ok"})
        assert span.span.status == SpanStatus.OK


# ---------------------------------------------------------------------------
# ProtocolTracer — context propagation
# ---------------------------------------------------------------------------

class TestContextPropagation:
    def test_inject_creates_headers(self):
        tracer = ProtocolTracer(agent_id="agent-1")
        with tracer.a2a_call("agent-2", task="task") as span:
            headers = tracer.inject(span)
        assert "traceparent" in headers

    def test_extract_parses_headers(self):
        tracer = ProtocolTracer(agent_id="agent-1")
        headers = {"traceparent": "00-abc-def-01", "baggage": "env=prod"}
        ctx = tracer.extract(headers)
        assert ctx.trace_id == "abc"
        assert ctx.span_id == "def"
        assert ctx.baggage["env"] == "prod"

    def test_end_to_end_propagation(self):
        """Simulate orchestrator → worker context flow."""
        # Orchestrator side
        orchestrator = ProtocolTracer(agent_id="orchestrator")
        with orchestrator.a2a_call("worker", task="analyze") as span:
            headers = orchestrator.inject(span)
            span.set_response({"result": "done"})

        # Worker side
        worker = ProtocolTracer(agent_id="worker")
        server_span = worker.receive_a2a("orchestrator", headers, task="analyze")

        # Verify trace correlation
        assert server_span.role == SpanRole.SERVER
        assert server_span.remote_agent_id == "orchestrator"
        assert len(server_span.links) == 1
        assert server_span.links[0].relationship == "caused_by"

    def test_mcp_server_side_receive(self):
        """Simulate agent → MCP server context flow."""
        agent = ProtocolTracer(agent_id="agent-1")
        with agent.mcp_call("search", tool="web_search") as span:
            headers = agent.inject(span)
            span.set_response({"results": []})

        # MCP server side
        server = ProtocolTracer(agent_id="search-server")
        server_span = server.receive_mcp("agent-1", headers, tool="web_search")
        assert server_span.role == SpanRole.SERVER
        assert server_span.mcp_tool_name == "web_search"
        assert len(server_span.links) == 1

    def test_parent_context_inherited(self):
        """Tracer with parent context propagates parent trace ID."""
        parent_ctx = TraceContext(trace_id="parent-trace-id")
        tracer = ProtocolTracer(agent_id="child", parent_context=parent_ctx)
        assert tracer.trace_id == "parent-trace-id"


# ---------------------------------------------------------------------------
# ProtocolTracer — report & timeline
# ---------------------------------------------------------------------------

class TestTracingReport:
    def test_report_counts(self):
        tracer = ProtocolTracer(agent_id="agent-1")
        with tracer.a2a_call("a", task="t1") as s:
            s.set_response("ok")
        with tracer.a2a_call("b", task="t2") as s:
            s.set_response("ok")
        with tracer.mcp_call("server", tool="tool1") as s:
            s.set_response({"data": 1})
        report = tracer.report()
        assert report.a2a_calls == 2
        assert report.mcp_calls == 1
        assert report.error_count == 0

    def test_report_cost_aggregation(self):
        tracer = ProtocolTracer(agent_id="agent-1")
        with tracer.mcp_call("s1", tool="t1") as s:
            s.set_response({}, cost_usd=0.01)
        with tracer.mcp_call("s2", tool="t2") as s:
            s.set_response({}, cost_usd=0.02)
        report = tracer.report()
        assert abs(report.total_cost_usd - 0.03) < 1e-10

    def test_report_timeline_ordered(self):
        tracer = ProtocolTracer(agent_id="agent-1")
        with tracer.a2a_call("a", task="first") as s:
            s.set_response("ok")
        time.sleep(0.01)
        with tracer.mcp_call("server", tool="second") as s:
            s.set_response({})
        report = tracer.report()
        assert len(report.timeline) == 2
        assert report.timeline[0].timestamp <= report.timeline[1].timestamp
        assert report.timeline[0].label.startswith("a2a:")
        assert report.timeline[1].label.startswith("mcp:")

    def test_report_protocol_breakdown(self):
        tracer = ProtocolTracer(agent_id="agent-1")
        with tracer.a2a_call("a", task="t") as s:
            s.set_response("ok")
        with tracer.mcp_call("s", tool="t") as s:
            s.set_response({})
        with tracer.http_call("api.com") as s:
            s.set_response("ok")
        report = tracer.report()
        breakdown = report.protocol_breakdown()
        assert breakdown["a2a"] == 1
        assert breakdown["mcp"] == 1
        assert breakdown["http"] == 1

    def test_report_to_dict(self):
        tracer = ProtocolTracer(agent_id="agent-1")
        with tracer.a2a_call("worker", task="test") as s:
            s.set_response("ok")
        report = tracer.report()
        d = report.to_dict()
        assert d["agent_id"] == "agent-1"
        assert d["a2a_calls"] == 1
        assert "spans" in d
        assert "timeline" in d

    def test_report_error_count(self):
        tracer = ProtocolTracer(agent_id="agent-1")
        with tracer.mcp_call("s", tool="ok") as s:
            s.set_response({})
        try:
            with tracer.mcp_call("s", tool="fail") as s:
                raise ValueError("boom")
        except ValueError:
            pass
        report = tracer.report()
        assert report.error_count == 1

    def test_report_duration(self):
        tracer = ProtocolTracer(agent_id="agent-1")
        with tracer.a2a_call("a", task="t") as s:
            s.set_response("ok")
        report = tracer.report()
        assert report.total_duration_ms is not None
        assert report.total_duration_ms >= 0

    def test_empty_report(self):
        tracer = ProtocolTracer(agent_id="agent-1")
        report = tracer.report()
        assert report.a2a_calls == 0
        assert report.mcp_calls == 0
        assert report.total_cost_usd == 0.0

    def test_timeline_entry_to_dict(self):
        entry = ProtocolTimelineEntry(
            timestamp=100.0,
            agent_id="a",
            protocol=ProtocolType.A2A,
            direction="send",
            peer_agent="b",
            span_id="s1",
            label="a2a:b/task",
            duration_ms=5.0,
        )
        d = entry.to_dict()
        assert d["protocol"] == "a2a"
        assert d["direction"] == "send"
        assert d["duration_ms"] == 5.0


# ---------------------------------------------------------------------------
# Multi-agent scenario
# ---------------------------------------------------------------------------

class TestMultiAgentScenario:
    def test_orchestrator_two_workers(self):
        """Orchestrator calls two workers via A2A, each calls MCP tools."""
        orchestrator = ProtocolTracer(agent_id="orchestrator")

        # Call worker-1
        with orchestrator.a2a_call("worker-1", task="search") as span1:
            headers1 = orchestrator.inject(span1)
            # Worker-1 receives and calls MCP
            w1 = ProtocolTracer(agent_id="worker-1", parent_context=TraceContext.from_headers(headers1))
            w1_recv = w1.receive_a2a("orchestrator", headers1, task="search")
            with w1.mcp_call("search-server", tool="web_search", params={"q": "test"}) as mcp_span:
                mcp_span.set_response({"results": ["r1"]})
            w1_recv.set_response({"results": ["r1"]})
            span1.set_response({"results": ["r1"]})

        # Call worker-2
        with orchestrator.a2a_call("worker-2", task="analyze") as span2:
            headers2 = orchestrator.inject(span2)
            w2 = ProtocolTracer(agent_id="worker-2", parent_context=TraceContext.from_headers(headers2))
            w2_recv = w2.receive_a2a("orchestrator", headers2, task="analyze")
            w2_recv.set_response({"analysis": "complete"})
            span2.set_response({"analysis": "complete"})

        # Verify orchestrator report
        report = orchestrator.report()
        assert report.a2a_calls == 2
        assert report.mcp_calls == 0  # MCP calls are on workers
        assert len(report.timeline) == 2

        # Verify worker-1 report
        w1_report = w1.report()
        assert w1_report.a2a_calls == 1  # receive_a2a
        assert w1_report.mcp_calls == 1
        assert w1_report.trace_id == orchestrator.trace_id  # same trace

    def test_chain_delegation(self):
        """A → B → C scope chain with context propagation."""
        agent_a = ProtocolTracer(agent_id="A")

        with agent_a.a2a_call("B", task="step1") as span_a:
            headers_ab = agent_a.inject(span_a)

            agent_b = ProtocolTracer(agent_id="B", parent_context=TraceContext.from_headers(headers_ab))
            b_recv = agent_b.receive_a2a("A", headers_ab, task="step1")

            with agent_b.a2a_call("C", task="step2") as span_b:
                headers_bc = agent_b.inject(span_b)

                agent_c = ProtocolTracer(agent_id="C", parent_context=TraceContext.from_headers(headers_bc))
                c_recv = agent_c.receive_a2a("B", headers_bc, task="step2")
                c_recv.set_response({"done": True})
                span_b.set_response({"done": True})

            b_recv.set_response({"forwarded": True})
            span_a.set_response({"chain_complete": True})

        # All three share the same trace ID
        assert agent_a.trace_id == agent_b.trace_id == agent_c.trace_id

    def test_mixed_protocol_scenario(self):
        """Agent uses A2A, MCP, and HTTP in one trace."""
        tracer = ProtocolTracer(agent_id="multi-protocol-agent")

        with tracer.a2a_call("peer", task="collaborate") as s:
            s.set_response("ack")
        with tracer.mcp_call("db-server", tool="query", params={"sql": "SELECT 1"}) as s:
            s.set_response({"rows": [1]})
        with tracer.http_call("api.example.com", method="POST", path="/webhook") as s:
            s.set_response({"accepted": True})

        report = tracer.report()
        assert report.a2a_calls == 1
        assert report.mcp_calls == 1
        breakdown = report.protocol_breakdown()
        assert breakdown.get("http") == 1
        assert len(report.timeline) == 3


# ---------------------------------------------------------------------------
# Tracer properties
# ---------------------------------------------------------------------------

class TestTracerProperties:
    def test_trace_id(self):
        tracer = ProtocolTracer(agent_id="test")
        assert len(tracer.trace_id) == 32

    def test_agent_id(self):
        tracer = ProtocolTracer(agent_id="my-agent")
        assert tracer.agent_id == "my-agent"

    def test_context(self):
        tracer = ProtocolTracer(agent_id="test")
        assert tracer.context.trace_id == tracer.trace_id

    def test_protocol_spans_empty(self):
        tracer = ProtocolTracer(agent_id="test")
        assert tracer.protocol_spans == []

    def test_protocol_spans_returns_copy(self):
        tracer = ProtocolTracer(agent_id="test")
        with tracer.a2a_call("a", task="t") as s:
            s.set_response("ok")
        spans = tracer.protocol_spans
        assert len(spans) == 1
        spans.clear()
        assert len(tracer.protocol_spans) == 1  # original unaffected

    def test_trace_has_spans(self):
        tracer = ProtocolTracer(agent_id="test")
        with tracer.mcp_call("s", tool="t") as s:
            s.set_response({})
        assert len(tracer.trace.spans) == 1
