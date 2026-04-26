# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for trace capture engine."""

import json
import tempfile

from agent_sre.replay.capture import (
    Span,
    SpanKind,
    SpanStatus,
    Trace,
    TraceCapture,
    TraceStore,
    _redact,
)


class TestSpan:
    def test_creation(self) -> None:
        span = Span(name="test", kind=SpanKind.TOOL_CALL)
        assert span.name == "test"
        assert span.kind == SpanKind.TOOL_CALL
        assert span.status == SpanStatus.OK
        assert span.end_time is None

    def test_finish(self) -> None:
        span = Span(name="test")
        span.finish(output={"result": "ok"}, cost_usd=0.01)
        assert span.end_time is not None
        assert span.output_data == {"result": "ok"}
        assert span.cost_usd == 0.01
        assert span.duration_ms is not None
        assert span.duration_ms >= 0

    def test_finish_with_error(self) -> None:
        span = Span(name="failing")
        span.finish(error="connection refused")
        assert span.status == SpanStatus.ERROR
        assert span.error == "connection refused"

    def test_serialization(self) -> None:
        span = Span(name="test", kind=SpanKind.LLM_INFERENCE)
        span.finish(output={"text": "hello"})
        d = span.to_dict()
        restored = Span.from_dict(d)
        assert restored.name == span.name
        assert restored.kind == span.kind
        assert restored.output_data == span.output_data

    def test_duration_none_when_not_finished(self) -> None:
        span = Span(name="running")
        assert span.duration_ms is None


class TestRedaction:
    def test_redact_password(self) -> None:
        text = '{"password": "secret123"}'
        assert "[REDACTED]" in _redact(text)

    def test_redact_api_key(self) -> None:
        text = '{"api_key": "sk-1234567890"}'
        assert "[REDACTED]" in _redact(text)

    def test_redact_email(self) -> None:
        text = "user@example.com sent a message"
        assert "[EMAIL_REDACTED]" in _redact(text)

    def test_preserves_normal_text(self) -> None:
        text = "This is a normal response"
        assert _redact(text) == text


class TestTrace:
    def test_creation(self) -> None:
        trace = Trace(agent_id="agent-1", task_input="hello")
        assert trace.agent_id == "agent-1"
        assert trace.trace_id != ""
        assert trace.end_time is None

    def test_add_span(self) -> None:
        trace = Trace(agent_id="agent-1")
        span = Span(name="step1")
        trace.add_span(span)
        assert len(trace.spans) == 1
        assert span.trace_id == trace.trace_id

    def test_finish(self) -> None:
        trace = Trace(agent_id="agent-1")
        span = Span(name="step1")
        span.finish(cost_usd=0.05)
        trace.add_span(span)
        trace.finish(output="done", success=True)
        assert trace.end_time is not None
        assert trace.task_output == "done"
        assert trace.success is True
        assert trace.total_cost_usd == 0.05

    def test_root_spans(self) -> None:
        trace = Trace()
        root = Span(name="root")
        child = Span(name="child", parent_id=root.span_id)
        trace.add_span(root)
        trace.add_span(child)
        roots = trace.root_spans()
        assert len(roots) == 1
        assert roots[0].name == "root"

    def test_children_of(self) -> None:
        trace = Trace()
        root = Span(name="root")
        child1 = Span(name="child1", parent_id=root.span_id)
        child2 = Span(name="child2", parent_id=root.span_id)
        trace.add_span(root)
        trace.add_span(child1)
        trace.add_span(child2)
        children = trace.children_of(root.span_id)
        assert len(children) == 2

    def test_content_hash_deterministic(self) -> None:
        trace = Trace(agent_id="x", task_input="y")
        h1 = trace.content_hash
        h2 = trace.content_hash
        assert h1 == h2

    def test_serialization(self) -> None:
        trace = Trace(agent_id="agent-1", task_input="test task")
        span = Span(name="tool_call", kind=SpanKind.TOOL_CALL)
        span.finish(output={"data": "result"})
        trace.add_span(span)
        trace.finish(output="done")

        d = trace.to_dict(redact=False)
        restored = Trace.from_dict(d)
        assert restored.trace_id == trace.trace_id
        assert restored.agent_id == trace.agent_id
        assert len(restored.spans) == 1

    def test_serialization_with_redaction(self) -> None:
        trace = Trace(agent_id="agent-1")
        span = Span(name="api_call", input_data={"api_key": "sk-secret123"})
        span.finish()
        trace.add_span(span)
        trace.finish()

        d = trace.to_dict(redact=True)
        serialized = json.dumps(d)
        assert "sk-secret123" not in serialized


class TestTraceCapture:
    def test_context_manager(self) -> None:
        with TraceCapture(agent_id="agent-1", task_input="hello") as cap:
            cap.start_span("step1", SpanKind.TOOL_CALL, input_data={"q": "test"})
            cap.end_span(output={"result": "found"})

        assert cap.trace.success is True
        assert cap.trace.end_time is not None
        assert len(cap.trace.spans) == 1

    def test_nested_spans(self) -> None:
        with TraceCapture(agent_id="agent-1") as cap:
            cap.start_span("outer", SpanKind.AGENT_TASK)
            cap.start_span("inner", SpanKind.TOOL_CALL)
            cap.end_span(output={"data": "result"})
            cap.end_span()

        assert len(cap.trace.spans) == 2
        outer = cap.trace.spans[0]
        inner = cap.trace.spans[1]
        assert inner.parent_id == outer.span_id

    def test_exception_marks_failure(self) -> None:
        try:
            with TraceCapture(agent_id="agent-1") as cap:
                cap.start_span("failing")
                raise ValueError("test error")
        except ValueError:
            pass

        assert cap.trace.success is False


class TestTraceStore:
    def test_save_and_load(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = TraceStore(tmpdir)
            trace = Trace(agent_id="agent-1", task_input="test")
            trace.finish(output="done")
            store.save(trace)

            loaded = store.load(trace.trace_id)
            assert loaded is not None
            assert loaded.trace_id == trace.trace_id
            assert loaded.agent_id == "agent-1"

    def test_load_nonexistent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = TraceStore(tmpdir)
            assert store.load("nonexistent") is None

    def test_list_traces(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = TraceStore(tmpdir)
            for i in range(3):
                trace = Trace(agent_id=f"agent-{i}")
                trace.finish()
                store.save(trace)

            traces = store.list_traces()
            assert len(traces) == 3

    def test_list_traces_filter_by_agent(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = TraceStore(tmpdir)
            for agent in ["a", "a", "b"]:
                trace = Trace(agent_id=agent)
                trace.finish()
                store.save(trace)

            traces = store.list_traces(agent_id="a")
            assert len(traces) == 2

    def test_delete(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            store = TraceStore(tmpdir)
            trace = Trace(agent_id="agent-1")
            trace.finish()
            store.save(trace)
            assert store.delete(trace.trace_id) is True
            assert store.load(trace.trace_id) is None
            assert store.delete("nonexistent") is False
