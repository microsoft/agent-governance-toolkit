# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for KernelTracer and SpanContext (tracer.py)."""

import sys
import os
import asyncio
import time
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from opentelemetry import trace as otel_trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    SimpleSpanProcessor,
    SpanExporter,
    SpanExportResult,
)
from opentelemetry.sdk.resources import Resource
from opentelemetry.trace import StatusCode

from agent_os_observability.tracer import KernelTracer, SpanContext, trace_operation


class InMemorySpanExporter(SpanExporter):
    """Simple in-memory span exporter for testing."""

    def __init__(self):
        self._spans = []
        self._lock = threading.Lock()

    def export(self, spans):
        with self._lock:
            self._spans.extend(spans)
        return SpanExportResult.SUCCESS

    def shutdown(self):
        pass

    def force_flush(self, timeout_millis=0):
        return True

    def get_finished_spans(self):
        with self._lock:
            return list(self._spans)

    def clear(self):
        with self._lock:
            self._spans.clear()


def _make_tracer_and_exporter():
    """Create a tracer with SimpleSpanProcessor so spans are exported immediately.

    Because ``trace.set_tracer_provider`` only works on the first call,
    we build the provider manually and get the tracer from it directly.
    """
    exporter = InMemorySpanExporter()
    provider = TracerProvider(
        resource=Resource.create({"service.name": "test-service"})
    )
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer_obj = provider.get_tracer(__name__)
    # Build a thin wrapper that behaves like KernelTracer but uses our provider
    kt = KernelTracer.__new__(KernelTracer)
    kt.tracer = tracer_obj
    return kt, exporter, provider


@pytest.fixture
def tracer_bundle():
    kt, exporter, provider = _make_tracer_and_exporter()
    yield kt, exporter, provider
    provider.shutdown()


@pytest.fixture
def tracer(tracer_bundle):
    return tracer_bundle[0]


@pytest.fixture
def exporter(tracer_bundle):
    return tracer_bundle[1]


class TestKernelTracerInit:
    def test_creates_tracer_with_service_name(self):
        t = KernelTracer(service_name="my-service")
        assert t.tracer is not None

    def test_creates_tracer_with_custom_attributes(self):
        t = KernelTracer(
            service_name="my-service",
            attributes={"custom.key": "value"},
        )
        assert t.tracer is not None

    def test_exporter_adds_batch_span_processor(self):
        kt, exp, provider = _make_tracer_and_exporter()
        with kt.span("test_span"):
            pass
        provider.force_flush()
        spans = exp.get_finished_spans()
        assert len(spans) >= 1
        provider.shutdown()


class TestSpan:
    def test_span_creates_context_manager(self, tracer):
        ctx = tracer.span("test_op")
        assert isinstance(ctx, SpanContext)

    def test_span_sets_attributes(self, tracer, exporter, tracer_bundle):
        provider = tracer_bundle[2]
        with tracer.span("test_op", {"key": "value"}):
            pass
        provider.force_flush()
        spans = exporter.get_finished_spans()
        span = [s for s in spans if s.name == "test_op"][-1]
        assert span.attributes["key"] == "value"


class TestSpanContext:
    def test_enter_exit_records_duration(self, tracer, exporter, tracer_bundle):
        provider = tracer_bundle[2]
        with tracer.span("timed_op") as ctx:
            time.sleep(0.02)
        provider.force_flush()
        spans = exporter.get_finished_spans()
        span = [s for s in spans if s.name == "timed_op"][-1]
        assert span.attributes["duration_ms"] > 0

    def test_success_sets_ok_status(self, tracer, exporter, tracer_bundle):
        provider = tracer_bundle[2]
        with tracer.span("ok_op"):
            pass
        provider.force_flush()
        spans = exporter.get_finished_spans()
        span = [s for s in spans if s.name == "ok_op"][-1]
        assert span.status.status_code == StatusCode.OK

    def test_exception_sets_error_status(self, tracer, exporter, tracer_bundle):
        provider = tracer_bundle[2]
        with pytest.raises(ValueError):
            with tracer.span("err_op"):
                raise ValueError("test error")
        provider.force_flush()
        spans = exporter.get_finished_spans()
        span = [s for s in spans if s.name == "err_op"][-1]
        assert span.status.status_code == StatusCode.ERROR

    def test_set_attribute(self, tracer, exporter, tracer_bundle):
        provider = tracer_bundle[2]
        with tracer.span("attr_op") as ctx:
            ctx.set_attribute("my_key", "my_value")
        provider.force_flush()
        spans = exporter.get_finished_spans()
        span = [s for s in spans if s.name == "attr_op"][-1]
        assert span.attributes["my_key"] == "my_value"

    def test_add_event(self, tracer, exporter, tracer_bundle):
        provider = tracer_bundle[2]
        with tracer.span("event_op") as ctx:
            ctx.add_event("my_event", {"detail": "info"})
        provider.force_flush()
        spans = exporter.get_finished_spans()
        span = [s for s in spans if s.name == "event_op"][-1]
        event_names = [e.name for e in span.events]
        assert "my_event" in event_names

    def test_record_exception(self, tracer, exporter, tracer_bundle):
        provider = tracer_bundle[2]
        with tracer.span("exc_op") as ctx:
            ctx.record_exception(RuntimeError("manual record"))
        provider.force_flush()
        spans = exporter.get_finished_spans()
        span = [s for s in spans if s.name == "exc_op"][-1]
        event_names = [e.name for e in span.events]
        assert "exception" in event_names


class TestTraceDecorator:
    def test_sync_function(self, tracer, exporter, tracer_bundle):
        provider = tracer_bundle[2]

        @tracer.trace("sync_fn")
        def add(a, b):
            return a + b

        result = add(2, 3)
        assert result == 5
        provider.force_flush()
        spans = exporter.get_finished_spans()
        names = [s.name for s in spans]
        assert "sync_fn" in names

    def test_async_function(self, tracer, exporter, tracer_bundle):
        provider = tracer_bundle[2]

        @tracer.trace("async_fn")
        async def async_add(a, b):
            return a + b

        result = asyncio.run(async_add(2, 3))
        assert result == 5
        provider.force_flush()
        spans = exporter.get_finished_spans()
        names = [s.name for s in spans]
        assert "async_fn" in names

    def test_decorator_reraises_sync_exceptions(self, tracer):
        @tracer.trace("failing_fn")
        def fail():
            raise RuntimeError("intentional")

        with pytest.raises(RuntimeError, match="intentional"):
            fail()

    def test_decorator_reraises_async_exceptions(self, tracer):
        @tracer.trace("failing_async")
        async def fail_async():
            raise RuntimeError("async intentional")

        with pytest.raises(RuntimeError, match="async intentional"):
            asyncio.run(fail_async())


class TestPrebuiltTraces:
    def test_trace_policy_check(self, tracer, exporter, tracer_bundle):
        provider = tracer_bundle[2]
        with tracer.trace_policy_check("agent-1", "query", ["policy_a", "policy_b"]):
            pass
        provider.force_flush()
        spans = exporter.get_finished_spans()
        span = [s for s in spans if s.name == "kernel.policy_check"][-1]
        assert span.attributes["agent.id"] == "agent-1"
        assert span.attributes["action"] == "query"
        assert span.attributes["policies"] == "policy_a,policy_b"
        assert span.attributes["kernel.component"] == "policy_engine"

    def test_trace_execution(self, tracer, exporter, tracer_bundle):
        provider = tracer_bundle[2]
        with tracer.trace_execution("agent-1", "write"):
            pass
        provider.force_flush()
        spans = exporter.get_finished_spans()
        span = [s for s in spans if s.name == "kernel.execute"][-1]
        assert span.attributes["agent.id"] == "agent-1"
        assert span.attributes["kernel.component"] == "dispatcher"

    def test_trace_signal(self, tracer, exporter, tracer_bundle):
        provider = tracer_bundle[2]
        with tracer.trace_signal("agent-1", "SIGKILL", "violation"):
            pass
        provider.force_flush()
        spans = exporter.get_finished_spans()
        span = [s for s in spans if s.name == "kernel.signal"][-1]
        assert span.attributes["signal"] == "SIGKILL"
        assert span.attributes["reason"] == "violation"

    def test_trace_violation(self, tracer, exporter, tracer_bundle):
        provider = tracer_bundle[2]
        with tracer.trace_violation("agent-1", "delete", "no_delete", "policy breach"):
            pass
        provider.force_flush()
        spans = exporter.get_finished_spans()
        span = [s for s in spans if s.name == "kernel.violation"][-1]
        assert span.attributes["severity"] == "high"
        assert span.attributes["policy"] == "no_delete"


class TestTraceOperation:
    def test_standalone_decorator(self, tracer, exporter, tracer_bundle):
        provider = tracer_bundle[2]

        @trace_operation(tracer, "standalone_op", {"env": "test"})
        def my_func():
            return 42

        result = my_func()
        assert result == 42
        provider.force_flush()
        spans = exporter.get_finished_spans()
        names = [s.name for s in spans]
        assert "standalone_op" in names
