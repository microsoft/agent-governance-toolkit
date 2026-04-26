# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for OpenTelemetry agent semantic conventions, spans, metrics, and exporters."""

from __future__ import annotations

import pytest
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import (
    SimpleSpanProcessor,
    SpanExporter,
    SpanExportResult,
)

# ---------------------------------------------------------------------------
# In-memory span exporter for testing
# ---------------------------------------------------------------------------


class _InMemorySpanExporter(SpanExporter):
    """Minimal in-memory span exporter for tests."""

    def __init__(self) -> None:
        self._spans: list = []
        self._stopped = False

    def export(self, spans):  # type: ignore[override]
        if self._stopped:
            return SpanExportResult.FAILURE
        self._spans.extend(spans)
        return SpanExportResult.SUCCESS

    def get_finished_spans(self) -> list:
        return list(self._spans)

    def clear(self) -> None:
        self._spans.clear()

    def shutdown(self) -> None:
        self._stopped = True


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def span_exporter():
    return _InMemorySpanExporter()


@pytest.fixture()
def tracer_provider(span_exporter):
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(span_exporter))
    return provider


@pytest.fixture()
def tracer(tracer_provider):
    return tracer_provider.get_tracer("test-agent-sre")


@pytest.fixture()
def metric_reader():
    return InMemoryMetricReader()


@pytest.fixture()
def meter(metric_reader):
    provider = MeterProvider(metric_readers=[metric_reader])
    return provider.get_meter("test-agent-sre")


# ---------------------------------------------------------------------------
# Tests — Conventions
# ---------------------------------------------------------------------------


class TestConventions:
    """Semantic convention constants exist and have correct values."""

    def test_custom_attributes(self):
        from agent_sre.tracing.conventions import (
            AGENT_DELEGATION_FROM,
            AGENT_DELEGATION_TO,
            AGENT_DID,
            AGENT_MODEL_NAME,
            AGENT_MODEL_PROVIDER,
            AGENT_POLICY_DECISION,
            AGENT_POLICY_NAME,
            AGENT_TASK_NAME,
            AGENT_TASK_SUCCESS,
            AGENT_TOOL_NAME,
            AGENT_TOOL_RESULT,
            AGENT_TRUST_SCORE,
        )

        assert AGENT_DID == "agent.did"
        assert AGENT_TRUST_SCORE == "agent.trust_score"
        assert AGENT_TASK_SUCCESS == "agent.task.success"
        assert AGENT_TASK_NAME == "agent.task.name"
        assert AGENT_TOOL_NAME == "agent.tool.name"
        assert AGENT_TOOL_RESULT == "agent.tool.result"
        assert AGENT_MODEL_NAME == "agent.model.name"
        assert AGENT_MODEL_PROVIDER == "agent.model.provider"
        assert AGENT_DELEGATION_FROM == "agent.delegation.from"
        assert AGENT_DELEGATION_TO == "agent.delegation.to"
        assert AGENT_POLICY_NAME == "agent.policy.name"
        assert AGENT_POLICY_DECISION == "agent.policy.decision"

    def test_span_kind_constants(self):
        from agent_sre.tracing.conventions import (
            AGENT_TASK,
            DELEGATION,
            LLM_INFERENCE,
            POLICY_CHECK,
            TOOL_CALL,
        )

        assert AGENT_TASK == "AGENT_TASK"
        assert TOOL_CALL == "TOOL_CALL"
        assert LLM_INFERENCE == "LLM_INFERENCE"
        assert DELEGATION == "DELEGATION"
        assert POLICY_CHECK == "POLICY_CHECK"

    def test_importable_from_tracing_package(self):
        from agent_sre.tracing import (
            AGENT_DID,
            AGENT_TASK,
        )

        assert AGENT_DID == "agent.did"
        assert AGENT_TASK == "AGENT_TASK"


# ---------------------------------------------------------------------------
# Tests — Span helpers
# ---------------------------------------------------------------------------


class TestSpanHelpers:
    """Span creation functions produce correctly attributed spans."""

    def test_agent_task_span(self, tracer, span_exporter):
        from agent_sre.tracing.spans import start_agent_task_span

        span = start_agent_task_span(tracer, "process_refund", "did:agent:123")
        span.end()

        finished = span_exporter.get_finished_spans()
        assert len(finished) == 1
        s = finished[0]
        assert s.name == "agent_task:process_refund"
        assert s.attributes["agent.span.kind"] == "AGENT_TASK"
        assert s.attributes["agent.task.name"] == "process_refund"
        assert s.attributes["agent.did"] == "did:agent:123"

    def test_tool_call_span(self, tracer, span_exporter):
        from agent_sre.tracing.spans import start_tool_call_span

        span = start_tool_call_span(tracer, "web_search", "did:agent:456")
        span.end()

        finished = span_exporter.get_finished_spans()
        assert len(finished) == 1
        s = finished[0]
        assert s.name == "tool_call:web_search"
        assert s.attributes["agent.span.kind"] == "TOOL_CALL"
        assert s.attributes["agent.tool.name"] == "web_search"
        assert s.attributes["agent.did"] == "did:agent:456"

    def test_llm_inference_span(self, tracer, span_exporter):
        from agent_sre.tracing.spans import start_llm_inference_span

        span = start_llm_inference_span(tracer, "gpt-4", "openai")
        span.end()

        finished = span_exporter.get_finished_spans()
        assert len(finished) == 1
        s = finished[0]
        assert s.name == "llm_inference:gpt-4"
        assert s.attributes["agent.span.kind"] == "LLM_INFERENCE"
        assert s.attributes["agent.model.name"] == "gpt-4"
        assert s.attributes["agent.model.provider"] == "openai"

    def test_delegation_span(self, tracer, span_exporter):
        from agent_sre.tracing.spans import start_delegation_span

        span = start_delegation_span(tracer, "did:agent:A", "did:agent:B")
        span.end()

        finished = span_exporter.get_finished_spans()
        assert len(finished) == 1
        s = finished[0]
        assert s.name == "delegation:did:agent:A->did:agent:B"
        assert s.attributes["agent.span.kind"] == "DELEGATION"
        assert s.attributes["agent.delegation.from"] == "did:agent:A"
        assert s.attributes["agent.delegation.to"] == "did:agent:B"

    def test_policy_check_span(self, tracer, span_exporter):
        from agent_sre.tracing.spans import start_policy_check_span

        span = start_policy_check_span(tracer, "budget_limit", "did:agent:789")
        span.end()

        finished = span_exporter.get_finished_spans()
        assert len(finished) == 1
        s = finished[0]
        assert s.name == "policy_check:budget_limit"
        assert s.attributes["agent.span.kind"] == "POLICY_CHECK"
        assert s.attributes["agent.policy.name"] == "budget_limit"
        assert s.attributes["agent.did"] == "did:agent:789"

    def test_extra_kwargs_set_as_attributes(self, tracer, span_exporter):
        from agent_sre.tracing.spans import start_agent_task_span

        span = start_agent_task_span(
            tracer,
            "classify",
            "did:agent:X",
            custom_key="custom_value",
        )
        span.end()

        finished = span_exporter.get_finished_spans()
        assert finished[0].attributes["custom_key"] == "custom_value"


# ---------------------------------------------------------------------------
# Tests — Metrics
# ---------------------------------------------------------------------------


class TestMetrics:
    """Metric instruments are created correctly."""

    def test_create_agent_metrics_without_callback(self, meter):
        from agent_sre.tracing.metrics import AgentMetrics, create_agent_metrics

        m = create_agent_metrics(meter)
        assert isinstance(m, AgentMetrics)
        assert m.trust_score is None

    def test_create_agent_metrics_with_callback(self, meter):
        from opentelemetry.metrics import Observation

        from agent_sre.tracing.metrics import create_agent_metrics

        def _cb(options):
            return [Observation(0.95)]

        m = create_agent_metrics(meter, trust_score_callback=_cb)
        assert m.trust_score is not None

    def test_counter_instruments(self, meter, metric_reader):
        from agent_sre.tracing.metrics import create_agent_metrics

        m = create_agent_metrics(meter)
        m.tasks_total.add(5, {"agent.did": "a1"})
        m.tool_calls_total.add(3, {"agent.did": "a1"})
        m.policy_violations.add(1, {"agent.did": "a1"})

        data = metric_reader.get_metrics_data()
        names = set()
        for rm in data.resource_metrics:
            for sm in rm.scope_metrics:
                for metric in sm.metrics:
                    names.add(metric.name)

        assert "agent.tasks.total" in names
        assert "agent.tool_calls.total" in names
        assert "agent.policy.violations" in names

    def test_histogram_instruments(self, meter, metric_reader):
        from agent_sre.tracing.metrics import create_agent_metrics

        m = create_agent_metrics(meter)
        m.task_duration.record(150.0)
        m.llm_latency.record(200.0)
        m.tool_latency.record(50.0)

        data = metric_reader.get_metrics_data()
        names = set()
        for rm in data.resource_metrics:
            for sm in rm.scope_metrics:
                for metric in sm.metrics:
                    names.add(metric.name)

        assert "agent.task.duration" in names
        assert "agent.llm.latency" in names
        assert "agent.tool.latency" in names

    def test_up_down_counter(self, meter, metric_reader):
        from agent_sre.tracing.metrics import create_agent_metrics

        m = create_agent_metrics(meter)
        m.active_tasks.add(1)
        m.active_tasks.add(1)
        m.active_tasks.add(-1)

        data = metric_reader.get_metrics_data()
        names = set()
        for rm in data.resource_metrics:
            for sm in rm.scope_metrics:
                for metric in sm.metrics:
                    names.add(metric.name)

        assert "agent.active_tasks" in names


# ---------------------------------------------------------------------------
# Tests — Exporters
# ---------------------------------------------------------------------------


class TestExporters:
    """Exporter configuration works."""

    def test_console_exporter(self):
        from agent_sre.tracing.exporters import configure_console_exporter

        provider = configure_console_exporter(service_name="test-svc")
        assert isinstance(provider, TracerProvider)

        tracer = provider.get_tracer("test")
        span = tracer.start_span("hello")
        span.end()
        provider.shutdown()

    def test_console_exporter_resource_name(self):
        from agent_sre.tracing.exporters import configure_console_exporter

        provider = configure_console_exporter(service_name="my-agent")
        resource_attrs = dict(provider.resource.attributes)
        assert resource_attrs["service.name"] == "my-agent"
        provider.shutdown()
