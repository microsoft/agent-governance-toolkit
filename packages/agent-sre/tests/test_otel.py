# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for OpenTelemetry integration — metrics, traces, and events.

Uses in-memory OTEL exporters to verify that Agent SRE data is correctly
converted to OTEL signals without requiring a running collector.
"""

from __future__ import annotations

import time

import pytest
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import InMemoryMetricReader
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter, SpanExportResult
from opentelemetry.trace import StatusCode


class _InMemorySpanExporter(SpanExporter):
    """Minimal in-memory span exporter for testing."""

    def __init__(self) -> None:
        self._spans: list = []
        self._stopped = False

    def export(self, spans):
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

from agent_sre.integrations.otel import EventLogger, MetricsExporter, TraceExporter
from agent_sre.integrations.otel.conventions import (
    METRIC_COST_TOTAL,
    METRIC_ERROR_BUDGET_REMAINING,
    METRIC_LATENCY,
    METRIC_SLI_VALUE,
    METRIC_SLO_STATUS,
    SLO_STATUS_CODES,
)
from agent_sre.replay.capture import Span, SpanKind, SpanStatus, Trace

# ========== Fixtures ==========


@pytest.fixture
def metric_reader():
    return InMemoryMetricReader()


@pytest.fixture
def meter_provider(metric_reader):
    provider = MeterProvider(metric_readers=[metric_reader])
    return provider


@pytest.fixture
def metrics_exporter(meter_provider):
    return MetricsExporter(service_name="test-sre", meter_provider=meter_provider)


@pytest.fixture
def span_exporter():
    return _InMemorySpanExporter()


@pytest.fixture
def trace_exporter_with_memory():
    """Create a trace exporter with in-memory span capture."""
    span_exp = _InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(span_exp))
    exporter = TraceExporter(service_name="test-sre", tracer_provider=provider)
    return exporter, span_exp


@pytest.fixture
def event_logger():
    return EventLogger(service_name="test-sre", logger_name="test.agent_sre.events")


# ========== Metrics Tests ==========


class TestMetricsExporter:
    """Test SLI/SLO metrics export."""

    def test_record_sli(self, metrics_exporter, metric_reader):
        """SLI values are recorded as gauge metrics."""
        metrics_exporter.record_sli(
            sli_name="task_success_rate",
            value=0.98,
            target=0.95,
            window="24h",
        )

        data = metric_reader.get_metrics_data()
        metric_names = []
        for resource_metrics in data.resource_metrics:
            for scope_metrics in resource_metrics.scope_metrics:
                for metric in scope_metrics.metrics:
                    metric_names.append(metric.name)

        assert METRIC_SLI_VALUE in metric_names

    def test_record_sli_with_compliance(self, metrics_exporter, metric_reader):
        """SLI compliance is recorded alongside value."""
        metrics_exporter.record_sli(
            sli_name="task_success_rate",
            value=0.98,
            target=0.95,
            window="24h",
            compliance=0.92,
        )

        data = metric_reader.get_metrics_data()
        metric_names = set()
        for resource_metrics in data.resource_metrics:
            for scope_metrics in resource_metrics.scope_metrics:
                for metric in scope_metrics.metrics:
                    metric_names.add(metric.name)

        assert METRIC_SLI_VALUE in metric_names
        assert "agent.sre.sli.compliance" in metric_names

    def test_record_slo(self, metrics_exporter, metric_reader):
        """SLO status, error budget, and burn rate are recorded."""
        metrics_exporter.record_slo(
            slo_name="my-agent",
            status="healthy",
            error_budget_remaining=0.85,
            burn_rate=0.5,
        )

        data = metric_reader.get_metrics_data()
        metric_names = set()
        for resource_metrics in data.resource_metrics:
            for scope_metrics in resource_metrics.scope_metrics:
                for metric in scope_metrics.metrics:
                    metric_names.add(metric.name)

        assert METRIC_SLO_STATUS in metric_names
        assert METRIC_ERROR_BUDGET_REMAINING in metric_names
        assert "agent.sre.burn_rate" in metric_names

    def test_record_slo_from_object(self, metrics_exporter, metric_reader):
        """SLO object can be exported directly."""
        from agent_sre.slo.indicators import TaskSuccessRate
        from agent_sre.slo.objectives import SLO, ErrorBudget

        slo = SLO(
            name="test-slo",
            indicators=[TaskSuccessRate(target=0.95, window="24h")],
            error_budget=ErrorBudget(total=0.05),
        )

        # Record some events
        slo.indicators[0].record_task(success=True)
        slo.indicators[0].record_task(success=True)
        slo.record_event(good=True)
        slo.record_event(good=True)

        metrics_exporter.record_slo_from_object(slo)

        data = metric_reader.get_metrics_data()
        metric_names = set()
        for resource_metrics in data.resource_metrics:
            for scope_metrics in resource_metrics.scope_metrics:
                for metric in scope_metrics.metrics:
                    metric_names.add(metric.name)

        assert METRIC_SLO_STATUS in metric_names
        assert METRIC_SLI_VALUE in metric_names

    def test_record_cost(self, metrics_exporter, metric_reader):
        """Cost metrics are recorded as counter + gauge."""
        metrics_exporter.record_cost(
            agent_id="bot-1",
            cost_usd=0.35,
            avg_per_task=0.35,
            budget_utilization=0.07,
        )

        data = metric_reader.get_metrics_data()
        metric_names = set()
        for resource_metrics in data.resource_metrics:
            for scope_metrics in resource_metrics.scope_metrics:
                for metric in scope_metrics.metrics:
                    metric_names.add(metric.name)

        assert METRIC_COST_TOTAL in metric_names

    def test_record_latency(self, metrics_exporter, metric_reader):
        """Latency is recorded as histogram."""
        metrics_exporter.record_latency(150.0, agent_id="bot-1")
        metrics_exporter.record_latency(200.0, agent_id="bot-1")
        metrics_exporter.record_latency(3500.0, agent_id="bot-1")

        data = metric_reader.get_metrics_data()
        metric_names = set()
        for resource_metrics in data.resource_metrics:
            for scope_metrics in resource_metrics.scope_metrics:
                for metric in scope_metrics.metrics:
                    metric_names.add(metric.name)

        assert METRIC_LATENCY in metric_names

    def test_record_incidents_open(self, metrics_exporter, metric_reader):
        """Open incident count is recorded as gauge."""
        metrics_exporter.record_incidents_open(3)

        data = metric_reader.get_metrics_data()
        metric_names = set()
        for resource_metrics in data.resource_metrics:
            for scope_metrics in resource_metrics.scope_metrics:
                for metric in scope_metrics.metrics:
                    metric_names.add(metric.name)

        assert "agent.sre.incidents.open" in metric_names

    def test_record_resilience(self, metrics_exporter, metric_reader):
        """Fault impact score is recorded as gauge."""
        metrics_exporter.record_resilience(
            experiment_name="tool-failure-test",
            score=85.0,
            agent_id="research-bot",
        )

        data = metric_reader.get_metrics_data()
        metric_names = set()
        for resource_metrics in data.resource_metrics:
            for scope_metrics in resource_metrics.scope_metrics:
                for metric in scope_metrics.metrics:
                    metric_names.add(metric.name)

        assert "agent.sre.chaos.resilience_score" in metric_names

    def test_slo_status_codes_mapping(self):
        """All SLO statuses have numeric codes."""
        assert SLO_STATUS_CODES["healthy"] == 0
        assert SLO_STATUS_CODES["warning"] == 1
        assert SLO_STATUS_CODES["critical"] == 2
        assert SLO_STATUS_CODES["exhausted"] == 3
        assert SLO_STATUS_CODES["unknown"] == -1

    def test_multiple_sli_labels(self, metrics_exporter, metric_reader):
        """Multiple SLIs with different labels don't overwrite each other."""
        metrics_exporter.record_sli("task_success_rate", 0.98, 0.95, "24h",
                                     labels={"env": "prod"})
        metrics_exporter.record_sli("cost_per_task", 0.35, 0.50, "24h",
                                     labels={"env": "prod"})

        data = metric_reader.get_metrics_data()
        sli_count = 0
        for resource_metrics in data.resource_metrics:
            for scope_metrics in resource_metrics.scope_metrics:
                for metric in scope_metrics.metrics:
                    if metric.name == METRIC_SLI_VALUE:
                        sli_count += len(metric.data.data_points)

        assert sli_count == 2


# ========== Trace Tests ==========


class TestTraceExporter:
    """Test replay trace -> OTEL span conversion."""

    def _make_trace(self) -> Trace:
        """Create a sample trace with parent-child spans."""
        now = time.time()
        root = Span(
            span_id="root-001",
            trace_id="trace-001",
            kind=SpanKind.AGENT_TASK,
            name="process_refund",
            start_time=now - 1.0,
            end_time=now - 0.1,
            status=SpanStatus.OK,
            input_data={"task": "refund order #123"},
            output_data={"decision": "approved"},
            cost_usd=0.0,
        )

        tool_call = Span(
            span_id="tool-001",
            parent_id="root-001",
            trace_id="trace-001",
            kind=SpanKind.TOOL_CALL,
            name="lookup_order",
            start_time=now - 0.9,
            end_time=now - 0.7,
            status=SpanStatus.OK,
            input_data={"order_id": "123"},
            output_data={"amount": 49.99},
            cost_usd=0.02,
        )

        llm_call = Span(
            span_id="llm-001",
            parent_id="root-001",
            trace_id="trace-001",
            kind=SpanKind.LLM_INFERENCE,
            name="decide_refund",
            start_time=now - 0.6,
            end_time=now - 0.2,
            status=SpanStatus.OK,
            input_data={"prompt": "Process refund?"},
            output_data={"decision": "approve"},
            cost_usd=0.15,
        )

        return Trace(
            trace_id="trace-001",
            agent_id="support-bot-v3",
            task_input="Refund order #123",
            spans=[root, tool_call, llm_call],
        )

    def test_export_trace_creates_spans(self, trace_exporter_with_memory):
        """Exporting a trace creates OTEL spans for each SRE span."""
        exporter, span_exp = trace_exporter_with_memory
        sre_trace = self._make_trace()

        otel_spans = exporter.export_trace(sre_trace)

        assert len(otel_spans) == 3

    def test_export_trace_span_names(self, trace_exporter_with_memory):
        """OTEL spans have correct names from SRE spans."""
        exporter, span_exp = trace_exporter_with_memory
        sre_trace = self._make_trace()

        exporter.export_trace(sre_trace)
        finished = span_exp.get_finished_spans()

        names = {s.name for s in finished}
        assert "process_refund" in names
        assert "lookup_order" in names
        assert "decide_refund" in names

    def test_export_trace_attributes(self, trace_exporter_with_memory):
        """OTEL spans carry agent-specific attributes."""
        exporter, span_exp = trace_exporter_with_memory
        sre_trace = self._make_trace()

        exporter.export_trace(sre_trace)
        finished = span_exp.get_finished_spans()

        tool_span = next(s for s in finished if s.name == "lookup_order")
        assert tool_span.attributes["agent.id"] == "support-bot-v3"
        assert tool_span.attributes["agent.sre.span.kind"] == "tool_call"
        assert tool_span.attributes["agent.sre.span.cost_usd"] == 0.02

    def test_export_trace_cost_in_attributes(self, trace_exporter_with_memory):
        """Cost is included as span attribute when > 0."""
        exporter, span_exp = trace_exporter_with_memory
        sre_trace = self._make_trace()

        exporter.export_trace(sre_trace)
        finished = span_exp.get_finished_spans()

        llm_span = next(s for s in finished if s.name == "decide_refund")
        assert llm_span.attributes["agent.sre.span.cost_usd"] == 0.15

        root_span = next(s for s in finished if s.name == "process_refund")
        # Root has cost_usd=0.0, so attribute should not be set
        assert "agent.sre.span.cost_usd" not in root_span.attributes

    def test_export_trace_error_status(self, trace_exporter_with_memory):
        """Error spans get OTEL ERROR status."""
        exporter, span_exp = trace_exporter_with_memory

        now = time.time()
        error_span = Span(
            span_id="err-001",
            trace_id="trace-err",
            kind=SpanKind.TOOL_CALL,
            name="failing_tool",
            start_time=now - 1.0,
            end_time=now,
            status=SpanStatus.ERROR,
            error="Connection refused",
        )
        sre_trace = Trace(
            trace_id="trace-err",
            agent_id="bot-1",
            task_input="test",
            spans=[error_span],
        )

        exporter.export_trace(sre_trace)
        finished = span_exp.get_finished_spans()

        assert len(finished) == 1
        assert finished[0].status.status_code == StatusCode.ERROR
        assert "Connection refused" in (finished[0].status.description or "")

    def test_export_empty_trace(self, trace_exporter_with_memory):
        """Empty traces produce no spans."""
        exporter, span_exp = trace_exporter_with_memory

        sre_trace = Trace(
            trace_id="trace-empty",
            agent_id="bot-1",
            task_input="",
            spans=[],
        )

        result = exporter.export_trace(sre_trace)
        assert result == []

    def test_export_span_simple(self, trace_exporter_with_memory):
        """Simple span export works without a full trace."""
        exporter, span_exp = trace_exporter_with_memory

        now = time.time()
        exporter.export_span_simple(
            name="quick_check",
            kind=SpanKind.POLICY_CHECK,
            agent_id="bot-1",
            start_time=now - 0.5,
            end_time=now,
            cost_usd=0.01,
        )

        finished = span_exp.get_finished_spans()
        assert len(finished) == 1
        assert finished[0].name == "quick_check"
        assert finished[0].attributes["agent.sre.span.cost_usd"] == 0.01

    def test_span_io_data_serialized(self, trace_exporter_with_memory):
        """Input/output data is serialized as JSON string attributes."""
        exporter, span_exp = trace_exporter_with_memory

        now = time.time()
        span = Span(
            span_id="io-001",
            trace_id="trace-io",
            kind=SpanKind.LLM_INFERENCE,
            name="inference",
            start_time=now - 1.0,
            end_time=now,
            input_data={"prompt": "Hello"},
            output_data={"response": "World"},
        )
        sre_trace = Trace(
            trace_id="trace-io",
            agent_id="bot-1",
            task_input="test",
            spans=[span],
        )

        exporter.export_trace(sre_trace)
        finished = span_exp.get_finished_spans()

        assert '"prompt": "Hello"' in finished[0].attributes["agent.sre.span.input"]
        assert '"response": "World"' in finished[0].attributes["agent.sre.span.output"]


# ========== Event Tests ==========


class TestEventLogger:
    """Test structured event logging."""

    def test_log_slo_status_change(self, event_logger):
        """SLO status changes produce structured events."""
        result = event_logger.log_slo_status_change(
            slo_name="my-agent",
            old_status="healthy",
            new_status="warning",
            error_budget_remaining=0.3,
        )

        assert result["event.name"] == "agent.sre.slo.status_change"
        assert result["agent.sre.slo.name"] == "my-agent"
        assert result["agent.sre.slo.status"] == "warning"
        assert result["agent.sre.error_budget.remaining"] == 0.3

    def test_log_burn_rate_alert(self, event_logger):
        """Burn rate alerts produce structured events."""
        result = event_logger.log_burn_rate_alert(
            slo_name="my-agent",
            alert_name="fast_burn_critical",
            burn_rate=12.5,
            severity="critical",
        )

        assert result["event.name"] == "agent.sre.burn_rate.alert"
        assert result["agent.sre.burn_rate"] == 12.5
        assert result["agent.sre.alert.severity"] == "critical"

    def test_log_cost_alert(self, event_logger):
        """Cost alerts produce structured events."""
        result = event_logger.log_cost_alert(
            agent_id="research-bot",
            severity="warning",
            message="Approaching daily limit",
            current_value=85.0,
            threshold=100.0,
        )

        assert result["event.name"] == "agent.sre.cost.alert"
        assert result["agent.sre.cost.agent_id"] == "research-bot"
        assert result["agent.sre.cost.current_value"] == 85.0

    def test_log_signal(self, event_logger):
        """Signals produce structured events."""
        result = event_logger.log_signal(
            signal_type="slo_breach",
            source="support-agent",
            value=0.89,
            message="Task success rate below target",
        )

        assert result["event.name"] == "agent.sre.signal.received"
        assert result["agent.sre.signal.type"] == "slo_breach"
        assert result["agent.sre.signal.source"] == "support-agent"

    def test_log_incident_detected(self, event_logger):
        """Incidents produce structured events with severity."""
        result = event_logger.log_incident_detected(
            incident_id="inc-001",
            title="Error budget exhausted",
            severity="p1",
            agent_id="support-bot",
            signal_count=3,
        )

        assert result["event.name"] == "agent.sre.incident.detected"
        assert result["agent.sre.incident.id"] == "inc-001"
        assert result["agent.sre.incident.severity"] == "p1"
        assert result["agent.sre.incident.signal_count"] == 3
        assert result["agent.id"] == "support-bot"

    def test_log_incident_resolved(self, event_logger):
        """Incident resolutions include duration."""
        result = event_logger.log_incident_resolved(
            incident_id="inc-001",
            duration_seconds=1800.0,
        )

        assert result["event.name"] == "agent.sre.incident.resolved"
        assert result["agent.sre.incident.state"] == "resolved"
        assert result["agent.sre.incident.duration_seconds"] == 1800.0

    def test_log_fault_injected(self, event_logger):
        """Chaos fault injections produce structured events."""
        result = event_logger.log_fault_injected(
            experiment_name="tool-failure-test",
            fault_type="tool_timeout",
            target="web_search",
            applied=True,
        )

        assert result["event.name"] == "agent.sre.chaos.fault_injected"
        assert result["agent.sre.chaos.fault_type"] == "tool_timeout"
        assert result["agent.sre.chaos.fault_target"] == "web_search"
        assert result["agent.sre.chaos.fault_applied"] is True

    def test_log_chaos_completed(self, event_logger):
        """Chaos experiment completions include fault impact score."""
        result = event_logger.log_chaos_completed(
            experiment_name="tool-failure-test",
            resilience_score=85.0,
            agent_id="research-bot",
        )

        assert result["event.name"] == "agent.sre.chaos.completed"
        assert result["agent.sre.chaos.resilience_score"] == 85.0
        assert result["agent.id"] == "research-bot"

    def test_incident_without_agent_id(self, event_logger):
        """Incident events work without agent_id."""
        result = event_logger.log_incident_detected(
            incident_id="inc-002",
            title="Global SLO breach",
            severity="p2",
        )

        assert "agent.id" not in result
        assert result["agent.sre.incident.severity"] == "p2"


# ========== Integration Tests ==========


class TestOtelIntegration:
    """End-to-end tests combining metrics + traces + events."""

    def test_full_slo_workflow(self, metrics_exporter, metric_reader, event_logger):
        """Full SLO lifecycle: create, record, evaluate, export, alert."""
        from agent_sre.slo.indicators import CostPerTask, TaskSuccessRate
        from agent_sre.slo.objectives import SLO, ErrorBudget

        # Create SLO
        slo = SLO(
            name="support-bot",
            indicators=[
                TaskSuccessRate(target=0.95, window="24h"),
                CostPerTask(target_usd=0.50, window="24h"),
            ],
            error_budget=ErrorBudget(total=0.05),
            labels={"team": "platform"},
        )

        # Record events
        for _ in range(9):
            slo.indicators[0].record_task(success=True)
            slo.indicators[1].record_cost(cost_usd=0.30)
            slo.record_event(good=True)

        # One failure
        slo.indicators[0].record_task(success=False)
        slo.record_event(good=False)

        # Export to OTEL
        metrics_exporter.record_slo_from_object(slo)

        # Verify metrics exist
        data = metric_reader.get_metrics_data()
        metric_names = set()
        for resource_metrics in data.resource_metrics:
            for scope_metrics in resource_metrics.scope_metrics:
                for metric in scope_metrics.metrics:
                    metric_names.add(metric.name)

        assert METRIC_SLO_STATUS in metric_names
        assert METRIC_SLI_VALUE in metric_names
        assert METRIC_ERROR_BUDGET_REMAINING in metric_names

        # Log the status
        status = slo.evaluate().value
        event = event_logger.log_slo_status_change(
            slo_name=slo.name,
            old_status="unknown",
            new_status=status,
            error_budget_remaining=slo.error_budget.remaining,
        )
        assert event["agent.sre.slo.name"] == "support-bot"

    def test_trace_and_cost_workflow(self, metrics_exporter, metric_reader, event_logger):
        """Trace capture + cost recording + event logging together."""
        # Record cost
        metrics_exporter.record_cost("bot-1", 0.50, avg_per_task=0.50)
        metrics_exporter.record_cost("bot-1", 0.45, avg_per_task=0.475)

        # Log cost alert
        event = event_logger.log_cost_alert(
            agent_id="bot-1",
            severity="info",
            message="Task cost recorded",
            current_value=0.95,
            threshold=2.00,
        )

        assert event["agent.sre.cost.agent_id"] == "bot-1"

        # Verify metrics
        data = metric_reader.get_metrics_data()
        metric_names = set()
        for resource_metrics in data.resource_metrics:
            for scope_metrics in resource_metrics.scope_metrics:
                for metric in scope_metrics.metrics:
                    metric_names.add(metric.name)

        assert METRIC_COST_TOTAL in metric_names

    def test_imports_from_package(self):
        """Public API is importable from the otel package."""
        from agent_sre.integrations.otel import (
            EventLogger,
            MetricsExporter,
            TraceExporter,
        )

        assert MetricsExporter is not None
        assert TraceExporter is not None
        assert EventLogger is not None
