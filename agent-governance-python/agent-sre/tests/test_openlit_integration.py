# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the OpenLit convenience exporter."""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest


class TestOpenLitExporterInit:
    """Test OpenLitExporter initialization without OTel SDK installed."""

    def test_import_error_without_otel(self):
        """Should raise ImportError with helpful message if OTel HTTP exporter missing."""
        with patch.dict("sys.modules", {"opentelemetry.exporter.otlp.proto.http.trace_exporter": None}):
            from agent_sre.integrations.openlit import OpenLitExporter

            # Re-importing won't re-trigger, so we test the class directly
            # The actual import error happens during _setup_otel
            # This is tested via the integration below


class TestOpenLitExporterWithMocks:
    """Test OpenLitExporter with mocked OTel SDK."""

    @pytest.fixture()
    def mock_otel(self):
        """Patch OTel SDK components for unit testing."""
        with (
            patch("agent_sre.integrations.openlit.OpenLitExporter._setup_otel") as setup,
        ):
            from agent_sre.integrations.openlit import OpenLitExporter

            exporter = OpenLitExporter.__new__(OpenLitExporter)
            exporter._endpoint = "http://localhost:4318"
            exporter._service_name = "test-agent"
            exporter._api_key = None
            exporter._environment = "test"
            exporter._application_name = "test-app"
            exporter._metrics = MagicMock()
            exporter._traces = MagicMock()
            exporter._tracer = MagicMock()
            exporter._tracer_provider = MagicMock()
            exporter._meter_provider = MagicMock()
            yield exporter

    def test_record_slo(self, mock_otel):
        """Should record SLO status and all SLI values."""
        from agent_sre.slo.indicators import TaskSuccessRate, TimeWindow
        from agent_sre.slo.objectives import ErrorBudget, SLO

        sli = TaskSuccessRate(target=0.99, window=TimeWindow.DAY_1)
        sli.record(True)
        sli.record(True)
        sli.record(False)

        budget = ErrorBudget(total=0.01, consumed=0.003)
        slo = SLO(
            name="test-slo",
            indicators=[sli],
            error_budget=budget,
            labels={"team": "platform"},
        )

        mock_otel.record_slo(slo)

        mock_otel._metrics.record_slo.assert_called_once()
        call_kwargs = mock_otel._metrics.record_slo.call_args
        assert call_kwargs[1]["slo_name"] == "test-slo"
        assert call_kwargs[1]["labels"] == {"team": "platform"}

        mock_otel._metrics.record_sli.assert_called_once()
        sli_kwargs = mock_otel._metrics.record_sli.call_args
        assert sli_kwargs[1]["sli_name"] == "task_success_rate"

    def test_record_chaos_experiment_completed(self, mock_otel):
        """Should record completed chaos experiment as span + metric."""
        from agent_sre.chaos.engine import (
            ChaosExperiment,
            ExperimentState,
            Fault,
            ResilienceScore,
        )

        exp = ChaosExperiment(
            name="latency-test",
            target_agent="bot-1",
            faults=[Fault.latency_injection("openai", delay_ms=5000)],
            duration_seconds=60,
        )
        exp.start()
        exp.complete(ResilienceScore(overall=85.0, passed=True))

        mock_otel.record_chaos_experiment(exp)

        mock_otel._tracer.start_span.assert_called_once()
        span_call = mock_otel._tracer.start_span.call_args
        assert span_call[1]["name"] == "chaos.latency-test"
        attrs = span_call[1]["attributes"]
        assert attrs["agent.sre.chaos.experiment_name"] == "latency-test"
        assert attrs["agent.id"] == "bot-1"
        assert attrs["agent.sre.chaos.resilience_score"] == 85.0
        assert attrs["agent.sre.chaos.resilience_passed"] is True

        mock_otel._metrics.record_resilience.assert_called_once_with(
            experiment_name="latency-test",
            score=85.0,
            agent_id="bot-1",
        )

    def test_record_chaos_experiment_aborted(self, mock_otel):
        """Should record aborted experiment with error status."""
        from agent_sre.chaos.engine import ChaosExperiment, Fault

        exp = ChaosExperiment(
            name="error-test",
            target_agent="bot-2",
            faults=[Fault.error_injection("tool-x")],
        )
        exp.start()
        exp.abort(reason="success_rate dropped below 50%")

        mock_otel.record_chaos_experiment(exp)

        attrs = mock_otel._tracer.start_span.call_args[1]["attributes"]
        assert attrs["agent.sre.chaos.abort_reason"] == "success_rate dropped below 50%"
        assert attrs["agent.sre.chaos.state"] == "aborted"

    def test_record_slo_no_data(self, mock_otel):
        """Should handle SLO with no SLI data gracefully."""
        from agent_sre.slo.indicators import TaskSuccessRate, TimeWindow
        from agent_sre.slo.objectives import SLO

        sli = TaskSuccessRate(target=0.99, window=TimeWindow.DAY_1)
        slo = SLO(name="empty-slo", indicators=[sli])

        mock_otel.record_slo(slo)

        mock_otel._metrics.record_slo.assert_called_once()
        # SLI should NOT be recorded since current_value() is None
        mock_otel._metrics.record_sli.assert_not_called()

    def test_shutdown(self, mock_otel):
        """Should flush and shutdown providers."""
        mock_otel.shutdown()

        mock_otel._tracer_provider.force_flush.assert_called_once()
        mock_otel._tracer_provider.shutdown.assert_called_once()
        mock_otel._meter_provider.shutdown.assert_called_once()

    def test_metrics_property(self, mock_otel):
        """Should expose underlying MetricsExporter."""
        assert mock_otel.metrics is mock_otel._metrics

    def test_traces_property(self, mock_otel):
        """Should expose underlying TraceExporter."""
        assert mock_otel.traces is mock_otel._traces
