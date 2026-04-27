# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Sentry integration.

Verifies offline and live-style behavior using a mock client.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from agent_sre.integrations.sentry import SentryExporter
from agent_sre.slo.indicators import CostPerTask, TaskSuccessRate
from agent_sre.slo.objectives import ErrorBudget, SLO


@pytest.fixture
def exporter() -> SentryExporter:
    """Offline exporter for testing."""
    return SentryExporter()


@pytest.fixture
def mock_client() -> MagicMock:
    """Mock Sentry-compatible client."""
    client = MagicMock()
    client.capture_message = MagicMock()
    client.capture_exception = MagicMock()
    return client


@pytest.fixture
def live_exporter(mock_client: MagicMock) -> SentryExporter:
    """Exporter wired to a mock Sentry client."""
    return SentryExporter(client=mock_client, environment="test", release="1.0.0")


@pytest.fixture
def sample_slo() -> SLO:
    """A sample SLO with data recorded."""
    slo = SLO(
        name="support-bot",
        indicators=[
            TaskSuccessRate(target=0.95, window="24h"),
            CostPerTask(target_usd=0.50, window="24h"),
        ],
        error_budget=ErrorBudget(total=0.05),
    )
    for _ in range(9):
        slo.indicators[0].record_task(success=True)
        slo.indicators[1].record_cost(cost_usd=0.30)
        slo.record_event(good=True)
    slo.indicators[0].record_task(success=False)
    slo.record_event(good=False)
    return slo


class TestSentryExporterOffline:
    def test_offline_mode(self, exporter: SentryExporter) -> None:
        assert exporter.is_offline is True

    def test_capture_incident(self, exporter: SentryExporter) -> None:
        event = exporter.capture_incident(
            title="Error budget exhausted",
            severity="error",
            tags={"agent_id": "bot-1"},
            context={"burn_rate": 9.1},
        )

        assert event.kind == "message"
        assert event.message == "Error budget exhausted"
        assert event.level == "error"
        assert event.tags["agent_id"] == "bot-1"
        assert event.context["burn_rate"] == 9.1
        assert len(exporter.events) == 1

    def test_capture_exception(self, exporter: SentryExporter) -> None:
        error = RuntimeError("tool timeout")
        event = exporter.capture_exception(
            error,
            tags={"agent_id": "bot-1"},
            context={"tool": "search"},
        )

        assert event.kind == "exception"
        assert event.message == "tool timeout"
        assert event.level == "error"
        assert event.tags["agent_id"] == "bot-1"
        assert event.context["tool"] == "search"
        assert len(exporter.events) == 1

    def test_capture_slo_breach(self, exporter: SentryExporter, sample_slo: SLO) -> None:
        event = exporter.capture_slo_breach(sample_slo, agent_id="bot-1")

        assert event.level == "error"
        assert "SLO breach detected: support-bot" in event.message
        assert event.tags["slo"] == "support-bot"
        assert event.tags["agent_id"] == "bot-1"
        assert "budget_remaining" in event.context
        assert "burn_rate" in event.context

    def test_stats_and_clear(self, exporter: SentryExporter) -> None:
        exporter.capture_incident("foo")
        exporter.capture_exception(ValueError("bar"))

        stats = exporter.get_stats()
        assert stats["total_events"] == 2
        assert stats["is_offline"] is True

        exporter.clear()
        assert len(exporter.events) == 0


class TestSentryExporterLive:
    def test_live_mode(self, live_exporter: SentryExporter) -> None:
        assert live_exporter.is_offline is False

    def test_capture_incident_calls_client(
        self,
        live_exporter: SentryExporter,
        mock_client: MagicMock,
    ) -> None:
        live_exporter.capture_incident(
            title="Canary rollback triggered",
            severity="warning",
            tags={"env": "prod"},
            context={"rollout": "support-bot-v4"},
        )

        mock_client.capture_message.assert_called_once_with(
            "Canary rollback triggered",
            level="warning",
            tags={"env": "prod"},
            context={"rollout": "support-bot-v4"},
        )

    def test_capture_exception_calls_client(
        self,
        live_exporter: SentryExporter,
        mock_client: MagicMock,
    ) -> None:
        error = RuntimeError("db timeout")
        live_exporter.capture_exception(error, tags={"agent_id": "bot-1"})

        mock_client.capture_exception.assert_called_once_with(
            error,
            tags={"agent_id": "bot-1"},
            context={},
        )

    def test_client_errors_are_swallowed(
        self,
        live_exporter: SentryExporter,
        mock_client: MagicMock,
    ) -> None:
        mock_client.capture_message.side_effect = Exception("connection error")
        mock_client.capture_exception.side_effect = Exception("connection error")

        live_exporter.capture_incident("incident")
        live_exporter.capture_exception(RuntimeError("boom"))

        # Events are still recorded locally
        assert len(live_exporter.events) == 2


class TestSentryIntegration:
    def test_imports_from_package(self) -> None:
        from agent_sre.integrations.sentry import SentryExporter

        exporter = SentryExporter()
        assert exporter.is_offline is True
