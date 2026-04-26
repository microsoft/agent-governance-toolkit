# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Datadog integration — metrics and events export.

Uses offline mode (no Datadog connection required) to verify that
metrics and events are correctly prepared for Datadog export.
"""

from __future__ import annotations

import pytest

from agent_sre.integrations.datadog import DatadogExporter
from agent_sre.slo.indicators import CostPerTask, TaskSuccessRate
from agent_sre.slo.objectives import SLO, ErrorBudget

# ========== Fixtures ==========


@pytest.fixture
def exporter():
    """Offline exporter for testing."""
    return DatadogExporter()


@pytest.fixture
def sample_slo():
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


# ========== Tests ==========


class TestDatadogExporter:
    def test_offline_mode(self, exporter):
        """Exporter without API key is offline."""
        assert exporter.is_offline is True

    def test_submit_metric(self, exporter):
        """Submit a metric and verify it's stored."""
        metric = exporter.submit_metric(
            "agent.latency", 0.45,
            tags=["agent:bot-1", "env:prod"],
            metric_type="gauge",
        )

        assert metric.name == "agent.latency"
        assert metric.value == 0.45
        assert "agent:bot-1" in metric.tags
        assert metric.metric_type == "gauge"
        assert len(exporter.metrics) == 1

    def test_submit_event(self, exporter):
        """Submit an event and verify it's stored."""
        event = exporter.submit_event(
            title="SLO Breach",
            text="Budget exhausted for support-bot",
            alert_type="error",
            tags=["slo:support-bot"],
        )

        assert event.title == "SLO Breach"
        assert event.text == "Budget exhausted for support-bot"
        assert event.alert_type == "error"
        assert "slo:support-bot" in event.tags
        assert len(exporter.events) == 1

    def test_export_slo(self, exporter, sample_slo):
        """Export SLO evaluation as Datadog metrics."""
        metrics = exporter.export_slo(slo=sample_slo, agent_id="bot-1")

        assert len(metrics) == 3
        names = [m.name for m in metrics]
        assert "agent_sre.slo.status" in names
        assert "agent_sre.slo.budget_remaining" in names
        assert "agent_sre.slo.burn_rate" in names

        # Check tags
        for m in metrics:
            assert any("slo:support-bot" in t for t in m.tags)
            assert any("agent:bot-1" in t for t in m.tags)

    def test_export_cost(self, exporter):
        """Export cost as Datadog metric."""
        metric = exporter.export_cost(
            agent_id="bot-1",
            cost_usd=0.42,
            task_id="task-99",
            tags=["env:prod"],
        )

        assert metric.name == "agent_sre.cost.usd"
        assert metric.value == 0.42
        assert "agent:bot-1" in metric.tags
        assert "task:task-99" in metric.tags
        assert "env:prod" in metric.tags

    def test_tags(self, exporter):
        """Verify tag formatting."""
        metric = exporter.submit_metric(
            "test.metric", 1.0,
            tags=["env:staging", "region:us-east-1"],
        )
        assert metric.tags == ["env:staging", "region:us-east-1"]

    def test_clear(self, exporter):
        """Clear removes all stored data."""
        exporter.submit_metric("m1", 1.0)
        exporter.submit_event("e1", "text")

        assert len(exporter.metrics) > 0
        assert len(exporter.events) > 0

        exporter.clear()
        assert len(exporter.metrics) == 0
        assert len(exporter.events) == 0

    def test_stats(self, exporter):
        """Get stats returns correct counts."""
        exporter.submit_metric("m1", 1.0)
        exporter.submit_metric("m2", 2.0)
        exporter.submit_event("e1", "text")

        stats = exporter.get_stats()
        assert stats["total_metrics"] == 2
        assert stats["total_events"] == 1
        assert stats["site"] == "datadoghq.com"

    def test_imports_from_package(self):
        """Public API is importable."""
        from agent_sre.integrations.datadog import DatadogExporter

        exporter = DatadogExporter()
        assert exporter.is_offline is True
