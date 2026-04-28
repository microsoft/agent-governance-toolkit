# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Braintrust integration — evaluation scoring and experiments.

Uses offline mode (no Braintrust connection required) to verify that
Agent SRE data is correctly prepared for Braintrust export.
"""

from __future__ import annotations

import pytest

from agent_sre.integrations.braintrust import BraintrustExporter
from agent_sre.slo.indicators import CostPerTask, TaskSuccessRate
from agent_sre.slo.objectives import SLO, ErrorBudget

# ========== Fixtures ==========


@pytest.fixture
def exporter():
    """Offline exporter for testing."""
    return BraintrustExporter(client=None)


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


class TestBraintrustExporter:
    def test_offline_mode(self, exporter):
        """Exporter without client is offline."""
        assert exporter.is_offline is True

    def test_log_eval(self, exporter):
        """Log an evaluation and verify it's stored."""
        record = exporter.log_eval(
            trace_id="trace-001",
            agent_id="bot-1",
            slo_name="latency",
            scores={"accuracy": 0.95, "latency": 0.8},
            input_data={"query": "hello"},
            output_data={"response": "hi"},
            expected={"response": "hello there"},
        )

        assert record.trace_id == "trace-001"
        assert record.agent_id == "bot-1"
        assert record.slo_name == "latency"
        assert record.scores["accuracy"] == 0.95
        assert record.input_data == {"query": "hello"}
        assert record.output_data == {"response": "hi"}
        assert record.expected == {"response": "hello there"}
        assert len(exporter.evaluations) == 1

    def test_log_experiment(self, exporter):
        """Log an experiment with multiple entries."""
        entries = [
            {"input": "q1", "output": "a1", "scores": {"accuracy": 0.9}},
            {"input": "q2", "output": "a2", "scores": {"accuracy": 0.85}},
        ]
        record = exporter.log_experiment("exp-001", entries)

        assert record.name == "exp-001"
        assert len(record.entries) == 2
        assert len(exporter.experiments) == 1

    def test_export_slo(self, exporter, sample_slo):
        """Export SLO evaluation as Braintrust scores."""
        records = exporter.export_slo(trace_id="trace-001", slo=sample_slo)

        assert len(records) == 1
        record = records[0]
        assert record.slo_name == "support-bot"
        assert "status" in record.scores
        assert "budget_remaining" in record.scores
        assert "burn_rate" in record.scores
        assert "sli.task_success_rate" in record.scores
        assert "sli.cost_per_task" in record.scores

    def test_record_cost(self, exporter):
        """Record cost data as evaluation."""
        record = exporter.record_cost(
            trace_id="trace-001",
            agent_id="bot-1",
            cost_usd=0.35,
            metadata={"model": "gpt-4o"},
        )

        assert record.slo_name == "cost"
        assert record.scores["cost_usd"] == 0.35
        assert record.agent_id == "bot-1"
        assert record.input_data == {"model": "gpt-4o"}
        assert len(exporter.evaluations) == 1

    def test_clear(self, exporter, sample_slo):
        """Clear removes all stored data."""
        exporter.log_eval(
            trace_id="t1", agent_id="a1", slo_name="s1", scores={"x": 1.0},
        )
        exporter.log_experiment("exp", [{"scores": {"x": 1.0}}])

        assert len(exporter.evaluations) > 0
        assert len(exporter.experiments) > 0

        exporter.clear()
        assert len(exporter.evaluations) == 0
        assert len(exporter.experiments) == 0

    def test_stats(self, exporter):
        """Get stats returns correct counts."""
        exporter.log_eval(
            trace_id="t1", agent_id="a1", slo_name="s1", scores={"x": 1.0},
        )
        exporter.log_eval(
            trace_id="t2", agent_id="a2", slo_name="s2", scores={"y": 0.5},
        )
        exporter.log_experiment("exp", [{"scores": {"x": 1.0}}])

        stats = exporter.get_stats()
        assert stats["total_evaluations"] == 2
        assert stats["total_experiments"] == 1
        assert stats["project"] == "agent-sre"

    def test_imports_from_package(self):
        """Public API is importable."""
        from agent_sre.integrations.braintrust import BraintrustExporter

        exporter = BraintrustExporter()
        assert exporter.is_offline is True
