# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for LangSmith integration — run-based tracing and feedback.

Uses offline mode (no LangSmith connection required) to verify that
runs and feedback are correctly prepared for LangSmith export.
"""

from __future__ import annotations

import pytest

from agent_sre.integrations.langsmith import LangSmithExporter
from agent_sre.slo.indicators import CostPerTask, TaskSuccessRate
from agent_sre.slo.objectives import SLO, ErrorBudget

# ========== Fixtures ==========


@pytest.fixture
def exporter():
    """Offline exporter for testing."""
    return LangSmithExporter()


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


class TestLangSmithExporter:
    def test_offline_mode(self, exporter):
        """Exporter without API key is offline."""
        assert exporter.is_offline is True

    def test_create_run(self, exporter):
        """Create a run and verify it's stored."""
        run = exporter.create_run(
            "my-task",
            run_type="llm",
            inputs={"query": "hello"},
            tags=["test"],
        )

        assert run.name == "my-task"
        assert run.run_type == "llm"
        assert run.inputs == {"query": "hello"}
        assert "test" in run.tags
        assert run.end_time is None
        assert run.error is None
        assert len(exporter.runs) == 1

    def test_end_run(self, exporter):
        """End a run with outputs."""
        run = exporter.create_run("task", inputs={"q": "hi"})
        updated = exporter.end_run(
            run.run_id,
            outputs={"response": "hello"},
        )

        assert updated is not None
        assert updated.outputs == {"response": "hello"}
        assert updated.end_time is not None

    def test_end_run_not_found(self, exporter):
        """End a non-existent run returns None."""
        result = exporter.end_run("nonexistent-id")
        assert result is None

    def test_end_run_with_error(self, exporter):
        """End a run with an error."""
        run = exporter.create_run("failing-task")
        updated = exporter.end_run(run.run_id, error="Something broke")

        assert updated is not None
        assert updated.error == "Something broke"
        assert updated.end_time is not None

    def test_add_feedback(self, exporter):
        """Add feedback to a run."""
        run = exporter.create_run("task")
        fb = exporter.add_feedback(
            run.run_id,
            key="correctness",
            score=0.95,
            comment="Almost perfect",
        )

        assert fb.run_id == run.run_id
        assert fb.key == "correctness"
        assert fb.score == 0.95
        assert fb.comment == "Almost perfect"
        assert len(exporter.feedbacks) == 1

    def test_export_slo(self, exporter, sample_slo):
        """Export SLO evaluation as feedback."""
        feedbacks = exporter.export_slo(slo=sample_slo)

        # status + budget_remaining + burn_rate + 2 SLIs = 5
        assert len(feedbacks) == 5

        keys = [f.key for f in feedbacks]
        assert "slo.support-bot.status" in keys
        assert "slo.support-bot.budget_remaining" in keys
        assert "slo.support-bot.burn_rate" in keys
        assert "sli.task_success_rate" in keys
        assert "sli.cost_per_task" in keys

        # Should have created a run too
        assert len(exporter.runs) == 1

    def test_export_slo_with_run_id(self, exporter, sample_slo):
        """Export SLO with explicit run_id doesn't create new run."""
        run = exporter.create_run("existing-run")
        feedbacks = exporter.export_slo(slo=sample_slo, run_id=run.run_id)

        assert len(feedbacks) == 5
        assert all(f.run_id == run.run_id for f in feedbacks)
        assert len(exporter.runs) == 1  # No additional run created

    def test_parent_child_runs(self, exporter):
        """Create parent-child run relationships."""
        parent = exporter.create_run("parent-task", run_type="chain")
        child = exporter.create_run(
            "child-llm-call",
            run_type="llm",
            parent_run_id=parent.run_id,
        )

        assert child.parent_run_id == parent.run_id
        assert len(exporter.runs) == 2

    def test_clear(self, exporter):
        """Clear removes all stored data."""
        exporter.create_run("task")
        exporter.add_feedback("run-id", "key", 0.5)

        assert len(exporter.runs) > 0
        assert len(exporter.feedbacks) > 0

        exporter.clear()
        assert len(exporter.runs) == 0
        assert len(exporter.feedbacks) == 0

    def test_stats(self, exporter):
        """Get stats returns correct counts."""
        run = exporter.create_run("task-1")
        exporter.create_run("task-2")
        exporter.end_run(run.run_id, outputs={"done": True})
        exporter.add_feedback(run.run_id, "quality", 0.9)

        stats = exporter.get_stats()
        assert stats["total_runs"] == 2
        assert stats["total_feedbacks"] == 1
        assert stats["completed_runs"] == 1
        assert stats["error_runs"] == 0
        assert stats["project"] == "agent-sre"

    def test_imports_from_package(self):
        """Public API is importable."""
        from agent_sre.integrations.langsmith import LangSmithExporter

        exporter = LangSmithExporter()
        assert exporter.is_offline is True
