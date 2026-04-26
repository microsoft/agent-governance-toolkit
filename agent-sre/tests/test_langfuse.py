# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Langfuse integration — SLO scoring and cost observations.

Uses offline mode (no Langfuse connection required) to verify that
Agent SRE data is correctly prepared for Langfuse export.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from agent_sre.integrations.langfuse import LangfuseExporter
from agent_sre.slo.indicators import CostPerTask, HallucinationRate, TaskSuccessRate
from agent_sre.slo.objectives import SLO, ErrorBudget

# ========== Fixtures ==========


@pytest.fixture
def exporter():
    """Offline exporter for testing."""
    return LangfuseExporter(client=None)


@pytest.fixture
def mock_client():
    """Mock Langfuse client."""
    client = MagicMock()
    client.score = MagicMock()
    client.span = MagicMock()
    return client


@pytest.fixture
def live_exporter(mock_client):
    """Exporter with mock Langfuse client."""
    return LangfuseExporter(client=mock_client)


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
    # Record some data
    for _ in range(9):
        slo.indicators[0].record_task(success=True)
        slo.indicators[1].record_cost(cost_usd=0.30)
        slo.record_event(good=True)
    slo.indicators[0].record_task(success=False)
    slo.record_event(good=False)
    return slo


# ========== Offline Mode Tests ==========


class TestLangfuseExporterOffline:
    """Test offline (no client) mode."""

    def test_is_offline(self, exporter):
        """Exporter without client is offline."""
        assert exporter.is_offline is True

    def test_score_slo_creates_scores(self, exporter, sample_slo):
        """Scoring an SLO produces multiple score objects."""
        scores = exporter.score_slo(trace_id="trace-001", slo=sample_slo)

        # Should have: status + budget_remaining + burn_rate + 2 SLIs = 5 scores
        assert len(scores) == 5

    def test_score_slo_status(self, exporter, sample_slo):
        """SLO status is correctly encoded as score."""
        scores = exporter.score_slo(trace_id="trace-001", slo=sample_slo)

        status_score = next(s for s in scores if "status" in s.name)
        assert status_score.name == "slo.support-bot.status"
        # With 1 failure in 10, budget is consumed but not exhausted
        assert status_score.value in (0.0, 1.0, 2.0, 3.0)

    def test_score_slo_budget_remaining(self, exporter, sample_slo):
        """Error budget remaining is recorded."""
        scores = exporter.score_slo(trace_id="trace-001", slo=sample_slo)

        budget_score = next(s for s in scores if "budget_remaining" in s.name)
        assert budget_score.name == "slo.support-bot.budget_remaining"
        assert 0.0 <= budget_score.value <= 1.0

    def test_score_slo_burn_rate(self, exporter, sample_slo):
        """Burn rate is recorded."""
        scores = exporter.score_slo(trace_id="trace-001", slo=sample_slo)

        burn_score = next(s for s in scores if "burn_rate" in s.name)
        assert burn_score.name == "slo.support-bot.burn_rate"
        assert burn_score.value >= 0.0

    def test_score_slo_sli_values(self, exporter, sample_slo):
        """Individual SLI values are scored."""
        scores = exporter.score_slo(trace_id="trace-001", slo=sample_slo)

        sli_scores = [s for s in scores if s.name.startswith("sli.")]
        assert len(sli_scores) == 2

        names = {s.name for s in sli_scores}
        assert "sli.task_success_rate" in names
        assert "sli.cost_per_task" in names

    def test_score_sli_task_success_rate(self, exporter, sample_slo):
        """Task success rate SLI has a value close to expected."""
        scores = exporter.score_slo(trace_id="trace-001", slo=sample_slo)

        tsr = next(s for s in scores if s.name == "sli.task_success_rate")
        # Value depends on windowed average of recorded measurements
        # 9 success + 1 failure, but current_value() averages all recorded SLIValues
        assert 0.85 <= tsr.value <= 1.0

    def test_score_sli_cost_per_task(self, exporter, sample_slo):
        """Cost per task SLI has correct value."""
        scores = exporter.score_slo(trace_id="trace-001", slo=sample_slo)

        cpt = next(s for s in scores if s.name == "sli.cost_per_task")
        # 9 * 0.30 = 2.70 / 9 = 0.30
        assert abs(cpt.value - 0.30) < 0.01

    def test_score_stored_in_memory(self, exporter, sample_slo):
        """Scores are accessible via .scores property."""
        exporter.score_slo(trace_id="trace-001", slo=sample_slo)

        assert len(exporter.scores) == 5
        assert all(s.trace_id == "trace-001" for s in exporter.scores)

    def test_record_cost(self, exporter):
        """Cost observations are stored offline."""
        obs = exporter.record_cost(
            trace_id="trace-001",
            agent_id="bot-1",
            cost_usd=0.35,
            task_id="task-42",
        )

        assert obs.agent_id == "bot-1"
        assert obs.cost_usd == 0.35
        assert obs.task_id == "task-42"
        assert len(exporter.observations) == 1

    def test_record_cost_with_metadata(self, exporter):
        """Cost observations can carry metadata."""
        obs = exporter.record_cost(
            trace_id="trace-001",
            agent_id="bot-1",
            cost_usd=0.50,
            metadata={"model": "gpt-4o", "tokens": 1500},
        )

        assert obs.metadata["model"] == "gpt-4o"
        assert obs.metadata["tokens"] == 1500

    def test_score_trace_arbitrary(self, exporter):
        """Arbitrary scores can be attached to traces."""
        score = exporter.score_trace(
            trace_id="trace-001",
            name="custom.quality",
            value=0.92,
            comment="Agent response quality score",
        )

        assert score.name == "custom.quality"
        assert score.value == 0.92
        assert len(exporter.scores) == 1

    def test_clear(self, exporter, sample_slo):
        """Clear removes all stored data."""
        exporter.score_slo(trace_id="trace-001", slo=sample_slo)
        exporter.record_cost(trace_id="trace-001", agent_id="bot-1", cost_usd=0.35)

        assert len(exporter.scores) > 0
        assert len(exporter.observations) > 0

        exporter.clear()
        assert len(exporter.scores) == 0
        assert len(exporter.observations) == 0

    def test_slo_no_data_produces_fewer_scores(self, exporter):
        """SLO with no recorded data produces SLO-level scores but no SLI scores."""
        slo = SLO(
            name="empty-slo",
            indicators=[TaskSuccessRate(target=0.95)],
            error_budget=ErrorBudget(total=0.05),
        )

        scores = exporter.score_slo(trace_id="trace-empty", slo=slo)

        # status + budget + burn_rate, but no SLI (current_value is None)
        sli_scores = [s for s in scores if s.name.startswith("sli.")]
        assert len(sli_scores) == 0

    def test_multiple_traces(self, exporter, sample_slo):
        """Different trace IDs produce separate score sets."""
        exporter.score_slo(trace_id="trace-001", slo=sample_slo)
        exporter.score_slo(trace_id="trace-002", slo=sample_slo)

        assert len(exporter.scores) == 10  # 5 per trace


# ========== Live Mode Tests ==========


class TestLangfuseExporterLive:
    """Test live mode with mock Langfuse client."""

    def test_is_not_offline(self, live_exporter):
        """Exporter with client is live."""
        assert live_exporter.is_offline is False

    def test_score_calls_client(self, live_exporter, mock_client, sample_slo):
        """Scoring calls the Langfuse client.score() method."""
        live_exporter.score_slo(trace_id="trace-001", slo=sample_slo)

        assert mock_client.score.call_count == 5

    def test_score_client_args(self, live_exporter, mock_client):
        """Client.score receives correct arguments."""
        live_exporter.score_trace(
            trace_id="trace-001",
            name="my-score",
            value=0.95,
            comment="test",
        )

        mock_client.score.assert_called_once_with(
            trace_id="trace-001",
            name="my-score",
            value=0.95,
            comment="test",
        )

    def test_cost_calls_client_span(self, live_exporter, mock_client):
        """Cost recording calls client.span()."""
        live_exporter.record_cost(
            trace_id="trace-001",
            agent_id="bot-1",
            cost_usd=0.35,
            task_id="task-42",
        )

        mock_client.span.assert_called_once()
        call_kwargs = mock_client.span.call_args
        assert call_kwargs.kwargs["trace_id"] == "trace-001"
        assert call_kwargs.kwargs["name"] == "cost.bot-1"
        assert call_kwargs.kwargs["metadata"]["cost_usd"] == 0.35

    def test_client_error_does_not_raise(self, live_exporter, mock_client):
        """Client errors are caught and logged, not raised."""
        mock_client.score.side_effect = Exception("Connection failed")

        # Should not raise
        score = live_exporter.score_trace(
            trace_id="trace-001",
            name="test",
            value=0.5,
        )

        # Score still recorded locally
        assert score.value == 0.5
        assert len(live_exporter.scores) == 1

    def test_cost_client_error_does_not_raise(self, live_exporter, mock_client):
        """Cost client errors are caught and logged."""
        mock_client.span.side_effect = Exception("Connection failed")

        obs = live_exporter.record_cost(
            trace_id="trace-001",
            agent_id="bot-1",
            cost_usd=0.35,
        )

        assert obs.cost_usd == 0.35
        assert len(live_exporter.observations) == 1


# ========== Integration Tests ==========


class TestLangfuseIntegration:
    """End-to-end tests combining Langfuse with other Agent SRE components."""

    def test_slo_lifecycle_with_langfuse(self, exporter):
        """Full SLO lifecycle: create, record, evaluate, score to Langfuse."""
        slo = SLO(
            name="research-bot",
            indicators=[
                TaskSuccessRate(target=0.99, window="24h"),
                CostPerTask(target_usd=1.00, window="24h"),
                HallucinationRate(target=0.02, window="24h"),
            ],
            error_budget=ErrorBudget(total=0.01),
        )

        # Simulate 100 tasks
        for i in range(100):
            success = i % 50 != 0  # 2% failure rate
            slo.indicators[0].record_task(success=success)
            slo.indicators[1].record_cost(cost_usd=0.45)
            slo.indicators[2].record_evaluation(hallucinated=(i % 100 == 0))
            slo.record_event(good=success)

            # Score every 10 tasks
            if (i + 1) % 10 == 0:
                exporter.record_cost(
                    trace_id=f"trace-{i:03d}",
                    agent_id="research-bot",
                    cost_usd=0.45 * 10,
                )

        # Final scoring
        scores = exporter.score_slo(trace_id="trace-final", slo=slo)

        # Should have status + budget + burn_rate + 3 SLIs = 6 scores
        assert len(scores) == 6

        # Check SLI values are in expected ranges
        tsr = next(s for s in scores if s.name == "sli.task_success_rate")
        assert 0.90 < tsr.value < 1.0  # ~96-98% (windowed average)

        cpt = next(s for s in scores if s.name == "sli.cost_per_task")
        assert abs(cpt.value - 0.45) < 0.01

        # Check cost observations
        assert len(exporter.observations) == 10

    def test_imports_from_package(self):
        """Public API is importable."""
        from agent_sre.integrations.langfuse import LangfuseExporter

        exporter = LangfuseExporter()
        assert exporter.is_offline is True
