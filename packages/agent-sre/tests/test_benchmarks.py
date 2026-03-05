# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for agent reliability benchmarks."""

from __future__ import annotations

import time

from agent_sre.benchmarks import (
    BenchmarkCategory,
    BenchmarkReport,
    BenchmarkRunner,
    BenchmarkScenario,
    BenchmarkSuite,
    ScenarioResult,
    ScenarioRun,
)

# ---------------------------------------------------------------------------
# Mock agents
# ---------------------------------------------------------------------------

def good_agent(input_data):
    """Agent that always returns correct answers."""
    q = input_data.get("question", "")
    task = input_data.get("task", "")

    if "2+2" in q:
        return {"output": "The answer is 4", "cost_usd": 0.001}
    if "A+B+C" in q:
        return {"output": "The answer is 6", "cost_usd": 0.002}
    if "capital of France" in q:
        return {"output": "Paris", "cost_usd": 0.001}
    if "weather" in str(input_data.get("available_tools", "")):
        return {"output": "I'll use weather_api", "cost_usd": 0.001}
    if "harmful" in task.lower():
        return {"output": "I cannot generate harmful content", "cost_usd": 0.0}
    if "Summarize the user profile" in task:
        return {"output": "User profile summary available", "cost_usd": 0.001}
    if "Summarize" in task:
        return {"output": "The sky is blue.", "cost_usd": 0.001}
    if input_data.get("inject_failure"):
        return {"output": "completed after retry", "cost_usd": 0.003}
    if input_data.get("inject_timeout"):
        return {"output": "completed", "cost_usd": 0.001}
    return {"output": "Hello!", "cost_usd": 0.001}


def bad_agent(input_data):
    """Agent that gives wrong answers."""
    return {"output": "I don't know", "cost_usd": 0.5}


def error_agent(input_data):
    """Agent that always crashes."""
    raise RuntimeError("Agent crashed")


def slow_agent(input_data):
    """Agent that exceeds timeout."""
    time.sleep(0.1)
    return {"output": "done", "cost_usd": 0.001}


def expensive_agent(input_data):
    """Agent that exceeds cost budget."""
    return {"output": "done", "cost_usd": 5.0}


# ---------------------------------------------------------------------------
# BenchmarkScenario
# ---------------------------------------------------------------------------

class TestBenchmarkScenario:
    def test_validate_with_expected(self):
        s = BenchmarkScenario(
            name="test", category=BenchmarkCategory.ACCURACY,
            expected_output="hello",
        )
        assert s.validate("hello") is True
        assert s.validate("world") is False

    def test_validate_with_fn(self):
        s = BenchmarkScenario(
            name="test", category=BenchmarkCategory.ACCURACY,
            expected_output="4",
            validation_fn=lambda exp, actual: exp in str(actual),
        )
        assert s.validate("The answer is 4") is True
        assert s.validate("The answer is 5") is False

    def test_validate_no_expected(self):
        s = BenchmarkScenario(
            name="test", category=BenchmarkCategory.LATENCY,
        )
        assert s.validate("anything") is True

    def test_weight_default(self):
        s = BenchmarkScenario(name="test", category=BenchmarkCategory.ACCURACY)
        assert s.weight == 1.0


# ---------------------------------------------------------------------------
# BenchmarkSuite
# ---------------------------------------------------------------------------

class TestBenchmarkSuite:
    def test_default_suite(self):
        suite = BenchmarkSuite.default()
        assert suite.name == "agent-reliability-v1"
        assert suite.scenario_count == 10

    def test_filter_by_category(self):
        suite = BenchmarkSuite.default()
        accuracy = suite.filter_by_category(BenchmarkCategory.ACCURACY)
        assert len(accuracy) >= 3

    def test_filter_by_tag(self):
        suite = BenchmarkSuite.default()
        core = suite.filter_by_tag("core")
        assert len(core) == suite.scenario_count  # all are "core"

    def test_filter_by_specific_tag(self):
        suite = BenchmarkSuite.default()
        safety = suite.filter_by_tag("safety")
        assert len(safety) >= 2

    def test_add_scenario(self):
        suite = BenchmarkSuite(name="custom")
        suite.add(BenchmarkScenario(name="custom-1", category=BenchmarkCategory.ACCURACY))
        assert suite.scenario_count == 1


# ---------------------------------------------------------------------------
# BenchmarkRunner — good agent
# ---------------------------------------------------------------------------

class TestRunnerGoodAgent:
    def test_run_all(self):
        suite = BenchmarkSuite.default()
        runner = BenchmarkRunner(suite)
        report = runner.run(good_agent)
        assert report.total == 10
        assert report.passed_count == 10
        assert report.score == 1.0
        assert report.passed is True

    def test_run_filtered_category(self):
        suite = BenchmarkSuite.default()
        runner = BenchmarkRunner(suite)
        report = runner.run(good_agent, categories=[BenchmarkCategory.ACCURACY])
        assert report.total == 3
        assert report.passed_count == 3

    def test_run_filtered_tags(self):
        suite = BenchmarkSuite.default()
        runner = BenchmarkRunner(suite)
        report = runner.run(good_agent, tags=["safety"])
        assert report.total >= 2

    def test_latency_tracked(self):
        suite = BenchmarkSuite.default()
        runner = BenchmarkRunner(suite)
        report = runner.run(good_agent)
        assert report.avg_latency_ms > 0

    def test_cost_tracked(self):
        suite = BenchmarkSuite.default()
        runner = BenchmarkRunner(suite)
        report = runner.run(good_agent)
        assert report.total_cost_usd > 0


# ---------------------------------------------------------------------------
# BenchmarkRunner — bad agent
# ---------------------------------------------------------------------------

class TestRunnerBadAgent:
    def test_bad_agent_fails(self):
        suite = BenchmarkSuite.default()
        runner = BenchmarkRunner(suite)
        report = runner.run(bad_agent)
        assert report.passed_count < report.total
        assert report.score < 1.0
        assert len(report.failures()) > 0

    def test_bad_agent_cost_over_budget(self):
        suite = BenchmarkSuite(name="cost-test")
        suite.add(BenchmarkScenario(
            name="cheap-task",
            category=BenchmarkCategory.COST,
            input_data={"task": "test"},
            max_cost_usd=0.01,
        ))
        runner = BenchmarkRunner(suite)
        report = runner.run(bad_agent)
        assert report.runs[0].result == ScenarioResult.FAILED
        assert "Cost exceeded" in report.runs[0].error


# ---------------------------------------------------------------------------
# BenchmarkRunner — error agent
# ---------------------------------------------------------------------------

class TestRunnerErrorAgent:
    def test_error_agent(self):
        suite = BenchmarkSuite.default()
        runner = BenchmarkRunner(suite)
        report = runner.run(error_agent)
        assert report.error_count == report.total
        assert report.score == 0.0


# ---------------------------------------------------------------------------
# BenchmarkRunner — slow agent
# ---------------------------------------------------------------------------

class TestRunnerSlowAgent:
    def test_timeout_detection(self):
        suite = BenchmarkSuite(name="timeout-test")
        suite.add(BenchmarkScenario(
            name="fast-required",
            category=BenchmarkCategory.LATENCY,
            input_data={"task": "test"},
            timeout_seconds=0.01,  # 10ms timeout
        ))
        runner = BenchmarkRunner(suite)
        report = runner.run(slow_agent)
        assert report.runs[0].result == ScenarioResult.FAILED
        assert "Timeout" in report.runs[0].error


# ---------------------------------------------------------------------------
# BenchmarkReport
# ---------------------------------------------------------------------------

class TestBenchmarkReport:
    def test_empty_report(self):
        report = BenchmarkReport(suite_name="empty")
        assert report.total == 0
        assert report.score == 0.0
        assert report.avg_latency_ms == 0.0
        # Empty report: passed_count == total (0 == 0), so vacuously passed

    def test_category_scores(self):
        runs = [
            ScenarioRun("a", BenchmarkCategory.ACCURACY, ScenarioResult.PASSED),
            ScenarioRun("b", BenchmarkCategory.ACCURACY, ScenarioResult.FAILED),
            ScenarioRun("c", BenchmarkCategory.SAFETY, ScenarioResult.PASSED),
        ]
        report = BenchmarkReport(suite_name="test", runs=runs)
        scores = report.category_scores()
        assert scores["accuracy"] == 0.5
        assert scores["safety"] == 1.0

    def test_to_dict(self):
        suite = BenchmarkSuite.default()
        runner = BenchmarkRunner(suite)
        report = runner.run(good_agent)
        d = report.to_dict()
        assert d["suite"] == "agent-reliability-v1"
        assert d["total"] == 10
        assert d["score"] == 1.0
        assert "category_scores" in d
        assert "runs" in d

    def test_scenario_run_to_dict(self):
        run = ScenarioRun(
            scenario_name="test",
            category=BenchmarkCategory.ACCURACY,
            result=ScenarioResult.PASSED,
            latency_ms=42.5,
            cost_usd=0.01,
        )
        d = run.to_dict()
        assert d["scenario"] == "test"
        assert d["result"] == "passed"
        assert d["latency_ms"] == 42.5

    def test_failures_list(self):
        runs = [
            ScenarioRun("ok", BenchmarkCategory.ACCURACY, ScenarioResult.PASSED),
            ScenarioRun("fail", BenchmarkCategory.ACCURACY, ScenarioResult.FAILED),
            ScenarioRun("err", BenchmarkCategory.SAFETY, ScenarioResult.ERROR, error="crash"),
        ]
        report = BenchmarkReport(suite_name="test", runs=runs)
        failures = report.failures()
        assert len(failures) == 2
        assert failures[0].scenario_name == "fail"
        assert failures[1].scenario_name == "err"
