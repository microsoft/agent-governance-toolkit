# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for golden-trace regression testing."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from agent_sre.replay.capture import Span, SpanKind, Trace
from agent_sre.replay.golden import (
    GoldenTraceSuite,
    TraceSource,
    load_golden_suites,
)
from agent_sre.replay.golden_manager import GoldenTraceManager

if TYPE_CHECKING:
    from pathlib import Path

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_trace(task_input: str = "hello", task_output: str = "world") -> Trace:
    """Create a minimal Trace for testing."""
    trace = Trace(agent_id="test-agent", task_input=task_input)
    span = Span(kind=SpanKind.TOOL_CALL, name="tool1", input_data={"q": task_input})
    span.finish(output={"a": task_output})
    trace.add_span(span)
    trace.finish(output=task_output, success=True)
    return trace


def _echo_agent(trace_dict: dict[str, Any]) -> str:
    """Agent function that returns the task_output stored in the trace."""
    return trace_dict.get("task_output", "")


def _bad_agent(_trace_dict: dict[str, Any]) -> str:
    """Agent function that always returns wrong output."""
    return "WRONG"


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestMarkGolden:
    def test_mark_trace_as_golden(self) -> None:
        mgr = GoldenTraceManager()
        trace = _make_trace()
        golden = mgr.mark_golden(trace, name="basic", expected_output="world")

        assert golden.name == "basic"
        assert golden.expected_output == "world"
        assert golden.tolerance == 0.0
        assert golden.source == TraceSource.PRODUCTION
        assert golden.trace["task_input"] == "hello"
        assert golden.id  # non-empty

    def test_mark_golden_with_labels(self) -> None:
        mgr = GoldenTraceManager()
        trace = _make_trace()
        golden = mgr.mark_golden(
            trace, name="labeled", expected_output="world",
            labels=["smoke", "fast"], source=TraceSource.SYNTHETIC,
        )
        assert golden.labels == ["smoke", "fast"]
        assert golden.source == TraceSource.SYNTHETIC


class TestRunSuite:
    def test_passing_suite(self) -> None:
        mgr = GoldenTraceManager()
        traces = [
            mgr.mark_golden(_make_trace("a", "A"), name="t1", expected_output="A"),
            mgr.mark_golden(_make_trace("b", "B"), name="t2", expected_output="B"),
        ]
        suite = GoldenTraceSuite(name="pass-suite", traces=traces, pass_threshold=1.0)
        result = mgr.run_suite(suite, _echo_agent)

        assert result.total == 2
        assert result.passed == 2
        assert result.failed == 0
        assert result.pass_rate == 1.0
        assert result.ci_passed is True

    def test_failing_suite(self) -> None:
        mgr = GoldenTraceManager()
        traces = [
            mgr.mark_golden(_make_trace("a", "A"), name="t1", expected_output="A"),
            mgr.mark_golden(_make_trace("b", "B"), name="t2", expected_output="B"),
        ]
        suite = GoldenTraceSuite(name="fail-suite", traces=traces, pass_threshold=1.0)
        result = mgr.run_suite(suite, _bad_agent)

        assert result.total == 2
        assert result.passed == 0
        assert result.failed == 2
        assert result.ci_passed is False
        assert all(len(r.diffs) > 0 for r in result.results)


class TestToleranceFuzzyMatching:
    def test_exact_match_required(self) -> None:
        mgr = GoldenTraceManager()
        passed, diffs = mgr.compare_output("hello", "hello", tolerance=0.0)
        assert passed is True
        assert diffs == []

    def test_exact_mismatch(self) -> None:
        mgr = GoldenTraceManager()
        passed, diffs = mgr.compare_output("hello", "hellx", tolerance=0.0)
        assert passed is False
        assert len(diffs) > 0

    def test_fuzzy_pass(self) -> None:
        mgr = GoldenTraceManager()
        # "hello" vs "hallo" — 80% similar; tolerance=0.3 → threshold 0.7
        passed, _ = mgr.compare_output("hello", "hallo", tolerance=0.3)
        assert passed is True

    def test_fuzzy_fail(self) -> None:
        mgr = GoldenTraceManager()
        # "hello" vs "xxxxx" — ~0% similar; tolerance=0.1 → threshold 0.9
        passed, diffs = mgr.compare_output("hello", "xxxxx", tolerance=0.1)
        assert passed is False
        assert len(diffs) > 0


class TestCIPassThreshold:
    def test_threshold_met(self) -> None:
        mgr = GoldenTraceManager()
        # 2 pass, 1 fail → 66.7% pass rate; threshold 0.5 → CI passes
        gt_pass1 = mgr.mark_golden(_make_trace("a", "A"), "p1", expected_output="A")
        gt_pass2 = mgr.mark_golden(_make_trace("b", "B"), "p2", expected_output="B")
        gt_fail = mgr.mark_golden(_make_trace("c", "C"), "f1", expected_output="C")

        suite = GoldenTraceSuite(
            name="threshold", traces=[gt_pass1, gt_pass2, gt_fail], pass_threshold=0.5,
        )

        def mixed_agent(trace_dict: dict[str, Any]) -> str:
            out = trace_dict.get("task_output", "")
            return "WRONG" if out == "C" else out

        result = mgr.run_suite(suite, mixed_agent)
        assert result.ci_passed is True
        assert result.pass_rate >= 0.5

    def test_threshold_not_met(self) -> None:
        mgr = GoldenTraceManager()
        gt = mgr.mark_golden(_make_trace("a", "A"), "t1", expected_output="A")
        suite = GoldenTraceSuite(name="strict", traces=[gt], pass_threshold=1.0)
        result = mgr.run_suite(suite, _bad_agent)
        assert result.ci_passed is False


class TestCuration:
    def test_diverse_selection(self) -> None:
        mgr = GoldenTraceManager()
        pool = [
            mgr.mark_golden(_make_trace(), f"t{i}", expected_output="world", labels=labels)
            for i, labels in enumerate([
                ["smoke"],
                ["smoke"],
                ["regression"],
                ["regression"],
                ["perf"],
            ])
        ]
        selected = mgr.curate(pool, max_count=3, strategy="diverse")
        assert len(selected) == 3
        label_sets = {tuple(sorted(g.labels)) for g in selected}
        # All three distinct label groups should be represented
        assert label_sets == {("smoke",), ("regression",), ("perf",)}

    def test_curate_returns_all_when_under_limit(self) -> None:
        mgr = GoldenTraceManager()
        pool = [mgr.mark_golden(_make_trace(), f"t{i}", expected_output="world") for i in range(2)]
        selected = mgr.curate(pool, max_count=10)
        assert len(selected) == 2


class TestYAMLRoundtrip:
    def test_roundtrip(self, tmp_path: Path) -> None:
        mgr = GoldenTraceManager()
        gt = mgr.mark_golden(_make_trace(), name="rt", expected_output="world", labels=["ci"])
        suite = GoldenTraceSuite(name="yaml-suite", traces=[gt], pass_threshold=0.9)

        yaml_file = tmp_path / "suite.yaml"
        suite.to_yaml(yaml_file)

        loaded = GoldenTraceSuite.from_yaml(yaml_file)
        assert loaded.name == suite.name
        assert len(loaded.traces) == 1
        assert loaded.traces[0].name == "rt"
        assert loaded.traces[0].expected_output == "world"
        assert loaded.pass_threshold == 0.9

    def test_load_golden_suites(self, tmp_path: Path) -> None:
        mgr = GoldenTraceManager()
        for i in range(3):
            gt = mgr.mark_golden(_make_trace(), name=f"t{i}", expected_output="world")
            s = GoldenTraceSuite(name=f"suite-{i}", traces=[gt])
            s.to_yaml(tmp_path / f"suite_{i}.yaml")

        suites = load_golden_suites(tmp_path)
        assert len(suites) == 3
        assert {s.name for s in suites} == {"suite-0", "suite-1", "suite-2"}
