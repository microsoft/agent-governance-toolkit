# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the replay engine."""

import pytest

from agent_sre.replay.capture import Span, SpanKind, Trace
from agent_sre.replay.engine import DiffType, ReplayEngine, ReplayResult, TraceDiff


class TestTraceDiff:
    def test_to_dict(self) -> None:
        diff = TraceDiff(
            diff_type=DiffType.OUTPUT_MISMATCH,
            span_name="tool_call_1",
            original={"a": 1},
            replayed={"a": 2},
            description="Output changed",
        )
        d = diff.to_dict()
        assert d["type"] == "output_mismatch"
        assert d["span"] == "tool_call_1"


class TestReplayResult:
    def test_no_divergence(self) -> None:
        result = ReplayResult(
            original_trace_id="abc",
            replay_trace_id="replay-abc",
            success=True,
        )
        assert result.has_divergence is False
        assert result.divergence_point is None

    def test_with_divergence(self) -> None:
        result = ReplayResult(
            original_trace_id="abc",
            replay_trace_id="replay-abc",
            success=False,
            diffs=[
                TraceDiff(DiffType.OUTPUT_MISMATCH, "step3"),
                TraceDiff(DiffType.COST_CHANGE, "step5"),
            ],
        )
        assert result.has_divergence is True
        assert result.divergence_point == "step3"

    def test_to_dict(self) -> None:
        result = ReplayResult(
            original_trace_id="abc",
            replay_trace_id="def",
            success=True,
            steps_executed=5,
            steps_total=5,
        )
        d = result.to_dict()
        assert d["diff_count"] == 0
        assert d["steps_executed"] == 5


class TestReplayEngine:
    def _make_trace(self) -> Trace:
        """Create a sample trace with multiple spans."""
        trace = Trace(agent_id="test-agent", task_input="What is 2+2?")

        llm_span = Span(
            name="gpt4_inference",
            kind=SpanKind.LLM_INFERENCE,
            input_data={"prompt": "What is 2+2?"},
        )
        llm_span.finish(output={"response": "I'll use the calculator"}, cost_usd=0.01)
        trace.add_span(llm_span)

        tool_span = Span(
            name="calculator",
            kind=SpanKind.TOOL_CALL,
            input_data={"expression": "2+2"},
            parent_id=llm_span.span_id,
        )
        tool_span.finish(output={"result": 4}, cost_usd=0.0)
        trace.add_span(tool_span)

        final_span = Span(
            name="format_response",
            kind=SpanKind.LLM_INFERENCE,
            input_data={"context": "calculator returned 4"},
        )
        final_span.finish(output={"response": "2+2 = 4"}, cost_usd=0.005)
        trace.add_span(final_span)

        trace.finish(output="2+2 = 4", success=True)
        return trace

    def test_replay_clean_trace(self) -> None:
        engine = ReplayEngine()
        trace = self._make_trace()
        result = engine.replay(trace)
        assert result.steps_executed == 3
        assert result.steps_total == 3
        # Clean trace with no errors should have no divergences
        # (only error spans create divergences in basic replay)
        assert result.success is True

    def test_replay_with_error_span(self) -> None:
        trace = Trace(agent_id="test")
        span = Span(name="failing_tool", kind=SpanKind.TOOL_CALL)
        span.finish(error="timeout")
        trace.add_span(span)
        trace.finish(success=False)

        engine = ReplayEngine()
        result = engine.replay(trace)
        assert result.has_divergence is True
        assert any(d.diff_type == DiffType.STATUS_CHANGE for d in result.diffs)

    def test_replay_with_overrides(self) -> None:
        engine = ReplayEngine()
        trace = self._make_trace()
        result = engine.replay(trace, overrides={
            "calculator": {"result": 5},  # Wrong answer
        })
        assert result.has_divergence is True
        assert any(d.diff_type == DiffType.OUTPUT_MISMATCH for d in result.diffs)

    def test_what_if(self) -> None:
        engine = ReplayEngine()
        trace = self._make_trace()
        result = engine.what_if(trace, overrides={
            "calculator": {"result": 5},
        })
        assert result.has_divergence is True
        assert any(d.diff_type == DiffType.OUTPUT_MISMATCH for d in result.diffs)

    def test_steps(self) -> None:
        engine = ReplayEngine()
        trace = self._make_trace()
        steps = engine.steps(trace)
        assert len(steps) == 3
        assert steps[0].span.name == "gpt4_inference"
        assert steps[0].index == 0
        step_dict = steps[0].to_dict()
        assert "name" in step_dict
        assert "kind" in step_dict

    def test_diff_identical_traces(self) -> None:
        engine = ReplayEngine()
        trace = self._make_trace()
        diffs = engine.diff(trace, trace)
        assert len(diffs) == 0

    def test_diff_missing_span(self) -> None:
        engine = ReplayEngine()
        trace_a = Trace(agent_id="test")
        trace_a.add_span(Span(name="step1"))
        trace_a.add_span(Span(name="step2"))

        trace_b = Trace(agent_id="test")
        trace_b.add_span(Span(name="step1"))

        diffs = engine.diff(trace_a, trace_b)
        assert any(d.diff_type == DiffType.MISSING_SPAN for d in diffs)

    def test_diff_extra_span(self) -> None:
        engine = ReplayEngine()
        trace_a = Trace(agent_id="test")
        trace_a.add_span(Span(name="step1"))

        trace_b = Trace(agent_id="test")
        trace_b.add_span(Span(name="step1"))
        trace_b.add_span(Span(name="step2"))

        diffs = engine.diff(trace_a, trace_b)
        assert any(d.diff_type == DiffType.EXTRA_SPAN for d in diffs)

    def test_diff_output_mismatch(self) -> None:
        engine = ReplayEngine()

        trace_a = Trace(agent_id="test")
        span_a = Span(name="tool")
        span_a.finish(output={"result": 1})
        trace_a.add_span(span_a)

        trace_b = Trace(agent_id="test")
        span_b = Span(name="tool")
        span_b.finish(output={"result": 2})
        trace_b.add_span(span_b)

        diffs = engine.diff(trace_a, trace_b)
        assert any(d.diff_type == DiffType.OUTPUT_MISMATCH for d in diffs)

    def test_diff_cost_change(self) -> None:
        """Cost change detection not available in Public Preview — only checks output."""
        engine = ReplayEngine()

        trace_a = Trace(agent_id="test")
        span_a = Span(name="llm")
        span_a.finish(output={"text": "hi"}, cost_usd=0.01)
        trace_a.add_span(span_a)

        trace_b = Trace(agent_id="test")
        span_b = Span(name="llm")
        span_b.finish(output={"text": "hi"}, cost_usd=0.05)
        trace_b.add_span(span_b)

        diffs = engine.diff(trace_a, trace_b)
        # Same output, different cost — no diff in Public Preview
        assert not any(d.diff_type == DiffType.COST_CHANGE for d in diffs)

    def test_diff_tool_sequence(self) -> None:
        """Tool sequence diff not available in Public Preview."""
        engine = ReplayEngine()

        trace_a = Trace(agent_id="test")
        trace_a.add_span(Span(name="search", kind=SpanKind.TOOL_CALL))
        trace_a.add_span(Span(name="calculate", kind=SpanKind.TOOL_CALL))

        trace_b = Trace(agent_id="test")
        trace_b.add_span(Span(name="calculate", kind=SpanKind.TOOL_CALL))
        trace_b.add_span(Span(name="search", kind=SpanKind.TOOL_CALL))

        diffs = engine.diff(trace_a, trace_b)
        # Different order — no TOOL_SEQUENCE_DIFF in Public Preview
        assert not any(d.diff_type == DiffType.TOOL_SEQUENCE_DIFF for d in diffs)
