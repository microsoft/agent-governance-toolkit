# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for trace visualization."""

from agent_sre.replay.capture import Span, SpanKind, Trace
from agent_sre.replay.visualization import (
    TraceVisualizer,
)


def _make_trace():
    """Create a sample trace with parent-child spans."""
    trace = Trace(trace_id="test-trace", agent_id="agent-1", task_input="test task")
    root = Span(span_id="root", trace_id="test-trace", kind=SpanKind.AGENT_TASK, name="main_task")
    root.finish(output={"result": "done"}, cost_usd=0.01)
    trace.add_span(root)

    tool = Span(span_id="tool1", parent_id="root", trace_id="test-trace",
                kind=SpanKind.TOOL_CALL, name="search")
    tool.finish(output={"data": "found"}, cost_usd=0.005)
    trace.add_span(tool)

    llm = Span(span_id="llm1", parent_id="root", trace_id="test-trace",
               kind=SpanKind.LLM_INFERENCE, name="generate")
    llm.finish(output={"text": "answer"}, cost_usd=0.02)
    trace.add_span(llm)

    trace.finish(output="answer", success=True)
    return trace


class TestTraceVisualizer:
    def test_build_graph(self):
        viz = TraceVisualizer()
        graph = viz.build_graph(_make_trace())
        assert len(graph.nodes) == 3
        assert len(graph.edges) == 2
        assert graph.trace_id == "test-trace"

    def test_node_depths(self):
        viz = TraceVisualizer()
        graph = viz.build_graph(_make_trace())
        depths = {n.label: n.depth for n in graph.nodes}
        assert depths["main_task"] == 0
        assert depths["search"] == 1
        assert depths["generate"] == 1

    def test_max_depth(self):
        viz = TraceVisualizer()
        graph = viz.build_graph(_make_trace())
        assert graph.max_depth == 1

    def test_build_timeline(self):
        viz = TraceVisualizer()
        timeline = viz.build_timeline(_make_trace())
        assert len(timeline) == 3
        assert all("offset_ms" in t for t in timeline)

    def test_build_decision_tree(self):
        viz = TraceVisualizer()
        tree = viz.build_decision_tree(_make_trace())
        assert tree["trace_id"] == "test-trace"
        assert len(tree["roots"]) == 1
        assert len(tree["roots"][0]["children"]) == 2

    def test_critical_path(self):
        viz = TraceVisualizer()
        graph = viz.build_graph(_make_trace())
        path = graph.critical_path
        assert len(path) >= 1
        assert path[0].label == "main_task"

    def test_graph_to_dict(self):
        viz = TraceVisualizer()
        graph = viz.build_graph(_make_trace())
        d = graph.to_dict()
        assert "nodes" in d
        assert "edges" in d
        assert "summary" in d
        assert d["node_count"] == 3

    def test_empty_trace(self):
        viz = TraceVisualizer()
        trace = Trace(trace_id="empty", agent_id="agent-1")
        graph = viz.build_graph(trace)
        assert len(graph.nodes) == 0
        assert graph.max_depth == 0

    def test_summary_stats(self):
        viz = TraceVisualizer()
        graph = viz.build_graph(_make_trace())
        assert "total_spans" in graph.summary
        assert graph.summary["total_spans"] == 3
