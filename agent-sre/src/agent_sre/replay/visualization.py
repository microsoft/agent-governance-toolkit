# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""Trace visualization — execution graph and decision tree rendering."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from agent_sre.replay.capture import Span, SpanKind, SpanStatus, Trace


@dataclass
class GraphNode:
    """A node in the execution graph."""
    node_id: str
    label: str
    kind: SpanKind
    status: SpanStatus
    duration_ms: float | None = None
    cost_usd: float = 0.0
    depth: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.node_id,
            "label": self.label,
            "kind": self.kind.value,
            "status": self.status.value,
            "duration_ms": self.duration_ms,
            "cost_usd": self.cost_usd,
            "depth": self.depth,
            "metadata": self.metadata,
        }


@dataclass
class GraphEdge:
    """An edge connecting two nodes in the execution graph."""
    source: str
    target: str
    label: str = ""
    edge_type: str = "child"  # child, delegation, tool_call

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "label": self.label,
            "type": self.edge_type,
        }


@dataclass
class ExecutionGraph:
    """Directed graph representation of an agent execution trace."""
    trace_id: str
    agent_id: str
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)

    def add_node(self, node: GraphNode) -> None:
        self.nodes.append(node)

    def add_edge(self, edge: GraphEdge) -> None:
        self.edges.append(edge)

    @property
    def max_depth(self) -> int:
        if not self.nodes:
            return 0
        return max(n.depth for n in self.nodes)

    @property
    def critical_path(self) -> list[GraphNode]:
        """Get the longest path through the graph (by duration)."""
        if not self.nodes:
            return []
        # Build adjacency
        children: dict[str, list[str]] = {}
        for edge in self.edges:
            children.setdefault(edge.source, []).append(edge.target)
        node_map = {n.node_id: n for n in self.nodes}

        def _longest(nid: str) -> tuple[float, list[str]]:
            node = node_map.get(nid)
            dur = (node.duration_ms or 0.0) if node else 0.0
            kids = children.get(nid, [])
            if not kids:
                return dur, [nid]
            best_dur, best_path = max(
                (_longest(c) for c in kids),
                key=lambda x: x[0],
            )
            return dur + best_dur, [nid] + best_path

        roots = [n.node_id for n in self.nodes if n.depth == 0]
        if not roots:
            return []
        _, path = max((_longest(r) for r in roots), key=lambda x: x[0])
        return [node_map[nid] for nid in path if nid in node_map]

    def to_dict(self) -> dict[str, Any]:
        return {
            "trace_id": self.trace_id,
            "agent_id": self.agent_id,
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "max_depth": self.max_depth,
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "summary": self.summary,
        }


class TraceVisualizer:
    """Converts traces into visual graph representations.

    Produces structured data suitable for rendering as:
    - DAG (directed acyclic graph) for execution flow
    - Decision tree for branching logic
    - Timeline for latency analysis
    """

    def build_graph(self, trace: Trace) -> ExecutionGraph:
        """Build an execution graph from a trace."""
        graph = ExecutionGraph(
            trace_id=trace.trace_id,
            agent_id=trace.agent_id,
        )

        # Build depth map
        depth_map: dict[str, int] = {}
        span_map = {s.span_id: s for s in trace.spans}

        def _depth(span: Span) -> int:
            if span.span_id in depth_map:
                return depth_map[span.span_id]
            if span.parent_id is None or span.parent_id not in span_map:
                depth_map[span.span_id] = 0
            else:
                depth_map[span.span_id] = _depth(span_map[span.parent_id]) + 1
            return depth_map[span.span_id]

        for span in trace.spans:
            d = _depth(span)
            node = GraphNode(
                node_id=span.span_id,
                label=span.name,
                kind=span.kind,
                status=span.status,
                duration_ms=span.duration_ms,
                cost_usd=span.cost_usd,
                depth=d,
            )
            graph.add_node(node)

            if span.parent_id and span.parent_id in span_map:
                edge_type = "delegation" if span.kind == SpanKind.DELEGATION else "child"
                edge = GraphEdge(
                    source=span.parent_id,
                    target=span.span_id,
                    label=span.kind.value,
                    edge_type=edge_type,
                )
                graph.add_edge(edge)

        # Summary stats
        graph.summary = self._compute_summary(trace, graph)
        return graph

    def build_timeline(self, trace: Trace) -> list[dict[str, Any]]:
        """Build a timeline representation for latency analysis."""
        if not trace.spans:
            return []
        base_time = trace.start_time
        timeline = []
        for span in trace.spans:
            timeline.append({
                "span_id": span.span_id,
                "name": span.name,
                "kind": span.kind.value,
                "status": span.status.value,
                "offset_ms": (span.start_time - base_time) * 1000,
                "duration_ms": span.duration_ms,
                "cost_usd": span.cost_usd,
            })
        return sorted(timeline, key=lambda x: x["offset_ms"])

    def build_decision_tree(self, trace: Trace) -> dict[str, Any]:
        """Build a decision tree showing branching logic."""
        {s.span_id: s for s in trace.spans}
        roots = trace.root_spans()

        def _build_subtree(span: Span) -> dict[str, Any]:
            children = trace.children_of(span.span_id)
            return {
                "name": span.name,
                "kind": span.kind.value,
                "status": span.status.value,
                "input_summary": _summarize(span.input_data),
                "output_summary": _summarize(span.output_data),
                "duration_ms": span.duration_ms,
                "cost_usd": span.cost_usd,
                "children": [_build_subtree(c) for c in children],
            }

        return {
            "trace_id": trace.trace_id,
            "agent_id": trace.agent_id,
            "roots": [_build_subtree(r) for r in roots],
        }

    def _compute_summary(self, trace: Trace, graph: ExecutionGraph) -> dict[str, Any]:
        """Compute summary statistics for the graph."""
        by_kind: dict[str, int] = {}
        by_status: dict[str, int] = {}
        total_cost = 0.0

        for span in trace.spans:
            by_kind[span.kind.value] = by_kind.get(span.kind.value, 0) + 1
            by_status[span.status.value] = by_status.get(span.status.value, 0) + 1
            total_cost += span.cost_usd

        return {
            "total_spans": len(trace.spans),
            "by_kind": by_kind,
            "by_status": by_status,
            "total_cost_usd": round(total_cost, 4),
            "duration_ms": trace.duration_ms,
            "max_depth": graph.max_depth,
        }


def _summarize(data: dict[str, Any], max_len: int = 100) -> str:
    """Create a short summary of data for display."""
    if not data:
        return ""
    text = str(data)
    if len(text) > max_len:
        return text[:max_len] + "..."
    return text
