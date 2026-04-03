# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic implementation
"""Replay engine for deterministic re-execution of agent traces."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from agent_sre.replay.capture import Span, SpanStatus, Trace, TraceStore


class DiffType(Enum):
    """Type of difference between two trace executions."""

    OUTPUT_MISMATCH = "output_mismatch"
    TOOL_SEQUENCE_DIFF = "tool_sequence_diff"
    MISSING_SPAN = "missing_span"
    EXTRA_SPAN = "extra_span"
    STATUS_CHANGE = "status_change"
    COST_CHANGE = "cost_change"
    LATENCY_CHANGE = "latency_change"


@dataclass
class TraceDiff:
    """A single difference between two traces."""

    diff_type: DiffType
    span_name: str
    original: Any = None
    replayed: Any = None
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.diff_type.value,
            "span": self.span_name,
            "original": str(self.original),
            "replayed": str(self.replayed),
            "description": self.description,
        }


@dataclass
class ReplayResult:
    """Result of replaying a trace."""

    original_trace_id: str
    replay_trace_id: str
    success: bool
    diffs: list[TraceDiff] = field(default_factory=list)
    steps_executed: int = 0
    steps_total: int = 0

    @property
    def has_divergence(self) -> bool:
        return len(self.diffs) > 0

    @property
    def divergence_point(self) -> str | None:
        """Name of the first span where divergence occurred."""
        if not self.diffs:
            return None
        return self.diffs[0].span_name

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_trace_id": self.original_trace_id,
            "replay_trace_id": self.replay_trace_id,
            "success": self.success,
            "has_divergence": self.has_divergence,
            "divergence_point": self.divergence_point,
            "diff_count": len(self.diffs),
            "diffs": [d.to_dict() for d in self.diffs],
            "steps_executed": self.steps_executed,
            "steps_total": self.steps_total,
        }


@dataclass
class ReplayStep:
    """A single step in an interactive replay session."""

    index: int
    span: Span
    children: list[Span] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "name": self.span.name,
            "kind": self.span.kind.value,
            "input": self.span.input_data,
            "output": self.span.output_data,
            "status": self.span.status.value,
            "duration_ms": self.span.duration_ms,
            "cost_usd": self.span.cost_usd,
            "children_count": len(self.children),
        }


class ReplayEngine:
    """Engine for deterministic replay of captured agent traces.

    Supports:
    - Full automated replay with mocked external calls
    - Interactive step-through
    - Trace diffing (compare two executions)
    - Trace comparison (what-if with modified inputs)
    """

    def __init__(self, store: TraceStore | None = None) -> None:
        self.store = store or TraceStore()
        self._overrides: dict[str, dict[str, Any]] = {}

    def load(self, trace_id: str) -> Trace | None:
        """Load a trace for replay."""
        return self.store.load(trace_id)

    def steps(self, trace: Trace) -> list[ReplayStep]:
        """Break a trace into interactive steps (root spans with their children)."""
        result = []
        for i, span in enumerate(trace.spans):
            children = trace.children_of(span.span_id)
            result.append(ReplayStep(index=i, span=span, children=children))
        return result

    def replay(
        self,
        trace: Trace,
        overrides: dict[str, dict[str, Any]] | None = None,
    ) -> ReplayResult:
        """Replay a trace, using captured outputs as mock responses.

        Args:
            trace: The trace to replay.
            overrides: Optional dict mapping span names to override output_data.
                       Used for trace comparison.

        Returns:
            ReplayResult with any divergences detected.
        """
        overrides = overrides or self._overrides
        result = ReplayResult(
            original_trace_id=trace.trace_id,
            replay_trace_id=f"replay-{trace.trace_id[:8]}",
            success=True,
            steps_total=len(trace.spans),
        )

        for span in trace.spans:
            result.steps_executed += 1

            # Apply overrides if any
            if span.name in overrides:
                override_output = overrides[span.name]
                if override_output != span.output_data:
                    result.diffs.append(TraceDiff(
                        diff_type=DiffType.OUTPUT_MISMATCH,
                        span_name=span.name,
                        original=span.output_data,
                        replayed=override_output,
                        description=f"Override applied to '{span.name}'",
                    ))

            # Check for errors in original
            if span.status == SpanStatus.ERROR:
                result.diffs.append(TraceDiff(
                    diff_type=DiffType.STATUS_CHANGE,
                    span_name=span.name,
                    original=span.status.value,
                    replayed="replayed_as_error",
                    description=f"Original span '{span.name}' had error: {span.error}",
                ))

        result.success = not result.has_divergence
        return result

    def diff(self, trace_a: Trace, trace_b: Trace) -> list[TraceDiff]:
        """Compare two traces and return differences.

        Basic comparison: checks for missing/extra spans and output mismatches.
        """
        diffs: list[TraceDiff] = []

        spans_a = {s.name: s for s in trace_a.spans}
        spans_b = {s.name: s for s in trace_b.spans}

        all_names = set(spans_a.keys()) | set(spans_b.keys())

        for name in sorted(all_names):
            sa = spans_a.get(name)
            sb = spans_b.get(name)

            if sa is None:
                diffs.append(TraceDiff(
                    diff_type=DiffType.EXTRA_SPAN,
                    span_name=name,
                    description=f"Span '{name}' only in trace B",
                ))
                continue

            if sb is None:
                diffs.append(TraceDiff(
                    diff_type=DiffType.MISSING_SPAN,
                    span_name=name,
                    description=f"Span '{name}' only in trace A",
                ))
                continue

            # Compare outputs
            if sa.output_data != sb.output_data:
                diffs.append(TraceDiff(
                    diff_type=DiffType.OUTPUT_MISMATCH,
                    span_name=name,
                    original=sa.output_data,
                    replayed=sb.output_data,
                    description=f"Output differs for '{name}'",
                ))

            # Compare status
            if sa.status != sb.status:
                diffs.append(TraceDiff(
                    diff_type=DiffType.STATUS_CHANGE,
                    span_name=name,
                    original=sa.status.value,
                    replayed=sb.status.value,
                    description=f"Status changed for '{name}'",
                ))

        return diffs

    def what_if(self, trace: Trace, overrides: dict[str, dict[str, Any]]) -> ReplayResult:
        """Run a what-if trace comparison with modified span outputs.

        Replays the trace with the given overrides applied, returning
        a ReplayResult that highlights divergences from the original.

        Args:
            trace: The original trace to replay.
            overrides: Dict mapping span names to replacement output_data.

        Returns:
            ReplayResult with divergences caused by the overrides.
        """
        return self.replay(trace, overrides=overrides)
