# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""Manager for running golden-trace regression suites."""

from __future__ import annotations

import time
from difflib import SequenceMatcher
from typing import TYPE_CHECKING, Any

from agent_sre.replay.golden import (
    GoldenSuiteResult,
    GoldenTrace,
    GoldenTraceResult,
    GoldenTraceSuite,
    TraceSource,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from agent_sre.replay.capture import Trace


class GoldenTraceManager:
    """Create, curate, and execute golden-trace regression suites."""

    def mark_golden(
        self,
        trace: Trace,
        name: str,
        expected_output: str,
        tolerance: float = 0.0,
        labels: list[str] | None = None,
        source: TraceSource = TraceSource.PRODUCTION,
    ) -> GoldenTrace:
        """Promote a successful trace to a golden reference.

        Args:
            trace: The captured Trace to use as golden reference.
            name: Human-readable name for this golden trace.
            expected_output: The expected output string.
            tolerance: Float 0-1 for fuzzy matching (0 = exact).
            labels: Optional classification labels.
            source: Whether the trace is from production or synthetic.

        Returns:
            A new GoldenTrace instance.
        """
        return GoldenTrace(
            name=name,
            trace=trace.to_dict(redact=False),
            expected_output=expected_output,
            tolerance=tolerance,
            labels=labels or [],
            source=source,
        )

    def compare_output(
        self, expected: str, actual: str, tolerance: float
    ) -> tuple[bool, list[str]]:
        """Compare expected vs actual output with optional fuzzy tolerance.

        Args:
            expected: The golden expected output.
            actual: The actual output from the agent function.
            tolerance: 0.0 = exact match required, 1.0 = always pass.

        Returns:
            Tuple of (passed, list_of_diff_descriptions).
        """
        if expected == actual:
            return True, []

        if tolerance > 0.0:
            ratio = SequenceMatcher(None, expected, actual).ratio()
            if ratio >= (1.0 - tolerance):
                return True, []
            return False, [
                f"Similarity {ratio:.4f} below threshold {1.0 - tolerance:.4f}"
            ]

        # Exact match failed — build diff descriptions
        diffs: list[str] = []
        if len(expected) != len(actual):
            diffs.append(
                f"Length differs: expected {len(expected)}, got {len(actual)}"
            )
        diffs.append(f"Expected: {expected!r}")
        diffs.append(f"Actual:   {actual!r}")
        return False, diffs

    def run_single(
        self,
        golden_trace: GoldenTrace,
        agent_fn: Callable[[dict[str, Any]], str],
    ) -> GoldenTraceResult:
        """Execute one golden trace against *agent_fn* and compare output.

        Args:
            golden_trace: The golden reference trace.
            agent_fn: Callable that accepts the trace dict and returns an output string.

        Returns:
            GoldenTraceResult with pass/fail and diffs.
        """
        start = time.monotonic()
        actual = agent_fn(golden_trace.trace)
        elapsed = time.monotonic() - start

        passed, diffs = self.compare_output(
            golden_trace.expected_output, actual, golden_trace.tolerance
        )
        return GoldenTraceResult(
            trace_id=golden_trace.id,
            passed=passed,
            diffs=diffs,
            execution_time=elapsed,
            actual_output=actual,
        )

    def run_suite(
        self,
        suite: GoldenTraceSuite,
        agent_fn: Callable[[dict[str, Any]], str],
    ) -> GoldenSuiteResult:
        """Run every golden trace in *suite* and aggregate results.

        Args:
            suite: The golden-trace suite to execute.
            agent_fn: Callable that accepts the trace dict and returns an output string.

        Returns:
            GoldenSuiteResult with per-trace results and CI pass/fail.
        """
        results: list[GoldenTraceResult] = []
        for gt in suite.traces:
            results.append(self.run_single(gt, agent_fn))

        total = len(results)
        passed = sum(1 for r in results if r.passed)
        failed = total - passed
        pass_rate = passed / total if total > 0 else 0.0

        return GoldenSuiteResult(
            suite_name=suite.name,
            total=total,
            passed=passed,
            failed=failed,
            pass_rate=pass_rate,
            results=results,
            ci_passed=pass_rate >= suite.pass_threshold,
        )

    def curate(
        self,
        traces: list[GoldenTrace],
        max_count: int,
        strategy: str = "diverse",
    ) -> list[GoldenTrace]:
        """Auto-select a diverse, representative subset of golden traces.

        Strategy ``"diverse"`` picks traces with different label combinations
        before filling remaining slots with the earliest-created traces.

        Args:
            traces: Pool of candidate golden traces.
            max_count: Maximum number of traces to return.
            strategy: Selection strategy (currently only ``"diverse"``).

        Returns:
            A list of at most *max_count* golden traces.
        """
        if len(traces) <= max_count:
            return list(traces)

        if strategy != "diverse":
            return list(traces[:max_count])

        # Group by unique label sets
        seen_labels: set[tuple[str, ...]] = set()
        selected: list[GoldenTrace] = []

        for gt in traces:
            key = tuple(sorted(gt.labels))
            if key not in seen_labels:
                seen_labels.add(key)
                selected.append(gt)
                if len(selected) >= max_count:
                    return selected

        # Fill remaining slots with traces not yet selected
        selected_ids = {gt.id for gt in selected}
        for gt in traces:
            if gt.id not in selected_ids:
                selected.append(gt)
                if len(selected) >= max_count:
                    break

        return selected
