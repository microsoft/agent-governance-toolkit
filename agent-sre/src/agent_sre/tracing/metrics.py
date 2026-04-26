# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""OpenTelemetry metric instruments for AI agent observability.

Provides counters, histograms, and an up-down counter following
Prometheus naming conventions as required by AGENTS.md.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable

    from opentelemetry.metrics import (
        Counter,
        Histogram,
        Meter,
        ObservableGauge,
        UpDownCounter,
    )

# ---------------------------------------------------------------------------
# Metric name constants
# ---------------------------------------------------------------------------

METRIC_TASKS_TOTAL = "agent.tasks.total"
METRIC_TOOL_CALLS_TOTAL = "agent.tool_calls.total"
METRIC_POLICY_VIOLATIONS = "agent.policy.violations"
METRIC_TASK_DURATION = "agent.task.duration"
METRIC_LLM_LATENCY = "agent.llm.latency"
METRIC_TOOL_LATENCY = "agent.tool.latency"
METRIC_ACTIVE_TASKS = "agent.active_tasks"
METRIC_TRUST_SCORE = "agent.trust_score"


@dataclass
class AgentMetrics:
    """Collection of OpenTelemetry metric instruments for agent monitoring."""

    tasks_total: Counter
    tool_calls_total: Counter
    policy_violations: Counter
    task_duration: Histogram
    llm_latency: Histogram
    tool_latency: Histogram
    active_tasks: UpDownCounter
    trust_score: ObservableGauge | None = None


def create_agent_metrics(
    meter: Meter,
    trust_score_callback: Callable[..., object] | None = None,
) -> AgentMetrics:
    """Create all agent metric instruments from a single meter.

    Args:
        meter: OpenTelemetry ``Meter`` instance.
        trust_score_callback: Optional callback for the observable gauge.
            When *None*, the ``trust_score`` gauge is not created.

    Returns:
        An :class:`AgentMetrics` dataclass with all instruments.
    """
    tasks_total = meter.create_counter(
        name=METRIC_TASKS_TOTAL,
        description="Total number of agent tasks executed",
        unit="1",
    )
    tool_calls_total = meter.create_counter(
        name=METRIC_TOOL_CALLS_TOTAL,
        description="Total number of tool calls made by agents",
        unit="1",
    )
    policy_violations = meter.create_counter(
        name=METRIC_POLICY_VIOLATIONS,
        description="Total number of policy violations detected",
        unit="1",
    )
    task_duration = meter.create_histogram(
        name=METRIC_TASK_DURATION,
        description="Duration of agent tasks",
        unit="ms",
    )
    llm_latency = meter.create_histogram(
        name=METRIC_LLM_LATENCY,
        description="Latency of LLM inference calls",
        unit="ms",
    )
    tool_latency = meter.create_histogram(
        name=METRIC_TOOL_LATENCY,
        description="Latency of tool calls",
        unit="ms",
    )
    active_tasks = meter.create_up_down_counter(
        name=METRIC_ACTIVE_TASKS,
        description="Number of currently active agent tasks",
        unit="1",
    )

    trust_score: ObservableGauge | None = None
    if trust_score_callback is not None:
        trust_score = meter.create_observable_gauge(
            name=METRIC_TRUST_SCORE,
            callbacks=[trust_score_callback],
            description="Current trust score of the agent",
            unit="1",
        )

    return AgentMetrics(
        tasks_total=tasks_total,
        tool_calls_total=tool_calls_total,
        policy_violations=policy_violations,
        task_duration=task_duration,
        llm_latency=llm_latency,
        tool_latency=tool_latency,
        active_tasks=active_tasks,
        trust_score=trust_score,
    )
