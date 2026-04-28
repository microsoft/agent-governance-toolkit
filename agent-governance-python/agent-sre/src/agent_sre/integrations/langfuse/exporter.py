# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Langfuse exporter — SLO scores and cost observations.

This module provides Langfuse-specific features that go beyond standard
OTLP export: trace-level scores from SLO evaluations and structured
cost observations with usage_details.

Requires: pip install langfuse

The exporter operates in two modes:
- **Live mode**: Connects to a real Langfuse instance (uses LANGFUSE_* env vars)
- **Offline mode**: Collects events in memory for testing/inspection

For standard metrics/traces, use the OTEL exporters in
agent_sre.integrations.otel and configure Langfuse as your OTLP endpoint.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@runtime_checkable
class LangfuseClient(Protocol):
    """Protocol matching the Langfuse Python SDK client interface."""

    def score(
        self,
        *,
        trace_id: str,
        name: str,
        value: float,
        comment: str | None = None,
        **kwargs: Any,
    ) -> Any: ...

    def span(
        self,
        *,
        trace_id: str,
        name: str,
        input: Any | None = None,
        output: Any | None = None,
        metadata: dict[str, Any] | None = None,
        **kwargs: Any,
    ) -> Any: ...


@dataclass
class SLOScore:
    """A score derived from SLO evaluation, ready for Langfuse."""

    trace_id: str
    name: str
    value: float
    comment: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class CostObservation:
    """A cost observation ready for Langfuse."""

    trace_id: str
    agent_id: str
    cost_usd: float
    task_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


class LangfuseExporter:
    """Exports Agent SRE data to Langfuse.

    Provides two capabilities beyond standard OTEL:
    1. **SLO Scores**: Attach SLO health as numeric scores to Langfuse traces
    2. **Cost Observations**: Record per-task costs with Langfuse-native metadata

    Args:
        client: A Langfuse client instance. If None, operates in offline mode
                (collects events in memory for testing).

    Example:
        from langfuse import get_client
        from agent_sre.integrations.langfuse import LangfuseExporter

        exporter = LangfuseExporter(client=get_client())
        exporter.score_slo(trace_id="trace-123", slo=my_slo)
    """

    def __init__(self, client: Any | None = None) -> None:
        self._client = client
        self._offline = client is None

        # Offline storage for testing
        self._scores: list[SLOScore] = []
        self._observations: list[CostObservation] = []

    @property
    def is_offline(self) -> bool:
        """True if operating in offline/test mode."""
        return self._offline

    @property
    def scores(self) -> list[SLOScore]:
        """Get recorded scores (offline mode)."""
        return list(self._scores)

    @property
    def observations(self) -> list[CostObservation]:
        """Get recorded observations (offline mode)."""
        return list(self._observations)

    def score_slo(
        self,
        trace_id: str,
        slo: Any,
    ) -> list[SLOScore]:
        """Score a Langfuse trace with SLO health data.

        Creates multiple scores per SLO:
        - `slo.<name>.status`: Overall status (0=healthy, 1=warning, 2=critical, 3=exhausted)
        - `slo.<name>.budget_remaining`: Error budget remaining (0.0-1.0)
        - `slo.<name>.burn_rate`: Current burn rate
        - One score per SLI: `sli.<name>`: Current value

        Args:
            trace_id: Langfuse trace ID to attach scores to
            slo: An agent_sre.slo.objectives.SLO instance

        Returns:
            List of SLOScore objects created
        """
        from agent_sre.integrations.otel.conventions import SLO_STATUS_CODES

        status = slo.evaluate()
        status_code = SLO_STATUS_CODES.get(status.value, -1)
        scores: list[SLOScore] = []

        # Overall SLO status
        scores.append(self._record_score(
            trace_id=trace_id,
            name=f"slo.{slo.name}.status",
            value=float(status_code),
            comment=f"SLO status: {status.value}",
        ))

        # Error budget remaining
        scores.append(self._record_score(
            trace_id=trace_id,
            name=f"slo.{slo.name}.budget_remaining",
            value=slo.error_budget.remaining,
            comment=f"Error budget: {slo.error_budget.remaining_percent:.1f}% remaining",
        ))

        # Burn rate
        burn = slo.error_budget.burn_rate()
        scores.append(self._record_score(
            trace_id=trace_id,
            name=f"slo.{slo.name}.burn_rate",
            value=burn,
            comment=f"Burn rate: {burn:.2f}x",
        ))

        # Per-SLI scores
        for indicator in slo.indicators:
            current = indicator.current_value()
            if current is not None:
                scores.append(self._record_score(
                    trace_id=trace_id,
                    name=f"sli.{indicator.name}",
                    value=current,
                    comment=f"SLI {indicator.name}: {current:.4f} (target: {indicator.target})",
                ))

        return scores

    def score_trace(
        self,
        trace_id: str,
        name: str,
        value: float,
        comment: str = "",
    ) -> SLOScore:
        """Score a trace with an arbitrary metric.

        Args:
            trace_id: Langfuse trace ID
            name: Score name
            value: Score value
            comment: Human-readable comment

        Returns:
            The created SLOScore
        """
        return self._record_score(trace_id, name, value, comment)

    def record_cost(
        self,
        trace_id: str,
        agent_id: str,
        cost_usd: float,
        task_id: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> CostObservation:
        """Record a cost observation for a trace.

        In live mode, creates a Langfuse span with cost metadata.
        In offline mode, stores the observation in memory.

        Args:
            trace_id: Langfuse trace ID
            agent_id: Agent identifier
            cost_usd: Cost in USD
            task_id: Optional task identifier
            metadata: Additional metadata

        Returns:
            The created CostObservation
        """
        obs = CostObservation(
            trace_id=trace_id,
            agent_id=agent_id,
            cost_usd=cost_usd,
            task_id=task_id,
            metadata=metadata or {},
        )
        self._observations.append(obs)

        if not self._offline and self._client:
            try:
                self._client.span(
                    trace_id=trace_id,
                    name=f"cost.{agent_id}",
                    metadata={
                        "agent_id": agent_id,
                        "task_id": task_id,
                        "cost_usd": cost_usd,
                        **(metadata or {}),
                    },
                )
            except Exception as e:
                logger.warning(f"Failed to record cost to Langfuse: {e}")

        return obs

    def _record_score(
        self,
        trace_id: str,
        name: str,
        value: float,
        comment: str,
    ) -> SLOScore:
        """Internal: record a score and send to Langfuse if live."""
        score = SLOScore(
            trace_id=trace_id,
            name=name,
            value=value,
            comment=comment,
        )
        self._scores.append(score)

        if not self._offline and self._client:
            try:
                self._client.score(
                    trace_id=trace_id,
                    name=name,
                    value=value,
                    comment=comment,
                )
            except Exception as e:
                logger.warning(f"Failed to send score to Langfuse: {e}")

        return score

    def clear(self) -> None:
        """Clear all offline storage."""
        self._scores.clear()
        self._observations.clear()
