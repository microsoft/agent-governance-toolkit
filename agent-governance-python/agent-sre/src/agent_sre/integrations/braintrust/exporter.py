# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Braintrust exporter — evaluation scoring and experiment tracking.

Exports Agent-SRE SLO evaluations as Braintrust scores and experiments.
Operates in two modes:
- **Live mode**: Sends data to a Braintrust client
- **Offline mode**: Collects records in memory for testing/inspection

No Braintrust dependency required — uses duck-typed client protocol.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@runtime_checkable
class BraintrustClient(Protocol):
    """Protocol matching the Braintrust Python SDK client interface."""

    def log(self, *, input: Any, output: Any, scores: dict, **kwargs: Any) -> Any: ...

    def start_experiment(self, name: str, **kwargs: Any) -> Any: ...


@dataclass
class EvalRecord:
    """An evaluation record for Braintrust."""

    trace_id: str
    agent_id: str
    slo_name: str
    scores: dict[str, float]
    input_data: Any = None
    output_data: Any = None
    expected: Any = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class ExperimentRecord:
    """A batch experiment record for Braintrust."""

    name: str
    entries: list[dict[str, Any]]
    timestamp: float = field(default_factory=time.time)


class BraintrustExporter:
    """Exports Agent SRE data to Braintrust.

    Provides evaluation scoring and experiment tracking:
    1. **Evaluations**: Log SLO evaluations with scores
    2. **Experiments**: Batch evaluations as experiments
    3. **Cost tracking**: Record per-task costs

    Args:
        client: A Braintrust client instance. If None, operates in offline mode.
        project_name: Braintrust project name.

    Example:
        from agent_sre.integrations.braintrust import BraintrustExporter

        exporter = BraintrustExporter()
        exporter.log_eval(
            trace_id="trace-1", agent_id="bot-1",
            slo_name="latency", scores={"accuracy": 0.95},
        )
    """

    def __init__(
        self,
        client: Any | None = None,
        project_name: str = "agent-sre",
    ) -> None:
        self._client = client
        self._offline = client is None
        self.project_name = project_name

        self._evaluations: list[EvalRecord] = []
        self._experiments: list[ExperimentRecord] = []

    @property
    def is_offline(self) -> bool:
        """True if operating in offline/test mode."""
        return self._offline

    @property
    def evaluations(self) -> list[EvalRecord]:
        """Get recorded evaluations."""
        return list(self._evaluations)

    @property
    def experiments(self) -> list[ExperimentRecord]:
        """Get recorded experiments."""
        return list(self._experiments)

    def log_eval(
        self,
        trace_id: str,
        agent_id: str,
        slo_name: str,
        scores: dict[str, float],
        input_data: Any = None,
        output_data: Any = None,
        expected: Any = None,
    ) -> EvalRecord:
        """Log an evaluation with SLO scores.

        Args:
            trace_id: Unique trace identifier
            agent_id: Agent identifier
            slo_name: SLO name being evaluated
            scores: Dictionary of score name to value
            input_data: Optional input data
            output_data: Optional output data
            expected: Optional expected output

        Returns:
            The created EvalRecord
        """
        record = EvalRecord(
            trace_id=trace_id,
            agent_id=agent_id,
            slo_name=slo_name,
            scores=scores,
            input_data=input_data,
            output_data=output_data,
            expected=expected,
        )
        self._evaluations.append(record)

        if not self._offline and self._client:
            try:
                self._client.log(
                    input=input_data,
                    output=output_data,
                    scores=scores,
                    metadata={
                        "trace_id": trace_id,
                        "agent_id": agent_id,
                        "slo_name": slo_name,
                    },
                )
            except Exception as e:
                logger.warning(f"Failed to log eval to Braintrust: {e}")

        return record

    def log_experiment(
        self,
        experiment_name: str,
        entries: list[dict[str, Any]],
    ) -> ExperimentRecord:
        """Log a batch of evaluations as an experiment.

        Args:
            experiment_name: Name of the experiment
            entries: List of evaluation entries

        Returns:
            The created ExperimentRecord
        """
        record = ExperimentRecord(name=experiment_name, entries=entries)
        self._experiments.append(record)

        if not self._offline and self._client:
            try:
                self._client.start_experiment(experiment_name)
                for entry in entries:
                    self._client.log(
                        input=entry.get("input"),
                        output=entry.get("output"),
                        scores=entry.get("scores", {}),
                    )
            except Exception as e:
                logger.warning(f"Failed to log experiment to Braintrust: {e}")

        return record

    def export_slo(
        self,
        trace_id: str,
        slo: Any,
    ) -> list[EvalRecord]:
        """Export SLO evaluation as Braintrust scores.

        Creates evaluation records with SLO metrics as scores:
        - status, budget_remaining, burn_rate
        - Per-SLI current values

        Args:
            trace_id: Trace identifier
            slo: An agent_sre.slo.objectives.SLO instance

        Returns:
            List of EvalRecord objects created
        """
        from agent_sre.integrations.otel.conventions import SLO_STATUS_CODES

        status = slo.evaluate()
        status_code = SLO_STATUS_CODES.get(status.value, -1)
        burn = slo.error_budget.burn_rate()

        scores: dict[str, float] = {
            "status": float(status_code),
            "budget_remaining": slo.error_budget.remaining,
            "burn_rate": burn,
        }

        for indicator in slo.indicators:
            current = indicator.current_value()
            if current is not None:
                scores[f"sli.{indicator.name}"] = current

        record = self.log_eval(
            trace_id=trace_id,
            agent_id="",
            slo_name=slo.name,
            scores=scores,
        )
        return [record]

    def record_cost(
        self,
        trace_id: str,
        agent_id: str,
        cost_usd: float,
        metadata: dict[str, Any] | None = None,
    ) -> EvalRecord:
        """Record cost data as an evaluation.

        Args:
            trace_id: Trace identifier
            agent_id: Agent identifier
            cost_usd: Cost in USD
            metadata: Additional metadata

        Returns:
            The created EvalRecord
        """
        scores = {"cost_usd": cost_usd}
        return self.log_eval(
            trace_id=trace_id,
            agent_id=agent_id,
            slo_name="cost",
            scores=scores,
            input_data=metadata,
        )

    def clear(self) -> None:
        """Clear all offline storage."""
        self._evaluations.clear()
        self._experiments.clear()

    def get_stats(self) -> dict[str, Any]:
        """Get statistics about recorded data."""
        return {
            "total_evaluations": len(self._evaluations),
            "total_experiments": len(self._experiments),
            "project": self.project_name,
        }
