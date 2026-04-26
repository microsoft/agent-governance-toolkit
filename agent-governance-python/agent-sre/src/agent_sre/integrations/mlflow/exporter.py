# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""MLflow exporter — log SRE metrics as MLflow experiments.

Maps agent tasks to experiment runs. Operates in offline mode
when no MLflow client is provided (collects runs in memory).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class MLflowRun:
    """An MLflow run record."""

    name: str
    metrics: dict[str, Any]
    params: dict[str, Any]
    tags: dict[str, str]
    timestamp: float = field(default_factory=time.time)


@dataclass
class MLflowArtifact:
    """An MLflow artifact record."""

    run_name: str
    path: str
    content: str
    timestamp: float = field(default_factory=time.time)


class MLflowExporter:
    """Exports Agent SRE data as MLflow runs.

    Args:
        experiment_name: MLflow experiment name.
        client: An MLflow client instance. If None, operates in offline mode.
    """

    def __init__(self, experiment_name: str = "agent-sre", client: Any = None) -> None:
        self._experiment_name = experiment_name
        self._client = client
        self._offline = client is None
        self._runs: list[MLflowRun] = []
        self._artifacts: list[MLflowArtifact] = []

    @property
    def is_offline(self) -> bool:
        """True if operating in offline/test mode."""
        return self._offline

    @property
    def runs(self) -> list[MLflowRun]:
        """Get recorded runs."""
        return list(self._runs)

    @property
    def artifacts(self) -> list[MLflowArtifact]:
        """Get recorded artifacts."""
        return list(self._artifacts)

    def log_run(
        self,
        run_name: str,
        metrics: dict[str, Any],
        params: dict[str, Any] | None = None,
        tags: dict[str, str] | None = None,
    ) -> MLflowRun:
        """Log a run with SRE metrics.

        Args:
            run_name: Name for the MLflow run.
            metrics: Metrics dict to log.
            params: Optional run parameters.
            tags: Optional dict of tags.

        Returns:
            The created MLflowRun.
        """
        run = MLflowRun(
            name=run_name,
            metrics=dict(metrics),
            params=dict(params) if params else {},
            tags=dict(tags) if tags else {},
        )
        self._runs.append(run)

        if not self._offline and self._client:
            try:
                self._client.log_metrics(metrics)
            except Exception as e:
                logger.warning("Failed to log run to MLflow: %s", e)

        return run

    def log_slo(self, slo: Any, agent_id: str = "") -> MLflowRun:
        """Log SLO evaluation as an MLflow run.

        Args:
            slo: An agent_sre.slo.objectives.SLO instance.
            agent_id: Optional agent identifier.

        Returns:
            The created MLflowRun.
        """
        status = slo.evaluate()
        metrics: dict[str, Any] = {
            "slo_status": status.value,
            "budget_remaining": slo.error_budget.remaining,
            "burn_rate": slo.error_budget.burn_rate(),
        }
        for indicator in slo.indicators:
            val = indicator.current_value()
            if val is not None:
                metrics[f"sli.{indicator.name}"] = val

        params = {"slo_name": slo.name, "agent_id": agent_id}
        tags = {"slo_name": slo.name}
        if agent_id:
            tags["agent_id"] = agent_id

        return self.log_run(
            run_name=f"slo-{slo.name}",
            metrics=metrics,
            params=params,
            tags=tags,
        )

    def log_artifact(
        self,
        run_name: str,
        artifact_path: str,
        content: str,
    ) -> MLflowArtifact:
        """Log artifact data.

        Args:
            run_name: Name of the run this artifact belongs to.
            artifact_path: Path/name for the artifact.
            content: Artifact content.

        Returns:
            The created MLflowArtifact.
        """
        artifact = MLflowArtifact(
            run_name=run_name,
            path=artifact_path,
            content=content,
        )
        self._artifacts.append(artifact)
        return artifact

    def clear(self) -> None:
        """Clear all recorded runs and artifacts."""
        self._runs.clear()
        self._artifacts.clear()

    def get_stats(self) -> dict[str, Any]:
        """Get exporter statistics."""
        return {
            "experiment_name": self._experiment_name,
            "total_runs": len(self._runs),
            "total_artifacts": len(self._artifacts),
            "is_offline": self._offline,
        }
