# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""W&B exporter — log SRE metrics as W&B runs.

Maps agent tasks to experiment runs. Operates in offline mode
when no W&B client is provided (collects runs in memory).
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class WandBRun:
    """A W&B run record."""

    name: str
    metrics: dict[str, Any]
    config: dict[str, Any]
    tags: list[str]
    timestamp: float = field(default_factory=time.time)


class WandBExporter:
    """Exports Agent SRE data as W&B runs.

    Args:
        project: W&B project name.
        client: A W&B client instance. If None, operates in offline mode.
    """

    def __init__(self, project: str = "agent-sre", client: Any = None) -> None:
        self._project = project
        self._client = client
        self._offline = client is None
        self._runs: list[WandBRun] = []

    @property
    def is_offline(self) -> bool:
        """True if operating in offline/test mode."""
        return self._offline

    @property
    def runs(self) -> list[WandBRun]:
        """Get recorded runs."""
        return list(self._runs)

    def log_run(
        self,
        run_name: str,
        metrics: dict[str, Any],
        config: dict[str, Any] | None = None,
        tags: list[str] | None = None,
    ) -> WandBRun:
        """Log a run with SRE metrics.

        Args:
            run_name: Name for the W&B run.
            metrics: Metrics dict to log.
            config: Optional run config.
            tags: Optional list of tags.

        Returns:
            The created WandBRun.
        """
        run = WandBRun(
            name=run_name,
            metrics=dict(metrics),
            config=dict(config) if config else {},
            tags=list(tags) if tags else [],
        )
        self._runs.append(run)

        if not self._offline and self._client:
            try:
                self._client.log(metrics, step=None)
            except Exception as e:
                logger.warning("Failed to log run to W&B: %s", e)

        return run

    def log_slo(self, slo: Any, agent_id: str = "") -> WandBRun:
        """Log SLO evaluation as a W&B run.

        Args:
            slo: An agent_sre.slo.objectives.SLO instance.
            agent_id: Optional agent identifier.

        Returns:
            The created WandBRun.
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

        config = {"slo_name": slo.name, "agent_id": agent_id}
        tags = ["slo", slo.name]
        if agent_id:
            tags.append(f"agent:{agent_id}")

        return self.log_run(
            run_name=f"slo-{slo.name}",
            metrics=metrics,
            config=config,
            tags=tags,
        )

    def log_cost_series(self, agent_id: str, costs: list[float]) -> WandBRun:
        """Log cost trajectory as a W&B run.

        Args:
            agent_id: Agent identifier.
            costs: List of cost values.

        Returns:
            The created WandBRun.
        """
        metrics: dict[str, Any] = {
            "total_cost": sum(costs),
            "num_steps": len(costs),
            "avg_cost": sum(costs) / len(costs) if costs else 0.0,
            "max_cost": max(costs) if costs else 0.0,
        }
        return self.log_run(
            run_name=f"cost-{agent_id}",
            metrics=metrics,
            config={"agent_id": agent_id},
            tags=["cost", f"agent:{agent_id}"],
        )

    def clear(self) -> None:
        """Clear all recorded runs."""
        self._runs.clear()

    def get_stats(self) -> dict[str, Any]:
        """Get exporter statistics."""
        return {
            "project": self._project,
            "total_runs": len(self._runs),
            "is_offline": self._offline,
        }
