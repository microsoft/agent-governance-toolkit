# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""LangSmith exporter — run-based tracing and evaluation feedback.

Exports Agent-SRE data as LangSmith runs with parent-child relationships
and evaluation feedback.

Operates in two modes:
- **Live mode**: Sends data to LangSmith API (when api_key is provided)
- **Offline mode**: Stores records in memory (when api_key is empty)

No LangSmith dependency required — uses duck-typed client protocol.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class RunRecord:
    """A LangSmith run record."""

    run_id: str
    name: str
    run_type: str = "chain"
    inputs: dict[str, Any] | None = None
    outputs: dict[str, Any] | None = None
    parent_run_id: str | None = None
    tags: list[str] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: float | None = None
    error: str | None = None


@dataclass
class FeedbackRecord:
    """A LangSmith feedback record."""

    run_id: str
    key: str
    score: float
    comment: str = ""
    timestamp: float = field(default_factory=time.time)


class LangSmithExporter:
    """Export Agent SRE data to LangSmith.

    Provides run-based tracing and evaluation feedback:
    1. **Runs**: Create and end runs with inputs/outputs
    2. **Feedback**: Add evaluation scores to runs
    3. **SLO export**: Map SLO evaluations to run feedback

    Args:
        api_key: LangSmith API key. Empty string for offline mode.
        project_name: LangSmith project name.

    Example:
        from agent_sre.integrations.langsmith import LangSmithExporter

        exporter = LangSmithExporter()
        run = exporter.create_run("my-task", inputs={"query": "hello"})
        exporter.end_run(run.run_id, outputs={"response": "hi"})
    """

    def __init__(
        self,
        api_key: str = "",
        project_name: str = "agent-sre",
    ) -> None:
        self._api_key = api_key
        self._offline = not bool(api_key)
        self.project_name = project_name

        self._runs: list[RunRecord] = []
        self._feedbacks: list[FeedbackRecord] = []

    @property
    def is_offline(self) -> bool:
        """True if operating in offline/test mode."""
        return self._offline

    @property
    def runs(self) -> list[RunRecord]:
        """Get recorded runs."""
        return list(self._runs)

    @property
    def feedbacks(self) -> list[FeedbackRecord]:
        """Get recorded feedbacks."""
        return list(self._feedbacks)

    def create_run(
        self,
        name: str,
        run_type: str = "chain",
        inputs: dict[str, Any] | None = None,
        parent_run_id: str | None = None,
        tags: list[str] | None = None,
    ) -> RunRecord:
        """Start a new run.

        Args:
            name: Run name
            run_type: Run type (chain, llm, tool, retriever)
            inputs: Optional input data
            parent_run_id: Optional parent run ID for nesting
            tags: Optional list of tags

        Returns:
            The created RunRecord
        """
        run = RunRecord(
            run_id=str(uuid.uuid4()),
            name=name,
            run_type=run_type,
            inputs=inputs,
            parent_run_id=parent_run_id,
            tags=tags or [],
        )
        self._runs.append(run)

        if not self._offline:
            self._send_run_create(run)

        return run

    def end_run(
        self,
        run_id: str,
        outputs: dict[str, Any] | None = None,
        error: str | None = None,
    ) -> RunRecord | None:
        """End a run.

        Args:
            run_id: Run ID to end
            outputs: Optional output data
            error: Optional error message

        Returns:
            The updated RunRecord, or None if not found
        """
        for run in self._runs:
            if run.run_id == run_id:
                run.end_time = time.time()
                run.outputs = outputs
                run.error = error

                if not self._offline:
                    self._send_run_update(run)

                return run
        return None

    def add_feedback(
        self,
        run_id: str,
        key: str,
        score: float,
        comment: str = "",
    ) -> FeedbackRecord:
        """Add evaluation feedback to a run.

        Args:
            run_id: Run ID to attach feedback to
            key: Feedback key (e.g. "correctness", "helpfulness")
            score: Score value (typically 0.0-1.0)
            comment: Optional comment

        Returns:
            The created FeedbackRecord
        """
        feedback = FeedbackRecord(
            run_id=run_id,
            key=key,
            score=score,
            comment=comment,
        )
        self._feedbacks.append(feedback)

        if not self._offline:
            self._send_feedback(feedback)

        return feedback

    def export_slo(
        self,
        slo: Any,
        run_id: str | None = None,
    ) -> list[FeedbackRecord]:
        """Export SLO evaluation as feedback on a run.

        Creates feedback records for:
        - slo.status, slo.budget_remaining, slo.burn_rate
        - Per-SLI current values

        Args:
            slo: An agent_sre.slo.objectives.SLO instance
            run_id: Run ID to attach feedback to. If None, creates a new run.

        Returns:
            List of FeedbackRecord objects created
        """
        from agent_sre.integrations.otel.conventions import SLO_STATUS_CODES

        if run_id is None:
            run = self.create_run(f"slo.evaluate/{slo.name}", run_type="chain")
            run_id = run.run_id

        status = slo.evaluate()
        status_code = SLO_STATUS_CODES.get(status.value, -1)
        burn = slo.error_budget.burn_rate()

        feedbacks: list[FeedbackRecord] = []

        feedbacks.append(self.add_feedback(
            run_id=run_id,
            key=f"slo.{slo.name}.status",
            score=float(status_code),
            comment=f"SLO status: {status.value}",
        ))

        feedbacks.append(self.add_feedback(
            run_id=run_id,
            key=f"slo.{slo.name}.budget_remaining",
            score=slo.error_budget.remaining,
            comment=f"Error budget: {slo.error_budget.remaining_percent:.1f}% remaining",
        ))

        feedbacks.append(self.add_feedback(
            run_id=run_id,
            key=f"slo.{slo.name}.burn_rate",
            score=burn,
            comment=f"Burn rate: {burn:.2f}x",
        ))

        for indicator in slo.indicators:
            current = indicator.current_value()
            if current is not None:
                feedbacks.append(self.add_feedback(
                    run_id=run_id,
                    key=f"sli.{indicator.name}",
                    score=current,
                    comment=f"SLI {indicator.name}: {current:.4f}",
                ))

        return feedbacks

    def _send_run_create(self, run: RunRecord) -> None:
        """Send run creation to LangSmith API via urllib."""
        import json
        import urllib.request

        url = "https://api.smith.langchain.com/api/v1/runs"
        payload: dict[str, Any] = {
            "id": run.run_id,
            "name": run.name,
            "run_type": run.run_type,
            "inputs": run.inputs or {},
            "start_time": run.start_time,
            "session_name": self.project_name,
        }
        if run.parent_run_id:
            payload["parent_run_id"] = run.parent_run_id
        if run.tags:
            payload["tags"] = run.tags

        data = json.dumps(payload).encode()
        req = urllib.request.Request(  # noqa: S310 — LangSmith API endpoint URL
            url,
            data=data,
            headers={
                "x-api-key": self._api_key,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            urllib.request.urlopen(req)  # noqa: S310 — LangSmith API endpoint URL
        except Exception as e:
            logger.warning(f"Failed to create run in LangSmith: {e}")

    def _send_run_update(self, run: RunRecord) -> None:
        """Send run update to LangSmith API via urllib."""
        import json
        import urllib.request

        url = f"https://api.smith.langchain.com/api/v1/runs/{run.run_id}"
        payload: dict[str, Any] = {
            "end_time": run.end_time,
        }
        if run.outputs:
            payload["outputs"] = run.outputs
        if run.error:
            payload["error"] = run.error

        data = json.dumps(payload).encode()
        req = urllib.request.Request(  # noqa: S310 — LangSmith API endpoint URL
            url,
            data=data,
            headers={
                "x-api-key": self._api_key,
                "Content-Type": "application/json",
            },
            method="PATCH",
        )
        try:
            urllib.request.urlopen(req)  # noqa: S310 — LangSmith API endpoint URL
        except Exception as e:
            logger.warning(f"Failed to update run in LangSmith: {e}")

    def _send_feedback(self, feedback: FeedbackRecord) -> None:
        """Send feedback to LangSmith API via urllib."""
        import json
        import urllib.request

        url = "https://api.smith.langchain.com/api/v1/feedback"
        payload = {
            "run_id": feedback.run_id,
            "key": feedback.key,
            "score": feedback.score,
            "comment": feedback.comment,
        }
        data = json.dumps(payload).encode()
        req = urllib.request.Request(  # noqa: S310 — LangSmith API endpoint URL
            url,
            data=data,
            headers={
                "x-api-key": self._api_key,
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            urllib.request.urlopen(req)  # noqa: S310 — LangSmith API endpoint URL
        except Exception as e:
            logger.warning(f"Failed to send feedback to LangSmith: {e}")

    def clear(self) -> None:
        """Clear all offline storage."""
        self._runs.clear()
        self._feedbacks.clear()

    def get_stats(self) -> dict[str, Any]:
        """Get statistics about recorded data."""
        return {
            "total_runs": len(self._runs),
            "total_feedbacks": len(self._feedbacks),
            "completed_runs": sum(1 for r in self._runs if r.end_time is not None),
            "error_runs": sum(1 for r in self._runs if r.error is not None),
            "project": self.project_name,
        }
