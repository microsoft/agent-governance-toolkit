# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Phoenix Exporter — export Agent-SRE data as Phoenix-compatible spans.

Phoenix (by Arize AI) uses OTEL-compatible spans with specific attributes
for LLM observability. This exporter maps Agent-SRE data to Phoenix's format.

No Phoenix/Arize dependency — produces dicts that can be sent to Phoenix
via its REST API or OTEL collector.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class PhoenixSpan:
    """A Phoenix-compatible span representation."""

    span_id: str = field(default_factory=lambda: str(uuid.uuid4())[:16])
    trace_id: str = ""
    parent_id: str = ""
    name: str = ""
    span_kind: str = "CHAIN"  # CHAIN, LLM, RETRIEVER, TOOL, AGENT, EVALUATOR
    start_time: float = 0.0
    end_time: float = 0.0
    status: str = "OK"  # OK, ERROR
    attributes: dict[str, Any] = field(default_factory=dict)
    events: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "context": {
                "span_id": self.span_id,
                "trace_id": self.trace_id,
            },
            "name": self.name,
            "span_kind": self.span_kind,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "status_code": self.status,
            "attributes": self.attributes,
        }
        if self.parent_id:
            d["parent_id"] = self.parent_id
        if self.events:
            d["events"] = self.events
        return d


class PhoenixExporter:
    """
    Export Agent-SRE SLO, cost, and trace data as Phoenix-compatible spans.

    Works in two modes:
    - Offline: stores spans in memory for testing/batch export
    - Live: sends spans to a callback function (e.g. Phoenix REST API)

    Phoenix attributes follow their conventions:
    - ``openinference.span.kind``: LLM, CHAIN, TOOL, AGENT, etc.
    - ``llm.token_count.prompt``, ``llm.token_count.completion``
    - ``output.value``, ``input.value``
    """

    def __init__(
        self,
        on_span: Any | None = None,
        project_name: str = "agent-sre",
    ):
        """
        Args:
            on_span: Callback function(PhoenixSpan) for live mode.
                     If None, operates in offline/memory mode.
            project_name: Phoenix project name for span metadata.
        """
        self._on_span = on_span
        self.project_name = project_name
        self._spans: list[PhoenixSpan] = []

    @property
    def is_offline(self) -> bool:
        return self._on_span is None

    def _emit(self, span: PhoenixSpan) -> None:
        if self._on_span:
            try:
                self._on_span(span)
            except Exception:
                logger.debug("on_span callback failed", exc_info=True)
        self._spans.append(span)

    def export_slo_evaluation(
        self,
        slo_name: str,
        status: str,
        budget_remaining: float,
        burn_rate: float,
        indicators: dict[str, float] | None = None,
        trace_id: str = "",
    ) -> PhoenixSpan:
        """Export an SLO evaluation as a Phoenix EVALUATOR span."""
        span = PhoenixSpan(
            trace_id=trace_id or str(uuid.uuid4())[:32],
            name=f"slo.evaluate/{slo_name}",
            span_kind="EVALUATOR",
            start_time=time.time(),
            end_time=time.time(),
            status="OK" if status in ("healthy", "warning") else "ERROR",
            attributes={
                "openinference.span.kind": "EVALUATOR",
                "slo.name": slo_name,
                "slo.status": status,
                "slo.budget_remaining": budget_remaining,
                "slo.burn_rate": burn_rate,
                "project.name": self.project_name,
            },
        )
        if indicators:
            for k, v in indicators.items():
                span.attributes[f"sli.{k}"] = v

        self._emit(span)
        return span

    def export_cost_record(
        self,
        agent_id: str,
        task_id: str,
        cost_usd: float,
        breakdown: dict[str, float] | None = None,
        trace_id: str = "",
    ) -> PhoenixSpan:
        """Export a cost record as a Phoenix span with cost attributes."""
        span = PhoenixSpan(
            trace_id=trace_id or str(uuid.uuid4())[:32],
            name=f"cost.record/{agent_id}",
            span_kind="CHAIN",
            start_time=time.time(),
            end_time=time.time(),
            attributes={
                "openinference.span.kind": "CHAIN",
                "agent.id": agent_id,
                "task.id": task_id,
                "cost.total_usd": cost_usd,
                "project.name": self.project_name,
            },
        )
        if breakdown:
            for k, v in breakdown.items():
                span.attributes[f"cost.{k}_usd"] = v

        self._emit(span)
        return span

    def export_incident(
        self,
        incident_id: str,
        severity: str,
        description: str,
        agent_id: str = "",
        trace_id: str = "",
    ) -> PhoenixSpan:
        """Export an incident as a Phoenix span."""
        span = PhoenixSpan(
            trace_id=trace_id or str(uuid.uuid4())[:32],
            name=f"incident/{incident_id}",
            span_kind="CHAIN",
            start_time=time.time(),
            end_time=time.time(),
            status="ERROR",
            attributes={
                "openinference.span.kind": "CHAIN",
                "incident.id": incident_id,
                "incident.severity": severity,
                "incident.description": description,
                "project.name": self.project_name,
            },
        )
        if agent_id:
            span.attributes["agent.id"] = agent_id

        self._emit(span)
        return span

    @property
    def spans(self) -> list[PhoenixSpan]:
        return list(self._spans)

    def clear(self) -> None:
        self._spans.clear()

    def get_stats(self) -> dict[str, Any]:
        return {
            "total_spans": len(self._spans),
            "evaluator_spans": sum(1 for s in self._spans if s.span_kind == "EVALUATOR"),
            "error_spans": sum(1 for s in self._spans if s.status == "ERROR"),
            "project": self.project_name,
        }
