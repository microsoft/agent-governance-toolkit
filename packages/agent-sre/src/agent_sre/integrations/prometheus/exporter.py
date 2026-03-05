# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Prometheus text format exporter for Agent-SRE metrics."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any


@dataclass
class MetricSample:
    """A single metric sample."""
    name: str
    value: float
    labels: dict[str, str] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    metric_type: str = "gauge"  # gauge, counter, histogram
    help_text: str = ""


class PrometheusExporter:
    """Export Agent-SRE metrics in Prometheus text format.

    Generates metrics in the Prometheus exposition format that can be
    scraped by a Prometheus server via a /metrics endpoint.

    No external dependencies — generates text format directly.
    """

    def __init__(self) -> None:
        self._gauges: dict[str, MetricSample] = {}
        self._counters: dict[str, MetricSample] = {}
        self._help: dict[str, str] = {}
        self._type: dict[str, str] = {}

    def _label_key(self, name: str, labels: dict[str, str]) -> str:
        """Create a unique key for a metric + label combination."""
        sorted_labels = sorted(labels.items())
        label_str = ",".join(f'{k}="{v}"' for k, v in sorted_labels)
        return f"{name}{{{label_str}}}" if label_str else name

    def set_gauge(self, name: str, value: float, labels: dict[str, str] | None = None,
                  help_text: str = "") -> None:
        """Set a gauge metric value."""
        labels = labels or {}
        key = self._label_key(name, labels)
        self._gauges[key] = MetricSample(name=name, value=value, labels=labels, metric_type="gauge")
        if help_text:
            self._help[name] = help_text
        self._type[name] = "gauge"

    def inc_counter(self, name: str, value: float = 1.0, labels: dict[str, str] | None = None,
                    help_text: str = "") -> None:
        """Increment a counter metric."""
        labels = labels or {}
        key = self._label_key(name, labels)
        if key in self._counters:
            self._counters[key].value += value
        else:
            self._counters[key] = MetricSample(name=name, value=value, labels=labels, metric_type="counter")
        if help_text:
            self._help[name] = help_text
        self._type[name] = "counter"

    def export_slo(self, slo: Any, agent_id: str = "") -> None:
        """Export SLO metrics to Prometheus format."""
        status = slo.evaluate()
        labels = {"slo": slo.name}
        if agent_id:
            labels["agent_id"] = agent_id

        status_codes = {"healthy": 0, "warning": 1, "critical": 2, "exhausted": 3, "unknown": -1}
        self.set_gauge("agent_sre_slo_status", float(status_codes.get(status.value, -1)),
                       labels, "Current SLO status (0=healthy, 1=warning, 2=critical, 3=exhausted)")
        self.set_gauge("agent_sre_slo_budget_remaining", slo.error_budget.remaining,
                       labels, "Error budget remaining (0.0-1.0)")
        self.set_gauge("agent_sre_slo_burn_rate", slo.error_budget.burn_rate(),
                       labels, "Current error budget burn rate")

    def render(self) -> str:
        """Render all metrics in Prometheus text exposition format."""
        lines: list[str] = []
        seen_meta: set[str] = set()

        all_samples = list(self._gauges.values()) + list(self._counters.values())
        all_samples.sort(key=lambda s: s.name)

        for sample in all_samples:
            if sample.name not in seen_meta:
                if sample.name in self._help:
                    lines.append(f"# HELP {sample.name} {self._help[sample.name]}")
                lines.append(f"# TYPE {sample.name} {self._type.get(sample.name, 'gauge')}")
                seen_meta.add(sample.name)

            if sample.labels:
                label_str = ",".join(f'{k}="{v}"' for k, v in sorted(sample.labels.items()))
                lines.append(f"{sample.name}{{{label_str}}} {sample.value}")
            else:
                lines.append(f"{sample.name} {sample.value}")

        return "\n".join(lines) + "\n" if lines else ""

    def clear(self) -> None:
        self._gauges.clear()
        self._counters.clear()
        self._help.clear()
        self._type.clear()

    def get_stats(self) -> dict[str, int]:
        return {
            "gauges": len(self._gauges),
            "counters": len(self._counters),
        }
