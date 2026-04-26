# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
A/B Testing Engine for Agent-SRE.

Compare agent variants (prompt changes, model swaps, tool configs)
using statistical methods. Integrates with the SLO engine to measure
impact on reliability indicators.

Components:
- Experiment: A/B test definition with variants and metrics
- TrafficSplitter: Route tasks to variants by percentage
- ExperimentResult: Statistical comparison with significance testing
"""

from __future__ import annotations

import math
import random
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class ExperimentStatus(Enum):
    DRAFT = "draft"
    RUNNING = "running"
    COMPLETED = "completed"
    ABORTED = "aborted"


class SignificanceLevel(Enum):
    NOT_SIGNIFICANT = "not_significant"
    MARGINALLY = "marginally"
    SIGNIFICANT = "significant"
    HIGHLY_SIGNIFICANT = "highly_significant"


@dataclass
class Variant:
    """A variant in an A/B experiment."""

    name: str
    description: str = ""
    weight: float = 0.5
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class MetricSample:
    """A single metric observation for a variant."""

    variant_name: str
    metric_name: str
    value: float
    timestamp: float = field(default_factory=time.time)


@dataclass
class MetricSummary:
    """Statistical summary for a metric across variants."""

    metric_name: str
    variant_a: str
    variant_b: str
    mean_a: float = 0.0
    mean_b: float = 0.0
    std_a: float = 0.0
    std_b: float = 0.0
    n_a: int = 0
    n_b: int = 0
    difference: float = 0.0
    relative_improvement: float = 0.0
    p_value: float = 1.0
    significance: SignificanceLevel = SignificanceLevel.NOT_SIGNIFICANT
    winner: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "metric": self.metric_name,
            "variant_a": {"name": self.variant_a, "mean": round(self.mean_a, 4), "n": self.n_a},
            "variant_b": {"name": self.variant_b, "mean": round(self.mean_b, 4), "n": self.n_b},
            "difference": round(self.difference, 4),
            "relative_improvement": f"{self.relative_improvement:.1%}",
            "p_value": round(self.p_value, 4),
            "significance": self.significance.value,
            "winner": self.winner,
        }


class Experiment:
    """
    An A/B experiment comparing agent variants.

    Usage:
        exp = Experiment(
            name="prompt-v2-test",
            variants=[Variant("control"), Variant("treatment")],
            metrics=["task_success_rate", "avg_latency_ms"],
        )
        exp.start()
        variant = exp.assign()
        exp.record(variant, "task_success_rate", 1.0)
        results = exp.analyze()
    """

    def __init__(
        self,
        name: str,
        variants: list[Variant] | None = None,
        metrics: list[str] | None = None,
        min_samples: int = 30,
        description: str = "",
    ) -> None:
        self.name = name
        self.description = description
        self.variants = variants or [Variant("control"), Variant("treatment")]
        self.metrics = metrics or ["task_success_rate"]
        self.min_samples = min_samples
        self.status = ExperimentStatus.DRAFT
        self._samples: list[MetricSample] = []
        self._assignments: dict[str, int] = {v.name: 0 for v in self.variants}
        self._started_at: float = 0.0
        self._ended_at: float = 0.0

    def start(self) -> None:
        self.status = ExperimentStatus.RUNNING
        self._started_at = time.time()

    def stop(self) -> None:
        self.status = ExperimentStatus.COMPLETED
        self._ended_at = time.time()

    def abort(self) -> None:
        self.status = ExperimentStatus.ABORTED
        self._ended_at = time.time()

    def assign(self) -> str:
        if self.status != ExperimentStatus.RUNNING:
            return self.variants[0].name

        r = random.random()  # noqa: S311 — non-cryptographic use for experiment randomization
        cumulative = 0.0
        for v in self.variants:
            cumulative += v.weight
            if r < cumulative:
                self._assignments[v.name] = self._assignments.get(v.name, 0) + 1
                return v.name

        name = self.variants[-1].name
        self._assignments[name] = self._assignments.get(name, 0) + 1
        return name

    def record(self, variant_name: str, metric_name: str, value: float) -> None:
        self._samples.append(MetricSample(
            variant_name=variant_name, metric_name=metric_name, value=value,
        ))

    def _get_values(self, variant_name: str, metric_name: str) -> list[float]:
        return [
            s.value for s in self._samples
            if s.variant_name == variant_name and s.metric_name == metric_name
        ]

    def analyze(self) -> list[MetricSummary]:
        if len(self.variants) < 2:
            return []

        results = []
        va, vb = self.variants[0], self.variants[1]

        for metric in self.metrics:
            values_a = self._get_values(va.name, metric)
            values_b = self._get_values(vb.name, metric)
            summary = _compare(metric, va.name, vb.name, values_a, values_b)
            results.append(summary)

        return results

    def is_ready(self) -> bool:
        for v in self.variants:
            for m in self.metrics:
                if len(self._get_values(v.name, m)) < self.min_samples:
                    return False
        return True

    @property
    def sample_count(self) -> int:
        return len(self._samples)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "variants": [{"name": v.name, "weight": v.weight} for v in self.variants],
            "metrics": self.metrics,
            "samples": self.sample_count,
            "assignments": self._assignments,
        }


def _std(values: list[float]) -> float:
    if len(values) < 2:
        return 0.0
    n = len(values)
    mean = sum(values) / n
    return math.sqrt(sum((x - mean) ** 2 for x in values) / (n - 1))


def _welch_p_value(m1: float, m2: float, s1: float, s2: float, n1: int, n2: int) -> float:
    if n1 < 2 or n2 < 2:
        return 1.0
    if s1 == 0 and s2 == 0:
        return 0.0 if m1 != m2 else 1.0
    se = math.sqrt((s1 ** 2) / n1 + (s2 ** 2) / n2)
    if se == 0:
        return 0.0 if m1 != m2 else 1.0
    t = abs(m1 - m2) / se
    return max(0.0, min(1.0, 2.0 * 0.5 * (1.0 + math.erf(-t / math.sqrt(2.0)))))


def _compare(
    metric: str, name_a: str, name_b: str,
    values_a: list[float], values_b: list[float],
) -> MetricSummary:
    n_a, n_b = len(values_a), len(values_b)
    mean_a = sum(values_a) / n_a if n_a else 0.0
    mean_b = sum(values_b) / n_b if n_b else 0.0
    std_a = _std(values_a) if n_a > 1 else 0.0
    std_b = _std(values_b) if n_b > 1 else 0.0

    diff = mean_b - mean_a
    rel = diff / mean_a if mean_a != 0 else 0.0
    p = _welch_p_value(mean_a, mean_b, std_a, std_b, n_a, n_b)

    if p < 0.01:
        sig = SignificanceLevel.HIGHLY_SIGNIFICANT
    elif p < 0.05:
        sig = SignificanceLevel.SIGNIFICANT
    elif p < 0.10:
        sig = SignificanceLevel.MARGINALLY
    else:
        sig = SignificanceLevel.NOT_SIGNIFICANT

    winner = ""
    if sig in (SignificanceLevel.SIGNIFICANT, SignificanceLevel.HIGHLY_SIGNIFICANT):
        winner = name_b if mean_b > mean_a else name_a

    return MetricSummary(
        metric_name=metric, variant_a=name_a, variant_b=name_b,
        mean_a=mean_a, mean_b=mean_b, std_a=std_a, std_b=std_b,
        n_a=n_a, n_b=n_b, difference=diff, relative_improvement=rel,
        p_value=p, significance=sig, winner=winner,
    )
