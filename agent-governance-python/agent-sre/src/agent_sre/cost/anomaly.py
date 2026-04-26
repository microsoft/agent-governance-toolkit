# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""Cost anomaly detection — simple threshold-based alerting."""

from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class AnomalyMethod(Enum):
    """Anomaly detection method."""
    THRESHOLD = "threshold"


class AnomalySeverity(Enum):
    """Severity of a detected anomaly."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class CostDataPoint:
    """A single cost data point for analysis."""
    value: float
    timestamp: float = field(default_factory=time.time)
    agent_id: str = ""
    task_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "value": self.value,
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "task_id": self.task_id,
        }


@dataclass
class AnomalyResult:
    """Result of anomaly detection analysis."""
    is_anomaly: bool
    severity: AnomalySeverity
    method: AnomalyMethod
    value: float
    expected_range: tuple[float, float]
    score: float
    message: str = ""
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_anomaly": self.is_anomaly,
            "severity": self.severity.value,
            "method": self.method.value,
            "value": round(self.value, 4),
            "expected_range": [round(self.expected_range[0], 4), round(self.expected_range[1], 4)],
            "score": round(self.score, 2),
            "message": self.message,
        }


@dataclass
class BaselineStats:
    """Statistical baseline for cost analysis."""
    mean: float = 0.0
    std_dev: float = 0.0
    sample_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "mean": round(self.mean, 4),
            "std_dev": round(self.std_dev, 4),
            "sample_count": self.sample_count,
        }


class CostAnomalyDetector:
    """Simple threshold-based cost anomaly detection.

    Detects anomalies when costs exceed a threshold above the running average.
    """

    def __init__(
        self,
        z_threshold: float = 2.5,
        iqr_multiplier: float = 1.5,
        ewma_alpha: float = 0.3,
        min_samples: int = 10,
        window_size: int = 1000,
    ) -> None:
        self.z_threshold = z_threshold
        self.min_samples = min_samples
        self._data: deque[CostDataPoint] = deque(maxlen=window_size)
        self._anomalies: list[AnomalyResult] = []

    @property
    def baseline(self) -> BaselineStats:
        """Compute current baseline statistics."""
        values = [d.value for d in self._data]
        if not values:
            return BaselineStats()

        n = len(values)
        mean = sum(values) / n
        variance = sum((x - mean) ** 2 for x in values) / n if n > 1 else 0.0
        std_dev = math.sqrt(variance)

        return BaselineStats(mean=mean, std_dev=std_dev, sample_count=n)

    def ingest(self, value: float, agent_id: str = "", task_id: str = "") -> AnomalyResult | None:
        """Ingest a cost data point and check for anomalies.

        Returns AnomalyResult if anomaly detected, None otherwise.
        """
        point = CostDataPoint(value=value, agent_id=agent_id, task_id=task_id)
        self._data.append(point)

        if len(self._data) < self.min_samples:
            return None

        stats = self.baseline
        if stats.std_dev == 0:
            return None

        z = abs(value - stats.mean) / stats.std_dev
        if z > self.z_threshold:
            lower = max(0, stats.mean - self.z_threshold * stats.std_dev)
            upper = stats.mean + self.z_threshold * stats.std_dev
            severity = AnomalySeverity.HIGH if z > 3.0 else AnomalySeverity.MEDIUM
            result = AnomalyResult(
                is_anomaly=True,
                severity=severity,
                method=AnomalyMethod.THRESHOLD,
                value=value,
                expected_range=(lower, upper),
                score=z,
                message=f"Cost {value:.4f} exceeds threshold (z-score: {z:.1f})",
            )
            self._anomalies.append(result)
            return result
        return None

    @property
    def anomalies(self) -> list[AnomalyResult]:
        return self._anomalies

    def summary(self) -> dict[str, Any]:
        return {
            "baseline": self.baseline.to_dict(),
            "total_anomalies": len(self._anomalies),
        }
