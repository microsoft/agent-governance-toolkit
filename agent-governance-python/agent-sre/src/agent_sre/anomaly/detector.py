# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Behavioral anomaly detection engine.

Learns normal agent behavior from metrics and traces, then flags
deviations that may indicate failures, attacks, or degradation.
"""

from __future__ import annotations

import logging
import math
import time
from collections import deque
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class AnomalyType(Enum):
    """Types of behavioral anomalies."""

    LATENCY_SPIKE = "latency_spike"
    THROUGHPUT_DROP = "throughput_drop"
    ERROR_RATE_SURGE = "error_rate_surge"
    UNUSUAL_TOOL_SEQUENCE = "unusual_tool_sequence"
    TOKEN_USAGE_SPIKE = "token_usage_spike"  # noqa: S105 — not a password, anomaly type constant name
    API_CALL_VOLUME = "api_call_volume"
    OUTPUT_DRIFT = "output_drift"
    RESOURCE_EXHAUSTION = "resource_exhaustion"


class AnomalySeverity(Enum):
    """Severity of a detected anomaly."""

    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class AnomalyAlert:
    """Alert raised when a behavioral anomaly is detected."""

    anomaly_type: AnomalyType
    severity: AnomalySeverity
    score: float
    message: str
    agent_id: str
    timestamp: float = field(default_factory=time.time)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "anomaly_type": self.anomaly_type.value,
            "severity": self.severity.value,
            "score": round(self.score, 4),
            "message": self.message,
            "agent_id": self.agent_id,
            "timestamp": self.timestamp,
            "details": self.details,
        }


@dataclass
class BehaviorBaseline:
    """Statistical baseline for a single metric."""

    mean: float = 0.0
    std_dev: float = 0.0
    sample_count: int = 0
    min_val: float = float("inf")
    max_val: float = float("-inf")
    p95: float = 0.0
    p99: float = 0.0
    last_updated: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        return {
            "mean": round(self.mean, 4),
            "std_dev": round(self.std_dev, 4),
            "sample_count": self.sample_count,
            "min_val": round(self.min_val, 4) if self.min_val != float("inf") else None,
            "max_val": round(self.max_val, 4) if self.max_val != float("-inf") else None,
            "p95": round(self.p95, 4),
            "p99": round(self.p99, 4),
        }


@dataclass
class DetectorConfig:
    """Configuration for the anomaly detector."""

    window_size: int = 1000
    z_threshold: float = 2.5
    iqr_multiplier: float = 1.5
    min_samples: int = 20
    severity_thresholds: dict[str, AnomalySeverity] = field(default_factory=lambda: {
        "low": AnomalySeverity.INFO,
        "medium": AnomalySeverity.WARNING,
        "high": AnomalySeverity.CRITICAL,
    })
    enabled_strategies: list[str] = field(
        default_factory=lambda: ["statistical", "sequential", "resource"],
    )


def _percentile(sorted_vals: list[float], pct: float) -> float:
    """Return the *pct*-th percentile from a pre-sorted list."""
    if not sorted_vals:
        return 0.0
    k = (len(sorted_vals) - 1) * pct / 100.0
    f = int(k)
    c = f + 1
    if c >= len(sorted_vals):
        return sorted_vals[-1]
    return sorted_vals[f] + (k - f) * (sorted_vals[c] - sorted_vals[f])


class AnomalyDetector:
    """Behavioral anomaly detector for agent metrics.

    Maintains rolling windows and baselines per metric, runs detection
    strategies, and produces ``AnomalyAlert`` objects.
    """

    def __init__(self, config: DetectorConfig | None = None) -> None:
        self._config = config or DetectorConfig()
        self._baselines: dict[str, BehaviorBaseline] = {}
        self._windows: dict[str, deque[float]] = {}
        self._alerts: list[AnomalyAlert] = []
        self._sequence_buffer: dict[str, list[str]] = {}

        # Lazily-initialized strategy instances (imported here to avoid
        # circular import at module level).
        self._statistical: Any = None
        self._sequential: Any = None
        self._resource: Any = None

    # -- strategies (lazy init) ------------------------------------------

    def _get_statistical(self) -> Any:
        if self._statistical is None:
            from agent_sre.anomaly.strategies import StatisticalStrategy

            self._statistical = StatisticalStrategy(
                z_threshold=self._config.z_threshold,
                iqr_multiplier=self._config.iqr_multiplier,
            )
        return self._statistical

    def _get_sequential(self) -> Any:
        if self._sequential is None:
            from agent_sre.anomaly.strategies import SequentialStrategy

            self._sequential = SequentialStrategy()
        return self._sequential

    def _get_resource(self) -> Any:
        if self._resource is None:
            from agent_sre.anomaly.strategies import ResourceStrategy

            self._resource = ResourceStrategy()
        return self._resource

    # -- baseline management ---------------------------------------------

    def _update_baseline(self, metric_name: str) -> BehaviorBaseline:
        """Recompute baseline statistics from the rolling window."""
        window = self._windows.get(metric_name)
        if not window:
            return BehaviorBaseline()

        values = list(window)
        n = len(values)
        mean = sum(values) / n
        variance = sum((x - mean) ** 2 for x in values) / n if n > 1 else 0.0
        std_dev = math.sqrt(variance)

        sorted_vals = sorted(values)
        baseline = BehaviorBaseline(
            mean=mean,
            std_dev=std_dev,
            sample_count=n,
            min_val=sorted_vals[0],
            max_val=sorted_vals[-1],
            p95=_percentile(sorted_vals, 95),
            p99=_percentile(sorted_vals, 99),
            last_updated=time.time(),
        )
        self._baselines[metric_name] = baseline
        return baseline

    # -- public API -------------------------------------------------------

    def ingest(
        self,
        metric_name: str,
        value: float,
        agent_id: str = "default",
        metadata: dict[str, Any] | None = None,
    ) -> AnomalyAlert | None:
        """Ingest a metric data point and check for anomalies.

        Returns an ``AnomalyAlert`` if an anomaly is detected, ``None``
        otherwise.
        """
        if metric_name not in self._windows:
            self._windows[metric_name] = deque(maxlen=self._config.window_size)

        self._windows[metric_name].append(value)
        baseline = self._update_baseline(metric_name)

        if baseline.sample_count < self._config.min_samples:
            return None

        # --- Statistical check ---
        if "statistical" in self._config.enabled_strategies:
            stat = self._get_statistical()
            is_anomaly, z_score = stat.check_zscore(value, baseline.mean, baseline.std_dev)
            if is_anomaly:
                severity = stat.determine_severity(z_score)
                alert = AnomalyAlert(
                    anomaly_type=_infer_anomaly_type(metric_name),
                    severity=severity,
                    score=z_score,
                    message=(
                        f"{metric_name} value {value:.4f} deviates from baseline "
                        f"(z-score: {z_score:.1f})"
                    ),
                    agent_id=agent_id,
                    details={
                        "metric": metric_name,
                        "value": value,
                        "mean": baseline.mean,
                        "std_dev": baseline.std_dev,
                        "z_score": z_score,
                        **(metadata or {}),
                    },
                )
                self._alerts.append(alert)
                logger.info("Anomaly detected: %s", alert.message)
                return alert

        # --- Resource check ---
        if "resource" in self._config.enabled_strategies:
            res = self._get_resource()
            is_anomaly, score = res.check_resource(metric_name, value, baseline)
            if is_anomaly:
                severity = self._get_statistical().determine_severity(score)
                alert = AnomalyAlert(
                    anomaly_type=AnomalyType.RESOURCE_EXHAUSTION,
                    severity=severity,
                    score=score,
                    message=f"{metric_name} resource limit exceeded (score: {score:.2f})",
                    agent_id=agent_id,
                    details={"metric": metric_name, "value": value, **(metadata or {})},
                )
                self._alerts.append(alert)
                logger.info("Resource anomaly detected: %s", alert.message)
                return alert

        return None

    def record_tool_call(
        self,
        agent_id: str,
        tool_name: str,
        timestamp: float | None = None,
    ) -> AnomalyAlert | None:
        """Record a tool call and check for unusual sequences.

        Returns an ``AnomalyAlert`` if a rare transition is detected.
        """
        if agent_id not in self._sequence_buffer:
            self._sequence_buffer[agent_id] = []

        seq = self._sequence_buffer[agent_id]

        if "sequential" in self._config.enabled_strategies and seq:
            strat = self._get_sequential()
            is_anomaly, score, explanation = strat.check_sequence(seq, tool_name)
            if is_anomaly:
                severity = self._get_statistical().determine_severity(
                    score * 4.0,  # scale to severity range
                )
                alert = AnomalyAlert(
                    anomaly_type=AnomalyType.UNUSUAL_TOOL_SEQUENCE,
                    severity=severity,
                    score=score,
                    message=f"Unusual tool sequence for agent {agent_id}: {explanation}",
                    agent_id=agent_id,
                    timestamp=timestamp or time.time(),
                    details={"tool_name": tool_name, "explanation": explanation},
                )
                self._alerts.append(alert)
                logger.info("Sequence anomaly detected: %s", alert.message)
                # Append after check so the sequence is available on next call
                seq.append(tool_name)
                # Trim to max length
                max_len = self._get_sequential().max_sequence_length
                if len(seq) > max_len:
                    self._sequence_buffer[agent_id] = seq[-max_len:]
                return alert

        seq.append(tool_name)
        # Trim to max length
        if self._sequential is not None:
            max_len = self._get_sequential().max_sequence_length
            if len(seq) > max_len:
                self._sequence_buffer[agent_id] = seq[-max_len:]

        return None

    def get_baseline(self, metric_name: str) -> BehaviorBaseline | None:
        """Return current baseline for a metric, or ``None``."""
        return self._baselines.get(metric_name)

    @property
    def alerts(self) -> list[AnomalyAlert]:
        """Return a copy of the alert history."""
        return list(self._alerts)

    def summary(self) -> dict[str, Any]:
        """Return a summary of detector state."""
        by_type: dict[str, int] = {}
        by_severity: dict[str, int] = {}
        for alert in self._alerts:
            by_type[alert.anomaly_type.value] = by_type.get(alert.anomaly_type.value, 0) + 1
            by_severity[alert.severity.value] = by_severity.get(alert.severity.value, 0) + 1

        return {
            "baselines_count": len(self._baselines),
            "total_alerts": len(self._alerts),
            "alerts_by_type": by_type,
            "alerts_by_severity": by_severity,
        }

    def reset(self, metric_name: str | None = None) -> None:
        """Reset baselines and windows for *metric_name*, or all if ``None``."""
        if metric_name is None:
            self._baselines.clear()
            self._windows.clear()
            self._alerts.clear()
            self._sequence_buffer.clear()
        else:
            self._baselines.pop(metric_name, None)
            self._windows.pop(metric_name, None)


# -- helpers --------------------------------------------------------------

def _infer_anomaly_type(metric_name: str) -> AnomalyType:
    """Best-effort mapping from metric name to anomaly type."""
    name = metric_name.lower()
    if "latency" in name or "duration" in name:
        return AnomalyType.LATENCY_SPIKE
    if "throughput" in name or "rate" in name:
        return AnomalyType.THROUGHPUT_DROP
    if "error" in name:
        return AnomalyType.ERROR_RATE_SURGE
    if "token" in name:
        return AnomalyType.TOKEN_USAGE_SPIKE
    if "api" in name or "call" in name:
        return AnomalyType.API_CALL_VOLUME
    return AnomalyType.OUTPUT_DRIFT
