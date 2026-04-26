# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic implementation
"""Service Level Indicators for AI agent systems."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from agent_sre.slo.persistence import InMemoryMeasurementStore, MeasurementStore


class TimeWindow(Enum):
    """Standard time windows for SLI aggregation."""

    HOUR_1 = "1h"
    HOUR_6 = "6h"
    DAY_1 = "24h"
    DAY_7 = "7d"
    DAY_30 = "30d"

    @property
    def seconds(self) -> int:
        _map = {"1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800, "30d": 2592000}
        return _map[self.value]


@dataclass(frozen=True)
class SLIValue:
    """A single SLI measurement."""

    name: str
    value: float
    timestamp: float = field(default_factory=time.time)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def is_good(self) -> bool:
        """True if value meets the target (assumes target stored in metadata)."""
        target = self.metadata.get("target")
        if target is None:
            return True
        return bool(self.value >= target)


class SLI(ABC):
    """Base class for Service Level Indicators.

    An SLI measures one aspect of agent reliability (e.g., task success rate,
    tool call accuracy, response latency).
    """

    def __init__(
        self,
        name: str,
        target: float,
        window: TimeWindow | str,
        store: MeasurementStore | None = None,
    ) -> None:
        self.name = name
        self.target = target
        self.window = TimeWindow(window) if isinstance(window, str) else window
        self._store: MeasurementStore = store if store is not None else InMemoryMeasurementStore()
        # Backward-compat alias — external code that appends directly to ._measurements
        # still works when using the default InMemoryMeasurementStore.
        self._measurements: list[SLIValue] = (
            self._store._rows  # type: ignore[attr-defined]
            if isinstance(self._store, InMemoryMeasurementStore)
            else []
        )

    @abstractmethod
    def collect(self) -> SLIValue:
        """Collect a new measurement."""

    def record(self, value: float, metadata: dict[str, Any] | None = None) -> SLIValue:
        """Record a measurement value."""
        ts = time.time()
        full_meta: dict[str, Any] = {"target": self.target, **(metadata or {})}
        measurement = SLIValue(
            name=self.name,
            value=value,
            timestamp=ts,
            metadata=full_meta,
        )
        self._store.append(self.name, value, ts, full_meta)
        return measurement

    def values_in_window(self) -> list[SLIValue]:
        """Get measurements within the current time window."""
        cutoff = time.time() - self.window.seconds
        rows = self._store.query(self.name, cutoff)
        return [
            SLIValue(name=r.name, value=r.value, timestamp=r.timestamp, metadata=r.metadata)
            for r in rows
        ]

    def current_value(self) -> float | None:
        """Get the current aggregated value within the window."""
        values = self.values_in_window()
        if not values:
            return None
        return sum(v.value for v in values) / len(values)

    def compliance(self) -> float | None:
        """Fraction of measurements meeting the target within the window."""
        values = self.values_in_window()
        if not values:
            return None
        good = sum(1 for v in values if v.is_good)
        return good / len(values)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dictionary."""
        return {
            "name": self.name,
            "target": self.target,
            "window": self.window.value,
            "current_value": self.current_value(),
            "compliance": self.compliance(),
            "measurement_count": len(self.values_in_window()),
        }


# --- Built-in SLIs ---


class TaskSuccessRate(SLI):
    """Measures the fraction of tasks completed successfully."""

    def __init__(
        self,
        target: float = 0.995,
        window: TimeWindow | str = "30d",
        store: MeasurementStore | None = None,
    ) -> None:
        super().__init__("task_success_rate", target, window, store=store)
        self._total = 0
        self._success = 0

    def record_task(self, success: bool, metadata: dict[str, Any] | None = None) -> SLIValue:
        """Record a task completion."""
        self._total += 1
        if success:
            self._success += 1
        rate = self._success / self._total if self._total > 0 else 0.0
        return self.record(rate, metadata)

    def collect(self) -> SLIValue:
        rate = self._success / self._total if self._total > 0 else 0.0
        return self.record(rate)


class ToolCallAccuracy(SLI):
    """Measures the fraction of tool calls that selected the correct tool."""

    def __init__(
        self,
        target: float = 0.999,
        window: TimeWindow | str = "7d",
        store: MeasurementStore | None = None,
    ) -> None:
        super().__init__("tool_call_accuracy", target, window, store=store)
        self._total = 0
        self._correct = 0

    def record_call(self, correct: bool, metadata: dict[str, Any] | None = None) -> SLIValue:
        """Record a tool call result."""
        self._total += 1
        if correct:
            self._correct += 1
        rate = self._correct / self._total if self._total > 0 else 0.0
        return self.record(rate, metadata)

    def collect(self) -> SLIValue:
        rate = self._correct / self._total if self._total > 0 else 0.0
        return self.record(rate)


class ResponseLatency(SLI):
    """Measures response latency at a given percentile."""

    def __init__(
        self,
        target_ms: float = 5000.0,
        percentile: float = 0.95,
        window: TimeWindow | str = "1h",
        store: MeasurementStore | None = None,
    ) -> None:
        super().__init__(f"response_latency_p{int(percentile * 100)}", target_ms, window, store=store)
        self.percentile = percentile
        self._latencies: list[float] = []

    def record_latency(self, latency_ms: float, metadata: dict[str, Any] | None = None) -> SLIValue:
        """Record a response latency in milliseconds."""
        self._latencies.append(latency_ms)
        return self.record(latency_ms, metadata)

    def current_value(self) -> float | None:
        """Get the percentile latency value."""
        if not self._latencies:
            return None
        sorted_vals = sorted(self._latencies)
        idx = int(len(sorted_vals) * self.percentile)
        idx = min(idx, len(sorted_vals) - 1)
        return sorted_vals[idx]

    def collect(self) -> SLIValue:
        val = self.current_value()
        return self.record(val if val is not None else 0.0)


class CostPerTask(SLI):
    """Measures the average cost per task in USD."""

    def __init__(
        self,
        target_usd: float = 0.50,
        window: TimeWindow | str = "24h",
        store: MeasurementStore | None = None,
    ) -> None:
        super().__init__("cost_per_task", target_usd, window, store=store)
        self._total_cost = 0.0
        self._task_count = 0

    def record_cost(self, cost_usd: float, metadata: dict[str, Any] | None = None) -> SLIValue:
        """Record a task cost."""
        self._total_cost += cost_usd
        self._task_count += 1
        avg = self._total_cost / self._task_count
        return self.record(avg, metadata)

    def collect(self) -> SLIValue:
        avg = self._total_cost / self._task_count if self._task_count > 0 else 0.0
        return self.record(avg)


class PolicyCompliance(SLI):
    """Measures adherence to Agent OS policies (100% target by default)."""

    def __init__(
        self,
        target: float = 1.0,
        window: TimeWindow | str = "24h",
        store: MeasurementStore | None = None,
    ) -> None:
        super().__init__("policy_compliance", target, window, store=store)
        self._total = 0
        self._compliant = 0

    def record_check(self, compliant: bool, metadata: dict[str, Any] | None = None) -> SLIValue:
        """Record a policy check result."""
        self._total += 1
        if compliant:
            self._compliant += 1
        rate = self._compliant / self._total if self._total > 0 else 1.0
        return self.record(rate, metadata)

    def collect(self) -> SLIValue:
        rate = self._compliant / self._total if self._total > 0 else 1.0
        return self.record(rate)


class DelegationChainDepth(SLI):
    """Measures scope chain depth (lower is better, inverted comparison)."""

    def __init__(
        self,
        max_depth: int = 3,
        window: TimeWindow | str = "24h",
        store: MeasurementStore | None = None,
    ) -> None:
        super().__init__("scope_chain_depth", float(max_depth), window, store=store)
        self.max_depth = max_depth

    def record_depth(self, depth: int, metadata: dict[str, Any] | None = None) -> SLIValue:
        """Record a scope chain depth."""
        return self.record(float(depth), metadata)

    def compliance(self) -> float | None:
        """Fraction of measurements within max depth."""
        values = self.values_in_window()
        if not values:
            return None
        good = sum(1 for v in values if v.value <= self.max_depth)
        return good / len(values)

    def collect(self) -> SLIValue:
        return self.record(0.0)


class HallucinationRate(SLI):
    """Measures hallucination rate via LLM-as-judge evaluation.

    Records evaluation results from an external judge (LLM or human)
    that scores agent outputs for factual accuracy. Lower is better.
    """

    def __init__(
        self,
        target: float = 0.05,
        window: TimeWindow | str = "24h",
        store: MeasurementStore | None = None,
    ) -> None:
        super().__init__("hallucination_rate", target, window, store=store)
        self._total = 0
        self._hallucinated = 0

    def record_evaluation(
        self,
        hallucinated: bool,
        confidence: float = 1.0,
        metadata: dict[str, Any] | None = None,
    ) -> SLIValue:
        """Record an evaluation result from the judge."""
        self._total += 1
        if hallucinated:
            self._hallucinated += 1
        rate = self._hallucinated / self._total if self._total > 0 else 0.0
        return self.record(rate, {"confidence": confidence, **(metadata or {})})

    def compliance(self) -> float | None:
        """Fraction of measurements at or below the target (lower is better)."""
        values = self.values_in_window()
        if not values:
            return None
        good = sum(1 for v in values if v.value <= self.target)
        return good / len(values)

    def collect(self) -> SLIValue:
        rate = self._hallucinated / self._total if self._total > 0 else 0.0
        return self.record(rate)


class CalibrationDeltaSLI(SLI):
    """Tracks calibration drift — the gap between predicted confidence and actual success rate.

    An agent is *well-calibrated* when its stated confidence for a claim matches the
    empirical success rate for that claim.  For example, a claim made with 0.80
    confidence should succeed ~80 % of the time.  A growing |avg_predicted − success_rate|
    over successive measurements signals systematic over- or under-confidence.

    The SLI records one ``SLIValue`` per ``record_prediction()`` call.  Each recorded
    value is the aggregate calibration delta up to that point (i.e. the running
    ``|mean_predicted_confidence − mean_actual_success_rate|``).  ``current_value()``
    therefore returns the latest aggregate delta within the measurement window.

    Compliance is defined as the fraction of recorded aggregates that are at or below
    *target_delta* — a lower value is better.

    Reference:
        PDR: Persistent Delivery Reliability for AI Agents,
        DOI 10.5281/zenodo.19339987 — calibration_delta axis, §3.

    Example::

        sli = CalibrationDeltaSLI(target_delta=0.05)
        # High-confidence prediction that succeeds — good calibration
        sli.record_prediction(predicted_confidence=0.90, actual_success=True)
        # Overconfident prediction that fails — calibration gap widens
        sli.record_prediction(predicted_confidence=0.90, actual_success=False)
        print(sli.current_value())  # Running |avg_pred − avg_success|
    """

    def __init__(
        self,
        target_delta: float = 0.05,
        window: TimeWindow | str = "30d",
        store: MeasurementStore | None = None,
    ) -> None:
        """Initialise the CalibrationDeltaSLI.

        Args:
            target_delta: Maximum acceptable calibration gap (lower is better).
                          Compliance is the fraction of measurements at or below
                          this threshold.  Defaults to 0.05 (5 percentage points).
            window:       Measurement window for ``values_in_window()`` and
                          ``compliance()``.  Defaults to ``"30d"``.
            store:        Optional persistence backend.  Defaults to
                          ``InMemoryMeasurementStore`` (same behaviour as before
                          persistence support was added).  Pass a
                          ``SQLiteMeasurementStore`` to survive agent restarts.
        """
        super().__init__("calibration_delta", target_delta, window, store=store)
        self._sum_predicted: float = 0.0
        self._sum_actual: float = 0.0
        self._count: int = 0

    def current_value(self) -> float | None:
        """Return the most recent aggregate calibration delta within the window.

        Unlike the base ``SLI.current_value()`` which averages all window
        measurements, CalibrationDelta tracks a *running aggregate* — so the
        most recent recorded value IS the current aggregate.  Averaging the
        history would give a misleadingly high number during a well-calibrated
        convergence phase.

        Returns:
            The latest aggregate ``|mean_predicted − mean_actual_success_rate|``,
            or ``None`` if no measurements exist in the window.
        """
        values = self.values_in_window()
        if not values:
            return None
        return values[-1].value  # last recorded running aggregate

    def record_prediction(
        self,
        predicted_confidence: float,
        actual_success: bool,
        metadata: dict[str, Any] | None = None,
    ) -> SLIValue:
        """Record one prediction and its outcome.

        Accumulates running sums so that each call records the *aggregate*
        ``|mean_predicted_confidence − mean_actual_success_rate|`` over all
        predictions seen so far.  This makes ``current_value()`` meaningful after
        just a single call while naturally smoothing out noise over many calls.

        Args:
            predicted_confidence: Agent's stated confidence in [0, 1] before
                                  observing the outcome.
            actual_success:       Whether the prediction/action ultimately
                                  succeeded (True) or failed (False).
            metadata:             Optional key/value annotations stored alongside
                                  the measurement.

        Returns:
            The ``SLIValue`` representing the current aggregate calibration delta.
        """
        self._sum_predicted += predicted_confidence
        self._sum_actual += float(actual_success)
        self._count += 1
        avg_pred = self._sum_predicted / self._count
        avg_actual = self._sum_actual / self._count
        delta = abs(avg_pred - avg_actual)
        return self.record(delta, metadata)

    def compliance(self) -> float | None:
        """Fraction of recorded aggregate deltas at or below *target_delta*.

        A measurement is *good* when the running calibration gap (the recorded
        value) is ≤ ``self.target``.  Because each recorded value is an aggregate
        over all preceding predictions, the compliance score reflects how often
        the agent has been within the target calibration envelope throughout the
        measurement window.

        Returns:
            A float in [0, 1], or ``None`` if no measurements exist in the window.
        """
        values = self.values_in_window()
        if not values:
            return None
        good = sum(1 for v in values if v.value <= self.target)
        return good / len(values)

    def collect(self) -> SLIValue:
        """Emit the current aggregate calibration delta as a new measurement."""
        if self._count == 0:
            return self.record(0.0)
        avg_pred = self._sum_predicted / self._count
        avg_actual = self._sum_actual / self._count
        return self.record(abs(avg_pred - avg_actual))


# --- Registry ---


class SLIRegistry:
    """Registry for discovering and managing SLI types."""

    def __init__(self) -> None:
        self._indicators: dict[str, type[SLI]] = {}
        self._instances: dict[str, list[SLI]] = defaultdict(list)
        # Register built-ins
        for cls in (
            TaskSuccessRate,
            ToolCallAccuracy,
            ResponseLatency,
            CostPerTask,
            PolicyCompliance,
            DelegationChainDepth,
            HallucinationRate,
            CalibrationDeltaSLI,
        ):
            self.register_type(cls)

    def register_type(self, sli_class: type[SLI]) -> None:
        """Register an SLI type for discovery."""
        # Use class name as key
        self._indicators[sli_class.__name__] = sli_class

    def register_instance(self, agent_id: str, sli: SLI) -> None:
        """Register an SLI instance for a specific agent."""
        self._instances[agent_id].append(sli)

    def get_type(self, name: str) -> type[SLI] | None:
        """Look up an SLI type by name."""
        return self._indicators.get(name)

    def get_instances(self, agent_id: str) -> list[SLI]:
        """Get all SLI instances for an agent."""
        return self._instances.get(agent_id, [])

    def list_types(self) -> list[str]:
        """List all registered SLI type names."""
        return list(self._indicators.keys())

    def collect_all(self, agent_id: str) -> list[SLIValue]:
        """Collect current values for all SLIs of an agent."""
        return [sli.collect() for sli in self.get_instances(agent_id)]
