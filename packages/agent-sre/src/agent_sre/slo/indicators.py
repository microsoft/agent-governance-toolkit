# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic implementation
"""Service Level Indicators for AI agent systems."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


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

    def __init__(self, name: str, target: float, window: TimeWindow | str) -> None:
        self.name = name
        self.target = target
        self.window = TimeWindow(window) if isinstance(window, str) else window
        self._measurements: list[SLIValue] = []

    @abstractmethod
    def collect(self) -> SLIValue:
        """Collect a new measurement."""

    def record(self, value: float, metadata: dict[str, Any] | None = None) -> SLIValue:
        """Record a measurement value."""
        measurement = SLIValue(
            name=self.name,
            value=value,
            metadata={"target": self.target, **(metadata or {})},
        )
        self._measurements.append(measurement)
        return measurement

    def values_in_window(self) -> list[SLIValue]:
        """Get measurements within the current time window."""
        cutoff = time.time() - self.window.seconds
        return [m for m in self._measurements if m.timestamp >= cutoff]

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

    def __init__(self, target: float = 0.995, window: TimeWindow | str = "30d") -> None:
        super().__init__("task_success_rate", target, window)
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

    def __init__(self, target: float = 0.999, window: TimeWindow | str = "7d") -> None:
        super().__init__("tool_call_accuracy", target, window)
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
    ) -> None:
        super().__init__(f"response_latency_p{int(percentile * 100)}", target_ms, window)
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

    def __init__(self, target_usd: float = 0.50, window: TimeWindow | str = "24h") -> None:
        super().__init__("cost_per_task", target_usd, window)
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

    def __init__(self, target: float = 1.0, window: TimeWindow | str = "24h") -> None:
        super().__init__("policy_compliance", target, window)
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

    def __init__(self, max_depth: int = 3, window: TimeWindow | str = "24h") -> None:
        super().__init__("scope_chain_depth", float(max_depth), window)
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

    def __init__(self, target: float = 0.05, window: TimeWindow | str = "24h") -> None:
        super().__init__("hallucination_rate", target, window)
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
