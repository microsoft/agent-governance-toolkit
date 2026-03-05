# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic implementation
"""Progressive delivery — basic blue/green deployment support.

Preview mode and staged rollouts are not available in Community Edition.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Callable


class DeploymentStrategy(Enum):
    """Rollout strategy types."""

    SHADOW = "shadow"
    CANARY = "canary"
    BLUE_GREEN = "blue_green"


class RolloutState(Enum):
    """Current state of a rollout."""

    PENDING = "pending"
    SHADOW = "shadow"
    CANARY = "canary"
    PROMOTING = "promoting"
    COMPLETE = "complete"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"
    PAUSED = "paused"


@dataclass
class AnalysisCriterion:
    """A metric check for rollout step analysis."""

    metric: str
    threshold: float
    comparator: str = "gte"  # gte, lte, eq

    def evaluate(self, value: float) -> bool:
        """Check if a metric value passes this criterion."""
        if self.comparator == "gte":
            return value >= self.threshold
        elif self.comparator == "lte":
            return value <= self.threshold
        elif self.comparator == "eq":
            return abs(value - self.threshold) < 1e-9
        return False

    def to_dict(self) -> dict[str, Any]:
        return {"metric": self.metric, "threshold": self.threshold, "comparator": self.comparator}


@dataclass
class RolloutStep:
    """A single step in a progressive rollout."""

    weight: float  # 0.0 to 1.0 — fraction of traffic to candidate
    duration_seconds: int = 3600
    analysis: list[AnalysisCriterion] = field(default_factory=list)
    manual_gate: bool = False
    name: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "weight": self.weight,
            "duration_seconds": self.duration_seconds,
            "analysis": [a.to_dict() for a in self.analysis],
            "manual_gate": self.manual_gate,
        }


@dataclass
class RollbackCondition:
    """Condition that triggers automatic rollback."""

    metric: str
    threshold: float
    comparator: str = "gte"  # trigger rollback when metric >= threshold

    def should_rollback(self, value: float) -> bool:
        if self.comparator == "gte":
            return value >= self.threshold
        elif self.comparator == "lte":
            return value <= self.threshold
        return False

    def to_dict(self) -> dict[str, Any]:
        return {"metric": self.metric, "threshold": self.threshold, "comparator": self.comparator}


# --- Preview Mode ---


@dataclass
class ShadowComparison:
    """Result of comparing current vs. candidate agent outputs."""

    request_id: str
    current_output: Any = None
    candidate_output: Any = None
    match: bool = False
    similarity_score: float = 0.0
    current_latency_ms: float = 0.0
    candidate_latency_ms: float = 0.0
    current_cost_usd: float = 0.0
    candidate_cost_usd: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def latency_delta_ms(self) -> float:
        return self.candidate_latency_ms - self.current_latency_ms

    @property
    def cost_delta_usd(self) -> float:
        return self.candidate_cost_usd - self.current_cost_usd

    def to_dict(self) -> dict[str, Any]:
        return {
            "request_id": self.request_id,
            "match": self.match,
            "similarity_score": self.similarity_score,
            "latency_delta_ms": self.latency_delta_ms,
            "cost_delta_usd": self.cost_delta_usd,
        }


@dataclass
class ShadowResult:
    """Aggregated results from a shadow testing session."""

    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    comparisons: list[ShadowComparison] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: float | None = None

    @property
    def total_requests(self) -> int:
        return len(self.comparisons)

    @property
    def match_rate(self) -> float:
        if not self.comparisons:
            return 0.0
        return sum(1 for c in self.comparisons if c.match) / len(self.comparisons)

    @property
    def avg_similarity(self) -> float:
        if not self.comparisons:
            return 0.0
        return sum(c.similarity_score for c in self.comparisons) / len(self.comparisons)

    @property
    def avg_latency_delta_ms(self) -> float:
        if not self.comparisons:
            return 0.0
        return sum(c.latency_delta_ms for c in self.comparisons) / len(self.comparisons)

    @property
    def avg_cost_delta_usd(self) -> float:
        if not self.comparisons:
            return 0.0
        return sum(c.cost_delta_usd for c in self.comparisons) / len(self.comparisons)

    @property
    def confidence_score(self) -> float:
        """Overall confidence that candidate is safe to promote (0-1)."""
        if not self.comparisons:
            return 0.0
        factors = [
            self.match_rate,
            self.avg_similarity,
            1.0 if self.avg_latency_delta_ms <= 0 else max(0.0, 1.0 - self.avg_latency_delta_ms / 5000),
            1.0 if self.avg_cost_delta_usd <= 0 else max(0.0, 1.0 - self.avg_cost_delta_usd / 1.0),
        ]
        return sum(factors) / len(factors)

    def finish(self) -> None:
        self.end_time = time.time()

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "total_requests": self.total_requests,
            "match_rate": self.match_rate,
            "avg_similarity": self.avg_similarity,
            "avg_latency_delta_ms": self.avg_latency_delta_ms,
            "avg_cost_delta_usd": self.avg_cost_delta_usd,
            "confidence_score": self.confidence_score,
        }


class ShadowMode:
    """Preview testing — not available in Community Edition.

    Class retained for API compatibility. Use blue/green deployment instead.
    """

    def __init__(
        self,
        similarity_threshold: float = 0.9,
        max_comparisons: int = 1000,
    ) -> None:
        self.similarity_threshold = similarity_threshold
        self.max_comparisons = max_comparisons
        self._result = ShadowResult()
        self._similarity_fn: Callable[[Any, Any], float] | None = None

    def set_similarity_function(self, fn: Callable[[Any, Any], float]) -> None:
        """Set custom similarity function — not available in Community Edition."""
        raise NotImplementedError("Not available in Community Edition")

    def compare(
        self,
        request_id: str,
        current_output: Any,
        candidate_output: Any,
        current_latency_ms: float = 0.0,
        candidate_latency_ms: float = 0.0,
        current_cost_usd: float = 0.0,
        candidate_cost_usd: float = 0.0,
    ) -> ShadowComparison:
        """Record a comparison — not available in Community Edition."""
        raise NotImplementedError("Not available in Community Edition")

    @property
    def result(self) -> ShadowResult:
        return self._result

    def is_passing(self, min_confidence: float = 0.8) -> bool:
        """Check if preview results meet promotion criteria — not available in Community Edition."""
        raise NotImplementedError("Not available in Community Edition")

    def finish(self) -> ShadowResult:
        """Complete the preview session — not available in Community Edition."""
        raise NotImplementedError("Not available in Community Edition")


# --- Staged Rollout ---


@dataclass
class RolloutEvent:
    """An event during a rollout (step change, analysis, rollback, etc.)."""

    event_type: str  # step_start, step_complete, analysis_pass, analysis_fail, rollback, promote
    timestamp: float = field(default_factory=time.time)
    step_index: int = -1
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "step_index": self.step_index,
            "details": self.details,
        }


class CanaryRollout:
    """Staged rollout — not available in Community Edition.

    Class retained for API compatibility. Use blue/green deployment instead.
    """

    def __init__(
        self,
        name: str,
        steps: list[RolloutStep] | None = None,
        rollback_conditions: list[RollbackCondition] | None = None,
    ) -> None:
        self.rollout_id = uuid.uuid4().hex[:12]
        self.name = name
        self.steps = steps or []
        self.rollback_conditions = rollback_conditions or []
        self.state = RolloutState.PENDING
        self.current_step_index = -1
        self.events: list[RolloutEvent] = []
        self.started_at: float | None = None
        self.completed_at: float | None = None

    @property
    def current_step(self) -> RolloutStep | None:
        if 0 <= self.current_step_index < len(self.steps):
            return self.steps[self.current_step_index]
        return None

    @property
    def current_weight(self) -> float:
        step = self.current_step
        return step.weight if step else 0.0

    @property
    def progress_percent(self) -> float:
        if not self.steps:
            return 0.0
        return ((self.current_step_index + 1) / len(self.steps)) * 100

    def start(self) -> None:
        """Begin the rollout — not available in Community Edition."""
        raise NotImplementedError("Not available in Community Edition")

    def advance(self) -> bool:
        """Move to the next step — not available in Community Edition."""
        raise NotImplementedError("Not available in Community Edition")

    def check_rollback(self, metrics: dict[str, float]) -> bool:
        """Check rollback conditions — not available in Community Edition."""
        raise NotImplementedError("Not available in Community Edition")

    def analyze_step(self, metrics: dict[str, float]) -> bool:
        """Check step analysis criteria — not available in Community Edition."""
        raise NotImplementedError("Not available in Community Edition")

    def rollback(self, reason: str = "") -> None:
        """Roll back — not available in Community Edition."""
        raise NotImplementedError("Not available in Community Edition")

    def pause(self) -> None:
        """Pause the rollout — not available in Community Edition."""
        raise NotImplementedError("Not available in Community Edition")

    def resume(self) -> None:
        """Resume a paused rollout — not available in Community Edition."""
        raise NotImplementedError("Not available in Community Edition")

    def promote(self) -> None:
        """Immediately promote — not available in Community Edition."""
        raise NotImplementedError("Not available in Community Edition")

    def _record_event(
        self,
        event_type: str,
        step_index: int = -1,
        details: dict[str, Any] | None = None,
    ) -> None:
        idx = step_index if step_index >= 0 else self.current_step_index
        self.events.append(RolloutEvent(
            event_type=event_type,
            step_index=idx,
            details=details or {},
        ))

    def to_dict(self) -> dict[str, Any]:
        return {
            "rollout_id": self.rollout_id,
            "name": self.name,
            "state": self.state.value,
            "current_step_index": self.current_step_index,
            "current_weight": self.current_weight,
            "progress_percent": self.progress_percent,
            "steps": [s.to_dict() for s in self.steps],
            "rollback_conditions": [r.to_dict() for r in self.rollback_conditions],
            "events": [e.to_dict() for e in self.events],
        }
