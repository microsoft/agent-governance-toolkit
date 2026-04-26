# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Standalone shadow mode and rollout implementation.

This module provides a self-contained implementation that requires only
the Python standard library.  It is used as a fallback by
``agentmesh.governance.shadow`` when ``agent_sre`` is not installed.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
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
    comparator: str = "gte"

    def evaluate(self, value: float) -> bool:
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

    weight: float
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
    comparator: str = "gte"

    def should_rollback(self, value: float) -> bool:
        if self.comparator == "gte":
            return value >= self.threshold
        elif self.comparator == "lte":
            return value <= self.threshold
        return False

    def to_dict(self) -> dict[str, Any]:
        return {"metric": self.metric, "threshold": self.threshold, "comparator": self.comparator}


@dataclass
class SimulatedAction:
    """An action to simulate in shadow mode."""

    action_id: str
    agent_did: str
    action_type: str
    context: dict[str, Any]
    timestamp: datetime | None = None

    def __post_init__(self) -> None:
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)


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
    """Unified shadow result for delivery comparisons and policy evaluations."""

    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    comparisons: list[ShadowComparison] = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    end_time: float | None = None
    action_id: str = ""
    shadow_allowed: bool | None = None
    shadow_action: str | None = None
    shadow_rule: str | None = None
    production_allowed: bool | None = None
    production_action: str | None = None
    production_rule: str | None = None
    diverged: bool = False
    divergence_reason: str | None = None
    evaluated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    shadow_latency_ms: float | None = None
    production_latency_ms: float | None = None

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
        data: dict[str, Any] = {
            "session_id": self.session_id,
            "total_requests": self.total_requests,
            "match_rate": self.match_rate,
            "avg_similarity": self.avg_similarity,
            "avg_latency_delta_ms": self.avg_latency_delta_ms,
            "avg_cost_delta_usd": self.avg_cost_delta_usd,
            "confidence_score": self.confidence_score,
        }
        if self.action_id:
            data.update({
                "action_id": self.action_id,
                "shadow_allowed": self.shadow_allowed,
                "shadow_action": self.shadow_action,
                "shadow_rule": self.shadow_rule,
                "production_allowed": self.production_allowed,
                "production_action": self.production_action,
                "production_rule": self.production_rule,
                "diverged": self.diverged,
                "divergence_reason": self.divergence_reason,
                "shadow_latency_ms": self.shadow_latency_ms,
                "production_latency_ms": self.production_latency_ms,
            })
        return data


@dataclass
class ShadowSession:
    """A governance shadow-mode evaluation session."""

    session_id: str = field(default_factory=lambda: f"shadow_{uuid.uuid4().hex[:12]}")
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    agent_dids: list[str] = field(default_factory=list)
    policy_names: list[str] = field(default_factory=list)
    total_evaluated: int = 0
    total_diverged: int = 0
    divergence_rate: float = 0.0
    results: list[ShadowResult] = field(default_factory=list)
    active: bool = True
    ended_at: datetime | None = None


class ShadowMode:
    """Hybrid shadow mode for delivery preview and governance evaluation."""

    DIVERGENCE_TARGET = 0.02

    def __init__(
        self,
        policy_engine: Any | None = None,
        similarity_threshold: float = 0.9,
        max_comparisons: int = 1000,
    ) -> None:
        if isinstance(policy_engine, (int, float)) and not isinstance(policy_engine, bool):
            similarity_threshold = float(policy_engine)
            policy_engine = None

        self.policy_engine = policy_engine
        self.similarity_threshold = similarity_threshold
        self.max_comparisons = max_comparisons
        self._result = ShadowResult()
        self._similarity_fn: Callable[[Any, Any], float] | None = None
        self._sessions: dict[str, ShadowSession] = {}
        self._active_session: str | None = None

    def set_similarity_function(self, fn: Callable[[Any, Any], float]) -> None:
        """Set custom similarity function — not available in Public Preview."""
        raise NotImplementedError("Not available in Public Preview")

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
        """Record a comparison — not available in Public Preview."""
        raise NotImplementedError("Not available in Public Preview")

    @property
    def result(self) -> ShadowResult:
        return self._result

    def is_passing(self, min_confidence: float = 0.8) -> bool:
        """Check delivery preview results — not available in Public Preview."""
        raise NotImplementedError("Not available in Public Preview")

    def finish(self) -> ShadowResult:
        """Complete a delivery preview session — not available in Public Preview."""
        raise NotImplementedError("Not available in Public Preview")

    def start_session(
        self,
        agent_dids: list[str] | None = None,
        policy_names: list[str] | None = None,
    ) -> ShadowSession:
        session = ShadowSession(
            agent_dids=agent_dids or [],
            policy_names=policy_names or [],
        )
        self._sessions[session.session_id] = session
        self._active_session = session.session_id
        return session

    def evaluate(
        self,
        action: SimulatedAction,
        production_decision: dict[str, Any] | None = None,
    ) -> ShadowResult:
        if self.policy_engine is None:
            raise RuntimeError("A policy_engine is required for governance shadow evaluation")

        start = datetime.now(timezone.utc)
        shadow_decision = self.policy_engine.evaluate(
            agent_did=action.agent_did,
            context=action.context,
        )
        shadow_latency = (datetime.now(timezone.utc) - start).total_seconds() * 1000

        result = ShadowResult(
            action_id=action.action_id,
            shadow_allowed=shadow_decision.allowed,
            shadow_action=shadow_decision.action,
            shadow_rule=getattr(shadow_decision, "matched_rule", None),
            shadow_latency_ms=shadow_latency,
        )

        if production_decision:
            result.production_allowed = production_decision.get("allowed")
            result.production_action = production_decision.get("action")
            result.production_rule = production_decision.get("matched_rule")
            result.production_latency_ms = production_decision.get("latency_ms")

            if result.shadow_allowed != result.production_allowed:
                result.diverged = True
                result.divergence_reason = (
                    f"Shadow={result.shadow_action}, Production={result.production_action}"
                )
            elif result.shadow_action != result.production_action:
                result.diverged = True
                result.divergence_reason = (
                    f"Action mismatch: {result.shadow_action} vs {result.production_action}"
                )

        if self._active_session:
            session = self._sessions[self._active_session]
            session.results.append(result)
            session.total_evaluated += 1
            if result.diverged:
                session.total_diverged += 1
            session.divergence_rate = (
                session.total_diverged / session.total_evaluated
                if session.total_evaluated > 0
                else 0.0
            )

        return result

    def replay_batch(
        self,
        actions: list[SimulatedAction],
        production_decisions: list[dict[str, Any]] | None = None,
    ) -> list[ShadowResult]:
        results: list[ShadowResult] = []
        for index, action in enumerate(actions):
            production_decision = None
            if production_decisions and index < len(production_decisions):
                production_decision = production_decisions[index]
            results.append(self.evaluate(action, production_decision))
        return results

    def end_session(self, session_id: str | None = None) -> ShadowSession:
        sid = session_id or self._active_session
        if not sid or sid not in self._sessions:
            raise ValueError("No active session")
        session = self._sessions[sid]
        session.active = False
        session.ended_at = datetime.now(timezone.utc)
        if sid == self._active_session:
            self._active_session = None
        return session

    def get_session(self, session_id: str) -> ShadowSession | None:
        return self._sessions.get(session_id)

    def get_divergence_report(self, session_id: str | None = None) -> dict[str, Any]:
        sid = session_id or self._active_session
        if not sid or sid not in self._sessions:
            return {"error": "No session found"}
        session = self._sessions[sid]
        divergence_reasons: dict[str, int] = {}
        for result in session.results:
            if result.diverged:
                reason = result.divergence_reason or "unknown"
                divergence_reasons[reason] = divergence_reasons.get(reason, 0) + 1
        within_target = session.divergence_rate <= self.DIVERGENCE_TARGET
        return {
            "session_id": session.session_id,
            "total_evaluated": session.total_evaluated,
            "total_diverged": session.total_diverged,
            "divergence_rate": session.divergence_rate,
            "divergence_rate_pct": f"{session.divergence_rate * 100:.2f}%",
            "target_rate_pct": f"{self.DIVERGENCE_TARGET * 100:.2f}%",
            "within_target": within_target,
            "divergence_breakdown": divergence_reasons,
            "recommendation": (
                "Ready for production"
                if within_target
                else "Review divergent cases before production"
            ),
        }

    def is_ready_for_production(self, session_id: str | None = None) -> bool:
        report = self.get_divergence_report(session_id)
        return report.get("within_target", False)


@dataclass
class RolloutEvent:
    """An event during a rollout."""

    event_type: str
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
    """Staged rollout — not available in Public Preview."""

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
        """Begin the rollout — not available in Public Preview."""
        raise NotImplementedError("Not available in Public Preview")

    def advance(self) -> bool:
        """Move to the next step — not available in Public Preview."""
        raise NotImplementedError("Not available in Public Preview")

    def check_rollback(self, metrics: dict[str, float]) -> bool:
        """Check rollback conditions — not available in Public Preview."""
        raise NotImplementedError("Not available in Public Preview")

    def analyze_step(self, metrics: dict[str, float]) -> bool:
        """Check step analysis criteria — not available in Public Preview."""
        raise NotImplementedError("Not available in Public Preview")

    def rollback(self, reason: str = "") -> None:
        """Roll back — not available in Public Preview."""
        raise NotImplementedError("Not available in Public Preview")

    def pause(self) -> None:
        """Pause the rollout — not available in Public Preview."""
        raise NotImplementedError("Not available in Public Preview")

    def resume(self) -> None:
        """Resume a paused rollout — not available in Public Preview."""
        raise NotImplementedError("Not available in Public Preview")

    def promote(self) -> None:
        """Immediately promote — not available in Public Preview."""
        raise NotImplementedError("Not available in Public Preview")

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


__all__ = [
    "AnalysisCriterion",
    "CanaryRollout",
    "DeploymentStrategy",
    "RollbackCondition",
    "RolloutEvent",
    "RolloutState",
    "RolloutStep",
    "ShadowComparison",
    "ShadowMode",
    "ShadowResult",
    "ShadowSession",
    "SimulatedAction",
]
