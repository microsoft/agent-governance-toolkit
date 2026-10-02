# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Governance-aware reward shaping for Agent Learning episodes."""

from __future__ import annotations

import copy
import math
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from .audit import AuditEvent, AuditEventType, AuditSink, emit_audit_event
from .models import (
    GOVERNANCE_METADATA_KEY,
    GovernanceTelemetry,
    RiskLevel,
)

_REWARD_SHAPING_KEY = "reward_shaping"


@dataclass(frozen=True)
class RewardAdapterConfig:
    """Reward adjustments kept within Agent Learning's native range."""

    critical_penalty: float = -1.0
    high_penalty: float = -0.75
    medium_penalty: float = -0.25
    low_penalty: float = -0.05
    compliant_bonus: float = 0.05
    min_reward: float = -1.0
    max_reward: float = 1.0

    def __post_init__(self) -> None:
        values = (
            self.critical_penalty,
            self.high_penalty,
            self.medium_penalty,
            self.low_penalty,
            self.compliant_bonus,
            self.min_reward,
            self.max_reward,
        )
        if not all(math.isfinite(value) for value in values):
            raise ValueError("reward configuration values must be finite")
        if self.min_reward < -1.0 or self.max_reward > 1.0:
            raise ValueError("reward bounds must stay within Agent Learning's [-1, 1] range")
        if self.min_reward >= self.max_reward:
            raise ValueError("min_reward must be less than max_reward")
        for name in (
            "critical_penalty",
            "high_penalty",
            "medium_penalty",
            "low_penalty",
        ):
            if getattr(self, name) > 0:
                raise ValueError(f"{name} must be non-positive")
        if self.compliant_bonus < 0:
            raise ValueError("compliant_bonus must be non-negative")


@dataclass(frozen=True)
class GovernanceRewardResult:
    """Decomposed reward and governance metrics for one episode."""

    base_reward: float
    final_reward: float
    governance_bonus: float
    violation_penalty: float
    violation_count: int
    denied_action_count: int
    policy_compliant: bool
    instrumented: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_reward": self.base_reward,
            "final_reward": self.final_reward,
            "governance_bonus": self.governance_bonus,
            "violation_penalty": self.violation_penalty,
            "violation_count": self.violation_count,
            "denied_action_count": self.denied_action_count,
            "policy_compliant": self.policy_compliant,
            "instrumented": self.instrumented,
        }


class PolicyAwareRewardAdapter:
    """Apply governance penalties and bonuses to aggregate rewards."""

    def __init__(
        self,
        *,
        store: Any | None = None,
        config: RewardAdapterConfig | None = None,
        audit_sink: AuditSink | None = None,
    ) -> None:
        self.store = store
        self.config = config or RewardAdapterConfig()
        self.audit_sink = audit_sink
        self._rewards_shaped = 0
        self._violations_seen = 0
        self._total_penalty = 0.0

    def shape(self, episode: Any, base_reward: float) -> GovernanceRewardResult:
        """Combine a base reward with governance outcomes."""
        if not math.isfinite(base_reward):
            raise ValueError("base_reward must be finite")
        telemetry = GovernanceTelemetry.from_metadata(getattr(episode, "metadata", None))
        instrumented = bool(telemetry.decisions or telemetry.violations or telemetry.tool_usage)
        penalties = {
            RiskLevel.CRITICAL: self.config.critical_penalty,
            RiskLevel.HIGH: self.config.high_penalty,
            RiskLevel.MEDIUM: self.config.medium_penalty,
            RiskLevel.LOW: self.config.low_penalty,
        }
        violation_penalty = sum(penalties[violation.severity] for violation in telemetry.violations)
        policy_compliant = instrumented and not telemetry.violations
        governance_bonus = self.config.compliant_bonus if policy_compliant else 0.0
        final_reward = max(
            self.config.min_reward,
            min(
                self.config.max_reward,
                float(base_reward) + governance_bonus + violation_penalty,
            ),
        )
        return GovernanceRewardResult(
            base_reward=float(base_reward),
            final_reward=final_reward,
            governance_bonus=governance_bonus,
            violation_penalty=violation_penalty,
            violation_count=len(telemetry.violations),
            denied_action_count=sum(1 for violation in telemetry.violations if violation.blocked),
            policy_compliant=policy_compliant,
            instrumented=instrumented,
        )

    def adapt_reward(
        self,
        episode: Any,
        reward: Any,
        *,
        persist: bool = True,
    ) -> Any:
        """Return a shaped copy of an Agent Learning aggregate reward."""
        if not _is_aggregate_reward(reward):
            return reward

        metadata = dict(getattr(reward, "metadata", {}) or {})
        prior = _reward_shaping_metadata(metadata)
        base_reward = float(prior.get("base_reward", reward.value))
        result = self.shape(episode, base_reward)

        adapted = copy.deepcopy(reward)
        adapted.value = result.final_reward
        adapted.metadata = _merge_reward_metadata(metadata, result)

        if persist and self.store is not None:
            self.store.store_reward(adapted)
        emit_audit_event(
            self.audit_sink,
            AuditEvent(
                event_type=AuditEventType.REWARD_SHAPED,
                agent_id=getattr(episode, "agent_id", getattr(reward, "agent_id", "unknown")),
                task_id=getattr(episode, "task_id", "default"),
                artifact_type="reward",
                artifact_id=getattr(adapted, "id", "unknown"),
                outcome="shaped",
                policy_id=getattr(episode, "policy_id", None),
                policy_version=getattr(episode, "policy_version", None),
                action_id=getattr(episode, "action_id", None),
                correlation_id=getattr(episode, "correlation_id", None),
                details=result.to_dict(),
            ),
        )

        self._rewards_shaped += 1
        self._violations_seen += result.violation_count
        self._total_penalty += result.violation_penalty
        return adapted

    def adapt_rewards(
        self,
        episode: Any,
        rewards: Iterable[Any],
        *,
        persist: bool = True,
    ) -> list[Any]:
        """Shape aggregate rows while preserving per-metric reward rows."""
        return [self.adapt_reward(episode, reward, persist=persist) for reward in rewards]

    def get_stats(self) -> dict[str, Any]:
        total = self._rewards_shaped
        return {
            "rewards_shaped": total,
            "violations_seen": self._violations_seen,
            "total_penalty": self._total_penalty,
            "average_penalty": self._total_penalty / total if total else 0.0,
        }

    def reset_stats(self) -> None:
        self._rewards_shaped = 0
        self._violations_seen = 0
        self._total_penalty = 0.0


def _is_aggregate_reward(reward: Any) -> bool:
    source = getattr(reward, "source", None)
    source = getattr(source, "value", source)
    return source == "aggregate"


def _reward_shaping_metadata(metadata: Mapping[str, Any]) -> Mapping[str, Any]:
    namespace = metadata.get(GOVERNANCE_METADATA_KEY, {})
    if not isinstance(namespace, Mapping):
        return {}
    shaping = namespace.get(_REWARD_SHAPING_KEY, {})
    return shaping if isinstance(shaping, Mapping) else {}


def _merge_reward_metadata(
    metadata: Mapping[str, Any],
    result: GovernanceRewardResult,
) -> dict[str, Any]:
    merged = dict(metadata)
    existing = merged.get(GOVERNANCE_METADATA_KEY, {})
    namespace = dict(existing) if isinstance(existing, Mapping) else {}
    namespace[_REWARD_SHAPING_KEY] = result.to_dict()
    merged[GOVERNANCE_METADATA_KEY] = namespace
    return merged


__all__ = [
    "GovernanceRewardResult",
    "PolicyAwareRewardAdapter",
    "RewardAdapterConfig",
]
