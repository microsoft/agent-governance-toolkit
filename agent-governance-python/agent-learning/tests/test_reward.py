# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for governance-aware Agent Learning rewards."""

from __future__ import annotations

from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

import pytest

from agent_learning_gov import (
    AuditEventType,
    GovernanceOutcome,
    GovernanceTelemetry,
    GovernanceViolation,
    InMemoryAuditSink,
    PolicyAwareRewardAdapter,
    PolicyDecisionRecord,
    RewardAdapterConfig,
    RiskLevel,
)


@dataclass
class _Reward:
    value: float
    source: str = "aggregate"
    metadata: dict[str, Any] = field(default_factory=dict)


class _Store:
    def __init__(self) -> None:
        self.rewards: list[_Reward] = []

    def store_reward(self, reward: _Reward) -> str:
        self.rewards.append(reward)
        return "reward"


def _episode(*violations: GovernanceViolation) -> Any:
    decision = PolicyDecisionRecord(
        policy_name="policy",
        action_id="search",
        outcome=(
            GovernanceOutcome.DENIED
            if any(violation.blocked for violation in violations)
            else GovernanceOutcome.ALLOWED
        ),
    )
    telemetry = GovernanceTelemetry(
        decisions=(decision,),
        violations=violations,
    )
    return SimpleNamespace(metadata=telemetry.merge_metadata())


def test_penalties_are_added_and_clamped_to_agent_learning_range() -> None:
    episode = _episode(
        GovernanceViolation(
            policy_name="restricted-action",
            description="blocked",
            severity=RiskLevel.CRITICAL,
            blocked=True,
        )
    )
    adapter = PolicyAwareRewardAdapter()

    result = adapter.shape(episode, 0.8)

    assert result.violation_penalty == -1.0
    assert result.final_reward == pytest.approx(-0.2)
    assert result.denied_action_count == 1


def test_clean_bonus_requires_governance_instrumentation() -> None:
    adapter = PolicyAwareRewardAdapter()

    clean = adapter.shape(_episode(), 0.5)
    legacy = adapter.shape(SimpleNamespace(metadata={}), 0.5)

    assert clean.final_reward == pytest.approx(0.55)
    assert legacy.final_reward == 0.5
    assert legacy.instrumented == False


def test_aggregate_reward_adaptation_is_idempotent_and_persisted() -> None:
    store = _Store()
    adapter = PolicyAwareRewardAdapter(store=store)
    episode = _episode(
        GovernanceViolation(
            policy_name="cost",
            description="over budget",
            severity=RiskLevel.MEDIUM,
        )
    )
    original = _Reward(value=0.7)

    first = adapter.adapt_reward(episode, original)
    second = adapter.adapt_reward(episode, first)

    assert original.value == 0.7
    assert first.value == pytest.approx(0.45)
    assert second.value == first.value
    assert len(store.rewards) == 2
    shaping = second.metadata["agent_governance"]["reward_shaping"]
    assert shaping["base_reward"] == 0.7
    assert shaping["violation_count"] == 1


def test_metric_rewards_are_not_modified() -> None:
    reward = _Reward(value=0.4, source="metric")

    adapted = PolicyAwareRewardAdapter().adapt_reward(_episode(), reward)

    assert adapted is reward


def test_reward_shaping_emits_audit_event() -> None:
    audit = InMemoryAuditSink()
    adapter = PolicyAwareRewardAdapter(audit_sink=audit)
    episode = _episode()
    episode.agent_id = "agent-1"
    episode.task_id = "task-1"
    reward = _Reward(value=0.5)
    reward.id = "reward-1"

    adapter.adapt_reward(episode, reward, persist=False)

    events = audit.query(agent_id="agent-1")
    assert len(events) == 1
    assert events[0].event_type is AuditEventType.REWARD_SHAPED
    assert events[0].details["final_reward"] == pytest.approx(0.55)


def test_reward_configuration_cannot_widen_native_range() -> None:
    with pytest.raises(ValueError, match=r"\[-1, 1\]"):
        RewardAdapterConfig(min_reward=0.0, max_reward=2.0)


def test_non_finite_reward_is_rejected() -> None:
    with pytest.raises(ValueError, match="finite"):
        PolicyAwareRewardAdapter().shape(_episode(), float("nan"))
