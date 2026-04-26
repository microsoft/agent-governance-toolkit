# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Reward Distribution Strategies.

Pluggable strategies for distributing rewards among task participants
based on trust scores, delegation depth, or explicit contribution weights.
"""

from __future__ import annotations

from typing import Optional, Protocol, runtime_checkable

from pydantic import BaseModel, Field


class ParticipantInfo(BaseModel):
    """Information about a single task participant."""

    agent_did: str
    trust_score: int = Field(ge=0, le=1000)
    delegation_depth: int = Field(ge=0, description="0 = root agent")
    contribution_weight: Optional[float] = Field(default=None, ge=0.0)


class RewardPool(BaseModel):
    """A pool of rewards to distribute for a completed task."""

    total_reward: float = Field(ge=0.0)
    task_id: str
    participants: list[ParticipantInfo]


class RewardAllocation(BaseModel):
    """Allocation result for a single participant."""

    agent_did: str
    amount: float
    percentage: float
    strategy_used: str


class DistributionResult(BaseModel):
    """Complete result of a reward distribution."""

    task_id: str
    strategy: str
    allocations: list[RewardAllocation]
    total_distributed: float


@runtime_checkable
class RewardStrategy(Protocol):
    """Protocol for pluggable reward distribution strategies."""

    def distribute(self, pool: RewardPool) -> DistributionResult: ...


class EqualSplitStrategy:
    """Divide rewards equally among all participants."""

    def distribute(self, pool: RewardPool) -> DistributionResult:
        n = len(pool.participants)
        if n == 0:
            return DistributionResult(
                task_id=pool.task_id,
                strategy="equal",
                allocations=[],
                total_distributed=0.0,
            )

        share = pool.total_reward / n
        pct = 100.0 / n
        allocations = [
            RewardAllocation(
                agent_did=p.agent_did,
                amount=share,
                percentage=pct,
                strategy_used="equal",
            )
            for p in pool.participants
        ]
        return DistributionResult(
            task_id=pool.task_id,
            strategy="equal",
            allocations=allocations,
            total_distributed=pool.total_reward,
        )


class TrustWeightedStrategy:
    """Distribute rewards weighted by trust score."""

    def distribute(self, pool: RewardPool) -> DistributionResult:
        if not pool.participants:
            return DistributionResult(
                task_id=pool.task_id,
                strategy="trust_weighted",
                allocations=[],
                total_distributed=0.0,
            )

        total_trust = sum(p.trust_score for p in pool.participants)
        allocations: list[RewardAllocation] = []

        for p in pool.participants:
            weight = p.trust_score / total_trust if total_trust > 0 else 1.0 / len(
                pool.participants
            )
            amount = pool.total_reward * weight
            allocations.append(
                RewardAllocation(
                    agent_did=p.agent_did,
                    amount=amount,
                    percentage=weight * 100.0,
                    strategy_used="trust_weighted",
                )
            )

        return DistributionResult(
            task_id=pool.task_id,
            strategy="trust_weighted",
            allocations=allocations,
            total_distributed=sum(a.amount for a in allocations),
        )


class HierarchicalStrategy:
    """Distribute rewards based on delegation depth with configurable decay.

    Root agents (depth 0) receive the largest share. Each successive
    delegation level receives ``decay_factor`` times the weight of the
    previous level.
    """

    def __init__(self, decay_factor: float = 0.7) -> None:
        self.decay_factor = decay_factor

    def distribute(self, pool: RewardPool) -> DistributionResult:
        if not pool.participants:
            return DistributionResult(
                task_id=pool.task_id,
                strategy="hierarchical",
                allocations=[],
                total_distributed=0.0,
            )

        weights = [self.decay_factor ** p.delegation_depth for p in pool.participants]
        total_weight = sum(weights)
        allocations: list[RewardAllocation] = []

        for p, w in zip(pool.participants, weights):
            share = w / total_weight if total_weight > 0 else 1.0 / len(pool.participants)
            amount = pool.total_reward * share
            allocations.append(
                RewardAllocation(
                    agent_did=p.agent_did,
                    amount=amount,
                    percentage=share * 100.0,
                    strategy_used="hierarchical",
                )
            )

        return DistributionResult(
            task_id=pool.task_id,
            strategy="hierarchical",
            allocations=allocations,
            total_distributed=sum(a.amount for a in allocations),
        )


class ContributionWeightedStrategy:
    """Distribute rewards by explicit contribution weights.

    Participants without a ``contribution_weight`` receive a weight of 0.
    """

    def distribute(self, pool: RewardPool) -> DistributionResult:
        if not pool.participants:
            return DistributionResult(
                task_id=pool.task_id,
                strategy="contribution",
                allocations=[],
                total_distributed=0.0,
            )

        weights = [p.contribution_weight or 0.0 for p in pool.participants]
        total_weight = sum(weights)
        allocations: list[RewardAllocation] = []

        for p, w in zip(pool.participants, weights):
            share = w / total_weight if total_weight > 0 else 0.0
            amount = pool.total_reward * share
            allocations.append(
                RewardAllocation(
                    agent_did=p.agent_did,
                    amount=amount,
                    percentage=share * 100.0,
                    strategy_used="contribution",
                )
            )

        return DistributionResult(
            task_id=pool.task_id,
            strategy="contribution",
            allocations=allocations,
            total_distributed=sum(a.amount for a in allocations),
        )
