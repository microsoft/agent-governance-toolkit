# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Reward & Learning Engine (Layer 4)

Behavioral feedback loop that scores agent actions
against a governance rubric.
"""

from .distribution import (
    ContributionWeightedStrategy,
    DistributionResult,
    EqualSplitStrategy,
    HierarchicalStrategy,
    ParticipantInfo,
    RewardAllocation,
    RewardPool,
    RewardStrategy,
    TrustWeightedStrategy,
)
from .distributor import RewardDistributor
from .engine import RewardEngine
from .scoring import RewardDimension, RewardSignal, TrustScore
from .trust_decay import NetworkTrustEngine, TrustEvent

__all__ = [
    "RewardEngine",
    "TrustScore",
    "RewardDimension",
    "RewardSignal",
    "NetworkTrustEngine",
    "TrustEvent",
    "ContributionWeightedStrategy",
    "DistributionResult",
    "EqualSplitStrategy",
    "HierarchicalStrategy",
    "ParticipantInfo",
    "RewardAllocation",
    "RewardPool",
    "RewardStrategy",
    "TrustWeightedStrategy",
    "RewardDistributor",
]
