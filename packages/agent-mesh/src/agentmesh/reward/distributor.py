# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Reward Distributor Engine.

Registry-based engine that manages named distribution strategies
and validates distribution results.
"""

from __future__ import annotations

import math

from .distribution import (
    ContributionWeightedStrategy,
    DistributionResult,
    EqualSplitStrategy,
    HierarchicalStrategy,
    RewardPool,
    RewardStrategy,
    TrustWeightedStrategy,
)


class RewardDistributor:
    """Distributes rewards using pluggable, named strategies.

    Built-in strategies (registered by default):
    - ``equal`` — equal split
    - ``trust_weighted`` — weighted by trust score
    - ``hierarchical`` — scope-chain proportional
    - ``contribution`` — explicit contribution weights
    """

    def __init__(self, default_strategy: str = "trust_weighted") -> None:
        self._strategies: dict[str, RewardStrategy] = {}
        self._default_strategy = default_strategy

        # Register built-in strategies
        self.register_strategy("equal", EqualSplitStrategy())
        self.register_strategy("trust_weighted", TrustWeightedStrategy())
        self.register_strategy("hierarchical", HierarchicalStrategy())
        self.register_strategy("contribution", ContributionWeightedStrategy())

    def register_strategy(self, name: str, strategy: RewardStrategy) -> None:
        """Register a custom or replacement strategy under *name*."""
        self._strategies[name] = strategy

    def distribute(
        self,
        pool: RewardPool,
        strategy_name: str | None = None,
    ) -> DistributionResult:
        """Distribute rewards from *pool* using the named strategy.

        Args:
            pool: The reward pool to distribute.
            strategy_name: Strategy name. Falls back to the default strategy.

        Raises:
            ValueError: If the strategy name is not registered.
            ValueError: If total distributed differs from total reward.
        """
        name = strategy_name or self._default_strategy
        strategy = self._strategies.get(name)
        if strategy is None:
            raise ValueError(
                f"Unknown strategy '{name}'. "
                f"Registered: {sorted(self._strategies)}"
            )

        result = strategy.distribute(pool)

        # Validate conservation of total reward (skip when pool is empty)
        if pool.participants and not math.isclose(
            result.total_distributed, pool.total_reward, abs_tol=1e-9
        ):
            raise ValueError(
                f"Distribution mismatch: distributed {result.total_distributed} "
                f"but pool total is {pool.total_reward}"
            )

        return result
