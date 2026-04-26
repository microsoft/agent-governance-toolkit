# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
PolicyReward - Convert Policy Violations to RL Penalties
=========================================================

Provides reward functions that integrate Agent OS governance
into Agent-Lightning's RL training loop.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable

logger = logging.getLogger(__name__)


@dataclass
class RewardConfig:
    """Configuration for policy-aware rewards."""

    # Penalty for each violation severity level
    critical_penalty: float = -100.0
    high_penalty: float = -50.0
    medium_penalty: float = -10.0
    low_penalty: float = -1.0

    # Bonus for clean execution (no violations)
    clean_bonus: float = 5.0

    # Whether to use multiplicative penalty (reward * factor) vs additive
    multiplicative: bool = False
    multiplicative_factor: float = 0.5  # Multiply reward by this on violation

    # Minimum reward floor (prevent extreme negative rewards)
    min_reward: float | None = -100.0

    # Maximum reward ceiling
    max_reward: float | None = 100.0


def policy_penalty(
    violations: list[Any],
    *,
    critical_penalty: float = -100.0,
    high_penalty: float = -50.0,
    medium_penalty: float = -10.0,
    low_penalty: float = -1.0,
) -> float:
    """
    Calculate penalty from a list of policy violations.

    This is a simple helper for computing penalties outside of the
    full PolicyReward class.

    Args:
        violations: List of PolicyViolation objects
        critical_penalty: Penalty for critical violations
        high_penalty: Penalty for high severity violations
        medium_penalty: Penalty for medium severity violations
        low_penalty: Penalty for low severity violations

    Returns:
        Total penalty (negative number)

    Example:
        >>> penalty = policy_penalty(rollout.violations)
        >>> final_reward = base_reward + penalty
    """
    severity_penalties = {
        "critical": critical_penalty,
        "high": high_penalty,
        "medium": medium_penalty,
        "low": low_penalty,
    }

    total_penalty = 0.0
    for violation in violations:
        severity = getattr(violation, 'severity', 'medium')
        total_penalty += severity_penalties.get(severity, medium_penalty)

    return total_penalty


class PolicyReward:
    """
    Reward function wrapper that adds policy violation penalties.

    This class wraps any base reward function and subtracts penalties
    for policy violations, creating a learning signal that discourages
    unsafe behavior during RL training.

    Example:
        >>> from agent_os import KernelSpace
        >>> from agent_os.policies import SQLPolicy
        >>>
        >>> kernel = KernelSpace(policy=SQLPolicy())
        >>>
        >>> # Define base reward (task completion, accuracy, etc.)
        >>> def accuracy_reward(rollout):
        ...     return rollout.task_output.accuracy if rollout.success else 0.0
        >>>
        >>> # Wrap with policy awareness
        >>> reward_fn = PolicyReward(kernel, base_reward_fn=accuracy_reward)
        >>>
        >>> # Use in training
        >>> reward = reward_fn(rollout)
    """

    def __init__(
        self,
        kernel: Any,  # KernelSpace
        *,
        base_reward_fn: Callable[[Any], float] | None = None,
        config: RewardConfig | None = None,
    ):
        """
        Initialize policy-aware reward function.

        Args:
            kernel: Agent OS KernelSpace for policy checking
            base_reward_fn: Optional base reward function
            config: Reward configuration
        """
        self.kernel = kernel
        self.base_reward_fn = base_reward_fn or self._default_base_reward
        self.config = config or RewardConfig()

        # Track reward statistics
        self._total_rewards = 0
        self._total_penalties = 0.0
        self._violation_count = 0
        self._clean_count = 0

    def _default_base_reward(self, rollout: Any) -> float:
        """Default base reward: 1.0 for success, 0.0 for failure."""
        if hasattr(rollout, 'success'):
            return 1.0 if rollout.success else 0.0
        if hasattr(rollout, 'task_output'):
            return 1.0 if rollout.task_output is not None else 0.0
        return 0.0

    def __call__(
        self,
        rollout: Any,
        *,
        emit: bool = True,
    ) -> float:
        """
        Calculate reward for a rollout.

        Args:
            rollout: GovernedRollout or similar object with violations
            emit: Whether to emit reward to Agent-Lightning

        Returns:
            Final reward with policy penalties applied
        """
        # Calculate base reward
        base_reward = self.base_reward_fn(rollout)

        # Get violations from rollout or check kernel
        violations = self._get_violations(rollout)

        # Calculate penalty
        penalty = self._calculate_penalty(violations)

        # Calculate final reward
        if self.config.multiplicative and violations:
            final_reward = base_reward * self.config.multiplicative_factor
        else:
            final_reward = base_reward + penalty

        # Apply clean execution bonus
        if not violations:
            final_reward += self.config.clean_bonus
            self._clean_count += 1
        else:
            self._violation_count += 1

        # Apply bounds
        if self.config.min_reward is not None:
            final_reward = max(final_reward, self.config.min_reward)
        if self.config.max_reward is not None:
            final_reward = min(final_reward, self.config.max_reward)

        # Update statistics
        self._total_rewards += 1
        self._total_penalties += penalty

        # Emit to Agent-Lightning
        if emit:
            self._emit_reward(final_reward, base_reward, penalty, violations)

        return final_reward

    def _get_violations(self, rollout: Any) -> list[Any]:
        """Extract violations from rollout."""
        if hasattr(rollout, 'violations'):
            return rollout.violations

        # Try to get from kernel's recent history
        if hasattr(self.kernel, 'get_recent_violations'):
            return self.kernel.get_recent_violations()

        return []

    def _calculate_penalty(self, violations: list[Any]) -> float:
        """Calculate total penalty from violations."""
        return policy_penalty(
            violations,
            critical_penalty=self.config.critical_penalty,
            high_penalty=self.config.high_penalty,
            medium_penalty=self.config.medium_penalty,
            low_penalty=self.config.low_penalty,
        )

    def _emit_reward(
        self,
        final_reward: float,
        base_reward: float,
        penalty: float,
        violations: list[Any],
    ) -> None:
        """Emit reward to Agent-Lightning."""
        try:
            from agentlightning.emitter import emit_reward

            # Emit multi-dimensional reward
            emit_reward(
                {
                    "final": final_reward,
                    "base": base_reward,
                    "policy_penalty": penalty,
                },
                primary_key="final",
                attributes={
                    "agent_os.violation_count": len(violations),
                    "agent_os.policy_compliant": len(violations) == 0,
                },
            )
        except ImportError:
            # Agent-Lightning not available
            pass

    def get_stats(self) -> dict[str, Any]:
        """Get reward statistics."""
        total = self._total_rewards or 1  # Avoid division by zero
        return {
            "total_rewards": self._total_rewards,
            "total_penalties": self._total_penalties,
            "avg_penalty": self._total_penalties / total,
            "violation_rate": self._violation_count / total,
            "clean_rate": self._clean_count / total,
        }

    def reset_stats(self) -> None:
        """Reset statistics."""
        self._total_rewards = 0
        self._total_penalties = 0.0
        self._violation_count = 0
        self._clean_count = 0


class CompositeReward:
    """
    Combine multiple reward functions with weights.

    Example:
        >>> reward = CompositeReward([
        ...     (accuracy_reward, 1.0),
        ...     (policy_reward, 0.5),
        ...     (efficiency_reward, 0.3),
        ... ])
    """

    def __init__(
        self,
        components: list[tuple[Callable[[Any], float], float]],
        *,
        normalize: bool = False,
    ):
        """
        Initialize composite reward.

        Args:
            components: List of (reward_fn, weight) tuples
            normalize: Whether to normalize weights to sum to 1
        """
        self.components = components

        if normalize:
            total_weight = sum(w for _, w in components)
            self.components = [(fn, w / total_weight) for fn, w in components]

    def __call__(self, rollout: Any) -> float:
        """Calculate weighted sum of all reward components."""
        total = 0.0
        for reward_fn, weight in self.components:
            total += weight * reward_fn(rollout)
        return total


def create_policy_reward(
    kernel: Any,
    *,
    base_reward_fn: Callable[[Any], float] | None = None,
    severity_penalties: dict[str, float] | None = None,
    clean_bonus: float = 5.0,
    multiplicative: bool = False,
) -> PolicyReward:
    """
    Factory function to create a PolicyReward with custom configuration.

    Args:
        kernel: Agent OS KernelSpace
        base_reward_fn: Base reward function
        severity_penalties: Dict mapping severity to penalty
        clean_bonus: Bonus for clean execution
        multiplicative: Use multiplicative penalty

    Returns:
        Configured PolicyReward instance
    """
    config = RewardConfig(clean_bonus=clean_bonus, multiplicative=multiplicative)

    if severity_penalties:
        if "critical" in severity_penalties:
            config.critical_penalty = severity_penalties["critical"]
        if "high" in severity_penalties:
            config.high_penalty = severity_penalties["high"]
        if "medium" in severity_penalties:
            config.medium_penalty = severity_penalties["medium"]
        if "low" in severity_penalties:
            config.low_penalty = severity_penalties["low"]

    return PolicyReward(kernel, base_reward_fn=base_reward_fn, config=config)
