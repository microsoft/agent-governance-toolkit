# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
GovernedEnvironment - Training Environment with Governance
==========================================================

Wraps an Agent OS kernel as a training environment for
Agent-Lightning's RL algorithms.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Generic, TypeVar

logger = logging.getLogger(__name__)

T_state = TypeVar("T_state")
T_action = TypeVar("T_action")


@dataclass
class EnvironmentConfig:
    """Configuration for governed training environment."""

    # Maximum steps per episode
    max_steps: int = 100

    # Penalty for policy violations
    violation_penalty: float = -10.0

    # Terminate episode on critical violation
    terminate_on_critical: bool = True

    # Reward shaping
    step_penalty: float = -0.1  # Small penalty per step to encourage efficiency
    success_bonus: float = 10.0

    # Reset behavior
    reset_kernel_state: bool = True


@dataclass
class EnvironmentState:
    """State of the governed environment."""

    step_count: int = 0
    total_reward: float = 0.0
    violations: list = field(default_factory=list)
    terminated: bool = False
    truncated: bool = False
    info: dict = field(default_factory=dict)


class GovernedEnvironment(Generic[T_state, T_action]):
    """
    RL training environment with Agent OS governance.

    This environment wraps an Agent OS kernel and can be used
    directly with Agent-Lightning or other RL frameworks.

    The environment:
    1. Enforces policies on each action
    2. Converts violations to negative rewards
    3. Optionally terminates on critical violations
    4. Tracks compliance metrics during training

    Example:
        >>> from agent_os import KernelSpace
        >>> from agent_os.policies import SQLPolicy
        >>>
        >>> kernel = KernelSpace(policy=SQLPolicy())
        >>> env = GovernedEnvironment(kernel)
        >>>
        >>> state = env.reset()
        >>> while not env.terminated:
        ...     action = agent.get_action(state)
        ...     state, reward, terminated, truncated, info = env.step(action)

    Compatible with:
    - Agent-Lightning trainers
    - OpenAI Gym / Gymnasium
    - Stable Baselines3
    - Any environment with step/reset interface
    """

    def __init__(
        self,
        kernel: Any,  # KernelSpace
        *,
        task_generator: Callable[[], T_state] | None = None,
        reward_fn: Callable[[T_state, T_action, Any], float] | None = None,
        config: EnvironmentConfig | None = None,
    ):
        """
        Initialize the governed environment.

        Args:
            kernel: Agent OS KernelSpace with loaded policies
            task_generator: Optional function to generate initial states
            reward_fn: Optional custom reward function
            config: Environment configuration
        """
        self.kernel = kernel
        self.task_generator = task_generator
        self.reward_fn = reward_fn or self._default_reward
        self.config = config or EnvironmentConfig()

        # Current episode state
        self._state = EnvironmentState()
        self._current_task: T_state | None = None
        self._current_violations: list = []

        # Metrics
        self._total_episodes = 0
        self._total_steps = 0
        self._total_violations = 0
        self._successful_episodes = 0

        # Set up kernel hooks
        self._setup_hooks()

        logger.info("GovernedEnvironment initialized")

    def _setup_hooks(self) -> None:
        """Set up hooks to capture violations."""
        if hasattr(self.kernel, 'on_policy_violation'):
            self.kernel.on_policy_violation(self._handle_violation)

    def _handle_violation(
        self,
        policy_name: str,
        description: str,
        severity: str,
        blocked: bool,
    ) -> None:
        """Handle policy violation during step."""
        violation = {
            "policy": policy_name,
            "description": description,
            "severity": severity,
            "blocked": blocked,
            "step": self._state.step_count,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self._current_violations.append(violation)
        self._state.violations.append(violation)
        self._total_violations += 1

    def _default_reward(
        self,
        state: T_state,
        action: T_action,
        result: Any,
    ) -> float:
        """Default reward function."""
        # Base reward for task completion
        if result is not None:
            return 1.0
        return 0.0

    def reset(
        self,
        *,
        seed: int | None = None,
        options: dict[str, Any] | None = None,
    ) -> tuple[T_state, dict[str, Any]]:
        """
        Reset environment for new episode.

        Args:
            seed: Random seed (for compatibility)
            options: Additional options

        Returns:
            Tuple of (initial_state, info_dict)
        """
        # Reset episode state
        self._state = EnvironmentState()
        self._current_violations = []
        self._total_episodes += 1

        # Reset kernel state if configured
        if self.config.reset_kernel_state and hasattr(self.kernel, 'reset'):
            self.kernel.reset()

        # Generate initial task
        if self.task_generator:
            self._current_task = self.task_generator()
        else:
            self._current_task = None

        info = {
            "episode": self._total_episodes,
            "kernel_policies": self._get_policy_names(),
        }

        return self._current_task, info

    def step(
        self,
        action: T_action,
    ) -> tuple[T_state, float, bool, bool, dict[str, Any]]:
        """
        Execute one step in the environment.

        Args:
            action: Agent's action

        Returns:
            Tuple of (next_state, reward, terminated, truncated, info)
        """
        self._current_violations = []
        self._state.step_count += 1
        self._total_steps += 1

        # Execute action through kernel
        try:
            if hasattr(self.kernel, 'execute'):
                result = self.kernel.execute(action)
            else:
                result = action  # No kernel execution, passthrough

            success = True
        except Exception as e:
            logger.error(f"Step failed: {e}")
            result = None
            success = False

        # Calculate reward
        reward = self.reward_fn(self._current_task, action, result)

        # Apply step penalty
        reward += self.config.step_penalty

        # Apply violation penalties
        for violation in self._current_violations:
            penalty = self.config.violation_penalty
            if violation["severity"] == "critical":
                penalty *= 10
            elif violation["severity"] == "high":
                penalty *= 5
            reward += penalty

        self._state.total_reward += reward

        # Check termination conditions
        terminated = False
        truncated = False

        # Terminate on critical violation if configured
        if self.config.terminate_on_critical:
            if any(v["severity"] == "critical" for v in self._current_violations):
                terminated = True
                logger.info("Episode terminated due to critical violation")

        # Truncate on max steps
        if self._state.step_count >= self.config.max_steps:
            truncated = True

        # Mark success
        if success and not self._current_violations:
            reward += self.config.success_bonus
            self._successful_episodes += 1

        self._state.terminated = terminated
        self._state.truncated = truncated

        info = {
            "violations": self._current_violations,
            "step": self._state.step_count,
            "total_reward": self._state.total_reward,
            "success": success,
        }
        self._state.info = info

        return self._current_task, reward, terminated, truncated, info

    def _get_policy_names(self) -> list[str]:
        """Get names of loaded policies."""
        if hasattr(self.kernel, 'get_policies'):
            return [p.name for p in self.kernel.get_policies()]
        if hasattr(self.kernel, 'policies'):
            return [getattr(p, 'name', str(p)) for p in self.kernel.policies]
        return []

    @property
    def terminated(self) -> bool:
        """Whether current episode is terminated."""
        return self._state.terminated or self._state.truncated

    def get_metrics(self) -> dict[str, Any]:
        """Get environment metrics."""
        return {
            "total_episodes": self._total_episodes,
            "total_steps": self._total_steps,
            "total_violations": self._total_violations,
            "successful_episodes": self._successful_episodes,
            "success_rate": self._successful_episodes / max(self._total_episodes, 1),
            "violations_per_episode": self._total_violations / max(self._total_episodes, 1),
            "steps_per_episode": self._total_steps / max(self._total_episodes, 1),
        }

    def close(self) -> None:
        """Clean up environment resources."""
        logger.info(f"Environment closed. Metrics: {self.get_metrics()}")


def create_governed_env(
    kernel: Any,
    **kwargs: Any,
) -> GovernedEnvironment:
    """
    Factory function to create a GovernedEnvironment.

    Args:
        kernel: Agent OS KernelSpace
        **kwargs: Environment configuration

    Returns:
        Configured GovernedEnvironment
    """
    config = EnvironmentConfig()
    for key, value in kwargs.items():
        if hasattr(config, key):
            setattr(config, key, value)

    return GovernedEnvironment(kernel, config=config)
