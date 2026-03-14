# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent-Lightning Governance Integration
=======================================

Provides kernel-level safety during Agent-Lightning RL training.

Key components:
- GovernedRunner: Agent-Lightning runner with policy enforcement
- PolicyReward: Convert policy violations to RL penalties
- FlightRecorderEmitter: Export audit logs to LightningStore
- GovernedEnvironment: Training environment with governance constraints

Example:
    >>> from agent_lightning_gov import GovernedRunner, PolicyReward
    >>> from agent_os import KernelSpace
    >>> from agent_os.policies import SQLPolicy
    >>>
    >>> kernel = KernelSpace(policy=SQLPolicy())
    >>> runner = GovernedRunner(kernel)
    >>> reward_fn = PolicyReward(kernel, base_reward_fn=accuracy)
"""

from .emitter import FlightRecorderEmitter
from .environment import GovernedEnvironment
from .reward import PolicyReward, policy_penalty
from .runner import GovernedRunner

__all__ = [
    "GovernedRunner",
    "PolicyReward",
    "policy_penalty",
    "FlightRecorderEmitter",
    "GovernedEnvironment",
]
