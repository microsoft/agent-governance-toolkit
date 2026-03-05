# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent-Lightning Integration for Agent OS
=========================================

Provides kernel-level safety during Agent-Lightning RL training.

Key components:
- GovernedRunner: Agent-Lightning runner with policy enforcement
- PolicyReward: Convert policy violations to RL penalties
- FlightRecorderEmitter: Export audit logs to LightningStore

Example:
    >>> from agent_os.integrations.agent_lightning import GovernedRunner, PolicyReward
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
