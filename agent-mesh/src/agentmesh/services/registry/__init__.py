# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Registry Service

The "Yellow Pages" of agents with DIDs and reputation scores.
"""

from .agent_registry import AgentRegistry, AgentRegistryEntry

__all__ = [
    "AgentRegistry",
    "AgentRegistryEntry",
]
