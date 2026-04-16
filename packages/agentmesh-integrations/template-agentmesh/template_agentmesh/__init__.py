# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
template-agentmesh: Starter template for AgentMesh trust integrations.

Copy this package and rename it for your target agent framework.
See Tutorial 28 (docs/tutorials/28-build-custom-integration.md) for the full walkthrough.

Components:
- AgentProfile: Agent identity with capabilities and trust score
- ActionResult: Outcome of a trust-gated action check
- ActionGuard: Trust score and capability verification
- TrustTracker: Trust score tracking with asymmetric reward/penalty
"""

from template_agentmesh.trust import (
    ActionGuard,
    ActionResult,
    AgentProfile,
    TrustTracker,
)

__all__ = [
    "ActionGuard",
    "ActionResult",
    "AgentProfile",
    "TrustTracker",
]
