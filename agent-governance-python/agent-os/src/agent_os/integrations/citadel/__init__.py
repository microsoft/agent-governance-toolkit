# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Citadel Integration Module

Provides integration between AGT and the Foundry Citadel Platform:
- Policy bundle binding for Citadel Access Contracts
- Audit event export to Azure Event Hub / Application Insights
- Correlation ID management for unified observability
"""

from __future__ import annotations

from agent_os.integrations.citadel.policy_bundle import (
    PolicyBundle,
    PolicyBundleResolver,
)

__all__ = [
    "PolicyBundle",
    "PolicyBundleResolver",
]
