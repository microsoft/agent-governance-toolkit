# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Agent Discovery — Shadow AI agent discovery and inventory for AGT.

Find, inventory, and reconcile AI agents running across your organization.
Detect unregistered "shadow" agents that operate outside governance.
"""

__version__ = "0.1.0"
__author__ = "Microsoft Corporation"

from .models import (
    AgentStatus,
    DetectionBasis,
    DiscoveredAgent,
    Evidence,
    RiskAssessment,
    RiskLevel,
    ScanResult,
    ShadowAgent,
)
from .inventory import AgentInventory
from .reconciler import Reconciler, RegistryProvider
from .risk import RiskScorer

__all__ = [
    "__version__",
    "__author__",
    # Models
    "AgentStatus",
    "DetectionBasis",
    "DiscoveredAgent",
    "Evidence",
    "RiskAssessment",
    "RiskLevel",
    "ScanResult",
    "ShadowAgent",
    # Core
    "AgentInventory",
    "Reconciler",
    "RegistryProvider",
    "RiskScorer",
]
