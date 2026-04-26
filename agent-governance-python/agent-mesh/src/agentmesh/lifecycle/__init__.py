# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Agent Lifecycle Management for AgentMesh.

Provides birth-to-retirement management of agent identities:
- Provisioning with approval workflows
- Credential rotation (automatic short-lived credentials)
- Health monitoring and heartbeat tracking
- Orphan/ghost agent detection
- Decommissioning with credential revocation
"""

from .models import (
    AgentLifecycleState,
    CredentialPolicy,
    LifecycleEvent,
    LifecycleEventType,
    LifecyclePolicy,
    ManagedAgent,
)
from .manager import LifecycleManager
from .credentials import CredentialRotator
from .orphan_detector import OrphanDetector

__all__ = [
    "AgentLifecycleState",
    "CredentialPolicy",
    "CredentialRotator",
    "LifecycleEvent",
    "LifecycleEventType",
    "LifecycleManager",
    "LifecyclePolicy",
    "ManagedAgent",
    "OrphanDetector",
]
