# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Nexus Schema Definitions

Pydantic models for all Nexus data structures.
"""

from .manifest import (
    AgentIdentity,
    AgentCapabilities,
    AgentPrivacy,
    MuteRules,
    AgentManifest,
)
from .receipt import (
    JobReceipt,
    JobCompletionReceipt,
    SignedReceipt,
)
from .escrow import (
    EscrowRequest,
    EscrowReceipt,
    EscrowStatus,
    EscrowRelease,
)
from .compliance import (
    ComplianceRecord,
    ComplianceAuditReport,
)

__all__ = [
    # Manifest
    "AgentIdentity",
    "AgentCapabilities",
    "AgentPrivacy",
    "MuteRules",
    "AgentManifest",
    # Receipt
    "JobReceipt",
    "JobCompletionReceipt",
    "SignedReceipt",
    # Escrow
    "EscrowRequest",
    "EscrowReceipt",
    "EscrowStatus",
    "EscrowRelease",
    # Compliance
    "ComplianceRecord",
    "ComplianceAuditReport",
]
