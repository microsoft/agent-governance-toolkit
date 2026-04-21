# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AgentMesh - The Secure Nervous System for Cloud-Native Agent Ecosystems

Identity · Trust · Reward · Governance

AgentMesh is the platform built for the Governed Agent Mesh - the cloud-native,
multi-vendor network of AI agents that will define enterprise operations.

Version: 1.0.0-alpha
"""

__version__ = "3.1.1"

# Layer 1: Identity & Zero-Trust Core
from .identity import (
    AgentIdentity,
    AgentDID,
    Credential,
    CredentialManager,
    ScopeChain,
    DelegationLink,
    HumanSponsor,
    RiskScorer,
    RiskScore,
    SPIFFEIdentity,
    SVID,
)

# Layer 2: Trust & Protocol Bridge
from .trust import (
    TrustBridge,
    ProtocolBridge,
    TrustHandshake,
    HandshakeResult,
    CapabilityScope,
    CapabilityGrant,
    CapabilityRegistry,
)

# Layer 3: Governance & Compliance Plane
from .governance import (
    PolicyEngine,
    Policy,
    PolicyRule,
    PolicyDecision,
    ComplianceEngine,
    ComplianceFramework,
    ComplianceReport,
    AuditLog,
    AuditEntry,
    AuditChain,
    ShadowMode,
    ShadowResult,
)

# Exceptions
from .exceptions import (
    AgentMeshError,
    IdentityError,
    TrustError,
    TrustVerificationError,
    TrustViolationError,
    DelegationError,
    DelegationDepthError,
    GovernanceError,
    HandshakeError,
    HandshakeTimeoutError,
    StorageError,
)

# Layer 4: Reward & Learning Engine
from .reward import (
    RewardEngine,
    TrustScore,
    RewardDimension,
    RewardSignal,
)

# Unified Client
from .client import AgentMeshClient, GovernanceResult

__all__ = [
    # Version
    "__version__",

    # Layer 1: Identity
    "AgentIdentity",
    "AgentDID",
    "Credential",
    "CredentialManager",
    "ScopeChain",
    "DelegationLink",
    "HumanSponsor",
    "RiskScorer",
    "RiskScore",
    "SPIFFEIdentity",
    "SVID",

    # Layer 2: Trust
    "TrustBridge",
    "ProtocolBridge",
    "TrustHandshake",
    "HandshakeResult",
    "CapabilityScope",
    "CapabilityGrant",
    "CapabilityRegistry",

    # Layer 3: Governance
    "PolicyEngine",
    "Policy",
    "PolicyRule",
    "PolicyDecision",
    "ComplianceEngine",
    "ComplianceFramework",
    "ComplianceReport",
    "AuditLog",
    "AuditEntry",
    "AuditChain",
    "ShadowMode",
    "ShadowResult",

    # Exceptions
    "AgentMeshError",
    "IdentityError",
    "TrustError",
    "TrustVerificationError",
    "TrustViolationError",
    "DelegationError",
    "DelegationDepthError",
    "GovernanceError",
    "HandshakeError",
    "HandshakeTimeoutError",
    "StorageError",

    # Layer 4: Reward
    "RewardEngine",
    "TrustScore",
    "RewardDimension",
    "RewardSignal",

    # Unified Client
    "AgentMeshClient",
    "GovernanceResult",

    # Trust Types (shared across integrations)
    "AgentProfile",
    "TrustRecord",
    "TrustTracker",
]

# Trust types (shared across integrations)
from agentmesh.trust_types import (
    AgentProfile,
    TrustRecord,
    TrustTracker,
)
