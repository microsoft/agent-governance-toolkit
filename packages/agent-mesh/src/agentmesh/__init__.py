# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AgentMesh - The Secure Nervous System for Cloud-Native Agent Ecosystems

Identity · Trust · Reward · Governance

AgentMesh is the platform built for the Governed Agent Mesh - the cloud-native,
multi-vendor network of AI agents that will define enterprise operations.

Version: 1.0.0-alpha
"""

__version__ = "2.0.2"

# Layer 1: Identity & Zero-Trust Core
# Exceptions
from .exceptions import (
    AgentMeshError,
    DelegationDepthError,
    DelegationError,
    GovernanceError,
    HandshakeError,
    HandshakeTimeoutError,
    IdentityError,
    StorageError,
    TrustError,
    TrustVerificationError,
    TrustViolationError,
)

# Layer 3: Governance & Compliance Plane
from .governance import (
    AuditChain,
    AuditEntry,
    AuditLog,
    ComplianceEngine,
    ComplianceFramework,
    ComplianceReport,
    Policy,
    PolicyDecision,
    PolicyEngine,
    PolicyRule,
    ShadowMode,
    ShadowResult,
)
from .identity import (
    SVID,
    AgentDID,
    AgentIdentity,
    Credential,
    CredentialManager,
    DelegationLink,
    HumanSponsor,
    RiskScore,
    RiskScorer,
    ScopeChain,
    SPIFFEIdentity,
)

# Layer 4: Reward & Learning Engine
from .reward import (
    RewardDimension,
    RewardEngine,
    RewardSignal,
    TrustScore,
)

# Layer 2: Trust & Protocol Bridge
from .trust import (
    CapabilityGrant,
    CapabilityRegistry,
    CapabilityScope,
    HandshakeResult,
    ProtocolBridge,
    TrustBridge,
    TrustHandshake,
)

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
]
