# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""AgentMesh - the secure nervous system for cloud-native agent ecosystems.

.. deprecated::
    ``agentmesh-platform`` is deprecated and will be removed in a future
    release. Use ``agent-governance-toolkit-core`` instead. See
    https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/package-consolidation/MIGRATION.md
"""

import warnings

warnings.warn(
    "agentmesh-platform is deprecated and will be removed in a future release. "
    "Use agent-governance-toolkit-core instead. "
    "See https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/package-consolidation/MIGRATION.md",
    DeprecationWarning,
    stacklevel=2,
)

# Keep in sync with the ``version`` field in pyproject.toml.
__version__ = "4.1.0"

# Telemetry bootstrap
from agentmesh.telemetry import bootstrap_otel, is_bootstrapped  # noqa: E402

# Trust types (shared across integrations)
from agentmesh.trust_types import (  # noqa: E402
    AgentProfile,
    TrustRecord,
    TrustTracker,
)

# Unified Client
from .client import AgentMeshClient, GovernanceResult  # noqa: E402

# Exceptions
from .exceptions import (  # noqa: E402
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
from .governance import (  # noqa: E402
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
from .identity import (  # noqa: E402
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
from .reward import (  # noqa: E402
    RewardDimension,
    RewardEngine,
    RewardSignal,
    TrustScore,
)

# Layer 2: Trust & Protocol Bridge
from .trust import (  # noqa: E402
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
    # Unified Client
    "AgentMeshClient",
    "GovernanceResult",
    # Trust Types (shared across integrations)
    "AgentProfile",
    "TrustRecord",
    "TrustTracker",
    # Telemetry
    "bootstrap_otel",
    "is_bootstrapped",
]
