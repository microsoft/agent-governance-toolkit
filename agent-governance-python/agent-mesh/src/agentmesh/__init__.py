# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""AgentMesh - the secure nervous system for cloud-native agent ecosystems.

.. deprecated::
    ``agentmesh-platform`` is deprecated and will be removed in a future
    release. Use ``agent-governance-toolkit-core`` instead. See
    https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/package-consolidation/MIGRATION.md
"""

from __future__ import annotations

import importlib
import warnings
from typing import TYPE_CHECKING, Any

warnings.warn(
    "agentmesh-platform is deprecated and will be removed in a future release. "
    "Use agent-governance-toolkit-core instead. "
    "See https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/package-consolidation/MIGRATION.md",
    DeprecationWarning,
    stacklevel=2,
)

# Keep in sync with the ``version`` field in pyproject.toml.
__version__ = "5.0.0"

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

if TYPE_CHECKING:  # pragma: no cover - import resolved by type checkers only
    # Mirrors __all__/_LAZY_SUBMODULE_BY_NAME below so static analysis (mypy,
    # pyright) still sees each name's real type instead of Any - matches the
    # pattern already used in agentmesh.engine_api. Never executed at
    # runtime; __getattr__ is what actually resolves these names.
    from .client import AgentMeshClient, GovernanceResult
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
    from .reward import RewardDimension, RewardEngine, RewardSignal, TrustScore
    from .telemetry import bootstrap_otel, is_bootstrapped
    from .trust import (
        CapabilityGrant,
        CapabilityRegistry,
        CapabilityScope,
        HandshakeResult,
        ProtocolBridge,
        TrustBridge,
        TrustHandshake,
    )
    from .trust_types import AgentProfile, TrustRecord, TrustTracker

# Every public name above (everything except __version__) is resolved lazily
# from its owning submodule on first access, via the PEP 562 __getattr__
# below - none of these submodules are imported at package-init time.
#
# Before this change, `agentmesh/__init__.py` imported every layer eagerly
# at module level, and Python always runs this file before any submodule
# import completes - so even `import agentmesh.governance` (which only
# needs the governance package's own ~30 lines of code) paid the full cost
# of `.client`, `.identity`, `.trust`, `.reward`, and `.telemetry` too.
# `.client` alone pulls in `agentmesh.identity` (httpx-based external JWKS
# federation) and `agentmesh.reward`, making a cold `import
# agentmesh.governance` cost ~3.5s for code that never touches identity,
# trust, or reward at all - the exact case that motivated this (see
# https://github.com/microsoft/agent-governance-toolkit/issues/3923).
_LAZY_SUBMODULE_BY_NAME: dict[str, str] = {
    **dict.fromkeys(("bootstrap_otel", "is_bootstrapped"), "telemetry"),
    **dict.fromkeys(("AgentProfile", "TrustRecord", "TrustTracker"), "trust_types"),
    **dict.fromkeys(("AgentMeshClient", "GovernanceResult"), "client"),
    **dict.fromkeys(
        (
            "AgentMeshError",
            "DelegationDepthError",
            "DelegationError",
            "GovernanceError",
            "HandshakeError",
            "HandshakeTimeoutError",
            "IdentityError",
            "StorageError",
            "TrustError",
            "TrustVerificationError",
            "TrustViolationError",
        ),
        "exceptions",
    ),
    **dict.fromkeys(
        (
            "AuditChain",
            "AuditEntry",
            "AuditLog",
            "ComplianceEngine",
            "ComplianceFramework",
            "ComplianceReport",
            "Policy",
            "PolicyDecision",
            "PolicyEngine",
            "PolicyRule",
            "ShadowMode",
            "ShadowResult",
        ),
        "governance",
    ),
    **dict.fromkeys(
        (
            "SVID",
            "AgentDID",
            "AgentIdentity",
            "Credential",
            "CredentialManager",
            "DelegationLink",
            "HumanSponsor",
            "RiskScore",
            "RiskScorer",
            "ScopeChain",
            "SPIFFEIdentity",
        ),
        "identity",
    ),
    **dict.fromkeys(
        ("RewardDimension", "RewardEngine", "RewardSignal", "TrustScore"),
        "reward",
    ),
    **dict.fromkeys(
        (
            "CapabilityGrant",
            "CapabilityRegistry",
            "CapabilityScope",
            "HandshakeResult",
            "ProtocolBridge",
            "TrustBridge",
            "TrustHandshake",
        ),
        "trust",
    ),
}

# On main, `agentmesh.client`/`.identity`/`.trust`/`.reward`/`.telemetry`/
# `.governance`/`.exceptions`/`.trust_types` were all accessible as plain
# submodule attributes (e.g. `import agentmesh; agentmesh.identity`) purely
# as a side effect of the eager `from .<submodule> import (...)` statements this
# file used to have - any submodule import binds the submodule itself onto
# its parent package. Preserve that without re-adding the eager imports:
# each of these names resolves to the submodule object itself.
_LAZY_SUBMODULES: tuple[str, ...] = (
    "client",
    "exceptions",
    "governance",
    "identity",
    "reward",
    "telemetry",
    "trust",
    "trust_types",
)


def __getattr__(name: str) -> Any:
    """Resolve a public name (or owning submodule) on first access.

    Caches the result as a real module attribute (``globals()[name] =
    value``), so this only runs once per name - every access after the
    first is a plain attribute lookup, not a re-import.
    """
    if name in _LAZY_SUBMODULES:
        value = importlib.import_module(f".{name}", __name__)
    else:
        submodule_name = _LAZY_SUBMODULE_BY_NAME.get(name)
        if submodule_name is None:
            raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
        submodule = importlib.import_module(f".{submodule_name}", __name__)
        value = getattr(submodule, name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_LAZY_SUBMODULE_BY_NAME) | set(_LAZY_SUBMODULES))
