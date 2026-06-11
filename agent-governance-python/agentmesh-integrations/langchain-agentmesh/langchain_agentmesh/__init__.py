import warnings
warnings.warn(
    "agentmesh-langchain is deprecated and will be removed in a future release. "
    "Use agent-governance-toolkit-integrations[langchain] instead. "
    "See https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/package-consolidation/MIGRATION.md",
    DeprecationWarning,
    stacklevel=2,
)

from langchain_agentmesh.identity import VerificationIdentity, VerificationSignature, UserContext
from langchain_agentmesh.trust import (
    TrustedAgentCard,
    TrustHandshake,
    TrustVerificationResult,
    TrustPolicy,
    DelegationChain,
    Delegation,
    AgentDirectory,
)
from langchain_agentmesh.tools import TrustGatedTool, TrustedToolExecutor
from langchain_agentmesh.callbacks import TrustCallbackHandler

__all__ = [
    # Identity
    "VerificationIdentity",
    "VerificationSignature",
    "UserContext",
    # Trust
    "TrustedAgentCard",
    "TrustHandshake",
    "TrustVerificationResult",
    "TrustPolicy",
    "DelegationChain",
    "Delegation",
    "AgentDirectory",
    # Tools
    "TrustGatedTool",
    "TrustedToolExecutor",
    # Callbacks
    "TrustCallbackHandler",
]
