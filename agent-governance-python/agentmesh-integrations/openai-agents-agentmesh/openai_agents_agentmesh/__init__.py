import warnings
warnings.warn(
    "openai-agents-agentmesh is deprecated and will be removed in a future release. "
    "Use agent-governance-toolkit-integrations[openai-agents] instead. "
    "See https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/package-consolidation/MIGRATION.md",
    DeprecationWarning,
    stacklevel=2,
)

from openai_agents_agentmesh.trust import (
    AgentTrustContext,
    HandoffResult,
    HandoffVerifier,
    FunctionCallResult,
    TrustedFunctionGuard,
)

__all__ = [
    "AgentTrustContext",
    "HandoffResult",
    "HandoffVerifier",
    "FunctionCallResult",
    "TrustedFunctionGuard",
]
