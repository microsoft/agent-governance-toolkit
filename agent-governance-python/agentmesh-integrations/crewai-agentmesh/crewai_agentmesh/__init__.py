import warnings
warnings.warn(
    "crewai-agentmesh is deprecated and will be removed in a future release. "
    "Use agent-governance-toolkit-integrations[crewai] instead. "
    "See https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/package-consolidation/MIGRATION.md",
    DeprecationWarning,
    stacklevel=2,
)

from crewai_agentmesh.trust import (
    AgentProfile,
    CapabilityGate,
    TrustedCrew,
    TrustTracker,
    TaskAssignment,
)

__all__ = [
    "AgentProfile",
    "CapabilityGate",
    "TrustedCrew",
    "TrustTracker",
    "TaskAssignment",
]
