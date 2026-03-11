"""
crewai-agentmesh: Trust layer for CrewAI multi-agent workflows.

Components:
- AgentProfile: Agent identity with capabilities and trust score
- TrustedCrew: Trust-verified crew member selection
- CapabilityGate: Task-to-agent capability matching
- TrustTracker: Trust score tracking across crew runs
"""

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
