"""
a2a-agentmesh: A2A Protocol Bridge for AgentMesh
=================================================

Maps AgentMesh identities and trust verification to the
Google A2A (Agent-to-Agent) protocol standard.

Components:
- AgentCard: A2A-compliant agent discovery cards
- TaskEnvelope: Trust-verified task request/response wrappers
- TrustGate: Policy enforcement for A2A task negotiations
"""

from a2a_agentmesh.agent_card import AgentCard, AgentSkill
from a2a_agentmesh.task import (
    TaskEnvelope,
    TaskState,
    TaskMessage,
)
from a2a_agentmesh.trust_gate import TrustGate, TrustPolicy, TrustResult

__all__ = [
    "AgentCard",
    "AgentSkill",
    "TaskEnvelope",
    "TaskState",
    "TaskMessage",
    "TrustGate",
    "TrustPolicy",
    "TrustResult",
]
