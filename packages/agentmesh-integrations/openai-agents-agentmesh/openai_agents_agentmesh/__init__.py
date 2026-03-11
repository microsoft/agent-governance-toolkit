"""
openai-agents-agentmesh: Trust layer for OpenAI Agents SDK.

Components:
- TrustedFunctionGuard: Trust-gated function/tool calling
- HandoffVerifier: Trust verification for agent-to-agent handoffs
- AgentTrustContext: Trust metadata propagation
"""

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
