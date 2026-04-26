# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AgentMesh Integrations
======================

Protocol and framework integrations for AI Card, A2A, MCP, LangGraph,
LangChain, Swarm, Langflow, Flowise, and Haystack.
"""

from .a2a import A2AAgentCard, A2ATrustProvider
from .ai_card import AICard, AICardIdentity, AICardService, AICardDiscovery
from .mcp import TrustGatedMCPServer, TrustGatedMCPClient
from .langchain import AgentMeshTrustCallback, TrustVerifiedTool, trust_verified_tool
from .langgraph import TrustedGraphNode, TrustCheckpoint
from .swarm import TrustedSwarm, TrustPolicy, TrustedAgent, HandoffVerifier
from .crewai import TrustAwareAgent, TrustAwareCrew
from .langflow import TrustGatedFlow, TrustVerificationComponent, IdentityComponent
from .flowise import TrustGatedFlowiseClient, FlowiseNodeIdentity, FlowiseTrustPolicy
from .haystack import TrustedPipeline, TrustGateComponent, TrustAgentComponent
from .http_middleware import TrustMiddleware, TrustConfig

__all__ = [
    # AI Card (cross-protocol identity standard)
    "AICard",
    "AICardIdentity",
    "AICardService",
    "AICardDiscovery",
    # A2A
    "A2AAgentCard",
    "A2ATrustProvider",
    # MCP
    "TrustGatedMCPServer",
    "TrustGatedMCPClient",
    # LangChain
    "AgentMeshTrustCallback",
    "TrustVerifiedTool",
    "trust_verified_tool",
    # LangGraph
    "TrustedGraphNode",
    "TrustCheckpoint",
    # Swarm
    "TrustedSwarm",
    "TrustPolicy",
    "TrustedAgent",
    "HandoffVerifier",
    # CrewAI
    "TrustAwareAgent",
    "TrustAwareCrew",
    # Langflow
    "TrustGatedFlow",
    "TrustVerificationComponent",
    "IdentityComponent",
    # Flowise
    "TrustGatedFlowiseClient",
    "FlowiseNodeIdentity",
    "FlowiseTrustPolicy",
    # Haystack
    "TrustedPipeline",
    "TrustGateComponent",
    "TrustAgentComponent",
    # HTTP Middleware
    "TrustMiddleware",
    "TrustConfig",
]
