# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
AgentMesh Integrations
======================

Protocol and framework integrations for AI Card, A2A, MCP, LangGraph,
LangChain, Swarm, Langflow, Flowise, and Haystack.
"""

from .a2a import A2AAgentCard, A2ATrustProvider
from .ai_card import AICard, AICardDiscovery, AICardIdentity, AICardService
from .crewai import TrustAwareAgent, TrustAwareCrew
from .flowise import FlowiseNodeIdentity, FlowiseTrustPolicy, TrustGatedFlowiseClient
from .haystack import TrustAgentComponent, TrustedPipeline, TrustGateComponent
from .http_middleware import TrustConfig, TrustMiddleware
from .langchain import AgentMeshTrustCallback, TrustVerifiedTool, trust_verified_tool
from .langflow import IdentityComponent, TrustGatedFlow, TrustVerificationComponent
from .langgraph import TrustCheckpoint, TrustedGraphNode
from .mcp import TrustGatedMCPClient, TrustGatedMCPServer
from .swarm import HandoffVerifier, TrustedAgent, TrustedSwarm, TrustPolicy

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
