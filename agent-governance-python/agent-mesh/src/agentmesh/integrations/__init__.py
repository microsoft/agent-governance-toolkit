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
from .http_middleware import (
    BODY_LIMIT_SCOPE_KEY,
    PeerCredential,
    SignedBodyLimitMiddleware,
    TrustConfig,
    TrustMiddleware,
    VerificationResult,
    install_fastapi_trust,
    registry_resolver,
)
from .request_auth import (
    InMemoryReplayCache,
    ReplayCache,
    ReplayCacheFull,
    RequestTargetMode,
    asgi_raw_target,
    build_request_signature_payload,
    decoded_target,
    select_signed_headers,
    wsgi_raw_target,
)

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
    "PeerCredential",
    "VerificationResult",
    "registry_resolver",
    "SignedBodyLimitMiddleware",
    "BODY_LIMIT_SCOPE_KEY",
    "install_fastapi_trust",
    # Request authentication primitives
    "build_request_signature_payload",
    "InMemoryReplayCache",
    "ReplayCache",
    "ReplayCacheFull",
    "RequestTargetMode",
    "asgi_raw_target",
    "decoded_target",
    "select_signed_headers",
    "wsgi_raw_target",
]
