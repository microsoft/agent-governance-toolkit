# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""AgentMesh Transport Layer.

Provides pluggable transport backends for agent-to-agent communication:
- **WebSocket** — real-time bidirectional streaming with trust update push.
- **gRPC** — high-performance RPC with typed message schemas.
"""

from .base import Transport, TransportConfig, TransportState
from .grpc_transport import (
    GRPCTransport,
    HandshakeRequest,
    HandshakeResponse,
    HAS_GRPC,
    PolicyCheckRequest,
    PolicyCheckResponse,
    TrustDimension,
    TrustRequest,
    TrustResponse,
)
from .websocket import HAS_WEBSOCKETS, WebSocketTransport

__all__ = [
    # Base
    "Transport",
    "TransportConfig",
    "TransportState",
    # WebSocket
    "WebSocketTransport",
    "HAS_WEBSOCKETS",
    # gRPC
    "GRPCTransport",
    "HAS_GRPC",
    # gRPC message schemas
    "TrustRequest",
    "TrustResponse",
    "HandshakeRequest",
    "HandshakeResponse",
    "PolicyCheckRequest",
    "PolicyCheckResponse",
    "TrustDimension",
]
