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
from .information_flow import (
    DEFAULT_RECEIPT_TTL,
    RECEIPT_FRAME_KEY,
    RECEIPT_SCHEMA_VERSION,
    InformationFlowEnvelopeLike,
    InformationFlowNonceCache,
    InformationFlowReceipt,
    InformationFlowReceiptVerification,
    attach_information_flow_receipt,
    create_information_flow_receipt,
    extract_information_flow_receipt,
    message_hash,
    verify_information_flow_receipt,
)
from .websocket import HAS_WEBSOCKETS, WebSocketTransport

__all__ = [
    # Base
    "Transport",
    "TransportConfig",
    "TransportState",
    # Distributed IFC receipts
    "DEFAULT_RECEIPT_TTL",
    "RECEIPT_FRAME_KEY",
    "RECEIPT_SCHEMA_VERSION",
    "InformationFlowEnvelopeLike",
    "InformationFlowNonceCache",
    "InformationFlowReceipt",
    "InformationFlowReceiptVerification",
    "attach_information_flow_receipt",
    "create_information_flow_receipt",
    "extract_information_flow_receipt",
    "message_hash",
    "verify_information_flow_receipt",
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
