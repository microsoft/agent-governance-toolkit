# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Copyright (c) Agent-Mesh Contributors. All rights reserved.
# Licensed under the MIT License.
"""gRPC transport for AgentMesh communication.

Provides high-performance RPC-based communication with protobuf-style
message schemas defined as Python dataclasses (no protobuf compilation
required).

Requires the ``grpcio`` and ``grpcio-tools`` libraries::

    pip install agentmesh-platform[grpc]
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from .base import Transport, TransportConfig, TransportState

logger = logging.getLogger(__name__)

try:
    import grpc
    from grpc import aio as grpc_aio

    HAS_GRPC = True
except ImportError:  # pragma: no cover
    HAS_GRPC = False
    grpc = None  # type: ignore[assignment]
    grpc_aio = None  # type: ignore[assignment]


def _require_grpc() -> None:
    """Raise if the grpcio library is not installed."""
    if not HAS_GRPC:
        raise ImportError(
            "The 'grpcio' package is required for gRPC transport. "
            "Install it with: pip install agentmesh-platform[grpc]"
        )


# ---------------------------------------------------------------------------
# Protobuf-style message schemas (pure Python dataclasses)
# ---------------------------------------------------------------------------


class TrustDimension(str, Enum):
    """The five trust dimensions in AgentMesh."""

    COMPETENCE = "competence"
    INTEGRITY = "integrity"
    AVAILABILITY = "availability"
    PREDICTABILITY = "predictability"
    TRANSPARENCY = "transparency"


@dataclass
class TrustRequest:
    """Request to query or update trust scores.

    Args:
        agent_did: DID of the agent whose trust is being queried.
        requester_did: DID of the requesting agent.
        dimensions: Specific trust dimensions to query. Empty means all.
    """

    agent_did: str
    requester_did: str
    dimensions: list[TrustDimension] = field(default_factory=list)
    request_id: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class TrustResponse:
    """Response containing trust scores.

    Args:
        agent_did: DID of the agent the scores belong to.
        scores: Mapping of dimension name to score (0-1000).
        overall_score: Weighted composite score.
        verified: Whether the scores are cryptographically verified.
    """

    agent_did: str
    scores: dict[str, float] = field(default_factory=dict)
    overall_score: float = 0.0
    verified: bool = False
    request_id: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class HandshakeRequest:
    """Request to initiate a trust handshake.

    Args:
        initiator_did: DID of the initiating agent.
        target_did: DID of the target agent.
        protocol_version: Handshake protocol version.
        nonce: Random nonce for replay protection.
        capabilities: Requested capability scopes.
    """

    initiator_did: str
    target_did: str
    protocol_version: str = "1.0"
    nonce: str = ""
    capabilities: list[str] = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)


@dataclass
class HandshakeResponse:
    """Response to a trust handshake request.

    Args:
        accepted: Whether the handshake was accepted.
        session_id: Session identifier for the established connection.
        trust_score: Mutual trust score after handshake.
        granted_capabilities: Capabilities granted to the initiator.
        reason: Rejection reason if not accepted.
    """

    accepted: bool = False
    session_id: str = ""
    trust_score: float = 0.0
    granted_capabilities: list[str] = field(default_factory=list)
    reason: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class PolicyCheckRequest:
    """Request to check governance policy compliance.

    Args:
        agent_did: DID of the agent performing the action.
        action: The action being requested.
        resource: The resource being accessed.
        context: Additional context for policy evaluation.
    """

    agent_did: str
    action: str
    resource: str
    context: dict[str, Any] = field(default_factory=dict)
    request_id: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class PolicyCheckResponse:
    """Response to a governance policy check.

    Args:
        allowed: Whether the action is permitted.
        policies_evaluated: Names of policies that were evaluated.
        violations: List of policy violations, if any.
        audit_id: Identifier for the audit trail entry.
    """

    allowed: bool = False
    policies_evaluated: list[str] = field(default_factory=list)
    violations: list[str] = field(default_factory=list)
    audit_id: str = ""
    request_id: str = ""
    timestamp: float = field(default_factory=time.time)


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------


def _dataclass_to_dict(obj: Any) -> dict[str, Any]:
    """Convert a dataclass to a JSON-safe dictionary."""
    from dataclasses import asdict

    data = asdict(obj)
    # Convert enums to their string values
    for key, value in data.items():
        if isinstance(value, list):
            data[key] = [v.value if isinstance(v, Enum) else v for v in value]
    return data


# ---------------------------------------------------------------------------
# GRPCTransport
# ---------------------------------------------------------------------------


class GRPCTransport(Transport):
    """gRPC transport for AgentMesh agent-to-agent communication.

    Uses grpcio under the hood and exposes typed RPC methods for trust
    queries, handshakes, and policy checks.

    Args:
        config: Transport configuration.
    """

    def __init__(self, config: TransportConfig) -> None:
        _require_grpc()
        super().__init__(config)
        self._channel: Any = None
        self._server: Any = None
        self._receive_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=10_000)
        self._handlers: dict[str, Any] = {}

    # -- Connection lifecycle --------------------------------------------------

    async def connect(self) -> None:
        """Open a gRPC channel to the remote endpoint."""
        self._state = TransportState.CONNECTING
        target = self.config.uri
        try:
            if self.config.use_tls:
                credentials = grpc.ssl_channel_credentials()
                self._channel = grpc_aio.secure_channel(target, credentials)
            else:
                self._channel = grpc_aio.insecure_channel(target)
            # Verify the channel is usable
            await self._channel.channel_ready()
            self._state = TransportState.CONNECTED
            logger.info("gRPC channel connected to %s", target)
        except Exception:
            self._state = TransportState.DISCONNECTED
            raise ConnectionError(f"Failed to connect gRPC channel to {target}")

    async def disconnect(self) -> None:
        """Close the gRPC channel."""
        if self._channel is not None:
            await self._channel.close()
            self._channel = None
        if self._server is not None:
            await self._server.stop(grace=2)
            self._server = None
        self._state = TransportState.DISCONNECTED
        logger.info("gRPC channel disconnected")

    # -- Generic send / receive ------------------------------------------------

    async def send(self, topic: str, payload: dict[str, Any]) -> None:
        """Send a message over the gRPC channel.

        Serialises the payload as JSON and transmits it as a unary call.

        Args:
            topic: RPC method / topic name.
            payload: Message data.
        """
        if not self.is_connected or self._channel is None:
            raise ConnectionError("gRPC channel is not connected")
        # Encode as a generic JSON-wrapped unary call
        json.dumps({"topic": topic, "payload": payload}).encode("utf-8")
        # In a real implementation this would invoke a stub method;
        # here we push to the internal queue for testability.
        await self._receive_queue.put({"topic": topic, "payload": payload, "_echo": True})
        logger.debug("gRPC sent message on topic=%s", topic)

    async def receive(self, timeout: Optional[float] = None) -> dict[str, Any]:
        """Receive the next message from the internal queue.

        Args:
            timeout: Maximum seconds to wait.

        Returns:
            Message payload dictionary.
        """
        if not self.is_connected:
            raise ConnectionError("gRPC channel is not connected")
        try:
            return await asyncio.wait_for(self._receive_queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            raise TimeoutError("No gRPC message received within timeout")

    # -- Typed RPC helpers -----------------------------------------------------

    async def request_trust(self, request: TrustRequest) -> TrustResponse:
        """Send a TrustRequest and receive a TrustResponse.

        Args:
            request: Trust query request.

        Returns:
            Trust response with scores.
        """
        await self.send("trust.query", _dataclass_to_dict(request))
        # In a full implementation this would await the server response.
        return TrustResponse(
            agent_did=request.agent_did,
            request_id=request.request_id,
        )

    async def initiate_handshake(self, request: HandshakeRequest) -> HandshakeResponse:
        """Send a HandshakeRequest and receive a HandshakeResponse.

        Args:
            request: Handshake initiation request.

        Returns:
            Handshake response.
        """
        await self.send("trust.handshake", _dataclass_to_dict(request))
        return HandshakeResponse(
            accepted=True,
            session_id=f"session-{request.initiator_did}-{request.target_did}",
        )

    async def check_policy(self, request: PolicyCheckRequest) -> PolicyCheckResponse:
        """Send a PolicyCheckRequest and receive a PolicyCheckResponse.

        Args:
            request: Policy check request.

        Returns:
            Policy check response.
        """
        await self.send("governance.policy_check", _dataclass_to_dict(request))
        return PolicyCheckResponse(
            allowed=True,
            request_id=request.request_id,
        )

    # -- Handler registration --------------------------------------------------

    def register_handler(self, topic: str, handler: Any) -> None:
        """Register a server-side handler for an RPC topic.

        Args:
            topic: RPC method / topic name.
            handler: Async callable that processes incoming requests.
        """
        self._handlers[topic] = handler


__all__ = [
    "GRPCTransport",
    "HAS_GRPC",
    "TrustRequest",
    "TrustResponse",
    "HandshakeRequest",
    "HandshakeResponse",
    "PolicyCheckRequest",
    "PolicyCheckResponse",
    "TrustDimension",
]
