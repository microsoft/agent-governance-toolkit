# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the gRPC transport implementation."""

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

grpc = pytest.importorskip("grpc", reason="grpcio is not installed")

from agentmesh.transport.base import TransportConfig, TransportState
from agentmesh.transport.grpc_transport import (
    GRPCTransport,
    HandshakeRequest,
    HandshakeResponse,
    PolicyCheckRequest,
    PolicyCheckResponse,
    TrustDimension,
    TrustRequest,
    TrustResponse,
    _dataclass_to_dict,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def config() -> TransportConfig:
    """Default transport config for gRPC."""
    return TransportConfig(host="localhost", port=50051)


@pytest.fixture
def connected_transport(config: TransportConfig) -> GRPCTransport:
    """A GRPCTransport pre-set to CONNECTED state with a mock channel."""
    transport = GRPCTransport(config)
    transport._channel = MagicMock()
    transport._state = TransportState.CONNECTED
    return transport


# ---------------------------------------------------------------------------
# Test: message dataclasses
# ---------------------------------------------------------------------------


class TestMessageSchemas:
    """Tests for protobuf-style message dataclasses."""

    def test_trust_request_defaults(self) -> None:
        """TrustRequest has correct defaults."""
        req = TrustRequest(agent_did="did:mesh:a", requester_did="did:mesh:b")
        assert req.agent_did == "did:mesh:a"
        assert req.requester_did == "did:mesh:b"
        assert req.dimensions == []
        assert req.request_id == ""
        assert req.timestamp > 0

    def test_trust_response_defaults(self) -> None:
        """TrustResponse has correct defaults."""
        resp = TrustResponse(agent_did="did:mesh:a")
        assert resp.agent_did == "did:mesh:a"
        assert resp.scores == {}
        assert resp.overall_score == 0.0
        assert resp.verified is False

    def test_handshake_request_defaults(self) -> None:
        """HandshakeRequest has correct defaults."""
        req = HandshakeRequest(initiator_did="did:mesh:a", target_did="did:mesh:b")
        assert req.protocol_version == "1.0"
        assert req.capabilities == []

    def test_handshake_response_defaults(self) -> None:
        """HandshakeResponse has correct defaults."""
        resp = HandshakeResponse()
        assert resp.accepted is False
        assert resp.session_id == ""

    def test_policy_check_request_defaults(self) -> None:
        """PolicyCheckRequest has correct defaults."""
        req = PolicyCheckRequest(
            agent_did="did:mesh:a", action="read", resource="/data"
        )
        assert req.action == "read"
        assert req.resource == "/data"
        assert req.context == {}

    def test_policy_check_response_defaults(self) -> None:
        """PolicyCheckResponse has correct defaults."""
        resp = PolicyCheckResponse()
        assert resp.allowed is False
        assert resp.violations == []

    def test_trust_dimension_enum(self) -> None:
        """TrustDimension enum covers all five dimensions."""
        dims = {d.value for d in TrustDimension}
        assert dims == {
            "competence",
            "integrity",
            "availability",
            "predictability",
            "transparency",
        }

    def test_trust_request_with_dimensions(self) -> None:
        """TrustRequest can specify dimensions."""
        req = TrustRequest(
            agent_did="did:mesh:a",
            requester_did="did:mesh:b",
            dimensions=[TrustDimension.COMPETENCE, TrustDimension.INTEGRITY],
        )
        assert len(req.dimensions) == 2

    def test_dataclass_to_dict(self) -> None:
        """_dataclass_to_dict serialises dataclass with enums."""
        req = TrustRequest(
            agent_did="did:mesh:a",
            requester_did="did:mesh:b",
            dimensions=[TrustDimension.COMPETENCE],
            request_id="r1",
        )
        data = _dataclass_to_dict(req)
        assert data["agent_did"] == "did:mesh:a"
        assert data["dimensions"] == ["competence"]
        assert isinstance(data["timestamp"], float)


# ---------------------------------------------------------------------------
# Test: GRPCTransport
# ---------------------------------------------------------------------------


class TestGRPCTransport:
    """Tests for GRPCTransport."""

    def test_initial_state(self, config: TransportConfig) -> None:
        """Transport starts disconnected."""
        transport = GRPCTransport(config)
        assert transport.state == TransportState.DISCONNECTED
        assert transport.is_connected is False

    @pytest.mark.asyncio
    async def test_send_when_not_connected(self, config: TransportConfig) -> None:
        """Sending when disconnected raises ConnectionError."""
        transport = GRPCTransport(config)
        with pytest.raises(ConnectionError):
            await transport.send("test", {"data": 1})

    @pytest.mark.asyncio
    async def test_receive_when_not_connected(self, config: TransportConfig) -> None:
        """Receiving when disconnected raises ConnectionError."""
        transport = GRPCTransport(config)
        with pytest.raises(ConnectionError):
            await transport.receive(timeout=0.1)

    @pytest.mark.asyncio
    async def test_send_and_receive(self, connected_transport: GRPCTransport) -> None:
        """Send places message in queue, receive retrieves it."""
        await connected_transport.send("trust.query", {"agent_did": "did:mesh:a"})
        msg = await connected_transport.receive(timeout=1.0)
        assert msg["topic"] == "trust.query"
        assert msg["payload"]["agent_did"] == "did:mesh:a"

    @pytest.mark.asyncio
    async def test_receive_timeout(self, connected_transport: GRPCTransport) -> None:
        """Receive raises TimeoutError on empty queue."""
        with pytest.raises(TimeoutError):
            await connected_transport.receive(timeout=0.05)

    @pytest.mark.asyncio
    async def test_disconnect(self, connected_transport: GRPCTransport) -> None:
        """Disconnect closes the channel."""
        connected_transport._channel = AsyncMock()
        await connected_transport.disconnect()
        assert connected_transport.state == TransportState.DISCONNECTED
        assert connected_transport._channel is None

    @pytest.mark.asyncio
    async def test_request_trust(self, connected_transport: GRPCTransport) -> None:
        """request_trust returns a TrustResponse."""
        req = TrustRequest(
            agent_did="did:mesh:a",
            requester_did="did:mesh:b",
            request_id="r1",
        )
        resp = await connected_transport.request_trust(req)
        assert isinstance(resp, TrustResponse)
        assert resp.agent_did == "did:mesh:a"
        assert resp.request_id == "r1"

    @pytest.mark.asyncio
    async def test_initiate_handshake(self, connected_transport: GRPCTransport) -> None:
        """initiate_handshake returns an accepted HandshakeResponse."""
        req = HandshakeRequest(
            initiator_did="did:mesh:a",
            target_did="did:mesh:b",
        )
        resp = await connected_transport.initiate_handshake(req)
        assert isinstance(resp, HandshakeResponse)
        assert resp.accepted is True
        assert "did:mesh:a" in resp.session_id

    @pytest.mark.asyncio
    async def test_check_policy(self, connected_transport: GRPCTransport) -> None:
        """check_policy returns a PolicyCheckResponse."""
        req = PolicyCheckRequest(
            agent_did="did:mesh:a",
            action="execute",
            resource="/pipeline",
            request_id="p1",
        )
        resp = await connected_transport.check_policy(req)
        assert isinstance(resp, PolicyCheckResponse)
        assert resp.allowed is True
        assert resp.request_id == "p1"

    def test_register_handler(self, connected_transport: GRPCTransport) -> None:
        """register_handler stores the handler for a topic."""
        handler = AsyncMock()
        connected_transport.register_handler("trust.query", handler)
        assert connected_transport._handlers["trust.query"] is handler

    @pytest.mark.asyncio
    async def test_subscribe_base(self, connected_transport: GRPCTransport) -> None:
        """Base subscribe/unsubscribe works on GRPCTransport."""
        cb = AsyncMock()
        await connected_transport.subscribe("events", cb)
        assert cb in connected_transport._subscribers["events"]

        await connected_transport.unsubscribe("events", cb)
        assert cb not in connected_transport._subscribers["events"]
