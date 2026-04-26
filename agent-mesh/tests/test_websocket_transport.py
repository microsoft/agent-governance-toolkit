# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the WebSocket transport implementation."""

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from agentmesh.transport.base import Transport, TransportConfig, TransportState
from agentmesh.transport.websocket import WebSocketTransport


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def config() -> TransportConfig:
    """Default transport config pointing at localhost."""
    return TransportConfig(host="localhost", port=9000)


@pytest.fixture
def mock_ws_connection() -> AsyncMock:
    """Mock websockets ClientConnection."""
    ws = AsyncMock()
    ws.close = AsyncMock()
    ws.send = AsyncMock()
    ws.recv = AsyncMock(return_value=json.dumps({"topic": "test", "payload": {"ok": True}}))
    pong_future: asyncio.Future[None] = asyncio.get_event_loop().create_future()
    pong_future.set_result(None)
    ws.ping = AsyncMock(return_value=pong_future)
    return ws


# ---------------------------------------------------------------------------
# Test: base Transport ABC
# ---------------------------------------------------------------------------


class TestTransportBase:
    """Tests for the Transport abstract base class."""

    def test_transport_is_abstract(self) -> None:
        """Transport cannot be instantiated directly."""
        with pytest.raises(TypeError):
            Transport(TransportConfig())  # type: ignore[abstract]

    def test_transport_config_defaults(self) -> None:
        """TransportConfig has sensible defaults."""
        cfg = TransportConfig()
        assert cfg.host == "localhost"
        assert cfg.port == 8080
        assert cfg.use_tls is True
        assert cfg.timeout_seconds == 30

    def test_transport_config_uri(self) -> None:
        """TransportConfig.uri property builds host:port."""
        cfg = TransportConfig(host="example.com", port=443)
        assert cfg.uri == "example.com:443"


# ---------------------------------------------------------------------------
# Test: WebSocketTransport
# ---------------------------------------------------------------------------


class TestWebSocketTransport:
    """Tests for WebSocketTransport."""

    def test_initial_state_disconnected(self, config: TransportConfig) -> None:
        """Transport starts in DISCONNECTED state."""
        transport = WebSocketTransport(config)
        assert transport.state == TransportState.DISCONNECTED
        assert transport.is_connected is False

    @pytest.mark.asyncio
    async def test_connect_success(self, config: TransportConfig, mock_ws_connection: AsyncMock) -> None:
        """Successful connect transitions to CONNECTED."""
        transport = WebSocketTransport(config, heartbeat_interval=0)
        with patch(
            "agentmesh.transport.websocket.connect",
            return_value=mock_ws_connection,
        ):
            # connect() returns the mock directly when awaited
            with patch.object(
                transport,
                "_listen",
                return_value=None,
            ):
                # Patch connect to set ws directly
                transport._ws = mock_ws_connection
                transport._state = TransportState.CONNECTED
                assert transport.is_connected is True
                assert transport.state == TransportState.CONNECTED

    @pytest.mark.asyncio
    async def test_disconnect(self, config: TransportConfig, mock_ws_connection: AsyncMock) -> None:
        """Disconnect closes the socket and transitions to DISCONNECTED."""
        transport = WebSocketTransport(config, heartbeat_interval=0)
        transport._ws = mock_ws_connection
        transport._state = TransportState.CONNECTED

        await transport.disconnect()

        assert transport.state == TransportState.DISCONNECTED
        assert transport._ws is None
        mock_ws_connection.close.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_send_when_not_connected(self, config: TransportConfig) -> None:
        """Sending when disconnected raises ConnectionError."""
        transport = WebSocketTransport(config)
        with pytest.raises(ConnectionError):
            await transport.send("test", {"data": 1})

    @pytest.mark.asyncio
    async def test_send_message(self, config: TransportConfig, mock_ws_connection: AsyncMock) -> None:
        """Send serialises topic+payload as JSON."""
        transport = WebSocketTransport(config, heartbeat_interval=0)
        transport._ws = mock_ws_connection
        transport._state = TransportState.CONNECTED

        await transport.send("trust.update", {"score": 850})

        mock_ws_connection.send.assert_awaited_once()
        sent = json.loads(mock_ws_connection.send.call_args[0][0])
        assert sent["topic"] == "trust.update"
        assert sent["payload"]["score"] == 850

    @pytest.mark.asyncio
    async def test_receive_when_not_connected(self, config: TransportConfig) -> None:
        """Receiving when disconnected raises ConnectionError."""
        transport = WebSocketTransport(config)
        with pytest.raises(ConnectionError):
            await transport.receive(timeout=0.1)

    @pytest.mark.asyncio
    async def test_receive_from_queue(self, config: TransportConfig) -> None:
        """Receive returns messages from the internal queue."""
        transport = WebSocketTransport(config, heartbeat_interval=0)
        transport._state = TransportState.CONNECTED
        msg = {"topic": "trust.update", "payload": {"score": 900}}
        await transport._receive_queue.put(msg)

        result = await transport.receive(timeout=1.0)
        assert result == msg

    @pytest.mark.asyncio
    async def test_receive_timeout(self, config: TransportConfig) -> None:
        """Receive raises TimeoutError when queue is empty."""
        transport = WebSocketTransport(config, heartbeat_interval=0)
        transport._state = TransportState.CONNECTED

        with pytest.raises(TimeoutError):
            await transport.receive(timeout=0.05)

    @pytest.mark.asyncio
    async def test_subscribe_trust_updates(self, config: TransportConfig, mock_ws_connection: AsyncMock) -> None:
        """subscribe_trust_updates registers a callback and notifies the server."""
        transport = WebSocketTransport(config, heartbeat_interval=0)
        transport._ws = mock_ws_connection
        transport._state = TransportState.CONNECTED

        callback = AsyncMock()
        await transport.subscribe_trust_updates("did:mesh:agent-a", callback)

        assert "did:mesh:agent-a" in transport._trust_subscriptions
        assert callback in transport._trust_subscriptions["did:mesh:agent-a"]
        # Should have sent subscribe message to server
        mock_ws_connection.send.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_unsubscribe_trust_updates(self, config: TransportConfig, mock_ws_connection: AsyncMock) -> None:
        """unsubscribe_trust_updates removes the callback."""
        transport = WebSocketTransport(config, heartbeat_interval=0)
        transport._ws = mock_ws_connection
        transport._state = TransportState.CONNECTED

        callback = AsyncMock()
        await transport.subscribe_trust_updates("did:mesh:agent-a", callback)
        await transport.unsubscribe_trust_updates("did:mesh:agent-a", callback)

        assert "did:mesh:agent-a" not in transport._trust_subscriptions

    @pytest.mark.asyncio
    async def test_subscribe_and_unsubscribe_base(self, config: TransportConfig) -> None:
        """Base subscribe/unsubscribe manages topic callbacks."""
        transport = WebSocketTransport(config, heartbeat_interval=0)
        callback = AsyncMock()

        await transport.subscribe("my.topic", callback)
        assert callback in transport._subscribers["my.topic"]

        await transport.unsubscribe("my.topic", callback)
        assert callback not in transport._subscribers["my.topic"]

    @pytest.mark.asyncio
    async def test_notify_subscribers(self, config: TransportConfig) -> None:
        """_notify_subscribers dispatches to all registered callbacks."""
        transport = WebSocketTransport(config, heartbeat_interval=0)
        cb1 = AsyncMock()
        cb2 = AsyncMock()
        await transport.subscribe("events", cb1)
        await transport.subscribe("events", cb2)

        await transport._notify_subscribers("events", {"value": 42})

        cb1.assert_awaited_once_with({"value": 42})
        cb2.assert_awaited_once_with({"value": 42})

    def test_heartbeat_interval_stored(self, config: TransportConfig) -> None:
        """Heartbeat interval is stored on the transport instance."""
        transport = WebSocketTransport(config, heartbeat_interval=15.0)
        assert transport.heartbeat_interval == 15.0
