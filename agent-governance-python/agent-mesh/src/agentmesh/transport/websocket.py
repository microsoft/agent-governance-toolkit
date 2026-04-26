# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Copyright (c) Agent-Mesh Contributors. All rights reserved.
# Licensed under the MIT License.
"""WebSocket transport for real-time AgentMesh communication.

Provides bidirectional streaming for trust score updates,
heartbeat/keepalive, and automatic reconnection.

Requires the ``websockets`` library::

    pip install websockets
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any, Optional

from .base import Transport, TransportConfig, TransportState

logger = logging.getLogger(__name__)

try:
    import websockets
    from websockets.asyncio.client import ClientConnection, connect

    HAS_WEBSOCKETS = True
except ImportError:  # pragma: no cover
    HAS_WEBSOCKETS = False
    websockets = None  # type: ignore[assignment]


def _require_websockets() -> None:
    """Raise if the websockets library is not installed."""
    if not HAS_WEBSOCKETS:
        raise ImportError(
            "The 'websockets' package is required for WebSocket transport. "
            "Install it with: pip install websockets"
        )


class WebSocketTransport(Transport):
    """WebSocket transport with heartbeat and auto-reconnect.

    Supports real-time push notifications for trust score updates
    and bidirectional agent-to-agent messaging.

    Args:
        config: Transport configuration (host, port, TLS, etc.).
        heartbeat_interval: Seconds between heartbeat pings. 0 to disable.
    """

    def __init__(
        self,
        config: TransportConfig,
        heartbeat_interval: float = 30.0,
    ) -> None:
        _require_websockets()
        super().__init__(config)
        self.heartbeat_interval = heartbeat_interval
        self._ws: Optional[ClientConnection] = None
        self._receive_queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=10_000)
        self._heartbeat_task: Optional[asyncio.Task[None]] = None
        self._listener_task: Optional[asyncio.Task[None]] = None
        self._reconnect_task: Optional[asyncio.Task[None]] = None
        self._should_reconnect = True
        self._last_pong: float = 0.0
        # Trust-specific subscriptions: agent_did -> [callbacks]
        self._trust_subscriptions: dict[str, list[Any]] = {}

    # -- Connection lifecycle --------------------------------------------------

    async def connect(self) -> None:
        """Open a WebSocket connection to the server."""
        self._state = TransportState.CONNECTING
        scheme = "wss" if self.config.use_tls else "ws"
        uri = f"{scheme}://{self.config.uri}"
        try:
            self._ws = await connect(uri, open_timeout=self.config.timeout_seconds)
            self._state = TransportState.CONNECTED
            self._should_reconnect = True
            self._last_pong = time.monotonic()
            self._listener_task = asyncio.create_task(self._listen())
            if self.heartbeat_interval > 0:
                self._heartbeat_task = asyncio.create_task(self._heartbeat_loop())
            logger.info("WebSocket connected to %s", uri)
        except Exception:
            self._state = TransportState.DISCONNECTED
            raise ConnectionError(f"Failed to connect to {uri}")

    async def disconnect(self) -> None:
        """Gracefully close the WebSocket connection."""
        self._should_reconnect = False
        if self._heartbeat_task and not self._heartbeat_task.done():
            self._heartbeat_task.cancel()
        if self._listener_task and not self._listener_task.done():
            self._listener_task.cancel()
        if self._reconnect_task and not self._reconnect_task.done():
            self._reconnect_task.cancel()
        if self._ws:
            await self._ws.close()
            self._ws = None
        self._state = TransportState.DISCONNECTED
        logger.info("WebSocket disconnected")

    # -- Send / Receive --------------------------------------------------------

    async def send(self, topic: str, payload: dict[str, Any]) -> None:
        """Send a JSON message over the WebSocket.

        Args:
            topic: Message topic.
            payload: Message data.
        """
        if not self.is_connected or self._ws is None:
            raise ConnectionError("WebSocket is not connected")
        message = json.dumps({"topic": topic, "payload": payload})
        await self._ws.send(message)

    async def receive(self, timeout: Optional[float] = None) -> dict[str, Any]:
        """Receive the next message from the queue.

        Args:
            timeout: Maximum seconds to wait.

        Returns:
            Parsed message payload.
        """
        if not self.is_connected:
            raise ConnectionError("WebSocket is not connected")
        try:
            return await asyncio.wait_for(self._receive_queue.get(), timeout=timeout)
        except asyncio.TimeoutError:
            raise TimeoutError("No message received within timeout")

    # -- Trust-specific subscriptions ------------------------------------------

    async def subscribe_trust_updates(
        self, agent_did: str, callback: Any
    ) -> None:
        """Subscribe to real-time trust score updates for an agent.

        Args:
            agent_did: The DID of the agent to monitor.
            callback: Async callable invoked with trust update payloads.
        """
        if agent_did not in self._trust_subscriptions:
            self._trust_subscriptions[agent_did] = []
        self._trust_subscriptions[agent_did].append(callback)
        # Notify server of the subscription
        if self.is_connected:
            await self.send("trust.subscribe", {"agent_did": agent_did})

    async def unsubscribe_trust_updates(
        self, agent_did: str, callback: Any
    ) -> None:
        """Unsubscribe from trust score updates for an agent.

        Args:
            agent_did: The DID of the agent.
            callback: The callback to remove.
        """
        if agent_did in self._trust_subscriptions:
            self._trust_subscriptions[agent_did] = [
                cb for cb in self._trust_subscriptions[agent_did] if cb is not callback
            ]
            if not self._trust_subscriptions[agent_did]:
                del self._trust_subscriptions[agent_did]
                if self.is_connected:
                    await self.send("trust.unsubscribe", {"agent_did": agent_did})

    # -- Internal: listener / heartbeat / reconnect ----------------------------

    async def _listen(self) -> None:
        """Background task that reads messages from the WebSocket."""
        try:
            assert self._ws is not None  # noqa: S101
            async for raw in self._ws:
                try:
                    msg = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    logger.warning("Received non-JSON message, ignoring")
                    continue

                topic = msg.get("topic", "")
                payload = msg.get("payload", msg)

                # Dispatch to topic subscribers
                await self._notify_subscribers(topic, payload)

                # Dispatch trust-specific updates
                if topic == "trust.update":
                    agent_did = payload.get("agent_did", "")
                    for cb in self._trust_subscriptions.get(agent_did, []):
                        await cb(payload)

                # Enqueue for receive()
                await self._receive_queue.put(msg)
        except asyncio.CancelledError:
            return
        except Exception:
            logger.warning("WebSocket listener disconnected")
            if self._should_reconnect:
                self._state = TransportState.RECONNECTING
                self._reconnect_task = asyncio.create_task(self._auto_reconnect())

    async def _heartbeat_loop(self) -> None:
        """Periodically send ping frames to keep the connection alive."""
        try:
            while self.is_connected and self._ws is not None:
                await asyncio.sleep(self.heartbeat_interval)
                if self._ws is not None and self.is_connected:
                    pong = await self._ws.ping()
                    await asyncio.wait_for(pong, timeout=self.config.timeout_seconds)
                    self._last_pong = time.monotonic()
        except asyncio.CancelledError:
            return
        except Exception:
            logger.warning("Heartbeat failed, triggering reconnect")
            if self._should_reconnect:
                self._state = TransportState.RECONNECTING
                self._reconnect_task = asyncio.create_task(self._auto_reconnect())

    async def _auto_reconnect(self) -> None:
        """Attempt to reconnect with exponential back-off."""
        for attempt in range(1, self.config.max_retries + 1):
            delay = self.config.retry_delay_seconds * (2 ** (attempt - 1))
            logger.info("Reconnect attempt %d/%d in %.1fs", attempt, self.config.max_retries, delay)
            await asyncio.sleep(delay)
            try:
                await self.connect()
                # Re-subscribe trust topics after reconnect
                for agent_did in list(self._trust_subscriptions.keys()):
                    await self.send("trust.subscribe", {"agent_did": agent_did})
                logger.info("Reconnected on attempt %d", attempt)
                return
            except ConnectionError:
                continue
        self._state = TransportState.DISCONNECTED
        logger.error("Failed to reconnect after %d attempts", self.config.max_retries)


__all__ = [
    "WebSocketTransport",
    "HAS_WEBSOCKETS",
]
