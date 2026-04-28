# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Copyright (c) Agent-Mesh Contributors. All rights reserved.
# Licensed under the MIT License.
"""Abstract transport interface for AgentMesh communication.

Defines the contract that all transport backends (WebSocket, gRPC, etc.)
must implement to exchange trust data between agents.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Optional


class TransportState(str, Enum):
    """Transport connection state."""

    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    RECONNECTING = "reconnecting"


@dataclass
class TransportConfig:
    """Configuration for a transport backend.

    Args:
        host: Server hostname or IP address.
        port: Server port number.
        use_tls: Whether to use TLS encryption.
        timeout_seconds: Connection and operation timeout.
        max_retries: Maximum reconnection attempts.
        retry_delay_seconds: Base delay between reconnection attempts.
        metadata: Additional transport-specific configuration.
    """

    host: str = "localhost"
    port: int = 8080
    use_tls: bool = True
    timeout_seconds: int = 30
    max_retries: int = 5
    retry_delay_seconds: float = 1.0
    metadata: dict[str, str] = field(default_factory=dict)

    @property
    def uri(self) -> str:
        """Build connection URI from host and port."""
        return f"{self.host}:{self.port}"


class Transport(ABC):
    """Abstract base class for AgentMesh transport backends.

    All transport implementations (WebSocket, gRPC, etc.) must implement
    this interface to provide reliable message delivery between agents.
    """

    def __init__(self, config: TransportConfig) -> None:
        """Initialize transport with configuration."""
        self.config = config
        self._state = TransportState.DISCONNECTED
        self._subscribers: dict[str, list[Callable[..., Any]]] = {}

    @property
    def state(self) -> TransportState:
        """Current transport connection state."""
        return self._state

    @property
    def is_connected(self) -> bool:
        """Whether the transport is currently connected."""
        return self._state == TransportState.CONNECTED

    @abstractmethod
    async def connect(self) -> None:
        """Establish connection to the remote endpoint.

        Raises:
            ConnectionError: If the connection cannot be established.
        """

    @abstractmethod
    async def disconnect(self) -> None:
        """Gracefully close the connection."""

    @abstractmethod
    async def send(self, topic: str, payload: dict[str, Any]) -> None:
        """Send a message on the given topic.

        Args:
            topic: Message topic/channel.
            payload: Message data as a dictionary.

        Raises:
            ConnectionError: If not connected.
        """

    @abstractmethod
    async def receive(self, timeout: Optional[float] = None) -> dict[str, Any]:
        """Receive the next message.

        Args:
            timeout: Maximum seconds to wait. None means wait forever.

        Returns:
            Received message payload.

        Raises:
            TimeoutError: If timeout expires before a message arrives.
            ConnectionError: If not connected.
        """

    async def subscribe(self, topic: str, callback: Callable[..., Any]) -> None:
        """Subscribe to messages on a topic.

        Args:
            topic: Topic to subscribe to.
            callback: Async callable invoked with each message payload.
        """
        if topic not in self._subscribers:
            self._subscribers[topic] = []
        self._subscribers[topic].append(callback)

    async def unsubscribe(self, topic: str, callback: Callable[..., Any]) -> None:
        """Unsubscribe a callback from a topic.

        Args:
            topic: Topic to unsubscribe from.
            callback: The callback to remove.
        """
        if topic in self._subscribers:
            self._subscribers[topic] = [
                cb for cb in self._subscribers[topic] if cb is not callback
            ]

    async def _notify_subscribers(self, topic: str, payload: dict[str, Any]) -> None:
        """Dispatch a message to all subscribers for the given topic.

        Args:
            topic: Message topic.
            payload: Message data.
        """
        for callback in self._subscribers.get(topic, []):
            await callback(payload)


__all__ = [
    "Transport",
    "TransportConfig",
    "TransportState",
]
