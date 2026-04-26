# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""NATS broker adapter for AMB.

NATS is a lightweight, cloud-native messaging system ideal for
microservices, IoT, and edge computing scenarios.
"""

import asyncio
import json
import uuid
from typing import Dict, List, Optional, Callable

from amb_core.broker import BrokerAdapter, MessageHandler
from amb_core.models import Message

try:
    import nats
    from nats.aio.client import Client as NATS
    from nats.js.api import StreamConfig, ConsumerConfig
except ImportError:
    raise ImportError(
        "NATS adapter requires 'nats-py' package. "
        "Install it with: pip install amb-core[nats]"
    )


class NATSBroker(BrokerAdapter):
    """
    NATS-based broker adapter.
    
    This adapter uses NATS for lightweight, high-performance messaging.
    Supports both core NATS (fire-and-forget) and JetStream (persistent).
    
    Example:
        ```python
        from amb_core.adapters import NATSBroker
        
        broker = NATSBroker(servers=["nats://localhost:4222"])
        await broker.connect()
        
        # Subscribe
        async def handler(msg):
            print(f"Received: {msg.payload}")
        
        await broker.subscribe("agent.tasks", handler)
        
        # Publish
        await broker.publish(Message(topic="agent.tasks", payload={"task": "analyze"}))
        ```
    """

    def __init__(
        self,
        servers: List[str] = None,
        use_jetstream: bool = False,
        stream_name: str = "AMB_STREAM"
    ):
        """
        Initialize NATS broker.
        
        Args:
            servers: List of NATS server URLs (default: ["nats://localhost:4222"])
            use_jetstream: Enable JetStream for persistence (default: False)
            stream_name: JetStream stream name (default: "AMB_STREAM")
        """
        self.servers = servers or ["nats://localhost:4222"]
        self.use_jetstream = use_jetstream
        self.stream_name = stream_name
        
        self._nc: Optional[NATS] = None
        self._js = None  # JetStream context
        self._subscriptions: Dict[str, object] = {}  # subscription_id -> subscription
        self._handlers: Dict[str, MessageHandler] = {}  # topic -> handler
        self._running = False

    async def connect(self) -> None:
        """Connect to NATS server(s)."""
        self._nc = await nats.connect(servers=self.servers)
        self._running = True
        
        if self.use_jetstream:
            self._js = self._nc.jetstream()
            # Create stream if it doesn't exist
            try:
                await self._js.add_stream(
                    name=self.stream_name,
                    subjects=["amb.>"],  # All AMB subjects
                    retention="limits",
                    max_msgs=100000,
                    max_bytes=100 * 1024 * 1024  # 100MB
                )
            except Exception:
                # Stream may already exist
                pass

    async def disconnect(self) -> None:
        """Disconnect from NATS."""
        self._running = False
        
        # Unsubscribe all
        for sub_id in list(self._subscriptions.keys()):
            await self.unsubscribe(sub_id)
        
        if self._nc:
            await self._nc.drain()
            await self._nc.close()

    async def publish(self, message: Message, wait_for_confirmation: bool = False) -> Optional[str]:
        """
        Publish message to NATS subject.
        
        Args:
            message: Message to publish
            wait_for_confirmation: Wait for acknowledgment (JetStream only)
        
        Returns:
            Message ID
        """
        if not self._nc:
            raise ConnectionError("Not connected to NATS")
        
        # Convert topic to NATS subject format (replace / with .)
        subject = f"amb.{message.topic.replace('/', '.')}"
        
        # Serialize message
        message_bytes = message.model_dump_json().encode()
        
        if self.use_jetstream and self._js:
            # Publish to JetStream for persistence
            ack = await self._js.publish(subject, message_bytes)
            if wait_for_confirmation:
                return message.id
        else:
            # Core NATS publish (fire-and-forget)
            await self._nc.publish(subject, message_bytes)
        
        return message.id

    async def subscribe(self, topic: str, handler: MessageHandler) -> str:
        """
        Subscribe to a NATS subject.
        
        Args:
            topic: Topic to subscribe to
            handler: Message handler
        
        Returns:
            Subscription ID
        """
        if not self._nc:
            raise ConnectionError("Not connected to NATS")
        
        subscription_id = str(uuid.uuid4())
        
        # Convert topic to NATS subject format
        subject = f"amb.{topic.replace('/', '.')}"
        
        # Create message callback
        async def message_callback(msg):
            try:
                # Parse message
                data = msg.data.decode('utf-8')
                amb_message = Message.model_validate_json(data)
                
                # Call handler
                await handler(amb_message)
                
            except Exception as e:
                print(f"Error handling NATS message: {e}")
        
        # Subscribe
        if self.use_jetstream and self._js:
            # JetStream subscription with durable consumer
            sub = await self._js.subscribe(
                subject,
                cb=message_callback,
                durable=f"amb-{subscription_id[:8]}"
            )
        else:
            # Core NATS subscription
            sub = await self._nc.subscribe(subject, cb=message_callback)
        
        self._subscriptions[subscription_id] = sub
        self._handlers[topic] = handler
        
        return subscription_id

    async def unsubscribe(self, subscription_id: str) -> None:
        """
        Unsubscribe from a subject.
        
        Args:
            subscription_id: Subscription ID
        """
        if subscription_id in self._subscriptions:
            sub = self._subscriptions[subscription_id]
            await sub.unsubscribe()
            del self._subscriptions[subscription_id]

    async def request(self, message: Message, timeout: float = 30.0) -> Message:
        """
        Send request and wait for response using NATS request-reply.
        
        NATS has native request-reply support which makes this efficient.
        
        Args:
            message: Request message
            timeout: Timeout in seconds
        
        Returns:
            Response message
        """
        if not self._nc:
            raise ConnectionError("Not connected to NATS")
        
        # Generate correlation ID
        if not message.correlation_id:
            message.correlation_id = str(uuid.uuid4())
        
        # Convert topic to NATS subject
        subject = f"amb.{message.topic.replace('/', '.')}"
        
        # Serialize message
        message_bytes = message.model_dump_json().encode()
        
        try:
            # NATS native request-reply
            response = await self._nc.request(
                subject,
                message_bytes,
                timeout=timeout
            )
            
            # Parse response
            response_data = response.data.decode('utf-8')
            return Message.model_validate_json(response_data)
            
        except asyncio.TimeoutError:
            raise TimeoutError(f"No response received within {timeout} seconds")

    async def get_pending_messages(self, topic: str, limit: int = 10) -> List[Message]:
        """
        Get pending messages (JetStream only).
        
        Args:
            topic: Topic to get messages from
            limit: Maximum messages to retrieve
        
        Returns:
            List of messages
        """
        if not self.use_jetstream or not self._js:
            return []  # Core NATS doesn't persist messages
        
        subject = f"amb.{topic.replace('/', '.')}"
        messages = []
        
        try:
            # Create pull consumer
            psub = await self._js.pull_subscribe(
                subject,
                durable=f"pending-{uuid.uuid4().hex[:8]}"
            )
            
            # Fetch messages
            try:
                fetched = await psub.fetch(limit, timeout=1.0)
                for msg in fetched:
                    data = msg.data.decode('utf-8')
                    amb_message = Message.model_validate_json(data)
                    messages.append(amb_message)
            except asyncio.TimeoutError:
                pass  # No more messages
            
            await psub.unsubscribe()
            
        except Exception as e:
            print(f"Error fetching pending messages: {e}")
        
        return messages

    async def health_check(self) -> bool:
        """Check if connected to NATS."""
        return self._nc is not None and self._nc.is_connected
