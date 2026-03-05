# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""RabbitMQ broker adapter for AMB."""

import asyncio
import uuid
from typing import Dict, List, Optional

from amb_core.broker import BrokerAdapter, MessageHandler
from amb_core.models import Message

try:
    from aio_pika import ExchangeType, connect_robust
    from aio_pika import Message as PikaMessage
    from aio_pika.abc import AbstractChannel, AbstractConnection, AbstractQueue
except ImportError:
    raise ImportError(
        "RabbitMQ adapter requires 'aio-pika' package. "
        "Install it with: pip install amb-core[rabbitmq]"
    )


class RabbitMQBroker(BrokerAdapter):
    """
    RabbitMQ-based broker adapter.
    
    This adapter uses RabbitMQ's topic exchanges for flexible routing
    and direct exchanges for request-response patterns.
    """

    def __init__(self, url: str = "amqp://guest:guest@localhost/"):
        """
        Initialize RabbitMQ broker.
        
        Args:
            url: RabbitMQ connection URL
        """
        self.url = url
        self._connection: Optional[AbstractConnection] = None
        self._channel: Optional[AbstractChannel] = None
        self._subscriptions: Dict[str, AbstractQueue] = {}
        self._response_queues: Dict[str, asyncio.Queue] = {}
        self._tasks: set = set()

    async def connect(self) -> None:
        """Connect to RabbitMQ."""
        self._connection = await connect_robust(self.url)
        self._channel = await self._connection.channel()

        # Declare topic exchange for pub/sub
        await self._channel.declare_exchange(
            "amb.topic",
            ExchangeType.TOPIC,
            durable=True
        )

    async def disconnect(self) -> None:
        """Disconnect from RabbitMQ."""
        # Cancel all tasks
        for task in self._tasks:
            if not task.done():
                task.cancel()

        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

        self._tasks.clear()

        if self._channel:
            await self._channel.close()

        if self._connection:
            await self._connection.close()

    async def publish(self, message: Message, wait_for_confirmation: bool = False) -> Optional[str]:
        """
        Publish message to RabbitMQ exchange.
        
        Args:
            message: Message to publish
            wait_for_confirmation: Wait for broker confirmation
        
        Returns:
            Message ID
        """
        if not self._channel:
            raise ConnectionError("Not connected to RabbitMQ")

        exchange = await self._channel.get_exchange("amb.topic")

        # Serialize message
        message_json = message.model_dump_json()

        # Create AMQP message
        amqp_message = PikaMessage(
            body=message_json.encode(),
            content_type="application/json",
            message_id=message.id,
            correlation_id=message.correlation_id,
        )

        # Publish
        await exchange.publish(
            amqp_message,
            routing_key=message.topic,
            mandatory=wait_for_confirmation
        )

        return message.id

    async def subscribe(self, topic: str, handler: MessageHandler) -> str:
        """
        Subscribe to a RabbitMQ topic.
        
        Args:
            topic: Topic pattern to subscribe to (supports wildcards: * and #)
            handler: Message handler
        
        Returns:
            Subscription ID
        """
        if not self._channel:
            raise ConnectionError("Not connected to RabbitMQ")

        subscription_id = str(uuid.uuid4())

        # Declare queue
        queue = await self._channel.declare_queue(
            f"amb.queue.{subscription_id}",
            auto_delete=True
        )

        # Bind to exchange
        exchange = await self._channel.get_exchange("amb.topic")
        await queue.bind(exchange, routing_key=topic)

        # Start consuming
        async def on_message(message):
            async with message.process():
                # Parse message
                msg = Message.model_validate_json(message.body.decode())

                # Call handler
                await handler(msg)

        await queue.consume(on_message)

        self._subscriptions[subscription_id] = queue

        return subscription_id

    async def unsubscribe(self, subscription_id: str) -> None:
        """
        Unsubscribe from a topic.
        
        Args:
            subscription_id: Subscription ID
        """
        if subscription_id in self._subscriptions:
            queue = self._subscriptions[subscription_id]
            await queue.delete()
            del self._subscriptions[subscription_id]

    async def request(self, message: Message, timeout: float = 30.0) -> Message:
        """
        Send request and wait for response using RabbitMQ RPC pattern.
        
        Args:
            message: Request message
            timeout: Timeout in seconds
        
        Returns:
            Response message
        """
        if not self._channel:
            raise ConnectionError("Not connected to RabbitMQ")

        # Generate correlation ID
        if not message.correlation_id:
            message.correlation_id = str(uuid.uuid4())

        # Declare callback queue
        callback_queue = await self._channel.declare_queue(
            exclusive=True,
            auto_delete=True
        )

        # Set up response queue
        response_queue: asyncio.Queue = asyncio.Queue()
        self._response_queues[message.correlation_id] = response_queue

        # Start consuming responses
        async def on_response(response_msg):
            async with response_msg.process():
                if response_msg.correlation_id in self._response_queues:
                    msg = Message.model_validate_json(response_msg.body.decode())
                    await self._response_queues[response_msg.correlation_id].put(msg)

        await callback_queue.consume(on_response)

        try:
            # Set reply_to
            message.reply_to = callback_queue.name

            # Publish request
            await self.publish(message, wait_for_confirmation=False)

            # Wait for response
            try:
                response = await asyncio.wait_for(response_queue.get(), timeout=timeout)
                return response
            except asyncio.TimeoutError:
                raise TimeoutError(f"No response received within {timeout} seconds")

        finally:
            # Clean up
            if message.correlation_id in self._response_queues:
                del self._response_queues[message.correlation_id]

            await callback_queue.delete()

    async def get_pending_messages(self, topic: str, limit: int = 10) -> List[Message]:
        """
        Get pending messages (limited support in RabbitMQ).
        
        Args:
            topic: Topic to get messages from
            limit: Maximum messages to retrieve
        
        Returns:
            Empty list (RabbitMQ doesn't support this easily)
        """
        # RabbitMQ doesn't support getting pending messages easily
        # Would need to implement message persistence differently
        return []
