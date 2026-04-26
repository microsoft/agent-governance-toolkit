# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Redis broker adapter for AMB."""

import asyncio
import time
import uuid
from typing import Dict, List, Optional

from amb_core.broker import BrokerAdapter, MessageHandler
from amb_core.models import Message

try:
    import redis.asyncio as aioredis
except ImportError:
    raise ImportError(
        "Redis adapter requires 'redis' package. "
        "Install it with: pip install amb-core[redis]"
    )


class RedisBroker(BrokerAdapter):
    """
    Redis-based broker adapter using pub/sub.
    
    This adapter uses Redis pub/sub for message distribution and
    Redis streams for request-response patterns.
    """

    def __init__(self, url: str = "redis://localhost:6379/0"):
        """
        Initialize Redis broker.
        
        Args:
            url: Redis connection URL
        """
        self.url = url
        self._client: Optional[aioredis.Redis] = None
        self._pubsub: Optional[aioredis.client.PubSub] = None
        self._subscriptions: Dict[str, str] = {}  # subscription_id -> topic
        self._handlers: Dict[str, MessageHandler] = {}  # topic -> handler
        self._tasks: set = set()
        self._running = False

    async def connect(self) -> None:
        """Connect to Redis."""
        self._client = await aioredis.from_url(self.url)
        self._pubsub = self._client.pubsub()
        self._running = True

    async def disconnect(self) -> None:
        """Disconnect from Redis."""
        self._running = False

        # Cancel all tasks
        for task in self._tasks:
            if not task.done():
                task.cancel()

        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

        self._tasks.clear()

        if self._pubsub:
            await self._pubsub.close()

        if self._client:
            await self._client.close()

    async def publish(self, message: Message, wait_for_confirmation: bool = False) -> Optional[str]:
        """
        Publish message to Redis pub/sub.
        
        Args:
            message: Message to publish
            wait_for_confirmation: Wait for Redis confirmation
        
        Returns:
            Message ID
        """
        if not self._client:
            raise ConnectionError("Not connected to Redis")

        # Serialize message
        message_json = message.model_dump_json()

        # Publish to channel
        result = await self._client.publish(message.topic, message_json)

        # Store in stream for pending messages
        await self._client.xadd(
            f"stream:{message.topic}",
            {"data": message_json},
            maxlen=1000  # Keep last 1000 messages
        )

        if wait_for_confirmation:
            # For Redis pub/sub, confirmation is implicit
            # result contains number of subscribers that received the message
            return message.id

        return message.id

    async def subscribe(self, topic: str, handler: MessageHandler) -> str:
        """
        Subscribe to a Redis channel.
        
        Args:
            topic: Topic/channel to subscribe to
            handler: Message handler
        
        Returns:
            Subscription ID
        """
        if not self._pubsub:
            raise ConnectionError("Not connected to Redis")

        subscription_id = str(uuid.uuid4())
        self._subscriptions[subscription_id] = topic
        self._handlers[topic] = handler

        # Subscribe to channel
        await self._pubsub.subscribe(topic)

        # Start listener task if not already running
        task = asyncio.create_task(self._listen_task(topic))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

        return subscription_id

    async def _listen_task(self, topic: str):
        """Listen for messages on a topic."""
        while self._running:
            try:
                message = await self._pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)
                if message and message['type'] == 'message':
                    # Parse message
                    data = message['data']
                    if isinstance(data, bytes):
                        data = data.decode('utf-8')

                    msg = Message.model_validate_json(data)

                    # Call handler
                    if topic in self._handlers:
                        await self._handlers[topic](msg)

            except asyncio.CancelledError:
                break
            except Exception as e:
                # Log error but continue
                print(f"Error in Redis listener: {e}")
                await asyncio.sleep(1.0)

    async def unsubscribe(self, subscription_id: str) -> None:
        """
        Unsubscribe from a channel.
        
        Args:
            subscription_id: Subscription ID
        """
        if subscription_id not in self._subscriptions:
            return

        topic = self._subscriptions[subscription_id]

        if self._pubsub:
            await self._pubsub.unsubscribe(topic)

        # Clean up
        del self._subscriptions[subscription_id]
        if topic in self._handlers:
            del self._handlers[topic]

    async def request(self, message: Message, timeout: float = 30.0) -> Message:
        """
        Send request and wait for response using Redis streams.
        
        Args:
            message: Request message
            timeout: Timeout in seconds
        
        Returns:
            Response message
        """
        if not self._client:
            raise ConnectionError("Not connected to Redis")

        # Generate correlation ID
        if not message.correlation_id:
            message.correlation_id = str(uuid.uuid4())

        # Create response stream
        response_key = f"response:{message.correlation_id}"

        # Publish request
        await self.publish(message, wait_for_confirmation=False)

        # Wait for response
        try:
            start_time = time.monotonic()
            while True:
                # Check for timeout
                elapsed = time.monotonic() - start_time
                if elapsed > timeout:
                    raise TimeoutError(f"No response received within {timeout} seconds")

                # Calculate remaining time for blocking
                remaining_time = timeout - elapsed
                block_ms = max(int(remaining_time * 1000), 100)  # At least 100ms

                # Read from response stream
                messages = await self._client.xread(
                    {response_key: '0'},
                    count=1,
                    block=block_ms
                )

                if messages:
                    # Parse response
                    stream_name, message_list = messages[0]
                    message_id, data = message_list[0]
                    response_json = data[b'data'].decode('utf-8')

                    # Clean up
                    await self._client.delete(response_key)

                    return Message.model_validate_json(response_json)

                await asyncio.sleep(0.1)

        except asyncio.TimeoutError:
            raise TimeoutError(f"No response received within {timeout} seconds")

    async def get_pending_messages(self, topic: str, limit: int = 10) -> List[Message]:
        """
        Get pending messages from Redis stream.
        
        Args:
            topic: Topic to get messages from
            limit: Maximum messages to retrieve
        
        Returns:
            List of messages
        """
        if not self._client:
            raise ConnectionError("Not connected to Redis")

        stream_key = f"stream:{topic}"

        # Read from stream
        messages = await self._client.xrevrange(stream_key, count=limit)

        result = []
        for message_id, data in messages:
            message_json = data[b'data'].decode('utf-8')
            msg = Message.model_validate_json(message_json)
            result.append(msg)

        return result
