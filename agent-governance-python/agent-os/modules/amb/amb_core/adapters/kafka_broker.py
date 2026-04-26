# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Kafka broker adapter for AMB."""

import asyncio
import json
import uuid
from typing import Dict, List, Optional

from amb_core.broker import BrokerAdapter, MessageHandler
from amb_core.models import Message

try:
    from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
    from aiokafka.errors import KafkaError
except ImportError:
    raise ImportError(
        "Kafka adapter requires 'aiokafka' package. "
        "Install it with: pip install amb-core[kafka]"
    )


class KafkaBroker(BrokerAdapter):
    """
    Kafka-based broker adapter.
    
    This adapter uses Kafka topics for message distribution with
    high throughput and durability.
    """

    def __init__(self, bootstrap_servers: str = "localhost:9092"):
        """
        Initialize Kafka broker.
        
        Args:
            bootstrap_servers: Kafka bootstrap servers
        """
        self.bootstrap_servers = bootstrap_servers
        self._producer: Optional[AIOKafkaProducer] = None
        self._consumers: Dict[str, AIOKafkaConsumer] = {}
        self._subscriptions: Dict[str, str] = {}  # subscription_id -> topic
        self._tasks: set = set()

    async def connect(self) -> None:
        """Connect to Kafka."""
        self._producer = AIOKafkaProducer(
            bootstrap_servers=self.bootstrap_servers,
            value_serializer=lambda v: json.dumps(v).encode()
        )
        await self._producer.start()

    async def disconnect(self) -> None:
        """Disconnect from Kafka."""
        # Cancel all tasks
        for task in self._tasks:
            if not task.done():
                task.cancel()

        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

        self._tasks.clear()

        # Stop consumers
        for consumer in self._consumers.values():
            await consumer.stop()

        self._consumers.clear()

        # Stop producer
        if self._producer:
            await self._producer.stop()

    async def publish(self, message: Message, wait_for_confirmation: bool = False) -> Optional[str]:
        """
        Publish message to Kafka topic.
        
        Args:
            message: Message to publish
            wait_for_confirmation: Wait for broker confirmation
        
        Returns:
            Message ID
        """
        if not self._producer:
            raise ConnectionError("Not connected to Kafka")

        # Serialize message
        message_dict = message.model_dump(mode='json')

        # Publish
        future = await self._producer.send(
            message.topic,
            value=message_dict,
            key=message.id.encode() if message.id else None
        )

        if wait_for_confirmation:
            # Wait for acknowledgment
            await future

        return message.id

    async def subscribe(self, topic: str, handler: MessageHandler) -> str:
        """
        Subscribe to a Kafka topic.
        
        Args:
            topic: Topic to subscribe to
            handler: Message handler
        
        Returns:
            Subscription ID
        """
        subscription_id = str(uuid.uuid4())

        # Create consumer
        consumer = AIOKafkaConsumer(
            topic,
            bootstrap_servers=self.bootstrap_servers,
            value_deserializer=lambda v: json.loads(v.decode()),
            group_id=f"amb-{subscription_id}",
            auto_offset_reset='latest'
        )

        await consumer.start()
        self._consumers[subscription_id] = consumer
        self._subscriptions[subscription_id] = topic

        # Start consumer task
        task = asyncio.create_task(self._consume_task(subscription_id, handler))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

        return subscription_id

    async def _consume_task(self, subscription_id: str, handler: MessageHandler):
        """Consume messages from Kafka."""
        consumer = self._consumers.get(subscription_id)
        if not consumer:
            return

        try:
            async for msg in consumer:
                try:
                    # Parse message
                    message = Message.model_validate(msg.value)

                    # Call handler
                    await handler(message)

                except Exception as e:
                    print(f"Error handling Kafka message: {e}")

        except asyncio.CancelledError:
            pass
        except Exception as e:
            print(f"Error in Kafka consumer: {e}")

    async def unsubscribe(self, subscription_id: str) -> None:
        """
        Unsubscribe from a topic.
        
        Args:
            subscription_id: Subscription ID
        """
        if subscription_id in self._consumers:
            consumer = self._consumers[subscription_id]
            await consumer.stop()
            del self._consumers[subscription_id]

        if subscription_id in self._subscriptions:
            del self._subscriptions[subscription_id]

    async def request(self, message: Message, timeout: float = 30.0) -> Message:
        """
        Send request and wait for response.
        
        This is a simplified implementation using temporary topics.
        
        Args:
            message: Request message
            timeout: Timeout in seconds
        
        Returns:
            Response message
        """
        if not self._producer:
            raise ConnectionError("Not connected to Kafka")

        # Generate correlation ID
        if not message.correlation_id:
            message.correlation_id = str(uuid.uuid4())

        # Create temporary response topic
        response_topic = f"response.{message.correlation_id}"
        message.reply_to = response_topic

        # Create response queue
        response_queue: asyncio.Queue = asyncio.Queue()

        # Subscribe to response topic
        async def response_handler(msg: Message):
            if msg.correlation_id == message.correlation_id:
                await response_queue.put(msg)

        sub_id = await self.subscribe(response_topic, response_handler)

        try:
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
            await self.unsubscribe(sub_id)

    async def get_pending_messages(self, topic: str, limit: int = 10) -> List[Message]:
        """
        Get pending messages from Kafka topic.
        
        This creates a temporary consumer to read recent messages.
        
        Args:
            topic: Topic to get messages from
            limit: Maximum messages to retrieve
        
        Returns:
            List of messages
        """
        # Create temporary consumer
        consumer = AIOKafkaConsumer(
            topic,
            bootstrap_servers=self.bootstrap_servers,
            value_deserializer=lambda v: json.loads(v.decode()),
            auto_offset_reset='earliest',
            consumer_timeout_ms=1000
        )

        try:
            await consumer.start()

            messages = []
            async for msg in consumer:
                message = Message.model_validate(msg.value)
                messages.append(message)

                if len(messages) >= limit:
                    break

            return messages

        finally:
            await consumer.stop()
