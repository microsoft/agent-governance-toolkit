# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Azure Service Bus broker adapter for AMB.

Azure Service Bus provides enterprise-grade messaging for cloud applications
with features like dead-letter queues, sessions, and transactions.
"""

import asyncio
import json
import uuid
from typing import Dict, List, Optional

from amb_core.broker import BrokerAdapter, MessageHandler
from amb_core.models import Message

try:
    from azure.servicebus.aio import ServiceBusClient, ServiceBusSender, ServiceBusReceiver
    from azure.servicebus import ServiceBusMessage
except ImportError:
    raise ImportError(
        "Azure Service Bus adapter requires 'azure-servicebus' package. "
        "Install it with: pip install amb-core[azure]"
    )


class AzureServiceBusBroker(BrokerAdapter):
    """
    Azure Service Bus broker adapter.
    
    This adapter uses Azure Service Bus topics and subscriptions for
    enterprise-grade messaging with guaranteed delivery.
    
    Example:
        ```python
        from amb_core.adapters import AzureServiceBusBroker
        
        broker = AzureServiceBusBroker(
            connection_string="Endpoint=sb://...",
            topic_name="agent-messages"
        )
        await broker.connect()
        
        # Subscribe
        async def handler(msg):
            print(f"Received: {msg.payload}")
        
        sub_id = await broker.subscribe("agent.tasks", handler)
        
        # Publish
        await broker.publish(Message(topic="agent.tasks", payload={"task": "analyze"}))
        ```
    """

    def __init__(
        self,
        connection_string: str,
        topic_name: str = "amb-messages",
        subscription_name: str = "amb-subscription"
    ):
        """
        Initialize Azure Service Bus broker.
        
        Args:
            connection_string: Azure Service Bus connection string
            topic_name: Service Bus topic name
            subscription_name: Default subscription name
        """
        self.connection_string = connection_string
        self.topic_name = topic_name
        self.subscription_name = subscription_name
        
        self._client: Optional[ServiceBusClient] = None
        self._sender: Optional[ServiceBusSender] = None
        self._receivers: Dict[str, ServiceBusReceiver] = {}
        self._subscriptions: Dict[str, str] = {}  # subscription_id -> topic
        self._handlers: Dict[str, MessageHandler] = {}
        self._tasks: set = set()
        self._running = False

    async def connect(self) -> None:
        """Connect to Azure Service Bus."""
        self._client = ServiceBusClient.from_connection_string(
            conn_str=self.connection_string
        )
        
        # Create sender for the topic
        self._sender = self._client.get_topic_sender(topic_name=self.topic_name)
        self._running = True

    async def disconnect(self) -> None:
        """Disconnect from Azure Service Bus."""
        self._running = False
        
        # Cancel all tasks
        for task in self._tasks:
            if not task.done():
                task.cancel()
        
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        
        self._tasks.clear()
        
        # Close receivers
        for receiver in self._receivers.values():
            await receiver.close()
        
        self._receivers.clear()
        
        # Close sender
        if self._sender:
            await self._sender.close()
        
        # Close client
        if self._client:
            await self._client.close()

    async def publish(self, message: Message, wait_for_confirmation: bool = False) -> Optional[str]:
        """
        Publish message to Azure Service Bus topic.
        
        Args:
            message: Message to publish
            wait_for_confirmation: Wait for broker acknowledgment
        
        Returns:
            Message ID
        """
        if not self._sender:
            raise ConnectionError("Not connected to Azure Service Bus")
        
        # Create Service Bus message
        sb_message = ServiceBusMessage(
            body=message.model_dump_json(),
            message_id=message.id,
            correlation_id=message.correlation_id,
            subject=message.topic,  # Use subject for filtering
            application_properties={
                "topic": message.topic,
                "source": message.source,
                "target": message.target or "",
                "message_type": message.message_type.value if hasattr(message.message_type, 'value') else str(message.message_type)
            }
        )
        
        # Send message
        await self._sender.send_messages(sb_message)
        
        return message.id

    async def subscribe(self, topic: str, handler: MessageHandler) -> str:
        """
        Subscribe to messages on a topic.
        
        Creates a receiver for the subscription and starts listening.
        
        Args:
            topic: Topic to filter messages by
            handler: Message handler
        
        Returns:
            Subscription ID
        """
        if not self._client:
            raise ConnectionError("Not connected to Azure Service Bus")
        
        subscription_id = str(uuid.uuid4())
        
        # Create receiver for the subscription
        receiver = self._client.get_subscription_receiver(
            topic_name=self.topic_name,
            subscription_name=self.subscription_name,
            max_wait_time=5  # seconds
        )
        
        self._receivers[subscription_id] = receiver
        self._subscriptions[subscription_id] = topic
        self._handlers[topic] = handler
        
        # Start receiver task
        task = asyncio.create_task(self._receive_task(subscription_id, topic, handler))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        
        return subscription_id

    async def _receive_task(self, subscription_id: str, topic: str, handler: MessageHandler):
        """Receive messages from Azure Service Bus."""
        receiver = self._receivers.get(subscription_id)
        if not receiver:
            return
        
        while self._running:
            try:
                # Receive messages in batches
                async with receiver:
                    messages = await receiver.receive_messages(max_message_count=10, max_wait_time=5)
                    
                    for sb_message in messages:
                        try:
                            # Parse message
                            body = str(sb_message)
                            amb_message = Message.model_validate_json(body)
                            
                            # Check if message matches topic filter
                            if amb_message.topic == topic or topic == "*":
                                await handler(amb_message)
                            
                            # Complete the message
                            await receiver.complete_message(sb_message)
                            
                        except Exception as e:
                            print(f"Error handling message: {e}")
                            # Dead-letter the message for investigation
                            await receiver.dead_letter_message(
                                sb_message,
                                reason="ProcessingError",
                                error_description=str(e)
                            )
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"Error in Service Bus receiver: {e}")
                await asyncio.sleep(1.0)

    async def unsubscribe(self, subscription_id: str) -> None:
        """
        Unsubscribe from messages.
        
        Args:
            subscription_id: Subscription ID
        """
        if subscription_id in self._receivers:
            receiver = self._receivers[subscription_id]
            await receiver.close()
            del self._receivers[subscription_id]
        
        if subscription_id in self._subscriptions:
            topic = self._subscriptions[subscription_id]
            del self._subscriptions[subscription_id]
            if topic in self._handlers:
                del self._handlers[topic]

    async def request(self, message: Message, timeout: float = 30.0) -> Message:
        """
        Send request and wait for response.
        
        Uses correlation ID and reply-to for request-response pattern.
        
        Args:
            message: Request message
            timeout: Timeout in seconds
        
        Returns:
            Response message
        """
        if not self._client or not self._sender:
            raise ConnectionError("Not connected to Azure Service Bus")
        
        # Generate correlation ID
        if not message.correlation_id:
            message.correlation_id = str(uuid.uuid4())
        
        # Create response queue
        response_queue: asyncio.Queue = asyncio.Queue()
        
        # Create temporary receiver for response
        response_subscription = f"response-{message.correlation_id[:8]}"
        
        async def response_handler(msg: Message):
            if msg.correlation_id == message.correlation_id:
                await response_queue.put(msg)
        
        # Subscribe to responses
        sub_id = await self.subscribe(response_subscription, response_handler)
        
        try:
            # Set reply-to
            message.reply_to = response_subscription
            
            # Publish request
            await self.publish(message, wait_for_confirmation=False)
            
            # Wait for response
            try:
                response = await asyncio.wait_for(response_queue.get(), timeout=timeout)
                return response
            except asyncio.TimeoutError:
                raise TimeoutError(f"No response received within {timeout} seconds")
        
        finally:
            await self.unsubscribe(sub_id)

    async def get_pending_messages(self, topic: str, limit: int = 10) -> List[Message]:
        """
        Peek at pending messages without consuming them.
        
        Args:
            topic: Topic to filter by
            limit: Maximum messages to retrieve
        
        Returns:
            List of messages
        """
        if not self._client:
            raise ConnectionError("Not connected to Azure Service Bus")
        
        messages = []
        
        # Create temporary receiver
        receiver = self._client.get_subscription_receiver(
            topic_name=self.topic_name,
            subscription_name=self.subscription_name
        )
        
        try:
            async with receiver:
                # Peek messages without completing them
                peeked = await receiver.peek_messages(max_message_count=limit)
                
                for sb_message in peeked:
                    try:
                        body = str(sb_message)
                        amb_message = Message.model_validate_json(body)
                        
                        if amb_message.topic == topic or topic == "*":
                            messages.append(amb_message)
                    except Exception:
                        continue
        
        finally:
            await receiver.close()
        
        return messages

    async def health_check(self) -> bool:
        """Check if connected to Azure Service Bus."""
        return self._client is not None and self._sender is not None
