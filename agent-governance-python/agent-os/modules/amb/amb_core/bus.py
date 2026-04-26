# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Main MessageBus implementation."""

import uuid
import traceback
from typing import Optional, Dict, Any, Union
from amb_core.broker import BrokerAdapter, MessageHandler
from amb_core.models import Message, MessagePriority, Priority
from amb_core.memory_broker import InMemoryBroker
from amb_core.schema import SchemaRegistry, SchemaValidationError
from amb_core.dlq import DeadLetterQueue, DLQEntry, DLQReason
from amb_core.persistence import MessageStore, InMemoryMessageStore, MessageStatus
from amb_core.tracing import TraceContext, get_current_trace


class MessageBus:
    """
    Main message bus interface for AI Agents.
    
    This class provides a simple API for publishing and subscribing to messages
    with support for both "fire and forget" and "wait for verification" patterns.
    
    New in v0.2.0:
        - persistence: Enable durable message storage for replay capability
        - schema_registry: Validate messages against schemas
        - dlq_enabled: Route failed messages to dead letter queue
        - Distributed tracing support via trace_id
    
    Example:
        # Basic usage (backward compatible)
        bus = MessageBus(adapter=InMemoryAdapter())
        await bus.publish("topic", Message(payload=data))
        
        # With new features
        bus = MessageBus(
            adapter=InMemoryAdapter(),
            persistence=True,              # Durable messages
            schema_registry=schemas,       # Validation
            dlq_enabled=True               # Dead letter queue
        )
        
        await bus.publish(
            "topic",
            Message(
                payload=data,
                priority=Priority.HIGH,    # Prioritization
                ttl_seconds=300,           # Expiration
                trace_id=uuid4()           # Distributed tracing
            )
        )
    """
    
    def __init__(
        self,
        adapter: Optional[BrokerAdapter] = None,
        *,
        persistence: Union[bool, MessageStore] = False,
        schema_registry: Optional[SchemaRegistry] = None,
        dlq_enabled: Union[bool, DeadLetterQueue] = False,
        auto_inject_trace: bool = True
    ):
        """
        Initialize the message bus.
        
        Args:
            adapter: Broker adapter to use. If None, uses InMemoryBroker.
            persistence: Enable message persistence. Can be True for default
                        InMemoryMessageStore, or a MessageStore instance.
            schema_registry: SchemaRegistry for message validation.
            dlq_enabled: Enable dead letter queue. Can be True for default
                        DeadLetterQueue, or a DeadLetterQueue instance.
            auto_inject_trace: Automatically inject trace context into messages.
        """
        self._adapter = adapter or InMemoryBroker()
        self._connected = False
        
        # Persistence (AMB-001)
        if persistence is True:
            self._persistence: Optional[MessageStore] = InMemoryMessageStore()
        elif persistence is False:
            self._persistence = None
        else:
            self._persistence = persistence
        
        # Schema validation (AMB-003)
        self._schema_registry = schema_registry
        
        # Dead letter queue (AMB-002)
        if dlq_enabled is True:
            self._dlq: Optional[DeadLetterQueue] = DeadLetterQueue()
        elif dlq_enabled is False:
            self._dlq = None
        else:
            self._dlq = dlq_enabled
        
        # Tracing (AMB-004)
        self._auto_inject_trace = auto_inject_trace
    
    @property
    def dlq(self) -> Optional[DeadLetterQueue]:
        """Get the dead letter queue."""
        return self._dlq
    
    @property
    def persistence(self) -> Optional[MessageStore]:
        """Get the message store."""
        return self._persistence
    
    @property
    def schema_registry(self) -> Optional[SchemaRegistry]:
        """Get the schema registry."""
        return self._schema_registry
    
    async def connect(self) -> None:
        """Connect to the broker."""
        await self._adapter.connect()
        self._connected = True
    
    async def disconnect(self) -> None:
        """Disconnect from the broker."""
        await self._adapter.disconnect()
        self._connected = False
    
    async def __aenter__(self):
        """Async context manager entry."""
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.disconnect()
    
    async def publish(
        self,
        topic: str,
        payload: Dict[str, Any],
        *,
        priority: MessagePriority = MessagePriority.NORMAL,
        sender: Optional[str] = None,
        wait_for_confirmation: bool = False,
        ttl_seconds: Optional[int] = None,
        trace_id: Optional[str] = None,
        **kwargs
    ) -> str:
        """
        Publish a message to a topic.
        
        This method supports both "fire and forget" (default) and
        "wait for verification" patterns via the wait_for_confirmation parameter.
        
        Args:
            topic: Topic to publish to
            payload: Message payload
            priority: Message priority level (use Priority.HIGH, Priority.URGENT, etc.)
            sender: Optional sender identifier
            wait_for_confirmation: If True, wait for broker confirmation
            ttl_seconds: Time-to-live in seconds (message expires after this)
            trace_id: Distributed trace ID for tracking message flow
            **kwargs: Additional message attributes
        
        Returns:
            Message ID
        
        Raises:
            ConnectionError: If not connected to the bus
            SchemaValidationError: If schema validation fails (when registry configured)
        
        Example:
            # Fire and forget (fast, no guarantee)
            await bus.publish("agent.thoughts", {"thought": "Hello"})
            
            # Wait for verification (slower, with guarantee)
            msg_id = await bus.publish(
                "agent.action",
                {"action": "execute"},
                wait_for_confirmation=True
            )
            
            # With new features
            await bus.publish(
                "fraud.alerts",
                {"transaction_id": "tx123", "risk_score": 0.95},
                priority=Priority.CRITICAL,
                ttl_seconds=300,
                trace_id=str(uuid4())
            )
        """
        if not self._connected:
            raise ConnectionError("Message bus not connected")
        
        # Schema validation (AMB-003)
        if self._schema_registry and self._schema_registry.has_schema(topic):
            payload = self._schema_registry.validate(topic, payload)
        
        # Auto-inject trace context (AMB-004)
        if self._auto_inject_trace and trace_id is None:
            current_trace = get_current_trace()
            if current_trace:
                trace_id = current_trace.trace_id
                kwargs.setdefault('span_id', current_trace.span_id)
                kwargs.setdefault('parent_span_id', current_trace.parent_span_id)
        
        message = Message(
            id=str(uuid.uuid4()),
            topic=topic,
            payload=payload,
            priority=priority,
            sender=sender,
            ttl=ttl_seconds,
            trace_id=trace_id,
            **kwargs
        )
        
        # Persist message if enabled (AMB-001)
        if self._persistence:
            await self._persistence.store(message)
        
        await self._adapter.publish(message, wait_for_confirmation=wait_for_confirmation)
        
        # Update persistence status
        if self._persistence:
            await self._persistence.update_status(message.id, MessageStatus.DELIVERED)
        
        return message.id
    
    async def subscribe(
        self,
        topic: str,
        handler: MessageHandler,
        *,
        with_dlq: bool = True
    ) -> str:
        """
        Subscribe to a topic with a message handler.
        
        Args:
            topic: Topic to subscribe to
            handler: Async function to handle messages
            with_dlq: If True and DLQ is enabled, route failed messages to DLQ
        
        Returns:
            Subscription ID
        
        Example:
            async def handle_message(msg: Message):
                print(f"Received: {msg.payload}")
            
            sub_id = await bus.subscribe("agent.thoughts", handle_message)
        """
        if not self._connected:
            raise ConnectionError("Message bus not connected")
        
        # Wrap handler with DLQ support if enabled
        if self._dlq and with_dlq:
            wrapped_handler = self._wrap_handler_with_dlq(handler, topic)
        else:
            wrapped_handler = handler
        
        return await self._adapter.subscribe(topic, wrapped_handler)
    
    def _wrap_handler_with_dlq(self, handler: MessageHandler, topic: str) -> MessageHandler:
        """Wrap a message handler with DLQ error handling."""
        async def dlq_handler(message: Message) -> None:
            # Check if message is expired (AMB-007)
            if message.is_expired:
                if self._dlq:
                    entry = DLQEntry(
                        message=message,
                        reason=DLQReason.EXPIRED,
                        error_message=f"Message expired (TTL: {message.ttl}s, age: {message.age_seconds:.1f}s)",
                        original_topic=topic
                    )
                    await self._dlq.add(entry)
                return  # Don't process expired messages
            
            try:
                await handler(message)
                # Update persistence status if enabled
                if self._persistence:
                    await self._persistence.update_status(message.id, MessageStatus.ACKNOWLEDGED)
            except Exception as e:
                # Route to DLQ on failure (AMB-002)
                if self._dlq:
                    entry = DLQEntry(
                        message=message,
                        reason=DLQReason.HANDLER_ERROR,
                        error_message=str(e),
                        original_topic=topic,
                        stack_trace=traceback.format_exc()
                    )
                    await self._dlq.add(entry)
                
                # Update persistence status
                if self._persistence:
                    await self._persistence.update_status(
                        message.id, MessageStatus.FAILED, error=str(e)
                    )
                
                # Re-raise if no DLQ to maintain original behavior
                if not self._dlq:
                    raise
        
        return dlq_handler
    
    async def unsubscribe(self, subscription_id: str) -> None:
        """
        Unsubscribe from a topic.
        
        Args:
            subscription_id: Subscription ID to unsubscribe
        """
        if not self._connected:
            raise ConnectionError("Message bus not connected")
        
        await self._adapter.unsubscribe(subscription_id)
    
    async def request(
        self,
        topic: str,
        payload: Dict[str, Any],
        *,
        timeout: float = 30.0,
        sender: Optional[str] = None,
        **kwargs
    ) -> Message:
        """
        Send a request and wait for a response.
        
        This implements the request-response pattern for cases where
        you need to wait for a reply from another agent.
        
        Args:
            topic: Topic to send request to
            payload: Request payload
            timeout: Maximum time to wait for response
            sender: Optional sender identifier
            **kwargs: Additional message attributes
        
        Returns:
            Response message
        
        Raises:
            TimeoutError: If no response within timeout
        
        Example:
            response = await bus.request(
                "agent.query",
                {"query": "What is the status?"},
                timeout=10.0
            )
            print(response.payload)
        """
        if not self._connected:
            raise ConnectionError("Message bus not connected")
        
        # Auto-inject trace context
        trace_id = kwargs.pop('trace_id', None)
        if self._auto_inject_trace and trace_id is None:
            current_trace = get_current_trace()
            if current_trace:
                trace_id = current_trace.trace_id
        
        message = Message(
            id=str(uuid.uuid4()),
            topic=topic,
            payload=payload,
            sender=sender,
            correlation_id=str(uuid.uuid4()),
            trace_id=trace_id,
            **kwargs
        )
        
        return await self._adapter.request(message, timeout=timeout)
    
    async def reply(self, original_message: Message, payload: Dict[str, Any]) -> str:
        """
        Reply to a request message.
        
        Args:
            original_message: The original request message
            payload: Reply payload
        
        Returns:
            Reply message ID
        
        Example:
            async def handle_request(msg: Message):
                result = process_request(msg.payload)
                await bus.reply(msg, {"result": result})
        """
        if not self._connected:
            raise ConnectionError("Message bus not connected")
        
        if not original_message.correlation_id:
            raise ValueError("Original message has no correlation_id")
        
        reply_topic = original_message.reply_to or original_message.topic
        
        reply_message = Message(
            id=str(uuid.uuid4()),
            topic=reply_topic,
            payload=payload,
            correlation_id=original_message.correlation_id,
            sender=None,
            trace_id=original_message.trace_id,  # Propagate trace_id
        )
        
        await self._adapter.publish(reply_message, wait_for_confirmation=False)
        return reply_message.id
    
    async def replay(
        self,
        topic: str,
        handler: MessageHandler,
        *,
        from_timestamp: Optional["datetime"] = None,
        to_timestamp: Optional["datetime"] = None
    ) -> int:
        """
        Replay persisted messages from a topic (AMB-001).
        
        Args:
            topic: Topic to replay messages from
            handler: Handler to process replayed messages
            from_timestamp: Start timestamp (inclusive)
            to_timestamp: End timestamp (inclusive)
            
        Returns:
            Number of messages replayed
            
        Raises:
            ValueError: If persistence is not enabled
            
        Example:
            # Replay all messages from the last hour
            from datetime import datetime, timedelta, timezone
            
            one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
            count = await bus.replay(
                "fraud.alerts",
                handle_alert,
                from_timestamp=one_hour_ago
            )
            print(f"Replayed {count} messages")
        """
        if not self._persistence:
            raise ValueError("Message persistence is not enabled")
        
        count = 0
        async for message in self._persistence.replay(topic, from_timestamp, to_timestamp):
            await handler(message)
            count += 1
        
        return count
    
    async def get_dlq_stats(self) -> Optional[Dict[str, Any]]:
        """
        Get DLQ statistics.
        
        Returns:
            DLQ stats dict or None if DLQ not enabled
        """
        if self._dlq is None:
            return None
        return await self._dlq.get_stats()
    
    async def get_persistence_stats(self) -> Optional[Dict[str, Any]]:
        """
        Get persistence statistics.
        
        Returns:
            Persistence stats dict or None if persistence not enabled
        """
        if not self._persistence:
            return None
        return await self._persistence.get_stats()


# Import datetime for type hints
from datetime import datetime
