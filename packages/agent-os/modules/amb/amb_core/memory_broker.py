# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""In-memory broker adapter for testing and simple use cases."""

import asyncio
import heapq
import uuid
from collections import defaultdict
from typing import Dict, List, Optional, Set, Tuple

from amb_core.broker import BrokerAdapter, MessageHandler
from amb_core.models import Message, MessagePriority

# Priority mapping for heapq (lower number = higher priority)
PRIORITY_ORDER = {
    MessagePriority.CRITICAL: 0,
    MessagePriority.URGENT: 1,
    MessagePriority.HIGH: 2,
    MessagePriority.NORMAL: 3,
    MessagePriority.LOW: 4,
    MessagePriority.BACKGROUND: 5,
}


class InMemoryBroker(BrokerAdapter):
    """
    In-memory broker implementation for testing and simple use cases.
    
    This broker stores messages in memory and uses anyio for async handling.
    It's suitable for testing, development, and single-process applications.
    
    Features:
    - Backpressure: Automatically slows down producers when consumers are overwhelmed
    - Priority lanes: CRITICAL messages jump ahead of BACKGROUND messages
    """

    def __init__(
        self,
        max_queue_size: int = 1000,
        backpressure_threshold: float = 0.8,
        backpressure_delay: float = 0.01,
        use_priority_delivery: bool = True
    ):
        """
        Initialize the in-memory broker.
        
        Args:
            max_queue_size: Maximum messages per topic before backpressure kicks in
            backpressure_threshold: Queue fill percentage (0.0-1.0) that triggers backpressure
            backpressure_delay: Delay in seconds when backpressure is active
            use_priority_delivery: If True, deliver messages in priority order (slower but respects priority lanes)
        """
        self._connected = False
        self._subscriptions: Dict[str, Dict[str, MessageHandler]] = defaultdict(dict)

        # Priority queue: List of tuples (priority_value, counter, message)
        self._message_queues: Dict[str, List[Tuple[int, int, Message]]] = defaultdict(list)
        self._message_counter = 0  # For stable sorting within same priority

        self._response_queues: Dict[str, asyncio.Queue] = {}
        self._request_message_ids: Set[str] = set()  # Track request message IDs to avoid self-capture
        self._tasks: Set[asyncio.Task] = set()

        # Backpressure configuration
        self._max_queue_size = max_queue_size
        self._backpressure_threshold = backpressure_threshold
        self._backpressure_delay = backpressure_delay
        self._use_priority_delivery = use_priority_delivery

        # Statistics for monitoring
        self._backpressure_events: Dict[str, int] = defaultdict(int)

        # Background processing tasks for priority delivery
        self._delivery_tasks: Dict[str, asyncio.Task] = {}

    async def connect(self) -> None:
        """Establish connection (no-op for in-memory broker)."""
        self._connected = True

    async def disconnect(self) -> None:
        """Close connection and cancel all tasks."""
        self._connected = False

        # Cancel all delivery tasks
        for task in self._delivery_tasks.values():
            if not task.done():
                task.cancel()

        if self._delivery_tasks:
            await asyncio.gather(*self._delivery_tasks.values(), return_exceptions=True)

        # Cancel all running tasks
        for task in self._tasks:
            if not task.done():
                task.cancel()

        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

        self._tasks.clear()
        self._delivery_tasks.clear()
        self._subscriptions.clear()
        self._message_queues.clear()
        self._response_queues.clear()
        self._request_message_ids.clear()
        self._backpressure_events.clear()

    def _check_backpressure(self, topic: str) -> bool:
        """
        Check if backpressure should be applied for a topic.
        
        Args:
            topic: The topic to check
            
        Returns:
            True if backpressure should be applied
        """
        queue_size = len(self._message_queues[topic])
        threshold = int(self._max_queue_size * self._backpressure_threshold)
        return queue_size >= threshold

    async def _apply_backpressure(self, topic: str) -> None:
        """
        Apply backpressure delay to slow down the producer.
        
        Args:
            topic: The topic experiencing backpressure
        """
        self._backpressure_events[topic] += 1
        await asyncio.sleep(self._backpressure_delay)

    async def _priority_delivery_worker(self, topic: str) -> None:
        """
        Background worker that delivers messages in priority order.
        
        Args:
            topic: The topic to process
        """
        try:
            while self._connected:
                # Check if there are messages to deliver
                if not self._message_queues[topic]:
                    await asyncio.sleep(0.001)  # Small delay to avoid busy waiting
                    continue

                # Get highest priority message
                _, _, message = heapq.heappop(self._message_queues[topic])

                # Check if this is a response message
                is_response = (
                    message.correlation_id
                    and message.correlation_id in self._response_queues
                    and message.id not in self._request_message_ids
                )

                # Deliver to handlers (unless it's a response message)
                if not is_response:
                    handlers = self._subscriptions.get(topic, {})
                    for handler in handlers.values():
                        task = asyncio.create_task(handler(message))
                        self._tasks.add(task)
                        task.add_done_callback(self._tasks.discard)

                # Handle response messages
                if is_response:
                    await self._response_queues[message.correlation_id].put(message)

        except asyncio.CancelledError:
            # Worker cancelled during shutdown
            pass

    async def publish(self, message: Message, wait_for_confirmation: bool = False) -> Optional[str]:
        """
        Publish a message to all subscribers of the topic.
        
        Implements backpressure: If the queue is near capacity, the publisher
        is automatically slowed down to prevent overwhelming consumers.
        
        Implements priority lanes: CRITICAL messages are processed before
        BACKGROUND messages, allowing urgent tasks to jump the queue.
        
        Args:
            message: The message to publish
            wait_for_confirmation: If True, wait for handlers to process
        
        Returns:
            Message ID
        """
        if not self._connected:
            raise ConnectionError("Broker not connected")

        topic = message.topic

        # Apply backpressure if queue is getting full (reactive streams flow control)
        if self._check_backpressure(topic):
            await self._apply_backpressure(topic)

        # Check if queue is at max capacity
        if len(self._message_queues[topic]) >= self._max_queue_size:
            # Drop oldest BACKGROUND message, or raise error if no BACKGROUND messages
            dropped = self._drop_background_message(topic)
            if not dropped:
                raise RuntimeError(
                    f"Queue for topic '{topic}' is full ({self._max_queue_size} messages). "
                    "Producer is overwhelmed. Consider increasing queue size or adding more consumers."
                )

        # Add message to priority queue
        priority_value = PRIORITY_ORDER.get(message.priority, 3)
        self._message_counter += 1
        heapq.heappush(
            self._message_queues[topic],
            (priority_value, self._message_counter, message)
        )

        # Start priority delivery worker if not already running
        if self._use_priority_delivery and topic not in self._delivery_tasks:
            task = asyncio.create_task(self._priority_delivery_worker(topic))
            self._delivery_tasks[topic] = task

        # Check if this is a response message for request-response pattern
        is_response = (
            message.correlation_id
            and message.correlation_id in self._response_queues
            and message.id not in self._request_message_ids
        )

        # For non-priority mode or when waiting for confirmation, deliver immediately
        if not self._use_priority_delivery:
            # Deliver to subscribers (skip if this is a response message)
            if not is_response:
                handlers = self._subscriptions.get(topic, {})

                if wait_for_confirmation:
                    # Wait for all handlers to complete
                    tasks = []
                    for handler in handlers.values():
                        tasks.append(handler(message))

                    if tasks:
                        await asyncio.gather(*tasks, return_exceptions=True)
                else:
                    # Fire and forget - schedule handlers without waiting
                    for handler in handlers.values():
                        task = asyncio.create_task(handler(message))
                        self._tasks.add(task)
                        task.add_done_callback(self._tasks.discard)

            # Handle request-response pattern
            # Capture response messages in the response queue
            if is_response:
                await self._response_queues[message.correlation_id].put(message)

        return message.id

    def _drop_background_message(self, topic: str) -> bool:
        """
        Drop the oldest BACKGROUND priority message from the queue.
        
        Args:
            topic: The topic to drop from
            
        Returns:
            True if a message was dropped, False if no BACKGROUND messages found
        """
        queue = self._message_queues[topic]
        background_priority = PRIORITY_ORDER[MessagePriority.BACKGROUND]

        # Find index of oldest BACKGROUND message (largest counter value for background priority)
        background_idx = None
        max_counter = -1
        
        for i, (priority, counter, _msg) in enumerate(queue):
            if priority == background_priority and counter > max_counter:
                background_idx = i
                max_counter = counter
        
        if background_idx is not None:
            # Remove the item and re-heapify
            queue[background_idx] = queue[-1]
            queue.pop()
            if background_idx < len(queue):
                heapq.heapify(queue)
            return True

        return False

    async def subscribe(self, topic: str, handler: MessageHandler) -> str:
        """
        Subscribe to a topic.
        
        Args:
            topic: Topic to subscribe to
            handler: Message handler function
        
        Returns:
            Subscription ID
        """
        if not self._connected:
            raise ConnectionError("Broker not connected")

        subscription_id = str(uuid.uuid4())
        self._subscriptions[topic][subscription_id] = handler
        return subscription_id

    async def unsubscribe(self, subscription_id: str) -> None:
        """
        Unsubscribe from a topic.
        
        Args:
            subscription_id: The subscription ID
        """
        for topic_handlers in self._subscriptions.values():
            if subscription_id in topic_handlers:
                del topic_handlers[subscription_id]
                return

    async def request(self, message: Message, timeout: float = 30.0) -> Message:
        """
        Send a request and wait for response.
        
        Args:
            message: Request message
            timeout: Timeout in seconds
        
        Returns:
            Response message
        
        Raises:
            TimeoutError: If timeout exceeded
        """
        if not self._connected:
            raise ConnectionError("Broker not connected")

        # Generate correlation ID if not present
        if not message.correlation_id:
            message.correlation_id = str(uuid.uuid4())

        # Set up reply queue
        reply_queue: asyncio.Queue = asyncio.Queue()
        self._response_queues[message.correlation_id] = reply_queue

        # Mark this message ID as a request to avoid self-capture
        self._request_message_ids.add(message.id)

        try:
            # Publish the request
            await self.publish(message, wait_for_confirmation=False)

            # Wait for response
            try:
                response = await asyncio.wait_for(reply_queue.get(), timeout=timeout)
                return response
            except asyncio.TimeoutError:
                raise TimeoutError(f"No response received within {timeout} seconds")

        finally:
            # Clean up
            if message.correlation_id in self._response_queues:
                del self._response_queues[message.correlation_id]
            if message.id in self._request_message_ids:
                self._request_message_ids.discard(message.id)

    async def get_pending_messages(self, topic: str, limit: int = 10) -> List[Message]:
        """
        Get pending messages from a topic (in priority order).
        
        Args:
            topic: Topic to get messages from
            limit: Maximum number of messages
        
        Returns:
            List of messages (highest priority first)
        """
        if not self._connected:
            raise ConnectionError("Broker not connected")

        queue = self._message_queues.get(topic, [])

        # Sort by priority and return top N messages
        sorted_messages = sorted(queue, key=lambda x: (x[0], x[1]))
        messages = [item[2] for item in sorted_messages[:limit]]

        return messages

    def get_backpressure_stats(self, topic: Optional[str] = None) -> Dict[str, int]:
        """
        Get backpressure statistics.
        
        Args:
            topic: Optional topic to get stats for. If None, returns all topics.
            
        Returns:
            Dictionary mapping topics to backpressure event counts
        """
        if topic:
            return {topic: self._backpressure_events.get(topic, 0)}
        return dict(self._backpressure_events)

    def get_queue_size(self, topic: str) -> int:
        """
        Get current queue size for a topic.
        
        Args:
            topic: The topic to check
            
        Returns:
            Number of messages in the queue
        """
        return len(self._message_queues.get(topic, []))
