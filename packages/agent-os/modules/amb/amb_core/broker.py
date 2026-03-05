# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Broker adapter interface for AMB."""

from abc import ABC, abstractmethod
from typing import Awaitable, Callable, List, Optional

from amb_core.models import Message

# Type alias for message handler functions
MessageHandler = Callable[[Message], Awaitable[None]]


class BrokerAdapter(ABC):
    """
    Abstract base class for broker adapters.
    
    This provides a broker-agnostic interface that can be implemented
    for different message brokers (Redis, RabbitMQ, Kafka, etc.).
    """

    @abstractmethod
    async def connect(self) -> None:
        """
        Establish connection to the broker.
        
        Raises:
            ConnectionError: If connection fails
        """
        pass

    @abstractmethod
    async def disconnect(self) -> None:
        """
        Close connection to the broker.
        """
        pass

    @abstractmethod
    async def publish(self, message: Message, wait_for_confirmation: bool = False) -> Optional[str]:
        """
        Publish a message to the broker.
        
        Args:
            message: The message to publish
            wait_for_confirmation: If True, wait for broker confirmation (slower but reliable)
                                 If False, fire and forget (faster but no guarantee)
        
        Returns:
            Optional message ID or confirmation token if wait_for_confirmation is True
        
        Raises:
            PublishError: If publishing fails
        """
        pass

    @abstractmethod
    async def subscribe(self, topic: str, handler: MessageHandler) -> str:
        """
        Subscribe to a topic and register a handler.
        
        Args:
            topic: Topic to subscribe to
            handler: Async function to handle incoming messages
        
        Returns:
            Subscription ID that can be used to unsubscribe
        
        Raises:
            SubscriptionError: If subscription fails
        """
        pass

    @abstractmethod
    async def unsubscribe(self, subscription_id: str) -> None:
        """
        Unsubscribe from a topic.
        
        Args:
            subscription_id: The subscription ID returned from subscribe()
        
        Raises:
            SubscriptionError: If unsubscription fails
        """
        pass

    @abstractmethod
    async def request(self, message: Message, timeout: float = 30.0) -> Message:
        """
        Send a request and wait for a response (request-response pattern).
        
        Args:
            message: The request message
            timeout: Maximum time to wait for response in seconds
        
        Returns:
            The response message
        
        Raises:
            TimeoutError: If no response received within timeout
            RequestError: If request fails
        """
        pass

    @abstractmethod
    async def get_pending_messages(self, topic: str, limit: int = 10) -> List[Message]:
        """
        Get pending messages from a topic (if supported by broker).
        
        Args:
            topic: Topic to get messages from
            limit: Maximum number of messages to retrieve
        
        Returns:
            List of pending messages
        """
        pass

    def get_backpressure_stats(self, topic: Optional[str] = None):
        """
        Get backpressure statistics (if supported by broker).
        
        Optional method - brokers may choose not to implement this.
        
        Args:
            topic: Optional topic to get stats for
            
        Returns:
            Statistics about backpressure events
        """
        return {}

    def get_queue_size(self, topic: str) -> int:
        """
        Get current queue size for a topic (if supported by broker).
        
        Optional method - brokers may choose not to implement this.
        
        Args:
            topic: The topic to check
            
        Returns:
            Number of messages in the queue, or 0 if not supported
        """
        return 0
