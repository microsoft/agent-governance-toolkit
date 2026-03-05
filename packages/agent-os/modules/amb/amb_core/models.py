# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Core message models for AMB."""

from enum import Enum, IntEnum
from typing import Any, Dict, Optional
from datetime import datetime, timezone
from pydantic import BaseModel, Field, ConfigDict, field_validator


class MessagePriority(IntEnum):
    """
    Message priority levels.
    
    Higher values indicate higher priority. Messages with higher priority
    are processed before lower priority messages when queued.
    """
    BACKGROUND = 0  # Lowest priority for background tasks
    LOW = 1
    NORMAL = 5
    HIGH = 8
    URGENT = 10
    CRITICAL = 15  # For system-critical messages like fraud alerts


class Priority:
    """
    Convenience class for accessing priority levels.
    
    Example:
        message = Message(payload=data, priority=Priority.HIGH)
    """
    BACKGROUND = MessagePriority.BACKGROUND
    LOW = MessagePriority.LOW
    NORMAL = MessagePriority.NORMAL
    HIGH = MessagePriority.HIGH
    URGENT = MessagePriority.URGENT
    CRITICAL = MessagePriority.CRITICAL


class MessageStatus(str, Enum):
    """Status of a message in its lifecycle."""
    PENDING = "pending"
    DELIVERED = "delivered"
    ACKNOWLEDGED = "acknowledged"
    FAILED = "failed"
    EXPIRED = "expired"
    DLQ = "dlq"  # Moved to dead letter queue


class Message(BaseModel):
    """
    Core message model for the Agent Message Bus.
    
    This model represents a message that can be sent through the bus.
    It includes metadata for routing, tracking, handling, and distributed tracing.
    
    New in v0.2.0:
        - trace_id: For distributed tracing across agents
        - ttl_seconds: Alias for ttl for clearer API
        - is_expired: Property to check if message has expired
    """
    
    id: str = Field(..., description="Unique message identifier")
    topic: str = Field(..., description="Message topic/channel")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Message payload")
    priority: MessagePriority = Field(default=MessagePriority.NORMAL, description="Message priority")
    
    # Metadata
    sender: Optional[str] = Field(None, description="Sender identifier")
    correlation_id: Optional[str] = Field(None, description="Correlation ID for request-response patterns")
    reply_to: Optional[str] = Field(None, description="Topic to reply to")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), description="Message timestamp")
    
    # TTL and expiration
    ttl: Optional[int] = Field(None, description="Time to live in seconds", alias="ttl_seconds")
    
    # Distributed tracing (AMB-004)
    trace_id: Optional[str] = Field(None, description="Distributed trace ID for tracking message flow")
    span_id: Optional[str] = Field(None, description="Span ID within the trace")
    parent_span_id: Optional[str] = Field(None, description="Parent span ID for nested operations")
    
    # Additional metadata
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    
    model_config = ConfigDict(
        json_encoders={
            datetime: lambda v: v.isoformat()
        },
        populate_by_name=True,  # Allow both 'ttl' and 'ttl_seconds'
    )
    
    @field_validator('priority', mode='before')
    @classmethod
    def validate_priority(cls, v):
        """Accept both int and MessagePriority."""
        if isinstance(v, int):
            return MessagePriority(v)
        if isinstance(v, str):
            return MessagePriority[v.upper()]
        return v
    
    @property
    def ttl_seconds(self) -> Optional[int]:
        """Alias for ttl for clearer API."""
        return self.ttl
    
    @property
    def is_expired(self) -> bool:
        """
        Check if the message has expired based on TTL.
        
        Returns:
            True if the message has exceeded its TTL, False otherwise
        """
        if self.ttl is None:
            return False
        
        now = datetime.now(timezone.utc)
        age_seconds = (now - self.timestamp).total_seconds()
        return age_seconds > self.ttl
    
    @property
    def age_seconds(self) -> float:
        """Get the age of the message in seconds."""
        now = datetime.now(timezone.utc)
        return (now - self.timestamp).total_seconds()
    
    @property
    def remaining_ttl(self) -> Optional[float]:
        """
        Get remaining TTL in seconds.
        
        Returns:
            Remaining TTL, 0 if expired, None if no TTL set
        """
        if self.ttl is None:
            return None
        
        remaining = self.ttl - self.age_seconds
        return max(0, remaining)
