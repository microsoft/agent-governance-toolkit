# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""CloudEvents specification support for AMB.

This module provides CloudEvents v1.0 compatibility, enabling interoperability
with other systems that support the CNCF CloudEvents specification.

CloudEvents Spec: https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/spec.md

Example:
    from amb_core.cloudevents import CloudEvent, to_cloudevent, from_cloudevent
    
    # Convert AMB Message to CloudEvent
    message = Message(id="123", topic="fraud.alerts", payload={"risk": 0.9})
    cloud_event = to_cloudevent(message, source="/agent-os/fraud-detector")
    
    # Send as JSON (CloudEvents structured content mode)
    json_data = cloud_event.to_json()
    
    # Convert CloudEvent back to AMB Message
    message = from_cloudevent(cloud_event)
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union
from pydantic import BaseModel, Field, field_validator, ConfigDict
import json
import uuid

from amb_core.models import Message, MessagePriority


# CloudEvents spec version
CLOUDEVENTS_SPEC_VERSION = "1.0"

# CloudEvents content type
CLOUDEVENTS_CONTENT_TYPE = "application/cloudevents+json"

# Agent OS event type prefix
AGENT_OS_TYPE_PREFIX = "dev.agent-os"


class CloudEvent(BaseModel):
    """
    CloudEvents v1.0 specification compliant event.
    
    This model implements the CloudEvents specification required and optional attributes.
    See: https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/spec.md
    
    Required Attributes:
        - id: Unique identifier for the event
        - source: Context in which the event happened (URI-reference)
        - specversion: CloudEvents specification version
        - type: Type of event (reverse-DNS naming recommended)
    
    Optional Attributes:
        - datacontenttype: Content type of data
        - dataschema: Schema that data adheres to
        - subject: Subject of the event in the context of the producer
        - time: Timestamp of when the event happened
        - data: Event payload
    
    Extension Attributes (Agent OS specific):
        - priority: Message priority (amb extension)
        - traceid: Distributed trace ID (amb extension)
        - spanid: Span ID for tracing (amb extension)
        - parentspanid: Parent span ID (amb extension)
        - ttl: Time-to-live in seconds (amb extension)
        - sender: Sender identifier (amb extension)
        - correlationid: Correlation ID for request-response (amb extension)
    """
    
    # Required attributes (CloudEvents spec)
    id: str = Field(..., description="Unique identifier for the event")
    source: str = Field(..., description="URI-reference identifying the context")
    specversion: str = Field(default=CLOUDEVENTS_SPEC_VERSION, description="CloudEvents spec version")
    type: str = Field(..., description="Event type (reverse-DNS naming)")
    
    # Optional attributes (CloudEvents spec)
    datacontenttype: Optional[str] = Field(
        default="application/json",
        description="Content type of the data attribute"
    )
    dataschema: Optional[str] = Field(
        None,
        description="URI identifying the schema that data adheres to"
    )
    subject: Optional[str] = Field(
        None,
        description="Subject of the event in the context of the event producer"
    )
    time: Optional[datetime] = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of when the event happened (RFC 3339)"
    )
    data: Optional[Dict[str, Any]] = Field(
        default_factory=dict,
        description="Event payload"
    )
    
    # Extension attributes (Agent OS / AMB specific)
    # Prefixed with 'amb' namespace per CloudEvents extension naming conventions
    ambpriority: Optional[int] = Field(
        None,
        description="Message priority (AMB extension)"
    )
    ambtraceid: Optional[str] = Field(
        None,
        description="Distributed trace ID (AMB extension)"
    )
    ambspanid: Optional[str] = Field(
        None,
        description="Span ID within the trace (AMB extension)"
    )
    ambparentspanid: Optional[str] = Field(
        None,
        description="Parent span ID (AMB extension)"
    )
    ambttl: Optional[int] = Field(
        None,
        description="Time-to-live in seconds (AMB extension)"
    )
    ambsender: Optional[str] = Field(
        None,
        description="Sender identifier (AMB extension)"
    )
    ambcorrelationid: Optional[str] = Field(
        None,
        description="Correlation ID for request-response patterns (AMB extension)"
    )
    ambreplyto: Optional[str] = Field(
        None,
        description="Topic to reply to (AMB extension)"
    )
    
    model_config = ConfigDict(
        json_encoders={
            datetime: lambda v: v.isoformat() if v else None
        },
        extra="allow",  # Allow additional extension attributes
    )
    
    @field_validator('specversion')
    @classmethod
    def validate_specversion(cls, v: str) -> str:
        """Validate CloudEvents spec version."""
        if v != CLOUDEVENTS_SPEC_VERSION:
            raise ValueError(f"Unsupported specversion: {v}. Expected: {CLOUDEVENTS_SPEC_VERSION}")
        return v
    
    @field_validator('source')
    @classmethod
    def validate_source(cls, v: str) -> str:
        """Validate source is a URI-reference."""
        if not v:
            raise ValueError("source cannot be empty")
        return v
    
    @field_validator('type')
    @classmethod
    def validate_type(cls, v: str) -> str:
        """Validate type is non-empty."""
        if not v:
            raise ValueError("type cannot be empty")
        return v
    
    def to_json(self, **kwargs) -> str:
        """
        Serialize to CloudEvents JSON format (structured content mode).
        
        Returns:
            JSON string representation
        """
        return self.model_dump_json(exclude_none=True, **kwargs)
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert to dictionary (excludes None values).
        
        Returns:
            Dictionary representation
        """
        return self.model_dump(exclude_none=True)
    
    @classmethod
    def from_json(cls, json_str: str) -> "CloudEvent":
        """
        Parse from CloudEvents JSON format.
        
        Args:
            json_str: JSON string to parse
            
        Returns:
            CloudEvent instance
        """
        data = json.loads(json_str)
        return cls.model_validate(data)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CloudEvent":
        """
        Create from dictionary.
        
        Args:
            data: Dictionary with CloudEvent attributes
            
        Returns:
            CloudEvent instance
        """
        return cls.model_validate(data)


def topic_to_type(topic: str, prefix: str = AGENT_OS_TYPE_PREFIX) -> str:
    """
    Convert an AMB topic to a CloudEvents type.
    
    CloudEvents recommends reverse-DNS naming for types.
    
    Args:
        topic: AMB topic (e.g., "fraud.alerts")
        prefix: Type prefix (default: "dev.agent-os")
        
    Returns:
        CloudEvents type (e.g., "dev.agent-os.fraud.alerts")
    
    Example:
        >>> topic_to_type("fraud.alerts")
        "dev.agent-os.fraud.alerts"
    """
    return f"{prefix}.{topic}"


def type_to_topic(event_type: str, prefix: str = AGENT_OS_TYPE_PREFIX) -> str:
    """
    Convert a CloudEvents type back to an AMB topic.
    
    Args:
        event_type: CloudEvents type (e.g., "dev.agent-os.fraud.alerts")
        prefix: Type prefix to strip (default: "dev.agent-os")
        
    Returns:
        AMB topic (e.g., "fraud.alerts")
    
    Example:
        >>> type_to_topic("dev.agent-os.fraud.alerts")
        "fraud.alerts"
    """
    full_prefix = f"{prefix}."
    if event_type.startswith(full_prefix):
        return event_type[len(full_prefix):]
    return event_type


def to_cloudevent(
    message: Message,
    source: str,
    *,
    type_prefix: str = AGENT_OS_TYPE_PREFIX,
    dataschema: Optional[str] = None
) -> CloudEvent:
    """
    Convert an AMB Message to a CloudEvent.
    
    Args:
        message: AMB Message to convert
        source: CloudEvents source URI (identifies the event producer)
        type_prefix: Prefix for the event type (default: "dev.agent-os")
        dataschema: Optional URI of the data schema
        
    Returns:
        CloudEvent instance
    
    Example:
        message = Message(
            id="msg-123",
            topic="fraud.alerts",
            payload={"transaction_id": "tx-456", "risk_score": 0.95},
            priority=Priority.CRITICAL,
            sender="fraud-detector"
        )
        
        event = to_cloudevent(message, source="/agent-os/fraud-detector")
        # Result:
        # {
        #     "specversion": "1.0",
        #     "id": "msg-123",
        #     "source": "/agent-os/fraud-detector",
        #     "type": "dev.agent-os.fraud.alerts",
        #     "datacontenttype": "application/json",
        #     "time": "2026-02-03T04:30:00Z",
        #     "data": {"transaction_id": "tx-456", "risk_score": 0.95},
        #     "ambpriority": 15,
        #     "ambsender": "fraud-detector"
        # }
    """
    return CloudEvent(
        id=message.id,
        source=source,
        type=topic_to_type(message.topic, type_prefix),
        subject=message.topic,  # Original topic as subject
        time=message.timestamp,
        data=message.payload,
        dataschema=dataschema,
        
        # AMB extensions
        ambpriority=message.priority.value if message.priority else None,
        ambtraceid=message.trace_id,
        ambspanid=message.span_id,
        ambparentspanid=message.parent_span_id,
        ambttl=message.ttl,
        ambsender=message.sender,
        ambcorrelationid=message.correlation_id,
        ambreplyto=message.reply_to,
    )


def from_cloudevent(
    event: CloudEvent,
    *,
    type_prefix: str = AGENT_OS_TYPE_PREFIX
) -> Message:
    """
    Convert a CloudEvent to an AMB Message.
    
    Args:
        event: CloudEvent to convert
        type_prefix: Prefix to strip from event type (default: "dev.agent-os")
        
    Returns:
        AMB Message instance
    
    Example:
        event = CloudEvent(
            id="evt-123",
            source="/external-system",
            type="dev.agent-os.user.events",
            data={"user_id": "u-456", "action": "login"}
        )
        
        message = from_cloudevent(event)
        # message.topic == "user.events"
        # message.payload == {"user_id": "u-456", "action": "login"}
    """
    # Determine topic from type or subject
    topic = event.subject or type_to_topic(event.type, type_prefix)
    
    # Map priority
    priority = MessagePriority.NORMAL
    if event.ambpriority is not None:
        try:
            priority = MessagePriority(event.ambpriority)
        except ValueError:
            # Use closest valid priority
            if event.ambpriority >= MessagePriority.CRITICAL:
                priority = MessagePriority.CRITICAL
            elif event.ambpriority >= MessagePriority.URGENT:
                priority = MessagePriority.URGENT
            elif event.ambpriority >= MessagePriority.HIGH:
                priority = MessagePriority.HIGH
            elif event.ambpriority >= MessagePriority.NORMAL:
                priority = MessagePriority.NORMAL
            elif event.ambpriority >= MessagePriority.LOW:
                priority = MessagePriority.LOW
            else:
                priority = MessagePriority.BACKGROUND
    
    return Message(
        id=event.id,
        topic=topic,
        payload=event.data or {},
        priority=priority,
        timestamp=event.time or datetime.now(timezone.utc),
        sender=event.ambsender,
        correlation_id=event.ambcorrelationid,
        reply_to=event.ambreplyto,
        ttl=event.ambttl,
        trace_id=event.ambtraceid,
        span_id=event.ambspanid,
        parent_span_id=event.ambparentspanid,
        metadata={
            "cloudevents.source": event.source,
            "cloudevents.type": event.type,
            "cloudevents.dataschema": event.dataschema,
        }
    )


class CloudEventBatch(BaseModel):
    """
    Batch of CloudEvents for bulk transmission.
    
    CloudEvents batching spec: https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/formats/json-format.md#4-json-batch-format
    """
    
    events: list[CloudEvent] = Field(default_factory=list)
    
    def to_json(self) -> str:
        """Serialize batch to JSON array."""
        def serialize_event(e: CloudEvent) -> Dict[str, Any]:
            d = e.to_dict()
            # Convert datetime to ISO format
            if "time" in d and isinstance(d["time"], datetime):
                d["time"] = d["time"].isoformat()
            return d
        
        return json.dumps([serialize_event(e) for e in self.events])
    
    @classmethod
    def from_json(cls, json_str: str) -> "CloudEventBatch":
        """Parse batch from JSON array."""
        data = json.loads(json_str)
        events = [CloudEvent.from_dict(e) for e in data]
        return cls(events=events)
    
    def __len__(self) -> int:
        return len(self.events)
    
    def __iter__(self):
        return iter(self.events)


# HTTP binding headers for CloudEvents
# See: https://github.com/cloudevents/spec/blob/v1.0.2/cloudevents/bindings/http-protocol-binding.md
HTTP_HEADERS = {
    "id": "ce-id",
    "source": "ce-source",
    "specversion": "ce-specversion",
    "type": "ce-type",
    "datacontenttype": "content-type",
    "dataschema": "ce-dataschema",
    "subject": "ce-subject",
    "time": "ce-time",
    # AMB extensions
    "ambpriority": "ce-ambpriority",
    "ambtraceid": "ce-ambtraceid",
    "ambspanid": "ce-ambspanid",
    "ambparentspanid": "ce-ambparentspanid",
    "ambttl": "ce-ambttl",
    "ambsender": "ce-ambsender",
    "ambcorrelationid": "ce-ambcorrelationid",
    "ambreplyto": "ce-ambreplyto",
}


def to_http_headers(event: CloudEvent) -> Dict[str, str]:
    """
    Convert CloudEvent to HTTP headers (binary content mode).
    
    Args:
        event: CloudEvent to convert
        
    Returns:
        Dictionary of HTTP headers
    
    Example:
        headers = to_http_headers(event)
        # {
        #     "ce-id": "msg-123",
        #     "ce-source": "/agent-os/detector",
        #     "ce-type": "dev.agent-os.fraud.alerts",
        #     "ce-specversion": "1.0",
        #     "content-type": "application/json",
        #     ...
        # }
    """
    headers = {}
    event_dict = event.to_dict()
    
    for attr, header in HTTP_HEADERS.items():
        if attr in event_dict and event_dict[attr] is not None:
            value = event_dict[attr]
            if isinstance(value, datetime):
                value = value.isoformat()
            elif not isinstance(value, str):
                value = str(value)
            headers[header] = value
    
    return headers


def from_http_headers(headers: Dict[str, str], data: Optional[Dict[str, Any]] = None) -> CloudEvent:
    """
    Create CloudEvent from HTTP headers (binary content mode).
    
    Args:
        headers: HTTP headers (case-insensitive)
        data: Request body as parsed JSON
        
    Returns:
        CloudEvent instance
    """
    # Normalize header names to lowercase
    normalized = {k.lower(): v for k, v in headers.items()}
    
    # Reverse mapping
    header_to_attr = {v.lower(): k for k, v in HTTP_HEADERS.items()}
    
    event_data = {}
    for header, value in normalized.items():
        if header in header_to_attr:
            attr = header_to_attr[header]
            # Convert types as needed
            if attr in ("ambpriority", "ambttl"):
                value = int(value)
            event_data[attr] = value
    
    event_data["data"] = data
    
    return CloudEvent.from_dict(event_data)
