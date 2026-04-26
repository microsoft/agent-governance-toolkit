# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for CloudEvents support in AMB."""

import pytest
from datetime import datetime, timezone
import json

from amb_core.models import Message, MessagePriority, Priority
from amb_core.cloudevents import (
    CloudEvent,
    CloudEventBatch,
    to_cloudevent,
    from_cloudevent,
    to_http_headers,
    from_http_headers,
    topic_to_type,
    type_to_topic,
    CLOUDEVENTS_SPEC_VERSION,
)


class TestCloudEvent:
    """Tests for CloudEvent model."""
    
    def test_create_minimal_event(self):
        """Test creating CloudEvent with minimal required attributes."""
        event = CloudEvent(
            id="evt-123",
            source="/agent-governance-python/agent-os/test",
            type="dev.agent-os.test.event"
        )
        
        assert event.id == "evt-123"
        assert event.source == "/agent-governance-python/agent-os/test"
        assert event.type == "dev.agent-os.test.event"
        assert event.specversion == CLOUDEVENTS_SPEC_VERSION
        assert event.datacontenttype == "application/json"
    
    def test_create_full_event(self):
        """Test creating CloudEvent with all attributes."""
        now = datetime.now(timezone.utc)
        event = CloudEvent(
            id="evt-456",
            source="/agent-governance-python/agent-os/fraud-detector",
            type="dev.agent-os.fraud.alerts",
            subject="fraud.alerts",
            time=now,
            data={"transaction_id": "tx-789", "risk_score": 0.95},
            dataschema="https://agent-os.dev/schemas/fraud-alert.json",
            ambpriority=Priority.CRITICAL,
            ambtraceid="trace-abc",
            ambspanid="span-def",
            ambsender="fraud-detector",
            ambttl=300,
        )
        
        assert event.id == "evt-456"
        assert event.data["risk_score"] == 0.95
        assert event.ambpriority == Priority.CRITICAL
        assert event.ambtraceid == "trace-abc"
        assert event.ambttl == 300
    
    def test_specversion_validation(self):
        """Test that invalid specversion is rejected."""
        with pytest.raises(ValueError, match="Unsupported specversion"):
            CloudEvent(
                id="evt-123",
                source="/test",
                type="test.event",
                specversion="0.3"
            )
    
    def test_source_validation(self):
        """Test that empty source is rejected."""
        with pytest.raises(ValueError, match="source cannot be empty"):
            CloudEvent(
                id="evt-123",
                source="",
                type="test.event"
            )
    
    def test_type_validation(self):
        """Test that empty type is rejected."""
        with pytest.raises(ValueError, match="type cannot be empty"):
            CloudEvent(
                id="evt-123",
                source="/test",
                type=""
            )
    
    def test_to_json(self):
        """Test JSON serialization."""
        event = CloudEvent(
            id="evt-123",
            source="/test",
            type="test.event",
            data={"key": "value"}
        )
        
        json_str = event.to_json()
        parsed = json.loads(json_str)
        
        assert parsed["id"] == "evt-123"
        assert parsed["source"] == "/test"
        assert parsed["type"] == "test.event"
        assert parsed["data"] == {"key": "value"}
        assert parsed["specversion"] == "1.0"
    
    def test_from_json(self):
        """Test JSON deserialization."""
        json_str = json.dumps({
            "id": "evt-123",
            "source": "/test",
            "type": "test.event",
            "specversion": "1.0",
            "data": {"key": "value"}
        })
        
        event = CloudEvent.from_json(json_str)
        
        assert event.id == "evt-123"
        assert event.source == "/test"
        assert event.type == "test.event"
        assert event.data == {"key": "value"}
    
    def test_to_dict(self):
        """Test dictionary conversion."""
        event = CloudEvent(
            id="evt-123",
            source="/test",
            type="test.event"
        )
        
        d = event.to_dict()
        
        assert d["id"] == "evt-123"
        assert "ambpriority" not in d  # None values excluded


class TestTopicTypeConversion:
    """Tests for topic/type conversion functions."""
    
    def test_topic_to_type_default_prefix(self):
        """Test converting topic to type with default prefix."""
        assert topic_to_type("fraud.alerts") == "dev.agent-os.fraud.alerts"
        assert topic_to_type("user.events") == "dev.agent-os.user.events"
    
    def test_topic_to_type_custom_prefix(self):
        """Test converting topic to type with custom prefix."""
        assert topic_to_type("fraud.alerts", prefix="com.example") == "com.example.fraud.alerts"
    
    def test_type_to_topic_default_prefix(self):
        """Test converting type to topic with default prefix."""
        assert type_to_topic("dev.agent-os.fraud.alerts") == "fraud.alerts"
        assert type_to_topic("dev.agent-os.user.events") == "user.events"
    
    def test_type_to_topic_custom_prefix(self):
        """Test converting type to topic with custom prefix."""
        assert type_to_topic("com.example.fraud.alerts", prefix="com.example") == "fraud.alerts"
    
    def test_type_to_topic_no_prefix_match(self):
        """Test type_to_topic when prefix doesn't match."""
        # Returns original type when prefix doesn't match
        assert type_to_topic("external.system.event") == "external.system.event"


class TestMessageConversion:
    """Tests for AMB Message <-> CloudEvent conversion."""
    
    def test_to_cloudevent_basic(self):
        """Test converting basic Message to CloudEvent."""
        message = Message(
            id="msg-123",
            topic="fraud.alerts",
            payload={"transaction_id": "tx-456", "risk_score": 0.9}
        )
        
        event = to_cloudevent(message, source="/agent-governance-python/agent-os/detector")
        
        assert event.id == "msg-123"
        assert event.source == "/agent-governance-python/agent-os/detector"
        assert event.type == "dev.agent-os.fraud.alerts"
        assert event.subject == "fraud.alerts"
        assert event.data == {"transaction_id": "tx-456", "risk_score": 0.9}
    
    def test_to_cloudevent_with_priority(self):
        """Test converting Message with priority."""
        message = Message(
            id="msg-123",
            topic="fraud.alerts",
            payload={},
            priority=MessagePriority.CRITICAL
        )
        
        event = to_cloudevent(message, source="/test")
        
        assert event.ambpriority == MessagePriority.CRITICAL.value
    
    def test_to_cloudevent_with_tracing(self):
        """Test converting Message with tracing info."""
        message = Message(
            id="msg-123",
            topic="test",
            payload={},
            trace_id="trace-abc",
            span_id="span-def",
            parent_span_id="parent-ghi"
        )
        
        event = to_cloudevent(message, source="/test")
        
        assert event.ambtraceid == "trace-abc"
        assert event.ambspanid == "span-def"
        assert event.ambparentspanid == "parent-ghi"
    
    def test_to_cloudevent_with_ttl(self):
        """Test converting Message with TTL."""
        message = Message(
            id="msg-123",
            topic="test",
            payload={},
            ttl=300
        )
        
        event = to_cloudevent(message, source="/test")
        
        assert event.ambttl == 300
    
    def test_to_cloudevent_custom_prefix(self):
        """Test converting Message with custom type prefix."""
        message = Message(
            id="msg-123",
            topic="fraud.alerts",
            payload={}
        )
        
        event = to_cloudevent(message, source="/test", type_prefix="com.mycompany")
        
        assert event.type == "com.mycompany.fraud.alerts"
    
    def test_from_cloudevent_basic(self):
        """Test converting CloudEvent to Message."""
        event = CloudEvent(
            id="evt-123",
            source="/external/system",
            type="dev.agent-os.user.events",
            data={"user_id": "u-456", "action": "login"}
        )
        
        message = from_cloudevent(event)
        
        assert message.id == "evt-123"
        assert message.topic == "user.events"
        assert message.payload == {"user_id": "u-456", "action": "login"}
    
    def test_from_cloudevent_with_subject(self):
        """Test that subject takes precedence for topic."""
        event = CloudEvent(
            id="evt-123",
            source="/external",
            type="com.external.some.event",
            subject="custom.topic",
            data={}
        )
        
        message = from_cloudevent(event)
        
        assert message.topic == "custom.topic"
    
    def test_from_cloudevent_with_priority(self):
        """Test converting CloudEvent with priority."""
        event = CloudEvent(
            id="evt-123",
            source="/test",
            type="test.event",
            ambpriority=MessagePriority.HIGH.value
        )
        
        message = from_cloudevent(event)
        
        assert message.priority == MessagePriority.HIGH
    
    def test_from_cloudevent_with_invalid_priority(self):
        """Test that invalid priority maps to closest valid value."""
        event = CloudEvent(
            id="evt-123",
            source="/test",
            type="test.event",
            ambpriority=99  # Invalid priority value
        )
        
        message = from_cloudevent(event)
        
        assert message.priority == MessagePriority.CRITICAL
    
    def test_from_cloudevent_preserves_metadata(self):
        """Test that CloudEvent source info is preserved in metadata."""
        event = CloudEvent(
            id="evt-123",
            source="/external/service",
            type="external.event.type",
            dataschema="https://example.com/schema.json"
        )
        
        message = from_cloudevent(event)
        
        assert message.metadata["cloudevents.source"] == "/external/service"
        assert message.metadata["cloudevents.type"] == "external.event.type"
        assert message.metadata["cloudevents.dataschema"] == "https://example.com/schema.json"
    
    def test_roundtrip_conversion(self):
        """Test that Message -> CloudEvent -> Message preserves data."""
        original = Message(
            id="msg-123",
            topic="fraud.alerts",
            payload={"risk": 0.95},
            priority=MessagePriority.CRITICAL,
            sender="detector",
            trace_id="trace-abc",
            ttl=300
        )
        
        event = to_cloudevent(original, source="/agent-governance-python/agent-os/detector")
        converted = from_cloudevent(event)
        
        assert converted.id == original.id
        assert converted.topic == original.topic
        assert converted.payload == original.payload
        assert converted.priority == original.priority
        assert converted.sender == original.sender
        assert converted.trace_id == original.trace_id
        assert converted.ttl == original.ttl


class TestCloudEventBatch:
    """Tests for CloudEventBatch."""
    
    def test_create_batch(self):
        """Test creating a batch of events."""
        events = [
            CloudEvent(id=f"evt-{i}", source="/test", type="test.event")
            for i in range(3)
        ]
        
        batch = CloudEventBatch(events=events)
        
        assert len(batch) == 3
    
    def test_batch_to_json(self):
        """Test serializing batch to JSON array."""
        batch = CloudEventBatch(events=[
            CloudEvent(id="evt-1", source="/test", type="test.event"),
            CloudEvent(id="evt-2", source="/test", type="test.event"),
        ])
        
        json_str = batch.to_json()
        parsed = json.loads(json_str)
        
        assert isinstance(parsed, list)
        assert len(parsed) == 2
        assert parsed[0]["id"] == "evt-1"
        assert parsed[1]["id"] == "evt-2"
    
    def test_batch_from_json(self):
        """Test parsing batch from JSON array."""
        json_str = json.dumps([
            {"id": "evt-1", "source": "/test", "type": "test.event", "specversion": "1.0"},
            {"id": "evt-2", "source": "/test", "type": "test.event", "specversion": "1.0"},
        ])
        
        batch = CloudEventBatch.from_json(json_str)
        
        assert len(batch) == 2
        assert list(batch)[0].id == "evt-1"
    
    def test_batch_iteration(self):
        """Test iterating over batch."""
        events = [
            CloudEvent(id=f"evt-{i}", source="/test", type="test.event")
            for i in range(3)
        ]
        batch = CloudEventBatch(events=events)
        
        ids = [e.id for e in batch]
        
        assert ids == ["evt-0", "evt-1", "evt-2"]


class TestHTTPBinding:
    """Tests for HTTP protocol binding."""
    
    def test_to_http_headers(self):
        """Test converting CloudEvent to HTTP headers."""
        event = CloudEvent(
            id="evt-123",
            source="/agent-governance-python/agent-os/detector",
            type="dev.agent-os.fraud.alerts",
            ambpriority=15,
            ambsender="detector"
        )
        
        headers = to_http_headers(event)
        
        assert headers["ce-id"] == "evt-123"
        assert headers["ce-source"] == "/agent-governance-python/agent-os/detector"
        assert headers["ce-type"] == "dev.agent-os.fraud.alerts"
        assert headers["ce-specversion"] == "1.0"
        assert headers["ce-ambpriority"] == "15"
        assert headers["ce-ambsender"] == "detector"
    
    def test_from_http_headers(self):
        """Test creating CloudEvent from HTTP headers."""
        headers = {
            "ce-id": "evt-123",
            "ce-source": "/external",
            "ce-type": "external.event",
            "ce-specversion": "1.0",
            "ce-ambpriority": "10",
            "ce-ambttl": "300",
        }
        data = {"key": "value"}
        
        event = from_http_headers(headers, data)
        
        assert event.id == "evt-123"
        assert event.source == "/external"
        assert event.type == "external.event"
        assert event.ambpriority == 10
        assert event.ambttl == 300
        assert event.data == {"key": "value"}
    
    def test_from_http_headers_case_insensitive(self):
        """Test that header parsing is case-insensitive."""
        headers = {
            "CE-ID": "evt-123",
            "CE-Source": "/external",
            "CE-Type": "external.event",
            "CE-Specversion": "1.0",
        }
        
        event = from_http_headers(headers)
        
        assert event.id == "evt-123"
        assert event.source == "/external"
