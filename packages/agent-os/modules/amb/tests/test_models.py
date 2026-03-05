# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for core message models."""

from amb_core.models import Message, MessagePriority


def test_message_creation():
    """Test basic message creation."""
    msg = Message(
        id="test-123",
        topic="test.topic",
        payload={"key": "value"}
    )

    assert msg.id == "test-123"
    assert msg.topic == "test.topic"
    assert msg.payload == {"key": "value"}
    assert msg.priority == MessagePriority.NORMAL


def test_message_with_priority():
    """Test message with different priority levels."""
    msg = Message(
        id="test-123",
        topic="test.topic",
        payload={},
        priority=MessagePriority.HIGH
    )

    assert msg.priority == MessagePriority.HIGH


def test_message_with_metadata():
    """Test message with metadata."""
    msg = Message(
        id="test-123",
        topic="test.topic",
        payload={},
        sender="agent-1",
        correlation_id="corr-123",
        reply_to="reply.topic",
        metadata={"custom": "data"}
    )

    assert msg.sender == "agent-1"
    assert msg.correlation_id == "corr-123"
    assert msg.reply_to == "reply.topic"
    assert msg.metadata == {"custom": "data"}


def test_message_serialization():
    """Test message JSON serialization."""
    msg = Message(
        id="test-123",
        topic="test.topic",
        payload={"key": "value"}
    )

    # Serialize
    json_str = msg.model_dump_json()
    assert "test-123" in json_str
    assert "test.topic" in json_str

    # Deserialize
    msg2 = Message.model_validate_json(json_str)
    assert msg2.id == msg.id
    assert msg2.topic == msg.topic
    assert msg2.payload == msg.payload


def test_message_priority_enum():
    """Test priority enum values are ordered correctly."""
    assert MessagePriority.LOW < MessagePriority.NORMAL
    assert MessagePriority.NORMAL < MessagePriority.HIGH
    assert MessagePriority.HIGH < MessagePriority.URGENT
