# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for distributed tracing integration."""

import asyncio

import pytest

from amb_core import Message, MessageBus, TraceContext, get_current_trace


@pytest.mark.asyncio
async def test_trace_id_in_message_model():
    """Test that Message model accepts trace_id."""
    msg = Message(
        id="test-123",
        topic="test.topic",
        payload={"key": "value"},
        trace_id="0123456789abcdef0123456789abcdef",
    )

    assert msg.trace_id == "0123456789abcdef0123456789abcdef"


@pytest.mark.asyncio
async def test_message_without_trace_id():
    """Test that Message works without trace_id (backward compatibility)."""
    msg = Message(id="test-123", topic="test.topic", payload={"key": "value"})

    assert msg.trace_id is None


@pytest.mark.asyncio
async def test_publish_injects_trace_id_from_active_context():
    """Test that publish injects trace_id from active trace context."""
    async with MessageBus() as bus:
        received_messages = []

        async def handler(msg: Message):
            received_messages.append(msg)

        await bus.subscribe("test.topic", handler)

        # Create a trace context and publish message within it
        with TraceContext.start("test-operation") as ctx:
            trace_id_from_context = ctx.trace_id
            await bus.publish("test.topic", {"data": "test"})

        await asyncio.sleep(0.1)

        # Check that message received has the trace_id
        assert len(received_messages) == 1
        assert received_messages[0].trace_id == trace_id_from_context


@pytest.mark.asyncio
async def test_publish_with_explicit_trace_id():
    """Test that explicit trace_id is used when provided."""
    custom_trace_id = "1234567890abcdef1234567890abcdef"

    async with MessageBus() as bus:
        received_messages = []

        async def handler(msg: Message):
            received_messages.append(msg)

        await bus.subscribe("test.topic", handler)

        # Publish with explicit trace_id
        await bus.publish("test.topic", {"data": "test"}, trace_id=custom_trace_id)

        await asyncio.sleep(0.1)

        # Check that message has the custom trace_id
        assert len(received_messages) == 1
        assert received_messages[0].trace_id == custom_trace_id


@pytest.mark.asyncio
async def test_request_injects_trace_id():
    """Test that request-response pattern includes trace_id."""
    custom_trace_id = "abcdef1234567890abcdef1234567890"

    async with MessageBus() as bus:
        received_requests = []

        async def responder(msg: Message):
            received_requests.append(msg)
            await bus.reply(msg, {"response": "pong"})

        await bus.subscribe("ping.topic", responder)
        await asyncio.sleep(0.1)

        # Send request with trace_id
        response = await bus.request(
            "ping.topic", {"request": "ping"}, timeout=5.0, trace_id=custom_trace_id
        )

        # Check request had trace_id
        assert len(received_requests) == 1
        assert received_requests[0].trace_id == custom_trace_id

        # Check response was received
        assert response.payload == {"response": "pong"}


@pytest.mark.asyncio
async def test_reply_propagates_trace_id():
    """Test that reply propagates trace_id from original message."""
    custom_trace_id = "fedcba0987654321fedcba0987654321"

    async with MessageBus() as bus:
        async def responder(msg: Message):
            await bus.reply(msg, {"response": "pong"})

        await bus.subscribe("ping.topic", responder)
        await asyncio.sleep(0.1)

        # Send request and get response
        response = await bus.request(
            "ping.topic", {"request": "ping"}, timeout=5.0, trace_id=custom_trace_id
        )

        # Response should have the same trace_id
        assert response.trace_id == custom_trace_id


@pytest.mark.asyncio
async def test_get_current_trace_returns_none_outside_context():
    """Test that get_current_trace returns None when no trace is active."""
    trace = get_current_trace()
    assert trace is None


@pytest.mark.asyncio
async def test_get_current_trace_returns_context_inside_trace():
    """Test that get_current_trace returns active context."""
    with TraceContext.start("test-operation") as ctx:
        current = get_current_trace()
        assert current is ctx
        assert current.trace_id == ctx.trace_id


@pytest.mark.asyncio
async def test_trace_context_new_creates_valid_context():
    """Test TraceContext.new creates valid trace context."""
    ctx = TraceContext.new("test-operation")
    
    assert ctx.trace_id is not None
    assert ctx.span_id is not None
    assert len(ctx.spans) == 1  # Root span


@pytest.mark.asyncio
async def test_trace_context_start_span():
    """Test creating child spans."""
    ctx = TraceContext.new("root-operation")
    
    span = ctx.start_span("child-operation")
    
    assert span.parent_span_id == ctx.span_id
    assert span.trace_id == ctx.trace_id
    assert len(ctx.spans) == 2


@pytest.mark.asyncio
async def test_trace_context_to_headers():
    """Test converting trace context to headers for propagation."""
    ctx = TraceContext.new("test-operation")
    
    headers = ctx.to_headers()
    
    assert "x-trace-id" in headers
    assert headers["x-trace-id"] == ctx.trace_id
    assert "x-span-id" in headers


@pytest.mark.asyncio
async def test_trace_context_from_headers():
    """Test creating trace context from headers."""
    original = TraceContext.new("original-operation")
    headers = original.to_headers()
    
    # Create new context from headers (simulating receiving in another service)
    continued = TraceContext.from_headers(headers)
    
    assert continued.trace_id == original.trace_id
    # New context gets a new span_id
    assert continued.span_id != original.span_id
    # Parent span should be the original span
    assert continued.parent_span_id == original.span_id


@pytest.mark.asyncio
async def test_trace_context_to_message_metadata():
    """Test converting trace context to message metadata."""
    ctx = TraceContext.new("test-operation")
    
    metadata = ctx.to_message_metadata()
    
    assert metadata["trace_id"] == ctx.trace_id
    assert metadata["span_id"] == ctx.span_id


@pytest.mark.asyncio
async def test_trace_context_baggage():
    """Test baggage propagation in trace context."""
    ctx = TraceContext.new("test-operation")
    
    ctx.set_baggage("user_id", "user-123")
    ctx.set_baggage("tenant_id", "tenant-abc")
    
    assert ctx.get_baggage("user_id") == "user-123"
    assert ctx.get_baggage("tenant_id") == "tenant-abc"
    assert ctx.get_baggage("missing") is None


@pytest.mark.asyncio
async def test_trace_span_logging():
    """Test span logging functionality."""
    ctx = TraceContext.new("test-operation")
    
    ctx.log("Processing started", item_count=10)
    ctx.log("Processing complete")
    
    # Find the root span
    root_span = ctx.spans[0]
    assert len(root_span.logs) == 2
    assert root_span.logs[0]["event"] == "Processing started"
    assert root_span.logs[0]["item_count"] == 10


@pytest.mark.asyncio
async def test_trace_span_tagging():
    """Test span tagging functionality."""
    ctx = TraceContext.new("test-operation")
    
    ctx.set_tag("component", "message-bus")
    ctx.set_tag("topic", "test.topic")
    
    root_span = ctx.spans[0]
    assert root_span.tags["component"] == "message-bus"
    assert root_span.tags["topic"] == "test.topic"


@pytest.mark.asyncio
async def test_trace_context_error_handling():
    """Test trace context handles errors gracefully."""
    try:
        with TraceContext.start("test-operation") as ctx:
            raise ValueError("Test error")
    except ValueError:
        pass
    
    # After context exit, current trace should be None
    assert get_current_trace() is None
