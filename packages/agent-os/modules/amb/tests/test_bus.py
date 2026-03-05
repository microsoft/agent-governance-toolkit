# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for MessageBus and InMemoryBroker."""

import asyncio

import pytest

from amb_core import Message, MessageBus, MessagePriority


@pytest.mark.asyncio
async def test_message_bus_connect_disconnect():
    """Test connecting and disconnecting the message bus."""
    bus = MessageBus()

    await bus.connect()
    assert bus._connected is True

    await bus.disconnect()
    assert bus._connected is False


@pytest.mark.asyncio
async def test_message_bus_context_manager():
    """Test message bus as async context manager."""
    async with MessageBus() as bus:
        assert bus._connected is True

    assert bus._connected is False


@pytest.mark.asyncio
async def test_publish_fire_and_forget():
    """Test fire and forget publishing pattern."""
    async with MessageBus() as bus:
        # Publish without waiting
        msg_id = await bus.publish("test.topic", {"message": "hello"}, wait_for_confirmation=False)

        assert msg_id is not None


@pytest.mark.asyncio
async def test_publish_with_confirmation():
    """Test publishing with confirmation."""
    async with MessageBus() as bus:
        # Publish with confirmation
        msg_id = await bus.publish("test.topic", {"message": "hello"}, wait_for_confirmation=True)

        assert msg_id is not None


@pytest.mark.asyncio
async def test_subscribe_and_publish():
    """Test subscribing and receiving messages."""
    async with MessageBus() as bus:
        received_messages = []

        async def handler(msg: Message):
            received_messages.append(msg)

        # Subscribe
        sub_id = await bus.subscribe("test.topic", handler)

        # Publish message
        await bus.publish("test.topic", {"data": "test"})

        # Give time for async processing
        await asyncio.sleep(0.1)

        # Check message was received
        assert len(received_messages) == 1
        assert received_messages[0].payload == {"data": "test"}

        # Unsubscribe
        await bus.unsubscribe(sub_id)


@pytest.mark.asyncio
async def test_multiple_subscribers():
    """Test multiple subscribers on same topic."""
    async with MessageBus() as bus:
        received_1 = []
        received_2 = []

        async def handler1(msg: Message):
            received_1.append(msg)

        async def handler2(msg: Message):
            received_2.append(msg)

        # Subscribe both handlers
        await bus.subscribe("test.topic", handler1)
        await bus.subscribe("test.topic", handler2)

        # Publish message
        await bus.publish("test.topic", {"data": "broadcast"})

        await asyncio.sleep(0.1)

        # Both should receive
        assert len(received_1) == 1
        assert len(received_2) == 1


@pytest.mark.asyncio
async def test_request_response_pattern():
    """Test request-response pattern."""
    async with MessageBus() as bus:
        # Set up responder
        async def responder(msg: Message):
            await bus.reply(msg, {"response": "pong"})

        await bus.subscribe("ping.topic", responder)

        # Give subscription time to set up
        await asyncio.sleep(0.1)

        # Send request
        response = await bus.request("ping.topic", {"request": "ping"}, timeout=5.0)

        assert response.payload == {"response": "pong"}


@pytest.mark.asyncio
async def test_request_timeout():
    """Test request timeout when no response."""
    async with MessageBus() as bus:
        # No responder set up

        with pytest.raises(TimeoutError):
            await bus.request("no.response.topic", {"request": "ping"}, timeout=1.0)


@pytest.mark.asyncio
async def test_message_with_priority():
    """Test publishing with different priorities."""
    async with MessageBus() as bus:
        received = []

        async def handler(msg: Message):
            received.append(msg)

        await bus.subscribe("test.topic", handler)

        # Publish with high priority
        await bus.publish("test.topic", {"urgent": "data"}, priority=MessagePriority.HIGH)

        await asyncio.sleep(0.1)

        assert len(received) == 1
        assert received[0].priority == MessagePriority.HIGH


@pytest.mark.asyncio
async def test_message_with_sender():
    """Test publishing with sender information."""
    async with MessageBus() as bus:
        received = []

        async def handler(msg: Message):
            received.append(msg)

        await bus.subscribe("test.topic", handler)

        # Publish with sender
        await bus.publish("test.topic", {"data": "test"}, sender="agent-123")

        await asyncio.sleep(0.1)

        assert len(received) == 1
        assert received[0].sender == "agent-123"


@pytest.mark.asyncio
async def test_unsubscribe():
    """Test unsubscribing stops receiving messages."""
    async with MessageBus() as bus:
        received = []

        async def handler(msg: Message):
            received.append(msg)

        # Subscribe
        sub_id = await bus.subscribe("test.topic", handler)

        # Publish first message
        await bus.publish("test.topic", {"first": "message"})
        await asyncio.sleep(0.1)

        # Unsubscribe
        await bus.unsubscribe(sub_id)

        # Publish second message
        await bus.publish("test.topic", {"second": "message"})
        await asyncio.sleep(0.1)

        # Should only have received first message
        assert len(received) == 1
        assert received[0].payload == {"first": "message"}
