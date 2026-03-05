# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for backpressure protocols and priority lanes."""

import asyncio

import pytest

from amb_core import Message, MessageBus, MessagePriority
from amb_core.memory_broker import InMemoryBroker


@pytest.mark.asyncio
async def test_priority_lanes_critical_before_background():
    """Test that CRITICAL messages are processed before BACKGROUND messages."""
    broker = InMemoryBroker()
    bus = MessageBus(adapter=broker)

    async with bus:
        received = []

        async def handler(msg: Message):
            received.append((msg.priority, msg.payload["order"]))

        await bus.subscribe("test.topic", handler)

        # Publish messages in reverse priority order
        await bus.publish("test.topic", {"order": 1}, priority=MessagePriority.BACKGROUND)
        await bus.publish("test.topic", {"order": 2}, priority=MessagePriority.LOW)
        await bus.publish("test.topic", {"order": 3}, priority=MessagePriority.NORMAL)
        await bus.publish("test.topic", {"order": 4}, priority=MessagePriority.HIGH)
        await bus.publish("test.topic", {"order": 5}, priority=MessagePriority.URGENT)
        await bus.publish("test.topic", {"order": 6}, priority=MessagePriority.CRITICAL)

        await asyncio.sleep(0.1)

        # Verify CRITICAL was processed first (order: 6)
        assert len(received) == 6

        # CRITICAL should be first
        assert received[0][0] == MessagePriority.CRITICAL
        assert received[0][1] == 6

        # BACKGROUND should be last
        assert received[-1][0] == MessagePriority.BACKGROUND
        assert received[-1][1] == 1


@pytest.mark.asyncio
async def test_priority_lanes_pending_messages():
    """Test that get_pending_messages returns messages in priority order."""
    # Disable priority delivery so messages stay in queue
    broker = InMemoryBroker(use_priority_delivery=False)
    bus = MessageBus(adapter=broker)

    async with bus:
        # Publish messages without subscribers (they'll stay in queue)
        await bus.publish("test.topic", {"data": "background"}, priority=MessagePriority.BACKGROUND)
        await bus.publish("test.topic", {"data": "normal"}, priority=MessagePriority.NORMAL)
        await bus.publish("test.topic", {"data": "critical"}, priority=MessagePriority.CRITICAL)
        await bus.publish("test.topic", {"data": "low"}, priority=MessagePriority.LOW)

        await asyncio.sleep(0.05)

        # Get pending messages
        pending = await broker.get_pending_messages("test.topic", limit=10)

        # Should be in priority order: CRITICAL, NORMAL, LOW, BACKGROUND
        assert len(pending) == 4
        assert pending[0].priority == MessagePriority.CRITICAL
        assert pending[1].priority == MessagePriority.NORMAL
        assert pending[2].priority == MessagePriority.LOW
        assert pending[3].priority == MessagePriority.BACKGROUND


@pytest.mark.asyncio
async def test_backpressure_triggered_on_high_load():
    """Test that backpressure is triggered when queue reaches threshold."""
    # Create broker with small queue and low threshold
    broker = InMemoryBroker(max_queue_size=10, backpressure_threshold=0.5, backpressure_delay=0.01)
    bus = MessageBus(adapter=broker)

    async with bus:
        # Don't add subscribers - messages will pile up in queue

        # Publish messages until we hit backpressure threshold (5 out of 10)
        start_time = asyncio.get_event_loop().time()

        for i in range(7):
            await bus.publish("test.topic", {"msg": i}, priority=MessagePriority.NORMAL)

        end_time = asyncio.get_event_loop().time()

        # Check that backpressure was applied
        stats = broker.get_backpressure_stats("test.topic")
        assert stats["test.topic"] > 0, "Backpressure should have been triggered"

        # Verify delay was applied (at least 2 backpressure events with 0.01s delay each)
        elapsed = end_time - start_time
        min_expected_delay = stats["test.topic"] * 0.01
        assert elapsed >= min_expected_delay * 0.5  # Allow some tolerance


@pytest.mark.asyncio
async def test_backpressure_drops_background_when_full():
    """Test that BACKGROUND messages are dropped when queue is full."""
    # Create broker with very small queue, disable priority delivery for queue inspection
    broker = InMemoryBroker(max_queue_size=5, backpressure_threshold=0.8, use_priority_delivery=False)
    bus = MessageBus(adapter=broker)

    async with bus:
        # Fill queue with BACKGROUND messages
        for i in range(5):
            await bus.publish("test.topic", {"msg": i}, priority=MessagePriority.BACKGROUND)

        # Queue should be full
        assert broker.get_queue_size("test.topic") == 5

        # Try to add a CRITICAL message - should drop a BACKGROUND message
        await bus.publish("test.topic", {"critical": True}, priority=MessagePriority.CRITICAL)

        # Queue should still be at max capacity
        assert broker.get_queue_size("test.topic") == 5

        # Get messages and verify CRITICAL is in there
        pending = await broker.get_pending_messages("test.topic", limit=10)
        priorities = [msg.priority for msg in pending]
        assert MessagePriority.CRITICAL in priorities


@pytest.mark.asyncio
async def test_backpressure_raises_when_no_background_to_drop():
    """Test that publish raises error when queue is full and no BACKGROUND messages to drop."""
    # Create broker with very small queue, disable priority delivery
    broker = InMemoryBroker(max_queue_size=3, backpressure_threshold=0.9, use_priority_delivery=False)
    bus = MessageBus(adapter=broker)

    async with bus:
        # Fill queue with HIGH priority messages
        for i in range(3):
            await bus.publish("test.topic", {"msg": i}, priority=MessagePriority.HIGH)

        # Try to add another HIGH priority message - should raise error
        with pytest.raises(RuntimeError, match="Queue.*is full"):
            await bus.publish("test.topic", {"msg": "overflow"}, priority=MessagePriority.HIGH)


@pytest.mark.asyncio
async def test_backpressure_with_slow_consumer():
    """Test that backpressure prevents overwhelming a slow consumer."""
    broker = InMemoryBroker(max_queue_size=50, backpressure_threshold=0.6, backpressure_delay=0.005)
    bus = MessageBus(adapter=broker)

    async with bus:
        processed = []

        # Slow consumer - takes 10ms per message
        async def slow_handler(msg: Message):
            await asyncio.sleep(0.01)
            processed.append(msg.payload["id"])

        await bus.subscribe("test.topic", slow_handler)

        # Rapidly publish many messages
        for i in range(40):
            await bus.publish("test.topic", {"id": i}, priority=MessagePriority.NORMAL)

        # Backpressure should have been triggered
        stats = broker.get_backpressure_stats("test.topic")
        assert stats.get("test.topic", 0) > 0, "Backpressure should activate with slow consumer"

        # Wait for processing to complete
        await asyncio.sleep(0.5)

        # All messages should eventually be processed
        assert len(processed) == 40


@pytest.mark.asyncio
async def test_priority_with_mixed_workload():
    """Test priority lanes with mixed CRITICAL and BACKGROUND workload."""
    broker = InMemoryBroker(max_queue_size=100)
    bus = MessageBus(adapter=broker)

    async with bus:
        received = []

        async def handler(msg: Message):
            received.append((msg.priority, msg.payload["type"], msg.payload["id"]))

        await bus.subscribe("test.topic", handler)

        # Publish mixed workload
        for i in range(5):
            await bus.publish("test.topic", {"type": "background", "id": i}, priority=MessagePriority.BACKGROUND)

        for i in range(3):
            await bus.publish("test.topic", {"type": "critical", "id": i}, priority=MessagePriority.CRITICAL)

        for i in range(5):
            await bus.publish("test.topic", {"type": "background", "id": i+5}, priority=MessagePriority.BACKGROUND)

        await asyncio.sleep(0.2)

        # All 13 messages should be received
        assert len(received) == 13

        # Critical messages should be processed first
        critical_messages = [r for r in received if r[1] == "critical"]
        assert len(critical_messages) == 3

        # The first 3 messages processed should be critical (or at least appear early)
        first_three = received[:3]
        critical_count_in_first_three = sum(1 for r in first_three if r[1] == "critical")
        assert critical_count_in_first_three >= 2, "Most critical messages should be processed early"


@pytest.mark.asyncio
async def test_get_queue_size():
    """Test queue size monitoring."""
    # Disable priority delivery so messages stay in queue
    broker = InMemoryBroker(max_queue_size=100, use_priority_delivery=False)
    bus = MessageBus(adapter=broker)

    async with bus:
        # Initially empty
        assert broker.get_queue_size("test.topic") == 0

        # Add messages
        await bus.publish("test.topic", {"data": "msg1"})
        await bus.publish("test.topic", {"data": "msg2"})
        await bus.publish("test.topic", {"data": "msg3"})

        await asyncio.sleep(0.05)

        # Should have 3 messages
        assert broker.get_queue_size("test.topic") == 3


@pytest.mark.asyncio
async def test_backpressure_stats():
    """Test backpressure statistics tracking."""
    broker = InMemoryBroker(max_queue_size=10, backpressure_threshold=0.5)
    bus = MessageBus(adapter=broker)

    async with bus:
        # Initially no backpressure
        stats = broker.get_backpressure_stats()
        assert len(stats) == 0 or stats.get("test.topic", 0) == 0

        # Publish enough to trigger backpressure
        for i in range(8):
            await bus.publish("test.topic", {"id": i})

        # Check stats
        stats = broker.get_backpressure_stats("test.topic")
        assert "test.topic" in stats
        assert stats["test.topic"] > 0


@pytest.mark.asyncio
async def test_priority_order_same_priority():
    """Test that messages with same priority maintain FIFO order."""
    broker = InMemoryBroker()
    bus = MessageBus(adapter=broker)

    async with bus:
        received = []

        async def handler(msg: Message):
            received.append(msg.payload["id"])

        await bus.subscribe("test.topic", handler)

        # Publish multiple messages with same priority
        for i in range(10):
            await bus.publish("test.topic", {"id": i}, priority=MessagePriority.NORMAL)

        await asyncio.sleep(0.1)

        # Should maintain order
        assert received == list(range(10))
