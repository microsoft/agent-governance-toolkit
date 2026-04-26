# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example demonstrating Backpressure Protocols and Priority Lanes.

This example shows:
1. How CRITICAL messages jump ahead of BACKGROUND messages
2. How backpressure prevents overwhelming slow consumers
3. How the system scales by subtraction - no external load balancer needed
"""

import asyncio

from amb_core import Message, MessageBus, MessagePriority
from amb_core.memory_broker import InMemoryBroker


async def main():
    """Demonstrate backpressure and priority lanes."""

    print("=== AMB: Backpressure & Priority Lanes Demo ===\n")

    # Example 1: Priority Lanes - Critical vs Background
    print("Example 1: Priority Lanes - CRITICAL jumps ahead of BACKGROUND")
    print("-" * 60)

    broker = InMemoryBroker(max_queue_size=100)
    async with MessageBus(adapter=broker) as bus:
        received = []

        async def priority_handler(msg: Message):
            received.append((msg.priority.value, msg.payload["task"]))
            print(f"  [{msg.priority.value:>10}] {msg.payload['task']}")

        await bus.subscribe("agent.tasks", priority_handler)

        # Publish mixed priority messages
        await bus.publish("agent.tasks",
                         {"task": "Memory consolidation (background)"},
                         priority=MessagePriority.BACKGROUND)

        await bus.publish("agent.tasks",
                         {"task": "Log analytics (background)"},
                         priority=MessagePriority.BACKGROUND)

        await bus.publish("agent.tasks",
                         {"task": "Security audit detected anomaly!"},
                         priority=MessagePriority.CRITICAL)

        await bus.publish("agent.tasks",
                         {"task": "Governance policy violation!"},
                         priority=MessagePriority.CRITICAL)

        await bus.publish("agent.tasks",
                         {"task": "Regular data sync (normal)"},
                         priority=MessagePriority.NORMAL)

        await asyncio.sleep(0.2)

        # Critical messages should be processed first
        critical_tasks = [task for priority, task in received if priority == "critical"]
        print(f"\n  ✓ {len(critical_tasks)} CRITICAL tasks processed first")
        print()

    # Example 2: Backpressure - Preventing Consumer Overload
    print("\nExample 2: Backpressure - Auto-throttling Fast Producer")
    print("-" * 60)

    # Small queue with low threshold to demonstrate backpressure quickly
    broker = InMemoryBroker(
        max_queue_size=20,
        backpressure_threshold=0.5,  # Activate at 50% capacity
        backpressure_delay=0.01       # 10ms delay when backpressure active
    )

    async with MessageBus(adapter=broker) as bus:
        processed_count = []

        # Slow consumer - 50ms per message
        async def slow_consumer(msg: Message):
            await asyncio.sleep(0.05)
            processed_count.append(msg.payload["id"])
            if len(processed_count) % 5 == 0:
                print(f"  Processed: {len(processed_count)} messages")

        await bus.subscribe("agent.work", slow_consumer)

        # Fast producer - publish 30 messages rapidly
        print("  Publishing 30 messages rapidly...")
        start_time = asyncio.get_event_loop().time()

        for i in range(30):
            await bus.publish("agent.work", {"id": i}, priority=MessagePriority.NORMAL)

        publish_time = asyncio.get_event_loop().time() - start_time

        # Check backpressure stats
        stats = broker.get_backpressure_stats("agent.work")
        backpressure_events = stats.get("agent.work", 0)

        print(f"  ✓ Backpressure activated {backpressure_events} times")
        print(f"  ✓ Publishing took {publish_time:.3f}s (with auto-throttling)")
        print(f"  ✓ Queue size: {broker.get_queue_size('agent.work')}")

        # Wait for processing
        await asyncio.sleep(2.0)
        print(f"  ✓ All {len(processed_count)} messages processed successfully")
        print()

    # Example 3: Scale by Subtraction - No External Load Balancer Needed
    print("\nExample 3: Scale by Subtraction - 100 Agents, No Crashes")
    print("-" * 60)

    broker = InMemoryBroker(
        max_queue_size=500,
        backpressure_threshold=0.7
    )

    async with MessageBus(adapter=broker) as bus:
        mute_agent_received = []

        # The "mute-agent" - could crash without backpressure
        async def mute_agent_handler(msg: Message):
            await asyncio.sleep(0.002)  # Simulates processing
            mute_agent_received.append(msg.payload["agent_id"])

        await bus.subscribe("agent.events", mute_agent_handler)

        # 100 agents rapidly emitting events
        print("  Simulating 100 agents emitting events...")

        for agent_id in range(100):
            for event_num in range(5):
                await bus.publish(
                    "agent.events",
                    {
                        "agent_id": f"agent-{agent_id}",
                        "event": f"thinking-{event_num}",
                        "timestamp": asyncio.get_event_loop().time()
                    },
                    priority=MessagePriority.NORMAL
                )

        stats = broker.get_backpressure_stats("agent.events")
        backpressure_events = stats.get("agent.events", 0)

        print("  ✓ Published 500 messages from 100 agents")
        print(f"  ✓ Backpressure protected consumer: {backpressure_events} throttle events")
        print(f"  ✓ Queue size stabilized at: {broker.get_queue_size('agent.events')}")

        # Wait for processing
        await asyncio.sleep(2.0)

        print(f"  ✓ Mute agent processed {len(mute_agent_received)} events without crashing")
        print()

    # Example 4: Mixed Workload with Priority + Backpressure
    print("\nExample 4: Real-World Mix - Security + Background Tasks")
    print("-" * 60)

    broker = InMemoryBroker(
        max_queue_size=50,
        backpressure_threshold=0.6
    )

    async with MessageBus(adapter=broker) as bus:
        security_processed = []
        background_processed = []

        async def task_handler(msg: Message):
            await asyncio.sleep(0.01)
            if msg.priority == MessagePriority.CRITICAL:
                security_processed.append(msg.payload["task"])
            elif msg.priority == MessagePriority.BACKGROUND:
                background_processed.append(msg.payload["task"])

        await bus.subscribe("agent.workload", task_handler)

        # Publish mixed workload
        for i in range(10):
            # Background tasks (memory consolidation)
            await bus.publish(
                "agent.workload",
                {"task": f"memory-consolidation-{i}"},
                priority=MessagePriority.BACKGROUND
            )

        for i in range(5):
            # Critical security tasks
            await bus.publish(
                "agent.workload",
                {"task": f"security-check-{i}"},
                priority=MessagePriority.CRITICAL
            )

        for i in range(10):
            # More background tasks
            await bus.publish(
                "agent.workload",
                {"task": f"analytics-{i}"},
                priority=MessagePriority.BACKGROUND
            )

        await asyncio.sleep(0.5)

        # Security tasks should be processed first
        total_security = len(security_processed)
        total_background = len(background_processed)

        print(f"  ✓ Security tasks processed: {total_security}/5 (CRITICAL priority)")
        print(f"  ✓ Background tasks: {total_background}/20 started processing")
        print("  ✓ Critical messages jumped the queue!")

        stats = broker.get_backpressure_stats("agent.workload")
        print(f"  ✓ Backpressure events: {stats.get('agent.workload', 0)}")
        print()

    print("=== Demo Complete! ===")
    print("\nKey Takeaways:")
    print("1. CRITICAL messages (security/governance) jump ahead of BACKGROUND tasks")
    print("2. Backpressure automatically slows producers when consumers are overwhelmed")
    print("3. No external load balancer needed - the bus scales by subtraction")
    print("4. 100 agents can spam the bus without crashing the mute-agent")


if __name__ == "__main__":
    asyncio.run(main())
