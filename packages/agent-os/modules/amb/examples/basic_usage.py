# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example demonstrating AMB usage patterns.

This example shows:
1. Fire and forget messaging
2. Request-response pattern
3. Agent signal emissions
"""

import asyncio

from amb_core import Message, MessageBus


async def main():
    """Demonstrate AMB usage."""

    # Create message bus (uses in-memory broker by default)
    async with MessageBus() as bus:
        print("=== AMB Example: Agent Nervous System ===\n")

        # Example 1: Simple pub/sub with agent thoughts
        print("Example 1: Agent emitting thoughts...")

        received_thoughts = []

        async def thought_listener(msg: Message):
            print(f"  🧠 Thought received: {msg.payload['thought']}")
            received_thoughts.append(msg.payload['thought'])

        await bus.subscribe("agent.thoughts", thought_listener)

        # Agent emits thoughts
        await bus.publish("agent.thoughts", {
            "agent_id": "agent-1",
            "thought": "I am analyzing the user request..."
        })

        await bus.publish("agent.thoughts", {
            "agent_id": "agent-1",
            "thought": "I need to gather more context..."
        })

        await asyncio.sleep(0.2)  # Wait for async processing
        print()

        # Example 2: Agent requesting verification
        print("Example 2: Agent requesting verification...")

        async def verification_handler(msg: Message):
            print(f"  ✓ Verification request: {msg.payload}")
            # Simulate approval
            await bus.reply(msg, {
                "approved": True,
                "reviewer": "human-supervisor"
            })

        await bus.subscribe("agent.verification", verification_handler)

        # Agent requests verification for critical action
        response = await bus.request(
            "agent.verification",
            {
                "agent_id": "agent-1",
                "action": "delete_database",
                "requires_approval": True
            },
            timeout=5.0
        )

        print(f"  📥 Verification response: {response.payload}")
        print()

        # Example 3: Agent emitting a "stuck" signal
        print("Example 3: Agent emitting stuck signal...")

        async def stuck_listener(msg: Message):
            print(f"  ⚠️  Agent stuck: {msg.payload['reason']}")
            print(f"     Needs: {msg.payload['needs']}")

        await bus.subscribe("agent.stuck", stuck_listener)

        await bus.publish("agent.stuck", {
            "agent_id": "agent-1",
            "reason": "Insufficient context to proceed",
            "needs": "user_clarification",
            "question": "Which database should I connect to?"
        })

        await asyncio.sleep(0.2)
        print()

        # Example 4: Fire and forget vs acknowledgment
        print("Example 4: Fire and forget vs acknowledgment...")

        # Fast - fire and forget (default)
        msg_id = await bus.publish(
            "agent.actions",
            {"action": "log_event", "priority": "low"},
            wait_for_confirmation=False
        )
        print(f"  🚀 Fire and forget: {msg_id}")

        # Slower - wait for acknowledgment
        msg_id = await bus.publish(
            "agent.critical",
            {"action": "save_checkpoint", "priority": "high"},
            wait_for_confirmation=True
        )
        print(f"  ✓  With acknowledgment: {msg_id}")
        print()

        print("=== All examples completed! ===")


if __name__ == "__main__":
    asyncio.run(main())
