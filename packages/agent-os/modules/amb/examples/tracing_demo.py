# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example demonstrating OpenTelemetry tracing with AMB.

This example shows how to:
1. Initialize OpenTelemetry tracing
2. Create spans that automatically inject trace_id into messages
3. Track messages across multiple agents with the same trace_id
"""

import asyncio

from amb_core import MessageBus, Message, get_tracer, initialize_tracing


async def agent_a(bus: MessageBus, tracer):
    """Agent A - Initial thought generator."""
    print("Agent A: Starting thought process...")
    
    with tracer.start_as_current_span("agent-a-thinking") as span:
        # Use the get_trace_id utility function
        from amb_core import get_trace_id
        trace_id = get_trace_id()
        print(f"Agent A: Trace ID = {trace_id}")
        
        # Publish a thought - trace_id automatically injected
        await bus.publish(
            "agent.thoughts",
            {"thought": "I need to process data X"}
        )
        print("Agent A: Thought published")


async def agent_b(bus: MessageBus):
    """Agent B - Tool executor that responds to thoughts."""
    print("Agent B: Listening for thoughts...")
    
    async def handle_thought(msg: Message):
        print(f"Agent B: Received thought with trace_id={msg.trace_id}")
        print(f"Agent B: Processing: {msg.payload}")
        
        # Execute a tool and publish result
        # trace_id is automatically propagated from the original message
        await bus.publish(
            "agent.tool_results",
            {
                "result": "Data X processed successfully",
                "original_trace_id": msg.trace_id
            },
            trace_id=msg.trace_id  # Explicitly propagate to maintain context
        )
        print("Agent B: Tool result published")
    
    await bus.subscribe("agent.thoughts", handle_thought)


async def agent_c(bus: MessageBus):
    """Agent C - Error handler and logger."""
    print("Agent C: Monitoring for results and errors...")
    
    async def handle_result(msg: Message):
        print(f"Agent C: Logging result with trace_id={msg.trace_id}")
        print(f"Agent C: Result = {msg.payload}")
        
        # Can trace the entire flow: Thought -> Tool Call -> Result
        if msg.trace_id:
            print(f"Agent C: Full trace available via trace_id={msg.trace_id}")
    
    await bus.subscribe("agent.tool_results", handle_result)


async def main():
    """Run the multi-agent tracing example."""
    # Initialize OpenTelemetry tracing
    initialize_tracing("amb-multi-agent-example")
    tracer = get_tracer("example")
    
    print("=" * 60)
    print("AMB OpenTelemetry Tracing Example")
    print("=" * 60)
    print()
    
    async with MessageBus() as bus:
        # Set up agents
        await agent_b(bus)
        await agent_c(bus)
        await asyncio.sleep(0.1)  # Let subscriptions set up
        
        # Agent A starts the flow with a trace
        with tracer.start_as_current_span("multi-agent-workflow"):
            await agent_a(bus, tracer)
        
        # Wait for messages to propagate
        await asyncio.sleep(0.5)
    
    print()
    print("=" * 60)
    print("Example complete!")
    print("All messages shared the same trace_id, enabling full tracing")
    print("across Agent A -> Agent B -> Agent C")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
