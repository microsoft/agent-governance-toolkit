# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example demonstrating AMB v0.2.0 new features.

This example shows:
1. Message persistence and replay
2. Dead Letter Queue for failed messages
3. Schema validation with Pydantic
4. Distributed tracing
5. Message prioritization
6. Message TTL/expiration
"""

import asyncio
from uuid import uuid4
from pydantic import BaseModel

from amb_core import (
    MessageBus,
    Message,
    Priority,
    SchemaRegistry,
    DeadLetterQueue,
    DLQReason,
    TraceContext,
)


# Define a schema for fraud alerts
class FraudAlertPayload(BaseModel):
    """Schema for fraud alert messages."""
    transaction_id: str
    amount: float
    risk_score: float
    account_id: str


async def main():
    """Demonstrate AMB v0.2.0 features."""
    
    print("=" * 60)
    print("AMB v0.2.0 - New Features Demo")
    print("=" * 60)
    print()
    
    # Set up schema registry (AMB-003: Schema Validation)
    schemas = SchemaRegistry(strict=False)
    schemas.register("fraud.alerts", FraudAlertPayload)
    schemas.register("user.events", {"user_id": str, "event_type": str})
    
    print("✓ Schema registry configured")
    print(f"  Registered topics: {schemas.list_topics()}")
    print()
    
    # Create message bus with all features enabled
    bus = MessageBus(
        persistence=True,              # AMB-001: Message Persistence
        schema_registry=schemas,       # AMB-003: Schema Validation
        dlq_enabled=True               # AMB-002: Dead Letter Queue
    )
    
    async with bus:
        print("✓ MessageBus connected with persistence, schema validation, and DLQ")
        print()
        
        # --------------------------------------------------------
        # Example 1: Publishing with priority and TTL (AMB-005, AMB-007)
        # --------------------------------------------------------
        print("=" * 40)
        print("Example 1: Priority and TTL")
        print("=" * 40)
        
        received_alerts = []
        
        async def fraud_handler(msg: Message):
            print(f"  🚨 Received fraud alert (priority={msg.priority.name}):")
            print(f"     Transaction: {msg.payload['transaction_id']}")
            print(f"     Risk score: {msg.payload['risk_score']}")
            print(f"     Remaining TTL: {msg.remaining_ttl:.1f}s")
            received_alerts.append(msg)
        
        await bus.subscribe("fraud.alerts", fraud_handler)
        
        # Publish a high-priority fraud alert with TTL
        await bus.publish(
            "fraud.alerts",
            {
                "transaction_id": "tx-" + str(uuid4())[:8],
                "amount": 15000.0,
                "risk_score": 0.95,
                "account_id": "acc-12345"
            },
            priority=Priority.CRITICAL,  # High priority
            ttl_seconds=300              # 5 minute TTL
        )
        
        await asyncio.sleep(0.1)
        print()
        
        # --------------------------------------------------------
        # Example 2: Distributed Tracing (AMB-004)
        # --------------------------------------------------------
        print("=" * 40)
        print("Example 2: Distributed Tracing")
        print("=" * 40)
        
        received_events = []
        
        async def event_handler(msg: Message):
            print(f"  📧 Received event with trace_id: {msg.trace_id[:8]}...")
            received_events.append(msg)
        
        await bus.subscribe("user.events", event_handler)
        
        # Start a trace context
        with TraceContext.start("process_user_action") as ctx:
            print(f"  Starting trace: {ctx.trace_id[:8]}...")
            
            # Messages published within this context get the trace ID
            await bus.publish(
                "user.events",
                {"user_id": "user-123", "event_type": "login"}
            )
            
            # Create a child span
            span = ctx.start_span("validate_session")
            ctx.log("Validating user session")
            ctx.finish_span()
            
            await bus.publish(
                "user.events",
                {"user_id": "user-123", "event_type": "session_validated"}
            )
        
        await asyncio.sleep(0.1)
        
        # All events should have the same trace ID
        assert all(e.trace_id == ctx.trace_id for e in received_events)
        print(f"  ✓ All {len(received_events)} events have same trace ID")
        print()
        
        # --------------------------------------------------------
        # Example 3: Dead Letter Queue (AMB-002)
        # --------------------------------------------------------
        print("=" * 40)
        print("Example 3: Dead Letter Queue")
        print("=" * 40)
        
        async def failing_handler(msg: Message):
            raise ValueError("Simulated processing error!")
        
        await bus.subscribe("unreliable.topic", failing_handler)
        
        # Publish a message that will fail processing
        await bus.publish(
            "unreliable.topic",
            {"data": "this will fail"}
        )
        
        await asyncio.sleep(0.2)
        
        # Check DLQ stats
        dlq_stats = await bus.get_dlq_stats()
        print(f"  DLQ Statistics:")
        print(f"    Total entries: {dlq_stats['total_entries']}")
        print(f"    By reason: {dlq_stats['by_reason']}")
        print()
        
        # --------------------------------------------------------
        # Example 4: Message Persistence and Replay (AMB-001)
        # --------------------------------------------------------
        print("=" * 40)
        print("Example 4: Persistence and Replay")
        print("=" * 40)
        
        # Publish some audit events
        for i in range(3):
            await bus.publish(
                "audit.events",
                {"event_num": i, "action": "test_action"}
            )
        
        # Get persistence stats
        persist_stats = await bus.get_persistence_stats()
        print(f"  Persistence Statistics:")
        print(f"    Total messages: {persist_stats['total_messages']}")
        print(f"    Topics: {persist_stats.get('topics', 'N/A')}")
        
        # Replay messages
        replayed = []
        
        async def replay_handler(msg: Message):
            replayed.append(msg)
        
        count = await bus.replay("audit.events", replay_handler)
        print(f"  Replayed {count} messages from audit.events")
        print()
        
        # --------------------------------------------------------
        # Example 5: Schema Validation Error (AMB-003)
        # --------------------------------------------------------
        print("=" * 40)
        print("Example 5: Schema Validation")
        print("=" * 40)
        
        # This should fail validation
        try:
            await bus.publish(
                "fraud.alerts",
                {"invalid": "payload"}  # Missing required fields
            )
        except Exception as e:
            print(f"  ✓ Validation error caught: {type(e).__name__}")
            print(f"    Topic: fraud.alerts")
            print(f"    Expected fields: transaction_id, amount, risk_score, account_id")
        
        print()
        print("=" * 60)
        print("Demo complete!")
        print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
