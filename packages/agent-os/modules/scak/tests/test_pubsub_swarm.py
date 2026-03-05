# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for pub-sub messaging and swarm coordination.
"""

import pytest
import asyncio
from src.agents.pubsub import (
    InMemoryPubSub,
    PubSubMessage,
    MessagePriority,
    AgentSwarm
)


class TestInMemoryPubSub:
    """Test in-memory pub-sub backend."""
    
    @pytest.fixture
    def pubsub(self):
        """Create pub-sub instance."""
        return InMemoryPubSub()
    
    @pytest.mark.asyncio
    async def test_publish_subscribe(self, pubsub):
        """Test basic publish-subscribe pattern."""
        messages_received = []
        
        async def handler(msg: PubSubMessage):
            messages_received.append(msg)
        
        # Subscribe
        await pubsub.subscribe("test-topic", handler)
        
        # Publish
        msg = PubSubMessage(
            topic="test-topic",
            from_agent="agent-001",
            payload={"message": "Hello"}
        )
        await pubsub.publish("test-topic", msg)
        
        # Wait for delivery
        await asyncio.sleep(0.1)
        
        assert len(messages_received) == 1
        assert messages_received[0].from_agent == "agent-001"
        assert messages_received[0].payload["message"] == "Hello"
    
    @pytest.mark.asyncio
    async def test_multiple_subscribers(self, pubsub):
        """Test multiple subscribers on same topic."""
        received_1 = []
        received_2 = []
        
        async def handler_1(msg):
            received_1.append(msg)
        
        async def handler_2(msg):
            received_2.append(msg)
        
        # Subscribe both
        await pubsub.subscribe("topic", handler_1)
        await pubsub.subscribe("topic", handler_2)
        
        # Publish message
        msg = PubSubMessage(
            topic="topic",
            from_agent="sender",
            payload={"data": "test"}
        )
        await pubsub.publish("topic", msg)
        
        await asyncio.sleep(0.1)
        
        # Both should receive
        assert len(received_1) == 1
        assert len(received_2) == 1
    
    @pytest.mark.asyncio
    async def test_message_history(self, pubsub):
        """Test message history tracking."""
        # Publish messages
        for i in range(5):
            msg = PubSubMessage(
                topic="history-test",
                from_agent=f"agent-{i}",
                payload={"index": i}
            )
            await pubsub.publish("history-test", msg)
        
        # Get history
        history = pubsub.get_message_history("history-test")
        
        assert len(history) == 5
        assert history[0].from_agent == "agent-0"
        assert history[4].from_agent == "agent-4"
    
    @pytest.mark.asyncio
    async def test_dead_letter_queue(self, pubsub):
        """Test dead letter queue for failed deliveries."""
        async def failing_handler(msg):
            raise RuntimeError("Handler failed")
        
        await pubsub.subscribe("fail-topic", failing_handler)
        
        msg = PubSubMessage(
            topic="fail-topic",
            from_agent="sender",
            payload={}
        )
        await pubsub.publish("fail-topic", msg)
        
        await asyncio.sleep(0.1)
        
        # Check dead letter queue
        dlq = pubsub.get_dead_letter_queue()
        assert len(dlq) == 1
        assert dlq[0][0].topic == "fail-topic"


class TestAgentSwarm:
    """Test agent swarm coordination."""
    
    @pytest.fixture
    def swarm(self):
        """Create swarm instance."""
        pubsub = InMemoryPubSub()
        return AgentSwarm(
            "test-swarm",
            pubsub,
            ["agent-1", "agent-2", "agent-3"]
        )
    
    @pytest.mark.asyncio
    async def test_broadcast(self, swarm):
        """Test swarm broadcast."""
        # Broadcast message
        await swarm.broadcast(
            "agent-1",
            "Test message",
            {"data": "value"}
        )
        
        # Check message was published
        history = swarm.pubsub.get_message_history(swarm.swarm_topic)
        assert len(history) == 1
        assert history[0].from_agent == "agent-1"
        assert history[0].payload["message"] == "Test message"
    
    @pytest.mark.asyncio
    async def test_consensus_vote(self, swarm):
        """Test consensus voting."""
        result = await swarm.request_consensus(
            "agent-1",
            "Should we proceed?",
            {"confidence": 0.9},
            required_votes=2
        )
        
        assert "consensus_reached" in result
        assert "votes_for" in result
        assert "proposal" in result
        assert result["proposal"] == "Should we proceed?"
    
    @pytest.mark.asyncio
    async def test_work_distribution(self, swarm):
        """Test work distribution across swarm."""
        tasks = [
            {"task": "analyze", "id": i}
            for i in range(10)
        ]
        
        assignments = await swarm.distribute_work(
            "supervisor",
            tasks,
            strategy="round_robin"
        )
        
        # Should distribute across 3 agents
        assert len(assignments) == 3
        
        # Each agent should have some tasks
        total_assigned = sum(len(tasks) for tasks in assignments.values())
        assert total_assigned == 10
    
    @pytest.mark.asyncio
    async def test_add_remove_agent(self, swarm):
        """Test adding and removing agents from swarm."""
        initial_count = len(swarm.agent_ids)
        
        # Add agent
        swarm.add_agent("agent-4")
        assert len(swarm.agent_ids) == initial_count + 1
        assert "agent-4" in swarm.agent_ids
        
        # Remove agent
        swarm.remove_agent("agent-4")
        assert len(swarm.agent_ids) == initial_count
        assert "agent-4" not in swarm.agent_ids


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
