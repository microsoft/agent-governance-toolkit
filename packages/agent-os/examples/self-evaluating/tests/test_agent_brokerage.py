# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for Agent Brokerage Layer
"""

import unittest
import sys
import os

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agent_brokerage import (
    AgentMarketplace,
    AgentBroker,
    AgentListing,
    AgentPricing,
    PricingModel,
    create_sample_agents
)


class TestAgentPricing(unittest.TestCase):
    """Test agent pricing calculations."""
    
    def test_per_execution_pricing(self):
        """Test per-execution pricing model."""
        pricing = AgentPricing(
            model=PricingModel.PER_EXECUTION,
            base_price=0.01
        )
        cost = pricing.calculate_cost()
        self.assertEqual(cost, 0.01)
    
    def test_per_token_pricing(self):
        """Test per-token pricing model."""
        pricing = AgentPricing(
            model=PricingModel.PER_TOKEN,
            base_price=0.01,
            per_token_price=0.002  # $0.002 per 1000 tokens
        )
        cost = pricing.calculate_cost(tokens=5000)
        self.assertEqual(cost, 0.01 + (5000 / 1000.0) * 0.002)
    
    def test_per_second_pricing(self):
        """Test per-second pricing model."""
        pricing = AgentPricing(
            model=PricingModel.PER_SECOND,
            base_price=0.01,
            per_second_price=0.001  # $0.001 per second
        )
        cost = pricing.calculate_cost(seconds=10.0)
        self.assertEqual(cost, 0.01 + 10.0 * 0.001)


class TestAgentListing(unittest.TestCase):
    """Test agent listing functionality."""
    
    def test_agent_creation(self):
        """Test creating an agent listing."""
        agent = AgentListing(
            agent_id="test_agent",
            name="Test Agent",
            description="A test agent",
            capabilities=["test"],
            pricing=AgentPricing(
                model=PricingModel.PER_EXECUTION,
                base_price=0.01
            ),
            executor=lambda task, metadata: "test response"
        )
        self.assertEqual(agent.agent_id, "test_agent")
        self.assertEqual(agent.name, "Test Agent")
    
    def test_agent_score_calculation(self):
        """Test agent scoring for task selection."""
        agent = AgentListing(
            agent_id="test_agent",
            name="Test Agent",
            description="A test agent",
            capabilities=["test"],
            pricing=AgentPricing(
                model=PricingModel.PER_EXECUTION,
                base_price=0.01
            ),
            executor=lambda task, metadata: "test response",
            avg_latency_ms=1000.0,
            success_rate=0.95
        )
        
        score = agent.calculate_score("test task")
        self.assertGreater(score, 0)
        self.assertLessEqual(score, 1.0)
    
    def test_agent_score_with_constraints(self):
        """Test agent scoring with user constraints."""
        agent = AgentListing(
            agent_id="expensive_agent",
            name="Expensive Agent",
            description="An expensive agent",
            capabilities=["test"],
            pricing=AgentPricing(
                model=PricingModel.PER_EXECUTION,
                base_price=0.50  # Expensive
            ),
            executor=lambda task, metadata: "test response"
        )
        
        # Should be eliminated due to budget constraint
        score = agent.calculate_score("test task", {"max_budget": 0.10})
        self.assertEqual(score, 0.0)


class TestAgentMarketplace(unittest.TestCase):
    """Test agent marketplace functionality."""
    
    def setUp(self):
        """Set up test marketplace."""
        self.marketplace = AgentMarketplace()
        self.agents = create_sample_agents()
        for agent in self.agents:
            self.marketplace.register_agent(agent)
    
    def test_register_agent(self):
        """Test registering an agent."""
        agent = AgentListing(
            agent_id="new_agent",
            name="New Agent",
            description="A new agent",
            capabilities=["test"],
            pricing=AgentPricing(
                model=PricingModel.PER_EXECUTION,
                base_price=0.01
            ),
            executor=lambda task, metadata: "test response"
        )
        self.marketplace.register_agent(agent)
        
        retrieved = self.marketplace.get_agent("new_agent")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.name, "New Agent")
    
    def test_unregister_agent(self):
        """Test unregistering an agent."""
        result = self.marketplace.unregister_agent("pdf_ocr_basic")
        self.assertTrue(result)
        
        retrieved = self.marketplace.get_agent("pdf_ocr_basic")
        self.assertIsNone(retrieved)
    
    def test_discover_agents_by_capability(self):
        """Test discovering agents by capability."""
        agents = self.marketplace.discover_agents(capability_filter="pdf_ocr")
        self.assertGreater(len(agents), 0)
        
        for agent in agents:
            self.assertTrue(any("pdf_ocr" in cap.lower() for cap in agent.capabilities))
    
    def test_discover_agents_by_price(self):
        """Test discovering agents by price."""
        agents = self.marketplace.discover_agents(max_price=0.03)
        self.assertGreater(len(agents), 0)
        
        for agent in agents:
            self.assertLessEqual(agent.pricing.base_price, 0.03)
    
    def test_discover_agents_by_success_rate(self):
        """Test discovering agents by success rate."""
        agents = self.marketplace.discover_agents(min_success_rate=0.95)
        self.assertGreater(len(agents), 0)
        
        for agent in agents:
            self.assertGreaterEqual(agent.success_rate, 0.95)
    
    def test_list_all_agents(self):
        """Test listing all agents."""
        agents = self.marketplace.list_all_agents()
        self.assertEqual(len(agents), len(self.agents))


class TestAgentBroker(unittest.TestCase):
    """Test agent broker functionality."""
    
    def setUp(self):
        """Set up test broker."""
        self.marketplace = AgentMarketplace()
        self.agents = create_sample_agents()
        for agent in self.agents:
            self.marketplace.register_agent(agent)
        self.broker = AgentBroker(self.marketplace)
    
    def test_request_bids(self):
        """Test requesting bids from agents."""
        bids = self.broker.request_bids("Extract text from PDF")
        self.assertGreater(len(bids), 0)
        
        # Bids should be sorted by score (highest first)
        for i in range(len(bids) - 1):
            self.assertGreaterEqual(bids[i].bid_score, bids[i + 1].bid_score)
    
    def test_select_agent_best_value(self):
        """Test selecting agent with best value strategy."""
        bids = self.broker.request_bids("Extract text from PDF")
        selected = self.broker.select_agent(bids, "best_value")
        
        self.assertIsNotNone(selected)
        self.assertEqual(selected, bids[0])  # Should be first (highest score)
    
    def test_select_agent_cheapest(self):
        """Test selecting cheapest agent."""
        bids = self.broker.request_bids("Extract text from PDF")
        selected = self.broker.select_agent(bids, "cheapest")
        
        self.assertIsNotNone(selected)
        # Should be the cheapest bid
        self.assertEqual(selected.estimated_cost, min(b.estimated_cost for b in bids))
    
    def test_select_agent_fastest(self):
        """Test selecting fastest agent."""
        bids = self.broker.request_bids("Extract text from PDF")
        selected = self.broker.select_agent(bids, "fastest")
        
        self.assertIsNotNone(selected)
        # Should be the fastest bid
        self.assertEqual(selected.estimated_latency_ms, 
                        min(b.estimated_latency_ms for b in bids))
    
    def test_execute_task(self):
        """Test executing a task."""
        result = self.broker.execute_task(
            "Extract text from document.pdf",
            verbose=False
        )
        
        self.assertTrue(result["success"])
        self.assertIn("response", result)
        self.assertIn("agent_id", result)
        self.assertIn("actual_cost", result)
        self.assertIn("actual_latency_ms", result)
    
    def test_execute_task_with_constraints(self):
        """Test executing task with user constraints."""
        result = self.broker.execute_task(
            "Extract text from document.pdf",
            user_constraints={"max_budget": 0.02},
            verbose=False
        )
        
        self.assertTrue(result["success"])
        self.assertLessEqual(result["actual_cost"], 0.02)
    
    def test_usage_tracking(self):
        """Test usage and cost tracking."""
        # Execute multiple tasks
        for i in range(5):
            self.broker.execute_task(f"Task {i}", verbose=False)
        
        report = self.broker.get_usage_report()
        
        self.assertEqual(report["total_executions"], 5)
        self.assertGreater(report["total_spent"], 0)
        self.assertGreater(len(report["agent_breakdown"]), 0)
    
    def test_no_agents_available(self):
        """Test handling when no agents are available."""
        empty_marketplace = AgentMarketplace()
        empty_broker = AgentBroker(empty_marketplace)
        
        result = empty_broker.execute_task("Test task", verbose=False)
        
        self.assertFalse(result["success"])
        self.assertIn("error", result)


class TestSampleAgents(unittest.TestCase):
    """Test sample agent creation."""
    
    def test_create_sample_agents(self):
        """Test creating sample agents."""
        agents = create_sample_agents()
        
        self.assertGreater(len(agents), 0)
        
        for agent in agents:
            self.assertIsNotNone(agent.agent_id)
            self.assertIsNotNone(agent.name)
            self.assertIsNotNone(agent.pricing)
            self.assertIsNotNone(agent.executor)


def run_tests():
    """Run all tests."""
    unittest.main(argv=[''], verbosity=2, exit=False)


if __name__ == "__main__":
    run_tests()
