# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Unit tests for Circuit Breaker (Loop Detection).
"""

import unittest
from datetime import datetime

from src.kernel.circuit_breaker import (
    CircuitBreaker,
    CircuitBreakerRegistry,
    LoopDetectedError,
    LoopDetectionStrategy,
    ActionResultPair,
)


class TestActionResultPair(unittest.TestCase):
    """Tests for ActionResultPair."""
    
    def test_signature_creation(self):
        """Test that signature is created correctly."""
        pair = ActionResultPair(
            action="query_db",
            action_params={"table": "users", "limit": 10},
            result="No data found"
        )
        
        signature = pair.signature()
        self.assertIsInstance(signature, str)
        self.assertIn("query_db", signature)
        self.assertIn("No data found", signature)
    
    def test_same_signature_for_identical_pairs(self):
        """Test that identical pairs produce same signature."""
        pair1 = ActionResultPair(
            action="search",
            action_params={"query": "test"},
            result="empty"
        )
        
        pair2 = ActionResultPair(
            action="search",
            action_params={"query": "test"},
            result="empty"
        )
        
        self.assertEqual(pair1.signature(), pair2.signature())
    
    def test_different_signature_for_different_params(self):
        """Test that different params produce different signatures."""
        pair1 = ActionResultPair(
            action="search",
            action_params={"query": "test"},
            result="empty"
        )
        
        pair2 = ActionResultPair(
            action="search",
            action_params={"query": "other"},
            result="empty"
        )
        
        self.assertNotEqual(pair1.signature(), pair2.signature())


class TestCircuitBreaker(unittest.TestCase):
    """Tests for CircuitBreaker."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.agent_id = "test-agent-123"
        self.breaker = CircuitBreaker(
            agent_id=self.agent_id,
            repetition_threshold=3,
            history_window=10,
            strategy=LoopDetectionStrategy.SWITCH_STRATEGY  # Don't raise exception in tests
        )
    
    def test_initialization(self):
        """Test circuit breaker initialization."""
        self.assertEqual(self.breaker.agent_id, self.agent_id)
        self.assertEqual(self.breaker.repetition_threshold, 3)
        self.assertEqual(self.breaker.history_window, 10)
        self.assertEqual(len(self.breaker.history), 0)
        self.assertFalse(self.breaker.loop_detected)
    
    def test_single_action_no_loop(self):
        """Test that single action doesn't trigger loop."""
        loop_detected = self.breaker.record_action_result(
            action="search",
            action_params={"query": "test"},
            result="No results found"
        )
        
        self.assertFalse(loop_detected)
        self.assertEqual(len(self.breaker.history), 1)
    
    def test_different_actions_no_loop(self):
        """Test that different actions don't trigger loop."""
        self.breaker.record_action_result(
            action="search",
            action_params={"query": "test"},
            result="No results"
        )
        
        self.breaker.record_action_result(
            action="query_db",
            action_params={"table": "users"},
            result="No data"
        )
        
        self.breaker.record_action_result(
            action="fetch_logs",
            action_params={"date": "2024-01-01"},
            result="Empty"
        )
        
        self.assertFalse(self.breaker.loop_detected)
        self.assertEqual(len(self.breaker.history), 3)
    
    def test_loop_detection_at_threshold(self):
        """Test that loop is detected at exactly threshold repetitions."""
        action = "search"
        params = {"query": "test"}
        result = "No results found"
        
        # Repeat same action 3 times (threshold)
        for i in range(3):
            loop_detected = self.breaker.record_action_result(
                action=action,
                action_params=params,
                result=result
            )
            
            if i < 2:
                self.assertFalse(loop_detected, f"Loop detected too early at iteration {i+1}")
            else:
                self.assertTrue(loop_detected, "Loop not detected at threshold")
        
        self.assertTrue(self.breaker.loop_detected)
        self.assertEqual(self.breaker.loop_count, 1)
    
    def test_loop_detection_with_stop_iteration_strategy(self):
        """Test that LoopDetectedError is raised with STOP_ITERATION strategy."""
        breaker_with_exception = CircuitBreaker(
            agent_id="test-agent",
            repetition_threshold=3,
            strategy=LoopDetectionStrategy.STOP_ITERATION
        )
        
        action = "search"
        params = {"query": "test"}
        result = "No results"
        
        # First two repetitions should not raise
        breaker_with_exception.record_action_result(action, params, result)
        breaker_with_exception.record_action_result(action, params, result)
        
        # Third repetition should raise LoopDetectedError
        with self.assertRaises(LoopDetectedError) as context:
            breaker_with_exception.record_action_result(action, params, result)
        
        error = context.exception
        self.assertEqual(error.agent_id, "test-agent")
        self.assertEqual(error.loop_count, 1)
        self.assertEqual(error.repeated_action, action)
    
    def test_loop_counter_resets_on_different_action(self):
        """Test that consecutive repetitions reset when action changes."""
        # Repeat action twice
        self.breaker.record_action_result("search", {"q": "test"}, "empty")
        self.breaker.record_action_result("search", {"q": "test"}, "empty")
        
        self.assertEqual(self.breaker.consecutive_repetitions, 2)
        
        # Different action - should reset counter
        self.breaker.record_action_result("query", {"table": "users"}, "empty")
        
        self.assertEqual(self.breaker.consecutive_repetitions, 1)
        self.assertFalse(self.breaker.loop_detected)
    
    def test_history_window_limit(self):
        """Test that history respects window limit."""
        breaker = CircuitBreaker(
            agent_id="test",
            repetition_threshold=3,
            history_window=5  # Small window
        )
        
        # Add 10 different actions
        for i in range(10):
            breaker.record_action_result(
                action=f"action_{i}",
                action_params={"id": i},
                result=f"result_{i}"
            )
        
        # History should be limited to 5
        self.assertEqual(len(breaker.history), 5)
    
    def test_reset_clears_state(self):
        """Test that reset clears all state."""
        # Create some history and trigger loop
        for _ in range(3):
            self.breaker.record_action_result("search", {}, "empty")
        
        self.assertTrue(self.breaker.loop_detected)
        self.assertEqual(self.breaker.loop_count, 1)
        
        # Reset
        self.breaker.reset()
        
        self.assertEqual(len(self.breaker.history), 0)
        self.assertFalse(self.breaker.loop_detected)
        self.assertEqual(self.breaker.loop_count, 0)
        self.assertEqual(self.breaker.consecutive_repetitions, 0)
    
    def test_get_state(self):
        """Test get_state returns correct state."""
        self.breaker.record_action_result("search", {"q": "test"}, "empty")
        
        state = self.breaker.get_state()
        
        self.assertEqual(state.agent_id, self.agent_id)
        self.assertEqual(len(state.history), 1)
        self.assertFalse(state.loop_detected)
        self.assertEqual(state.consecutive_repetitions, 1)
    
    def test_get_statistics(self):
        """Test get_statistics returns correct stats."""
        # Create some history
        self.breaker.record_action_result("action1", {}, "result1")
        self.breaker.record_action_result("action1", {}, "result1")
        
        stats = self.breaker.get_statistics()
        
        self.assertEqual(stats["agent_id"], self.agent_id)
        self.assertEqual(stats["history_size"], 2)
        self.assertEqual(stats["repetition_threshold"], 3)
        self.assertEqual(stats["consecutive_repetitions"], 2)
    
    def test_detect_recent_loops(self):
        """Test detect_recent_loops identifies patterns."""
        # Add same action multiple times
        self.breaker.record_action_result("search", {"q": "test"}, "empty")
        self.breaker.record_action_result("search", {"q": "test"}, "empty")
        
        pattern = self.breaker.detect_recent_loops()
        
        self.assertIsNotNone(pattern)
        signature, count = pattern
        self.assertEqual(count, 2)


class TestCircuitBreakerRegistry(unittest.TestCase):
    """Tests for CircuitBreakerRegistry."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.registry = CircuitBreakerRegistry(
            default_repetition_threshold=3,
            default_history_window=10
        )
    
    def test_get_or_create_new_breaker(self):
        """Test creating new circuit breaker for agent."""
        breaker = self.registry.get_or_create("agent-1")
        
        self.assertIsInstance(breaker, CircuitBreaker)
        self.assertEqual(breaker.agent_id, "agent-1")
        self.assertEqual(breaker.repetition_threshold, 3)
    
    def test_get_or_create_returns_existing(self):
        """Test that get_or_create returns existing breaker."""
        breaker1 = self.registry.get_or_create("agent-1")
        breaker1.record_action_result("action", {}, "result")
        
        breaker2 = self.registry.get_or_create("agent-1")
        
        # Should be same instance
        self.assertEqual(len(breaker2.history), 1)
        self.assertIs(breaker1, breaker2)
    
    def test_multiple_agents(self):
        """Test managing multiple agents."""
        breaker1 = self.registry.get_or_create("agent-1")
        breaker2 = self.registry.get_or_create("agent-2")
        
        self.assertIsNot(breaker1, breaker2)
        self.assertEqual(breaker1.agent_id, "agent-1")
        self.assertEqual(breaker2.agent_id, "agent-2")
    
    def test_reset_agent(self):
        """Test resetting specific agent."""
        breaker = self.registry.get_or_create("agent-1")
        breaker.record_action_result("action", {}, "result")
        
        self.assertEqual(len(breaker.history), 1)
        
        self.registry.reset_agent("agent-1")
        
        self.assertEqual(len(breaker.history), 0)
    
    def test_reset_all(self):
        """Test resetting all agents."""
        breaker1 = self.registry.get_or_create("agent-1")
        breaker2 = self.registry.get_or_create("agent-2")
        
        breaker1.record_action_result("action", {}, "result")
        breaker2.record_action_result("action", {}, "result")
        
        self.registry.reset_all()
        
        self.assertEqual(len(breaker1.history), 0)
        self.assertEqual(len(breaker2.history), 0)
    
    def test_get_all_statistics(self):
        """Test getting statistics for all agents."""
        breaker1 = self.registry.get_or_create("agent-1")
        breaker2 = self.registry.get_or_create("agent-2")
        
        breaker1.record_action_result("action", {}, "result")
        breaker2.record_action_result("action", {}, "result")
        breaker2.record_action_result("action", {}, "result")
        
        all_stats = self.registry.get_all_statistics()
        
        self.assertEqual(len(all_stats), 2)
        self.assertIn("agent-1", all_stats)
        self.assertIn("agent-2", all_stats)
        self.assertEqual(all_stats["agent-1"]["history_size"], 1)
        self.assertEqual(all_stats["agent-2"]["history_size"], 2)


class TestLoopDetectionScenarios(unittest.TestCase):
    """Real-world loop detection scenarios."""
    
    def test_search_loop_scenario(self):
        """Test detecting search loop (I'm sorry, I couldn't find...)."""
        breaker = CircuitBreaker(
            agent_id="search-agent",
            repetition_threshold=3,
            strategy=LoopDetectionStrategy.SWITCH_STRATEGY
        )
        
        # Agent keeps searching and failing
        loop_detected = breaker.record_action_result(
            action="search_logs",
            action_params={"query": "error", "partition": "recent"},
            result="I'm sorry, I couldn't find any matching logs."
        )
        self.assertFalse(loop_detected)
        
        loop_detected = breaker.record_action_result(
            action="search_logs",
            action_params={"query": "error", "partition": "recent"},
            result="I'm sorry, I couldn't find any matching logs."
        )
        self.assertFalse(loop_detected)
        
        loop_detected = breaker.record_action_result(
            action="search_logs",
            action_params={"query": "error", "partition": "recent"},
            result="I'm sorry, I couldn't find any matching logs."
        )
        self.assertTrue(loop_detected, "Loop should be detected after 3 repetitions")
    
    def test_query_with_different_params_no_loop(self):
        """Test that same action with different params doesn't trigger loop."""
        breaker = CircuitBreaker(
            agent_id="query-agent",
            repetition_threshold=3
        )
        
        # Same action, different parameters
        breaker.record_action_result("query_db", {"table": "users"}, "No data")
        breaker.record_action_result("query_db", {"table": "orders"}, "No data")
        breaker.record_action_result("query_db", {"table": "products"}, "No data")
        
        self.assertFalse(breaker.loop_detected)
    
    def test_api_retry_loop(self):
        """Test detecting API retry loop."""
        breaker = CircuitBreaker(
            agent_id="api-agent",
            repetition_threshold=3,
            strategy=LoopDetectionStrategy.ESCALATE
        )
        
        # API keeps failing with same error
        for i in range(3):
            loop_detected = breaker.record_action_result(
                action="call_api",
                action_params={"endpoint": "/data", "method": "GET"},
                result="Error: Connection timeout"
            )
            
            if i == 2:
                self.assertTrue(loop_detected)


if __name__ == "__main__":
    unittest.main()
