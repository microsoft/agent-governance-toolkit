# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Unit tests for Lazy Evaluator (Deferred Computation).
"""

import unittest
from datetime import datetime

from src.kernel.lazy_evaluator import (
    LazyEvaluator,
    LazyEvaluatorRegistry,
    TODOToken,
    DeferralReason,
    LazyEvaluationDecision,
)


class TestTODOToken(unittest.TestCase):
    """Tests for TODOToken."""
    
    def test_token_creation(self):
        """Test creating a TODO token."""
        token = TODOToken(
            description="Fetch historical logs",
            reason=DeferralReason.TOO_EXPENSIVE,
            priority=5,
            context={"time_range": "2023"},
            estimated_cost_ms=5000
        )
        
        self.assertIsNotNone(token.token_id)
        self.assertTrue(token.token_id.startswith("todo-"))
        self.assertEqual(token.description, "Fetch historical logs")
        self.assertEqual(token.reason, DeferralReason.TOO_EXPENSIVE)
        self.assertEqual(token.priority, 5)
        self.assertFalse(token.resolved)
        self.assertIsNone(token.result)
    
    def test_token_id_uniqueness(self):
        """Test that token IDs are unique."""
        token1 = TODOToken(description="Task 1", reason=DeferralReason.NOT_NEEDED_NOW)
        token2 = TODOToken(description="Task 2", reason=DeferralReason.NOT_NEEDED_NOW)
        
        self.assertNotEqual(token1.token_id, token2.token_id)


class TestLazyEvaluationDecision(unittest.TestCase):
    """Tests for LazyEvaluationDecision."""
    
    def test_decision_creation(self):
        """Test creating a deferral decision."""
        decision = LazyEvaluationDecision(
            should_defer=True,
            reason=DeferralReason.TOO_EXPENSIVE,
            estimated_savings_ms=3000,
            confidence=0.9,
            explanation="Operation too expensive"
        )
        
        self.assertTrue(decision.should_defer)
        self.assertEqual(decision.reason, DeferralReason.TOO_EXPENSIVE)
        self.assertEqual(decision.estimated_savings_ms, 3000)
        self.assertEqual(decision.confidence, 0.9)


class TestLazyEvaluator(unittest.TestCase):
    """Tests for LazyEvaluator."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.agent_id = "test-agent-123"
        self.evaluator = LazyEvaluator(
            agent_id=self.agent_id,
            enable_lazy_eval=True,
            max_deferred_tasks=100
        )
    
    def test_initialization(self):
        """Test lazy evaluator initialization."""
        self.assertEqual(self.evaluator.agent_id, self.agent_id)
        self.assertTrue(self.evaluator.enable_lazy_eval)
        self.assertEqual(self.evaluator.max_deferred_tasks, 100)
        self.assertEqual(len(self.evaluator.todo_tokens), 0)
        self.assertEqual(self.evaluator.total_deferrals, 0)
    
    def test_should_defer_disabled(self):
        """Test that deferral is rejected when lazy eval is disabled."""
        evaluator = LazyEvaluator(
            agent_id="test",
            enable_lazy_eval=False
        )
        
        decision = evaluator.should_defer(
            description="Expensive operation",
            context={},
            estimated_cost_ms=5000
        )
        
        self.assertFalse(decision.should_defer)
        self.assertEqual(decision.confidence, 1.0)
    
    def test_should_defer_expensive_operation(self):
        """Test deferral of expensive operations (>2 seconds)."""
        decision = self.evaluator.should_defer(
            description="Complex analysis",
            context={},
            estimated_cost_ms=3000  # > 2000ms threshold
        )
        
        self.assertTrue(decision.should_defer)
        self.assertEqual(decision.reason, DeferralReason.TOO_EXPENSIVE)
        self.assertEqual(decision.estimated_savings_ms, 3000)
        self.assertGreater(decision.confidence, 0.8)
    
    def test_should_defer_speculative_computation(self):
        """Test deferral of speculative queries."""
        # Test with "might" keyword
        decision = self.evaluator.should_defer(
            description="Check if user might need archived data",
            context={}
        )
        
        self.assertTrue(decision.should_defer)
        self.assertEqual(decision.reason, DeferralReason.SPECULATIVE)
        
        # Test with "optional" keyword
        decision = self.evaluator.should_defer(
            description="Optional analysis of historical trends",
            context={}
        )
        
        self.assertTrue(decision.should_defer)
        self.assertEqual(decision.reason, DeferralReason.SPECULATIVE)
    
    def test_should_defer_missing_context(self):
        """Test deferral when context is missing."""
        decision = self.evaluator.should_defer(
            description="Need more information from user before proceeding",
            context={}
        )
        
        self.assertTrue(decision.should_defer)
        self.assertEqual(decision.reason, DeferralReason.MISSING_CONTEXT)
    
    def test_should_defer_low_priority(self):
        """Test deferral of low priority tasks."""
        decision = self.evaluator.should_defer(
            description="Background cleanup task",
            context={"priority": 3, "low_priority": True}
        )
        
        self.assertTrue(decision.should_defer)
        self.assertEqual(decision.reason, DeferralReason.LOW_PRIORITY)
    
    def test_should_defer_archive_query(self):
        """Test deferral of archive/historical queries."""
        decision = self.evaluator.should_defer(
            description="Fetch historical data from archive",
            context={}
        )
        
        self.assertTrue(decision.should_defer)
        self.assertEqual(decision.reason, DeferralReason.NOT_NEEDED_NOW)
    
    def test_should_not_defer_immediate_archive_query(self):
        """Test that immediate flag overrides archive deferral."""
        decision = self.evaluator.should_defer(
            description="Fetch historical data from archive",
            context={"immediate": True}
        )
        
        self.assertFalse(decision.should_defer)
    
    def test_should_not_defer_normal_operation(self):
        """Test that normal operations are not deferred."""
        decision = self.evaluator.should_defer(
            description="Fetch current user data",
            context={},
            estimated_cost_ms=500
        )
        
        self.assertFalse(decision.should_defer)
    
    def test_defer_creates_token(self):
        """Test that defer creates a TODO token."""
        token = self.evaluator.defer(
            description="Analyze logs",
            reason=DeferralReason.TOO_EXPENSIVE,
            context={"time_range": "2023"},
            priority=7,
            estimated_cost_ms=4000
        )
        
        self.assertIsNotNone(token)
        self.assertIn(token.token_id, self.evaluator.todo_tokens)
        self.assertEqual(token.description, "Analyze logs")
        self.assertEqual(token.priority, 7)
        self.assertEqual(self.evaluator.total_deferrals, 1)
        self.assertEqual(self.evaluator.total_savings_ms, 4000)
    
    def test_resolve_token(self):
        """Test resolving a TODO token."""
        # Defer a computation
        token = self.evaluator.defer(
            description="Compute result",
            reason=DeferralReason.NOT_NEEDED_NOW,
            context={}
        )
        
        self.assertFalse(token.resolved)
        
        # Resolve it
        result = {"data": [1, 2, 3]}
        success = self.evaluator.resolve(token.token_id, result)
        
        self.assertTrue(success)
        self.assertTrue(token.resolved)
        self.assertIsNotNone(token.resolved_at)
        self.assertEqual(token.result, result)
        self.assertEqual(self.evaluator.total_resolutions, 1)
    
    def test_resolve_nonexistent_token(self):
        """Test resolving non-existent token returns False."""
        success = self.evaluator.resolve("nonexistent-token", "result")
        
        self.assertFalse(success)
    
    def test_get_pending_tokens(self):
        """Test getting pending tokens sorted by priority."""
        # Create tokens with different priorities
        token1 = self.evaluator.defer("Task 1", DeferralReason.NOT_NEEDED_NOW, {}, priority=3)
        token2 = self.evaluator.defer("Task 2", DeferralReason.NOT_NEEDED_NOW, {}, priority=8)
        token3 = self.evaluator.defer("Task 3", DeferralReason.NOT_NEEDED_NOW, {}, priority=5)
        
        pending = self.evaluator.get_pending_tokens()
        
        self.assertEqual(len(pending), 3)
        # Should be sorted by priority (highest first)
        self.assertEqual(pending[0].priority, 8)
        self.assertEqual(pending[1].priority, 5)
        self.assertEqual(pending[2].priority, 3)
    
    def test_get_resolved_tokens(self):
        """Test getting resolved tokens."""
        token1 = self.evaluator.defer("Task 1", DeferralReason.NOT_NEEDED_NOW, {})
        token2 = self.evaluator.defer("Task 2", DeferralReason.NOT_NEEDED_NOW, {})
        
        # Resolve one
        self.evaluator.resolve(token1.token_id, "result1")
        
        resolved = self.evaluator.get_resolved_tokens()
        
        self.assertEqual(len(resolved), 1)
        self.assertEqual(resolved[0].token_id, token1.token_id)
    
    def test_clear_resolved(self):
        """Test clearing resolved tokens."""
        token1 = self.evaluator.defer("Task 1", DeferralReason.NOT_NEEDED_NOW, {})
        token2 = self.evaluator.defer("Task 2", DeferralReason.NOT_NEEDED_NOW, {})
        
        # Resolve one
        self.evaluator.resolve(token1.token_id, "result1")
        
        self.assertEqual(len(self.evaluator.todo_tokens), 2)
        
        # Clear resolved
        self.evaluator.clear_resolved()
        
        self.assertEqual(len(self.evaluator.todo_tokens), 1)
        self.assertNotIn(token1.token_id, self.evaluator.todo_tokens)
        self.assertIn(token2.token_id, self.evaluator.todo_tokens)
    
    def test_max_deferred_tasks_eviction(self):
        """Test that old tokens are evicted when reaching max capacity."""
        evaluator = LazyEvaluator(
            agent_id="test",
            enable_lazy_eval=True,
            max_deferred_tasks=3  # Small capacity
        )
        
        # Create and resolve 2 tokens
        token1 = evaluator.defer("Task 1", DeferralReason.NOT_NEEDED_NOW, {}, priority=1)
        token2 = evaluator.defer("Task 2", DeferralReason.NOT_NEEDED_NOW, {}, priority=2)
        evaluator.resolve(token1.token_id, "result1")
        evaluator.resolve(token2.token_id, "result2")
        
        # Add one more (at capacity)
        token3 = evaluator.defer("Task 3", DeferralReason.NOT_NEEDED_NOW, {}, priority=3)
        
        self.assertEqual(len(evaluator.todo_tokens), 3)
        
        # Add one more (exceeds capacity, should evict lowest priority resolved)
        token4 = evaluator.defer("Task 4", DeferralReason.NOT_NEEDED_NOW, {}, priority=4)
        
        # Should still be 3, with lowest priority resolved token evicted
        self.assertEqual(len(evaluator.todo_tokens), 3)
        self.assertNotIn(token1.token_id, evaluator.todo_tokens)  # Lowest priority, resolved
    
    def test_get_statistics(self):
        """Test getting lazy evaluation statistics."""
        # Create some tokens
        token1 = self.evaluator.defer("Task 1", DeferralReason.NOT_NEEDED_NOW, {}, estimated_cost_ms=1000)
        token2 = self.evaluator.defer("Task 2", DeferralReason.TOO_EXPENSIVE, {}, estimated_cost_ms=2000)
        
        # Resolve one
        self.evaluator.resolve(token1.token_id, "result")
        
        stats = self.evaluator.get_statistics()
        
        self.assertEqual(stats["agent_id"], self.agent_id)
        self.assertTrue(stats["enable_lazy_eval"])
        self.assertEqual(stats["total_deferrals"], 2)
        self.assertEqual(stats["total_resolutions"], 1)
        self.assertEqual(stats["pending_tokens"], 1)
        self.assertEqual(stats["resolved_tokens"], 1)
        self.assertEqual(stats["total_savings_ms"], 3000)
        self.assertEqual(stats["total_savings_seconds"], 3.0)
        self.assertEqual(stats["resolution_rate"], 0.5)


class TestLazyEvaluatorRegistry(unittest.TestCase):
    """Tests for LazyEvaluatorRegistry."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.registry = LazyEvaluatorRegistry(
            enable_lazy_eval=True,
            max_deferred_tasks=100
        )
    
    def test_get_or_create_new_evaluator(self):
        """Test creating new lazy evaluator for agent."""
        evaluator = self.registry.get_or_create("agent-1")
        
        self.assertIsInstance(evaluator, LazyEvaluator)
        self.assertEqual(evaluator.agent_id, "agent-1")
        self.assertTrue(evaluator.enable_lazy_eval)
    
    def test_get_or_create_returns_existing(self):
        """Test that get_or_create returns existing evaluator."""
        evaluator1 = self.registry.get_or_create("agent-1")
        evaluator1.defer("Task", DeferralReason.NOT_NEEDED_NOW, {})
        
        evaluator2 = self.registry.get_or_create("agent-1")
        
        # Should be same instance
        self.assertEqual(len(evaluator2.todo_tokens), 1)
        self.assertIs(evaluator1, evaluator2)
    
    def test_multiple_agents(self):
        """Test managing multiple agents."""
        evaluator1 = self.registry.get_or_create("agent-1")
        evaluator2 = self.registry.get_or_create("agent-2")
        
        self.assertIsNot(evaluator1, evaluator2)
        self.assertEqual(evaluator1.agent_id, "agent-1")
        self.assertEqual(evaluator2.agent_id, "agent-2")
    
    def test_get_all_statistics(self):
        """Test getting statistics for all agents."""
        evaluator1 = self.registry.get_or_create("agent-1")
        evaluator2 = self.registry.get_or_create("agent-2")
        
        evaluator1.defer("Task 1", DeferralReason.NOT_NEEDED_NOW, {})
        evaluator2.defer("Task 2", DeferralReason.TOO_EXPENSIVE, {})
        evaluator2.defer("Task 3", DeferralReason.LOW_PRIORITY, {})
        
        all_stats = self.registry.get_all_statistics()
        
        self.assertEqual(len(all_stats), 2)
        self.assertIn("agent-1", all_stats)
        self.assertIn("agent-2", all_stats)
        self.assertEqual(all_stats["agent-1"]["total_deferrals"], 1)
        self.assertEqual(all_stats["agent-2"]["total_deferrals"], 2)
    
    def test_get_global_statistics(self):
        """Test getting global statistics."""
        evaluator1 = self.registry.get_or_create("agent-1")
        evaluator2 = self.registry.get_or_create("agent-2")
        
        # Agent 1: defer 2 tasks, resolve 1
        token1 = evaluator1.defer("Task 1", DeferralReason.NOT_NEEDED_NOW, {}, estimated_cost_ms=1000)
        evaluator1.defer("Task 2", DeferralReason.NOT_NEEDED_NOW, {}, estimated_cost_ms=2000)
        evaluator1.resolve(token1.token_id, "result")
        
        # Agent 2: defer 1 task
        evaluator2.defer("Task 3", DeferralReason.TOO_EXPENSIVE, {}, estimated_cost_ms=3000)
        
        global_stats = self.registry.get_global_statistics()
        
        self.assertEqual(global_stats["total_agents"], 2)
        self.assertEqual(global_stats["total_deferrals"], 3)
        self.assertEqual(global_stats["total_resolutions"], 1)
        self.assertEqual(global_stats["total_savings_ms"], 6000)
        self.assertEqual(global_stats["total_savings_seconds"], 6.0)
        self.assertAlmostEqual(global_stats["global_resolution_rate"], 1/3, places=2)


class TestLazyEvaluationScenarios(unittest.TestCase):
    """Real-world lazy evaluation scenarios."""
    
    def test_archive_query_deferral(self):
        """Test deferring expensive archive queries."""
        evaluator = LazyEvaluator(agent_id="query-agent", enable_lazy_eval=True)
        
        # Archive query should be deferred
        decision = evaluator.should_defer(
            description="Fetch logs from 2023 archive",
            context={},
            estimated_cost_ms=5000
        )
        
        self.assertTrue(decision.should_defer)
        self.assertIn(decision.reason, [
            DeferralReason.TOO_EXPENSIVE,
            DeferralReason.NOT_NEEDED_NOW
        ])
    
    def test_speculative_analysis_deferral(self):
        """Test deferring speculative analysis."""
        evaluator = LazyEvaluator(agent_id="analysis-agent", enable_lazy_eval=True)
        
        decision = evaluator.should_defer(
            description="The user might need a detailed breakdown, so let's compute it",
            context={}
        )
        
        self.assertTrue(decision.should_defer)
        self.assertEqual(decision.reason, DeferralReason.SPECULATIVE)
    
    def test_immediate_query_not_deferred(self):
        """Test that immediate queries are not deferred."""
        evaluator = LazyEvaluator(agent_id="search-agent", enable_lazy_eval=True)
        
        decision = evaluator.should_defer(
            description="Fetch current user session",
            context={"immediate": True},
            estimated_cost_ms=200
        )
        
        self.assertFalse(decision.should_defer)
    
    def test_batch_processing_workflow(self):
        """Test batch processing with lazy evaluation."""
        evaluator = LazyEvaluator(agent_id="batch-agent", enable_lazy_eval=True)
        
        # Defer multiple low-priority tasks
        token1 = evaluator.defer("Process batch 1", DeferralReason.LOW_PRIORITY, {}, priority=2)
        token2 = evaluator.defer("Process batch 2", DeferralReason.LOW_PRIORITY, {}, priority=2)
        token3 = evaluator.defer("Process batch 3", DeferralReason.LOW_PRIORITY, {}, priority=2)
        
        # All should be pending
        pending = evaluator.get_pending_tokens()
        self.assertEqual(len(pending), 3)
        
        # Process them in batch
        for token in pending:
            evaluator.resolve(token.token_id, f"Processed {token.description}")
        
        # All should be resolved
        resolved = evaluator.get_resolved_tokens()
        self.assertEqual(len(resolved), 3)


if __name__ == "__main__":
    unittest.main()
