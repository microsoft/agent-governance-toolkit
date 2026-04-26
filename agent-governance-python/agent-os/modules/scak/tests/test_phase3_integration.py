# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Integration test for Phase 3 components working together.

This test validates the complete workflow:
1. SkillMapper extracts tool from failure trace
2. LessonRubric evaluates and assigns tier
3. MemoryController commits with write-through pattern
4. Cache can be evicted and rebuilt safely
"""

import unittest
from datetime import datetime, timedelta

from src.kernel.skill_mapper import SkillMapper
from src.kernel.rubric import LessonRubric
from src.kernel.memory import MemoryController
from src.kernel.schemas import FailureTrace, Lesson, PatchRequest, MemoryTier


class TestPhase3Integration(unittest.TestCase):
    """Integration tests for Phase 3 components."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mapper = SkillMapper()
        self.rubric = LessonRubric()
        self.controller = MemoryController()
    
    def test_complete_workflow_tier2_lesson(self):
        """Test complete workflow for a Tier 2 lesson."""
        # Step 1: Failure occurs
        trace = FailureTrace(
            user_prompt="Query database for users",
            agent_reasoning="I'll execute SELECT * FROM users",
            tool_call={"tool": "sql_db", "query": "SELECT * FROM users"},
            tool_output="Error: Query returned 1,000,000 rows",
            failure_type="commission_safety",
            severity="critical"
        )
        
        # Step 2: Map to tool
        tool = self.mapper.extract_tool_context(trace)
        self.assertEqual(tool, "sql_db")
        
        # Step 3: Create lesson
        lesson = Lesson(
            trigger_pattern=f"tool:{tool}",
            rule_text="Always use LIMIT clause in SELECT queries",
            lesson_type="syntax",
            confidence_score=0.90
        )
        
        # Step 4: Evaluate with rubric
        evaluation = self.rubric.evaluate(trace, lesson)
        self.assertIn(evaluation["tier"], [MemoryTier.TIER_1_KERNEL, MemoryTier.TIER_2_SKILL_CACHE])
        self.assertGreater(evaluation["score"], 40)  # Should be Tier 1 or 2
        
        # Step 5: Commit with write-through
        patch = PatchRequest(
            trace_id=trace.trace_id,
            diagnosis="Agent didn't limit query results",
            proposed_lesson=lesson,
            apply_strategy="hotfix_now"
        )
        
        result = self.controller.commit_lesson(patch)
        self.assertEqual(result["status"], "committed")
        self.assertTrue(result["write_through"])
        self.assertIn("vector_db", result["location"])
        
        # Verify lesson is in Vector DB
        self.assertGreater(len(self.controller.vector_store.documents), 0)
        
        # If Tier 2, verify in Redis cache
        if evaluation["tier"] == MemoryTier.TIER_2_SKILL_CACHE:
            cached = self.controller.redis_cache.lrange(f"skill:{tool}", 0, -1)
            self.assertGreater(len(cached), 0)
    
    def test_complete_workflow_tier3_lesson(self):
        """Test complete workflow for a Tier 3 lesson."""
        # Step 1: Failure with specific business data
        trace = FailureTrace(
            user_prompt="Find Q3 report",
            agent_reasoning="Searched main partition",
            tool_call={"tool": "search", "query": "Q3 report"},
            tool_output="No results",
            failure_type="omission_laziness",
            severity="non_critical"
        )
        
        # Step 2: Map to tool
        tool = self.mapper.extract_tool_context(trace)
        self.assertEqual(tool, "search")
        
        # Step 3: Create lesson with specific data
        lesson = Lesson(
            trigger_pattern="Q3 report search",
            rule_text="Q3 2023 reports are in archived partition on server-42",
            lesson_type="business",
            confidence_score=0.70
        )
        
        # Step 4: Evaluate with rubric (should be Tier 3 due to specific IDs)
        evaluation = self.rubric.evaluate(trace, lesson)
        self.assertEqual(evaluation["tier"], MemoryTier.TIER_3_ARCHIVE)
        self.assertLess(evaluation["score"], 40)
        
        # Step 5: Commit
        patch = PatchRequest(
            trace_id=trace.trace_id,
            diagnosis="Didn't check archived partition",
            proposed_lesson=lesson,
            apply_strategy="batch_later"
        )
        
        result = self.controller.commit_lesson(patch)
        self.assertEqual(result["status"], "committed")
        self.assertEqual(result["tier"], "rag_archive")
        
        # Verify in Vector DB only (not in Redis)
        self.assertGreater(len(self.controller.vector_store.documents), 0)
    
    def test_disaster_recovery_workflow(self):
        """Test disaster recovery with cache rebuild."""
        # Create multiple Tier 2 lessons
        lessons_data = [
            ("sql_db", "Use LIMIT in queries"),
            ("sql_db", "Always use WHERE clause in DELETE"),
            ("python_repl", "Import libraries at the top"),
        ]
        
        for tool, rule_text in lessons_data:
            trace = FailureTrace(
                user_prompt=f"Use {tool}",
                agent_reasoning="Test",
                tool_call={"tool": tool, "action": "test"},
                tool_output="Error",
                failure_type="omission_laziness",
                severity="non_critical"
            )
            
            lesson = Lesson(
                trigger_pattern=f"tool:{tool}",
                rule_text=rule_text,
                lesson_type="syntax",
                confidence_score=0.85
            )
            
            patch = PatchRequest(
                trace_id=trace.trace_id,
                diagnosis="Test",
                proposed_lesson=lesson,
                apply_strategy="batch_later"
            )
            
            self.controller.commit_lesson(patch)
        
        # Verify lessons in cache
        original_cache_keys = [k for k in self.controller.redis_cache.store.keys() 
                               if k.startswith('skill:')]
        self.assertGreater(len(original_cache_keys), 0)
        
        # Simulate Redis crash
        self.controller.redis_cache = type(self.controller.redis_cache)()
        
        # Verify cache is empty
        empty_cache = self.controller.redis_cache.lrange("skill:sql_db", 0, -1)
        self.assertEqual(len(empty_cache), 0)
        
        # Rebuild cache
        rebuild_result = self.controller.rebuild_cache_from_db()
        
        # Verify rebuild was successful
        self.assertGreater(rebuild_result["rebuilt_count"], 0)
        self.assertGreater(rebuild_result["tools_rebuilt"], 0)
        self.assertIn("sql_db", rebuild_result["tool_list"])
    
    def test_semantic_fallback_and_evaluation(self):
        """Test semantic fallback in mapper and rubric evaluation."""
        # No explicit tool_call, rely on semantic matching
        trace = FailureTrace(
            user_prompt="Run Python code",
            agent_reasoning="I need to import pandas and print the dataframe",
            tool_call=None,  # No explicit tool
            tool_output="Error: pandas not installed",
            failure_type="omission_laziness",
            severity="non_critical"
        )
        
        # Mapper should detect python_repl from keywords
        tool = self.mapper.extract_tool_context(trace)
        self.assertEqual(tool, "python_repl")
        
        # Create lesson
        lesson = Lesson(
            trigger_pattern=f"tool:{tool}",
            rule_text="Check library availability before importing",
            lesson_type="syntax",
            confidence_score=0.80
        )
        
        # Evaluate
        evaluation = self.rubric.evaluate(trace, lesson)
        self.assertIn(evaluation["tier"], 
                     [MemoryTier.TIER_2_SKILL_CACHE, MemoryTier.TIER_3_ARCHIVE])
        
        # Commit
        patch = PatchRequest(
            trace_id=trace.trace_id,
            diagnosis="Didn't check library availability",
            proposed_lesson=lesson,
            apply_strategy="batch_later"
        )
        
        result = self.controller.commit_lesson(patch)
        self.assertEqual(result["status"], "committed")
    
    def test_high_severity_security_workflow(self):
        """Test workflow for high-severity security failure."""
        trace = FailureTrace(
            user_prompt="Delete files",
            agent_reasoning="Deleting from root directory",
            tool_call={"tool": "file_operations", "path": "/"},
            tool_output="Error: Blocked by safety policy",
            failure_type="commission_safety",
            severity="critical"
        )
        
        # Map to tool
        tool = self.mapper.extract_tool_context(trace)
        self.assertEqual(tool, "file_operations")
        
        # Create security lesson
        lesson = Lesson(
            trigger_pattern="delete operation",
            rule_text="Never delete root directory without explicit confirmation",
            lesson_type="security",
            confidence_score=0.95
        )
        
        # Evaluate - should be Tier 1 due to high severity
        evaluation = self.rubric.evaluate(trace, lesson)
        self.assertEqual(evaluation["tier"], MemoryTier.TIER_1_KERNEL)
        self.assertGreaterEqual(evaluation["score"], 75)
        
        # Commit
        patch = PatchRequest(
            trace_id=trace.trace_id,
            diagnosis="Attempted unsafe deletion",
            proposed_lesson=lesson,
            apply_strategy="hotfix_now"
        )
        
        result = self.controller.commit_lesson(patch)
        self.assertEqual(result["tier"], "kernel")
        
        # Verify in kernel rules
        self.assertIn(lesson, self.controller.kernel_rules)
        
        # Verify also in Vector DB (write-through)
        self.assertGreater(len(self.controller.vector_store.documents), 0)


if __name__ == '__main__':
    unittest.main()
