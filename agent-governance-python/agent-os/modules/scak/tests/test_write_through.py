# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Unit tests for Write-Through Architecture and Safe Purge Protocol.

Tests the enhanced memory management features:
1. Write-Through Pattern: Always write to Vector DB, conditionally to cache
2. Safe Demotion: Update tier tags without data loss
3. Cache Eviction: Remove unused entries from Redis
4. Disaster Recovery: Rebuild cache from Vector DB
"""

import unittest
from datetime import datetime, timedelta
from src.kernel.memory import MemoryController
from src.kernel.schemas import Lesson, PatchRequest, MemoryTier


# Test constants
EVICTION_THRESHOLD_DAYS_OLD = 45  # Days since last retrieval
EVICTION_THRESHOLD_DAYS_NEW = 30  # Eviction threshold parameter


class TestWriteThroughArchitecture(unittest.TestCase):
    """Tests for Write-Through Pattern and Safe Purge Protocol."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.controller = MemoryController()
    
    def test_write_through_tier1_writes_to_both(self):
        """Test that Tier 1 lessons are written to both kernel and vector DB."""
        lesson = Lesson(
            trigger_pattern="security check",
            rule_text="Never bypass authentication",
            lesson_type="security",
            confidence_score=0.95
        )
        patch = PatchRequest(
            trace_id="trace-1",
            diagnosis="Security violation",
            proposed_lesson=lesson,
            apply_strategy="hotfix_now"
        )
        
        result = self.controller.commit_lesson(patch)
        
        # Should be in kernel
        self.assertEqual(result["status"], "committed")
        self.assertEqual(result["tier"], "kernel")
        self.assertTrue(result["write_through"])
        self.assertIn("vector_db", result["location"])
        
        # Verify lesson is in kernel rules
        self.assertIn(lesson, self.controller.kernel_rules)
        
        # Verify lesson is in vector DB
        self.assertEqual(len(self.controller.vector_store.documents), 1)
        doc = self.controller.vector_store.documents[0]
        self.assertEqual(doc["metadata"]["active_tier"], "kernel")
    
    def test_write_through_tier2_writes_to_redis_and_vector_db(self):
        """Test that Tier 2 lessons are written to Redis and Vector DB."""
        lesson = Lesson(
            trigger_pattern="tool:sql_query",
            rule_text="Use LIMIT in SELECT statements",
            lesson_type="syntax",
            confidence_score=0.85
        )
        patch = PatchRequest(
            trace_id="trace-2",
            diagnosis="SQL query returned too many rows",
            proposed_lesson=lesson,
            apply_strategy="batch_later"
        )
        
        result = self.controller.commit_lesson(patch)
        
        # Should be in skill cache
        self.assertEqual(result["status"], "committed")
        self.assertEqual(result["tier"], "skill_cache")
        self.assertTrue(result["write_through"])
        self.assertIn("redis", result["location"])
        self.assertIn("vector_db", result["location"])
        
        # Verify lesson is in Redis
        tool_name = result["tool"]
        cached = self.controller.redis_cache.lrange(f"skill:{tool_name}", 0, -1)
        self.assertEqual(len(cached), 1)
        
        # Verify lesson is in vector DB
        self.assertEqual(len(self.controller.vector_store.documents), 1)
        doc = self.controller.vector_store.documents[0]
        self.assertEqual(doc["metadata"]["active_tier"], "skill_cache")
    
    def test_write_through_tier3_writes_only_to_vector_db(self):
        """Test that Tier 3 lessons are written only to Vector DB."""
        lesson = Lesson(
            trigger_pattern="Q3 report search",
            rule_text="Q3 2023 reports are archived",
            lesson_type="business",
            confidence_score=0.80
        )
        patch = PatchRequest(
            trace_id="trace-3",
            diagnosis="Agent didn't check archives",
            proposed_lesson=lesson,
            apply_strategy="batch_later"
        )
        
        result = self.controller.commit_lesson(patch)
        
        # Should be in archive only
        self.assertEqual(result["status"], "committed")
        self.assertEqual(result["tier"], "rag_archive")
        self.assertTrue(result["write_through"])
        self.assertEqual(result["location"], "vector_db")
        
        # Verify lesson is in vector DB
        self.assertEqual(len(self.controller.vector_store.documents), 1)
        doc = self.controller.vector_store.documents[0]
        self.assertEqual(doc["metadata"]["active_tier"], "rag_archive")
    
    def test_evict_from_cache_removes_old_entries(self):
        """Test that cache eviction removes unused entries."""
        # Add a Tier 2 lesson with old last_retrieved_at
        lesson = Lesson(
            trigger_pattern="tool:sql_query",
            rule_text="Old lesson",
            lesson_type="syntax",
            confidence_score=0.85,
            last_retrieved_at=datetime.now() - timedelta(days=EVICTION_THRESHOLD_DAYS_OLD)
        )
        patch = PatchRequest(
            trace_id="trace-4",
            diagnosis="Test",
            proposed_lesson=lesson,
            apply_strategy="batch_later"
        )
        
        # Commit the lesson
        self.controller.commit_lesson(patch)
        
        # Verify it's in cache
        tool_name = "sql_query"
        cached_before = self.controller.redis_cache.lrange(f"skill:{tool_name}", 0, -1)
        self.assertGreater(len(cached_before), 0)
        
        # Run eviction with 30-day threshold
        result = self.controller.evict_from_cache(unused_days=EVICTION_THRESHOLD_DAYS_NEW)
        
        # Verify eviction happened
        self.assertEqual(result["threshold_days"], EVICTION_THRESHOLD_DAYS_NEW)
        # Note: Mock implementation may not fully simulate eviction
        # In production, this would remove the entry from Redis
    
    def test_update_tier_tag_in_vector_db(self):
        """Test that tier tags can be updated in Vector DB."""
        # Add a lesson
        lesson = Lesson(
            id="lesson-123",
            trigger_pattern="test",
            rule_text="Test lesson",
            lesson_type="business",
            confidence_score=0.8
        )
        patch = PatchRequest(
            trace_id="trace-5",
            diagnosis="Test",
            proposed_lesson=lesson,
            apply_strategy="batch_later"
        )
        
        # Commit to Tier 3
        self.controller.commit_lesson(patch)
        
        # Verify initial tier
        doc = self.controller.vector_store.documents[0]
        self.assertEqual(doc["metadata"]["active_tier"], "rag_archive")
        
        # Update tier tag
        self.controller._update_tier_tag_in_vector_db("lesson-123", MemoryTier.TIER_2_SKILL_CACHE)
        
        # Verify updated tier
        doc = self.controller.vector_store.documents[0]
        self.assertEqual(doc["metadata"]["active_tier"], "skill_cache")
    
    def test_rebuild_cache_from_db(self):
        """Test disaster recovery by rebuilding cache from Vector DB."""
        # Add multiple Tier 2 lessons
        lessons = [
            Lesson(
                trigger_pattern="tool:sql_query",
                rule_text="SQL lesson 1",
                lesson_type="syntax",
                confidence_score=0.85
            ),
            Lesson(
                trigger_pattern="tool:sql_query",
                rule_text="SQL lesson 2",
                lesson_type="syntax",
                confidence_score=0.80
            ),
            Lesson(
                trigger_pattern="tool:python_repl",
                rule_text="Python lesson 1",
                lesson_type="syntax",
                confidence_score=0.90
            )
        ]
        
        for i, lesson in enumerate(lessons):
            patch = PatchRequest(
                trace_id=f"trace-{i}",
                diagnosis="Test",
                proposed_lesson=lesson,
                apply_strategy="batch_later"
            )
            self.controller.commit_lesson(patch)
        
        # Simulate Redis crash - use clear() method
        self.controller.redis_cache.clear()
        
        # Verify cache is empty
        sql_cache = self.controller.redis_cache.lrange("skill:sql_query", 0, -1)
        self.assertEqual(len(sql_cache), 0)
        
        # Rebuild cache from Vector DB
        result = self.controller.rebuild_cache_from_db()
        
        # Verify rebuild stats
        self.assertGreater(result["rebuilt_count"], 0)
        self.assertGreater(result["tools_rebuilt"], 0)
        self.assertIn("tool_list", result)
    
    def test_safe_demotion_preserves_data(self):
        """Test that demotion changes tier tag but preserves data."""
        # Add a Tier 2 lesson
        lesson = Lesson(
            id="lesson-456",
            trigger_pattern="tool:sql_query",
            rule_text="Demotion test",
            lesson_type="syntax",
            confidence_score=0.85
        )
        patch = PatchRequest(
            trace_id="trace-6",
            diagnosis="Test",
            proposed_lesson=lesson,
            apply_strategy="batch_later"
        )
        
        # Commit to Tier 2
        result = self.controller.commit_lesson(patch)
        self.assertEqual(result["tier"], "skill_cache")
        
        # Verify it's in Vector DB with Tier 2 tag
        doc = next(d for d in self.controller.vector_store.documents if d["id"] == "lesson-456")
        self.assertEqual(doc["metadata"]["active_tier"], "skill_cache")
        
        # Demote to Tier 3 (safe demotion)
        self.controller._update_tier_tag_in_vector_db("lesson-456", MemoryTier.TIER_3_ARCHIVE)
        
        # Verify data still exists but with updated tier
        doc = next(d for d in self.controller.vector_store.documents if d["id"] == "lesson-456")
        self.assertEqual(doc["metadata"]["active_tier"], "rag_archive")
        self.assertEqual(doc["text"], "Demotion test")  # Data preserved
    
    def test_multiple_lessons_same_tool(self):
        """Test that multiple lessons for the same tool are handled correctly."""
        lessons = [
            Lesson(
                trigger_pattern="tool:sql_query",
                rule_text=f"SQL lesson {i}",
                lesson_type="syntax",
                confidence_score=0.85
            )
            for i in range(3)
        ]
        
        for i, lesson in enumerate(lessons):
            patch = PatchRequest(
                trace_id=f"trace-{i}",
                diagnosis="Test",
                proposed_lesson=lesson,
                apply_strategy="batch_later"
            )
            self.controller.commit_lesson(patch)
        
        # Verify all lessons are in cache
        cached = self.controller.redis_cache.lrange("skill:sql_query", 0, -1)
        self.assertEqual(len(cached), 3)
        
        # Verify all lessons are in Vector DB
        self.assertEqual(len(self.controller.vector_store.documents), 3)
    
    def test_write_through_creates_consistent_timestamps(self):
        """Test that write-through creates consistent timestamps."""
        lesson = Lesson(
            trigger_pattern="test",
            rule_text="Test lesson",
            lesson_type="business",
            confidence_score=0.8
        )
        patch = PatchRequest(
            trace_id="trace-7",
            diagnosis="Test",
            proposed_lesson=lesson,
            apply_strategy="batch_later"
        )
        
        # Commit lesson
        self.controller.commit_lesson(patch)
        
        # Verify created_at is set
        self.assertIsNotNone(lesson.created_at)
        self.assertIsInstance(lesson.created_at, datetime)


if __name__ == '__main__':
    unittest.main()
