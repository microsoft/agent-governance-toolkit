# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Unit tests for the reference implementations.

These tests validate the simplified reference implementations:
- auditor.py: Soft failure detection
- teacher.py: Shadow teacher diagnosis
- memory_manager.py: Lesson lifecycle management
"""

import unittest
import asyncio
from datetime import datetime

from agent_kernel.auditor import CompletenessAuditor as SimpleAuditor
from agent_kernel.teacher import diagnose_failure
from agent_kernel.memory_manager import MemoryManager, LessonType


class TestSimpleAuditor(unittest.TestCase):
    """Tests for the simplified auditor reference implementation."""
    
    def setUp(self):
        self.auditor = SimpleAuditor()
    
    def test_detects_verbal_resignation(self):
        """Test detection of lazy verbal signals."""
        agent_response = "I cannot find the data you requested."
        tool_output = None
        
        needs_intervention = self.auditor.audit_response(agent_response, tool_output)
        self.assertTrue(needs_intervention)
    
    def test_detects_no_data_found(self):
        """Test detection of 'no data found' signal."""
        agent_response = "No data found in the system."
        tool_output = None
        
        needs_intervention = self.auditor.audit_response(agent_response, tool_output)
        self.assertTrue(needs_intervention)
    
    def test_detects_empty_results(self):
        """Test detection of empty tool output."""
        agent_response = "Here are the results:"
        tool_output = "[]"
        
        needs_intervention = self.auditor.audit_response(agent_response, tool_output)
        self.assertTrue(needs_intervention)
    
    def test_accepts_valid_response(self):
        """Test that valid responses are not flagged."""
        agent_response = "Found 42 records matching your query."
        tool_output = '[{"id": 1, "name": "test"}]'
        
        needs_intervention = self.auditor.audit_response(agent_response, tool_output)
        self.assertFalse(needs_intervention)
    
    def test_all_lazy_signals(self):
        """Test all lazy signal patterns."""
        test_cases = [
            "I'm sorry, I cannot help with that.",
            "Unable to access the resource.",
            "The context does not contain this information.",
            "No data found for your request."
        ]
        
        for response in test_cases:
            with self.subTest(response=response):
                needs_intervention = self.auditor.audit_response(response, None)
                self.assertTrue(needs_intervention, f"Should detect: {response}")


class TestTeacher(unittest.TestCase):
    """Tests for the shadow teacher reference implementation."""
    
    def test_diagnose_failure_basic(self):
        """Test basic diagnosis functionality."""
        prompt = "Find logs for error 500"
        failed_response = "No logs found."
        tool_trace = "search_logs(error_code='500', time_range='recent')"
        
        # Run async function
        diagnosis = asyncio.run(diagnose_failure(prompt, failed_response, tool_trace))
        
        self.assertIsInstance(diagnosis, dict)
        self.assertIn("cause", diagnosis)
        self.assertIn("lesson_patch", diagnosis)
    
    def test_diagnosis_structure(self):
        """Test that diagnosis has proper structure."""
        prompt = "Delete recent user records"
        failed_response = "Cannot delete records."
        tool_trace = "execute_sql(query='DELETE FROM recent_users')"
        
        diagnosis = asyncio.run(diagnose_failure(prompt, failed_response, tool_trace))
        
        # Verify structure
        self.assertIsInstance(diagnosis["cause"], str)
        self.assertIsInstance(diagnosis["lesson_patch"], str)
        self.assertGreater(len(diagnosis["cause"]), 0)
        self.assertGreater(len(diagnosis["lesson_patch"]), 0)


class TestMemoryManager(unittest.TestCase):
    """Tests for the memory manager reference implementation."""
    
    def setUp(self):
        self.manager = MemoryManager()
    
    def test_add_syntax_lesson(self):
        """Test adding a syntax lesson."""
        self.manager.add_lesson(
            "Always output JSON format",
            LessonType.SYNTAX
        )
        
        lessons = self.manager.get_lessons_by_type(LessonType.SYNTAX)
        self.assertEqual(len(lessons), 1)
        self.assertEqual(lessons[0]["text"], "Always output JSON format")
    
    def test_add_business_lesson(self):
        """Test adding a business lesson."""
        self.manager.add_lesson(
            "Fiscal year starts in October",
            LessonType.BUSINESS
        )
        
        lessons = self.manager.get_lessons_by_type(LessonType.BUSINESS)
        self.assertEqual(len(lessons), 1)
        self.assertEqual(lessons[0]["text"], "Fiscal year starts in October")
    
    def test_add_one_off_lesson(self):
        """Test adding a one-off lesson."""
        self.manager.add_lesson(
            "Server maintenance on 2024-01-15",
            LessonType.ONE_OFF
        )
        
        lessons = self.manager.get_lessons_by_type(LessonType.ONE_OFF)
        self.assertEqual(len(lessons), 1)
    
    def test_upgrade_purge_removes_syntax(self):
        """Test that upgrade purge removes SYNTAX lessons."""
        # Add various lesson types
        self.manager.add_lesson("Output JSON", LessonType.SYNTAX)
        self.manager.add_lesson("Use UUIDs", LessonType.SYNTAX)
        self.manager.add_lesson("Fiscal year Oct", LessonType.BUSINESS)
        self.manager.add_lesson("Project Alpha deprecated", LessonType.BUSINESS)
        
        # Verify initial state
        self.assertEqual(len(self.manager.vector_store), 4)
        
        # Run upgrade purge
        result = self.manager.run_upgrade_purge("gpt-5")
        
        # Verify SYNTAX lessons were purged
        self.assertEqual(result["purged_count"], 2)
        self.assertEqual(result["retained_count"], 2)
        self.assertEqual(result["new_model_version"], "gpt-5")
        
        # Verify only BUSINESS lessons remain
        remaining_lessons = self.manager.vector_store
        self.assertEqual(len(remaining_lessons), 2)
        for lesson in remaining_lessons:
            self.assertEqual(lesson["type"], LessonType.BUSINESS)
    
    def test_upgrade_purge_preserves_business(self):
        """Test that business lessons are preserved on upgrade."""
        self.manager.add_lesson("Fiscal year starts Oct", LessonType.BUSINESS)
        self.manager.add_lesson("Medical advice prohibited", LessonType.BUSINESS)
        
        result = self.manager.run_upgrade_purge("gpt-5")
        
        # No lessons should be purged
        self.assertEqual(result["purged_count"], 0)
        self.assertEqual(result["retained_count"], 2)
    
    def test_get_lesson_count(self):
        """Test lesson count by type."""
        self.manager.add_lesson("Lesson 1", LessonType.SYNTAX)
        self.manager.add_lesson("Lesson 2", LessonType.SYNTAX)
        self.manager.add_lesson("Lesson 3", LessonType.BUSINESS)
        self.manager.add_lesson("Lesson 4", LessonType.ONE_OFF)
        
        counts = self.manager.get_lesson_count()
        
        self.assertEqual(counts[LessonType.SYNTAX], 2)
        self.assertEqual(counts[LessonType.BUSINESS], 1)
        self.assertEqual(counts[LessonType.ONE_OFF], 1)
    
    def test_lesson_metadata(self):
        """Test that lessons include proper metadata."""
        self.manager.add_lesson(
            "Test lesson",
            LessonType.BUSINESS
        )
        
        lesson = self.manager.vector_store[0]
        
        # Verify metadata fields
        self.assertIn("text", lesson)
        self.assertIn("type", lesson)
        self.assertIn("model_version", lesson)
        self.assertIn("created_at", lesson)
        self.assertIsInstance(lesson["created_at"], datetime)


class TestIntegration(unittest.TestCase):
    """Integration tests combining the reference implementations."""
    
    def test_full_workflow(self):
        """Test complete workflow: audit -> diagnose -> store lesson."""
        # Step 1: Audit detects laziness
        auditor = SimpleAuditor()
        agent_response = "No data found."
        needs_intervention = auditor.audit_response(agent_response, None)
        self.assertTrue(needs_intervention)
        
        # Step 2: Teacher diagnoses the issue
        diagnosis = asyncio.run(diagnose_failure(
            "Find user records",
            agent_response,
            "search_users(limit=10)"
        ))
        self.assertIn("lesson_patch", diagnosis)
        
        # Step 3: Store the lesson
        manager = MemoryManager()
        manager.add_lesson(
            diagnosis["lesson_patch"],
            LessonType.BUSINESS  # Competence patches are business context
        )
        
        # Verify lesson stored
        business_lessons = manager.get_lessons_by_type(LessonType.BUSINESS)
        self.assertEqual(len(business_lessons), 1)
        self.assertIn("not found", business_lessons[0]["text"].lower())


if __name__ == "__main__":
    unittest.main()
