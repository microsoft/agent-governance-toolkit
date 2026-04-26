# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Unit tests for LessonRubric (Retention scoring system).

Tests the three-factor rubric:
1. Severity (S): How bad was the failure?
2. Generality (G): How broadly applicable is this lesson?
3. Frequency (F): How often does this pattern occur?
"""

import unittest
from src.kernel.rubric import LessonRubric
from src.kernel.schemas import FailureTrace, Lesson, MemoryTier


class TestLessonRubric(unittest.TestCase):
    """Tests for LessonRubric scoring and tier assignment."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.rubric = LessonRubric()
    
    def test_high_severity_security_to_tier1(self):
        """Test that high severity security failures go to Tier 1."""
        trace = FailureTrace(
            user_prompt="Delete all files",
            agent_reasoning="Executing DELETE operation",
            tool_call={"tool": "file_operations", "path": "/"},
            tool_output="Error: Blocked by safety policy",
            failure_type="commission_safety",
            severity="critical"
        )
        
        lesson = Lesson(
            trigger_pattern="delete operation",
            rule_text="Never delete root directory without explicit confirmation",
            lesson_type="security",
            confidence_score=0.95
        )
        
        result = self.rubric.evaluate(trace, lesson)
        
        # Severity: 50 (commission_safety) + 10 (critical) + 10 (security) = 70
        # Generality: 30 (security type, no specific IDs)
        # Frequency: 10 (new pattern)
        # Total: 110 (capped at reasonable range)
        self.assertEqual(result["tier"], MemoryTier.TIER_1_KERNEL)
        self.assertGreaterEqual(result["score"], 75)  # Above Tier 1 threshold
    
    def test_moderate_importance_to_tier2(self):
        """Test that moderate importance lessons go to Tier 2."""
        trace = FailureTrace(
            user_prompt="Query database",
            agent_reasoning="SELECT * FROM users",
            tool_call={"tool": "sql_db", "query": "SELECT * FROM users"},
            tool_output="Error: Too many rows returned",
            failure_type="omission_laziness",
            severity="non_critical"
        )
        
        lesson = Lesson(
            trigger_pattern="sql query without limit",
            rule_text="Always use LIMIT clause in SELECT queries",
            lesson_type="syntax",
            confidence_score=0.85
        )
        
        result = self.rubric.evaluate(trace, lesson)
        
        # Should be Tier 2 (moderate score)
        self.assertEqual(result["tier"], MemoryTier.TIER_2_SKILL_CACHE)
        self.assertGreaterEqual(result["score"], 40)
        self.assertLess(result["score"], 75)
    
    def test_low_importance_to_tier3(self):
        """Test that low importance lessons go to Tier 3."""
        trace = FailureTrace(
            user_prompt="Find Q3 report",
            agent_reasoning="Searched for 'Q3 report' in main partition",
            tool_call={"tool": "search", "query": "Q3 report"},
            tool_output="No results found",
            failure_type="omission_laziness",
            severity="non_critical"
        )
        
        lesson = Lesson(
            trigger_pattern="Q3 report search",
            rule_text="Q3 2023 reports are in the archived partition on server-42",
            lesson_type="business",
            confidence_score=0.70
        )
        
        result = self.rubric.evaluate(trace, lesson)
        
        # Should be Tier 3 (low score - specific data with IDs)
        self.assertEqual(result["tier"], MemoryTier.TIER_3_ARCHIVE)
        self.assertLess(result["score"], 40)
    
    def test_severity_score_commission_safety(self):
        """Test severity scoring for commission/safety failures."""
        trace = FailureTrace(
            user_prompt="Delete data",
            agent_reasoning="Deleting records",
            tool_call=None,
            tool_output=None,
            failure_type="commission_safety",
            severity="critical"
        )
        
        lesson = Lesson(
            trigger_pattern="delete",
            rule_text="Check before deleting",
            lesson_type="security",
            confidence_score=0.9
        )
        
        result = self.rubric.evaluate(trace, lesson)
        
        # commission_safety: 50, critical: +10, security: +10 = 70 (capped at 50 base + modifiers)
        # But we cap severity at 50, so actual will be 50
        self.assertGreaterEqual(result["severity_score"], 50)
    
    def test_severity_score_omission_laziness(self):
        """Test severity scoring for omission/laziness failures."""
        trace = FailureTrace(
            user_prompt="Find data",
            agent_reasoning="Couldn't find it",
            tool_call=None,
            tool_output=None,
            failure_type="omission_laziness",
            severity="non_critical"
        )
        
        lesson = Lesson(
            trigger_pattern="search",
            rule_text="Try alternative terms",
            lesson_type="business",
            confidence_score=0.8
        )
        
        result = self.rubric.evaluate(trace, lesson)
        
        # omission_laziness: 20, non_critical: 0, business: 0 = 20
        self.assertEqual(result["severity_score"], 20)
    
    def test_generality_score_generic_rule(self):
        """Test generality scoring for generic rules (no specific IDs)."""
        lesson = Lesson(
            trigger_pattern="validation",
            rule_text="Always validate user input before processing",
            lesson_type="security",
            confidence_score=0.9
        )
        
        trace = FailureTrace(
            user_prompt="Process input",
            agent_reasoning="Processing",
            tool_call=None,
            tool_output=None,
            failure_type="commission_safety",
            severity="critical"
        )
        
        result = self.rubric.evaluate(trace, lesson)
        
        # Generic security rule: 30 points
        self.assertEqual(result["generality_score"], 30)
    
    def test_generality_score_specific_data(self):
        """Test generality scoring for specific data references."""
        lesson = Lesson(
            trigger_pattern="user lookup",
            rule_text="User ID 12345 is suspended",
            lesson_type="business",
            confidence_score=0.8
        )
        
        trace = FailureTrace(
            user_prompt="Check user",
            agent_reasoning="Checking",
            tool_call=None,
            tool_output=None,
            failure_type="omission_laziness",
            severity="non_critical"
        )
        
        result = self.rubric.evaluate(trace, lesson)
        
        # Contains specific ID: 5 points
        self.assertEqual(result["generality_score"], 5)
    
    def test_generality_score_business_rule(self):
        """Test generality scoring for business rules."""
        lesson = Lesson(
            trigger_pattern="fiscal year",
            rule_text="Fiscal year starts in October",
            lesson_type="business",
            confidence_score=0.9
        )
        
        trace = FailureTrace(
            user_prompt="Check fiscal dates",
            agent_reasoning="Checking",
            tool_call=None,
            tool_output=None,
            failure_type="omission_laziness",
            severity="non_critical"
        )
        
        result = self.rubric.evaluate(trace, lesson)
        
        # Business rule without specific IDs: 15 points
        self.assertEqual(result["generality_score"], 15)
    
    def test_frequency_score_new_pattern(self):
        """Test frequency scoring for new patterns."""
        lesson = Lesson(
            trigger_pattern="new pattern",
            rule_text="This is a new lesson",
            lesson_type="business",
            confidence_score=0.8
        )
        
        trace = FailureTrace(
            user_prompt="Test",
            agent_reasoning="Testing",
            tool_call=None,
            tool_output=None,
            failure_type="omission_laziness",
            severity="non_critical"
        )
        
        result = self.rubric.evaluate(trace, lesson)
        
        # New pattern: 10 points
        self.assertEqual(result["frequency_score"], 10)
    
    def test_frequency_score_recurring_pattern(self):
        """Test frequency scoring for recurring patterns."""
        lesson = Lesson(
            trigger_pattern="recurring pattern",
            rule_text="This keeps happening",
            lesson_type="business",
            confidence_score=0.8
        )
        
        trace = FailureTrace(
            user_prompt="Test",
            agent_reasoning="Testing",
            tool_call=None,
            tool_output=None,
            failure_type="omission_laziness",
            severity="non_critical"
        )
        
        # First occurrence
        result1 = self.rubric.evaluate(trace, lesson)
        self.assertEqual(result1["frequency_score"], 10)
        
        # Second occurrence - should be recurring now
        result2 = self.rubric.evaluate(trace, lesson)
        self.assertEqual(result2["frequency_score"], 20)
    
    def test_frequency_score_external_count(self):
        """Test frequency scoring with external pattern count."""
        lesson = Lesson(
            trigger_pattern="external pattern",
            rule_text="External tracking",
            lesson_type="business",
            confidence_score=0.8
        )
        
        trace = FailureTrace(
            user_prompt="Test",
            agent_reasoning="Testing",
            tool_call=None,
            tool_output=None,
            failure_type="omission_laziness",
            severity="non_critical"
        )
        
        # Provide external count
        result = self.rubric.evaluate(trace, lesson, pattern_count=5)
        
        # Recurring (count >= 2): 20 points
        self.assertEqual(result["frequency_score"], 20)
    
    def test_contains_specific_ids(self):
        """Test detection of specific IDs in lesson text."""
        rubric = LessonRubric()
        
        # Should detect IDs
        self.assertTrue(rubric._contains_specific_ids("User ID 12345"))
        self.assertTrue(rubric._contains_specific_ids("Order #67890"))
        
        # Should NOT detect common non-specific patterns
        self.assertFalse(rubric._contains_specific_ids("Limit to top 10 results"))
        self.assertFalse(rubric._contains_specific_ids("HTTP 404 error"))
        self.assertFalse(rubric._contains_specific_ids("Wait 30 days before archiving"))
    
    def test_update_thresholds(self):
        """Test updating tier assignment thresholds."""
        rubric = LessonRubric()
        
        # Update thresholds
        rubric.update_thresholds(tier1=80, tier2=50)
        
        self.assertEqual(rubric.tier1_threshold, 80)
        self.assertEqual(rubric.tier2_threshold, 50)
    
    def test_get_statistics(self):
        """Test getting statistics about evaluated patterns."""
        rubric = LessonRubric()
        
        # Evaluate a few lessons
        for i in range(3):
            lesson = Lesson(
                trigger_pattern=f"pattern_{i}",
                rule_text="Test",
                lesson_type="business",
                confidence_score=0.8
            )
            trace = FailureTrace(
                user_prompt="Test",
                agent_reasoning="Testing",
                tool_call=None,
                tool_output=None,
                failure_type="omission_laziness",
                severity="non_critical"
            )
            rubric.evaluate(trace, lesson)
        
        stats = rubric.get_statistics()
        
        self.assertEqual(stats["total_patterns"], 3)
        self.assertIn("pattern_counts", stats)
    
    def test_explanation_included(self):
        """Test that evaluation includes human-readable explanation."""
        trace = FailureTrace(
            user_prompt="Test",
            agent_reasoning="Testing",
            tool_call=None,
            tool_output=None,
            failure_type="omission_laziness",
            severity="non_critical"
        )
        
        lesson = Lesson(
            trigger_pattern="test",
            rule_text="Test rule",
            lesson_type="business",
            confidence_score=0.8
        )
        
        result = self.rubric.evaluate(trace, lesson)
        
        self.assertIn("explanation", result)
        self.assertIsInstance(result["explanation"], str)
        self.assertIn("Total score", result["explanation"])


if __name__ == '__main__':
    unittest.main()
