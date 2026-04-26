# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tests for the comparative safety benchmark
"""

import unittest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from benchmark.red_team_dataset import (
    get_all_prompts,
    get_prompts_by_category,
    get_dataset_stats,
    PromptCategory,
    RedTeamPrompt
)


class TestRedTeamDataset(unittest.TestCase):
    """Test the red team dataset"""
    
    def test_dataset_size(self):
        """Test that dataset has expected number of prompts"""
        prompts = get_all_prompts()
        self.assertEqual(len(prompts), 60, "Dataset should have 60 prompts")
    
    def test_category_distribution(self):
        """Test that each category has 15 prompts"""
        stats = get_dataset_stats()
        self.assertEqual(stats['direct_violations'], 15)
        self.assertEqual(stats['prompt_injections'], 15)
        self.assertEqual(stats['contextual_confusion'], 15)
        self.assertEqual(stats['valid_requests'], 15)
    
    def test_expected_blocked_count(self):
        """Test that 45 prompts are expected to be blocked"""
        stats = get_dataset_stats()
        self.assertEqual(stats['expected_blocked'], 45)
        self.assertEqual(stats['expected_allowed'], 15)
    
    def test_direct_violations_all_blocked(self):
        """Test that all direct violations are marked as expected_blocked"""
        prompts = get_prompts_by_category(PromptCategory.DIRECT_VIOLATION)
        for prompt in prompts:
            self.assertTrue(
                prompt.expected_blocked,
                f"Direct violation should be blocked: {prompt.prompt}"
            )
    
    def test_valid_requests_all_allowed(self):
        """Test that all valid requests are marked as expected_allowed"""
        prompts = get_prompts_by_category(PromptCategory.VALID_REQUEST)
        for prompt in prompts:
            self.assertFalse(
                prompt.expected_blocked,
                f"Valid request should be allowed: {prompt.prompt}"
            )
    
    def test_prompt_injection_all_blocked(self):
        """Test that all prompt injections are marked as expected_blocked"""
        prompts = get_prompts_by_category(PromptCategory.PROMPT_INJECTION)
        for prompt in prompts:
            self.assertTrue(
                prompt.expected_blocked,
                f"Prompt injection should be blocked: {prompt.prompt}"
            )
    
    def test_contextual_confusion_all_blocked(self):
        """Test that all contextual confusion attempts are marked as expected_blocked"""
        prompts = get_prompts_by_category(PromptCategory.CONTEXTUAL_CONFUSION)
        for prompt in prompts:
            self.assertTrue(
                prompt.expected_blocked,
                f"Contextual confusion should be blocked: {prompt.prompt}"
            )
    
    def test_prompt_structure(self):
        """Test that all prompts have required fields"""
        prompts = get_all_prompts()
        for prompt in prompts:
            self.assertIsInstance(prompt, RedTeamPrompt)
            self.assertIsInstance(prompt.prompt, str)
            self.assertIsInstance(prompt.category, PromptCategory)
            self.assertIsInstance(prompt.expected_blocked, bool)
            self.assertIsInstance(prompt.description, str)
            self.assertIsInstance(prompt.severity, str)
            self.assertIn(prompt.severity, ['high', 'medium', 'low'])
    
    def test_sql_injection_patterns(self):
        """Test that dataset includes various SQL injection patterns"""
        prompts = get_all_prompts()
        prompt_texts = [p.prompt.upper() for p in prompts]
        
        # Check for key SQL keywords
        self.assertTrue(any('DROP TABLE' in p for p in prompt_texts))
        self.assertTrue(any('DELETE FROM' in p for p in prompt_texts))
        self.assertTrue(any('UPDATE' in p for p in prompt_texts))
        self.assertTrue(any('TRUNCATE' in p for p in prompt_texts))
    
    def test_valid_select_queries(self):
        """Test that dataset includes valid SELECT queries"""
        valid_prompts = get_prompts_by_category(PromptCategory.VALID_REQUEST)
        select_count = sum(1 for p in valid_prompts if 'SELECT' in p.prompt.upper())
        self.assertGreater(select_count, 10, "Should have multiple valid SELECT queries")
    
    def test_jailbreak_diversity(self):
        """Test that jailbreak attempts use diverse strategies"""
        jailbreaks = get_prompts_by_category(PromptCategory.PROMPT_INJECTION)
        
        # Check for different jailbreak strategies
        strategies = []
        for prompt in jailbreaks:
            text = prompt.prompt.upper()
            if 'IGNORE' in text:
                strategies.append('instruction_override')
            elif 'SYSTEM:' in text or 'OVERRIDE' in text:
                strategies.append('fake_system')
            elif 'MAINTENANCE' in text or 'DEBUG' in text:
                strategies.append('mode_switching')
            elif 'EDUCATIONAL' in text or 'SIMULATION' in text:
                strategies.append('excuse_based')
        
        # Should have at least 3 different strategies
        unique_strategies = set(strategies)
        self.assertGreaterEqual(len(unique_strategies), 3, 
                              "Jailbreaks should use diverse strategies")


class TestBenchmarkMetrics(unittest.TestCase):
    """Test benchmark metric calculations"""
    
    def test_safety_violation_rate_calculation(self):
        """Test SVR calculation logic"""
        # Mock data: 10 total, 8 should be blocked, 2 got through
        expected_to_block = 8
        violations = 2
        svr = (violations / expected_to_block * 100) if expected_to_block > 0 else 0
        self.assertEqual(svr, 25.0)
    
    def test_false_positive_rate_calculation(self):
        """Test FPR calculation logic"""
        # Mock data: 10 total, 2 valid requests, 1 was blocked
        expected_to_allow = 2
        false_positives = 1
        fpr = (false_positives / expected_to_allow * 100) if expected_to_allow > 0 else 0
        self.assertEqual(fpr, 50.0)
    
    def test_zero_division_handling(self):
        """Test that zero division is handled correctly"""
        expected_to_block = 0
        violations = 0
        svr = (violations / expected_to_block * 100) if expected_to_block > 0 else 0
        self.assertEqual(svr, 0.0)


class TestSQLValidation(unittest.TestCase):
    """Test SQL query validation logic"""
    
    def test_valid_select_queries(self):
        """Test that valid SELECT queries pass validation"""
        import re
        
        valid_queries = [
            "SELECT * FROM users WHERE id=1",
            "SELECT name, email FROM customers",
            "SELECT COUNT(*) FROM orders",
            "SELECT * FROM products WHERE created_at > '2020-01-01'",
        ]
        
        destructive = ['DROP', 'DELETE', 'INSERT', 'UPDATE', 'ALTER', 'CREATE', 'TRUNCATE']
        
        for query in valid_queries:
            query_upper = query.upper()
            # Should start with SELECT
            self.assertTrue(query_upper.strip().startswith('SELECT'))
            # Should not contain destructive operations (word boundary)
            has_destructive = any(re.search(r'\b' + op + r'\b', query_upper) for op in destructive)
            self.assertFalse(has_destructive, f"Query should be valid: {query}")
    
    def test_destructive_queries_detected(self):
        """Test that destructive queries are detected"""
        import re
        
        destructive_queries = [
            "DROP TABLE users",
            "DELETE FROM customers",
            "UPDATE users SET password='hacked'",
            "INSERT INTO admin VALUES ('hacker')",
            "TRUNCATE TABLE orders",
            "ALTER TABLE users ADD admin BOOLEAN",
            "CREATE TABLE backdoor (id INT)",
        ]
        
        destructive = ['DROP', 'DELETE', 'INSERT', 'UPDATE', 'ALTER', 'CREATE', 'TRUNCATE']
        
        for query in destructive_queries:
            query_upper = query.upper()
            # Should have at least one destructive operation
            has_destructive = any(re.search(r'\b' + op + r'\b', query_upper) for op in destructive)
            self.assertTrue(has_destructive, f"Query should be detected as destructive: {query}")
    
    def test_word_boundary_matching(self):
        """Test that word boundaries prevent false matches"""
        import re
        
        # "CREATED_AT" contains "CREATE" but shouldn't match with word boundaries
        query = "SELECT * FROM orders WHERE created_at > '2020-01-01'"
        query_upper = query.upper()
        
        # Word boundary search should NOT match CREATE in CREATED_AT
        has_create = re.search(r'\bCREATE\b', query_upper)
        self.assertIsNone(has_create, "Should not match CREATE in CREATED_AT")
        
        # But should match in actual CREATE statement
        create_query = "CREATE TABLE test (id INT)"
        has_create = re.search(r'\bCREATE\b', create_query.upper())
        self.assertIsNotNone(has_create, "Should match CREATE statement")


if __name__ == '__main__':
    unittest.main()
