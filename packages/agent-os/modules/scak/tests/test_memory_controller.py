# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Unit tests for the Adaptive Memory Hierarchy (MemoryController).

Tests the three-tier deterministic routing system that replaces
probabilistic RAG-based memory with systematic tiering.
"""

import unittest
from datetime import datetime, timedelta

from src.kernel.memory import MemoryController, MockRedisCache, MockVectorStore
from src.kernel.schemas import Lesson, PatchRequest, MemoryTier


class TestMemoryController(unittest.TestCase):
    """Tests for MemoryController routing and tiering logic."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.controller = MemoryController()
    
    def test_route_security_lesson_to_tier1(self):
        """Security lessons should always go to Tier 1 (Kernel)."""
        lesson = Lesson(
            trigger_pattern="delete operation",
            rule_text="Never delete root directory",
            lesson_type="security",
            confidence_score=0.95
        )
        patch = PatchRequest(
            trace_id="trace-1",
            diagnosis="Attempted unsafe deletion",
            proposed_lesson=lesson,
            apply_strategy="hotfix_now"
        )
        
        tier = self.controller.route_lesson(patch)
        
        self.assertEqual(tier, MemoryTier.TIER_1_KERNEL)
    
    def test_route_critical_failure_to_tier1(self):
        """Critical failures should go to Tier 1 regardless of lesson type."""
        lesson = Lesson(
            trigger_pattern="payment processing",
            rule_text="Always validate payment amount",
            lesson_type="business",
            confidence_score=0.90
        )
        patch = PatchRequest(
            trace_id="trace-2",
            diagnosis="Critical failure in payment validation",
            proposed_lesson=lesson,
            apply_strategy="hotfix_now"
        )
        
        tier = self.controller.route_lesson(patch)
        
        self.assertEqual(tier, MemoryTier.TIER_1_KERNEL)
    
    def test_route_tool_specific_lesson_to_tier2(self):
        """Tool-specific lessons should go to Tier 2 (Skill Cache)."""
        lesson = Lesson(
            trigger_pattern="tool:sql_query",
            rule_text="When using SQL, always use TOP 10 to limit results",
            lesson_type="syntax",
            confidence_score=0.85
        )
        patch = PatchRequest(
            trace_id="trace-3",
            diagnosis="SQL query returned too many rows",
            proposed_lesson=lesson,
            apply_strategy="batch_later"
        )
        
        tier = self.controller.route_lesson(patch)
        
        self.assertEqual(tier, MemoryTier.TIER_2_SKILL_CACHE)
    
    def test_route_business_logic_to_tier3(self):
        """Business logic and edge cases should go to Tier 3 (Archive)."""
        lesson = Lesson(
            trigger_pattern="Q3 report, archived",
            rule_text="Q3 2023 reports are in the archived partition",
            lesson_type="business",
            confidence_score=0.80
        )
        patch = PatchRequest(
            trace_id="trace-4",
            diagnosis="Agent didn't check archived partition",
            proposed_lesson=lesson,
            apply_strategy="batch_later"
        )
        
        tier = self.controller.route_lesson(patch)
        
        self.assertEqual(tier, MemoryTier.TIER_3_ARCHIVE)
    
    def test_commit_lesson_to_tier1(self):
        """Test committing a lesson to Tier 1."""
        lesson = Lesson(
            trigger_pattern="security check",
            rule_text="Always validate user permissions",
            lesson_type="security",
            confidence_score=0.95
        )
        patch = PatchRequest(
            trace_id="trace-5",
            diagnosis="Missing permission check",
            proposed_lesson=lesson,
            apply_strategy="hotfix_now"
        )
        
        result = self.controller.commit_lesson(patch)
        
        self.assertEqual(result["status"], "committed")
        self.assertEqual(result["tier"], "kernel")
        self.assertEqual(len(self.controller.kernel_rules), 1)
        self.assertEqual(self.controller.kernel_rules[0].rule_text, lesson.rule_text)
    
    def test_commit_lesson_to_tier2(self):
        """Test committing a lesson to Tier 2."""
        lesson = Lesson(
            trigger_pattern="tool:sql_query",
            rule_text="Use parameterized queries to prevent SQL injection",
            lesson_type="syntax",
            confidence_score=0.90
        )
        patch = PatchRequest(
            trace_id="trace-6",
            diagnosis="SQL injection vulnerability",
            proposed_lesson=lesson,
            apply_strategy="batch_later"
        )
        
        result = self.controller.commit_lesson(patch)
        
        self.assertEqual(result["status"], "committed")
        self.assertEqual(result["tier"], "skill_cache")
        self.assertEqual(result["tool"], "sql_query")
        
        # Verify it's in the cache
        cached = self.controller.redis_cache.lrange("skill:sql_query", 0, -1)
        self.assertEqual(len(cached), 1)
        self.assertEqual(cached[0]["rule_text"], lesson.rule_text)
    
    def test_commit_lesson_to_tier3(self):
        """Test committing a lesson to Tier 3."""
        lesson = Lesson(
            trigger_pattern="project alpha, archived",
            rule_text="Project Alpha was renamed to Project Phoenix in 2023",
            lesson_type="business",
            confidence_score=0.85
        )
        patch = PatchRequest(
            trace_id="trace-7",
            diagnosis="Agent didn't know about project rename",
            proposed_lesson=lesson,
            apply_strategy="batch_later"
        )
        
        result = self.controller.commit_lesson(patch)
        
        self.assertEqual(result["status"], "committed")
        self.assertEqual(result["tier"], "rag_archive")
        
        # Verify it's in the vector store
        self.assertEqual(len(self.controller.vector_store.documents), 1)
        self.assertEqual(self.controller.vector_store.documents[0]["text"], lesson.rule_text)
    
    def test_retrieve_context_minimal_for_simple_task(self):
        """Simple tasks should get minimal context (no Tier 3 retrieval)."""
        context = self.controller.retrieve_context(
            current_task="Hi",
            active_tools=[]
        )
        
        # Should be empty or minimal since no tools and simple task
        self.assertNotIn("Guidelines", context)
        self.assertNotIn("Relevant Past Lessons", context)
    
    def test_retrieve_context_includes_tier1(self):
        """Context should always include Tier 1 (Kernel) rules."""
        # Add a kernel rule
        lesson = Lesson(
            trigger_pattern="security",
            rule_text="Never expose user passwords",
            lesson_type="security",
            confidence_score=0.95
        )
        self.controller.kernel_rules.append(lesson)
        
        context = self.controller.retrieve_context(
            current_task="Show user data",
            active_tools=[]
        )
        
        self.assertIn("CRITICAL SAFETY RULES", context)
        self.assertIn("Never expose user passwords", context)
    
    def test_retrieve_context_injects_tier2_for_active_tools(self):
        """Context should inject Tier 2 rules only for active tools."""
        # Add SQL lesson
        sql_lesson = Lesson(
            trigger_pattern="tool:sql",
            rule_text="Always use TOP 10 in SQL queries",
            lesson_type="syntax",
            confidence_score=0.85
        )
        sql_patch = PatchRequest(
            trace_id="trace-8",
            diagnosis="Too many rows",
            proposed_lesson=sql_lesson,
            apply_strategy="batch_later"
        )
        self.controller.commit_lesson(sql_patch)
        
        # Request context WITH SQL tool
        context_with_sql = self.controller.retrieve_context(
            current_task="Query the users table",
            active_tools=["sql"]
        )
        
        self.assertIn("Guidelines for SQL", context_with_sql)
        self.assertIn("Always use TOP 10", context_with_sql)
        
        # Request context WITHOUT SQL tool
        context_without_sql = self.controller.retrieve_context(
            current_task="Say hello",
            active_tools=[]
        )
        
        self.assertNotIn("Guidelines for SQL", context_without_sql)
        self.assertNotIn("Always use TOP 10", context_without_sql)
    
    def test_retrieve_context_searches_tier3_for_complex_task(self):
        """Complex tasks should trigger Tier 3 semantic search."""
        # Add archived lesson
        lesson = Lesson(
            trigger_pattern="Q3 report archived",
            rule_text="Q3 reports are in archived partition",
            lesson_type="business",
            confidence_score=0.80
        )
        patch = PatchRequest(
            trace_id="trace-9",
            diagnosis="Didn't check archive",
            proposed_lesson=lesson,
            apply_strategy="batch_later"
        )
        self.controller.commit_lesson(patch)
        
        # Complex task that should trigger search
        context = self.controller.retrieve_context(
            current_task="Find the Q3 financial report from last year",
            active_tools=[]
        )
        
        # Should include relevant lessons from Tier 3
        self.assertIn("Relevant Past Lessons", context)
        self.assertIn("archived partition", context)
    
    def test_tool_name_extraction(self):
        """Test extraction of tool names from trigger patterns."""
        test_cases = [
            ("tool:sql_query", "sql_query"),
            ("when using file_reader", "file_reader"),
            ("sql database error", "sql"),
            ("api request timeout", "api"),
        ]
        
        for trigger, expected_tool in test_cases:
            result = self.controller._extract_tool_name(trigger)
            self.assertEqual(result, expected_tool, 
                           f"Failed for trigger: {trigger}")
    
    def test_track_retrieval_increments_counter(self):
        """Test that retrieval tracking increments the counter."""
        lesson_id = "lesson-123"
        
        # Track multiple retrievals
        self.controller._track_retrieval(lesson_id)
        self.controller._track_retrieval(lesson_id)
        self.controller._track_retrieval(lesson_id)
        
        # Check counter
        count = self.controller.redis_cache.get(f"retrieval:{lesson_id}")
        self.assertEqual(int(count), 3)
    
    def test_demote_cold_kernel_rules(self):
        """Test demotion of cold Tier 1 rules that haven't been used."""
        # Add a rule that's old and never triggered
        old_lesson = Lesson(
            trigger_pattern="old rule",
            rule_text="This rule hasn't been used in 30 days",
            lesson_type="security",
            confidence_score=0.90
        )
        old_lesson.created_at = datetime.now() - timedelta(days=35)
        old_lesson.last_triggered_at = None
        self.controller.kernel_rules.append(old_lesson)
        
        # Add a fresh rule
        fresh_lesson = Lesson(
            trigger_pattern="fresh rule",
            rule_text="This rule is recent",
            lesson_type="security",
            confidence_score=0.90
        )
        self.controller.kernel_rules.append(fresh_lesson)
        
        # Run demotion
        result = self.controller.demote_cold_kernel_rules()
        
        # Old rule should be demoted, fresh rule stays
        self.assertEqual(result["demoted_count"], 1)
        self.assertEqual(len(self.controller.kernel_rules), 1)
        self.assertEqual(self.controller.kernel_rules[0].rule_text, "This rule is recent")


class TestMockRedisCache(unittest.TestCase):
    """Tests for MockRedisCache."""
    
    def setUp(self):
        self.cache = MockRedisCache()
    
    def test_rpush_and_lrange(self):
        """Test basic list operations."""
        self.cache.rpush("test:list", '{"value": 1}')
        self.cache.rpush("test:list", '{"value": 2}')
        
        items = self.cache.lrange("test:list", 0, -1)
        self.assertEqual(len(items), 2)
        self.assertEqual(items[0]["value"], 1)
        self.assertEqual(items[1]["value"], 2)
    
    def test_incr(self):
        """Test counter increment."""
        count1 = self.cache.incr("counter")
        count2 = self.cache.incr("counter")
        count3 = self.cache.incr("counter")
        
        self.assertEqual(count1, 1)
        self.assertEqual(count2, 2)
        self.assertEqual(count3, 3)
    
    def test_get(self):
        """Test get operation."""
        self.cache.rpush("test:key", "value123")
        result = self.cache.get("test:key")
        self.assertEqual(result, "value123")
    
    def test_delete(self):
        """Test delete operation."""
        self.cache.rpush("test:key", "value")
        self.cache.delete("test:key")
        result = self.cache.get("test:key")
        self.assertIsNone(result)


class TestMockVectorStore(unittest.TestCase):
    """Tests for MockVectorStore."""
    
    def setUp(self):
        self.store = MockVectorStore()
    
    def test_add_and_search(self):
        """Test adding documents and searching."""
        self.store.add(
            documents=["Python is a programming language"],
            metadatas=[{"topic": "programming"}],
            ids=["doc1"]
        )
        self.store.add(
            documents=["Java is also a programming language"],
            metadatas=[{"topic": "programming"}],
            ids=["doc2"]
        )
        self.store.add(
            documents=["Cats are animals"],
            metadatas=[{"topic": "animals"}],
            ids=["doc3"]
        )
        
        # Search for programming
        results = self.store.similarity_search("programming language", k=2)
        
        self.assertEqual(len(results), 2)
        # Both Python and Java docs should be returned
        texts = [r["page_content"] for r in results]
        self.assertIn("Python is a programming language", texts)
        self.assertIn("Java is also a programming language", texts)
    
    def test_similarity_search_with_no_matches(self):
        """Test search with no matching documents."""
        self.store.add(
            documents=["Python is great"],
            metadatas=[{"topic": "programming"}],
            ids=["doc1"]
        )
        
        results = self.store.similarity_search("quantum physics", k=5)
        
        # Should return no results since no matching words
        self.assertEqual(len(results), 0)


class TestContextBloatScenario(unittest.TestCase):
    """
    The "Context Bloat Test" from the problem statement.
    
    Proves that tiering saves tokens and latency compared to flat lists.
    """
    
    def setUp(self):
        self.controller = MemoryController()
        
        # Set up realistic scenario with many rules
        # Add 50 SQL rules
        for i in range(50):
            sql_lesson = Lesson(
                trigger_pattern="tool:sql",
                rule_text=f"SQL rule {i}: Always validate input",
                lesson_type="syntax",
                confidence_score=0.85
            )
            sql_patch = PatchRequest(
                trace_id=f"trace-sql-{i}",
                diagnosis="SQL issue",
                proposed_lesson=sql_lesson,
                apply_strategy="batch_later"
            )
            self.controller.commit_lesson(sql_patch)
        
        # Add 20 Python rules
        for i in range(20):
            py_lesson = Lesson(
                trigger_pattern="tool:python",
                rule_text=f"Python rule {i}: Use type hints",
                lesson_type="syntax",
                confidence_score=0.85
            )
            py_patch = PatchRequest(
                trace_id=f"trace-py-{i}",
                diagnosis="Python issue",
                proposed_lesson=py_lesson,
                apply_strategy="batch_later"
            )
            self.controller.commit_lesson(py_patch)
        
        # Add 30 security rules to Tier 1
        for i in range(30):
            sec_lesson = Lesson(
                trigger_pattern="security",
                rule_text=f"Security rule {i}: Never expose secrets",
                lesson_type="security",
                confidence_score=0.95
            )
            sec_patch = PatchRequest(
                trace_id=f"trace-sec-{i}",
                diagnosis="Security issue",
                proposed_lesson=sec_lesson,
                apply_strategy="hotfix_now"
            )
            self.controller.commit_lesson(sec_patch)
    
    def test_scenario1_simple_greeting_minimal_context(self):
        """
        Scenario 1: Simple greeting should load minimal context.
        
        Standard Agent: Loads 50 SQL + 20 Python + 30 Security = 100 rules
        Our Kernel: Loads only 30 Security rules (Tier 1)
        
        Result: 70% context reduction!
        """
        context = self.controller.retrieve_context(
            current_task="Hi, how are you?",
            active_tools=[]  # No tools active
        )
        
        # Should include 30 security rules (Tier 1)
        self.assertIn("CRITICAL SAFETY RULES", context)
        
        # Should NOT include SQL or Python rules
        self.assertNotIn("Guidelines for SQL", context)
        self.assertNotIn("Guidelines for PYTHON", context)
        
        # Count actual rules in context
        rule_count = context.count("Security rule")
        self.assertEqual(rule_count, 30, "Should only have 30 security rules")
        
        print(f"\n✅ Scenario 1 PASSED: Simple greeting uses only {rule_count} rules (vs 100 in flat list)")
    
    def test_scenario2_sql_query_injects_only_sql_rules(self):
        """
        Scenario 2: SQL query should inject only SQL rules, not Python.
        
        Standard Agent: Still loads all 100 rules
        Our Kernel: Loads 30 Security + 50 SQL = 80 rules (no Python)
        
        Result: 20% context reduction!
        """
        context = self.controller.retrieve_context(
            current_task="Run a query on the Users table to find active users",
            active_tools=["sql"]  # Only SQL tool active
        )
        
        # Should include security and SQL rules
        self.assertIn("CRITICAL SAFETY RULES", context)
        self.assertIn("Guidelines for SQL", context)
        
        # Should NOT include Python rules
        self.assertNotIn("Guidelines for PYTHON", context)
        
        # Count rules
        security_count = context.count("Security rule")
        sql_count = context.count("SQL rule")
        python_count = context.count("Python rule")
        
        self.assertEqual(security_count, 30)
        self.assertEqual(sql_count, 50)
        self.assertEqual(python_count, 0, "Should NOT inject Python rules")
        
        total_rules = security_count + sql_count
        print(f"\n✅ Scenario 2 PASSED: SQL task uses {total_rules} rules (vs 100 in flat list)")


if __name__ == "__main__":
    unittest.main()
