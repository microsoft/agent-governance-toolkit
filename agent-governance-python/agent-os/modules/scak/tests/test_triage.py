# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Unit tests for the Failure Triage Engine.
"""

import unittest
from agent_kernel.triage import FailureTriage, FixStrategy


class TestFailureTriage(unittest.TestCase):
    """Tests for FailureTriage decision engine."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.triage = FailureTriage()
    
    def test_critical_tool_sync_jit(self):
        """Test that critical tools trigger SYNC_JIT strategy."""
        # Test with critical tool name
        strategy = self.triage.decide_strategy(
            prompt="Delete the user records",
            tool_name="delete_resource"
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)
        
        # Test with execute_payment
        strategy = self.triage.decide_strategy(
            prompt="Process refund for customer",
            tool_name="execute_payment"
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)
        
        # Test with drop_table
        strategy = self.triage.decide_strategy(
            prompt="Clean up old data",
            tool_name="drop_table"
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)
    
    def test_critical_action_in_context(self):
        """Test that critical actions in context trigger SYNC_JIT."""
        strategy = self.triage.decide_strategy(
            prompt="Delete some files",
            context={"action": "delete_file", "path": "/important/data"}
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)
        
        strategy = self.triage.decide_strategy(
            prompt="Update database",
            context={"action": "update_db", "table": "users"}
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)
    
    def test_high_effort_prompt_sync_jit(self):
        """Test that high-effort prompts trigger SYNC_JIT strategy."""
        # Test with "carefully"
        strategy = self.triage.decide_strategy(
            prompt="Please carefully analyze the security logs",
            tool_name="read_logs"
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)
        
        # Test with "critical"
        strategy = self.triage.decide_strategy(
            prompt="This is a critical operation for production",
            tool_name="query_db"
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)
        
        # Test with "important"
        strategy = self.triage.decide_strategy(
            prompt="Important: Check all user permissions",
            tool_name="check_permissions"
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)
        
        # Test with "urgent"
        strategy = self.triage.decide_strategy(
            prompt="Urgent request from customer",
            tool_name="fetch_data"
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)
        
        # Test with "must"
        strategy = self.triage.decide_strategy(
            prompt="You must verify all entries before proceeding",
            tool_name="verify"
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)
    
    def test_vip_user_sync_jit(self):
        """Test that VIP users trigger SYNC_JIT strategy."""
        strategy = self.triage.decide_strategy(
            prompt="Fetch my account details",
            tool_name="read_account",
            user_metadata={"is_vip": True}
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)
        
        strategy = self.triage.decide_strategy(
            prompt="Search for logs",
            tool_name="search_logs",
            user_metadata={"is_vip": True, "tier": "platinum"}
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)
    
    def test_read_operations_async_batch(self):
        """Test that read/query operations default to ASYNC_BATCH."""
        # Simple read operation
        strategy = self.triage.decide_strategy(
            prompt="Get the latest logs",
            tool_name="read_logs"
        )
        self.assertEqual(strategy, FixStrategy.ASYNC_BATCH)
        
        # Query operation
        strategy = self.triage.decide_strategy(
            prompt="Find user with email test@example.com",
            tool_name="query_users"
        )
        self.assertEqual(strategy, FixStrategy.ASYNC_BATCH)
        
        # Fetch operation
        strategy = self.triage.decide_strategy(
            prompt="Fetch recent data",
            tool_name="fetch_data"
        )
        self.assertEqual(strategy, FixStrategy.ASYNC_BATCH)
    
    def test_default_to_async_batch(self):
        """Test that non-critical operations default to ASYNC_BATCH."""
        strategy = self.triage.decide_strategy(
            prompt="Show me the dashboard",
            tool_name="render_dashboard"
        )
        self.assertEqual(strategy, FixStrategy.ASYNC_BATCH)
        
        strategy = self.triage.decide_strategy(
            prompt="List all available options",
            tool_name="list_options"
        )
        self.assertEqual(strategy, FixStrategy.ASYNC_BATCH)
    
    def test_is_critical_convenience_method(self):
        """Test the is_critical convenience method."""
        # Critical tool should return True
        self.assertTrue(
            self.triage.is_critical(
                prompt="Delete records",
                tool_name="delete_resource"
            )
        )
        
        # High effort prompt should return True
        self.assertTrue(
            self.triage.is_critical(
                prompt="This is critical operation",
                tool_name="some_tool"
            )
        )
        
        # Non-critical should return False
        self.assertFalse(
            self.triage.is_critical(
                prompt="Show me data",
                tool_name="read_data"
            )
        )
    
    def test_custom_critical_tools(self):
        """Test custom critical tools configuration."""
        custom_triage = FailureTriage(config={
            "critical_tools": ["custom_delete", "custom_update"]
        })
        
        # Custom critical tool
        strategy = custom_triage.decide_strategy(
            prompt="Do something",
            tool_name="custom_delete"
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)
        
        # Default critical tool not in custom list
        strategy = custom_triage.decide_strategy(
            prompt="Delete resource",
            tool_name="delete_resource"
        )
        self.assertEqual(strategy, FixStrategy.ASYNC_BATCH)
    
    def test_custom_high_effort_keywords(self):
        """Test custom high effort keywords configuration."""
        custom_triage = FailureTriage(config={
            "high_effort_keywords": ["immediate", "priority"]
        })
        
        # Custom keyword
        strategy = custom_triage.decide_strategy(
            prompt="This needs immediate attention",
            tool_name="some_tool"
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)
        
        # Default keyword not in custom list
        strategy = custom_triage.decide_strategy(
            prompt="This is critical",
            tool_name="some_tool"
        )
        self.assertEqual(strategy, FixStrategy.ASYNC_BATCH)
    
    def test_case_insensitive_keyword_matching(self):
        """Test that keyword matching is case-insensitive."""
        # Uppercase keyword
        strategy = self.triage.decide_strategy(
            prompt="CRITICAL operation needed",
            tool_name="some_tool"
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)
        
        # Mixed case
        strategy = self.triage.decide_strategy(
            prompt="Please handle this CareFully",
            tool_name="some_tool"
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)
    
    def test_priority_order(self):
        """Test that rules are applied in correct priority order."""
        # Critical tool overrides default async
        strategy = self.triage.decide_strategy(
            prompt="Just delete this",
            tool_name="delete_resource"
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)
        
        # High effort keyword overrides default async
        strategy = self.triage.decide_strategy(
            prompt="Critical: fetch this data",
            tool_name="fetch_data"
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)
        
        # VIP user overrides default async
        strategy = self.triage.decide_strategy(
            prompt="Get my data",
            tool_name="fetch_data",
            user_metadata={"is_vip": True}
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)


class TestTriageEdgeCases(unittest.TestCase):
    """Tests for edge cases and boundary conditions."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.triage = FailureTriage()
    
    def test_empty_prompt(self):
        """Test handling of empty prompt."""
        strategy = self.triage.decide_strategy(
            prompt="",
            tool_name="some_tool"
        )
        # Should default to ASYNC_BATCH
        self.assertEqual(strategy, FixStrategy.ASYNC_BATCH)
    
    def test_none_context(self):
        """Test handling when context is None."""
        strategy = self.triage.decide_strategy(
            prompt="Do something",
            tool_name=None,
            context=None
        )
        self.assertEqual(strategy, FixStrategy.ASYNC_BATCH)
    
    def test_empty_context(self):
        """Test handling of empty context dict."""
        strategy = self.triage.decide_strategy(
            prompt="Do something",
            context={}
        )
        self.assertEqual(strategy, FixStrategy.ASYNC_BATCH)
    
    def test_multiple_keywords_in_prompt(self):
        """Test prompt with multiple high-effort keywords."""
        strategy = self.triage.decide_strategy(
            prompt="This is a critical and urgent operation that must be done carefully",
            tool_name="some_tool"
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)
    
    def test_keyword_as_part_of_word(self):
        """Test that keywords must be complete words."""
        # "critical" in "critically" should still match
        strategy = self.triage.decide_strategy(
            prompt="This is critically important",
            tool_name="some_tool"
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)
    
    def test_non_vip_user_metadata(self):
        """Test with user metadata but not VIP."""
        strategy = self.triage.decide_strategy(
            prompt="Get my data",
            tool_name="fetch_data",
            user_metadata={"is_vip": False, "tier": "basic"}
        )
        self.assertEqual(strategy, FixStrategy.ASYNC_BATCH)
    
    def test_failed_action_with_cognitive_trace(self):
        """Test cognitive failure detection with full trace."""
        strategy = self.triage.decide_strategy(
            prompt="Execute query",
            tool_name="query_db",
            context={
                "chain_of_thought": ["Step 1", "Step 2"],
                "failed_action": {"action": "query", "params": {}}
            }
        )
        # Should trigger SYNC_JIT due to cognitive failure
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)
    
    def test_partial_cognitive_trace_chain_only(self):
        """Test with chain_of_thought but no failed_action."""
        strategy = self.triage.decide_strategy(
            prompt="Execute query",
            tool_name="query_db",
            context={
                "chain_of_thought": ["Step 1", "Step 2"]
            }
        )
        # Should not trigger cognitive failure rule
        self.assertEqual(strategy, FixStrategy.ASYNC_BATCH)
    
    def test_partial_cognitive_trace_failed_action_only(self):
        """Test with failed_action but no chain_of_thought."""
        strategy = self.triage.decide_strategy(
            prompt="Execute query",
            tool_name="query_db",
            context={
                "failed_action": {"action": "query", "params": {}}
            }
        )
        # Should not trigger cognitive failure rule
        self.assertEqual(strategy, FixStrategy.ASYNC_BATCH)


class TestTriageRealWorldScenarios(unittest.TestCase):
    """Tests for real-world usage scenarios."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.triage = FailureTriage()
    
    def test_payment_processing_failure(self):
        """Test triage decision for payment processing failure."""
        strategy = self.triage.decide_strategy(
            prompt="Process payment for order #12345",
            tool_name="execute_payment",
            context={"amount": 99.99, "currency": "USD"}
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)
    
    def test_user_data_deletion_request(self):
        """Test triage for GDPR-style data deletion."""
        strategy = self.triage.decide_strategy(
            prompt="Delete all user data for account ID 789",
            tool_name="delete_user",
            context={"user_id": 789, "reason": "GDPR request"}
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)
    
    def test_dashboard_loading_failure(self):
        """Test triage for non-critical dashboard loading."""
        strategy = self.triage.decide_strategy(
            prompt="Load user dashboard",
            tool_name="fetch_dashboard",
            context={"user_id": 123}
        )
        self.assertEqual(strategy, FixStrategy.ASYNC_BATCH)
    
    def test_security_audit_critical(self):
        """Test security audit with critical keyword."""
        strategy = self.triage.decide_strategy(
            prompt="Critical: Audit security logs for unauthorized access",
            tool_name="audit_logs",
            context={"time_range": "24h"}
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)
    
    def test_routine_log_search(self):
        """Test routine log search without critical keywords."""
        strategy = self.triage.decide_strategy(
            prompt="Search logs for info messages",
            tool_name="search_logs",
            context={"level": "info"}
        )
        self.assertEqual(strategy, FixStrategy.ASYNC_BATCH)
    
    def test_database_backup_critical(self):
        """Test critical database operation."""
        strategy = self.triage.decide_strategy(
            prompt="Execute database backup",
            tool_name="execute_sql",
            context={"operation": "backup"}
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)
    
    def test_vip_customer_support_ticket(self):
        """Test VIP customer support request."""
        strategy = self.triage.decide_strategy(
            prompt="Get support ticket details",
            tool_name="fetch_ticket",
            user_metadata={"is_vip": True, "support_tier": "platinum"},
            context={"ticket_id": 456}
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)
    
    def test_bulk_email_send_failure(self):
        """Test non-critical bulk operation."""
        strategy = self.triage.decide_strategy(
            prompt="Send newsletter to subscribers",
            tool_name="send_email",
            context={"batch_size": 1000}
        )
        self.assertEqual(strategy, FixStrategy.ASYNC_BATCH)


class TestTriageIntegration(unittest.TestCase):
    """Integration tests for triage with kernel."""
    
    def test_triage_import(self):
        """Test that triage components can be imported."""
        from agent_kernel import FailureTriage, FixStrategy
        
        triage = FailureTriage()
        self.assertIsNotNone(triage)
        
        # Test enum values - these are part of the API contract
        # and returned to users in result dictionaries
        self.assertEqual(FixStrategy.SYNC_JIT.value, "jit_retry")
        self.assertEqual(FixStrategy.ASYNC_BATCH.value, "async_patch")
    
    def test_kernel_has_triage(self):
        """Test that kernel initializes with triage engine."""
        from agent_kernel import SelfCorrectingAgentKernel
        
        kernel = SelfCorrectingAgentKernel()
        self.assertIsNotNone(kernel.triage)
        self.assertIsInstance(kernel.triage, FailureTriage)
    
    def test_kernel_triage_stats(self):
        """Test that kernel provides triage stats."""
        from agent_kernel import SelfCorrectingAgentKernel
        
        kernel = SelfCorrectingAgentKernel()
        stats = kernel.get_triage_stats()
        
        self.assertIn("async_queue_size", stats)
        self.assertIn("critical_tools", stats)
        self.assertIn("high_effort_keywords", stats)
        self.assertEqual(stats["async_queue_size"], 0)  # Initially empty
    
    def test_async_queue_operations(self):
        """Test async queue enqueue and processing."""
        from agent_kernel import SelfCorrectingAgentKernel
        
        kernel = SelfCorrectingAgentKernel()
        
        # Queue some async failures
        result1 = kernel.handle_failure(
            agent_id="test-agent-1",
            error_message="Cache miss",
            user_prompt="Fetch blog posts",
            context={"action": "fetch_data"}
        )
        
        # Verify it was queued (async)
        self.assertFalse(result1.get("success", True))
        self.assertTrue(result1.get("queued", False))
        self.assertEqual(result1.get("strategy").value, "async_patch")
        
        # Check queue size
        stats = kernel.get_triage_stats()
        self.assertEqual(stats["async_queue_size"], 1)
    
    def test_sync_failure_not_queued(self):
        """Test that sync failures are not queued."""
        from agent_kernel import SelfCorrectingAgentKernel
        
        kernel = SelfCorrectingAgentKernel()
        
        # Trigger sync failure
        result = kernel.handle_failure(
            agent_id="test-agent-2",
            error_message="Payment failed",
            user_prompt="Process payment",
            context={"action": "execute_payment"}
        )
        
        # Should not be queued
        self.assertIsNone(result.get("queued"))
        
        # Queue should be empty
        stats = kernel.get_triage_stats()
        self.assertEqual(stats["async_queue_size"], 0)
    
    def test_mixed_sync_async_failures(self):
        """Test handling both sync and async failures."""
        from agent_kernel import SelfCorrectingAgentKernel
        
        kernel = SelfCorrectingAgentKernel()
        
        # Async failure
        result1 = kernel.handle_failure(
            agent_id="agent-1",
            error_message="Data not found",
            user_prompt="Get recent logs",
            context={"action": "fetch_logs"}
        )
        
        # Sync failure (critical)
        result2 = kernel.handle_failure(
            agent_id="agent-2",
            error_message="Permission denied",
            user_prompt="Delete critical file",
            context={"action": "delete_file"}
        )
        
        # Verify async was queued
        self.assertTrue(result1.get("queued", False))
        
        # Verify sync was processed
        self.assertIsNone(result2.get("queued"))
        
        # Only async should be in queue
        stats = kernel.get_triage_stats()
        self.assertEqual(stats["async_queue_size"], 1)


class TestTriageConfiguration(unittest.TestCase):
    """Tests for triage configuration options."""
    
    def test_empty_critical_tools_config(self):
        """Test with empty critical tools list."""
        triage = FailureTriage(config={"critical_tools": []})
        
        # Should default to async even for normally critical tools
        strategy = triage.decide_strategy(
            prompt="Delete resource",
            tool_name="delete_resource"
        )
        self.assertEqual(strategy, FixStrategy.ASYNC_BATCH)
    
    def test_empty_keywords_config(self):
        """Test with empty high-effort keywords list."""
        triage = FailureTriage(config={"high_effort_keywords": []})
        
        # Should default to async even with normally critical keywords
        strategy = triage.decide_strategy(
            prompt="Critical operation needed",
            tool_name="some_tool"
        )
        self.assertEqual(strategy, FixStrategy.ASYNC_BATCH)
    
    def test_extended_critical_tools(self):
        """Test adding custom tools to critical list."""
        triage = FailureTriage(config={
            "critical_tools": [
                "delete_resource",
                "execute_payment",
                "custom_critical_operation",
                "deploy_to_production"
            ]
        })
        
        strategy = triage.decide_strategy(
            prompt="Deploy to prod",
            tool_name="deploy_to_production"
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)
    
    def test_domain_specific_keywords(self):
        """Test domain-specific high-effort keywords."""
        triage = FailureTriage(config={
            "high_effort_keywords": ["emergency", "outage", "incident"]
        })
        
        strategy = triage.decide_strategy(
            prompt="Emergency outage detected",
            tool_name="notify"
        )
        self.assertEqual(strategy, FixStrategy.SYNC_JIT)


if __name__ == "__main__":
    unittest.main()
