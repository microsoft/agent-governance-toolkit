# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Unit tests for Agent Control Plane v1.0 new features:
- Async support
- ABAC (Attribute-Based Access Control) with conditions
- Flight Recorder (Black Box audit logging)
"""

import unittest
import asyncio
import os
import tempfile
from src.agent_control_plane.agent_kernel import AgentKernel
from src.agent_control_plane.policy_engine import PolicyEngine, Condition, ConditionalPermission
from src.agent_control_plane.flight_recorder import FlightRecorder


class TestAsyncSupport(unittest.TestCase):
    """Test async support in AgentKernel"""

    def test_async_intercept_allowed(self):
        """Test async intercept_tool_execution allows authorized tools"""
        policy = PolicyEngine()
        policy.add_constraint(role="test-agent", allowed_tools=["read"])

        kernel = AgentKernel(policy_engine=policy, shadow_mode=False)

        # Run async method
        result = asyncio.run(
            kernel.intercept_tool_execution_async(
                agent_id="test-agent", tool_name="read", tool_args={}
            )
        )

        self.assertTrue(result["allowed"])

    def test_async_intercept_blocked(self):
        """Test async intercept_tool_execution blocks unauthorized tools"""
        policy = PolicyEngine()
        policy.add_constraint(role="test-agent", allowed_tools=["read"])

        kernel = AgentKernel(policy_engine=policy, shadow_mode=False)

        # Run async method
        result = asyncio.run(
            kernel.intercept_tool_execution_async(
                agent_id="test-agent", tool_name="write", tool_args={}
            )
        )

        self.assertFalse(result["allowed"])
        self.assertTrue(result["mute"])
        self.assertIn("error", result)

    @unittest.skip("shadow mode not available")
    def test_async_shadow_mode(self):
        """Test async shadow mode returns simulated results"""
        pass


class TestConditions(unittest.TestCase):
    """Test the Condition class for ABAC"""

    def test_condition_eq_operator(self):
        """Test condition with equality operator"""
        condition = Condition("user_status", "eq", "verified")

        context = {"user_status": "verified"}
        self.assertTrue(condition.evaluate(context))

        context = {"user_status": "unverified"}
        self.assertFalse(condition.evaluate(context))

    def test_condition_gt_operator(self):
        """Test condition with greater than operator"""
        condition = Condition("amount", "gt", 100)

        context = {"amount": 150}
        self.assertTrue(condition.evaluate(context))

        context = {"amount": 50}
        self.assertFalse(condition.evaluate(context))

    def test_condition_in_operator(self):
        """Test condition with 'in' operator"""
        condition = Condition("role", "in", ["admin", "manager"])

        context = {"role": "admin"}
        self.assertTrue(condition.evaluate(context))

        context = {"role": "user"}
        self.assertFalse(condition.evaluate(context))

    def test_condition_nested_path(self):
        """Test condition with nested attribute path"""
        condition = Condition("args.amount", "lt", 1000)

        context = {"args": {"amount": 500}}
        self.assertTrue(condition.evaluate(context))

        context = {"args": {"amount": 1500}}
        self.assertFalse(condition.evaluate(context))


class TestConditionalPermissions(unittest.TestCase):
    """Test ConditionalPermission for ABAC"""

    def test_conditional_permission_single_condition(self):
        """Test conditional permission with single condition"""
        condition = Condition("user_status", "eq", "verified")
        permission = ConditionalPermission("refund_user", [condition])

        context = {"user_status": "verified"}
        self.assertTrue(permission.is_allowed(context))

        context = {"user_status": "unverified"}
        self.assertFalse(permission.is_allowed(context))

    def test_conditional_permission_multiple_conditions_and(self):
        """Test conditional permission with multiple AND conditions"""
        conditions = [Condition("user_status", "eq", "verified"), Condition("amount", "lt", 1000)]
        permission = ConditionalPermission("refund_user", conditions, require_all=True)

        # Both conditions met
        context = {"user_status": "verified", "amount": 500}
        self.assertTrue(permission.is_allowed(context))

        # Only one condition met
        context = {"user_status": "verified", "amount": 1500}
        self.assertFalse(permission.is_allowed(context))

        # No conditions met
        context = {"user_status": "unverified", "amount": 1500}
        self.assertFalse(permission.is_allowed(context))

    def test_conditional_permission_multiple_conditions_or(self):
        """Test conditional permission with multiple OR conditions"""
        conditions = [Condition("user_status", "eq", "verified"), Condition("role", "eq", "admin")]
        permission = ConditionalPermission("refund_user", conditions, require_all=False)

        # First condition met
        context = {"user_status": "verified", "role": "user"}
        self.assertTrue(permission.is_allowed(context))

        # Second condition met
        context = {"user_status": "unverified", "role": "admin"}
        self.assertTrue(permission.is_allowed(context))

        # No conditions met
        context = {"user_status": "unverified", "role": "user"}
        self.assertFalse(permission.is_allowed(context))


class TestABACPolicyEngine(unittest.TestCase):
    """Test ABAC functionality in PolicyEngine"""

    def test_add_conditional_permission(self):
        """Test adding conditional permissions"""
        policy = PolicyEngine()

        condition = Condition("user_status", "eq", "verified")
        permission = ConditionalPermission("refund_user", [condition])

        policy.add_conditional_permission("finance-agent", permission)

        self.assertIn("finance-agent", policy.conditional_permissions)
        self.assertIn("refund_user", policy.state_permissions["finance-agent"])

    def test_check_violation_with_condition_allowed(self):
        """Test check_violation allows when conditions are met"""
        policy = PolicyEngine()

        # Add conditional permission: refund_user allowed if user_status == verified
        condition = Condition("user_status", "eq", "verified")
        permission = ConditionalPermission("refund_user", [condition])
        policy.add_conditional_permission("finance-agent", permission)

        # Set agent context
        policy.set_agent_context("finance-agent", {"user_status": "verified"})

        # Should be allowed
        violation = policy.check_violation(
            agent_role="finance-agent", tool_name="refund_user", args={}
        )

        self.assertIsNone(violation)

    def test_check_violation_with_condition_blocked(self):
        """Test check_violation blocks when conditions are not met"""
        policy = PolicyEngine()

        # Add conditional permission: refund_user allowed if user_status == verified
        condition = Condition("user_status", "eq", "verified")
        permission = ConditionalPermission("refund_user", [condition])
        policy.add_conditional_permission("finance-agent", permission)

        # Set agent context with unverified status
        policy.set_agent_context("finance-agent", {"user_status": "unverified"})

        # Should be blocked
        violation = policy.check_violation(
            agent_role="finance-agent", tool_name="refund_user", args={}
        )

        self.assertIsNotNone(violation)
        self.assertIn("Conditional permission denied", violation)

    def test_check_violation_with_args_condition(self):
        """Test check_violation with condition on arguments"""
        policy = PolicyEngine()

        # Add conditional permission: refund_user allowed if amount < 1000
        condition = Condition("args.amount", "lt", 1000)
        permission = ConditionalPermission("refund_user", [condition])
        policy.add_conditional_permission("finance-agent", permission)

        # Amount under limit - should be allowed
        violation = policy.check_violation(
            agent_role="finance-agent", tool_name="refund_user", args={"amount": 500}
        )
        self.assertIsNone(violation)

        # Amount over limit - should be blocked
        violation = policy.check_violation(
            agent_role="finance-agent", tool_name="refund_user", args={"amount": 1500}
        )
        self.assertIsNotNone(violation)
        self.assertIn("Conditional permission denied", violation)


class TestFlightRecorder(unittest.TestCase):
    """Test Flight Recorder audit logging"""

    def setUp(self):
        """Create a temporary database for each test"""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.db_path = self.temp_db.name
        self.temp_db.close()
        self.recorder = FlightRecorder(self.db_path)

    def tearDown(self):
        """Clean up temporary database"""
        self.recorder.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_start_trace(self):
        """Test starting a new trace"""
        trace_id = self.recorder.start_trace(
            agent_id="test-agent",
            tool_name="read_file",
            tool_args={"path": "/data/file.txt"},
            input_prompt="Please read the file",
        )

        self.assertIsNotNone(trace_id)

        # Verify it was logged
        logs = self.recorder.query_logs(agent_id="test-agent")
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["tool_name"], "read_file")

    def test_log_violation(self):
        """Test logging a policy violation"""
        trace_id = self.recorder.start_trace(
            agent_id="test-agent", tool_name="delete_file", tool_args={"path": "/etc/passwd"}
        )

        self.recorder.log_violation(trace_id, "Path Violation: Cannot access /etc/")

        # Verify it was logged as blocked
        logs = self.recorder.query_logs(policy_verdict="blocked")
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["policy_verdict"], "blocked")
        self.assertIn("Path Violation", logs[0]["violation_reason"])

    def test_log_shadow_exec(self):
        """Test logging shadow mode execution"""
        trace_id = self.recorder.start_trace(agent_id="test-agent", tool_name="write_file")

        self.recorder.log_shadow_exec(trace_id, "Simulated success")

        # Verify it was logged as shadow
        logs = self.recorder.query_logs(policy_verdict="shadow")
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["policy_verdict"], "shadow")

    def test_log_success(self):
        """Test logging successful execution"""
        trace_id = self.recorder.start_trace(agent_id="test-agent", tool_name="read_file")

        self.recorder.log_success(trace_id, result="File contents", execution_time_ms=15.5)

        # Verify it was logged as allowed
        logs = self.recorder.query_logs(policy_verdict="allowed")
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["policy_verdict"], "allowed")
        self.assertEqual(logs[0]["execution_time_ms"], 15.5)

    def test_get_statistics(self):
        """Test getting audit log statistics"""
        # Create multiple traces
        trace1 = self.recorder.start_trace("agent1", "tool1")
        self.recorder.log_success(trace1)

        trace2 = self.recorder.start_trace("agent2", "tool2")
        self.recorder.log_violation(trace2, "Blocked")

        trace3 = self.recorder.start_trace("agent1", "tool3")
        self.recorder.log_shadow_exec(trace3)

        stats = self.recorder.get_statistics()

        self.assertEqual(stats["total_actions"], 3)
        self.assertEqual(stats["by_verdict"]["allowed"], 1)
        self.assertEqual(stats["by_verdict"]["blocked"], 1)
        self.assertEqual(stats["by_verdict"]["shadow"], 1)


class TestIntegratedABACWithKernel(unittest.TestCase):
    """Test integrated ABAC functionality with AgentKernel"""

    def test_kernel_with_abac_allowed(self):
        """Test kernel allows action when ABAC conditions are met"""
        policy = PolicyEngine()

        # Setup: refund_user allowed if user_status == verified AND amount < 1000
        conditions = [
            Condition("user_status", "eq", "verified"),
            Condition("args.amount", "lt", 1000),
        ]
        permission = ConditionalPermission("refund_user", conditions, require_all=True)
        policy.add_conditional_permission("finance-agent", permission)
        policy.set_agent_context("finance-agent", {"user_status": "verified"})

        kernel = AgentKernel(policy_engine=policy, shadow_mode=False)

        # Should be allowed
        result = kernel.intercept_tool_execution(
            agent_id="finance-agent", tool_name="refund_user", tool_args={"amount": 500}
        )

        self.assertIsNone(result)  # None means allowed

    def test_kernel_with_abac_blocked(self):
        """Test kernel blocks action when ABAC conditions are not met"""
        policy = PolicyEngine()

        # Setup: refund_user allowed if user_status == verified AND amount < 1000
        conditions = [
            Condition("user_status", "eq", "verified"),
            Condition("args.amount", "lt", 1000),
        ]
        permission = ConditionalPermission("refund_user", conditions, require_all=True)
        policy.add_conditional_permission("finance-agent", permission)
        policy.set_agent_context("finance-agent", {"user_status": "verified"})

        kernel = AgentKernel(policy_engine=policy, shadow_mode=False)

        # Should be blocked (amount too high)
        result = kernel.intercept_tool_execution(
            agent_id="finance-agent", tool_name="refund_user", tool_args={"amount": 1500}
        )

        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "blocked")
        self.assertTrue(result["mute"])


class TestIntegratedWithFlightRecorder(unittest.TestCase):
    """Test integrated functionality with FlightRecorder"""

    def setUp(self):
        """Create a temporary database for each test"""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self.db_path = self.temp_db.name
        self.temp_db.close()
        self.recorder = FlightRecorder(self.db_path)

    def tearDown(self):
        """Clean up temporary database"""
        self.recorder.close()
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    def test_kernel_logs_to_flight_recorder(self):
        """Test that kernel logs actions to flight recorder"""
        policy = PolicyEngine()
        policy.add_constraint(role="test-agent", allowed_tools=["read", "write"])

        kernel = AgentKernel(policy_engine=policy, audit_logger=self.recorder)

        # Execute allowed action
        kernel.intercept_tool_execution(
            agent_id="test-agent",
            tool_name="read",
            tool_args={"path": "/data/file.txt"},
            input_prompt="Read the file",
        )

        # Check flight recorder
        logs = self.recorder.query_logs(agent_id="test-agent")
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["tool_name"], "read")
        self.assertEqual(logs[0]["policy_verdict"], "allowed")

    def test_kernel_logs_blocked_to_flight_recorder(self):
        """Test that kernel logs blocked actions to flight recorder"""
        policy = PolicyEngine()
        policy.add_constraint(role="test-agent", allowed_tools=["read"])

        kernel = AgentKernel(policy_engine=policy, audit_logger=self.recorder)

        # Execute blocked action
        kernel.intercept_tool_execution(
            agent_id="test-agent", tool_name="write", tool_args={"path": "/data/file.txt"}
        )

        # Check flight recorder
        logs = self.recorder.query_logs(policy_verdict="blocked")
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0]["tool_name"], "write")
        self.assertIsNotNone(logs[0]["violation_reason"])


if __name__ == "__main__":
    unittest.main()
