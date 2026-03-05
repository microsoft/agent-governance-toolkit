# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Unit tests for the new AgentKernel and PolicyEngine features
(Tool Interception and Graph-based Constraint Enforcement)
"""

import unittest
from src.agent_control_plane.agent_kernel import AgentKernel
from src.agent_control_plane.policy_engine import PolicyEngine


class TestToolInterception(unittest.TestCase):
    """Test the tool interception functionality"""
    
    def test_shadow_mode_intercepts_all_tools(self):
        """Test that shadow mode intercepts all tool executions"""
        kernel = AgentKernel(shadow_mode=True)
        
        result = kernel.intercept_tool_execution(
            agent_id="test-agent",
            tool_name="dangerous_tool",
            tool_args={"action": "delete_all"}
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "simulated")
        self.assertIn("meta", result)
        self.assertTrue(result["meta"]["shadow"])
    
    def test_no_policy_allows_execution(self):
        """Test that without policy engine, tools are allowed"""
        kernel = AgentKernel(shadow_mode=False, policy_engine=None)
        
        result = kernel.intercept_tool_execution(
            agent_id="test-agent",
            tool_name="any_tool",
            tool_args={}
        )
        
        self.assertIsNone(result)  # None means allowed
    
    def test_blocked_tool_returns_mute_response(self):
        """Test that blocked tools return mute response (NULL)"""
        policy = PolicyEngine()
        policy.add_constraint(role="restricted-agent", allowed_tools=["read_only"])
        
        kernel = AgentKernel(policy_engine=policy, shadow_mode=False)
        
        result = kernel.intercept_tool_execution(
            agent_id="restricted-agent",
            tool_name="write_data",
            tool_args={}
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "blocked")
        self.assertTrue(result["mute"])
        self.assertIn("error", result)


class TestConstraintGraph(unittest.TestCase):
    """Test the constraint graph (graph-based policy) functionality"""
    
    def test_add_constraint_creates_allow_list(self):
        """Test that add_constraint creates an allow-list"""
        policy = PolicyEngine()
        policy.add_constraint(role="finance", allowed_tools=["read", "calculate"])
        
        self.assertIn("finance", policy.state_permissions)
        self.assertEqual(policy.state_permissions["finance"], {"read", "calculate"})
    
    def test_check_violation_blocks_unauthorized_tool(self):
        """Test that check_violation blocks tools not in allow-list"""
        policy = PolicyEngine()
        policy.add_constraint(role="finance", allowed_tools=["read"])
        
        violation = policy.check_violation(
            agent_role="finance",
            tool_name="delete",
            args={}
        )
        
        self.assertIsNotNone(violation)
        self.assertIn("finance", violation)
        self.assertIn("delete", violation)
    
    def test_check_violation_allows_authorized_tool(self):
        """Test that check_violation allows tools in allow-list"""
        policy = PolicyEngine()
        policy.add_constraint(role="finance", allowed_tools=["read", "calculate"])
        
        violation = policy.check_violation(
            agent_role="finance",
            tool_name="read",
            args={}
        )
        
        self.assertIsNone(violation)
    
    def test_argument_validation_blocks_dangerous_paths(self):
        """Test that argument validation blocks dangerous file paths"""
        policy = PolicyEngine()
        policy.add_constraint(role="file-agent", allowed_tools=["write_file"])
        
        violation = policy.check_violation(
            agent_role="file-agent",
            tool_name="write_file",
            args={"path": "/etc/passwd"}
        )
        
        self.assertIsNotNone(violation)
        self.assertIn("Path Violation", violation)
    
    def test_argument_validation_allows_safe_paths(self):
        """Test that argument validation allows safe file paths"""
        policy = PolicyEngine()
        policy.add_constraint(role="file-agent", allowed_tools=["write_file"])
        
        violation = policy.check_violation(
            agent_role="file-agent",
            tool_name="write_file",
            args={"path": "/data/report.txt"}
        )
        
        self.assertIsNone(violation)
    
    def test_path_traversal_attack_blocked(self):
        """Test that path traversal attacks are blocked"""
        policy = PolicyEngine()
        policy.add_constraint(role="file-agent", allowed_tools=["write_file"])
        
        # Try to bypass protection with ../
        violation = policy.check_violation(
            agent_role="file-agent",
            tool_name="write_file",
            args={"path": "/data/../etc/passwd"}
        )
        
        self.assertIsNotNone(violation)
        self.assertIn("Path Violation", violation)
    
    def test_code_execution_blocks_dangerous_patterns(self):
        """Test that code execution blocks dangerous command patterns"""
        policy = PolicyEngine()
        policy.add_constraint(role="code-agent", allowed_tools=["execute_code"])
        
        # Test rm -rf pattern
        violation = policy.check_violation(
            agent_role="code-agent",
            tool_name="execute_code",
            args={"code": "rm -rf /"}
        )
        
        self.assertIsNotNone(violation)
        self.assertIn("Dangerous pattern", violation)
        
        # Test DROP TABLE pattern
        violation = policy.check_violation(
            agent_role="code-agent",
            tool_name="execute_code",
            args={"code": "DROP TABLE users"}
        )
        
        self.assertIsNotNone(violation)
        self.assertIn("Dangerous pattern", violation)
    
    def test_dangerous_pattern_case_insensitive(self):
        """Test that dangerous patterns are detected case-insensitively"""
        policy = PolicyEngine()
        policy.add_constraint(role="code-agent", allowed_tools=["execute_code"])
        
        # Test with uppercase
        violation = policy.check_violation(
            agent_role="code-agent",
            tool_name="execute_code",
            args={"code": "RM -RF /"}
        )
        
        self.assertIsNotNone(violation)
        self.assertIn("Dangerous pattern", violation)
        
        # Test with mixed case
        violation = policy.check_violation(
            agent_role="code-agent",
            tool_name="execute_code",
            args={"code": "DrOp TaBlE users"}
        )
        
        self.assertIsNotNone(violation)
        self.assertIn("Dangerous pattern", violation)
    
    def test_dangerous_pattern_with_extra_spaces(self):
        """Test that dangerous patterns with extra spaces are detected"""
        policy = PolicyEngine()
        policy.add_constraint(role="code-agent", allowed_tools=["execute_code"])
        
        # Test with extra spaces
        violation = policy.check_violation(
            agent_role="code-agent",
            tool_name="execute_code",
            args={"code": "rm  -rf /"}  # Two spaces
        )
        
        self.assertIsNotNone(violation)
        self.assertIn("Dangerous pattern", violation)
    
    def test_scale_by_subtraction_default_deny(self):
        """Test that Scale by Subtraction blocks by default"""
        policy = PolicyEngine()
        # Don't add any constraints for this agent
        
        violation = policy.check_violation(
            agent_role="unknown-agent",
            tool_name="any_tool",
            args={}
        )
        
        self.assertIsNotNone(violation)
        self.assertIn("cannot use tool", violation)


class TestIntegratedInterception(unittest.TestCase):
    """Test the integrated kernel + policy engine flow"""
    
    def test_end_to_end_blocking(self):
        """Test end-to-end blocking of unauthorized tools"""
        policy = PolicyEngine()
        policy.add_constraint(role="sql-agent", allowed_tools=["SELECT"])
        
        kernel = AgentKernel(policy_engine=policy, shadow_mode=False)
        
        # Allowed: SELECT
        result = kernel.intercept_tool_execution(
            agent_id="sql-agent",
            tool_name="SELECT",
            tool_args={"query": "SELECT * FROM users"}
        )
        self.assertIsNone(result)  # Allowed
        
        # Blocked: DROP
        result = kernel.intercept_tool_execution(
            agent_id="sql-agent",
            tool_name="DROP",
            tool_args={"query": "DROP TABLE users"}
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "blocked")
        self.assertTrue(result["mute"])
    
    def test_multiple_agents_different_permissions(self):
        """Test that different agents can have different permissions"""
        policy = PolicyEngine()
        policy.add_constraint(role="read-agent", allowed_tools=["read"])
        policy.add_constraint(role="write-agent", allowed_tools=["read", "write"])
        
        kernel = AgentKernel(policy_engine=policy, shadow_mode=False)
        
        # read-agent can read
        result = kernel.intercept_tool_execution(
            agent_id="read-agent",
            tool_name="read",
            tool_args={}
        )
        self.assertIsNone(result)
        
        # read-agent cannot write
        result = kernel.intercept_tool_execution(
            agent_id="read-agent",
            tool_name="write",
            tool_args={}
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["status"], "blocked")
        
        # write-agent can write
        result = kernel.intercept_tool_execution(
            agent_id="write-agent",
            tool_name="write",
            tool_args={}
        )
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
