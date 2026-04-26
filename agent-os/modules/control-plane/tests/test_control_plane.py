# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Unit tests for the Agent Control Plane
"""

import unittest
from datetime import datetime
from agent_control_plane import (
    AgentControlPlane,
    create_read_only_agent,
    create_standard_agent,
)
from agent_control_plane.agent_kernel import ActionType, PermissionLevel, PolicyRule
from agent_control_plane.policy_engine import ResourceQuota
import uuid


class TestAgentKernel(unittest.TestCase):
    """Test the Agent Kernel component"""
    
    def setUp(self):
        self.control_plane = AgentControlPlane()
    
    def test_create_agent_session(self):
        """Test creating an agent session"""
        agent_context = create_standard_agent(self.control_plane, "test-agent")
        self.assertEqual(agent_context.agent_id, "test-agent")
        self.assertIsNotNone(agent_context.session_id)
        self.assertIsInstance(agent_context.permissions, dict)
    
    def test_permission_check_success(self):
        """Test permission check allows valid actions"""
        agent_context = create_standard_agent(self.control_plane, "test-agent")
        result = self.control_plane.execute_action(
            agent_context,
            ActionType.FILE_READ,
            {"path": "/data/test.txt"}
        )
        self.assertTrue(result["success"])
    
    def test_permission_check_failure(self):
        """Test permission check denies unauthorized actions"""
        agent_context = create_read_only_agent(self.control_plane, "test-agent")
        result = self.control_plane.execute_action(
            agent_context,
            ActionType.FILE_WRITE,
            {"path": "/data/test.txt", "content": "test"}
        )
        self.assertFalse(result["success"])
        self.assertIn("denied", result["error"].lower())
    
    def test_audit_logging(self):
        """Test that actions are audited"""
        agent_context = create_standard_agent(self.control_plane, "test-agent")
        
        initial_log_length = len(self.control_plane.get_audit_log())
        
        self.control_plane.execute_action(
            agent_context,
            ActionType.FILE_READ,
            {"path": "/data/test.txt"}
        )
        
        final_log_length = len(self.control_plane.get_audit_log())
        self.assertGreater(final_log_length, initial_log_length)


class TestPolicyEngine(unittest.TestCase):
    """Test the Policy Engine component"""
    
    def setUp(self):
        self.control_plane = AgentControlPlane()
    
    def test_rate_limiting(self):
        """Test rate limiting enforcement"""
        quota = ResourceQuota(
            agent_id="rate-test-agent",
            max_requests_per_minute=2,
            allowed_action_types=[ActionType.FILE_READ]
        )
        
        agent_context = self.control_plane.create_agent(
            "rate-test-agent",
            {ActionType.FILE_READ: PermissionLevel.READ_ONLY},
            quota
        )
        
        # First two requests should succeed
        result1 = self.control_plane.execute_action(
            agent_context,
            ActionType.FILE_READ,
            {"path": "/data/file1.txt"}
        )
        self.assertTrue(result1["success"])
        
        result2 = self.control_plane.execute_action(
            agent_context,
            ActionType.FILE_READ,
            {"path": "/data/file2.txt"}
        )
        self.assertTrue(result2["success"])
        
        # Third request should fail due to rate limit
        result3 = self.control_plane.execute_action(
            agent_context,
            ActionType.FILE_READ,
            {"path": "/data/file3.txt"}
        )
        self.assertFalse(result3["success"])
        self.assertIn("rate_limit", result3["error"].lower())
    
    def test_system_file_protection(self):
        """Test that system files are protected by default policies"""
        agent_context = create_standard_agent(self.control_plane, "test-agent")
        
        result = self.control_plane.execute_action(
            agent_context,
            ActionType.FILE_READ,
            {"path": "/etc/passwd"}
        )
        
        # Should be denied by policy
        self.assertFalse(result["success"])
    
    def test_custom_policy_rule(self):
        """Test adding custom policy rules"""
        def deny_all(request):
            return False
        
        custom_rule = PolicyRule(
            rule_id=str(uuid.uuid4()),
            name="deny_all_code",
            description="Deny all code execution",
            action_types=[ActionType.CODE_EXECUTION],
            validator=deny_all,
            priority=10
        )
        
        self.control_plane.add_policy_rule(custom_rule)
        
        agent_context = create_standard_agent(self.control_plane, "test-agent")
        
        result = self.control_plane.execute_action(
            agent_context,
            ActionType.CODE_EXECUTION,
            {"code": "print('test')", "language": "python"}
        )
        
        self.assertFalse(result["success"])
        # Should be denied by kernel or policy
        self.assertIn("denied", result["error"].lower())


class TestExecutionEngine(unittest.TestCase):
    """Test the Execution Engine component"""
    
    def setUp(self):
        self.control_plane = AgentControlPlane()
    
    def test_file_read_execution(self):
        """Test file read execution"""
        agent_context = create_standard_agent(self.control_plane, "test-agent")
        
        result = self.control_plane.execute_action(
            agent_context,
            ActionType.FILE_READ,
            {"path": "/data/test.txt"}
        )
        
        self.assertTrue(result["success"])
        self.assertIn("result", result)
        self.assertIn("metrics", result)
    
    def test_code_execution(self):
        """Test code execution"""
        agent_context = create_standard_agent(self.control_plane, "test-agent")
        
        result = self.control_plane.execute_action(
            agent_context,
            ActionType.CODE_EXECUTION,
            {"code": "print('Hello')", "language": "python"}
        )
        
        self.assertTrue(result["success"])
        self.assertIn("result", result)
    
    def test_execution_metrics(self):
        """Test that execution metrics are collected"""
        agent_context = create_standard_agent(self.control_plane, "test-agent")
        
        result = self.control_plane.execute_action(
            agent_context,
            ActionType.FILE_READ,
            {"path": "/data/test.txt"}
        )
        
        self.assertTrue(result["success"])
        self.assertIn("metrics", result)
        self.assertIn("execution_time_ms", result["metrics"])


class TestControlPlane(unittest.TestCase):
    """Test the integrated Control Plane"""
    
    def setUp(self):
        self.control_plane = AgentControlPlane()
    
    def test_end_to_end_workflow(self):
        """Test complete workflow from agent creation to execution"""
        # Create agent
        agent_context = create_standard_agent(self.control_plane, "workflow-agent")
        self.assertIsNotNone(agent_context)
        
        # Execute action
        result = self.control_plane.execute_action(
            agent_context,
            ActionType.FILE_READ,
            {"path": "/data/workflow.txt"}
        )
        self.assertTrue(result["success"])
        
        # Check agent status
        status = self.control_plane.get_agent_status("workflow-agent")
        self.assertEqual(status["agent_id"], "workflow-agent")
        self.assertIn("quota_status", status)
        
        # Check audit log
        audit_log = self.control_plane.get_audit_log()
        self.assertGreater(len(audit_log), 0)
    
    def test_risk_scoring(self):
        """Test that risk scoring is applied"""
        agent_context = create_standard_agent(self.control_plane, "risk-test-agent")
        
        # File read should have low risk
        result_low = self.control_plane.execute_action(
            agent_context,
            ActionType.FILE_READ,
            {"path": "/data/test.txt"}
        )
        risk_low = result_low.get("risk_score", 0)
        
        # Code execution should have higher risk
        result_high = self.control_plane.execute_action(
            agent_context,
            ActionType.CODE_EXECUTION,
            {"code": "print('test')", "language": "python"}
        )
        risk_high = result_high.get("risk_score", 0)
        
        self.assertLess(risk_low, risk_high)
    
    def test_multiple_agents_isolation(self):
        """Test that multiple agents are isolated from each other"""
        agent1 = create_standard_agent(self.control_plane, "agent-1")
        agent2 = create_standard_agent(self.control_plane, "agent-2")
        
        self.assertNotEqual(agent1.session_id, agent2.session_id)
        
        # Execute actions for both agents
        result1 = self.control_plane.execute_action(
            agent1,
            ActionType.FILE_READ,
            {"path": "/data/agent1.txt"}
        )
        
        result2 = self.control_plane.execute_action(
            agent2,
            ActionType.FILE_READ,
            {"path": "/data/agent2.txt"}
        )
        
        self.assertTrue(result1["success"])
        self.assertTrue(result2["success"])
        self.assertNotEqual(result1["request_id"], result2["request_id"])


def run_tests():
    """Run all tests"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestAgentKernel))
    suite.addTests(loader.loadTestsFromTestCase(TestPolicyEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestExecutionEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestControlPlane))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    exit(0 if success else 1)
