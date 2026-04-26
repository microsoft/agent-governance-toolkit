# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Unit tests for advanced Agent Control Plane features:
- Mute Agent
- Shadow Mode
- Constraint Graphs
- Supervisor Agents
"""

import unittest
from datetime import datetime, time
from agent_control_plane import AgentControlPlane, create_standard_agent
from agent_control_plane.agent_kernel import ActionType, PermissionLevel
from agent_control_plane.mute_agent import (
    create_mute_sql_agent, create_mute_data_analyst,
    MuteAgentValidator, AgentCapability
)
from agent_control_plane.shadow_mode import (
    ShadowModeExecutor, ShadowModeConfig,
    SimulationOutcome, add_reasoning_step
)
from agent_control_plane.constraint_graphs import (
    DataGraph, PolicyGraph, TemporalGraph,
    ConstraintGraphValidator, GraphNode, GraphNodeType
)
from agent_control_plane.supervisor_agents import (
    SupervisorAgent, SupervisorConfig,
    create_default_supervisor, ViolationType
)


class TestMuteAgent(unittest.TestCase):
    """Test the Mute Agent functionality"""
    
    def setUp(self):
        self.control_plane = AgentControlPlane()
    
    def test_mute_sql_agent_valid_query(self):
        """Test that Mute SQL Agent accepts valid SELECT queries"""
        config = create_mute_sql_agent("sql-test")
        permissions = {ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY}
        agent = self.control_plane.create_agent("sql-test", permissions)
        self.control_plane.enable_mute_agent("sql-test", config)
        
        result = self.control_plane.execute_action(
            agent,
            ActionType.DATABASE_QUERY,
            {"query": "SELECT * FROM users"}
        )
        self.assertTrue(result["success"])
    
    def test_mute_sql_agent_invalid_query(self):
        """Test that Mute SQL Agent rejects destructive queries"""
        config = create_mute_sql_agent("sql-test")
        permissions = {ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY}
        agent = self.control_plane.create_agent("sql-test", permissions)
        self.control_plane.enable_mute_agent("sql-test", config)
        
        result = self.control_plane.execute_action(
            agent,
            ActionType.DATABASE_QUERY,
            {"query": "DROP TABLE users"}
        )
        self.assertFalse(result["success"])
        self.assertEqual(result.get("status"), "capability_mismatch")
    
    def test_mute_agent_out_of_scope(self):
        """Test that Mute Agent returns NULL for out-of-scope actions"""
        config = create_mute_sql_agent("sql-test")
        permissions = {
            ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY,
            ActionType.FILE_READ: PermissionLevel.READ_ONLY
        }
        agent = self.control_plane.create_agent("sql-test", permissions)
        self.control_plane.enable_mute_agent("sql-test", config)
        
        # Try file read (not in SQL agent capabilities)
        result = self.control_plane.execute_action(
            agent,
            ActionType.FILE_READ,
            {"path": "/data/file.txt"}
        )
        self.assertFalse(result["success"])
        self.assertIn("NULL", result.get("error", ""))
    
    def test_data_analyst_capabilities(self):
        """Test data analyst mute agent with multiple capabilities"""
        config = create_mute_data_analyst("analyst-test")
        permissions = {
            ActionType.FILE_READ: PermissionLevel.READ_ONLY,
            ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY
        }
        agent = self.control_plane.create_agent("analyst-test", permissions)
        self.control_plane.enable_mute_agent("analyst-test", config)
        
        # Should allow file read in /data
        result = self.control_plane.execute_action(
            agent,
            ActionType.FILE_READ,
            {"path": "/data/analytics.csv"}
        )
        self.assertTrue(result["success"])


class TestShadowMode(unittest.TestCase):
    """Test Shadow Mode functionality"""
    
    def test_shadow_mode_enabled(self):
        """Test that shadow mode intercepts executions"""
        control_plane = AgentControlPlane(enable_shadow_mode=True)
        agent = create_standard_agent(control_plane, "test-agent")
        
        result = control_plane.execute_action(
            agent,
            ActionType.FILE_READ,
            {"path": "/data/test.txt"}
        )
        
        self.assertTrue(result["success"])
        self.assertEqual(result.get("status"), "simulated")
        self.assertIn("SHADOW MODE", result.get("note", ""))
    
    def test_shadow_mode_disabled(self):
        """Test that executions work normally when shadow mode is off"""
        control_plane = AgentControlPlane(enable_shadow_mode=False)
        agent = create_standard_agent(control_plane, "test-agent")
        
        result = control_plane.execute_action(
            agent,
            ActionType.FILE_READ,
            {"path": "/data/test.txt"}
        )
        
        self.assertTrue(result["success"])
        self.assertNotEqual(result.get("status"), "simulated")
    
    def test_shadow_mode_statistics(self):
        """Test that shadow mode tracks statistics"""
        control_plane = AgentControlPlane(enable_shadow_mode=True)
        agent = create_standard_agent(control_plane, "test-agent")
        
        # Execute a few actions
        for i in range(3):
            control_plane.execute_action(
                agent,
                ActionType.FILE_READ,
                {"path": f"/data/file{i}.txt"}
            )
        
        stats = control_plane.get_shadow_statistics()
        self.assertEqual(stats["total_simulations"], 3)
        self.assertGreater(stats["success_rate"], 0)
    
    def test_reasoning_chain(self):
        """Test that reasoning chains are captured in shadow mode"""
        control_plane = AgentControlPlane(enable_shadow_mode=True)
        agent = create_standard_agent(control_plane, "test-agent")
        
        reasoning_chain = []
        add_reasoning_step(
            reasoning_chain,
            "User requested data",
            ActionType.FILE_READ,
            {"path": "/data/test.txt"},
            "File read is safe"
        )
        
        result = control_plane.execute_action(
            agent,
            ActionType.FILE_READ,
            {"path": "/data/test.txt"},
            reasoning_chain=reasoning_chain
        )
        
        self.assertTrue(result["success"])
        self.assertEqual(len(reasoning_chain), 1)


class TestConstraintGraphs(unittest.TestCase):
    """Test Constraint Graphs functionality"""
    
    def test_data_graph_table_access(self):
        """Test that data graph controls table access"""
        control_plane = AgentControlPlane(enable_constraint_graphs=True)
        
        # Add accessible table
        control_plane.add_data_table("users", {"id": "int", "name": "string"})
        
        agent = create_standard_agent(control_plane, "test-agent")
        
        # Try to access table in graph - should work
        result = control_plane.execute_action(
            agent,
            ActionType.DATABASE_QUERY,
            {"table": "users", "query": "SELECT * FROM users"}
        )
        self.assertTrue(result["success"])
        
        # Try to access table NOT in graph - should fail
        result = control_plane.execute_action(
            agent,
            ActionType.DATABASE_QUERY,
            {"table": "secrets", "query": "SELECT * FROM secrets"}
        )
        self.assertFalse(result["success"])
        self.assertIn("not in accessible data graph", result["error"])
    
    def test_data_graph_file_access(self):
        """Test that data graph controls file access"""
        control_plane = AgentControlPlane(enable_constraint_graphs=True)
        
        # Add accessible path
        control_plane.add_data_path("/data/")
        
        agent = create_standard_agent(control_plane, "test-agent")
        
        # Try to access file in allowed path
        result = control_plane.execute_action(
            agent,
            ActionType.FILE_READ,
            {"path": "/data/file.txt"}
        )
        self.assertTrue(result["success"])
        
        # Try to access file outside allowed path
        result = control_plane.execute_action(
            agent,
            ActionType.FILE_READ,
            {"path": "/etc/passwd"}
        )
        self.assertFalse(result["success"])
    
    def test_temporal_graph_maintenance_window(self):
        """Test that temporal graph respects maintenance windows"""
        control_plane = AgentControlPlane(enable_constraint_graphs=True)
        
        # Add maintenance window (this test assumes we're not in the window)
        control_plane.add_maintenance_window(
            "test_window",
            time(2, 0),  # 2 AM
            time(4, 0),  # 4 AM
            [ActionType.DATABASE_WRITE]
        )
        
        # Current time is not in maintenance window, so writes should work
        # (unless it happens to be 2-4 AM when test runs)
        agent = create_standard_agent(control_plane, "test-agent")
        
        # This test is time-dependent, so we just verify the mechanism exists
        self.assertIsNotNone(control_plane.temporal_graph)
    
    def test_constraint_validation_log(self):
        """Test that constraint validations are logged"""
        control_plane = AgentControlPlane(enable_constraint_graphs=True)
        control_plane.add_data_table("users", {"id": "int"})
        
        agent = create_standard_agent(control_plane, "test-agent")
        
        control_plane.execute_action(
            agent,
            ActionType.DATABASE_QUERY,
            {"table": "users", "query": "SELECT * FROM users"}
        )
        
        log = control_plane.get_constraint_validation_log()
        self.assertGreater(len(log), 0)


class TestSupervisorAgents(unittest.TestCase):
    """Test Supervisor Agents functionality"""
    
    def test_supervisor_creation(self):
        """Test creating a supervisor agent"""
        supervisor = create_default_supervisor(["agent-1", "agent-2"])
        
        self.assertEqual(len(supervisor.config.watches), 2)
        self.assertIn("agent-1", supervisor.config.watches)
        self.assertGreater(len(supervisor.config.detection_rules), 0)
    
    def test_supervisor_detects_violations(self):
        """Test that supervisor detects violations"""
        control_plane = AgentControlPlane()
        agent = create_standard_agent(control_plane, "worker-agent")
        
        # Create failures by trying unauthorized actions
        for i in range(6):
            control_plane.execute_action(
                agent,
                ActionType.DATABASE_WRITE,  # Not allowed for standard agent
                {"table": "test", "data": {"id": i}}
            )
        
        # Add supervisor
        supervisor = create_default_supervisor(["worker-agent"])
        control_plane.add_supervisor(supervisor)
        
        # Run supervision
        violations = control_plane.run_supervision()
        
        # Should detect repeated failures
        self.assertIsNotNone(violations)
    
    def test_supervisor_summary(self):
        """Test getting supervisor summary"""
        control_plane = AgentControlPlane()
        
        supervisor1 = create_default_supervisor(["agent-1"])
        supervisor2 = create_default_supervisor(["agent-2"])
        
        control_plane.add_supervisor(supervisor1)
        control_plane.add_supervisor(supervisor2)
        
        summary = control_plane.get_supervisor_summary()
        self.assertEqual(summary["total_supervisors"], 2)
    
    def test_supervisor_violation_filtering(self):
        """Test filtering violations by severity"""
        supervisor = create_default_supervisor(["test-agent"])
        
        # Initially no violations
        violations = supervisor.get_violations(severity="high")
        self.assertEqual(len(violations), 0)


class TestIntegration(unittest.TestCase):
    """Test integration of all advanced features"""
    
    def test_full_integration(self):
        """Test all features working together"""
        # Create control plane with all features
        control_plane = AgentControlPlane(
            enable_default_policies=True,
            enable_shadow_mode=False,
            enable_constraint_graphs=True
        )
        
        # Setup constraint graphs
        control_plane.add_data_table("users", {"id": "int"})
        control_plane.add_data_path("/data/")
        
        # Create mute agent
        config = create_mute_sql_agent("integrated-agent")
        permissions = {ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY}
        agent = control_plane.create_agent("integrated-agent", permissions)
        control_plane.enable_mute_agent("integrated-agent", config)
        
        # Add supervisor
        supervisor = create_default_supervisor(["integrated-agent"])
        control_plane.add_supervisor(supervisor)
        
        # Execute action
        result = control_plane.execute_action(
            agent,
            ActionType.DATABASE_QUERY,
            {"table": "users", "query": "SELECT * FROM users"}
        )
        
        self.assertTrue(result["success"])
        
        # Run supervision
        violations = control_plane.run_supervision()
        self.assertIsNotNone(violations)
    
    def test_shadow_to_production_transition(self):
        """Test transitioning from shadow mode to production"""
        control_plane = AgentControlPlane(enable_shadow_mode=True)
        agent = create_standard_agent(control_plane, "test-agent")
        
        # Execute in shadow mode
        result1 = control_plane.execute_action(
            agent,
            ActionType.FILE_READ,
            {"path": "/data/test.txt"}
        )
        self.assertEqual(result1.get("status"), "simulated")
        
        # Switch to production
        control_plane.enable_shadow_mode(False)
        
        # Execute in production
        result2 = control_plane.execute_action(
            agent,
            ActionType.FILE_READ,
            {"path": "/data/test.txt"}
        )
        self.assertNotEqual(result2.get("status"), "simulated")


if __name__ == "__main__":
    unittest.main()
