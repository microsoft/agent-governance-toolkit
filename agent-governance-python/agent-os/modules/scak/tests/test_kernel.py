# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Unit tests for the Self-Correcting Agent Kernel.
"""

import unittest
from datetime import datetime

from agent_kernel import SelfCorrectingAgentKernel
from agent_kernel.models import (
    AgentFailure, FailureType, FailureSeverity,
    FailureAnalysis, SimulationResult, CorrectionPatch
)
from agent_kernel.detector import FailureDetector
from agent_kernel.analyzer import FailureAnalyzer
from agent_kernel.simulator import PathSimulator
from agent_kernel.patcher import AgentPatcher


class TestFailureDetector(unittest.TestCase):
    """Tests for FailureDetector."""
    
    def setUp(self):
        self.detector = FailureDetector()
    
    def test_detect_control_plane_blocking(self):
        """Test detection of control plane blocking."""
        failure = self.detector.detect_failure(
            agent_id="test-agent-1",
            error_message="Action blocked by control plane policy",
            context={"action": "delete_file"}
        )
        
        self.assertEqual(failure.failure_type, FailureType.BLOCKED_BY_CONTROL_PLANE)
        self.assertEqual(failure.severity, FailureSeverity.HIGH)
        self.assertEqual(failure.agent_id, "test-agent-1")
    
    def test_detect_timeout(self):
        """Test detection of timeout failures."""
        failure = self.detector.detect_failure(
            agent_id="test-agent-2",
            error_message="Operation timed out after 30 seconds"
        )
        
        self.assertEqual(failure.failure_type, FailureType.TIMEOUT)
        self.assertEqual(failure.severity, FailureSeverity.MEDIUM)
    
    def test_detect_invalid_action(self):
        """Test detection of invalid actions."""
        failure = self.detector.detect_failure(
            agent_id="test-agent-3",
            error_message="Invalid action: not supported"
        )
        
        self.assertEqual(failure.failure_type, FailureType.INVALID_ACTION)
    
    def test_failure_history(self):
        """Test failure history tracking."""
        self.detector.detect_failure("agent-1", "Error 1")
        self.detector.detect_failure("agent-2", "Error 2")
        self.detector.detect_failure("agent-1", "Error 3")
        
        all_history = self.detector.get_failure_history()
        self.assertEqual(len(all_history), 3)
        
        agent1_history = self.detector.get_failure_history(agent_id="agent-1")
        self.assertEqual(len(agent1_history), 2)


class TestFailureAnalyzer(unittest.TestCase):
    """Tests for FailureAnalyzer."""
    
    def setUp(self):
        self.analyzer = FailureAnalyzer()
    
    def test_analyze_control_plane_failure(self):
        """Test analysis of control plane failures."""
        failure = AgentFailure(
            agent_id="test-agent",
            failure_type=FailureType.BLOCKED_BY_CONTROL_PLANE,
            error_message="Blocked by policy",
            context={"action": "write_file"}
        )
        
        analysis = self.analyzer.analyze(failure)
        
        self.assertIsInstance(analysis, FailureAnalysis)
        self.assertGreater(len(analysis.suggested_fixes), 0)
        self.assertGreater(analysis.confidence_score, 0.5)
    
    def test_find_similar_failures(self):
        """Test finding similar failures."""
        failure1 = AgentFailure(
            agent_id="agent-1",
            failure_type=FailureType.TIMEOUT,
            error_message="Operation timed out"
        )
        failure2 = AgentFailure(
            agent_id="agent-2",
            failure_type=FailureType.TIMEOUT,
            error_message="Operation timed out waiting"
        )
        failure3 = AgentFailure(
            agent_id="agent-3",
            failure_type=FailureType.INVALID_ACTION,
            error_message="Invalid request"
        )
        
        similar = self.analyzer.find_similar_failures(
            failure1,
            [failure2, failure3]
        )
        
        self.assertEqual(len(similar), 1)
        self.assertEqual(similar[0].agent_id, "agent-2")
    
    def test_confidence_increases_with_similar_failures(self):
        """Test that confidence increases with similar failures."""
        failure = AgentFailure(
            agent_id="test-agent",
            failure_type=FailureType.TIMEOUT,
            error_message="Timeout"
        )
        
        # Analyze without similar failures
        analysis1 = self.analyzer.analyze(failure)
        
        # Analyze with similar failures
        similar = [failure, failure, failure]
        analysis2 = self.analyzer.analyze(failure, similar)
        
        self.assertGreater(analysis2.confidence_score, analysis1.confidence_score)


class TestPathSimulator(unittest.TestCase):
    """Tests for PathSimulator."""
    
    def setUp(self):
        self.simulator = PathSimulator()
    
    def test_simulate_control_plane_fix(self):
        """Test simulation of control plane fix."""
        failure = AgentFailure(
            agent_id="test-agent",
            failure_type=FailureType.BLOCKED_BY_CONTROL_PLANE,
            error_message="Blocked",
            context={"action": "delete", "resource": "/tmp/file"}
        )
        
        analysis = FailureAnalysis(
            failure=failure,
            root_cause="Missing permissions",
            suggested_fixes=["Add permission check"],
            confidence_score=0.8
        )
        
        simulation = self.simulator.simulate(analysis)
        
        self.assertIsInstance(simulation, SimulationResult)
        self.assertGreater(len(simulation.alternative_path), 0)
        self.assertGreater(simulation.estimated_success_rate, 0.5)
    
    def test_simulation_success_criteria(self):
        """Test that simulation success depends on risk and success rate."""
        failure = AgentFailure(
            agent_id="test-agent",
            failure_type=FailureType.TIMEOUT,
            error_message="Timeout"
        )
        
        # High confidence analysis should produce successful simulation
        analysis = FailureAnalysis(
            failure=failure,
            root_cause="Slow operation",
            suggested_fixes=["Add timeout handling"],
            confidence_score=0.9
        )
        
        simulation = self.simulator.simulate(analysis)
        self.assertTrue(simulation.success)


class TestAgentPatcher(unittest.TestCase):
    """Tests for AgentPatcher."""
    
    def setUp(self):
        self.patcher = AgentPatcher()
    
    def test_create_patch(self):
        """Test patch creation."""
        failure = AgentFailure(
            agent_id="test-agent",
            failure_type=FailureType.BLOCKED_BY_CONTROL_PLANE,
            error_message="Blocked"
        )
        
        analysis = FailureAnalysis(
            failure=failure,
            root_cause="Missing permissions",
            suggested_fixes=["Add check"],
            confidence_score=0.8
        )
        
        simulation = SimulationResult(
            simulation_id="sim-1",
            success=True,
            alternative_path=[{"step": 1, "action": "validate"}],
            expected_outcome="Success",
            risk_score=0.2,
            estimated_success_rate=0.9
        )
        
        patch = self.patcher.create_patch("test-agent", analysis, simulation)
        
        self.assertIsInstance(patch, CorrectionPatch)
        self.assertEqual(patch.agent_id, "test-agent")
        self.assertFalse(patch.applied)
    
    def test_apply_patch(self):
        """Test applying a patch."""
        failure = AgentFailure(
            agent_id="test-agent",
            failure_type=FailureType.TIMEOUT,
            error_message="Timeout"
        )
        
        analysis = FailureAnalysis(
            failure=failure,
            root_cause="Slow",
            suggested_fixes=["Fix"],
            confidence_score=0.8
        )
        
        simulation = SimulationResult(
            simulation_id="sim-1",
            success=True,
            alternative_path=[],
            expected_outcome="Success",
            risk_score=0.2,
            estimated_success_rate=0.9
        )
        
        patch = self.patcher.create_patch("test-agent", analysis, simulation)
        success = self.patcher.apply_patch(patch)
        
        self.assertTrue(success)
        self.assertTrue(patch.applied)
        self.assertIsNotNone(patch.applied_at)
    
    def test_rollback_patch(self):
        """Test patch rollback."""
        failure = AgentFailure(
            agent_id="test-agent",
            failure_type=FailureType.TIMEOUT,
            error_message="Timeout"
        )
        
        analysis = FailureAnalysis(
            failure=failure,
            root_cause="Slow",
            suggested_fixes=["Fix"],
            confidence_score=0.8
        )
        
        simulation = SimulationResult(
            simulation_id="sim-1",
            success=True,
            alternative_path=[],
            expected_outcome="Success",
            risk_score=0.2,
            estimated_success_rate=0.9
        )
        
        patch = self.patcher.create_patch("test-agent", analysis, simulation)
        self.patcher.apply_patch(patch)
        
        success = self.patcher.rollback_patch(patch.patch_id)
        
        self.assertTrue(success)
        self.assertFalse(patch.applied)


class TestSelfCorrectingAgentKernel(unittest.TestCase):
    """Tests for the main SelfCorrectingAgentKernel."""
    
    def setUp(self):
        self.kernel = SelfCorrectingAgentKernel()
    
    def test_handle_failure_full_pipeline(self):
        """Test the full failure handling pipeline."""
        result = self.kernel.handle_failure(
            agent_id="test-agent",
            error_message="Action blocked by control plane",
            context={"action": "delete_file"},
            auto_patch=True
        )
        
        self.assertTrue(result["success"])
        self.assertIsNotNone(result["failure"])
        self.assertIsNotNone(result["analysis"])
        self.assertIsNotNone(result["simulation"])
        self.assertIsNotNone(result["patch"])
        self.assertTrue(result["patch_applied"])
    
    def test_wake_up_and_fix(self):
        """Test the wake_up_and_fix convenience method."""
        result = self.kernel.wake_up_and_fix(
            agent_id="test-agent",
            error_message="Blocked by policy"
        )
        
        self.assertTrue(result["success"])
        self.assertTrue(result["patch_applied"])
    
    def test_get_agent_status(self):
        """Test retrieving agent status."""
        # Create a failure that will succeed (control plane block)
        self.kernel.handle_failure(
            agent_id="test-agent",
            error_message="Action blocked by control plane",
            context={"action": "test"},
            auto_patch=True
        )
        
        status = self.kernel.get_agent_status("test-agent")
        
        self.assertEqual(status.agent_id, "test-agent")
        self.assertEqual(status.status, "patched")
        self.assertGreater(len(status.patches_applied), 0)
    
    def test_failure_history(self):
        """Test failure history tracking."""
        self.kernel.handle_failure("agent-1", "Error 1")
        self.kernel.handle_failure("agent-2", "Error 2")
        
        history = self.kernel.get_failure_history()
        self.assertGreaterEqual(len(history), 2)
        
        agent1_history = self.kernel.get_failure_history(agent_id="agent-1")
        self.assertGreaterEqual(len(agent1_history), 1)
    
    def test_patch_history(self):
        """Test patch history tracking."""
        # Use a failure type that will create a successful patch
        self.kernel.handle_failure(
            "agent-1",
            "Action blocked by control plane",
            context={"action": "test"},
            auto_patch=True
        )
        
        history = self.kernel.get_patch_history()
        self.assertGreater(len(history), 0)
        
        agent1_patches = self.kernel.get_patch_history(agent_id="agent-1")
        self.assertGreater(len(agent1_patches), 0)


if __name__ == "__main__":
    unittest.main()
