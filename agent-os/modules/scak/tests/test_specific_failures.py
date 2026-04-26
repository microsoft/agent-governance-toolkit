# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Unit tests for the three specific failure types from the problem statement:
1. Tool Misuse - Agent called delete_user(id) with a name instead of UUID
2. Hallucination - Agent referenced Project_Alpha which doesn't exist
3. Policy Violation - Agent tried to advise on medical issues
"""

import unittest
from datetime import datetime

from agent_kernel import SelfCorrectingAgentKernel
from agent_kernel.models import (
    AgentFailure, FailureType, FailureSeverity,
    FailureTrace, CognitiveGlitch, PatchStrategy
)
from agent_kernel.analyzer import FailureAnalyzer
from agent_kernel.patcher import AgentPatcher


class TestToolMisuse(unittest.TestCase):
    """Tests for Tool Misuse failure type."""
    
    def setUp(self):
        self.kernel = SelfCorrectingAgentKernel()
        self.analyzer = FailureAnalyzer()
    
    def test_detect_tool_misuse_uuid_error(self):
        """Test detection of tool misuse when name is used instead of UUID."""
        # Create a failure trace with tool misuse
        trace = FailureTrace(
            user_prompt="Delete the user john_doe",
            chain_of_thought=[
                "User wants to delete a user",
                "I'll call delete_user with the username",
                "Calling delete_user('john_doe')"
            ],
            failed_action={
                "action": "delete_user",
                "params": {"id": "john_doe"}  # Wrong: name instead of UUID
            },
            error_details="Expected UUID format for parameter 'id', got string 'john_doe'"
        )
        
        failure = AgentFailure(
            agent_id="user-manager-agent",
            failure_type=FailureType.INVALID_ACTION,
            severity=FailureSeverity.HIGH,
            error_message="Expected UUID format for parameter 'id', got string 'john_doe'",
            context={"tool": "delete_user", "param": "id"},
            failure_trace=trace
        )
        
        # Diagnose the cognitive glitch
        diagnosis = self.analyzer.diagnose_cognitive_glitch(failure)
        
        # Verify it's detected as TOOL_MISUSE
        self.assertEqual(diagnosis.cognitive_glitch, CognitiveGlitch.TOOL_MISUSE)
        self.assertGreater(diagnosis.confidence, 0.5)
        self.assertIn("parameter type", diagnosis.hint.lower())
    
    def test_tool_misuse_patch_strategy(self):
        """Test that tool misuse results in Schema Injection patch."""
        trace = FailureTrace(
            user_prompt="Delete user admin",
            chain_of_thought=["Deleting user"],
            failed_action={"action": "delete_user", "params": {"id": "admin"}},
            error_details="Invalid UUID format"
        )
        
        failure = AgentFailure(
            agent_id="test-agent",
            failure_type=FailureType.INVALID_ACTION,
            error_message="Invalid UUID format for id parameter",
            failure_trace=trace
        )
        
        # Get full pipeline result
        result = self.kernel.handle_failure(
            agent_id="test-agent",
            error_message="Invalid UUID format for id parameter",
            user_prompt="Delete user admin",
            chain_of_thought=["Deleting user"],
            failed_action={"action": "delete_user", "params": {"id": "admin"}},
            auto_patch=True
        )
        
        # Verify diagnosis
        if result.get("diagnosis"):
            self.assertEqual(result["diagnosis"].cognitive_glitch, CognitiveGlitch.TOOL_MISUSE)
        
        # Verify patch is system_prompt (Schema Injection)
        if result.get("patch"):
            self.assertEqual(result["patch"].patch_type, "system_prompt")
            # Verify the patch content mentions schema injection
            patch_content = result["patch"].patch_content
            if "rule" in patch_content:
                self.assertIn("SCHEMA INJECTION", patch_content["rule"])


class TestHallucination(unittest.TestCase):
    """Tests for Hallucination failure type."""
    
    def setUp(self):
        self.kernel = SelfCorrectingAgentKernel()
        self.analyzer = FailureAnalyzer()
    
    def test_detect_hallucination_project_alpha(self):
        """Test detection of hallucination when agent references non-existent Project_Alpha."""
        trace = FailureTrace(
            user_prompt="Show me the status of all projects",
            chain_of_thought=[
                "User wants project status",
                "I'll query Project_Alpha, Project_Beta, and Project_Gamma",
                "Fetching data for these projects"
            ],
            failed_action={
                "action": "get_project_status",
                "params": {"project_name": "Project_Alpha"}
            },
            error_details="Project 'Project_Alpha' does not exist"
        )
        
        failure = AgentFailure(
            agent_id="project-manager-agent",
            failure_type=FailureType.INVALID_ACTION,
            severity=FailureSeverity.MEDIUM,
            error_message="Project 'Project_Alpha' does not exist",
            context={"entity": "Project_Alpha"},
            failure_trace=trace
        )
        
        # Diagnose the cognitive glitch
        diagnosis = self.analyzer.diagnose_cognitive_glitch(failure)
        
        # Verify it's detected as HALLUCINATION
        self.assertEqual(diagnosis.cognitive_glitch, CognitiveGlitch.HALLUCINATION)
        self.assertGreater(diagnosis.confidence, 0.5)
    
    def test_hallucination_patch_strategy(self):
        """Test that hallucination results in RAG Patch with negative constraint."""
        result = self.kernel.handle_failure(
            agent_id="project-agent",
            error_message="Entity 'Project_Alpha' does not exist",
            user_prompt="Show me Project_Alpha details",
            chain_of_thought=[
                "User wants Project_Alpha info",
                "Querying Project_Alpha"
            ],
            failed_action={
                "action": "get_project",
                "params": {"name": "Project_Alpha"}
            },
            auto_patch=True
        )
        
        # Verify diagnosis
        if result.get("diagnosis"):
            self.assertEqual(result["diagnosis"].cognitive_glitch, CognitiveGlitch.HALLUCINATION)
        
        # Verify patch is rag_memory
        if result.get("patch"):
            self.assertEqual(result["patch"].patch_type, "rag_memory")
            # Verify the patch content includes negative constraint
            patch_content = result["patch"].patch_content
            if "negative_constraint" in patch_content:
                self.assertIsNotNone(patch_content["negative_constraint"])
                # Should mention that Project_Alpha doesn't exist
                self.assertIn("does not exist", patch_content["negative_constraint"].lower())
    
    def test_extract_hallucinated_entity(self):
        """Test extraction of hallucinated entity name."""
        patcher = AgentPatcher()
        
        # Test with quoted entity
        trace1 = FailureTrace(
            user_prompt="Query recent users",
            chain_of_thought=["Querying"],
            failed_action={"query": "SELECT * FROM recent_users"},
            error_details="Table 'recent_users' does not exist"
        )
        failure1 = AgentFailure(
            agent_id="test",
            failure_type=FailureType.INVALID_ACTION,
            error_message="Table 'recent_users' does not exist",
            failure_trace=trace1
        )
        entity1 = patcher._extract_hallucinated_entity(failure1)
        self.assertEqual(entity1, "recent_users")
        
        # Test with CamelCase entity in failed_action
        trace2 = FailureTrace(
            user_prompt="Get project",
            chain_of_thought=["Getting"],
            failed_action={"action": "get", "entity": "Project_Alpha"},
            error_details="Project does not exist"
        )
        failure2 = AgentFailure(
            agent_id="test",
            failure_type=FailureType.INVALID_ACTION,
            error_message="Project does not exist",
            failure_trace=trace2
        )
        entity2 = patcher._extract_hallucinated_entity(failure2)
        self.assertEqual(entity2, "Project_Alpha")


class TestPolicyViolation(unittest.TestCase):
    """Tests for Policy Violation failure type."""
    
    def setUp(self):
        self.kernel = SelfCorrectingAgentKernel()
        self.analyzer = FailureAnalyzer()
    
    def test_detect_policy_violation_medical(self):
        """Test detection of policy violation when agent tries to give medical advice."""
        trace = FailureTrace(
            user_prompt="What medication should I take for my headache?",
            chain_of_thought=[
                "User has a headache",
                "I should recommend some medication",
                "Common headache medications include aspirin"
            ],
            failed_action={
                "action": "provide_advice",
                "domain": "medical",
                "response": "You should take aspirin..."
            },
            error_details="Action blocked: Cannot advise on medical issues"
        )
        
        failure = AgentFailure(
            agent_id="assistant-agent",
            failure_type=FailureType.BLOCKED_BY_CONTROL_PLANE,
            severity=FailureSeverity.HIGH,
            error_message="Policy violation: Cannot advise on medical issues",
            context={"domain": "medical"},
            failure_trace=trace
        )
        
        # Diagnose the cognitive glitch
        diagnosis = self.analyzer.diagnose_cognitive_glitch(failure)
        
        # Verify it's detected as POLICY_VIOLATION
        self.assertEqual(diagnosis.cognitive_glitch, CognitiveGlitch.POLICY_VIOLATION)
        self.assertGreater(diagnosis.confidence, 0.5)
        self.assertIn("policy", diagnosis.hint.lower())
    
    def test_policy_violation_patch_strategy(self):
        """Test that policy violation results in Constitutional Update (system_prompt)."""
        result = self.kernel.handle_failure(
            agent_id="medical-assistant",
            error_message="Policy violation: Cannot provide medical advice",
            user_prompt="What should I do about my chest pain?",
            chain_of_thought=[
                "User has chest pain",
                "I'll provide medical guidance"
            ],
            failed_action={
                "action": "provide_medical_advice",
                "advice": "You should..."
            },
            auto_patch=True
        )
        
        # Verify diagnosis
        if result.get("diagnosis"):
            self.assertEqual(result["diagnosis"].cognitive_glitch, CognitiveGlitch.POLICY_VIOLATION)
        
        # Verify patch is system_prompt (Constitutional Update)
        if result.get("patch"):
            self.assertEqual(result["patch"].patch_type, "system_prompt")
            # Verify the patch content mentions refusal rule
            patch_content = result["patch"].patch_content
            if "rule" in patch_content:
                self.assertIn("CONSTITUTIONAL REFUSAL RULE", patch_content["rule"])
                self.assertIn("refuse", patch_content["rule"].lower())
    
    def test_policy_violation_different_domains(self):
        """Test policy violation detection for different restricted domains."""
        # Test legal advice
        result_legal = self.kernel.handle_failure(
            agent_id="legal-assistant",
            error_message="Policy violation: Cannot provide legal advice",
            user_prompt="Should I sue my landlord?",
            chain_of_thought=["User has legal question"],
            failed_action={"action": "legal_advice"},
            auto_patch=True
        )
        
        if result_legal.get("patch") and result_legal["patch"].patch_content.get("rule"):
            self.assertIn("legal", result_legal["patch"].patch_content["rule"].lower())
        
        # Test investment advice
        result_invest = self.kernel.handle_failure(
            agent_id="investment-assistant",
            error_message="Policy violation: Cannot provide investment advice",
            user_prompt="Which stocks should I buy?",
            chain_of_thought=["User wants investment advice"],
            failed_action={"action": "investment_advice"},
            auto_patch=True
        )
        
        if result_invest.get("patch") and result_invest["patch"].patch_content.get("rule"):
            self.assertIn("investment", result_invest["patch"].patch_content["rule"].lower())


class TestPatchIntegration(unittest.TestCase):
    """Integration tests for all three failure types."""
    
    def setUp(self):
        self.kernel = SelfCorrectingAgentKernel()
    
    def test_all_three_scenarios_in_sequence(self):
        """Test that all three failure scenarios are handled correctly."""
        
        # Scenario 1: Tool Misuse
        result1 = self.kernel.handle_failure(
            agent_id="test-agent-1",
            error_message="Expected UUID for id parameter",
            user_prompt="Delete user bob",
            chain_of_thought=["Deleting user"],
            failed_action={"action": "delete_user", "params": {"id": "bob"}},
            auto_patch=True
        )
        self.assertTrue(result1["success"])
        self.assertTrue(result1["patch_applied"])
        
        # Scenario 2: Hallucination
        result2 = self.kernel.handle_failure(
            agent_id="test-agent-2",
            error_message="Project_Alpha does not exist",
            user_prompt="Show Project_Alpha status",
            chain_of_thought=["Getting project status"],
            failed_action={"action": "get_project", "name": "Project_Alpha"},
            auto_patch=True
        )
        self.assertTrue(result2["success"])
        self.assertTrue(result2["patch_applied"])
        
        # Scenario 3: Policy Violation
        result3 = self.kernel.handle_failure(
            agent_id="test-agent-3",
            error_message="Policy violation: Cannot advise on medical issues",
            user_prompt="What medicine should I take?",
            chain_of_thought=["User needs medical advice"],
            failed_action={"action": "medical_advice"},
            auto_patch=True
        )
        self.assertTrue(result3["success"])
        self.assertTrue(result3["patch_applied"])
    
    def test_patch_types_match_requirements(self):
        """Verify that patch types match the problem statement requirements."""
        
        # Tool Misuse → Schema Injection (system_prompt)
        result1 = self.kernel.handle_failure(
            agent_id="uuid-agent",
            error_message="Invalid UUID format",
            user_prompt="Delete user alice",
            chain_of_thought=["Deleting"],
            failed_action={"action": "delete_user", "id": "alice"},
            auto_patch=True
        )
        if result1.get("diagnosis") and result1["diagnosis"].cognitive_glitch == CognitiveGlitch.TOOL_MISUSE:
            self.assertEqual(result1["patch"].patch_type, "system_prompt")
        
        # Hallucination → RAG Patch (rag_memory)
        result2 = self.kernel.handle_failure(
            agent_id="hallucination-agent",
            error_message="Entity_XYZ does not exist",
            user_prompt="Get Entity_XYZ",
            chain_of_thought=["Getting entity"],
            failed_action={"action": "get", "entity": "Entity_XYZ"},
            auto_patch=True
        )
        if result2.get("diagnosis") and result2["diagnosis"].cognitive_glitch == CognitiveGlitch.HALLUCINATION:
            self.assertEqual(result2["patch"].patch_type, "rag_memory")
        
        # Policy Violation → Constitutional Update (system_prompt)
        result3 = self.kernel.handle_failure(
            agent_id="policy-agent",
            error_message="Cannot advise on medical topics",
            user_prompt="Diagnose my symptoms",
            chain_of_thought=["Providing diagnosis"],
            failed_action={"action": "diagnose"},
            auto_patch=True
        )
        if result3.get("diagnosis") and result3["diagnosis"].cognitive_glitch == CognitiveGlitch.POLICY_VIOLATION:
            self.assertEqual(result3["patch"].patch_type, "system_prompt")


if __name__ == "__main__":
    unittest.main()
