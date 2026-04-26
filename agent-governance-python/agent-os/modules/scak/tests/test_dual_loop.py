# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Tests for the Dual-Loop Architecture:
- Loop 2: Alignment Engine
  - Completeness Auditor
  - Semantic Purge
  - Outcome Analyzer
"""

import pytest
from agent_kernel import (
    SelfCorrectingAgentKernel,
    OutcomeAnalyzer,
    CompletenessAuditor,
    SemanticPurge,
    OutcomeType,
    GiveUpSignal,
    PatchDecayType
)


class TestOutcomeAnalyzer:
    """Test the Outcome Analyzer component."""
    
    def test_detect_no_data_found_signal(self):
        """Test detection of 'no data found' give-up signals."""
        analyzer = OutcomeAnalyzer()
        
        outcome = analyzer.analyze_outcome(
            agent_id="test-agent",
            user_prompt="Find logs for error 500",
            agent_response="No logs found for error 500."
        )
        
        assert outcome.outcome_type == OutcomeType.GIVE_UP
        assert outcome.give_up_signal == GiveUpSignal.NO_DATA_FOUND
    
    def test_detect_cannot_answer_signal(self):
        """Test detection of 'cannot answer' give-up signals."""
        analyzer = OutcomeAnalyzer()
        
        outcome = analyzer.analyze_outcome(
            agent_id="test-agent",
            user_prompt="What is the capital of France?",
            agent_response="I cannot answer this question."
        )
        
        assert outcome.outcome_type == OutcomeType.GIVE_UP
        assert outcome.give_up_signal == GiveUpSignal.CANNOT_ANSWER
    
    def test_successful_outcome_no_signal(self):
        """Test that successful outcomes don't trigger give-up signals."""
        analyzer = OutcomeAnalyzer()
        
        outcome = analyzer.analyze_outcome(
            agent_id="test-agent",
            user_prompt="Find logs for error 500",
            agent_response="Found 247 log entries for error 500 in /var/log/app.log"
        )
        
        assert outcome.outcome_type == OutcomeType.SUCCESS
        assert outcome.give_up_signal is None
    
    def test_should_trigger_audit(self):
        """Test that give-up outcomes trigger audits."""
        analyzer = OutcomeAnalyzer()
        
        outcome = analyzer.analyze_outcome(
            agent_id="test-agent",
            user_prompt="Find data",
            agent_response="No data found."
        )
        
        assert analyzer.should_trigger_audit(outcome) is True
    
    def test_give_up_rate_calculation(self):
        """Test give-up rate calculation."""
        analyzer = OutcomeAnalyzer()
        
        # Add some outcomes
        analyzer.analyze_outcome("agent1", "prompt1", "No data found")
        analyzer.analyze_outcome("agent1", "prompt2", "Success data here")
        analyzer.analyze_outcome("agent1", "prompt3", "Cannot answer")
        analyzer.analyze_outcome("agent1", "prompt4", "Another success response")
        
        rate = analyzer.get_give_up_rate(agent_id="agent1")
        assert rate == 0.5  # 2 out of 4 gave up


class TestCompletenessAuditor:
    """Test the Completeness Auditor component."""
    
    def test_audit_detects_laziness(self):
        """Test that auditor detects when teacher finds data agent missed."""
        auditor = CompletenessAuditor()
        analyzer = OutcomeAnalyzer()
        
        # Create a give-up outcome for logs
        outcome = analyzer.analyze_outcome(
            agent_id="test-agent",
            user_prompt="Find logs for error 500",
            agent_response="No logs found for error 500.",
            context={"search_location": "recent_logs"}
        )
        
        # Run audit
        audit = auditor.audit_give_up(outcome)
        
        # Teacher should find the logs in archived partition
        assert audit.teacher_found_data is True
        assert "archived" in audit.gap_analysis.lower()
        assert "archived" in audit.competence_patch.lower()
        assert audit.confidence > 0.8
    
    def test_audit_confirms_agent_correct(self):
        """Test that auditor confirms when agent was correct about no data."""
        auditor = CompletenessAuditor()
        analyzer = OutcomeAnalyzer()
        
        # Create a give-up outcome for something that truly doesn't exist
        outcome = analyzer.analyze_outcome(
            agent_id="test-agent",
            user_prompt="Find data for nonexistent_entity_xyz_123",
            agent_response="No data found for nonexistent_entity_xyz_123."
        )
        
        # Run audit
        audit = auditor.audit_give_up(outcome)
        
        # Teacher should also not find data
        assert audit.teacher_found_data is False
        assert "appropriate" in audit.gap_analysis.lower() or "correct" in audit.gap_analysis.lower()
    
    def test_competence_patch_generation(self):
        """Test that competence patches are specific and actionable."""
        auditor = CompletenessAuditor()
        analyzer = OutcomeAnalyzer()
        
        outcome = analyzer.analyze_outcome(
            agent_id="test-agent",
            user_prompt="Find recent user records",
            agent_response="No data found."
        )
        
        audit = auditor.audit_give_up(outcome)
        
        # Competence patch should be specific and actionable
        assert len(audit.competence_patch) > 20
        # Check for key instructional words
        patch_lower = audit.competence_patch.lower()
        assert any(word in patch_lower for word in ["before", "always", "use", "check", "when"])
    
    def test_audit_stats(self):
        """Test audit statistics tracking."""
        auditor = CompletenessAuditor()
        analyzer = OutcomeAnalyzer()
        
        # Run several audits
        for i in range(3):
            outcome = analyzer.analyze_outcome(
                agent_id="test-agent",
                user_prompt=f"Find logs {i}",
                agent_response="No logs found."
            )
            auditor.audit_give_up(outcome)
        
        stats = auditor.get_audit_stats()
        
        assert stats["total_audits"] == 3
        assert stats["laziness_detected"] >= 0
        assert "laziness_rate" in stats


class TestSemanticPurge:
    """Test the Semantic Purge component."""
    
    def test_classify_tool_misuse_as_syntax(self):
        """Test that tool misuse patches are classified as Type A (Syntax)."""
        from agent_kernel.models import (
            CorrectionPatch, FailureAnalysis, SimulationResult, 
            AgentFailure, FailureType, FailureSeverity, DiagnosisJSON,
            CognitiveGlitch
        )
        
        purge = SemanticPurge()
        
        # Create a patch with tool misuse diagnosis
        failure = AgentFailure(
            agent_id="test", failure_type=FailureType.INVALID_ACTION,
            severity=FailureSeverity.MEDIUM, error_message="UUID error"
        )
        
        analysis = FailureAnalysis(
            failure=failure, root_cause="Tool misuse", suggested_fixes=[],
            confidence_score=0.9, similar_failures=[]
        )
        
        simulation = SimulationResult(
            simulation_id="sim1", success=True, alternative_path=[],
            expected_outcome="Fix", risk_score=0.1, estimated_success_rate=0.9
        )
        
        diagnosis = DiagnosisJSON(
            cognitive_glitch=CognitiveGlitch.TOOL_MISUSE,
            deep_problem="Wrong parameter type",
            evidence=[], hint="Use UUID", expected_fix="Fixed",
            confidence=0.9
        )
        
        patch = CorrectionPatch(
            patch_id="patch1", agent_id="test",
            failure_analysis=analysis, simulation_result=simulation,
            patch_type="system_prompt",
            patch_content={"rule": "Use UUID format for id parameters"}
        )
        patch.diagnosis = diagnosis
        
        classified = purge.register_patch(patch, "gpt-4o")
        
        assert classified.decay_type == PatchDecayType.SYNTAX_CAPABILITY
        assert classified.should_purge_on_upgrade is True
    
    def test_classify_hallucination_as_business(self):
        """Test that hallucination patches are classified as Type B (Business)."""
        from agent_kernel.models import (
            CorrectionPatch, FailureAnalysis, SimulationResult,
            AgentFailure, FailureType, FailureSeverity, DiagnosisJSON,
            CognitiveGlitch
        )
        
        purge = SemanticPurge()
        
        failure = AgentFailure(
            agent_id="test", failure_type=FailureType.LOGIC_ERROR,
            severity=FailureSeverity.MEDIUM, error_message="Project not found"
        )
        
        analysis = FailureAnalysis(
            failure=failure, root_cause="Hallucination", suggested_fixes=[],
            confidence_score=0.9, similar_failures=[]
        )
        
        simulation = SimulationResult(
            simulation_id="sim1", success=True, alternative_path=[],
            expected_outcome="Fix", risk_score=0.1, estimated_success_rate=0.9
        )
        
        diagnosis = DiagnosisJSON(
            cognitive_glitch=CognitiveGlitch.HALLUCINATION,
            deep_problem="Invented project name",
            evidence=[], hint="Verify entities", expected_fix="Fixed",
            confidence=0.9
        )
        
        patch = CorrectionPatch(
            patch_id="patch1", agent_id="test",
            failure_analysis=analysis, simulation_result=simulation,
            patch_type="rag_memory",
            patch_content={
                "negative_constraint": "Project_Alpha does not exist"
            }
        )
        patch.diagnosis = diagnosis
        
        classified = purge.register_patch(patch, "gpt-4o")
        
        assert classified.decay_type == PatchDecayType.BUSINESS_CONTEXT
        assert classified.should_purge_on_upgrade is False
    
    def test_purge_on_upgrade(self):
        """Test that Type A patches are purged on model upgrade."""
        from agent_kernel.models import (
            CorrectionPatch, FailureAnalysis, SimulationResult,
            AgentFailure, FailureType, FailureSeverity, DiagnosisJSON,
            CognitiveGlitch
        )
        
        purge = SemanticPurge()
        
        # Create Type A patch (syntax)
        failure = AgentFailure(
            agent_id="test", failure_type=FailureType.INVALID_ACTION,
            severity=FailureSeverity.MEDIUM, error_message="Type error"
        )
        
        analysis = FailureAnalysis(
            failure=failure, root_cause="Syntax", suggested_fixes=[],
            confidence_score=0.9, similar_failures=[]
        )
        
        simulation = SimulationResult(
            simulation_id="sim1", success=True, alternative_path=[],
            expected_outcome="Fix", risk_score=0.1, estimated_success_rate=0.9
        )
        
        diagnosis_a = DiagnosisJSON(
            cognitive_glitch=CognitiveGlitch.TOOL_MISUSE,
            deep_problem="Type error", evidence=[], hint="Fix",
            expected_fix="Fixed", confidence=0.9
        )
        
        patch_a = CorrectionPatch(
            patch_id="patch-a", agent_id="test",
            failure_analysis=analysis, simulation_result=simulation,
            patch_type="system_prompt",
            patch_content={"rule": "Check types"}
        )
        patch_a.diagnosis = diagnosis_a
        
        # Create Type B patch (business)
        diagnosis_b = DiagnosisJSON(
            cognitive_glitch=CognitiveGlitch.HALLUCINATION,
            deep_problem="Entity error", evidence=[], hint="Fix",
            expected_fix="Fixed", confidence=0.9
        )
        
        patch_b = CorrectionPatch(
            patch_id="patch-b", agent_id="test",
            failure_analysis=analysis, simulation_result=simulation,
            patch_type="rag_memory",
            patch_content={"negative_constraint": "Entity X deprecated"}
        )
        patch_b.diagnosis = diagnosis_b
        
        # Register both
        purge.register_patch(patch_a, "gpt-4o")
        purge.register_patch(patch_b, "gpt-4o")
        
        # Upgrade model
        result = purge.purge_on_upgrade("gpt-4o", "gpt-5")
        
        # Type A should be purged, Type B retained
        assert "patch-a" in result["purged"]
        assert "patch-b" in result["retained"]
        assert result["stats"]["purged_count"] == 1
        assert result["stats"]["retained_count"] == 1
        assert result["stats"]["tokens_reclaimed"] > 0
    
    def test_get_purge_stats(self):
        """Test purge statistics."""
        purge = SemanticPurge()
        
        stats = purge.get_purge_stats()
        
        assert "current_patches" in stats
        assert "type_a_syntax" in stats
        assert "type_b_business" in stats
        assert "total_tokens_reclaimed" in stats


class TestDualLoopIntegration:
    """Test integration of Dual-Loop Architecture in the kernel."""
    
    def test_handle_outcome_with_give_up(self):
        """Test handling of give-up outcomes."""
        kernel = SelfCorrectingAgentKernel()
        
        result = kernel.handle_outcome(
            agent_id="test-agent",
            user_prompt="Find logs for error 500",
            agent_response="No logs found for error 500."
        )
        
        assert result["outcome"].outcome_type == OutcomeType.GIVE_UP
        assert result["audit"] is not None
        
        # If teacher found data (laziness), patch should be created
        if result["audit"].teacher_found_data:
            assert result["patch"] is not None
            assert result["classified_patch"] is not None
    
    def test_handle_outcome_without_give_up(self):
        """Test handling of successful outcomes."""
        kernel = SelfCorrectingAgentKernel()
        
        result = kernel.handle_outcome(
            agent_id="test-agent",
            user_prompt="Find logs",
            agent_response="Found 100 log entries successfully."
        )
        
        assert result["outcome"].outcome_type == OutcomeType.SUCCESS
        assert result["audit"] is None
        assert result["patch"] is None
    
    def test_model_upgrade_triggers_purge(self):
        """Test that model upgrades trigger semantic purge."""
        kernel = SelfCorrectingAgentKernel(config={"model_version": "gpt-4o"})
        
        # Create some patches first
        kernel.handle_failure(
            agent_id="test-agent",
            error_message="Type error: expected UUID",
            user_prompt="Delete user john_doe",
            chain_of_thought=["Deleting user"],
            failed_action={"action": "delete_user", "params": {"id": "john_doe"}}
        )
        
        # Upgrade model
        result = kernel.upgrade_model("gpt-5")
        
        assert "purged" in result
        assert "retained" in result
        assert "stats" in result
        assert kernel.current_model_version == "gpt-5"
    
    def test_get_alignment_stats(self):
        """Test getting alignment engine statistics."""
        kernel = SelfCorrectingAgentKernel()
        
        # Generate some activity
        kernel.handle_outcome(
            agent_id="test-agent",
            user_prompt="Find data",
            agent_response="No data found."
        )
        
        stats = kernel.get_alignment_stats()
        
        assert "completeness_auditor" in stats
        assert "semantic_purge" in stats
        assert "outcome_analyzer" in stats
        assert "total_outcomes" in stats["outcome_analyzer"]
    
    def test_get_classified_patches(self):
        """Test getting classified patches."""
        kernel = SelfCorrectingAgentKernel()
        
        patches = kernel.get_classified_patches()
        
        assert "purgeable" in patches
        assert "permanent" in patches
        assert isinstance(patches["purgeable"], list)
        assert isinstance(patches["permanent"], list)
    
    def test_full_dual_loop_workflow(self):
        """Test complete dual-loop workflow."""
        kernel = SelfCorrectingAgentKernel(config={
            "model_version": "gpt-4o",
            "auto_patch": True
        })
        
        # 1. Agent gives up (triggers Completeness Auditor)
        outcome_result = kernel.handle_outcome(
            agent_id="prod-agent",
            user_prompt="Find logs for error 500",
            agent_response="No logs found."
        )
        
        # 2. Check outcome was analyzed
        assert outcome_result["outcome"] is not None
        
        # 3. If audit triggered and found laziness, patch created and classified
        if outcome_result["audit"] and outcome_result["audit"].teacher_found_data:
            assert outcome_result["patch"] is not None
            assert outcome_result["classified_patch"] is not None
            
            # 4. Get stats
            stats = kernel.get_alignment_stats()
            assert stats["completeness_auditor"]["total_audits"] > 0
        
        # 5. Simulate model upgrade (Semantic Purge)
        purge_result = kernel.upgrade_model("gpt-5")
        assert purge_result is not None
