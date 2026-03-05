# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Path simulation system to test alternative solutions.
"""

import logging
import uuid
from typing import List, Dict, Any, Optional

from .models import FailureAnalysis, SimulationResult, DiagnosisJSON, ShadowAgentResult, AgentFailure, CognitiveGlitch

logger = logging.getLogger(__name__)


class ShadowAgent:
    """
    Shadow Agent for counterfactual simulation.
    
    Replays the user prompt with an injected hint in a sandbox environment.
    This is "The Scientist" that verifies if the hint actually fixes the problem.
    """
    
    def __init__(self):
        self.execution_history: List[ShadowAgentResult] = []
    
    def replay_with_hint(
        self,
        original_prompt: str,
        hint: str,
        diagnosis: DiagnosisJSON,
        failure: AgentFailure
    ) -> ShadowAgentResult:
        """
        Replay the original prompt with an injected hint.
        
        This simulates the agent executing with additional context/guidance.
        
        Args:
            original_prompt: Original user prompt that led to failure
            hint: Hint to inject based on diagnosis
            diagnosis: Cognitive glitch diagnosis
            failure: Original failure for context
            
        Returns:
            ShadowAgentResult with execution outcome
        """
        shadow_id = f"shadow-{uuid.uuid4().hex[:8]}"
        
        logger.info(f"Shadow agent {shadow_id} replaying with hint")
        
        # Construct modified prompt with hint
        modified_prompt = f"{original_prompt}\n\n{hint}"
        
        # Simulate execution (in real system, this would run actual agent in sandbox)
        execution_success, output, reasoning, action = self._simulate_execution(
            modified_prompt, diagnosis, failure
        )
        
        # Verify the fix
        verified = self._verify_fix(execution_success, action, failure)
        
        result = ShadowAgentResult(
            shadow_id=shadow_id,
            original_prompt=original_prompt,
            injected_hint=hint,
            modified_prompt=modified_prompt,
            execution_success=execution_success,
            output=output,
            reasoning_chain=reasoning,
            action_taken=action,
            verified=verified
        )
        
        self.execution_history.append(result)
        logger.info(f"Shadow execution complete. Success: {execution_success}, Verified: {verified}")
        
        return result
    
    def _simulate_execution(
        self,
        prompt: str,
        diagnosis: DiagnosisJSON,
        failure: AgentFailure
    ) -> tuple:
        """
        Simulate agent execution with the modified prompt.
        
        In a real system, this would:
        1. Spin up a sandboxed agent instance
        2. Inject the hint into the system prompt or context
        3. Execute the agent with the original user prompt
        4. Capture the reasoning chain and action
        5. Check if the action would pass control plane checks
        """
        # Simulate reasoning chain with hint consideration
        reasoning = [
            "Parse user request",
            f"Consider hint: {diagnosis.hint[:50]}...",
            "Validate assumptions against provided context",
            "Construct safe action"
        ]
        
        # Simulate a corrected action
        # In reality, this would be the actual agent's output
        if diagnosis.cognitive_glitch == CognitiveGlitch.HALLUCINATION:
            # Agent would verify schema
            action = {
                "action": "execute_with_validation",
                "validation": "schema_check_passed",
                "safe_mode": True
            }
            success = True
            output = "Action validated and executed successfully"
        elif diagnosis.cognitive_glitch == CognitiveGlitch.PERMISSION_ERROR:
            # Agent would check permissions first
            action = {
                "action": "check_permissions_then_execute",
                "permission_validation": True
            }
            success = True
            output = "Permissions validated, action executed"
        else:
            # Generic safe action
            action = {
                "action": "safe_execute",
                "hint_applied": True
            }
            # Success based on diagnosis confidence (deterministic)
            success = diagnosis.confidence > 0.7
            output = "Action executed with safety checks" if success else "Action still failed"
        
        return success, output, reasoning, action
    
    def _verify_fix(self, success: bool, action: Optional[Dict], failure: AgentFailure) -> bool:
        """
        Verify that the fix actually works.
        
        This is the key validation step - confirming the hint flips the outcome
        from Fail to Pass.
        """
        if not success:
            return False
        
        # Check if action has safety mechanisms that original lacked
        if action:
            has_validation = any(
                key in action for key in ["validation", "permission_validation", "schema_check", "safe_mode"]
            )
            return has_validation
        
        return success


class PathSimulator:
    """Simulates alternative paths to avoid failures."""
    
    def __init__(self):
        self.simulation_history: List[SimulationResult] = []
        self.shadow_agent = ShadowAgent()
        self.mcts_iterations = 5  # MCTS search iterations
    
    def simulate(self, analysis: FailureAnalysis) -> SimulationResult:
        """
        Simulate an alternative path based on failure analysis.
        
        Args:
            analysis: The failure analysis containing suggested fixes
            
        Returns:
            SimulationResult with the alternative path and predicted outcome
        """
        logger.info(f"Simulating alternative path for agent {analysis.failure.agent_id}")
        
        # Generate simulation ID
        simulation_id = str(uuid.uuid4())
        
        # Build alternative path from suggested fixes
        alternative_path = self._build_alternative_path(analysis)
        
        # Predict outcome
        expected_outcome = self._predict_outcome(analysis, alternative_path)
        
        # Calculate risk score
        risk_score = self._calculate_risk(analysis, alternative_path)
        
        # Estimate success rate
        estimated_success_rate = self._estimate_success_rate(analysis, risk_score)
        
        # Determine if simulation is successful
        success = risk_score < 0.5 and estimated_success_rate > 0.7
        
        result = SimulationResult(
            simulation_id=simulation_id,
            success=success,
            alternative_path=alternative_path,
            expected_outcome=expected_outcome,
            risk_score=risk_score,
            estimated_success_rate=estimated_success_rate
        )
        
        self.simulation_history.append(result)
        
        if success:
            logger.info(f"Simulation successful. Success rate: {estimated_success_rate:.2f}, Risk: {risk_score:.2f}")
        else:
            logger.warning(f"Simulation failed. Success rate: {estimated_success_rate:.2f}, Risk: {risk_score:.2f}")
        
        return result
    
    def simulate_counterfactual(
        self,
        diagnosis: DiagnosisJSON,
        failure: AgentFailure
    ) -> ShadowAgentResult:
        """
        Counterfactual simulation using Shadow Agent.
        
        This is "The Simulator" - it replays the user prompt but injects a hint
        based on the DiagnosisJSON. Uses MCTS-like approach to find minimal
        change required to flip outcome from Fail to Pass.
        
        Args:
            diagnosis: Cognitive glitch diagnosis with hint
            failure: Original failure with trace
            
        Returns:
            ShadowAgentResult showing if hint fixes the problem
        """
        logger.info("Starting counterfactual simulation with Shadow Agent")
        
        if not failure.failure_trace:
            logger.warning("No failure trace available for counterfactual simulation")
            # Create a dummy result
            return ShadowAgentResult(
                shadow_id="shadow-no-trace",
                original_prompt="No prompt available",
                injected_hint=diagnosis.hint,
                modified_prompt="No prompt available",
                execution_success=False,
                output="No trace available for simulation",
                reasoning_chain=[],
                action_taken=None,
                verified=False
            )
        
        # Use MCTS-inspired approach: try multiple hint variations
        best_result = self._mcts_search_minimal_hint(
            failure.failure_trace.user_prompt,
            diagnosis,
            failure
        )
        
        return best_result
    
    def _mcts_search_minimal_hint(
        self,
        prompt: str,
        diagnosis: DiagnosisJSON,
        failure: AgentFailure
    ) -> ShadowAgentResult:
        """
        MCTS-inspired search for minimal hint that fixes the problem.
        
        This searches for the minimal change required to flip the outcome.
        In full MCTS, we'd build a tree of hint variations and explore/exploit,
        but here we do a simplified version with multiple trials.
        """
        logger.info(f"MCTS search across {self.mcts_iterations} iterations")
        
        hint_variations = self._generate_hint_variations(diagnosis.hint)
        results = []
        
        for i, hint in enumerate(hint_variations[:self.mcts_iterations]):
            logger.debug(f"MCTS iteration {i+1}: Testing hint variation")
            result = self.shadow_agent.replay_with_hint(
                prompt, hint, diagnosis, failure
            )
            results.append(result)
            
            # Early exit if we find a verified solution
            if result.verified and result.execution_success:
                logger.info(f"Found verified solution at iteration {i+1}")
                break
        
        # Select best result (verified + successful, or highest success)
        best = max(
            results,
            key=lambda r: (r.verified, r.execution_success, len(r.reasoning_chain))
        )
        
        logger.info(f"MCTS search complete. Best result verified: {best.verified}")
        return best
    
    def _generate_hint_variations(self, base_hint: str) -> List[str]:
        """
        Generate variations of the hint for MCTS exploration.
        
        This finds different ways to provide the same guidance,
        searching for the minimal effective intervention.
        """
        variations = [base_hint]  # Original hint
        
        # Variation 1: More concise
        if len(base_hint) > 50:
            concise = base_hint.split(".")[0] + "."
            variations.append(concise)
        
        # Variation 2: More explicit
        explicit = base_hint + " Double-check all assumptions."
        variations.append(explicit)
        
        # Variation 3: Focus on specific action
        if "validate" in base_hint.lower():
            variations.append("VALIDATION REQUIRED: " + base_hint)
        
        # Variation 4: Minimal version
        if "HINT:" in base_hint:
            minimal = base_hint.replace("HINT: ", "")
            variations.append(minimal)
        
        return variations
    
    def _build_alternative_path(self, analysis: FailureAnalysis) -> List[Dict[str, Any]]:
        """Build an alternative execution path from suggested fixes."""
        path = []
        failure = analysis.failure
        
        # Add validation step for control plane blocks
        if failure.failure_type.value == "blocked_by_control_plane":
            path.append({
                "step": 1,
                "action": "validate_permissions",
                "description": "Check permissions before attempting action",
                "params": {
                    "resource": failure.context.get("resource", "unknown"),
                    "action": failure.context.get("action", "unknown")
                }
            })
            
            path.append({
                "step": 2,
                "action": "request_authorization",
                "description": "Request proper authorization if needed",
                "params": {
                    "required_permission": "resource_access"
                }
            })
            
            path.append({
                "step": 3,
                "action": "safe_execute",
                "description": "Execute action with safety checks",
                "params": {
                    "original_action": failure.context.get("action", "unknown"),
                    "safety_mode": "enabled"
                }
            })
        
        # Add timeout handling for timeout failures
        elif failure.failure_type.value == "timeout":
            path.append({
                "step": 1,
                "action": "set_timeout",
                "description": "Configure appropriate timeout",
                "params": {"timeout_seconds": 30}
            })
            
            path.append({
                "step": 2,
                "action": "add_progress_monitoring",
                "description": "Add progress monitoring",
                "params": {"check_interval_seconds": 5}
            })
            
            path.append({
                "step": 3,
                "action": "execute_with_timeout",
                "description": "Execute with timeout handling",
                "params": {"allow_partial_results": True}
            })
        
        # Generic alternative path for other failures
        else:
            for i, fix in enumerate(analysis.suggested_fixes[:3], 1):
                path.append({
                    "step": i,
                    "action": "apply_fix",
                    "description": fix,
                    "params": {"fix": fix}
                })
        
        return path
    
    def _predict_outcome(self, analysis: FailureAnalysis, alternative_path: List[Dict[str, Any]]) -> str:
        """Predict the outcome of executing the alternative path."""
        failure = analysis.failure
        
        if failure.failure_type.value == "blocked_by_control_plane":
            return "Action will be executed with proper authorization and safety checks"
        elif failure.failure_type.value == "timeout":
            return "Operation will complete within timeout with progress monitoring"
        else:
            return f"Failure {failure.failure_type.value} will be prevented by applying suggested fixes"
    
    def _calculate_risk(self, analysis: FailureAnalysis, alternative_path: List[Dict[str, Any]]) -> float:
        """Calculate risk score for the alternative path."""
        risk = 0.3  # Base risk
        
        # Lower risk if confidence is high
        risk -= (analysis.confidence_score * 0.2)
        
        # Lower risk if we have multiple steps (more thorough)
        if len(alternative_path) >= 3:
            risk -= 0.1
        
        # Higher risk for unknown failure types
        if analysis.failure.failure_type.value == "unknown":
            risk += 0.2
        
        return max(0.0, min(1.0, risk))
    
    def _estimate_success_rate(self, analysis: FailureAnalysis, risk_score: float) -> float:
        """Estimate success rate of the alternative path."""
        # Base success rate from confidence
        success_rate = analysis.confidence_score
        
        # Adjust based on risk
        success_rate = success_rate * (1.0 - risk_score * 0.5)
        
        # Bonus for having similar failures (we've seen this before)
        if len(analysis.similar_failures) > 0:
            success_rate += 0.1
        
        return max(0.0, min(1.0, success_rate))
    
    def get_best_simulation(self, simulations: List[SimulationResult]) -> SimulationResult:
        """Get the best simulation from a list based on success rate and risk."""
        if not simulations:
            raise ValueError("No simulations provided")
        
        # Sort by estimated success rate (desc) and risk score (asc)
        sorted_sims = sorted(
            simulations,
            key=lambda s: (s.estimated_success_rate, -s.risk_score),
            reverse=True
        )
        
        return sorted_sims[0]
