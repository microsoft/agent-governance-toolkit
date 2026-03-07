# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Failure analysis system that diagnoses root causes.
"""

import logging
from typing import List, Optional, Dict
from collections import Counter

from .models import AgentFailure, FailureAnalysis, FailureType, DiagnosisJSON, CognitiveGlitch

logger = logging.getLogger(__name__)


class FailureAnalyzer:
    """Analyzes failures to identify root causes and suggest fixes."""
    
    def __init__(self):
        self.analysis_history: List[FailureAnalysis] = []
        self.known_patterns: Dict[str, dict] = self._load_known_patterns()
    
    def _load_known_patterns(self) -> Dict[str, dict]:
        """Load known failure patterns and their solutions."""
        return {
            FailureType.BLOCKED_BY_CONTROL_PLANE: {
                "root_causes": [
                    "Missing permission validation",
                    "Attempting unauthorized resource access",
                    "Policy violation",
                    "Security constraint violation"
                ],
                "fixes": [
                    "Add permission checks before actions",
                    "Implement resource access validation",
                    "Use safe alternatives for restricted operations",
                    "Request proper authorization before attempting action"
                ]
            },
            FailureType.TIMEOUT: {
                "root_causes": [
                    "Operation taking too long",
                    "Infinite loop or deadlock",
                    "Network latency",
                    "Resource contention"
                ],
                "fixes": [
                    "Implement operation timeout handling",
                    "Add progress monitoring",
                    "Optimize algorithm efficiency",
                    "Add async/parallel processing"
                ]
            },
            FailureType.INVALID_ACTION: {
                "root_causes": [
                    "Invalid input parameters",
                    "Action not supported in current state",
                    "Precondition not met"
                ],
                "fixes": [
                    "Add input validation",
                    "Check state before action",
                    "Verify preconditions"
                ]
            },
            FailureType.RESOURCE_EXHAUSTED: {
                "root_causes": [
                    "Memory leak",
                    "Unbounded resource allocation",
                    "Missing cleanup"
                ],
                "fixes": [
                    "Implement resource cleanup",
                    "Add resource limits",
                    "Use resource pooling"
                ]
            },
            FailureType.LOGIC_ERROR: {
                "root_causes": [
                    "Incorrect algorithm",
                    "Edge case not handled",
                    "Type mismatch"
                ],
                "fixes": [
                    "Fix algorithm logic",
                    "Add edge case handling",
                    "Add type checking"
                ]
            }
        }
    
    def analyze(self, failure: AgentFailure, similar_failures: Optional[List[AgentFailure]] = None) -> FailureAnalysis:
        """
        Analyze a failure to identify root cause and suggest fixes.
        
        Args:
            failure: The failure to analyze
            similar_failures: Optional list of similar past failures
            
        Returns:
            FailureAnalysis with root cause and suggested fixes
        """
        logger.info(f"Analyzing failure for agent {failure.agent_id}")
        
        # Get known patterns for this failure type
        patterns = self.known_patterns.get(failure.failure_type, {})
        
        # Identify root cause
        root_cause = self._identify_root_cause(failure, patterns)
        
        # Identify contributing factors
        contributing_factors = self._identify_contributing_factors(failure, patterns)
        
        # Generate suggested fixes
        suggested_fixes = self._generate_fixes(failure, patterns)
        
        # Calculate confidence based on pattern matching and similar failures
        confidence_score = self._calculate_confidence(failure, similar_failures)
        
        # Find similar failures
        similar_failure_ids = []
        if similar_failures:
            similar_failure_ids = [f.agent_id + "_" + str(f.timestamp) for f in similar_failures[:5]]
        
        analysis = FailureAnalysis(
            failure=failure,
            root_cause=root_cause,
            contributing_factors=contributing_factors,
            suggested_fixes=suggested_fixes,
            confidence_score=confidence_score,
            similar_failures=similar_failure_ids
        )
        
        self.analysis_history.append(analysis)
        logger.info(f"Analysis complete. Root cause: {root_cause} (confidence: {confidence_score:.2f})")
        
        return analysis
    
    def _identify_root_cause(self, failure: AgentFailure, patterns: dict) -> str:
        """Identify the root cause of the failure."""
        root_causes = patterns.get("root_causes", ["Unknown root cause"])
        
        # For control plane blocks, check context for more specific cause
        if failure.failure_type == FailureType.BLOCKED_BY_CONTROL_PLANE:
            context = failure.context
            if "permission" in failure.error_message.lower():
                return "Missing or insufficient permissions for requested operation"
            elif "policy" in failure.error_message.lower():
                return "Action violates control plane policy"
            else:
                return root_causes[0]
        
        # Return the first root cause as default
        return root_causes[0]
    
    def _identify_contributing_factors(self, failure: AgentFailure, patterns: dict) -> List[str]:
        """Identify contributing factors to the failure."""
        factors = []
        
        # Check for common contributing factors
        if failure.severity.value in ["high", "critical"]:
            factors.append("High severity failure requiring immediate attention")
        
        if failure.stack_trace:
            factors.append("Stack trace available for detailed debugging")
        
        if failure.context:
            factors.append(f"Additional context available: {', '.join(failure.context.keys())}")
        
        return factors
    
    def _generate_fixes(self, failure: AgentFailure, patterns: dict) -> List[str]:
        """Generate suggested fixes for the failure."""
        fixes = patterns.get("fixes", ["Manual investigation required"])
        
        # Add specific fixes based on failure type
        if failure.failure_type == FailureType.BLOCKED_BY_CONTROL_PLANE:
            if "file" in failure.context:
                fixes.append(f"Validate access permissions for: {failure.context['file']}")
            if "action" in failure.context:
                fixes.append(f"Check if action '{failure.context['action']}' is allowed by policy")
        
        return fixes[:3]  # Return top 3 fixes
    
    def _calculate_confidence(self, failure: AgentFailure, similar_failures: Optional[List[AgentFailure]]) -> float:
        """Calculate confidence score for the analysis."""
        confidence = 0.5  # Base confidence
        
        # Increase confidence if we have a known pattern
        if failure.failure_type in self.known_patterns:
            confidence += 0.2
        
        # Increase confidence if we have similar failures
        if similar_failures and len(similar_failures) > 0:
            confidence += min(0.2, len(similar_failures) * 0.05)
        
        # Increase confidence if we have detailed context
        if failure.context and len(failure.context) > 0:
            confidence += 0.1
        
        return min(1.0, confidence)
    
    def diagnose_cognitive_glitch(self, failure: AgentFailure) -> DiagnosisJSON:
        """
        Deep diagnosis to identify cognitive glitches in agent reasoning.
        
        This is "The Analyst" - looking at the reasoning that led to the error,
        not just the error itself.
        
        Args:
            failure: AgentFailure with full trace
            
        Returns:
            DiagnosisJSON with cognitive glitch identification
        """
        logger.info(f"Diagnosing cognitive glitch for agent {failure.agent_id}")
        
        if not failure.failure_trace:
            # Fall back to basic diagnosis if no trace available
            return self._basic_diagnosis(failure)
        
        trace = failure.failure_trace
        
        # Identify cognitive glitch type
        glitch = self._identify_cognitive_glitch(failure, trace)
        
        # Deep problem analysis
        deep_problem = self._analyze_deep_problem(failure, trace, glitch)
        
        # Collect evidence
        evidence = self._collect_evidence(failure, trace, glitch)
        
        # Generate hint for counterfactual simulation
        hint = self._generate_hint(failure, trace, glitch)
        
        # Expected fix description
        expected_fix = self._describe_expected_fix(glitch, hint)
        
        # Calculate confidence
        confidence = self._calculate_diagnosis_confidence(failure, trace, evidence)
        
        diagnosis = DiagnosisJSON(
            cognitive_glitch=glitch,
            deep_problem=deep_problem,
            evidence=evidence,
            hint=hint,
            expected_fix=expected_fix,
            confidence=confidence
        )
        
        logger.info(f"Diagnosis complete: {glitch.value} (confidence: {confidence:.2f})")
        return diagnosis
    
    def _identify_cognitive_glitch(self, failure: AgentFailure, trace) -> CognitiveGlitch:
        """Identify the type of cognitive glitch."""
        error_lower = failure.error_message.lower()
        
        # Check for tool misuse (wrong parameter types) - high priority
        if any(keyword in error_lower for keyword in ["type error", "invalid type", "expected uuid", "wrong parameter type", "parameter type mismatch"]):
            return CognitiveGlitch.TOOL_MISUSE
        if "uuid" in error_lower or ("id" in error_lower and any(kw in error_lower for kw in ["invalid", "malformed", "not a valid", "format"])):
            # Check if this looks like a tool misuse scenario
            if trace.failed_action:
                action_str = str(trace.failed_action).lower()
                if any(kw in action_str for kw in ["name", "username", "email", "params", "id"]):
                    return CognitiveGlitch.TOOL_MISUSE
            return CognitiveGlitch.TOOL_MISUSE
        
        # Check for policy violations (e.g., medical advice, legal advice) - high priority
        if any(keyword in error_lower for keyword in ["policy violation", "violates policy", "not allowed to", "cannot advise", "cannot provide"]):
            return CognitiveGlitch.POLICY_VIOLATION
        # Check for specific policy domains in combination with blocking
        if trace.user_prompt:
            prompt_lower = trace.user_prompt.lower()
            if any(domain in prompt_lower for domain in ["medical", "health", "diagnosis", "treatment", "medicine", "legal", "attorney", "sue", "investment", "stock"]):
                if any(keyword in error_lower for keyword in ["blocked", "violation", "not permitted", "cannot", "policy"]):
                    return CognitiveGlitch.POLICY_VIOLATION
        
        # Check for hallucination (inventing facts) - check early before context gap
        if any(keyword in error_lower for keyword in ["not found", "does not exist", "unknown", "deprecated", "invalid reference", "no such"]):
            return CognitiveGlitch.HALLUCINATION
        
        # Check for schema mismatch
        if trace.failed_action:
            action_str = str(trace.failed_action).lower()
            if "schema" in error_lower and "mismatch" in action_str:
                return CognitiveGlitch.SCHEMA_MISMATCH
        
        # Check for logic error (misunderstanding)
        if trace.chain_of_thought:
            cot_text = " ".join(trace.chain_of_thought).lower()
            # Look for misinterpretation of terms like "recent", "delete", etc.
            if any(keyword in cot_text for keyword in ["i think", "probably", "assume", "guess"]):
                return CognitiveGlitch.LOGIC_ERROR
        
        # Check for context gap (missing information) - lower priority
        if not trace.chain_of_thought or len(trace.chain_of_thought) < 2:
            # Don't default to context gap if we have other clear signals
            if trace.failed_action and ("uuid" in error_lower or "id" in error_lower):
                return CognitiveGlitch.TOOL_MISUSE
            if any(keyword in error_lower for keyword in ["not found", "does not exist"]):
                return CognitiveGlitch.HALLUCINATION
            return CognitiveGlitch.CONTEXT_GAP
        
        # Check for permission errors
        if any(keyword in error_lower for keyword in ["permission", "unauthorized", "forbidden"]):
            # Distinguish from policy violations
            if "policy" not in error_lower and "violates" not in error_lower:
                return CognitiveGlitch.PERMISSION_ERROR
        
        return CognitiveGlitch.LOGIC_ERROR  # Default
    
    def _analyze_deep_problem(self, failure: AgentFailure, trace, glitch: CognitiveGlitch) -> str:
        """Analyze the deep problem behind the glitch."""
        if glitch == CognitiveGlitch.HALLUCINATION:
            return f"Agent invented non-existent entities in action: {trace.failed_action}"
        elif glitch == CognitiveGlitch.LOGIC_ERROR:
            return f"Agent misunderstood user intent in prompt: '{trace.user_prompt}'"
        elif glitch == CognitiveGlitch.CONTEXT_GAP:
            return f"Agent lacked necessary context (schema/permissions) to safely execute action"
        elif glitch == CognitiveGlitch.PERMISSION_ERROR:
            return f"Agent attempted unauthorized action without checking permissions first"
        elif glitch == CognitiveGlitch.SCHEMA_MISMATCH:
            return f"Agent referenced incorrect schema elements in action"
        elif glitch == CognitiveGlitch.TOOL_MISUSE:
            return f"Agent used tool with wrong parameter type or value: {trace.failed_action}"
        elif glitch == CognitiveGlitch.POLICY_VIOLATION:
            return f"Agent violated policy boundaries by attempting: '{trace.user_prompt}'"
        return "Unknown deep problem"
    
    def _collect_evidence(self, failure: AgentFailure, trace, glitch: CognitiveGlitch) -> List[str]:
        """Collect evidence supporting the diagnosis."""
        evidence = []
        
        evidence.append(f"User prompt: '{trace.user_prompt}'")
        evidence.append(f"Failed action: {trace.failed_action}")
        evidence.append(f"Error: {failure.error_message}")
        
        if trace.chain_of_thought:
            evidence.append(f"Reasoning steps: {len(trace.chain_of_thought)} steps")
            if trace.chain_of_thought:
                evidence.append(f"Last thought: '{trace.chain_of_thought[-1]}'")
        
        return evidence
    
    def _generate_hint(self, failure: AgentFailure, trace, glitch: CognitiveGlitch) -> str:
        """Generate a hint to inject for counterfactual simulation."""
        if glitch == CognitiveGlitch.HALLUCINATION:
            return "HINT: Always verify entity names against the provided schema before using them. Available tables/resources must be explicitly listed."
        elif glitch == CognitiveGlitch.LOGIC_ERROR:
            return f"HINT: When interpreting '{trace.user_prompt}', be precise about terms like 'recent', 'delete', 'modify'. Ask for clarification if ambiguous."
        elif glitch == CognitiveGlitch.CONTEXT_GAP:
            return "HINT: Before executing actions, ensure you have: 1) Complete schema information, 2) Permission requirements, 3) Clear action scope."
        elif glitch == CognitiveGlitch.PERMISSION_ERROR:
            return "HINT: Always check permissions before attempting actions. Use validate_permissions() first."
        elif glitch == CognitiveGlitch.SCHEMA_MISMATCH:
            return "HINT: Available schema elements must be verified before use. Do not assume table/column names."
        elif glitch == CognitiveGlitch.TOOL_MISUSE:
            return "HINT: Always verify parameter types match the tool schema. For example, use UUIDs where required, not names or strings."
        elif glitch == CognitiveGlitch.POLICY_VIOLATION:
            return "HINT: Some topics are outside your policy boundaries. Refuse requests for medical advice, legal advice, or other restricted domains."
        return "HINT: Proceed with caution and verify all assumptions."
    
    def _describe_expected_fix(self, glitch: CognitiveGlitch, hint: str) -> str:
        """Describe the expected outcome of applying the hint."""
        if glitch == CognitiveGlitch.HALLUCINATION:
            return "Agent will verify schema before action and use only existing entities"
        elif glitch == CognitiveGlitch.LOGIC_ERROR:
            return "Agent will correctly interpret user intent and clarify ambiguous terms"
        elif glitch == CognitiveGlitch.CONTEXT_GAP:
            return "Agent will request necessary context before proceeding with action"
        elif glitch == CognitiveGlitch.PERMISSION_ERROR:
            return "Agent will validate permissions before attempting action"
        elif glitch == CognitiveGlitch.TOOL_MISUSE:
            return "Agent will use correct parameter types according to tool schema"
        elif glitch == CognitiveGlitch.POLICY_VIOLATION:
            return "Agent will refuse to provide advice in restricted domains"
        return "Agent will handle the situation correctly"
    
    def _calculate_diagnosis_confidence(self, failure: AgentFailure, trace, evidence: List[str]) -> float:
        """Calculate confidence in the diagnosis."""
        confidence = 0.5  # Base
        
        # More confidence with complete trace
        if trace.chain_of_thought and len(trace.chain_of_thought) > 2:
            confidence += 0.2
        
        # More confidence with detailed action
        if trace.failed_action and len(trace.failed_action) > 0:
            confidence += 0.15
        
        # More confidence with rich evidence
        if len(evidence) >= 4:
            confidence += 0.15
        
        return min(1.0, confidence)
    
    def _basic_diagnosis(self, failure: AgentFailure) -> DiagnosisJSON:
        """Fallback diagnosis when no trace is available."""
        return DiagnosisJSON(
            cognitive_glitch=CognitiveGlitch.NONE,
            deep_problem=f"No trace available. Basic error: {failure.error_message}",
            evidence=[f"Error message: {failure.error_message}"],
            hint="HINT: Ensure proper validation before actions.",
            expected_fix="Action will be validated before execution",
            confidence=0.5
        )
    
    def find_similar_failures(self, failure: AgentFailure, history: List[AgentFailure]) -> List[AgentFailure]:
        """Find similar failures in history."""
        similar = []
        
        for past_failure in history:
            if past_failure.failure_type == failure.failure_type:
                # Calculate similarity based on error message
                similarity = self._calculate_similarity(failure.error_message, past_failure.error_message)
                if similarity > 0.6:
                    similar.append(past_failure)
        
        return similar[:10]  # Return top 10 similar failures
    
    def _calculate_similarity(self, msg1: str, msg2: str) -> float:
        """Calculate similarity between two error messages."""
        # Simple word-based similarity
        words1 = set(msg1.lower().split())
        words2 = set(msg2.lower().split())
        
        if not words1 or not words2:
            return 0.0
        
        intersection = words1.intersection(words2)
        union = words1.union(words2)
        
        return len(intersection) / len(union) if union else 0.0
