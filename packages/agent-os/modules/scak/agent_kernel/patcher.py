# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Agent patcher that applies corrections to agents.
"""

import logging
import uuid
from typing import Dict, Any, Optional, List
from datetime import datetime

from .models import (
    FailureAnalysis, SimulationResult, CorrectionPatch, AgentState,
    DiagnosisJSON, ShadowAgentResult, PatchStrategy, CognitiveGlitch,
    AgentFailure
)

logger = logging.getLogger(__name__)


class AgentPatcher:
    """
    Patches agents to prevent future failures.
    
    This is "The Patcher" (The Optimizer) - applies fixes permanently.
    """
    
    def __init__(self):
        self.patches: Dict[str, CorrectionPatch] = {}
        self.agent_states: Dict[str, AgentState] = {}
        self.system_prompts: Dict[str, str] = {}  # Store system prompts
        self.rag_memories: List[Dict[str, Any]] = []  # RAG memory store
    
    def create_patch(
        self,
        agent_id: str,
        analysis: FailureAnalysis,
        simulation: SimulationResult,
        diagnosis: Optional[DiagnosisJSON] = None,
        shadow_result: Optional[ShadowAgentResult] = None
    ) -> CorrectionPatch:
        """
        Create a correction patch for an agent.
        
        Args:
            agent_id: ID of the agent to patch
            analysis: Failure analysis
            simulation: Successful simulation result
            diagnosis: Cognitive glitch diagnosis if available
            shadow_result: Shadow agent verification result
            
        Returns:
            CorrectionPatch object
        """
        logger.info(f"Creating patch for agent {agent_id}")
        
        # Generate patch ID
        patch_id = f"patch-{uuid.uuid4().hex[:8]}"
        
        # Determine patch strategy (easy vs hard fix)
        strategy = self._determine_patch_strategy(analysis, diagnosis)
        
        # Determine patch type based on failure
        patch_type = self._determine_patch_type(analysis, strategy)
        
        # Generate patch content based on strategy
        patch_content = self._generate_patch_content(
            analysis, simulation, strategy, diagnosis, shadow_result
        )
        
        patch = CorrectionPatch(
            patch_id=patch_id,
            agent_id=agent_id,
            failure_analysis=analysis,
            simulation_result=simulation,
            patch_type=patch_type,
            patch_content=patch_content,
            applied=False,
            rollback_available=True,
            diagnosis=diagnosis,
            shadow_result=shadow_result
        )
        
        self.patches[patch_id] = patch
        logger.info(f"Created {patch_type} patch {patch_id} with strategy {strategy}")
        
        return patch
    
    def apply_patch(self, patch: CorrectionPatch) -> bool:
        """
        Apply a correction patch to an agent.
        
        This is "The Patcher" in action - applying the fix permanently.
        
        Args:
            patch: The patch to apply
            
        Returns:
            True if patch was applied successfully
        """
        logger.info(f"Applying patch {patch.patch_id} to agent {patch.agent_id}")
        
        try:
            # Apply patch based on type
            if patch.patch_type in [PatchStrategy.SYSTEM_PROMPT.value, "system_prompt"]:
                self._apply_system_prompt_patch(patch)
            elif patch.patch_type in [PatchStrategy.RAG_MEMORY.value, "rag_memory"]:
                self._apply_rag_memory_patch(patch)
            elif patch.patch_type == "code":
                self._apply_code_patch(patch)
            elif patch.patch_type == "config":
                self._apply_config_patch(patch)
            else:
                logger.warning(f"Unknown patch type: {patch.patch_type}, applying generically")
            
            # Mark as applied
            patch.applied = True
            patch.applied_at = datetime.utcnow()
            
            # Update agent state
            self._update_agent_state(patch.agent_id, patch)
            
            logger.info(f"Successfully applied patch {patch.patch_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to apply patch {patch.patch_id}: {e}")
            return False
    
    def _apply_system_prompt_patch(self, patch: CorrectionPatch):
        """
        Apply an easy fix: Update the system_prompt with a new rule.
        
        Example: "Always check schema before querying"
        """
        agent_id = patch.agent_id
        rule = patch.patch_content.get("rule", "")
        
        # Get or create system prompt
        if agent_id not in self.system_prompts:
            self.system_prompts[agent_id] = "You are a helpful assistant."
        
        # Append the new rule
        self.system_prompts[agent_id] += f"\n\nIMPORTANT RULE: {rule}"
        
        logger.info(f"Updated system prompt for agent {agent_id} with new rule")
    
    def _apply_rag_memory_patch(self, patch: CorrectionPatch):
        """
        Apply a hard fix: Inject a "Memory" into the vector store.
        
        Example: "In 2025, user asked X, and we failed. The correct logic is Y."
        """
        memory = {
            "agent_id": patch.agent_id,
            "timestamp": datetime.utcnow(),
            "failure_context": patch.patch_content.get("failure_context", ""),
            "correct_logic": patch.patch_content.get("correct_logic", ""),
            "patch_id": patch.patch_id,
            "embeddings_ready": False  # Would compute embeddings in real system
        }
        
        self.rag_memories.append(memory)
        
        logger.info(f"Injected RAG memory for agent {patch.agent_id}: {memory['correct_logic'][:50]}...")
    
    def _apply_code_patch(self, patch: CorrectionPatch):
        """Apply code changes patch."""
        # In real system, would modify actual code
        logger.info(f"Code patch applied (simulated) for agent {patch.agent_id}")
    
    def _apply_config_patch(self, patch: CorrectionPatch):
        """Apply configuration changes patch."""
        # In real system, would update configuration
        logger.info(f"Config patch applied (simulated) for agent {patch.agent_id}")
    
    def rollback_patch(self, patch_id: str) -> bool:
        """
        Rollback a previously applied patch.
        
        Args:
            patch_id: ID of the patch to rollback
            
        Returns:
            True if rollback was successful
        """
        if patch_id not in self.patches:
            logger.error(f"Patch {patch_id} not found")
            return False
        
        patch = self.patches[patch_id]
        
        if not patch.applied:
            logger.warning(f"Patch {patch_id} is not applied, cannot rollback")
            return False
        
        if not patch.rollback_available:
            logger.error(f"Patch {patch_id} does not support rollback")
            return False
        
        logger.info(f"Rolling back patch {patch_id}")
        
        try:
            # Rollback based on patch type
            if patch.patch_type in [PatchStrategy.SYSTEM_PROMPT.value, "system_prompt"]:
                self._rollback_system_prompt(patch)
            elif patch.patch_type in [PatchStrategy.RAG_MEMORY.value, "rag_memory"]:
                self._rollback_rag_memory(patch)
            
            # Mark as not applied
            patch.applied = False
            patch.applied_at = None
            
            # Update agent state
            if patch.agent_id in self.agent_states:
                state = self.agent_states[patch.agent_id]
                if patch_id in state.patches_applied:
                    state.patches_applied.remove(patch_id)
            
            logger.info(f"Successfully rolled back patch {patch_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to rollback patch {patch_id}: {e}")
            return False
    
    def _rollback_system_prompt(self, patch: CorrectionPatch):
        """Rollback system prompt changes."""
        # In real system, would restore previous version
        logger.info(f"Rolled back system prompt for agent {patch.agent_id}")
    
    def _rollback_rag_memory(self, patch: CorrectionPatch):
        """Rollback RAG memory injection."""
        # Remove the memory from RAG store
        self.rag_memories = [
            m for m in self.rag_memories if m.get("patch_id") != patch.patch_id
        ]
        logger.info(f"Removed RAG memory for patch {patch.patch_id}")
    
    def get_agent_state(self, agent_id: str) -> AgentState:
        """Get the current state of an agent."""
        if agent_id not in self.agent_states:
            self.agent_states[agent_id] = AgentState(
                agent_id=agent_id,
                status="unknown"
            )
        return self.agent_states[agent_id]
    
    def _determine_patch_strategy(
        self,
        analysis: FailureAnalysis,
        diagnosis: Optional[DiagnosisJSON]
    ) -> PatchStrategy:
        """
        Determine patch strategy based on the problem statement requirements:
        
        - Tool Misuse → Schema Injection (update tool definition in prompt)
        - Hallucination → RAG Patch (add negative constraint to context)
        - Policy Violation → Constitutional Update (prepend refusal rule to system prompt)
        """
        if not diagnosis:
            return PatchStrategy.CODE_CHANGE
        
        # Tool Misuse: Schema Injection - update tool definition in the prompt
        if diagnosis.cognitive_glitch == CognitiveGlitch.TOOL_MISUSE:
            return PatchStrategy.SYSTEM_PROMPT
        
        # Policy Violation: Constitutional Update - prepend refusal rule to system prompt
        if diagnosis.cognitive_glitch == CognitiveGlitch.POLICY_VIOLATION:
            return PatchStrategy.SYSTEM_PROMPT
        
        # Hallucination: RAG Patch - add negative constraint to memory
        if diagnosis.cognitive_glitch == CognitiveGlitch.HALLUCINATION:
            return PatchStrategy.RAG_MEMORY
        
        # Easy fixes: Simple cognitive glitches that can be addressed with rules
        if diagnosis.cognitive_glitch in [
            CognitiveGlitch.PERMISSION_ERROR,
            CognitiveGlitch.CONTEXT_GAP
        ]:
            if diagnosis.confidence > 0.8:
                return PatchStrategy.SYSTEM_PROMPT
        
        # Hard fixes: Complex patterns requiring historical context
        if diagnosis.cognitive_glitch in [
            CognitiveGlitch.SCHEMA_MISMATCH,
            CognitiveGlitch.LOGIC_ERROR
        ]:
            return PatchStrategy.RAG_MEMORY
        
        return PatchStrategy.CODE_CHANGE
    
    def _determine_patch_type(
        self,
        analysis: FailureAnalysis,
        strategy: PatchStrategy
    ) -> str:
        """Determine the type of patch needed."""
        # Use strategy as primary determinant
        if strategy == PatchStrategy.SYSTEM_PROMPT:
            return "system_prompt"
        elif strategy == PatchStrategy.RAG_MEMORY:
            return "rag_memory"
        elif strategy == PatchStrategy.CONFIG_UPDATE:
            return "config"
        elif strategy == PatchStrategy.RULE_UPDATE:
            return "rule"
        
        # Fall back to failure type analysis
        failure_type = analysis.failure.failure_type.value
        
        if failure_type == "blocked_by_control_plane":
            return "code"  # Code changes to add permission checks
        elif failure_type == "timeout":
            return "config"  # Configuration changes for timeouts
        elif failure_type == "invalid_action":
            return "rule"  # Rule changes to validate actions
        else:
            return "code"  # Default to code patches
    
    def _generate_patch_content(
        self,
        analysis: FailureAnalysis,
        simulation: SimulationResult,
        strategy: PatchStrategy,
        diagnosis: Optional[DiagnosisJSON] = None,
        shadow_result: Optional[ShadowAgentResult] = None
    ) -> Dict[str, Any]:
        """Generate the actual patch content based on strategy."""
        
        # EASY FIX: System Prompt Update
        if strategy == PatchStrategy.SYSTEM_PROMPT:
            rule = self._generate_system_prompt_rule(diagnosis, analysis)
            return {
                "type": "system_prompt_update",
                "rule": rule,
                "diagnosis": diagnosis.cognitive_glitch.value if diagnosis else "unknown",
                "hint_applied": diagnosis.hint if diagnosis else ""
            }
        
        # HARD FIX: RAG Memory Injection
        elif strategy == PatchStrategy.RAG_MEMORY:
            return self._generate_rag_memory_content(diagnosis, analysis, shadow_result)
        
        # CODE CHANGE
        elif strategy == PatchStrategy.CODE_CHANGE:
            return self._generate_code_change_content(analysis, simulation)
        
        # CONFIG UPDATE
        elif strategy == PatchStrategy.CONFIG_UPDATE:
            return self._generate_config_content(analysis, simulation)
        
        # Default fallback
        return {
            "type": "generic_fix",
            "suggested_fixes": analysis.suggested_fixes,
            "simulation_steps": simulation.alternative_path
        }
    
    def _generate_system_prompt_rule(
        self,
        diagnosis: Optional[DiagnosisJSON],
        analysis: FailureAnalysis
    ) -> str:
        """
        Generate a rule to add to system prompt.
        
        Implements:
        - Tool Misuse → Schema Injection (stricter tool definition)
        - Policy Violation → Constitutional Update (refusal rule)
        """
        if not diagnosis:
            return f"Always validate before: {analysis.suggested_fixes[0] if analysis.suggested_fixes else 'executing actions'}"
        
        # Tool Misuse: Schema Injection - Make tool definition stricter
        if diagnosis.cognitive_glitch == CognitiveGlitch.TOOL_MISUSE:
            failure = analysis.failure
            # Extract specific tool information from the failure
            tool_info = ""
            if failure.failure_trace and failure.failure_trace.failed_action:
                action_name = failure.failure_trace.failed_action.get("action", "tool")
                tool_info = f" for {action_name}"
            return f"SCHEMA INJECTION: Tool definitions{tool_info} require strict parameter type checking. Always verify parameter types match the schema exactly (e.g., UUID format for id parameters, not names or strings)."
        
        # Policy Violation: Constitutional Update - Prepend refusal rule
        if diagnosis.cognitive_glitch == CognitiveGlitch.POLICY_VIOLATION:
            # Determine the specific policy domain from the failure
            failure = analysis.failure
            domain = "restricted topics"
            
            # Check error message first
            error_lower = failure.error_message.lower()
            if any(kw in error_lower for kw in ["medical", "health"]):
                domain = "medical issues"
            elif any(kw in error_lower for kw in ["legal", "law"]):
                domain = "legal matters"
            elif any(kw in error_lower for kw in ["investment", "financial"]):
                domain = "investment advice"
            # Then check failure trace if available
            elif failure.failure_trace and failure.failure_trace.user_prompt:
                prompt_lower = failure.failure_trace.user_prompt.lower()
                if any(kw in prompt_lower for kw in ["medical", "health", "diagnosis", "treatment", "medicine"]):
                    domain = "medical issues"
                elif any(kw in prompt_lower for kw in ["legal", "law", "attorney", "sue", "lawsuit"]):
                    domain = "legal matters"
                elif any(kw in prompt_lower for kw in ["investment", "financial", "stock", "invest"]):
                    domain = "investment advice"
            
            return f"CONSTITUTIONAL REFUSAL RULE: You must refuse to provide advice on {domain}. Politely decline and explain that you are not qualified to advise on such matters."
        
        # Convert hint into a permanent rule for other glitches
        if diagnosis.cognitive_glitch == CognitiveGlitch.PERMISSION_ERROR:
            return "Always check permissions before attempting any action. Use validate_permissions() first."
        elif diagnosis.cognitive_glitch == CognitiveGlitch.CONTEXT_GAP:
            return "Before executing actions, ensure you have: 1) Complete schema information, 2) Permission requirements, 3) Clear action scope."
        elif diagnosis.cognitive_glitch == CognitiveGlitch.HALLUCINATION:
            return "Always verify entity names against the provided schema before using them. Never invent or assume entity names."
        elif diagnosis.cognitive_glitch == CognitiveGlitch.SCHEMA_MISMATCH:
            return "Verify all table and column names against the schema before use. Do not assume schema structure."
        elif diagnosis.cognitive_glitch == CognitiveGlitch.LOGIC_ERROR:
            return "When interpreting ambiguous terms like 'recent', 'delete', 'modify', ask for clarification before proceeding."
        
        return "Proceed with caution and verify all assumptions before actions."
    
    def _generate_rag_memory_content(
        self,
        diagnosis: Optional[DiagnosisJSON],
        analysis: FailureAnalysis,
        shadow_result: Optional[ShadowAgentResult]
    ) -> Dict[str, Any]:
        """
        Generate RAG memory content (Hard Fix).
        
        For Hallucination: Add negative constraint to the context.
        Example: "Project_Alpha is deprecated" or "Entity X does not exist"
        """
        failure = analysis.failure
        
        # Create a memory entry
        memory_text = f"In {failure.timestamp.year}, "
        negative_constraint = None
        
        if failure.failure_trace:
            memory_text += f"user asked: '{failure.failure_trace.user_prompt}', "
            memory_text += f"and we failed with: {failure.error_message}. "
            
            if diagnosis:
                memory_text += f"The problem was {diagnosis.cognitive_glitch.value}: {diagnosis.deep_problem}. "
                
                # For hallucinations, extract the hallucinated entity and create negative constraint
                if diagnosis.cognitive_glitch == CognitiveGlitch.HALLUCINATION:
                    # Extract hallucinated entity from error message or failed action
                    hallucinated_entity = self._extract_hallucinated_entity(failure)
                    if hallucinated_entity:
                        negative_constraint = f"{hallucinated_entity} does not exist and is deprecated. Do not reference it."
                        memory_text += f"NEGATIVE CONSTRAINT: {negative_constraint} "
            
            if shadow_result and shadow_result.verified:
                memory_text += f"The correct approach is: {shadow_result.output}. "
                if shadow_result.action_taken:
                    memory_text += f"Correct action: {shadow_result.action_taken}"
        else:
            memory_text += f"we encountered: {failure.error_message}. "
            memory_text += f"The correct approach is: {analysis.suggested_fixes[0] if analysis.suggested_fixes else 'validate before action'}"
        
        return {
            "type": "rag_memory",
            "failure_context": memory_text,
            "correct_logic": shadow_result.output if shadow_result else analysis.suggested_fixes[0] if analysis.suggested_fixes else "Unknown",
            "cognitive_glitch": diagnosis.cognitive_glitch.value if diagnosis else "unknown",
            "negative_constraint": negative_constraint,  # New field for hallucinations
            "timestamp": datetime.utcnow().isoformat(),
            "verified_by_shadow": shadow_result.verified if shadow_result else False
        }
    
    def _extract_hallucinated_entity(self, failure: AgentFailure) -> Optional[str]:
        """Extract the hallucinated entity name from failure context."""
        error_lower = failure.error_message.lower()
        
        # Common patterns for hallucinations
        # "Project_Alpha does not exist" -> "Project_Alpha"
        # "Table 'recent_users' not found" -> "recent_users"
        # "Unknown entity: XYZ" -> "XYZ"
        
        import re
        
        # Pattern: 'entity_name' or "entity_name" in error message
        quoted_match = re.search(r"['\"]([^'\"]+)['\"]", failure.error_message)
        if quoted_match:
            return quoted_match.group(1)
        
        # Pattern: Entity_Name or Project_Alpha (CamelCase or Snake_Case with underscores)
        if failure.failure_trace and failure.failure_trace.failed_action:
            action_str = str(failure.failure_trace.failed_action)
            # Look for CamelCase or underscore-separated capitalized words
            camel_match = re.search(r'\b([A-Z][a-z]*(?:_[A-Z][a-z]*)+)\b', action_str)
            if camel_match:
                return camel_match.group(1)
            # Also try looking for simple CamelCase 
            camel_match2 = re.search(r'\b([A-Z][a-z]+[A-Z][a-z]+(?:[A-Z][a-z]+)*)\b', action_str)
            if camel_match2:
                return camel_match2.group(1)
        
        # Try to find in error message
        camel_match3 = re.search(r'\b([A-Z][a-z]*(?:_[A-Z][a-z]*)+)\b', failure.error_message)
        if camel_match3:
            return camel_match3.group(1)
        
        return None
    
    def _generate_code_change_content(
        self,
        analysis: FailureAnalysis,
        simulation: SimulationResult
    ) -> Dict[str, Any]:
        """Generate code change content."""
        failure_type = analysis.failure.failure_type.value
        
        if failure_type == "blocked_by_control_plane":
            return {
                "type": "permission_check",
                "changes": [
                    {
                        "location": "before_action",
                        "code": "if not validate_permissions(action, resource): raise PermissionError()",
                        "description": "Add permission validation"
                    },
                    {
                        "location": "action_handler",
                        "code": "with safe_context(): execute_action()",
                        "description": "Wrap action in safe context"
                    }
                ],
                "simulation_steps": simulation.alternative_path
            }
        else:
            return {
                "type": "generic_code_fix",
                "suggested_fixes": analysis.suggested_fixes,
                "simulation_steps": simulation.alternative_path
            }
    
    def _generate_config_content(
        self,
        analysis: FailureAnalysis,
        simulation: SimulationResult
    ) -> Dict[str, Any]:
        """Generate configuration update content."""
        return {
            "type": "timeout_handling",
            "config": {
                "timeout_seconds": 30,
                "enable_progress_monitoring": True,
                "allow_partial_results": True
            },
            "simulation_steps": simulation.alternative_path
        }
    
    def _update_agent_state(self, agent_id: str, patch: CorrectionPatch):
        """Update the state of an agent after patching."""
        if agent_id not in self.agent_states:
            self.agent_states[agent_id] = AgentState(
                agent_id=agent_id,
                status="running"
            )
        
        state = self.agent_states[agent_id]
        state.status = "patched"
        state.last_failure = patch.failure_analysis.failure
        
        if patch.patch_id not in state.patches_applied:
            state.patches_applied.append(patch.patch_id)
    
    def get_patch_history(self, agent_id: Optional[str] = None) -> List[CorrectionPatch]:
        """Get patch history, optionally filtered by agent_id."""
        patches = list(self.patches.values())
        
        if agent_id:
            patches = [p for p in patches if p.agent_id == agent_id]
        
        return sorted(patches, key=lambda p: p.applied_at or datetime.min, reverse=True)
