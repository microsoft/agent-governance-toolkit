# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Baseline Agent - The "Steel Man" Reflective Tool-User

This represents a state-of-the-art reflective agent that:
1. Has access to system state (like `kubectl get all`)
2. Can reflect on failures and retry (up to 3 turns)
3. Can ask for clarification when parameters are missing
4. Uses reasoning to infer context from available information

This is the "fair fight" baseline - not a strawman, but a competent agent
that represents current industry best practices (e.g., ReAct with reflection).
"""

from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from datetime import datetime
import sys
import os

# Import the shared infrastructure API
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))
from src.core.tools import (
    MockInfrastructureAPI,
    SessionContext,
    User,
    UserRole,
    Environment,
    ResourceState,
)


@dataclass
class ReflectionStep:
    """Represents one step in the reflection loop."""
    turn: int
    thought: str
    action: Optional[str]
    parameters: Optional[Dict[str, Any]]
    result: Optional[Dict[str, Any]]
    error: Optional[str]
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class BaselineAgentResult:
    """Result from baseline agent execution."""
    success: bool
    action_taken: Optional[str]
    parameters_used: Optional[Dict[str, Any]]
    final_result: Optional[Dict[str, Any]]
    
    # Failure analysis
    hallucinated: bool
    hallucination_details: Optional[str]
    safety_violation: bool
    state_misalignment: bool
    
    # Performance metrics
    token_count: int
    reflection_steps: List[ReflectionStep]
    turns_used: int
    latency_ms: float
    
    # Clarification
    needed_clarification: bool
    clarification_question: Optional[str]


class BaselineAgent:
    """
    The Steel Man Baseline Agent - Reflective Tool-User
    
    Architecture:
    - Maintains context by querying system state
    - Uses reasoning to infer missing parameters
    - Reflects on failures and retries (up to 3 turns)
    - Can ask user for clarification
    
    This represents a "good" baseline that doesn't just guess blindly,
    but uses available tools and reasoning to make informed decisions.
    """
    
    # Token costs (simulated)
    BASE_SYSTEM_PROMPT_TOKENS = 800  # Includes reflection instructions
    TOOL_DEFINITIONS_TOKENS = 500  # All tool schemas in context
    REASONING_TOKENS = 300  # Per reasoning step
    REFLECTION_TOKENS = 400  # Per reflection turn
    
    MAX_REFLECTION_TURNS = 3
    
    def __init__(self, api: MockInfrastructureAPI):
        """Initialize with access to infrastructure API."""
        self.api = api
        self.execution_history: List[BaselineAgentResult] = []
    
    def execute_request(
        self, 
        user_command: str, 
        context: SessionContext,
        allow_clarification: bool = True
    ) -> BaselineAgentResult:
        """
        Execute a user request using reflection and tool access.
        
        Args:
            user_command: Natural language command from user
            context: Session context with user info and history
            allow_clarification: Whether agent can ask user for clarification
        
        Returns:
            BaselineAgentResult with execution details
        """
        start_time = datetime.now()
        reflection_steps: List[ReflectionStep] = []
        token_count = self.BASE_SYSTEM_PROMPT_TOKENS + self.TOOL_DEFINITIONS_TOKENS
        
        # Turn 1: Initial attempt with reasoning
        result = self._attempt_execution(
            user_command, context, reflection_steps, allow_clarification
        )
        token_count += self.REASONING_TOKENS
        
        # If initial attempt needs clarification, return early
        if result.needed_clarification:
            latency = (datetime.now() - start_time).total_seconds() * 1000
            result.token_count = token_count
            result.latency_ms = latency
            result.turns_used = 1
            return result
        
        # Reflection loop (up to MAX_REFLECTION_TURNS)
        turn = 1
        while not result.success and turn < self.MAX_REFLECTION_TURNS:
            turn += 1
            token_count += self.REFLECTION_TOKENS
            
            # Reflect on why previous attempt failed
            reflection = self._reflect_on_failure(result, context)
            reflection_steps.append(reflection)
            
            # Retry with updated understanding
            result = self._attempt_execution(
                user_command, context, reflection_steps, allow_clarification
            )
            token_count += self.REASONING_TOKENS
            
            if result.needed_clarification:
                break
        
        # Finalize result
        latency = (datetime.now() - start_time).total_seconds() * 1000
        result.token_count = token_count
        result.latency_ms = latency
        result.turns_used = turn
        result.reflection_steps = reflection_steps
        
        self.execution_history.append(result)
        return result
    
    def _attempt_execution(
        self,
        user_command: str,
        context: SessionContext,
        reflection_steps: List[ReflectionStep],
        allow_clarification: bool
    ) -> BaselineAgentResult:
        """
        Attempt to execute the user command.
        
        This simulates the agent's reasoning process:
        1. Query system state for context
        2. Parse the command and infer intent
        3. Try to resolve missing parameters
        4. Execute the action
        """
        # Step 1: Get system state for context (this is the agent's "awareness")
        system_state = self.api.get_system_state(context)
        
        # Step 2: Parse command and infer intent
        intent = self._parse_command(user_command)
        
        # Step 3: Try to resolve parameters
        resolution_result = self._resolve_parameters(
            intent, user_command, context, system_state, reflection_steps
        )
        
        if resolution_result["needs_clarification"] and allow_clarification:
            return BaselineAgentResult(
                success=False,
                action_taken=None,
                parameters_used=None,
                final_result=None,
                hallucinated=False,
                hallucination_details=None,
                safety_violation=False,
                state_misalignment=False,
                token_count=0,  # Will be set later
                reflection_steps=[],
                turns_used=0,
                latency_ms=0,
                needed_clarification=True,
                clarification_question=resolution_result["clarification_question"]
            )
        
        # Step 4: Execute the action
        action = resolution_result["action"]
        params = resolution_result["parameters"]
        
        return self._execute_action(action, params, context, system_state)
    
    def _parse_command(self, command: str) -> str:
        """
        Parse user command to determine intent.
        
        This uses simple keyword matching. A real agent would use an LLM.
        """
        command_lower = command.lower()
        
        if "restart" in command_lower:
            return "restart_service"
        elif "scale" in command_lower:
            return "scale_service"
        elif "rollback" in command_lower:
            return "rollback_deployment"
        elif "force delete" in command_lower or "force-delete" in command_lower:
            return "force_delete"
        elif "delete" in command_lower or "remove" in command_lower or "clean" in command_lower:
            return "force_delete"
        elif "start" in command_lower and "restart" not in command_lower:
            return "start_service"
        elif "stop" in command_lower:
            return "stop_service"
        elif "fix" in command_lower:
            return "restart_service"  # Assume restart is the fix
        else:
            return "unknown"
    
    def _resolve_parameters(
        self,
        intent: str,
        command: str,
        context: SessionContext,
        system_state: Dict[str, Any],
        reflection_steps: List[ReflectionStep]
    ) -> Dict[str, Any]:
        """
        Try to resolve parameters for the action.
        
        The Baseline Agent's Strategy:
        1. Check if service is explicitly named in command
        2. If not, use context.last_service_accessed (STALE STATE RISK!)
        3. If still missing, look for services mentioned in reflection
        4. If still missing, ask for clarification
        
        This is where the baseline agent is vulnerable to the "Stale State" scenario.
        """
        services = system_state.get("services", {})
        
        # For actions that need a service
        if intent in ["restart_service", "scale_service", "start_service", "stop_service", "force_delete"]:
            # Try to find service in command
            service_id = self._find_service_in_command(command, services)
            
            if service_id:
                # Found explicitly in command
                result = {
                    "action": intent,
                    "parameters": {"service_id": service_id},
                    "needs_clarification": False,
                    "clarification_question": None,
                    "resolution_method": "explicit"
                }
            elif context.last_service_accessed:
                # VULNERABILITY: Use last accessed service (might be stale!)
                service_id = context.last_service_accessed
                result = {
                    "action": intent,
                    "parameters": {"service_id": service_id},
                    "needs_clarification": False,
                    "clarification_question": None,
                    "resolution_method": "stale_context"  # This is the problem!
                }
            else:
                # Need clarification
                result = {
                    "action": intent,
                    "parameters": None,
                    "needs_clarification": True,
                    "clarification_question": f"Which service would you like to {intent.replace('_', ' ')}?",
                    "resolution_method": "clarification"
                }
            
            # Add replicas for scale operations
            if intent == "scale_service" and not result["needs_clarification"]:
                replicas = self._extract_number(command)
                if replicas:
                    result["parameters"]["replicas"] = replicas
                else:
                    result["needs_clarification"] = True
                    result["clarification_question"] = "How many replicas would you like?"
            
            return result
        
        elif intent == "rollback_deployment":
            # Try to find deployment ID
            deployment_id = self._find_deployment_in_state(system_state)
            
            if deployment_id:
                return {
                    "action": intent,
                    "parameters": {"deployment_id": deployment_id},
                    "needs_clarification": False,
                    "clarification_question": None,
                    "resolution_method": "inferred"
                }
            else:
                return {
                    "action": intent,
                    "parameters": None,
                    "needs_clarification": True,
                    "clarification_question": "Which deployment would you like to rollback?",
                    "resolution_method": "clarification"
                }
        
        else:
            # Unknown intent
            return {
                "action": "unknown",
                "parameters": None,
                "needs_clarification": True,
                "clarification_question": f"I'm not sure what you want to do. Can you clarify?",
                "resolution_method": "clarification"
            }
    
    def _find_service_in_command(self, command: str, services: Dict[str, Any]) -> Optional[str]:
        """
        Try to find a service ID from the command text.
        
        Looks for service names or IDs mentioned in the command.
        """
        command_lower = command.lower()
        
        # Check each service
        for service_id, service_data in services.items():
            service_name = service_data.get("name", "").lower()
            env = service_data.get("environment", "").lower()
            
            # Check if service name is in command
            if service_name in command_lower:
                # If environment is also mentioned, use that to disambiguate
                if env in command_lower:
                    return service_id
                # If only one service with this name, use it
                matching_services = [
                    sid for sid, sdata in services.items()
                    if sdata.get("name", "").lower() == service_name
                ]
                if len(matching_services) == 1:
                    return matching_services[0]
                # Multiple services with same name, check environment hints
                if "prod" in command_lower and "prod" in env:
                    return service_id
                if "dev" in command_lower and "dev" in env:
                    return service_id
                if "staging" in command_lower and "staging" in env:
                    return service_id
        
        # Check for pronouns like "it" or "the service"
        # These are ambiguous - we'll return None and rely on context
        if any(word in command_lower for word in ["it", "the service", "this service"]):
            return None
        
        return None
    
    def _extract_number(self, text: str) -> Optional[int]:
        """Extract a number from text (for replica counts, etc.)"""
        import re
        numbers = re.findall(r'\d+', text)
        return int(numbers[0]) if numbers else None
    
    def _find_deployment_in_state(self, system_state: Dict[str, Any]) -> Optional[str]:
        """Find a deployment ID from system state."""
        deployments = system_state.get("deployments", {})
        if deployments:
            # Return first deployment (might not be the right one!)
            return list(deployments.keys())[0]
        return None
    
    def _execute_action(
        self,
        action: str,
        parameters: Dict[str, Any],
        context: SessionContext,
        system_state: Dict[str, Any]
    ) -> BaselineAgentResult:
        """Execute the determined action."""
        # Check if parameters is None (couldn't resolve)
        if parameters is None:
            return BaselineAgentResult(
                success=False,
                action_taken=action,
                parameters_used=None,
                final_result={"error": "Could not resolve parameters"},
                hallucinated=False,
                hallucination_details=None,
                safety_violation=False,
                state_misalignment=False,
                token_count=0,
                reflection_steps=[],
                turns_used=0,
                latency_ms=0,
                needed_clarification=False,
                clarification_question=None
            )
        
        # Map action to API call
        if action == "restart_service":
            result = self.api.restart_service(parameters["service_id"], context)
        elif action == "scale_service":
            result = self.api.scale_service(
                parameters["service_id"], 
                parameters["replicas"], 
                context
            )
        elif action == "rollback_deployment":
            result = self.api.rollback_deployment(parameters["deployment_id"], context)
        elif action == "force_delete":
            result = self.api.force_delete(parameters["service_id"], context)
        else:
            result = {"error": "Unknown action", "safety_violation": False}
        
        # Analyze result
        success = result.get("success", False)
        error = result.get("error")
        safety_violation = result.get("safety_violation", False)
        
        # Detect hallucination (using stale context)
        hallucinated = False
        hallucination_details = None
        state_misalignment = False
        
        # Check if we used stale context (didn't match current focus)
        if context.current_focus and context.current_focus != context.last_service_accessed:
            if parameters and parameters.get("service_id") == context.last_service_accessed:
                hallucinated = True
                hallucination_details = f"Used stale context: {context.last_service_accessed} instead of current focus: {context.current_focus}"
                state_misalignment = True
        
        return BaselineAgentResult(
            success=success,
            action_taken=action,
            parameters_used=parameters,
            final_result=result if success else None,
            hallucinated=hallucinated,
            hallucination_details=hallucination_details,
            safety_violation=safety_violation,
            state_misalignment=state_misalignment,
            token_count=0,  # Will be set by caller
            reflection_steps=[],
            turns_used=0,
            latency_ms=0,
            needed_clarification=False,
            clarification_question=None
        )
    
    def _reflect_on_failure(
        self,
        previous_result: BaselineAgentResult,
        context: SessionContext
    ) -> ReflectionStep:
        """
        Reflect on why the previous attempt failed.
        
        This simulates the agent thinking about what went wrong and
        adjusting its strategy.
        """
        error = previous_result.final_result.get("error") if previous_result.final_result else "Unknown error"
        
        # Analyze the error and form a reflection
        if "Permission denied" in str(error):
            thought = "The user doesn't have permission. Should check user role before attempting."
        elif "partial state" in str(error):
            thought = "Service is in partial/zombie state. Should use force_delete instead."
        elif "not found" in str(error):
            thought = "Resource doesn't exist. Should verify existence first."
        else:
            thought = f"Operation failed: {error}. Need to reconsider approach."
        
        return ReflectionStep(
            turn=len(previous_result.reflection_steps) + 1,
            thought=thought,
            action=previous_result.action_taken,
            parameters=previous_result.parameters_used,
            result=previous_result.final_result,
            error=error,
        )
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get performance statistics across all executions."""
        if not self.execution_history:
            return {}
        
        total = len(self.execution_history)
        successful = len([r for r in self.execution_history if r.success])
        hallucinated = len([r for r in self.execution_history if r.hallucinated])
        safety_violations = len([r for r in self.execution_history if r.safety_violation])
        state_misalignments = len([r for r in self.execution_history if r.state_misalignment])
        needed_clarification = len([r for r in self.execution_history if r.needed_clarification])
        
        avg_tokens = sum(r.token_count for r in self.execution_history) / total
        avg_latency = sum(r.latency_ms for r in self.execution_history) / total
        avg_turns = sum(r.turns_used for r in self.execution_history) / total
        
        return {
            "total_executions": total,
            "success_rate": successful / total if total > 0 else 0,
            "hallucination_rate": hallucinated / total if total > 0 else 0,
            "safety_violation_rate": safety_violations / total if total > 0 else 0,
            "state_misalignment_rate": state_misalignments / total if total > 0 else 0,
            "clarification_rate": needed_clarification / total if total > 0 else 0,
            "avg_tokens": avg_tokens,
            "avg_latency_ms": avg_latency,
            "avg_turns": avg_turns,
        }
