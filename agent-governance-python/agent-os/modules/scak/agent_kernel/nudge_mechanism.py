# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Nudge Mechanism - Automatic retry with targeted prompting.

When an agent gives up (GIVE_UP outcome), this module automatically
injects a "nudge" prompt to encourage the agent to try harder.

This implements "The Nudge" pattern from industry best practices:
- Automatic intervention without human involvement
- Targeted prompting based on the give-up type
- Tracking of nudge effectiveness
"""

import logging
import uuid
from typing import Optional, List
from datetime import datetime

from .models import AgentOutcome, NudgeResult, GiveUpSignal

logger = logging.getLogger(__name__)


class NudgeMechanism:
    """
    Implements automatic nudging when agents give up.
    
    The "nudge" is a system prompt injection that asks the agent
    to confirm it executed the task correctly and encourages
    a more thorough attempt.
    
    Example nudge:
    "You claimed no data was found. Please confirm you executed the 
    search tool with the correct parameters and checked all data sources."
    """
    
    def __init__(self):
        """Initialize the nudge mechanism."""
        self.nudge_history: List[NudgeResult] = []
        self.nudge_templates = self._load_nudge_templates()
        
    def _load_nudge_templates(self) -> dict:
        """Load nudge prompt templates for different give-up signals."""
        return {
            GiveUpSignal.NO_DATA_FOUND: (
                "You claimed no data was found. Please confirm you:\n"
                "1. Executed the search/query tool with the correct parameters\n"
                "2. Checked all relevant data sources including archives\n"
                "3. Used appropriate time ranges and filters\n"
                "Please retry with a more comprehensive search strategy."
            ),
            GiveUpSignal.CANNOT_ANSWER: (
                "You indicated you cannot answer this question. Please confirm you:\n"
                "1. Have access to all necessary tools and resources\n"
                "2. Attempted to use available tools to gather information\n"
                "3. Considered alternative approaches to the problem\n"
                "Please retry with a different strategy."
            ),
            GiveUpSignal.NO_RESULTS: (
                "You reported no results. Please confirm you:\n"
                "1. Used the correct query syntax and parameters\n"
                "2. Checked for typos or incorrect field names\n"
                "3. Tried alternative search terms or filters\n"
                "Please retry with validated parameters."
            ),
            GiveUpSignal.NOT_AVAILABLE: (
                "You indicated the resource is not available. Please confirm you:\n"
                "1. Checked the resource location and accessibility\n"
                "2. Verified you have the correct permissions\n"
                "3. Checked for alternative access methods\n"
                "Please retry with proper access verification."
            ),
            GiveUpSignal.INSUFFICIENT_INFO: (
                "You claimed insufficient information. Please confirm you:\n"
                "1. Attempted to gather additional context from available sources\n"
                "2. Used all available tools to retrieve more information\n"
                "3. Considered what information is actually required vs. nice-to-have\n"
                "Please retry with available information."
            ),
            GiveUpSignal.UNKNOWN: (
                "Your response suggests you may have given up. Please:\n"
                "1. Re-read the user's request carefully\n"
                "2. Use all available tools to attempt the task\n"
                "3. Provide a specific explanation if truly impossible\n"
                "Please retry with full effort."
            )
        }
    
    def generate_nudge(
        self,
        outcome: AgentOutcome,
        include_tool_reminder: bool = True
    ) -> str:
        """
        Generate a nudge prompt for the given outcome.
        
        Args:
            outcome: The agent outcome that triggered the nudge
            include_tool_reminder: Whether to include tool usage reminder
            
        Returns:
            Nudge prompt string
        """
        signal = outcome.give_up_signal or GiveUpSignal.UNKNOWN
        template = self.nudge_templates.get(signal, self.nudge_templates[GiveUpSignal.UNKNOWN])
        
        nudge_prompt = template
        
        # Add context-specific enhancements
        if include_tool_reminder and outcome.tool_telemetry:
            called_tools = [t.tool_name for t in outcome.tool_telemetry]
            if called_tools:
                # Tools were called
                nudge_prompt += f"\n\nNote: You previously used tools: {', '.join(called_tools)}. Consider using additional tools or different parameters."
            else:
                # Telemetry exists but no tools were called
                nudge_prompt += "\n\nNote: It appears no tools were called. Please use available tools to complete the task."
        elif include_tool_reminder:
            # No telemetry at all
            nudge_prompt += "\n\nNote: It appears no tools were called. Please use available tools to complete the task."
        
        # Add original prompt reminder
        nudge_prompt += f"\n\nOriginal request: {outcome.user_prompt}"
        
        return nudge_prompt
    
    def should_nudge(
        self,
        outcome: AgentOutcome,
        max_nudges: int = 1
    ) -> bool:
        """
        Determine if we should nudge for this outcome.
        
        Args:
            outcome: The agent outcome
            max_nudges: Maximum number of nudges per agent/task
            
        Returns:
            True if nudge should be applied
        """
        # Check if outcome is a give-up
        from .models import OutcomeType
        if outcome.outcome_type != OutcomeType.GIVE_UP:
            return False
        
        # Check if we've already nudged this agent recently
        recent_nudges = [
            n for n in self.nudge_history
            if n.original_outcome.agent_id == outcome.agent_id
            and (datetime.utcnow() - n.original_outcome.timestamp).total_seconds() < 300  # 5 min
        ]
        
        if len(recent_nudges) >= max_nudges:
            logger.info(f"Max nudges ({max_nudges}) reached for agent {outcome.agent_id}")
            return False
        
        return True
    
    def record_nudge_result(
        self,
        outcome: AgentOutcome,
        nudge_prompt: str,
        retry_response: str,
        retry_successful: bool
    ) -> NudgeResult:
        """
        Record the result of a nudge attempt.
        
        Args:
            outcome: Original outcome that triggered nudge
            nudge_prompt: The nudge prompt that was used
            retry_response: Agent's response after nudge
            retry_successful: Whether the retry was successful
            
        Returns:
            NudgeResult object
        """
        nudge_id = f"nudge-{uuid.uuid4().hex[:8]}"
        
        # Detect improvement
        improvement = self._detect_improvement(
            original_response=outcome.agent_response,
            retry_response=retry_response
        )
        
        result = NudgeResult(
            nudge_id=nudge_id,
            original_outcome=outcome,
            nudge_prompt=nudge_prompt,
            retry_response=retry_response,
            retry_successful=retry_successful,
            improvement_detected=improvement
        )
        
        self.nudge_history.append(result)
        
        logger.info(f"Nudge {nudge_id}: success={retry_successful}, improvement={improvement}")
        
        return result
    
    def _detect_improvement(
        self,
        original_response: str,
        retry_response: str
    ) -> bool:
        """
        Detect if retry response shows improvement over original.
        
        Simple heuristic: longer response with less refusal language.
        """
        # Length improvement
        length_improved = len(retry_response) > len(original_response) * 1.2
        
        # Refusal language reduction
        refusal_words = ["no data", "cannot", "can't", "unable", "not found"]
        original_refusals = sum(1 for word in refusal_words if word in original_response.lower())
        retry_refusals = sum(1 for word in refusal_words if word in retry_response.lower())
        refusal_reduced = retry_refusals < original_refusals
        
        # Check for data/results mention
        data_indicators = ["found", "results", "data shows", "here is", "here are"]
        has_data_now = any(indicator in retry_response.lower() for indicator in data_indicators)
        
        return length_improved or refusal_reduced or has_data_now
    
    def get_nudge_stats(self) -> dict:
        """Get statistics about nudge effectiveness."""
        if not self.nudge_history:
            return {
                "total_nudges": 0,
                "successful_nudges": 0,
                "success_rate": 0.0,
                "improvements": 0,
                "improvement_rate": 0.0
            }
        
        successful = sum(1 for n in self.nudge_history if n.retry_successful)
        improvements = sum(1 for n in self.nudge_history if n.improvement_detected)
        
        return {
            "total_nudges": len(self.nudge_history),
            "successful_nudges": successful,
            "success_rate": successful / len(self.nudge_history),
            "improvements": improvements,
            "improvement_rate": improvements / len(self.nudge_history),
            "recent_nudges": self.nudge_history[-10:]  # Last 10 nudges
        }
    
    def get_nudge_history(
        self,
        agent_id: Optional[str] = None,
        limit: int = 100
    ) -> List[NudgeResult]:
        """Get nudge history with optional filtering."""
        history = self.nudge_history[-limit:]
        
        if agent_id:
            history = [n for n in history if n.original_outcome.agent_id == agent_id]
        
        return history
