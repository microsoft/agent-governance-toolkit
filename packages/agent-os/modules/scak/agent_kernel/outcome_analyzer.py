# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Outcome Analyzer - Filters agent outcomes for competence issues.

This is part of Loop 2 (Alignment Engine) that identifies when agents
"give up" with negative results instead of delivering value.

Enhanced with:
- Tool execution telemetry to distinguish valid empty results from laziness
- Semantic analysis for detecting subtle forms of refusal
"""

import logging
import re
from typing import Optional, List
from datetime import datetime

from .models import (
    AgentOutcome,
    OutcomeType,
    GiveUpSignal,
    ToolExecutionTelemetry,
    ToolExecutionStatus
)
from .semantic_analyzer import SemanticAnalyzer

logger = logging.getLogger(__name__)


class OutcomeAnalyzer:
    """
    Analyzes agent outcomes to detect "Give-Up Signals" (Laziness).
    
    This filters for competence issues - when agents comply with safety rules
    but fail to deliver value (e.g., "No data found" is safe, but wrong if data exists).
    
    Enhanced Features:
    1. Tool Execution Telemetry - Correlates give-up signals with tool usage
    2. Semantic Analysis - Goes beyond regex for subtle refusal detection
    3. False Positive Prevention - Distinguishes valid empty results from laziness
    """
    
    def __init__(self, use_semantic_analysis: bool = True):
        self.give_up_patterns = self._load_give_up_patterns()
        self.outcome_history: List[AgentOutcome] = []
        self.use_semantic_analysis = use_semantic_analysis
        self.semantic_analyzer = SemanticAnalyzer() if use_semantic_analysis else None
    
    def _load_give_up_patterns(self) -> dict:
        """Load patterns that indicate agent is giving up."""
        return {
            GiveUpSignal.NO_DATA_FOUND: [
                r"no (?:data|results|logs|records|information) (?:found|available)",
                r"could(?:n't| not) find (?:any |the )?(?:data|logs|records|information)",
                r"(?:data|logs|records) (?:not found|unavailable|missing)",
                r"no matching (?:data|logs|records|results)"
            ],
            GiveUpSignal.CANNOT_ANSWER: [
                r"(?:i )?cannot answer",
                r"(?:i )?(?:can't|cannot) (?:help|assist|answer) (?:with|you)",
                r"unable to (?:answer|respond|help)",
                r"(?:i )?don't have (?:enough|sufficient) information"
            ],
            GiveUpSignal.NO_RESULTS: [
                r"no results",
                r"0 results",
                r"zero results",
                r"empty result set",
                r"query returned (?:no|zero) results"
            ],
            GiveUpSignal.NOT_AVAILABLE: [
                r"(?:not|isn't) (?:currently )?available",
                r"(?:is|are) unavailable",
                r"(?:service|resource|data) (?:not|isn't) available"
            ],
            GiveUpSignal.INSUFFICIENT_INFO: [
                r"insufficient (?:data|information)",
                r"not enough (?:data|information|context)",
                r"incomplete (?:data|information)",
                r"missing (?:required|necessary) (?:data|information)"
            ]
        }
    
    def analyze_outcome(
        self,
        agent_id: str,
        user_prompt: str,
        agent_response: str,
        context: Optional[dict] = None,
        tool_telemetry: Optional[List[ToolExecutionTelemetry]] = None
    ) -> AgentOutcome:
        """
        Analyze an agent's outcome to determine if it gave up.
        
        Enhanced with tool telemetry correlation and semantic analysis.
        
        Args:
            agent_id: ID of the agent
            user_prompt: Original user request
            agent_response: Agent's response
            context: Additional context
            tool_telemetry: Tool execution telemetry data
            
        Returns:
            AgentOutcome with classification and analysis
        """
        logger.info(f"Analyzing outcome for agent {agent_id}")
        
        # Check if this is a give-up signal (regex-based)
        give_up_signal = self._detect_give_up_signal(agent_response)
        
        # Perform semantic analysis if enabled
        semantic_analysis = None
        if self.use_semantic_analysis:
            semantic_analysis = self.semantic_analyzer.analyze(
                agent_response=agent_response,
                user_prompt=user_prompt,
                tool_telemetry=tool_telemetry
            )
            logger.debug(f"Semantic analysis: {semantic_analysis.semantic_category} "
                        f"(confidence: {semantic_analysis.refusal_confidence:.2f})")
        
        # Determine outcome type with enhanced logic
        outcome_type = self._determine_outcome_type(
            agent_response=agent_response,
            give_up_signal=give_up_signal,
            tool_telemetry=tool_telemetry,
            semantic_analysis=semantic_analysis
        )
        
        if outcome_type == OutcomeType.GIVE_UP:
            logger.warning(f"Give-up detected: signal={give_up_signal.value if give_up_signal else 'semantic'}")
        
        outcome = AgentOutcome(
            agent_id=agent_id,
            outcome_type=outcome_type,
            user_prompt=user_prompt,
            agent_response=agent_response,
            give_up_signal=give_up_signal,
            context=context or {},
            tool_telemetry=tool_telemetry or [],
            semantic_analysis=semantic_analysis
        )
        
        self.outcome_history.append(outcome)
        
        return outcome
    
    def _detect_give_up_signal(self, response: str) -> Optional[GiveUpSignal]:
        """
        Detect if the response contains a give-up signal.
        
        These are "Negative Results" that trigger the Completeness Auditor.
        """
        response_lower = response.lower()
        
        # Check each pattern category
        for signal_type, patterns in self.give_up_patterns.items():
            for pattern in patterns:
                if re.search(pattern, response_lower):
                    logger.debug(f"Matched pattern '{pattern}' for signal {signal_type.value}")
                    return signal_type
        
        return None
    
    def _determine_outcome_type(
        self,
        agent_response: str,
        give_up_signal: Optional[GiveUpSignal],
        tool_telemetry: Optional[List[ToolExecutionTelemetry]],
        semantic_analysis: Optional[any]
    ) -> OutcomeType:
        """
        Determine outcome type with enhanced logic.
        
        Considers:
        1. Regex-based give-up signal
        2. Tool execution telemetry
        3. Semantic analysis
        
        Key Enhancement: Correlation with tool execution to avoid false positives
        """
        # Check regex signal
        has_regex_signal = give_up_signal is not None
        
        # Check semantic signal
        has_semantic_signal = (
            semantic_analysis is not None and
            semantic_analysis.is_refusal and
            semantic_analysis.refusal_confidence > 0.6
        )
        
        # Analyze tool telemetry
        tool_analysis = self._analyze_tool_execution(tool_telemetry)
        
        # Decision logic with false positive prevention
        if has_regex_signal or has_semantic_signal:
            # Agent said "no data found" or similar
            
            # Check if tools were actually called and returned empty
            if tool_analysis["tools_called"] and tool_analysis["all_empty_results"]:
                # Valid empty result: Tools called, returned empty -> SUCCESS
                logger.info("Give-up signal present but tools returned empty results - valid empty set")
                return OutcomeType.SUCCESS
            
            elif tool_analysis["tools_called"] and tool_analysis["has_errors"]:
                # Tools called but errored -> Potential laziness (didn't handle errors)
                logger.warning("Give-up with tool errors - potential laziness or error handling issue")
                return OutcomeType.GIVE_UP
            
            elif not tool_analysis["tools_called"]:
                # No tools called -> Clear laziness
                logger.warning("Give-up signal without tool execution - clear laziness")
                return OutcomeType.GIVE_UP
            
            else:
                # Mixed results or unclear -> Default to GIVE_UP for audit
                logger.warning("Give-up signal with unclear tool usage - flagging for audit")
                return OutcomeType.GIVE_UP
        
        else:
            # No give-up signal detected
            if len(agent_response.strip()) < 20:
                return OutcomeType.FAILURE
            else:
                return OutcomeType.SUCCESS
    
    def _analyze_tool_execution(
        self,
        tool_telemetry: Optional[List[ToolExecutionTelemetry]]
    ) -> dict:
        """
        Analyze tool execution telemetry.
        
        Returns a dict with:
        - tools_called: bool - Were any tools called?
        - all_empty_results: bool - Did all tools return empty results?
        - has_errors: bool - Did any tools error?
        - tool_count: int - Number of tools called
        """
        if not tool_telemetry:
            return {
                "tools_called": False,
                "all_empty_results": False,
                "has_errors": False,
                "tool_count": 0
            }
        
        called_tools = [
            t for t in tool_telemetry
            if t.tool_status != ToolExecutionStatus.NOT_CALLED
        ]
        
        if not called_tools:
            return {
                "tools_called": False,
                "all_empty_results": False,
                "has_errors": False,
                "tool_count": 0
            }
        
        empty_results = [
            t for t in called_tools
            if t.tool_status == ToolExecutionStatus.EMPTY_RESULT
        ]
        
        errored_tools = [
            t for t in called_tools
            if t.tool_status == ToolExecutionStatus.ERROR
        ]
        
        return {
            "tools_called": True,
            "all_empty_results": len(empty_results) == len(called_tools),
            "has_errors": len(errored_tools) > 0,
            "tool_count": len(called_tools),
            "empty_count": len(empty_results),
            "error_count": len(errored_tools)
        }
    
    def should_trigger_audit(self, outcome: AgentOutcome) -> bool:
        """
        Determine if this outcome should trigger a Completeness Audit.
        
        The Completeness Auditor is only triggered on "Give-Up Signals"
        to avoid expensive auditing of every interaction.
        
        Args:
            outcome: The agent outcome
            
        Returns:
            True if Completeness Auditor should be triggered
        """
        return outcome.outcome_type == OutcomeType.GIVE_UP
    
    def get_give_up_rate(self, agent_id: Optional[str] = None, recent_n: int = 100) -> float:
        """
        Calculate the give-up rate for an agent.
        
        This metric helps identify agents that are consistently lazy.
        
        Args:
            agent_id: Optional agent ID to filter by
            recent_n: Number of recent outcomes to analyze
            
        Returns:
            Give-up rate as a float between 0 and 1
        """
        outcomes = self.outcome_history[-recent_n:]
        
        if agent_id:
            outcomes = [o for o in outcomes if o.agent_id == agent_id]
        
        if not outcomes:
            return 0.0
        
        give_ups = sum(1 for o in outcomes if o.outcome_type == OutcomeType.GIVE_UP)
        
        return give_ups / len(outcomes)
    
    def get_outcome_history(
        self,
        agent_id: Optional[str] = None,
        outcome_type: Optional[OutcomeType] = None,
        limit: int = 100
    ) -> List[AgentOutcome]:
        """Get outcome history with optional filters."""
        outcomes = self.outcome_history[-limit:]
        
        if agent_id:
            outcomes = [o for o in outcomes if o.agent_id == agent_id]
        
        if outcome_type:
            outcomes = [o for o in outcomes if o.outcome_type == outcome_type]
        
        return outcomes
