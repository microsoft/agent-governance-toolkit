# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Semantic Analyzer - Advanced refusal detection beyond regex patterns.

This module provides semantic analysis of agent responses to detect
"refusal" vs "compliance" behavior using contextual understanding
rather than just pattern matching.
"""

import logging
from typing import Optional, List

from .models import SemanticAnalysis

logger = logging.getLogger(__name__)


class SemanticAnalyzer:
    """
    Analyzes agent responses semantically to detect refusal patterns.
    
    Unlike regex-based detection, this analyzes the semantic meaning
    to catch subtle forms of giving up like:
    - "I'm afraid those records are elusive at the moment."
    - "The information seems to be unavailable."
    - "It appears there's nothing to show."
    
    This is inspired by "Refusal Benchmarking" in AI safety research.
    """
    
    def __init__(self):
        """Initialize the semantic analyzer."""
        self.refusal_indicators = self._load_refusal_indicators()
        self.compliance_indicators = self._load_compliance_indicators()
        
    def _load_refusal_indicators(self) -> List[str]:
        """Load semantic indicators of refusal/giving up."""
        return [
            # Direct refusal phrases
            "cannot", "can't", "unable", "impossible", "won't",
            "don't have", "doesn't exist", "not available", "unavailable",
            
            # Evasive/elusive language
            "elusive", "appears to be", "seems to be", "might be",
            "could be", "perhaps", "possibly", "unclear",
            
            # Uncertainty/hedging
            "I'm afraid", "unfortunately", "regrettably", "sadly",
            "it seems", "it appears", "looks like",
            
            # Empty/negative results
            "no data", "no results", "no information", "nothing found",
            "zero results", "empty", "none available",
            
            # Insufficient effort indicators
            "not sure", "uncertain", "don't know", "can't tell",
            "hard to say", "difficult to determine"
        ]
    
    def _load_compliance_indicators(self) -> List[str]:
        """Load semantic indicators of compliance/success."""
        return [
            # Action completion
            "found", "discovered", "located", "identified", "retrieved",
            "obtained", "extracted", "collected",
            
            # Data presentation
            "here is", "here are", "the results", "the data shows",
            "according to", "based on", "from the",
            
            # Quantity indicators
            "total", "count", "number of", "records", "entries",
            "items", "results show",
            
            # Confidence indicators
            "successfully", "confirmed", "verified", "validated"
        ]
    
    def analyze(
        self,
        agent_response: str,
        user_prompt: str,
        tool_telemetry: Optional[List] = None
    ) -> SemanticAnalysis:
        """
        Perform semantic analysis on agent response.
        
        Args:
            agent_response: The agent's response to analyze
            user_prompt: The original user prompt for context
            tool_telemetry: Optional tool execution telemetry
            
        Returns:
            SemanticAnalysis with classification and confidence
        """
        response_lower = agent_response.lower()
        prompt_lower = user_prompt.lower()
        
        # Calculate refusal and compliance scores
        refusal_score = self._calculate_refusal_score(response_lower)
        compliance_score = self._calculate_compliance_score(response_lower)
        
        # Check for tool execution context
        tool_context_score = self._analyze_tool_context(tool_telemetry)
        
        # Determine if this is a refusal
        is_refusal = self._determine_refusal(
            refusal_score,
            compliance_score,
            tool_context_score,
            response_lower
        )
        
        # Calculate confidence based on multiple signals
        confidence = self._calculate_confidence(
            refusal_score,
            compliance_score,
            tool_context_score,
            response_lower
        )
        
        # Determine semantic category
        category = self._determine_category(
            is_refusal,
            refusal_score,
            compliance_score
        )
        
        # Generate reasoning explanation
        reasoning = self._generate_reasoning(
            is_refusal,
            refusal_score,
            compliance_score,
            tool_context_score,
            response_lower
        )
        
        return SemanticAnalysis(
            is_refusal=is_refusal,
            refusal_confidence=confidence,
            semantic_category=category,
            reasoning=reasoning
        )
    
    def _calculate_refusal_score(self, response: str) -> float:
        """Calculate refusal score based on indicators present."""
        matches = sum(1 for indicator in self.refusal_indicators if indicator in response)
        # Normalize to 0-1 range
        return min(matches / 3.0, 1.0)  # 3+ matches = 1.0
    
    def _calculate_compliance_score(self, response: str) -> float:
        """Calculate compliance score based on indicators present."""
        matches = sum(1 for indicator in self.compliance_indicators if indicator in response)
        # Normalize to 0-1 range
        return min(matches / 3.0, 1.0)  # 3+ matches = 1.0
    
    def _analyze_tool_context(self, tool_telemetry: Optional[List]) -> float:
        """
        Analyze tool execution context.
        
        Returns a score indicating likelihood of laziness:
        - 0.0: Tools called and returned data (not lazy)
        - 0.5: Tools called but empty results (might be lazy)
        - 1.0: Tools not called (likely lazy)
        """
        if not tool_telemetry:
            return 0.7  # No telemetry suggests possible laziness
        
        from .models import ToolExecutionStatus
        
        # Check if any tools were called
        called_tools = [t for t in tool_telemetry if t.tool_status != ToolExecutionStatus.NOT_CALLED]
        
        if not called_tools:
            return 1.0  # No tools called - clear laziness
        
        # Check if tools returned empty results
        empty_results = [t for t in called_tools if t.tool_status == ToolExecutionStatus.EMPTY_RESULT]
        
        if len(empty_results) == len(called_tools):
            return 0.3  # All tools returned empty - likely legitimate
        
        # Mix of results
        return 0.5
    
    def _determine_refusal(
        self,
        refusal_score: float,
        compliance_score: float,
        tool_context_score: float,
        response: str
    ) -> bool:
        """
        Determine if response indicates refusal.
        
        Uses multiple signals to make decision:
        - Refusal language
        - Lack of compliance language
        - Tool execution context
        - Response length
        """
        # Short responses with refusal language
        if len(response) < 50 and refusal_score > 0.3:
            return True
        
        # High refusal score and low compliance
        if refusal_score > 0.5 and compliance_score < 0.2:
            return True
        
        # High tool laziness (not called) + some refusal language
        if tool_context_score > 0.7 and refusal_score > 0.2:
            return True
        
        # Moderate refusal with no compliance
        if refusal_score > 0.3 and compliance_score == 0.0:
            return True
        
        return False
    
    def _calculate_confidence(
        self,
        refusal_score: float,
        compliance_score: float,
        tool_context_score: float,
        response: str
    ) -> float:
        """
        Calculate confidence in the refusal detection.
        
        Higher confidence when:
        - Clear refusal indicators
        - Clear tool context (called or not)
        - Low ambiguity
        """
        # Base confidence from score differences
        score_diff = abs(refusal_score - compliance_score)
        base_confidence = min(score_diff + 0.5, 1.0)
        
        # Boost confidence if tool context is clear
        if tool_context_score < 0.3 or tool_context_score > 0.7:
            base_confidence = min(base_confidence + 0.1, 1.0)
        
        # Reduce confidence for very short responses (ambiguous)
        if len(response) < 20:
            base_confidence *= 0.8
        
        # Boost confidence for very clear patterns
        if refusal_score > 0.7 or compliance_score > 0.7:
            base_confidence = min(base_confidence + 0.15, 1.0)
        
        return round(base_confidence, 2)
    
    def _determine_category(
        self,
        is_refusal: bool,
        refusal_score: float,
        compliance_score: float
    ) -> str:
        """Determine semantic category of response."""
        if is_refusal:
            return "refusal"
        
        if compliance_score > 0.5:
            return "compliance"
        
        if refusal_score > 0.2 and compliance_score > 0.2:
            return "unclear"
        
        return "error"
    
    def _generate_reasoning(
        self,
        is_refusal: bool,
        refusal_score: float,
        compliance_score: float,
        tool_context_score: float,
        response: str
    ) -> str:
        """Generate human-readable reasoning for the classification."""
        if is_refusal:
            reasons = []
            
            if refusal_score > 0.5:
                reasons.append(f"Strong refusal language detected (score: {refusal_score:.2f})")
            elif refusal_score > 0.3:
                reasons.append(f"Moderate refusal indicators present (score: {refusal_score:.2f})")
            
            if compliance_score < 0.2:
                reasons.append(f"Low compliance indicators (score: {compliance_score:.2f})")
            
            if tool_context_score > 0.7:
                reasons.append("Tools not called or minimal usage")
            elif tool_context_score > 0.4:
                reasons.append("Tools returned empty results")
            
            if len(response) < 50:
                reasons.append("Response is brief, suggesting minimal effort")
            
            return "Response indicates refusal/give-up: " + "; ".join(reasons)
        else:
            reasons = []
            
            if compliance_score > 0.5:
                reasons.append(f"Strong compliance indicators (score: {compliance_score:.2f})")
            elif compliance_score > 0.2:
                reasons.append(f"Some compliance indicators present (score: {compliance_score:.2f})")
            
            if tool_context_score < 0.3:
                reasons.append("Tools executed and returned data")
            
            if refusal_score < 0.2:
                reasons.append("Minimal refusal language")
            
            return "Response indicates compliance/success: " + "; ".join(reasons)
