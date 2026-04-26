# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
InteractiveAgent - The "Steel Man" / SOTA Baseline

This represents the State-of-the-Art (SOTA) approach to building agents,
based on modern frameworks like LangGraph and AutoGen.

Key Capabilities (The "Steel Man" Features):
1. Reflection: If a tool fails, reads the error and retries (Max 3 attempts)
2. Human-in-the-Loop: Can pause and ask user for clarification
3. System State Access: Can query infrastructure state
4. Context Reasoning: Uses available information to infer intent

This is implemented as an alias/wrapper for BaselineAgent to clearly
document what we're comparing against in the benchmarks.

Why this matters:
We admit that this baseline CAN solve problems, but we argue it solves
them INEFFICIENTLY due to:
- High token costs from reflection loops
- Latency from clarification requests
- User interruption from Human-in-the-Loop

The Mute Agent wins on EFFICIENCY, not just correctness.
"""

from typing import Dict, Any, List, Optional
from dataclasses import dataclass
import sys
import os

# Import the BaselineAgent implementation
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))
from src.agents.baseline_agent import (
    BaselineAgent,
    BaselineAgentResult,
    ReflectionStep,
)
from src.core.tools import MockInfrastructureAPI, SessionContext


class InteractiveAgent(BaselineAgent):
    """
    InteractiveAgent - The "Steel Man" SOTA Baseline
    
    This is essentially the BaselineAgent with explicit documentation
    that it represents the State-of-the-Art approach (LangGraph, AutoGen style).
    
    Architecture:
    - Maintains context by querying system state
    - Uses reasoning to infer missing parameters
    - Reflects on failures and retries (up to 3 turns)
    - Can ask user for clarification (Human-in-the-Loop)
    
    This is the "fair fight" baseline - not a strawman, but a competent agent
    that represents current industry best practices.
    
    The Thesis:
    "Clarification is a bug, not a feature, in autonomous systems."
    
    In high-throughput production systems:
    - Clarification kills latency (waiting for human response)
    - Reflection kills efficiency (multiple LLM calls)
    - State queries kill simplicity (complex context management)
    
    The Mute Agent proves that graph constraints provide:
    - Zero clarification needed (deterministic from graph)
    - Zero reflection needed (fail fast on constraints)
    - Zero state queries needed (context encoded in graph)
    """
    
    def __init__(self, api: MockInfrastructureAPI):
        """
        Initialize the Interactive Agent.
        
        Args:
            api: MockInfrastructureAPI for infrastructure operations
        """
        super().__init__(api)
        # Inherit all functionality from BaselineAgent
        # This class exists primarily for documentation and clarity
    
    def execute_request(
        self, 
        user_command: str, 
        context: SessionContext,
        allow_clarification: bool = True
    ) -> BaselineAgentResult:
        """
        Execute a user request using reflection and interactive clarification.
        
        This is the "SOTA" approach that:
        1. Attempts execution with available context
        2. Reflects on failures (up to 3 turns)
        3. May ask user for clarification (Human-in-the-Loop)
        
        The cost of this approach:
        - Multiple LLM calls for reflection
        - Waiting for user response (latency)
        - High token usage from tool definitions
        
        Args:
            user_command: Natural language command from user
            context: Session context with user info and history
            allow_clarification: Whether to ask user for clarification (default: True)
        
        Returns:
            BaselineAgentResult with execution details
        """
        return super().execute_request(user_command, context, allow_clarification)


# Export the same result types for convenience
__all__ = ['InteractiveAgent', 'BaselineAgentResult', 'ReflectionStep']
