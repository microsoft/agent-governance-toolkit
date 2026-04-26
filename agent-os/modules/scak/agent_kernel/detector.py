# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Failure detection and monitoring system.
"""

import logging
from typing import Optional, Callable, Dict, Any, List
from datetime import datetime
from collections import deque

from .models import AgentFailure, FailureType, FailureSeverity, FailureTrace

logger = logging.getLogger(__name__)


class FailureQueue:
    """Queue for storing full failure traces with reasoning chains."""
    
    def __init__(self, max_size: int = 1000):
        """
        Initialize failure queue.
        
        Args:
            max_size: Maximum number of failures to store in queue
        """
        self.queue: deque = deque(maxlen=max_size)
        self.max_size = max_size
    
    def enqueue(self, failure: AgentFailure):
        """
        Add a failure with full trace to the queue.
        
        Args:
            failure: AgentFailure object with trace information
        """
        self.queue.append(failure)
        logger.info(f"Enqueued failure for agent {failure.agent_id}. Queue size: {len(self.queue)}")
    
    def dequeue(self) -> Optional[AgentFailure]:
        """Remove and return the oldest failure from queue."""
        if self.queue:
            return self.queue.popleft()
        return None
    
    def peek(self) -> Optional[AgentFailure]:
        """View the oldest failure without removing it."""
        if self.queue:
            return self.queue[0]
        return None
    
    def get_all(self) -> List[AgentFailure]:
        """Get all failures in the queue."""
        return list(self.queue)
    
    def size(self) -> int:
        """Get current queue size."""
        return len(self.queue)
    
    def clear(self):
        """Clear all failures from queue."""
        self.queue.clear()


class FailureDetector:
    """Detects and classifies agent failures."""
    
    def __init__(self):
        self.failure_handlers: Dict[str, Callable] = {}
        self.failure_history: List[AgentFailure] = []
        self.failure_queue = FailureQueue()
        
    def register_handler(self, failure_type: str, handler: Callable):
        """Register a custom handler for a specific failure type."""
        self.failure_handlers[failure_type] = handler
        logger.info(f"Registered handler for failure type: {failure_type}")
    
    def detect_failure(
        self,
        agent_id: str,
        error_message: str,
        context: Optional[Dict[str, Any]] = None,
        stack_trace: Optional[str] = None,
        user_prompt: Optional[str] = None,
        chain_of_thought: Optional[List[str]] = None,
        failed_action: Optional[Dict[str, Any]] = None
    ) -> AgentFailure:
        """
        Detect and classify a failure with full trace capture.
        
        Args:
            agent_id: Identifier of the agent that failed
            error_message: Error message from the failure
            context: Additional context about the failure
            stack_trace: Stack trace if available
            user_prompt: Original user prompt that led to failure
            chain_of_thought: Agent's reasoning steps
            failed_action: The specific action that failed
            
        Returns:
            AgentFailure object with classified failure and full trace
        """
        failure_type = self._classify_failure(error_message, context)
        severity = self._assess_severity(failure_type, context)
        
        # Create failure trace if information is available
        failure_trace = None
        if user_prompt and failed_action:
            failure_trace = FailureTrace(
                user_prompt=user_prompt,
                chain_of_thought=chain_of_thought or [],
                failed_action=failed_action,
                error_details=error_message
            )
        
        failure = AgentFailure(
            agent_id=agent_id,
            failure_type=failure_type,
            severity=severity,
            error_message=error_message,
            context=context or {},
            stack_trace=stack_trace,
            failure_trace=failure_trace,
            timestamp=datetime.utcnow()
        )
        
        self.failure_history.append(failure)
        
        # Enqueue failure with full trace for processing
        if failure_trace:
            self.failure_queue.enqueue(failure)
            logger.info(f"Failure with full trace enqueued for agent {agent_id}")
        
        logger.warning(f"Detected {failure_type} failure for agent {agent_id}: {error_message}")
        
        return failure
    
    def _classify_failure(self, error_message: str, context: Optional[Dict[str, Any]]) -> FailureType:
        """Classify the type of failure based on error message and context."""
        error_lower = error_message.lower()
        
        # Check for control plane blocking (including policy violations)
        if any(keyword in error_lower for keyword in [
            "blocked", "control plane", "policy", "unauthorized", "forbidden",
            "cannot advise", "cannot provide", "not allowed to"
        ]):
            return FailureType.BLOCKED_BY_CONTROL_PLANE
        
        # Check for timeout
        if any(keyword in error_lower for keyword in ["timeout", "timed out", "deadline"]):
            return FailureType.TIMEOUT
        
        # Check for invalid action (including UUID/parameter type errors)
        if any(keyword in error_lower for keyword in [
            "invalid", "unsupported", "expected", "uuid", 
            "does not exist", "not found", "format", "parameter"
        ]):
            return FailureType.INVALID_ACTION
        
        # Check for resource exhaustion
        if any(keyword in error_lower for keyword in [
            "resource", "memory", "disk", "quota", "limit exceeded"
        ]):
            return FailureType.RESOURCE_EXHAUSTED
        
        # Check for logic errors
        if any(keyword in error_lower for keyword in [
            "assertion", "null pointer", "index out", "key error", "type error"
        ]):
            return FailureType.LOGIC_ERROR
        
        return FailureType.UNKNOWN
    
    def _assess_severity(self, failure_type: FailureType, context: Optional[Dict[str, Any]]) -> FailureSeverity:
        """Assess the severity of a failure."""
        # Control plane blocks are typically high severity
        if failure_type == FailureType.BLOCKED_BY_CONTROL_PLANE:
            return FailureSeverity.HIGH
        
        # Resource exhaustion can be critical
        if failure_type == FailureType.RESOURCE_EXHAUSTED:
            return FailureSeverity.HIGH
        
        # Timeouts are usually medium severity
        if failure_type == FailureType.TIMEOUT:
            return FailureSeverity.MEDIUM
        
        # Logic errors can vary
        if failure_type == FailureType.LOGIC_ERROR:
            return FailureSeverity.MEDIUM
        
        # Default to medium for unknown
        return FailureSeverity.MEDIUM
    
    def get_failure_history(self, agent_id: Optional[str] = None, limit: int = 100) -> List[AgentFailure]:
        """Get failure history, optionally filtered by agent_id."""
        history = self.failure_history
        
        if agent_id:
            history = [f for f in history if f.agent_id == agent_id]
        
        return history[-limit:]
