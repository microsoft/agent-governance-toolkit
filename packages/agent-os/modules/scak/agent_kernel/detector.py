# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Community Edition — basic self-correction with retry
"""
Failure detection — simple list-based queue and basic classifier.
"""

import logging
from typing import Optional, Callable, Dict, Any, List
from datetime import datetime, timezone

from .models import AgentFailure, FailureType, FailureSeverity, FailureTrace

logger = logging.getLogger(__name__)


class FailureQueue:
    """Simple list-based failure queue."""

    def __init__(self, max_size: int = 1000):
        self._items: List[AgentFailure] = []
        self.max_size = max_size

    def enqueue(self, failure: AgentFailure):
        """Add a failure to the queue, dropping oldest if full."""
        if len(self._items) >= self.max_size:
            self._items.pop(0)
        self._items.append(failure)

    def dequeue(self) -> Optional[AgentFailure]:
        """Remove and return the oldest failure."""
        if self._items:
            return self._items.pop(0)
        return None

    def peek(self) -> Optional[AgentFailure]:
        """View the oldest failure without removing it."""
        return self._items[0] if self._items else None

    def get_all(self) -> List[AgentFailure]:
        return list(self._items)

    def size(self) -> int:
        return len(self._items)

    def clear(self):
        self._items.clear()


class FailureDetector:
    """Detects and classifies agent failures."""

    def __init__(self):
        self.failure_handlers: Dict[str, Callable] = {}
        self.failure_history: List[AgentFailure] = []
        self.failure_queue = FailureQueue()

    def register_handler(self, failure_type: str, handler: Callable):
        self.failure_handlers[failure_type] = handler

    def detect_failure(
        self,
        agent_id: str,
        error_message: str,
        context: Optional[Dict[str, Any]] = None,
        stack_trace: Optional[str] = None,
        user_prompt: Optional[str] = None,
        chain_of_thought: Optional[List[str]] = None,
        failed_action: Optional[Dict[str, Any]] = None,
    ) -> AgentFailure:
        """Detect and classify a failure."""
        failure_type = self._classify_failure(error_message)
        severity = self._assess_severity(failure_type)

        failure_trace = None
        if user_prompt and failed_action:
            failure_trace = FailureTrace(
                user_prompt=user_prompt,
                chain_of_thought=chain_of_thought or [],
                failed_action=failed_action,
                error_details=error_message,
            )

        failure = AgentFailure(
            agent_id=agent_id,
            failure_type=failure_type,
            severity=severity,
            error_message=error_message,
            context=context or {},
            stack_trace=stack_trace,
            failure_trace=failure_trace,
            timestamp=datetime.now(timezone.utc),
        )

        self.failure_history.append(failure)
        if failure_trace:
            self.failure_queue.enqueue(failure)

        logger.warning(f"Detected {failure_type} failure for agent {agent_id}: {error_message}")
        return failure

    def _classify_failure(self, error_message: str) -> FailureType:
        error_lower = error_message.lower()
        if any(k in error_lower for k in ["blocked", "policy", "unauthorized", "forbidden"]):
            return FailureType.BLOCKED_BY_CONTROL_PLANE
        if any(k in error_lower for k in ["timeout", "timed out", "deadline"]):
            return FailureType.TIMEOUT
        if any(k in error_lower for k in ["invalid", "not found", "does not exist"]):
            return FailureType.INVALID_ACTION
        if any(k in error_lower for k in ["resource", "memory", "quota"]):
            return FailureType.RESOURCE_EXHAUSTED
        if any(k in error_lower for k in ["assertion", "type error", "key error"]):
            return FailureType.LOGIC_ERROR
        return FailureType.UNKNOWN

    def _assess_severity(self, failure_type: FailureType) -> FailureSeverity:
        if failure_type in (FailureType.BLOCKED_BY_CONTROL_PLANE, FailureType.RESOURCE_EXHAUSTED):
            return FailureSeverity.HIGH
        return FailureSeverity.MEDIUM

    def get_failure_history(self, agent_id: Optional[str] = None, limit: int = 100) -> List[AgentFailure]:
        history = self.failure_history
        if agent_id:
            history = [f for f in history if f.agent_id == agent_id]
        return history[-limit:]
