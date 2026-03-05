# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Failure models for Agent OS.

These are the foundational failure tracking primitives used across the stack.
Extracted to Layer 1 to allow proper dependency layering.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict


class FailureType(str, Enum):
    """Types of agent failures."""
    BLOCKED_BY_CONTROL_PLANE = "blocked_by_control_plane"
    TIMEOUT = "timeout"
    INVALID_ACTION = "invalid_action"
    RESOURCE_EXHAUSTED = "resource_exhausted"
    LOGIC_ERROR = "logic_error"
    UNKNOWN = "unknown"


class FailureSeverity(str, Enum):
    """Severity levels for failures."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FailureTrace(BaseModel):
    """Full trace of an agent failure including reasoning chain."""
    
    user_prompt: str = Field(..., description="Original user prompt that led to failure")
    chain_of_thought: List[str] = Field(default_factory=list, description="Agent's reasoning steps")
    failed_action: Dict[str, Any] = Field(..., description="The action that failed")
    error_details: str = Field(..., description="Detailed error information")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "user_prompt": "Delete the recent user records",
                "chain_of_thought": [
                    "User wants to delete records",
                    "I need to identify which records are 'recent'",
                    "I'll delete from users table"
                ],
                "failed_action": {
                    "action": "execute_sql",
                    "query": "DELETE FROM users WHERE created_at > '2024-01-01'"
                },
                "error_details": "Action blocked by control plane: Dangerous SQL query"
            }
        }
    )


class AgentFailure(BaseModel):
    """Represents a failure detected in an agent."""
    
    agent_id: str = Field(..., description="Unique identifier for the agent")
    failure_type: FailureType = Field(..., description="Type of failure")
    severity: FailureSeverity = Field(default=FailureSeverity.MEDIUM)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    error_message: str = Field(..., description="Error message from the failure")
    context: Dict[str, Any] = Field(default_factory=dict, description="Additional context")
    stack_trace: Optional[str] = Field(None, description="Stack trace if available")
    failure_trace: Optional[FailureTrace] = Field(None, description="Full failure trace if available")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "agent_id": "agent-123",
                "failure_type": "blocked_by_control_plane",
                "severity": "high",
                "error_message": "Agent action blocked by control plane policy",
                "context": {"action": "delete_file", "resource": "/etc/passwd"}
            }
        }
    )
