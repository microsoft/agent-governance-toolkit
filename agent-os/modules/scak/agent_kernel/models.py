# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Data models for the self-correcting agent kernel.

Note: Core failure primitives (FailureType, FailureSeverity, AgentFailure, FailureTrace)
are imported from agent-primitives (Layer 1) and re-exported here for backward compatibility.
"""

from typing import Dict, List, Optional, Any
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field, ConfigDict

# Import from agent-primitives (Layer 1) and re-export for backward compatibility
from agent_primitives import (
    FailureType,
    FailureSeverity,
    FailureTrace,
    AgentFailure,
)


class CognitiveGlitch(str, Enum):
    """Types of cognitive glitches that can occur in agent reasoning."""
    HALLUCINATION = "hallucination"  # Agent invents facts not in context
    LOGIC_ERROR = "logic_error"  # Agent misunderstands instructions or makes faulty inferences
    CONTEXT_GAP = "context_gap"  # Agent lacks necessary information in prompt/schema
    PERMISSION_ERROR = "permission_error"  # Agent attempts unauthorized actions
    SCHEMA_MISMATCH = "schema_mismatch"  # Agent references non-existent tables/fields
    TOOL_MISUSE = "tool_misuse"  # Agent uses tool with wrong parameter types or values
    POLICY_VIOLATION = "policy_violation"  # Agent violates policy boundaries (e.g., medical advice)
    NONE = "none"  # No cognitive glitch detected


# Note: FailureTrace and AgentFailure are now imported from agent-primitives above


class FailureAnalysis(BaseModel):
    """Analysis of an agent failure."""
    
    failure: AgentFailure
    root_cause: str = Field(..., description="Identified root cause")
    contributing_factors: List[str] = Field(default_factory=list)
    suggested_fixes: List[str] = Field(default_factory=list)
    confidence_score: float = Field(..., ge=0.0, le=1.0, description="Confidence in analysis")
    similar_failures: List[str] = Field(default_factory=list, description="IDs of similar past failures")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "root_cause": "Agent attempted unauthorized file access",
                "contributing_factors": ["Missing permission check", "Inadequate input validation"],
                "suggested_fixes": ["Add permission validation", "Implement safe file access patterns"],
                "confidence_score": 0.85
            }
        }
    )


class DiagnosisJSON(BaseModel):
    """Structured diagnosis identifying cognitive glitches in agent reasoning."""
    
    cognitive_glitch: CognitiveGlitch = Field(..., description="Primary cognitive glitch identified")
    deep_problem: str = Field(..., description="Deep analysis of the problem")
    evidence: List[str] = Field(default_factory=list, description="Evidence supporting diagnosis")
    hint: str = Field(..., description="Hint to inject for counterfactual simulation")
    expected_fix: str = Field(..., description="Expected outcome of applying the hint")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in diagnosis")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "cognitive_glitch": "hallucination",
                "deep_problem": "Agent invented table name 'recent_users' that doesn't exist in schema",
                "evidence": [
                    "Query references 'recent_users' table",
                    "Schema only contains 'users' table",
                    "No context provided about table names"
                ],
                "hint": "Available tables: users, orders, products. Use 'users' table with date filter.",
                "expected_fix": "Agent will query 'users' table with proper date filter",
                "confidence": 0.92
            }
        }
    )


class SimulationResult(BaseModel):
    """Result of simulating an alternative path."""
    
    simulation_id: str
    success: bool
    alternative_path: List[Dict[str, Any]] = Field(description="Steps in the alternative path")
    expected_outcome: str
    risk_score: float = Field(..., ge=0.0, le=1.0, description="Risk of the alternative")
    estimated_success_rate: float = Field(..., ge=0.0, le=1.0)
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "simulation_id": "sim-456",
                "success": True,
                "alternative_path": [
                    {"action": "validate_permissions", "params": {}},
                    {"action": "safe_file_access", "params": {"file": "/tmp/safe.txt"}}
                ],
                "expected_outcome": "Safe file operation completed",
                "risk_score": 0.15,
                "estimated_success_rate": 0.92
            }
        }
    )


class ShadowAgentResult(BaseModel):
    """Result of running a shadow agent with counterfactual simulation."""
    
    shadow_id: str
    original_prompt: str = Field(..., description="Original user prompt")
    injected_hint: str = Field(..., description="Hint injected into the prompt")
    modified_prompt: str = Field(..., description="Full prompt with hint")
    execution_success: bool = Field(..., description="Whether execution succeeded")
    output: str = Field(..., description="Output from shadow agent")
    reasoning_chain: List[str] = Field(default_factory=list, description="Shadow agent's reasoning")
    action_taken: Optional[Dict[str, Any]] = Field(None, description="Action the shadow agent took")
    verified: bool = Field(..., description="Whether the fix actually works")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "shadow_id": "shadow-789",
                "original_prompt": "Delete recent user records",
                "injected_hint": "Available tables: users. 'Recent' means created_at > 7 days ago",
                "modified_prompt": "Delete recent user records. [HINT: Available tables: users. 'Recent' means created_at > 7 days ago]",
                "execution_success": True,
                "output": "Query executed successfully",
                "reasoning_chain": ["Parse user request", "Check hint for table info", "Build safe query"],
                "action_taken": {"action": "execute_sql", "query": "DELETE FROM users WHERE created_at > NOW() - INTERVAL 7 DAY"},
                "verified": True
            }
        }
    )


class CorrectionPatch(BaseModel):
    """A patch to correct an agent's behavior."""
    
    patch_id: str
    agent_id: str
    failure_analysis: FailureAnalysis
    simulation_result: SimulationResult
    patch_type: str = Field(..., description="Type of patch (code, config, rule)")
    patch_content: Dict[str, Any] = Field(..., description="The actual patch content")
    applied: bool = Field(default=False)
    applied_at: Optional[datetime] = None
    rollback_available: bool = Field(default=True)
    diagnosis: Optional["DiagnosisJSON"] = Field(None, description="Cognitive diagnosis if available")
    shadow_result: Optional[ShadowAgentResult] = Field(None, description="Shadow agent verification result")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "patch_id": "patch-789",
                "agent_id": "agent-123",
                "patch_type": "code",
                "patch_content": {
                    "module": "file_handler",
                    "changes": [
                        {"type": "add_validation", "code": "if not has_permission(file): return"}
                    ]
                },
                "applied": True
            }
        }
    )


class PatchStrategy(str, Enum):
    """Strategy for applying patches."""
    SYSTEM_PROMPT = "system_prompt"  # Easy fix: Update system prompt
    RAG_MEMORY = "rag_memory"  # Hard fix: Inject into vector store
    CODE_CHANGE = "code_change"  # Direct code modification
    CONFIG_UPDATE = "config_update"  # Configuration change
    RULE_UPDATE = "rule_update"  # Policy/rule update


class AgentState(BaseModel):
    """Current state of an agent."""
    
    agent_id: str
    status: str = Field(..., description="Current status (running, failed, patched, etc.)")
    last_failure: Optional[AgentFailure] = None
    patches_applied: List[str] = Field(default_factory=list, description="List of patch IDs")
    success_rate: float = Field(default=1.0, ge=0.0, le=1.0)
    total_runs: int = Field(default=0)
    failed_runs: int = Field(default=0)
    model_version: str = Field(default="gpt-4o", description="Current model version")


class GiveUpSignal(str, Enum):
    """Types of give-up signals indicating agent laziness."""
    NO_DATA_FOUND = "no_data_found"
    CANNOT_ANSWER = "cannot_answer"
    NO_RESULTS = "no_results"
    NOT_AVAILABLE = "not_available"
    INSUFFICIENT_INFO = "insufficient_info"
    UNKNOWN = "unknown"


class PatchDecayType(str, Enum):
    """Classification of patch based on decay characteristics."""
    SYNTAX_CAPABILITY = "syntax_capability"  # Type A: High decay - likely model defects
    BUSINESS_CONTEXT = "business_context"  # Type B: Zero decay - world truths


class ToolExecutionStatus(str, Enum):
    """Status of tool execution."""
    SUCCESS = "success"
    ERROR = "error"
    EMPTY_RESULT = "empty_result"
    NOT_CALLED = "not_called"


class OutcomeType(str, Enum):
    """Types of agent outcomes."""
    SUCCESS = "success"
    GIVE_UP = "give_up"  # Negative result - triggers Completeness Auditor
    FAILURE = "failure"
    BLOCKED = "blocked"


class ToolExecutionTelemetry(BaseModel):
    """Telemetry data for tool executions during agent interaction."""
    
    tool_name: str = Field(..., description="Name of the tool that was called")
    tool_status: ToolExecutionStatus = Field(..., description="Execution status of the tool")
    tool_result: Any = Field(None, description="Result returned by the tool")
    execution_time_ms: Optional[float] = Field(None, description="Execution time in milliseconds")
    error_message: Optional[str] = Field(None, description="Error message if tool failed")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "tool_name": "search_logs",
                "tool_status": "empty_result",
                "tool_result": [],
                "execution_time_ms": 150.5
            }
        }
    )


class SemanticAnalysis(BaseModel):
    """Semantic analysis of agent response for refusal detection."""
    
    is_refusal: bool = Field(..., description="Whether response indicates refusal/give-up")
    refusal_confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in refusal detection")
    semantic_category: str = Field(..., description="Category: 'compliance', 'refusal', 'error', 'unclear'")
    reasoning: str = Field(..., description="Explanation of the classification")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "is_refusal": True,
                "refusal_confidence": 0.85,
                "semantic_category": "refusal",
                "reasoning": "Response indicates inability to find data without attempting comprehensive search"
            }
        }
    )


class NudgeResult(BaseModel):
    """Result of nudging agent after give-up detection."""
    
    nudge_id: str
    original_outcome: "AgentOutcome"
    nudge_prompt: str = Field(..., description="The nudge prompt that was injected")
    retry_response: str = Field(..., description="Agent's response after nudge")
    retry_successful: bool = Field(..., description="Whether nudge resolved the issue")
    improvement_detected: bool = Field(..., description="Whether response improved after nudge")
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "nudge_id": "nudge-123",
                "nudge_prompt": "You claimed no data was found. Please confirm you executed the search tool with correct parameters and checked all data sources.",
                "retry_response": "After checking all sources, found 15 log entries in archived partition.",
                "retry_successful": True,
                "improvement_detected": True
            }
        }
    )


class AgentOutcome(BaseModel):
    """Result of an agent execution."""
    
    agent_id: str
    outcome_type: OutcomeType
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    user_prompt: str
    agent_response: str
    give_up_signal: Optional[GiveUpSignal] = None
    context: Dict[str, Any] = Field(default_factory=dict)
    tool_telemetry: List[ToolExecutionTelemetry] = Field(
        default_factory=list,
        description="Telemetry data for tools called during execution"
    )
    semantic_analysis: Optional[SemanticAnalysis] = Field(
        None,
        description="Semantic analysis of the response"
    )
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "agent_id": "agent-123",
                "outcome_type": "give_up",
                "user_prompt": "Find logs for error 500",
                "agent_response": "No logs found for error 500.",
                "give_up_signal": "no_data_found"
            }
        }
    )


class CompletenessAudit(BaseModel):
    """Result of completeness auditing by teacher model."""
    
    audit_id: str
    agent_outcome: AgentOutcome
    teacher_model: str = Field(default="o1-preview", description="High-reasoning teacher model")
    teacher_response: str
    teacher_found_data: bool
    gap_analysis: str = Field(..., description="What the agent missed")
    competence_patch: str = Field(..., description="Lesson to prevent future laziness")
    confidence: float = Field(..., ge=0.0, le=1.0)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "audit_id": "audit-123",
                "teacher_model": "o1-preview",
                "teacher_response": "Found logs in archived partition",
                "teacher_found_data": True,
                "gap_analysis": "Agent didn't check archived partitions",
                "competence_patch": "When searching logs, always check archived partitions if recent logs are empty",
                "confidence": 0.92
            }
        }
    )


class ClassifiedPatch(BaseModel):
    """A patch with classification metadata for lifecycle management."""
    
    base_patch: CorrectionPatch
    decay_type: PatchDecayType
    created_at_model_version: str = Field(..., description="Model version when patch was created")
    decay_metadata: Dict[str, Any] = Field(default_factory=dict)
    should_purge_on_upgrade: bool = Field(default=False)
    
    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "decay_type": "syntax_capability",
                "created_at_model_version": "gpt-4o",
                "should_purge_on_upgrade": True
            }
        }
    )
