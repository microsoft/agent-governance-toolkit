# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Pydantic v2 request/response models for Agent OS Governance API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class ExecuteRequest(BaseModel):
    """Request to execute an action through the stateless kernel."""

    action: str = Field(..., description="Action to execute")
    params: dict = Field(default_factory=dict, description="Action parameters")
    agent_id: str = Field(..., description="Unique agent identifier")
    policies: list[str] = Field(default_factory=list, description="Policy names to enforce")


class DetectInjectionRequest(BaseModel):
    """Request to scan a single text for prompt injection."""

    text: str = Field(..., description="Input text to screen")
    source: str = Field(default="api", description="Source identifier")
    canary_tokens: list[str] | None = Field(default=None, description="Canary tokens to check")
    sensitivity: str = Field(default="balanced", description="Detection sensitivity")


class DetectBatchRequest(BaseModel):
    """Request to scan multiple texts for prompt injection."""

    inputs: list[dict] = Field(
        ..., description="List of dicts with 'text' and optional 'source' keys"
    )
    canary_tokens: list[str] | None = Field(default=None, description="Canary tokens to check")
    sensitivity: str = Field(default="balanced", description="Detection sensitivity")


class PolicyEvalRequest(BaseModel):
    """Request to evaluate policies against a context."""

    context: dict = Field(..., description="Execution context for policy evaluation")
    policy_name: str | None = Field(default=None, description="Specific policy to evaluate")


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------

class ExecuteResponse(BaseModel):
    """Response from stateless kernel execution."""

    success: bool
    data: Any = None
    error: str | None = None
    signal: str | None = None


class DetectionResponse(BaseModel):
    """Response from prompt injection detection."""

    is_injection: bool
    threat_level: str
    injection_type: str | None = None
    confidence: float
    matched_patterns: list[str] = Field(default_factory=list)
    explanation: str = ""


class DetectionBatchResponse(BaseModel):
    """Response from batch prompt injection detection."""

    results: list[DetectionResponse]
    total: int
    injections_found: int


class HealthResponse(BaseModel):
    """Health check response."""

    status: str
    components: dict = Field(default_factory=dict)
    timestamp: str = ""


class MetricsResponse(BaseModel):
    """Governance metrics snapshot."""

    total_checks: int = 0
    violations: int = 0
    approvals: int = 0
    blocked: int = 0
    avg_latency_ms: float = 0.0


class ErrorResponse(BaseModel):
    """Error response for failed requests."""

    detail: str
    error_code: str = "INTERNAL_ERROR"
