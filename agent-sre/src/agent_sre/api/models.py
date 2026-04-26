# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Pydantic request/response models for the Agent-SRE REST API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# SLO models
# ---------------------------------------------------------------------------


class SLOIndicatorRequest(BaseModel):
    """An SLI definition within an SLO registration request."""

    name: str
    target: float = Field(..., ge=0.0, le=1.0, description="Target value (0-1)")
    window: str = "30d"


class SLOCreateRequest(BaseModel):
    """Register a new SLO."""

    name: str
    description: str = ""
    agent_id: str = ""
    indicators: list[SLOIndicatorRequest] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)
    error_budget_total: float | None = None


class SLOEventRequest(BaseModel):
    """Record a good/bad event against an SLO."""

    good: bool
    metadata: dict[str, Any] = Field(default_factory=dict)


class SLOResponse(BaseModel):
    """Serialised SLO details."""

    name: str
    description: str = ""
    status: str
    labels: dict[str, str] = Field(default_factory=dict)
    error_budget: dict[str, Any] = Field(default_factory=dict)
    indicators: list[dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Cost models
# ---------------------------------------------------------------------------


class CostRecordRequest(BaseModel):
    """Record a cost event."""

    agent_id: str
    task_id: str
    cost_usd: float = Field(..., ge=0.0)
    breakdown: dict[str, float] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Chaos models
# ---------------------------------------------------------------------------


class FaultRequest(BaseModel):
    """A single fault definition."""

    fault_type: str
    target: str
    rate: float = Field(1.0, ge=0.0, le=1.0)
    params: dict[str, Any] = Field(default_factory=dict)


class AbortConditionRequest(BaseModel):
    """Abort condition for a chaos experiment."""

    metric: str
    threshold: float
    comparator: str = "lte"


class ChaosCreateRequest(BaseModel):
    """Create a chaos experiment."""

    name: str
    target_agent: str
    faults: list[FaultRequest]
    duration_seconds: int = 1800
    abort_conditions: list[AbortConditionRequest] = Field(default_factory=list)
    blast_radius: float = Field(1.0, ge=0.0, le=1.0)
    description: str = ""


class FaultInjectRequest(BaseModel):
    """Inject a fault into a running experiment."""

    fault_type: str
    target: str
    rate: float = 1.0
    params: dict[str, Any] = Field(default_factory=dict)
    applied: bool = True
    details: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Incident / Signal models
# ---------------------------------------------------------------------------


class SignalIngestRequest(BaseModel):
    """Ingest a reliability signal."""

    signal_type: str
    source: str
    value: float = 0.0
    threshold: float = 0.0
    message: str = ""
    metadata: dict[str, Any] = Field(default_factory=dict)


class IncidentResolveRequest(BaseModel):
    """Resolve an incident."""

    note: str = ""


# ---------------------------------------------------------------------------
# Delivery models
# ---------------------------------------------------------------------------


class RolloutStepRequest(BaseModel):
    """A step in a staged rollout."""

    name: str = ""
    weight: float = Field(..., ge=0.0, le=1.0)
    duration_seconds: int = 3600
    manual_gate: bool = False


class RollbackConditionRequest(BaseModel):
    """Rollback condition for a rollout."""

    metric: str
    threshold: float
    comparator: str = "gte"


class RolloutCreateRequest(BaseModel):
    """Create a staged rollout."""

    name: str
    steps: list[RolloutStepRequest] = Field(default_factory=list)
    rollback_conditions: list[RollbackConditionRequest] = Field(default_factory=list)
