# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Pydantic request/response models for the Engine API reference adapter.

Field names match ``docs/studio/engine-api-contract.md`` section 7 exactly. Paginated list
endpoints use the wrapper models at the bottom of this module, which carry a top-level
``items`` array plus the section 11.2 :class:`~agentmesh.engine_api.pagination.Pagination`
object.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from agentmesh.engine_api.pagination import Pagination

# Shared enums expressed as Literal types.
PolicyFormat = Literal["yaml", "json"]
Verdict = Literal["allow", "deny", "warn", "require_approval"]
TrustLevel = Literal["untrusted", "probationary", "standard", "trusted", "verified_partner"]


# ── Health (section 7.1) ─────────────────────────────────────────────────────
class HealthResponse(BaseModel):
    status: Literal["ok", "degraded"] = Field(..., description="Engine health status")
    version: str = Field(..., description="Engine software version")
    uptime_seconds: float = Field(..., description="Seconds since engine process start")


# ── Policies (sections 7.2, 7.3) ─────────────────────────────────────────────
class PolicySummary(BaseModel):
    id: str = Field(..., description="Unique identifier derived from filename")
    name: str = Field(..., description="Human-readable policy name")
    format: PolicyFormat = Field(..., description="File format")
    source: str = Field(..., description="File path relative to policy directory")
    description: str | None = Field(None, description="Policy description if present")


class PolicyDetail(PolicySummary):
    content: str = Field(..., description="Raw policy file content")
    rules_count: int = Field(..., description="Number of rules in the policy")
    last_modified: datetime = Field(..., description="Last modification timestamp (date-time)")


# ── Policy validate (section 7.4) ────────────────────────────────────────────
class PolicyValidationError(BaseModel):
    line: int = Field(..., description="1-based line of the error (0 when unknown)")
    col: int = Field(..., description="1-based column of the error (0 when unknown)")
    message: str = Field(..., description="Parse or lint error message")


class ValidateRequest(BaseModel):
    content: str = Field(..., description="Raw policy content to validate")
    format: PolicyFormat = Field(..., description="Format of the content")


class ValidateResponse(BaseModel):
    valid: bool = Field(..., description="True if the policy parses and passes all lint rules")
    errors: list[PolicyValidationError] = Field(
        default_factory=list, description="Parse or lint errors (empty when valid)"
    )


# ── Policy test (section 7.5) ────────────────────────────────────────────────
class FixtureInput(BaseModel):
    id: str = Field(..., description="Unique fixture identifier")
    input: dict[str, Any] = Field(..., description="Evaluation context for the fixture")
    expected_verdict: Verdict = Field(..., description="Expected policy verdict")
    expected_rule: str | None = Field(None, description="Expected matching rule name")


class TestRequest(BaseModel):
    fixtures: list[FixtureInput] = Field(..., description="Inline fixtures to execute")
    policy_dir: str | None = Field(
        None, description="Policy directory override (defaults to engine policy_dir)"
    )


class FixtureResult(BaseModel):
    fixture_id: str
    passed: bool
    expected_verdict: str
    actual_verdict: str
    expected_rule: str | None = None
    actual_rule: str | None = None
    fixture_path: str | None = None
    resolution_metadata: dict[str, Any] | None = None


class TestResponse(BaseModel):
    total: int = Field(..., description="Total fixtures run")
    passed: int = Field(..., description="Fixtures that matched expected verdict")
    failed: int = Field(..., description="Fixtures that did not match")
    results: list[FixtureResult] = Field(default_factory=list, description="Per-fixture outcomes")


# ── Policy save (section 7.6) ────────────────────────────────────────────────
class SaveRequest(BaseModel):
    id: str = Field(
        ...,
        pattern=r"^[a-z0-9][a-z0-9_-]{0,63}$",
        description="Policy identifier (becomes filename)",
    )
    content: str = Field(..., description="Policy content to persist")
    format: PolicyFormat = Field(..., description="File format to write")
    commit_message: str | None = Field(
        None, max_length=512, description="Human description for the audit log"
    )


class SaveResponse(BaseModel):
    id: str = Field(..., description="Saved policy identifier")
    saved_at: datetime = Field(..., description="Timestamp of the save (date-time)")
    version: str = Field(..., description="Opaque version token for optimistic concurrency")


# ── Audit log (section 7.7) ──────────────────────────────────────────────────
class AuditLogEntry(BaseModel):
    entry_id: str
    timestamp: datetime
    agent_did: str
    action: str
    outcome: Literal["success", "failure", "denied"]
    resource: str | None = None
    target_did: str | None = None
    policy_decision: str | None = None
    entry_hash: str


# ── Trust (sections 7.8, 7.9) ────────────────────────────────────────────────
class TrustScoreItem(BaseModel):
    agent_did: str
    trust_score: int = Field(..., ge=0, le=1000)
    trust_level: TrustLevel
    last_updated: datetime | None = None


class TrustGraphNode(BaseModel):
    did: str
    trust_score: int = Field(..., ge=0, le=1000)
    name: str | None = None


class TrustGraphEdge(BaseModel):
    from_did: str
    to_did: str
    relationship: Literal["trusts", "delegates", "sponsors"]
    weight: float


class TrustGraph(BaseModel):
    nodes: list[TrustGraphNode] = Field(default_factory=list)
    edges: list[TrustGraphEdge] = Field(default_factory=list)


# ── Agents (section 7.10) ────────────────────────────────────────────────────
class AgentSummary(BaseModel):
    did: str
    name: str | None = None
    trust_score: int = Field(..., ge=0, le=1000)
    trust_level: TrustLevel
    last_active: datetime | None = None
    capabilities: list[str] = Field(default_factory=list)


# ── Decisions (section 7.11) ─────────────────────────────────────────────────
class Decision(BaseModel):
    decision_id: str
    timestamp: datetime
    agent_did: str
    action: str
    resource: str | None = None
    verdict: Verdict
    matched_rule: str | None = None
    policy_name: str | None = None
    reason: str


# ── Versions (section 7.12) ──────────────────────────────────────────────────
class VersionsResponse(BaseModel):
    engine: str = Field(..., description="Engine software version")
    api: str = Field(..., description="API contract version")
    python: str | None = Field(None, description="Python runtime version")
    capabilities: list[str] | None = Field(
        None, description="Supported capability identifiers"
    )


# ── Paginated wrappers (section 11.2) ────────────────────────────────────────
class PolicyListResponse(BaseModel):
    items: list[PolicySummary]
    pagination: Pagination


class AuditLogResponse(BaseModel):
    items: list[AuditLogEntry]
    pagination: Pagination


class TrustScoreListResponse(BaseModel):
    items: list[TrustScoreItem]
    pagination: Pagination


class AgentListResponse(BaseModel):
    items: list[AgentSummary]
    pagination: Pagination


class DecisionListResponse(BaseModel):
    items: list[Decision]
    pagination: Pagination
