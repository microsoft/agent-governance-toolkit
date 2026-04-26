# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Pydantic request/response models for the Hypervisor REST API."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from hypervisor.models import ConsistencyMode

# ── Session models ──────────────────────────────────────────────────────────

class CreateSessionRequest(BaseModel):
    """Request body for creating a new session."""

    creator_did: str = Field(..., description="DID of the session creator")
    consistency_mode: ConsistencyMode = ConsistencyMode.EVENTUAL
    max_participants: int = 10
    max_duration_seconds: int = 3600
    min_eff_score: float = 0.60
    enable_audit: bool = True
    enable_blockchain_commitment: bool = False


class ParticipantInfo(BaseModel):
    """Serialized session participant."""

    agent_did: str
    ring: int
    sigma_raw: float
    eff_score: float
    joined_at: str
    is_active: bool


class CreateSessionResponse(BaseModel):
    """Response after creating a session."""

    session_id: str
    state: str
    consistency_mode: str
    created_at: str


class SessionDetailResponse(BaseModel):
    """Detailed session information."""

    session_id: str
    state: str
    consistency_mode: str
    creator_did: str
    participant_count: int
    participants: list[ParticipantInfo]
    created_at: str
    terminated_at: str | None = None
    sagas: list[dict[str, Any]] = []


class SessionListItem(BaseModel):
    """Summary item for session listing."""

    session_id: str
    state: str
    consistency_mode: str
    participant_count: int
    created_at: str


class JoinSessionRequest(BaseModel):
    """Request body for joining a session."""

    agent_did: str = Field(..., description="DID of the joining agent")
    actions: list[dict[str, Any]] | None = None
    sigma_raw: float = 0.0


class JoinSessionResponse(BaseModel):
    """Response after joining a session."""

    agent_did: str
    session_id: str
    assigned_ring: int
    ring_name: str


# ── Ring models ─────────────────────────────────────────────────────────────

class RingDistributionResponse(BaseModel):
    """Ring distribution across session participants."""

    session_id: str
    distribution: dict[str, list[str]]


class AgentRingResponse(BaseModel):
    """Agent's current ring assignment."""

    agent_did: str
    ring: int
    ring_name: str
    session_id: str


class RingCheckRequest(BaseModel):
    """Request body for checking ring-based access."""

    agent_ring: int = Field(..., description="Agent's current ring level (0-3)")
    action: dict[str, Any] = Field(..., description="ActionDescriptor fields")
    eff_score: float = Field(..., description="Agent's effective reputation score")
    has_consensus: bool = False
    has_sre_witness: bool = False


class RingCheckResponse(BaseModel):
    """Response from ring access check."""

    allowed: bool
    required_ring: int
    agent_ring: int
    eff_score: float
    reason: str
    requires_consensus: bool = False
    requires_sre_witness: bool = False


# ── Saga models ─────────────────────────────────────────────────────────────

class CreateSagaResponse(BaseModel):
    """Response after creating a saga."""

    saga_id: str
    session_id: str
    state: str
    created_at: str


class SagaDetailResponse(BaseModel):
    """Detailed saga information."""

    saga_id: str
    session_id: str
    state: str
    created_at: str
    completed_at: str | None = None
    error: str | None = None
    steps: list[dict[str, Any]]


class AddStepRequest(BaseModel):
    """Request body for adding a step to a saga."""

    action_id: str
    agent_did: str
    execute_api: str
    undo_api: str | None = None
    timeout_seconds: int = 300
    max_retries: int = 0


class AddStepResponse(BaseModel):
    """Response after adding a step."""

    step_id: str
    saga_id: str
    action_id: str
    state: str


class ExecuteStepResponse(BaseModel):
    """Response after executing a step."""

    step_id: str
    saga_id: str
    state: str
    error: str | None = None


# ── Liability models ────────────────────────────────────────────────────────

class CreateVouchRequest(BaseModel):
    """Request body for creating a sponsor."""

    voucher_did: str = Field(..., description="DID of the sponsorship agent")
    vouchee_did: str = Field(..., description="DID of the agent being vouched for")
    voucher_sigma: float = Field(..., description="Sponsor's raw reputation score")
    bond_pct: float | None = None
    expiry: str | None = None


class VouchResponse(BaseModel):
    """Response after creating a sponsor."""

    vouch_id: str
    voucher_did: str
    vouchee_did: str
    session_id: str
    bonded_amount: float
    bonded_sigma_pct: float
    is_active: bool


class LiabilityExposureResponse(BaseModel):
    """Agent's liability exposure across sessions."""

    agent_did: str
    vouches_given: list[VouchResponse]
    vouches_received: list[VouchResponse]
    total_exposure: float


# ── Event models ────────────────────────────────────────────────────────────

class EventResponse(BaseModel):
    """Serialized hypervisor event."""

    event_id: str
    event_type: str
    timestamp: str
    session_id: str | None = None
    agent_did: str | None = None
    causal_trace_id: str | None = None
    payload: dict[str, Any] = {}


class EventStatsResponse(BaseModel):
    """Event type counts."""

    total_events: int
    by_type: dict[str, int]


# ── Stats models ────────────────────────────────────────────────────────────

class StatsResponse(BaseModel):
    """Overall hypervisor statistics."""

    version: str
    total_sessions: int
    active_sessions: int
    total_participants: int
    active_sagas: int
    total_vouches: int
    event_count: int


# ── Audit models ────────────────────────────────────────────────────────────

class CommitmentResponse(BaseModel):
    session_id: str
    hash_chain_root: str
    participant_dids: list[str]
    delta_count: int
    committed_at: str
    committed_to: str = "local"
    blockchain_tx_id: str | None = None

class VerifyCommitmentResponse(BaseModel):
    session_id: str
    valid: bool
    committed_root: str
    expected_root: str

# ── Verification models ─────────────────────────────────────────────────────

class TransactionInput(BaseModel):
    session_id: str
    summary_hash: str
    timestamp: datetime
    participant_count: int = 0

class VerifyHistoryRequest(BaseModel):
    agent_did: str
    transactions: list[TransactionInput]

class VerifyHistoryResponse(BaseModel):
    agent_did: str
    status: str
    transactions_checked: int
    transactions_found: int
    inconsistencies: list[str]
    is_trustworthy: bool
    cached: bool = False
