# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
FastAPI REST API server for the Agent Hypervisor.

Exposes the hypervisor's core capabilities — sessions, rings, sagas,
liability, events, and health — as a RESTful API with OpenAPI docs.

Run with: uvicorn hypervisor.api.server:app
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from hypervisor import __version__
from hypervisor.api.models import (
    AddStepRequest,
    AddStepResponse,
    AgentRingResponse,
    CommitmentResponse,
    CreateSagaResponse,
    CreateSessionRequest,
    CreateSessionResponse,
    CreateVouchRequest,
    EventResponse,
    EventStatsResponse,
    ExecuteStepResponse,
    JoinSessionRequest,
    JoinSessionResponse,
    LiabilityExposureResponse,
    ParticipantInfo,
    RingCheckRequest,
    RingCheckResponse,
    RingDistributionResponse,
    SagaDetailResponse,
    SessionDetailResponse,
    SessionListItem,
    StatsResponse,
    VerifyCommitmentResponse,
    VerifyHistoryRequest,
    VerifyHistoryResponse,
    VouchResponse,
)
from hypervisor.core import Hypervisor, ManagedSession
from hypervisor.models import (
    ActionDescriptor,
    ExecutionRing,
    SessionConfig,
)
from hypervisor.observability.event_bus import EventType, HypervisorEventBus

logger = logging.getLogger(__name__)

# ── Global state ────────────────────────────────────────────────────────────

_hypervisor: Hypervisor | None = None
_event_bus: HypervisorEventBus | None = None


def _hv() -> Hypervisor:
    """Get the global Hypervisor instance."""
    if _hypervisor is None:
        raise HTTPException(status_code=503, detail="Hypervisor not initialized")
    return _hypervisor


def _bus() -> HypervisorEventBus:
    """Get the global event bus."""
    if _event_bus is None:
        raise HTTPException(status_code=503, detail="Event bus not initialized")
    return _event_bus


def _get_managed(session_id: str) -> ManagedSession:
    """Get a managed session or raise 404."""
    managed = _hv().get_session(session_id)
    if not managed:
        raise HTTPException(status_code=404, detail=f"Session {session_id} not found")
    return managed


def _participant_info(p: Any) -> ParticipantInfo:
    return ParticipantInfo(
        agent_did=p.agent_did,
        ring=p.ring.value,
        sigma_raw=p.sigma_raw,
        eff_score=p.eff_score,
        joined_at=p.joined_at.isoformat(),
        is_active=p.is_active,
    )


# ── Lifespan ────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    """Initialize hypervisor on startup, clean up on shutdown."""
    global _hypervisor, _event_bus
    _hypervisor = Hypervisor()
    _event_bus = HypervisorEventBus()
    yield
    _hypervisor = None
    _event_bus = None


# ── App factory ─────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    application = FastAPI(
        title="Agent Hypervisor API",
        description=(
            "REST API for the Agent Hypervisor — runtime supervisor for "
            "multi-agent Shared Sessions with Execution Rings, Joint Liability, "
            "Saga Orchestration, and Audit log audit trails."
        ),
        version=__version__,
        lifespan=lifespan,
    )

    application.add_middleware(
        CORSMiddleware,
        allow_origins=os.environ.get("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8080").split(","),
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    return application


app = create_app()


# ── Health ──────────────────────────────────────────────────────────────────

@app.get("/health", tags=["Health"])
async def health_check() -> dict[str, str]:
    """Health check endpoint."""
    return {"status": "ok", "version": __version__}


@app.get("/api/v1/stats", response_model=StatsResponse, tags=["Health"])
async def get_stats() -> StatsResponse:
    """Get overall hypervisor statistics."""
    hv = _hv()
    bus = _bus()
    total_participants = sum(
        m.sso.participant_count for m in hv._sessions.values()
    )
    active_sagas = sum(
        len(m.saga.active_sagas) for m in hv._sessions.values()
    )
    return StatsResponse(
        version=__version__,
        total_sessions=len(hv._sessions),
        active_sessions=len(hv.active_sessions),
        total_participants=total_participants,
        active_sagas=active_sagas,
        total_vouches=len(hv.vouching._vouches),
        event_count=bus.event_count,
    )


# ── Sessions ────────────────────────────────────────────────────────────────

@app.post(
    "/api/v1/sessions",
    response_model=CreateSessionResponse,
    status_code=201,
    tags=["Sessions"],
)
async def create_session(req: CreateSessionRequest) -> CreateSessionResponse:
    """Create a new Shared Session."""
    config = SessionConfig(
        consistency_mode=req.consistency_mode,
        max_participants=req.max_participants,
        max_duration_seconds=req.max_duration_seconds,
        min_eff_score=req.min_eff_score,
        enable_audit=req.enable_audit,
        enable_blockchain_commitment=req.enable_blockchain_commitment,
    )
    managed = await _hv().create_session(config=config, creator_did=req.creator_did)
    return CreateSessionResponse(
        session_id=managed.sso.session_id,
        state=managed.sso.state.value,
        consistency_mode=managed.sso.consistency_mode.value,
        created_at=managed.sso.created_at.isoformat(),
    )


@app.get("/api/v1/sessions", response_model=list[SessionListItem], tags=["Sessions"])
async def list_sessions(
    state: str | None = Query(None, description="Filter by session state"),
) -> list[SessionListItem]:
    """List all sessions, optionally filtered by state."""
    sessions = _hv()._sessions.values()
    if state:
        sessions = [m for m in sessions if m.sso.state.value == state]
    return [
        SessionListItem(
            session_id=m.sso.session_id,
            state=m.sso.state.value,
            consistency_mode=m.sso.consistency_mode.value,
            participant_count=m.sso.participant_count,
            created_at=m.sso.created_at.isoformat(),
        )
        for m in sessions
    ]


@app.get(
    "/api/v1/sessions/{session_id}",
    response_model=SessionDetailResponse,
    tags=["Sessions"],
)
async def get_session(session_id: str) -> SessionDetailResponse:
    """Get detailed session information including participants and sagas."""
    managed = _get_managed(session_id)
    sso = managed.sso
    sagas = [
        s.to_dict()
        for s in managed.saga._sagas.values()
    ]
    return SessionDetailResponse(
        session_id=sso.session_id,
        state=sso.state.value,
        consistency_mode=sso.consistency_mode.value,
        creator_did=sso.creator_did,
        participant_count=sso.participant_count,
        participants=[_participant_info(p) for p in sso.participants],
        created_at=sso.created_at.isoformat(),
        terminated_at=sso.terminated_at.isoformat() if sso.terminated_at else None,
        sagas=sagas,
    )


@app.post(
    "/api/v1/sessions/{session_id}/join",
    response_model=JoinSessionResponse,
    tags=["Sessions"],
)
async def join_session(session_id: str, req: JoinSessionRequest) -> JoinSessionResponse:
    """Join an agent to a session via the IATP handshake."""
    hv = _hv()
    actions = None
    if req.actions:
        actions = [ActionDescriptor(**a) for a in req.actions]
    try:
        ring = await hv.join_session(
            session_id=session_id,
            agent_did=req.agent_did,
            actions=actions,
            sigma_raw=req.sigma_raw,
        )
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.debug("join_session failed for %s: %s", session_id, e, exc_info=True)
        raise HTTPException(status_code=400, detail=str(e))
    return JoinSessionResponse(
        agent_did=req.agent_did,
        session_id=session_id,
        assigned_ring=ring.value,
        ring_name=ring.name,
    )


@app.post("/api/v1/sessions/{session_id}/activate", tags=["Sessions"])
async def activate_session(session_id: str) -> dict[str, str]:
    """Activate a session after handshaking is complete."""
    try:
        await _hv().activate_session(session_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.debug("activate_session failed for %s: %s", session_id, e, exc_info=True)
        raise HTTPException(status_code=400, detail=str(e))
    return {"session_id": session_id, "state": "active"}


@app.post("/api/v1/sessions/{session_id}/terminate", tags=["Sessions"])
async def terminate_session(session_id: str) -> dict[str, Any]:
    """Terminate a session and commit audit trail."""
    try:
        hash_chain_root = await _hv().terminate_session(session_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.debug("terminate_session failed for %s: %s", session_id, e, exc_info=True)
        raise HTTPException(status_code=400, detail=str(e))
    return {
        "session_id": session_id,
        "state": "archived",
        "hash_chain_root": hash_chain_root,
    }


# ── Rings ───────────────────────────────────────────────────────────────────

@app.get(
    "/api/v1/sessions/{session_id}/rings",
    response_model=RingDistributionResponse,
    tags=["Rings"],
)
async def get_ring_distribution(session_id: str) -> RingDistributionResponse:
    """Get the ring distribution for all participants in a session."""
    managed = _get_managed(session_id)
    distribution: dict[str, list[str]] = {}
    for p in managed.sso.participants:
        ring_name = p.ring.name
        distribution.setdefault(ring_name, []).append(p.agent_did)
    return RingDistributionResponse(session_id=session_id, distribution=distribution)


@app.get(
    "/api/v1/agents/{agent_did}/ring",
    response_model=AgentRingResponse,
    tags=["Rings"],
)
async def get_agent_ring(agent_did: str) -> AgentRingResponse:
    """Get an agent's current ring level across all active sessions."""
    hv = _hv()
    for managed in hv._sessions.values():
        for p in managed.sso.participants:
            if p.agent_did == agent_did and p.is_active:
                return AgentRingResponse(
                    agent_did=agent_did,
                    ring=p.ring.value,
                    ring_name=p.ring.name,
                    session_id=managed.sso.session_id,
                )
    raise HTTPException(status_code=404, detail=f"Agent {agent_did} not found in any session")


@app.post(
    "/api/v1/rings/check",
    response_model=RingCheckResponse,
    tags=["Rings"],
)
async def check_ring_access(req: RingCheckRequest) -> RingCheckResponse:
    """Check if an action is allowed for the given ring level and sigma."""
    hv = _hv()
    action = ActionDescriptor(**req.action)
    agent_ring = ExecutionRing(req.agent_ring)
    result = hv.ring_enforcer.check(
        agent_ring=agent_ring,
        action=action,
        eff_score=req.eff_score,
        has_consensus=req.has_consensus,
        has_sre_witness=req.has_sre_witness,
    )
    return RingCheckResponse(
        allowed=result.allowed,
        required_ring=result.required_ring.value,
        agent_ring=result.agent_ring.value,
        eff_score=result.eff_score,
        reason=result.reason,
        requires_consensus=result.requires_consensus,
        requires_sre_witness=result.requires_sre_witness,
    )


# ── Sagas ───────────────────────────────────────────────────────────────────

@app.post(
    "/api/v1/sessions/{session_id}/sagas",
    response_model=CreateSagaResponse,
    status_code=201,
    tags=["Sagas"],
)
async def create_saga(session_id: str) -> CreateSagaResponse:
    """Create a new saga for a session."""
    managed = _get_managed(session_id)
    saga = managed.saga.create_saga(session_id)
    return CreateSagaResponse(
        saga_id=saga.saga_id,
        session_id=saga.session_id,
        state=saga.state.value,
        created_at=saga.created_at.isoformat(),
    )


@app.get(
    "/api/v1/sessions/{session_id}/sagas",
    response_model=list[SagaDetailResponse],
    tags=["Sagas"],
)
async def list_sagas(session_id: str) -> list[SagaDetailResponse]:
    """List all sagas in a session."""
    managed = _get_managed(session_id)
    return [
        SagaDetailResponse(
            saga_id=s.saga_id,
            session_id=s.session_id,
            state=s.state.value,
            created_at=s.created_at.isoformat(),
            completed_at=s.completed_at.isoformat() if s.completed_at else None,
            error=s.error,
            steps=[
                {
                    "step_id": st.step_id,
                    "action_id": st.action_id,
                    "agent_did": st.agent_did,
                    "state": st.state.value,
                    "error": st.error,
                }
                for st in s.steps
            ],
        )
        for s in managed.saga._sagas.values()
    ]


@app.get(
    "/api/v1/sagas/{saga_id}",
    response_model=SagaDetailResponse,
    tags=["Sagas"],
)
async def get_saga(saga_id: str) -> SagaDetailResponse:
    """Get detailed saga information including steps and state."""
    hv = _hv()
    for managed in hv._sessions.values():
        saga = managed.saga.get_saga(saga_id)
        if saga:
            return SagaDetailResponse(
                saga_id=saga.saga_id,
                session_id=saga.session_id,
                state=saga.state.value,
                created_at=saga.created_at.isoformat(),
                completed_at=saga.completed_at.isoformat() if saga.completed_at else None,
                error=saga.error,
                steps=[
                    {
                        "step_id": st.step_id,
                        "action_id": st.action_id,
                        "agent_did": st.agent_did,
                        "state": st.state.value,
                        "error": st.error,
                    }
                    for st in saga.steps
                ],
            )
    raise HTTPException(status_code=404, detail=f"Saga {saga_id} not found")


@app.post(
    "/api/v1/sagas/{saga_id}/steps",
    response_model=AddStepResponse,
    status_code=201,
    tags=["Sagas"],
)
async def add_saga_step(saga_id: str, req: AddStepRequest) -> AddStepResponse:
    """Add a step to an existing saga."""
    hv = _hv()
    for managed in hv._sessions.values():
        saga = managed.saga.get_saga(saga_id)
        if saga:
            try:
                step = managed.saga.add_step(
                    saga_id=saga_id,
                    action_id=req.action_id,
                    agent_did=req.agent_did,
                    execute_api=req.execute_api,
                    undo_api=req.undo_api,
                    timeout_seconds=req.timeout_seconds,
                    max_retries=req.max_retries,
                )
            except Exception as e:
                logger.debug("add_step failed for saga %s: %s", saga_id, e, exc_info=True)
                raise HTTPException(status_code=400, detail=str(e))
            return AddStepResponse(
                step_id=step.step_id,
                saga_id=saga_id,
                action_id=step.action_id,
                state=step.state.value,
            )
    raise HTTPException(status_code=404, detail=f"Saga {saga_id} not found")


@app.post(
    "/api/v1/sagas/{saga_id}/steps/{step_id}/execute",
    response_model=ExecuteStepResponse,
    tags=["Sagas"],
)
async def execute_saga_step(saga_id: str, step_id: str) -> ExecuteStepResponse:
    """Execute a pending saga step (using a no-op executor for API-driven flow)."""
    hv = _hv()
    for managed in hv._sessions.values():
        saga = managed.saga.get_saga(saga_id)
        if saga:
            try:
                async def _noop_executor() -> dict[str, str]:
                    return {"status": "executed_via_api"}

                await managed.saga.execute_step(saga_id, step_id, _noop_executor)
            except Exception as e:
                logger.debug("execute_step failed for saga %s step %s: %s", saga_id, step_id, e, exc_info=True)
                raise HTTPException(status_code=400, detail=str(e))
            # Find the step to return its state
            for st in saga.steps:
                if st.step_id == step_id:
                    return ExecuteStepResponse(
                        step_id=step_id,
                        saga_id=saga_id,
                        state=st.state.value,
                        error=st.error,
                    )
    raise HTTPException(status_code=404, detail=f"Saga {saga_id} or step {step_id} not found")


# ── Liability ───────────────────────────────────────────────────────────────

@app.post(
    "/api/v1/sessions/{session_id}/sponsor",
    response_model=VouchResponse,
    status_code=201,
    tags=["Liability"],
)
async def create_vouch(session_id: str, req: CreateVouchRequest) -> VouchResponse:
    """Create a sponsorship bond between agents in a session."""
    hv = _hv()
    _get_managed(session_id)  # verify session exists
    try:
        record = hv.vouching.vouch(
            voucher_did=req.voucher_did,
            vouchee_did=req.vouchee_did,
            session_id=session_id,
            voucher_sigma=req.voucher_sigma,
            bond_pct=req.bond_pct,
        )
    except Exception as e:
        logger.debug("create_vouch failed for session %s: %s", session_id, e, exc_info=True)
        raise HTTPException(status_code=400, detail=str(e))
    return VouchResponse(
        vouch_id=record.vouch_id,
        voucher_did=record.voucher_did,
        vouchee_did=record.vouchee_did,
        session_id=record.session_id,
        bonded_amount=record.bonded_amount,
        bonded_sigma_pct=record.bonded_sigma_pct,
        is_active=record.is_active,
    )


@app.get(
    "/api/v1/sessions/{session_id}/sponsors",
    response_model=list[VouchResponse],
    tags=["Liability"],
)
async def list_vouches(session_id: str) -> list[VouchResponse]:
    """List all sponsors in a session."""
    _get_managed(session_id)
    hv = _hv()
    return [
        VouchResponse(
            vouch_id=v.vouch_id,
            voucher_did=v.voucher_did,
            vouchee_did=v.vouchee_did,
            session_id=v.session_id,
            bonded_amount=v.bonded_amount,
            bonded_sigma_pct=v.bonded_sigma_pct,
            is_active=v.is_active,
        )
        for v in hv.vouching._vouches.values()
        if v.session_id == session_id
    ]


@app.get(
    "/api/v1/agents/{agent_did}/liability",
    response_model=LiabilityExposureResponse,
    tags=["Liability"],
)
async def get_agent_liability(agent_did: str) -> LiabilityExposureResponse:
    """Get an agent's liability exposure across all sessions."""
    hv = _hv()
    vouches_given = []
    vouches_received = []
    total_exposure = 0.0

    for v in hv.vouching._vouches.values():
        vr = VouchResponse(
            vouch_id=v.vouch_id,
            voucher_did=v.voucher_did,
            vouchee_did=v.vouchee_did,
            session_id=v.session_id,
            bonded_amount=v.bonded_amount,
            bonded_sigma_pct=v.bonded_sigma_pct,
            is_active=v.is_active,
        )
        if v.voucher_did == agent_did:
            vouches_given.append(vr)
            if v.is_active and not v.is_expired:
                total_exposure += v.bonded_amount
        if v.vouchee_did == agent_did:
            vouches_received.append(vr)

    return LiabilityExposureResponse(
        agent_did=agent_did,
        vouches_given=vouches_given,
        vouches_received=vouches_received,
        total_exposure=total_exposure,
    )


# ── Events ──────────────────────────────────────────────────────────────────

@app.get("/api/v1/events", response_model=list[EventResponse], tags=["Events"])
async def query_events(
    event_type: str | None = Query(None, description="Filter by event type"),
    session_id: str | None = Query(None, description="Filter by session ID"),
    agent_did: str | None = Query(None, description="Filter by agent DID"),
    limit: int | None = Query(None, description="Max events to return"),
) -> list[EventResponse]:
    """Query events with optional filters."""
    bus = _bus()
    et = None
    if event_type:
        try:
            et = EventType(event_type)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Unknown event type: {event_type}")
    events = bus.query(event_type=et, session_id=session_id, agent_did=agent_did, limit=limit)
    return [
        EventResponse(
            event_id=e.event_id,
            event_type=e.event_type.value,
            timestamp=e.timestamp.isoformat(),
            session_id=e.session_id,
            agent_did=e.agent_did,
            causal_trace_id=e.causal_trace_id,
            payload=e.payload,
        )
        for e in events
    ]


@app.get(
    "/api/v1/events/stats",
    response_model=EventStatsResponse,
    tags=["Events"],
)
async def get_event_stats() -> EventStatsResponse:
    """Get event type counts."""
    bus = _bus()
    return EventStatsResponse(
        total_events=bus.event_count,
        by_type=bus.type_counts(),
    )


# ── Audit endpoints ─────────────────────────────────────────────────────────

@app.get("/api/v1/audit/commitments", response_model=list[CommitmentResponse], tags=["Audit"])
async def list_commitments():
    """List all session commitments."""
    engine = _hv().commitment_engine
    return [
        CommitmentResponse(
            session_id=r.session_id,
            hash_chain_root=r.hash_chain_root,
            participant_dids=r.participant_dids,
            delta_count=r.delta_count,
            committed_at=r.committed_at.isoformat(),
            committed_to=r.committed_to,
            blockchain_tx_id=r.blockchain_tx_id,
        )
        for r in engine._commitments.values()
    ]

@app.get("/api/v1/audit/commitments/{session_id}", response_model=CommitmentResponse, tags=["Audit"])
async def get_commitment(session_id: str):
    """Get commitment for a specific session."""
    engine = _hv().commitment_engine
    record = engine.get_commitment(session_id)
    if not record:
        raise HTTPException(status_code=404, detail="Commitment not found")
    return CommitmentResponse(
        session_id=record.session_id,
        hash_chain_root=record.hash_chain_root,
        participant_dids=record.participant_dids,
        delta_count=record.delta_count,
        committed_at=record.committed_at.isoformat(),
        committed_to=record.committed_to,
        blockchain_tx_id=record.blockchain_tx_id,
    )

@app.post("/api/v1/audit/verify/{session_id}", response_model=VerifyCommitmentResponse, tags=["Audit"])
async def verify_commitment(session_id: str, expected_root: str = Query(...)):
    """Verify a session's audit log root matches its commitment."""
    engine = _hv().commitment_engine
    record = engine.get_commitment(session_id)
    if not record:
        raise HTTPException(status_code=404, detail="Commitment not found")
    valid = engine.verify(session_id, expected_root)
    return VerifyCommitmentResponse(
        session_id=session_id,
        valid=valid,
        committed_root=record.hash_chain_root,
        expected_root=expected_root,
    )

# ── Verification endpoints ──────────────────────────────────────────────────

@app.post("/api/v1/verify/history", response_model=VerifyHistoryResponse, tags=["Verification"])
async def verify_agent_history(request: VerifyHistoryRequest):
    """Verify an agent's transaction history."""
    from hypervisor.verification.history import TransactionRecord
    records = [
        TransactionRecord(
            session_id=r.session_id,
            summary_hash=r.summary_hash,
            timestamp=r.timestamp,
            participant_count=r.participant_count,
        )
        for r in request.transactions
    ]
    verifier = _hv().history_verifier
    result = verifier.verify(request.agent_did, records)
    return VerifyHistoryResponse(
        agent_did=result.agent_did,
        status=result.status.value,
        transactions_checked=result.transactions_checked,
        transactions_found=result.transactions_found,
        inconsistencies=result.inconsistencies,
        is_trustworthy=result.is_trustworthy,
        cached=result.cached,
    )

@app.delete("/api/v1/verify/cache/{agent_did}", tags=["Verification"])
async def clear_verification_cache(agent_did: str):
    """Clear cached verification result for an agent."""
    _hv().history_verifier.clear_cache(agent_did)
    return {"status": "cleared", "agent_did": agent_did}
