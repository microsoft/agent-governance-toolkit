# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Hypervisor — Example REST API Server

Simplified FastAPI server demonstrating hypervisor capabilities:
  - Agent registration with execution ring assignment
  - Kill switch for rogue agents
  - Health check and audit log

Run:
    uvicorn app.server:app --host 0.0.0.0 --port 8000
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Optional

import yaml
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from hypervisor import __version__
from hypervisor.core import Hypervisor
from hypervisor.models import ExecutionRing, SessionConfig
from hypervisor.security.kill_switch import KillReason, KillSwitch

logger = logging.getLogger(__name__)

# ── Request / Response models ───────────────────────────────────────────────


class RegisterAgentRequest(BaseModel):
    """Register an agent with an execution ring."""

    agent_did: str = Field(..., description="Decentralized identifier for the agent")
    sigma_raw: float = Field(0.0, description="Raw reputation score (0.0 – 1.0)")
    actions: Optional[list[dict[str, Any]]] = Field(
        None, description="IATP capability manifest actions"
    )


class AgentInfo(BaseModel):
    """Agent details with ring assignment."""

    agent_did: str
    ring: int
    ring_name: str
    sigma_raw: float
    eff_score: float
    session_id: str
    registered_at: str


class KillRequest(BaseModel):
    """Kill switch request."""

    agent_did: str = Field(..., description="Agent to terminate")
    reason: str = Field("manual", description="Kill reason")


class KillResponse(BaseModel):
    """Kill switch result."""

    kill_id: str
    agent_did: str
    reason: str
    compensation_triggered: bool
    timestamp: str


class AuditEntry(BaseModel):
    """Single audit log entry."""

    event: str
    agent_did: str
    detail: str
    timestamp: str


# ── State ───────────────────────────────────────────────────────────────────

_hypervisor: Optional[Hypervisor] = None
_kill_switch: Optional[KillSwitch] = None
_session_id: Optional[str] = None
_audit_log: list[dict[str, str]] = []


def _log_audit(event: str, agent_did: str, detail: str) -> None:
    _audit_log.append(
        {
            "event": event,
            "agent_did": agent_did,
            "detail": detail,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )


def _load_config() -> dict[str, Any]:
    config_path = os.getenv("HYPERVISOR_CONFIG", "config/hypervisor.yaml")
    try:
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        logger.warning("Config %s not found, using defaults", config_path)
        return {}


# ── Lifespan ────────────────────────────────────────────────────────────────


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    global _hypervisor, _kill_switch, _session_id

    config = _load_config()
    _hypervisor = Hypervisor()
    _kill_switch = KillSwitch()

    hv_cfg = config.get("hypervisor", {})
    session_config = SessionConfig(
        max_participants=hv_cfg.get("max_participants", 10),
        min_eff_score=hv_cfg.get("min_eff_score", 0.60),
        enable_audit=hv_cfg.get("enable_audit", True),
    )
    managed = await _hypervisor.create_session(
        config=session_config, creator_did="did:mesh:hypervisor"
    )
    _session_id = managed.sso.session_id
    logger.info("Hypervisor session %s created", _session_id)

    yield

    _hypervisor = None
    _kill_switch = None
    _session_id = None
    _audit_log.clear()


# ── App ─────────────────────────────────────────────────────────────────────


app = FastAPI(
    title="Agent Hypervisor API",
    description="Docker Compose example — register agents, assign rings, kill switch, audit log.",
    version=__version__,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:8080").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Endpoints ───────────────────────────────────────────────────────────────


@app.get("/health", tags=["Health"])
async def health() -> dict[str, str]:
    """Health check."""
    return {"status": "ok", "version": __version__, "session_id": _session_id or ""}


@app.post("/agents", response_model=AgentInfo, status_code=201, tags=["Agents"])
async def register_agent(req: RegisterAgentRequest) -> AgentInfo:
    """Register an agent and assign an execution ring based on reputation."""
    if _hypervisor is None or _session_id is None:
        raise HTTPException(status_code=503, detail="Hypervisor not initialized")

    try:
        ring = await _hypervisor.join_session(
            session_id=_session_id,
            agent_did=req.agent_did,
            sigma_raw=req.sigma_raw,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    managed = _hypervisor.get_session(_session_id)
    participant = managed.sso.get_participant(req.agent_did)  # type: ignore[union-attr]

    _log_audit("agent_registered", req.agent_did, f"ring={ring.name}")

    return AgentInfo(
        agent_did=req.agent_did,
        ring=ring.value,
        ring_name=ring.name,
        sigma_raw=participant.sigma_raw,
        eff_score=participant.eff_score,
        session_id=_session_id,
        registered_at=participant.joined_at.isoformat(),
    )


@app.get("/agents", response_model=list[AgentInfo], tags=["Agents"])
async def list_agents() -> list[AgentInfo]:
    """List all registered agents with their ring assignments."""
    if _hypervisor is None or _session_id is None:
        raise HTTPException(status_code=503, detail="Hypervisor not initialized")

    managed = _hypervisor.get_session(_session_id)
    if not managed:
        return []

    return [
        AgentInfo(
            agent_did=p.agent_did,
            ring=p.ring.value,
            ring_name=p.ring.name,
            sigma_raw=p.sigma_raw,
            eff_score=p.eff_score,
            session_id=_session_id,
            registered_at=p.joined_at.isoformat(),
        )
        for p in managed.sso.participants
    ]


@app.post("/kill", response_model=KillResponse, tags=["Security"])
async def kill_agent(req: KillRequest) -> KillResponse:
    """Emergency kill switch — immediately terminate a rogue agent."""
    if _kill_switch is None or _session_id is None:
        raise HTTPException(status_code=503, detail="Kill switch not initialized")

    try:
        reason = KillReason(req.reason)
    except ValueError:
        reason = KillReason.MANUAL

    result = _kill_switch.kill(
        agent_did=req.agent_did,
        session_id=_session_id,
        reason=reason,
    )

    _log_audit("agent_killed", req.agent_did, f"reason={reason.value}")

    return KillResponse(
        kill_id=result.kill_id,
        agent_did=result.agent_did,
        reason=result.reason.value,
        compensation_triggered=result.compensation_triggered,
        timestamp=result.timestamp.isoformat(),
    )


@app.get("/audit", response_model=list[AuditEntry], tags=["Audit"])
async def get_audit_log() -> list[AuditEntry]:
    """Return the audit log of all hypervisor actions."""
    return [AuditEntry(**entry) for entry in _audit_log]
