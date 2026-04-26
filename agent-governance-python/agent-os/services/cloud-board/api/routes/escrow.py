# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Escrow Routes

API endpoints for the Proof-of-Outcome escrow system.
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, Literal
from datetime import datetime, timedelta, timezone
import uuid

router = APIRouter()


class CreateEscrowRequest(BaseModel):
    requester_did: str
    provider_did: str
    task_hash: str
    task_description: Optional[str] = None
    credits: int
    timeout_seconds: int = 3600
    require_scak_validation: bool = True
    scak_drift_threshold: float = 0.15
    data_classification: Literal["public", "internal", "confidential", "pii"] = "internal"


class EscrowReceiptResponse(BaseModel):
    escrow_id: str
    status: str
    requester_did: str
    provider_did: str
    credits: int
    created_at: str
    expires_at: str
    nexus_signature: Optional[str] = None


class ReleaseEscrowRequest(BaseModel):
    outcome: Literal["success", "failure", "dispute"]
    output_hash: Optional[str] = None
    duration_ms: Optional[int] = None
    scak_drift_score: Optional[float] = None
    dispute_reason: Optional[str] = None


class EscrowResolutionResponse(BaseModel):
    escrow_id: str
    final_status: str
    credits_to_provider: int
    credits_to_requester: int
    provider_reputation_change: int
    requester_reputation_change: int
    resolution_reason: str
    resolved_by: str


# In-memory storage
_escrows: dict[str, dict] = {}
_agent_credits: dict[str, int] = {}


@router.post("", response_model=EscrowReceiptResponse)
async def create_escrow(request: CreateEscrowRequest):
    """
    Create an escrow for a task.
    
    Locks credits from requester until task completion or timeout.
    """
    # Check credits
    available = _agent_credits.get(request.requester_did, 1000)  # Default 1000 for demo
    if available < request.credits:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "INSUFFICIENT_CREDITS",
                "message": f"Insufficient credits: required={request.credits}, available={available}",
                "required": request.credits,
                "available": available,
            }
        )
    
    # Generate escrow ID
    escrow_id = f"escrow_{uuid.uuid4().hex[:16]}"
    
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=request.timeout_seconds)
    
    # Create escrow
    escrow = {
        "escrow_id": escrow_id,
        "status": "pending",
        "requester_did": request.requester_did,
        "provider_did": request.provider_did,
        "task_hash": request.task_hash,
        "credits": request.credits,
        "require_scak": request.require_scak_validation,
        "scak_threshold": request.scak_drift_threshold,
        "data_classification": request.data_classification,
        "created_at": now.isoformat(),
        "expires_at": expires_at.isoformat(),
    }
    
    # Lock credits
    _agent_credits[request.requester_did] = available - request.credits
    
    # Store
    _escrows[escrow_id] = escrow
    
    return EscrowReceiptResponse(
        escrow_id=escrow_id,
        status="pending",
        requester_did=request.requester_did,
        provider_did=request.provider_did,
        credits=request.credits,
        created_at=now.isoformat(),
        expires_at=expires_at.isoformat(),
        nexus_signature=f"nexus_escrow_{escrow_id[:16]}",
    )


@router.get("/{escrow_id}", response_model=EscrowReceiptResponse)
async def get_escrow(escrow_id: str):
    """Get escrow details."""
    if escrow_id not in _escrows:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "ESCROW_NOT_FOUND",
                "message": f"Escrow {escrow_id} not found",
            }
        )
    
    escrow = _escrows[escrow_id]
    return EscrowReceiptResponse(
        escrow_id=escrow["escrow_id"],
        status=escrow["status"],
        requester_did=escrow["requester_did"],
        provider_did=escrow["provider_did"],
        credits=escrow["credits"],
        created_at=escrow["created_at"],
        expires_at=escrow["expires_at"],
    )


@router.post("/{escrow_id}/activate")
async def activate_escrow(escrow_id: str):
    """Mark escrow as active (task in progress)."""
    if escrow_id not in _escrows:
        raise HTTPException(status_code=404, detail="Escrow not found")
    
    escrow = _escrows[escrow_id]
    
    if escrow["status"] != "pending":
        raise HTTPException(
            status_code=400,
            detail=f"Cannot activate escrow in status: {escrow['status']}"
        )
    
    escrow["status"] = "active"
    escrow["activated_at"] = datetime.now(timezone.utc).isoformat()
    
    return {"success": True, "status": "active"}


@router.post("/{escrow_id}/release", response_model=EscrowResolutionResponse)
async def release_escrow(escrow_id: str, request: ReleaseEscrowRequest):
    """
    Release escrow based on outcome.
    
    - success: Credits go to provider
    - failure: Credits returned to requester  
    - dispute: Escalate to Arbiter
    """
    if escrow_id not in _escrows:
        raise HTTPException(status_code=404, detail="Escrow not found")
    
    escrow = _escrows[escrow_id]
    
    if escrow["status"] not in ("pending", "active", "awaiting_validation"):
        raise HTTPException(
            status_code=400,
            detail=f"Escrow already resolved: {escrow['status']}"
        )
    
    credits = escrow["credits"]
    requester = escrow["requester_did"]
    provider = escrow["provider_did"]
    
    if request.outcome == "success":
        # Check SCAK if required
        if escrow.get("require_scak") and request.scak_drift_score is not None:
            if request.scak_drift_score > escrow.get("scak_threshold", 0.15):
                # SCAK failed - treat as failure
                return await _resolve_failure(escrow_id, escrow)
        
        return await _resolve_success(escrow_id, escrow)
    
    elif request.outcome == "failure":
        return await _resolve_failure(escrow_id, escrow)
    
    else:  # dispute
        escrow["status"] = "disputed"
        escrow["dispute_reason"] = request.dispute_reason
        
        return EscrowResolutionResponse(
            escrow_id=escrow_id,
            final_status="disputed",
            credits_to_provider=0,
            credits_to_requester=0,
            provider_reputation_change=0,
            requester_reputation_change=0,
            resolution_reason=f"Dispute raised: {request.dispute_reason}",
            resolved_by="arbiter",
        )


@router.post("/{escrow_id}/dispute")
async def raise_dispute(escrow_id: str, reason: str):
    """Raise a dispute on an escrow."""
    if escrow_id not in _escrows:
        raise HTTPException(status_code=404, detail="Escrow not found")
    
    escrow = _escrows[escrow_id]
    escrow["status"] = "disputed"
    escrow["dispute_reason"] = reason
    
    return {
        "success": True,
        "escrow_id": escrow_id,
        "status": "disputed",
        "message": "Dispute submitted to Arbiter",
    }


@router.get("")
async def list_escrows(
    agent_did: Optional[str] = Query(default=None),
    status: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
):
    """List escrows with optional filtering."""
    results = list(_escrows.values())
    
    if agent_did:
        results = [
            e for e in results
            if e["requester_did"] == agent_did or e["provider_did"] == agent_did
        ]
    
    if status:
        results = [e for e in results if e["status"] == status]
    
    return {"escrows": results[:limit], "total": len(results)}


# Credit management endpoints

@router.get("/credits/{agent_did}")
async def get_credits(agent_did: str):
    """Get credit balance for an agent."""
    credits = _agent_credits.get(agent_did, 1000)  # Default 1000 for demo
    return {"agent_did": agent_did, "credits": credits}


@router.post("/credits/{agent_did}/add")
async def add_credits(agent_did: str, amount: int):
    """Add credits to an agent's balance."""
    current = _agent_credits.get(agent_did, 1000)
    _agent_credits[agent_did] = current + amount
    return {"agent_did": agent_did, "credits": _agent_credits[agent_did]}


async def _resolve_success(escrow_id: str, escrow: dict) -> EscrowResolutionResponse:
    """Resolve escrow as success."""
    credits = escrow["credits"]
    provider = escrow["provider_did"]
    
    # Transfer credits to provider
    _agent_credits[provider] = _agent_credits.get(provider, 1000) + credits
    
    escrow["status"] = "released"
    escrow["resolved_at"] = datetime.now(timezone.utc).isoformat()
    
    return EscrowResolutionResponse(
        escrow_id=escrow_id,
        final_status="released",
        credits_to_provider=credits,
        credits_to_requester=0,
        provider_reputation_change=2,
        requester_reputation_change=0,
        resolution_reason="Task completed successfully",
        resolved_by="automatic",
    )


async def _resolve_failure(escrow_id: str, escrow: dict) -> EscrowResolutionResponse:
    """Resolve escrow as failure."""
    credits = escrow["credits"]
    requester = escrow["requester_did"]
    
    # Return credits to requester
    _agent_credits[requester] = _agent_credits.get(requester, 1000) + credits
    
    escrow["status"] = "refunded"
    escrow["resolved_at"] = datetime.now(timezone.utc).isoformat()
    
    return EscrowResolutionResponse(
        escrow_id=escrow_id,
        final_status="refunded",
        credits_to_provider=0,
        credits_to_requester=credits,
        provider_reputation_change=-10,
        requester_reputation_change=0,
        resolution_reason="Task failed",
        resolved_by="automatic",
    )
