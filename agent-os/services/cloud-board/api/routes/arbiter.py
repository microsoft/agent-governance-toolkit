# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Arbiter Routes

API endpoints for dispute resolution.
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, Literal
from datetime import datetime, timezone
import uuid

router = APIRouter()


class SubmitDisputeRequest(BaseModel):
    escrow_id: str
    disputing_party: Literal["requester", "provider"]
    dispute_reason: str
    claimed_outcome: Literal["success", "failure", "partial"]
    flight_recorder_logs_hash: Optional[str] = None


class DisputeResponse(BaseModel):
    dispute_id: str
    escrow_id: str
    disputing_party: str
    dispute_reason: str
    claimed_outcome: str
    status: str
    created_at: str
    requester_logs_hash: Optional[str] = None
    provider_logs_hash: Optional[str] = None


class SubmitEvidenceRequest(BaseModel):
    flight_recorder_logs_hash: str


class DisputeResolutionResponse(BaseModel):
    dispute_id: str
    escrow_id: str
    outcome: Literal["requester_wins", "provider_wins", "split"]
    decision_explanation: str
    confidence_score: float
    credits_to_requester: int
    credits_to_provider: int
    requester_reputation_change: int
    provider_reputation_change: int
    liar_identified: Optional[str] = None
    resolved_at: str


# In-memory storage
_disputes: dict[str, dict] = {}


@router.post("", response_model=DisputeResponse)
async def submit_dispute(request: SubmitDisputeRequest):
    """
    Submit a new dispute for resolution.
    
    The Arbiter will analyze evidence from both parties.
    """
    dispute_id = f"dispute_{uuid.uuid4().hex[:16]}"
    
    now = datetime.now(timezone.utc)
    
    dispute = {
        "dispute_id": dispute_id,
        "escrow_id": request.escrow_id,
        "disputing_party": request.disputing_party,
        "dispute_reason": request.dispute_reason,
        "claimed_outcome": request.claimed_outcome,
        "status": "pending_evidence",
        "created_at": now.isoformat(),
        "requester_logs_hash": None,
        "provider_logs_hash": None,
        "resolved": False,
    }
    
    # Set initial evidence
    if request.flight_recorder_logs_hash:
        if request.disputing_party == "requester":
            dispute["requester_logs_hash"] = request.flight_recorder_logs_hash
        else:
            dispute["provider_logs_hash"] = request.flight_recorder_logs_hash
    
    _disputes[dispute_id] = dispute
    
    return DisputeResponse(**dispute)


@router.get("/{dispute_id}", response_model=DisputeResponse)
async def get_dispute(dispute_id: str):
    """Get dispute details."""
    if dispute_id not in _disputes:
        raise HTTPException(status_code=404, detail="Dispute not found")
    
    return DisputeResponse(**_disputes[dispute_id])


@router.post("/{dispute_id}/evidence")
async def submit_evidence(dispute_id: str, request: SubmitEvidenceRequest, party: str):
    """Submit counter-evidence from the other party."""
    if dispute_id not in _disputes:
        raise HTTPException(status_code=404, detail="Dispute not found")
    
    dispute = _disputes[dispute_id]
    
    if dispute["resolved"]:
        raise HTTPException(status_code=400, detail="Dispute already resolved")
    
    if party == "requester":
        dispute["requester_logs_hash"] = request.flight_recorder_logs_hash
    else:
        dispute["provider_logs_hash"] = request.flight_recorder_logs_hash
    
    # Check if we have evidence from both parties
    if dispute["requester_logs_hash"] and dispute["provider_logs_hash"]:
        dispute["status"] = "ready_for_resolution"
    
    return {"success": True, "status": dispute["status"]}


@router.post("/{dispute_id}/resolve", response_model=DisputeResolutionResponse)
async def resolve_dispute(dispute_id: str):
    """
    Resolve a dispute by analyzing evidence.
    
    The Arbiter replays flight recorder logs against the Control Plane
    to determine which agent's claim is accurate.
    """
    if dispute_id not in _disputes:
        raise HTTPException(status_code=404, detail="Dispute not found")
    
    dispute = _disputes[dispute_id]
    
    if dispute["resolved"]:
        raise HTTPException(status_code=400, detail="Dispute already resolved")
    
    # Check we have evidence
    if not dispute["requester_logs_hash"] or not dispute["provider_logs_hash"]:
        raise HTTPException(
            status_code=400,
            detail="Evidence required from both parties before resolution"
        )
    
    # Analyze dispute (placeholder logic)
    # In production, would replay logs against Control Plane
    
    # For demo, use simple heuristics
    requester_valid = bool(dispute["requester_logs_hash"])
    provider_valid = bool(dispute["provider_logs_hash"])
    
    # Determine outcome
    if dispute["claimed_outcome"] == "success":
        # Disputing party claims success - likely provider
        outcome = "provider_wins"
        decision = "Evidence supports task completion claim"
        liar = None
    elif dispute["claimed_outcome"] == "failure":
        # Disputing party claims failure - likely requester
        outcome = "requester_wins"
        decision = "Evidence supports task failure claim"
        liar = None
    else:
        outcome = "split"
        decision = "Inconclusive evidence; compromise reached"
        liar = None
    
    # Calculate credit distribution (assume 100 credits for demo)
    total_credits = 100
    
    if outcome == "requester_wins":
        credits_requester = total_credits
        credits_provider = 0
        rep_requester = 10
        rep_provider = -50
    elif outcome == "provider_wins":
        credits_requester = 0
        credits_provider = total_credits
        rep_requester = -50
        rep_provider = 10
    else:
        credits_requester = total_credits // 2
        credits_provider = total_credits // 2
        rep_requester = -10
        rep_provider = -10
    
    # Mark resolved
    dispute["resolved"] = True
    dispute["status"] = "resolved"
    dispute["resolution_outcome"] = outcome
    dispute["resolved_at"] = datetime.now(timezone.utc).isoformat()
    
    return DisputeResolutionResponse(
        dispute_id=dispute_id,
        escrow_id=dispute["escrow_id"],
        outcome=outcome,
        decision_explanation=decision,
        confidence_score=0.85,
        credits_to_requester=credits_requester,
        credits_to_provider=credits_provider,
        requester_reputation_change=rep_requester,
        provider_reputation_change=rep_provider,
        liar_identified=liar,
        resolved_at=dispute["resolved_at"],
    )


@router.get("/{dispute_id}/resolution", response_model=DisputeResolutionResponse)
async def get_resolution(dispute_id: str):
    """Get resolution for a resolved dispute."""
    if dispute_id not in _disputes:
        raise HTTPException(status_code=404, detail="Dispute not found")
    
    dispute = _disputes[dispute_id]
    
    if not dispute["resolved"]:
        raise HTTPException(status_code=400, detail="Dispute not yet resolved")
    
    # Return stored resolution (in production would fetch from resolution store)
    return DisputeResolutionResponse(
        dispute_id=dispute_id,
        escrow_id=dispute["escrow_id"],
        outcome=dispute.get("resolution_outcome", "split"),
        decision_explanation="Resolution from Arbiter",
        confidence_score=0.85,
        credits_to_requester=50,
        credits_to_provider=50,
        requester_reputation_change=-10,
        provider_reputation_change=-10,
        liar_identified=None,
        resolved_at=dispute["resolved_at"],
    )


@router.get("")
async def list_disputes(
    agent_did: Optional[str] = Query(default=None),
    resolved: Optional[bool] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
):
    """List disputes with optional filtering."""
    results = list(_disputes.values())
    
    if resolved is not None:
        results = [d for d in results if d["resolved"] == resolved]
    
    # Would filter by agent_did if we stored that
    
    return {"disputes": results[:limit], "total": len(results)}
