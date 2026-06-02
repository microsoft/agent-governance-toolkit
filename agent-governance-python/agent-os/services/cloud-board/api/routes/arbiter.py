# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Arbiter Routes

API endpoints for dispute resolution.
"""

import uuid
from datetime import datetime, timezone
from typing import Literal, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from ..auth import ADMIN_AUTH, AGENT_AUTH, AuthPrincipal, authorize_agent
from . import compliance as compliance_routes
from . import escrow as escrow_routes

router = APIRouter()


class SubmitDisputeRequest(BaseModel):
    escrow_id: str
    disputing_party: Literal["requester", "provider"]
    # Capped to 1000 chars consistent with RaiseDisputeRequest.reason and
    # ReleaseEscrowRequest.dispute_reason — any of the three paths can be
    # used to seed the dispute audit record, so a per-path cap would let
    # callers smuggle multi-megabyte reasons via the longest-allowed surface.
    dispute_reason: str = Field(min_length=1, max_length=1000)
    claimed_outcome: Literal["success", "failure", "partial"]
    flight_recorder_logs_hash: Optional[str] = None


class DisputeResponse(BaseModel):
    dispute_id: str
    escrow_id: str
    requester_did: Optional[str] = None
    provider_did: Optional[str] = None
    disputing_party: str
    dispute_reason: str
    claimed_outcome: str
    status: str
    created_at: str
    requester_logs_hash: Optional[str] = None
    provider_logs_hash: Optional[str] = None
    submitted_by: Optional[str] = None


class SubmitEvidenceRequest(BaseModel):
    flight_recorder_logs_hash: str


class ResolveDisputeRequest(BaseModel):
    """Admin-supplied resolution input for ``resolve_dispute``.

    The arbiter does not infer the winner from caller-supplied claim metadata.
    An administrator must explicitly state ``outcome`` (and may attach an
    ``explanation`` for the audit trail) before credits are redistributed.
    """

    outcome: Literal["requester_wins", "provider_wins", "split"]
    explanation: str = Field(default="", max_length=2000)


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
async def submit_dispute(
    request: SubmitDisputeRequest,
    principal: AuthPrincipal = AGENT_AUTH,
):
    """
    Submit a new dispute for resolution.

    The Arbiter will analyze evidence from both parties.
    """
    escrow_parties = escrow_routes.get_escrow_parties(request.escrow_id)
    if escrow_parties is None:
        raise HTTPException(status_code=404, detail="Escrow not found")

    # Use 404 (not 403) for the participant check so an unauthorized caller
    # cannot use submit_dispute as an oracle for escrow_id existence.
    expected_did = escrow_parties[request.disputing_party]
    if not principal.is_admin and principal.agent_did != expected_did:
        raise HTTPException(status_code=404, detail="Escrow not found")

    # Reject duplicate disputes for the same escrow: only one open (unresolved)
    # dispute may exist per escrow at a time, to prevent dispute spam and the
    # creation of "orphan" disputes that can never be resolved.
    for existing in _disputes.values():
        if existing["escrow_id"] == request.escrow_id and not existing.get("resolved"):
            raise HTTPException(
                status_code=409,
                detail={
                    "error": "DISPUTE_ALREADY_OPEN",
                    "message": (
                        f"An unresolved dispute ({existing['dispute_id']}) already "
                        f"exists for escrow {request.escrow_id}"
                    ),
                },
            )

    # Lock the escrow against any further release attempts before recording
    # the dispute. mark_escrow_disputed raises 400 if the escrow is already in
    # a terminal state and is idempotent for already-disputed escrows.
    escrow_routes.mark_escrow_disputed(
        request.escrow_id,
        reason=request.dispute_reason,
    )

    dispute_id = f"dispute_{uuid.uuid4().hex[:16]}"

    now = datetime.now(timezone.utc)

    dispute = {
        "dispute_id": dispute_id,
        "escrow_id": request.escrow_id,
        "requester_did": escrow_parties["requester"],
        "provider_did": escrow_parties["provider"],
        "disputing_party": request.disputing_party,
        "dispute_reason": request.dispute_reason,
        "claimed_outcome": request.claimed_outcome,
        "status": "pending_evidence",
        "created_at": now.isoformat(),
        "requester_logs_hash": None,
        "provider_logs_hash": None,
        "resolved": False,
        # Attribution: who actually called submit_dispute. For agent callers
        # this is their DID; for admin callers it is the literal "admin"
        # sentinel so audit/log readers can distinguish admin-initiated from
        # participant-initiated disputes.
        "submitted_by": "admin" if principal.is_admin else principal.agent_did,
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
async def get_dispute(
    dispute_id: str,
    principal: AuthPrincipal = AGENT_AUTH,
):
    """Get dispute details."""
    dispute = _get_dispute_or_404(dispute_id)
    _authorize_dispute_participant(dispute, principal)

    return DisputeResponse(**dispute)


@router.post("/{dispute_id}/evidence")
async def submit_evidence(
    dispute_id: str,
    request: SubmitEvidenceRequest,
    party: Literal["requester", "provider"],
    principal: AuthPrincipal = AGENT_AUTH,
):
    """Submit counter-evidence from the other party."""
    dispute = _get_dispute_or_404(dispute_id)
    # Convert agent-mismatch 403 to 404 so unauthorized callers cannot
    # enumerate dispute IDs or party slots via submit_evidence.
    expected_did = dispute[f"{party}_did"]
    if not principal.is_admin and principal.agent_did != expected_did:
        raise HTTPException(status_code=404, detail="Dispute not found")

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
async def resolve_dispute(
    dispute_id: str,
    request: ResolveDisputeRequest,
    _principal: AuthPrincipal = ADMIN_AUTH,
):
    """Resolve a dispute using an admin-supplied outcome.

    The outcome **must** be supplied by the administrator; the arbiter does
    not derive it from ``claimed_outcome`` (which is attacker-controlled at
    submit time). The decision is persisted on the dispute record so
    ``get_resolution`` can return the actual decision.
    """
    dispute = _get_dispute_or_404(dispute_id)

    if dispute["resolved"]:
        raise HTTPException(status_code=400, detail="Dispute already resolved")

    if not dispute["requester_logs_hash"] or not dispute["provider_logs_hash"]:
        raise HTTPException(
            status_code=400, detail="Evidence required from both parties before resolution"
        )

    # Total credits are derived from the locked escrow, not a hardcoded
    # constant — otherwise the disbursement would silently over- or
    # under-pay for any non-100-credit escrow.
    total_credits = escrow_routes.get_escrow_credits(dispute["escrow_id"])
    if total_credits is None:
        # The escrow has disappeared from under this dispute. Mark the
        # dispute terminal so it cannot accumulate as an orphan in
        # ``_disputes`` (and so a retry will see a 400 "already resolved"
        # rather than another 409). The dispute is recorded as
        # ``unresolvable`` for audit purposes.
        resolved_at_orphan = datetime.now(timezone.utc).isoformat()
        dispute["resolved"] = True
        dispute["status"] = "unresolvable"
        dispute["resolved_at"] = resolved_at_orphan
        dispute["resolution_outcome"] = "unresolvable"
        dispute["resolution"] = None
        raise HTTPException(
            status_code=409,
            detail={
                "error": "ESCROW_NOT_FOUND",
                "message": (
                    f"Escrow {dispute['escrow_id']} for dispute {dispute_id} no longer exists"
                ),
            },
        )

    outcome = request.outcome
    explanation = request.explanation or {
        "requester_wins": "Administrator ruled in favor of the requester",
        "provider_wins": "Administrator ruled in favor of the provider",
        "split": "Administrator ruled the dispute should be split",
    }[outcome]

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
        credits_provider = total_credits // 2
        credits_requester = total_credits - credits_provider
        rep_requester = -10
        rep_provider = -10

    # Actually disburse the locked escrow credits and transition the escrow
    # out of the 'disputed' state. Reputation deltas remain advisory in this
    # demo (they are surfaced on the response but not yet wired into
    # reputation._reputation_history); the README documents that boundary.
    escrow_routes.disburse_disputed_escrow(
        dispute["escrow_id"],
        credits_to_requester=credits_requester,
        credits_to_provider=credits_provider,
        resolution_reason=f"Arbiter ruled: {outcome}",
        resolved_by="arbiter",
    )

    resolved_at = datetime.now(timezone.utc).isoformat()
    resolution_record = {
        "outcome": outcome,
        "decision_explanation": explanation,
        "confidence_score": 1.0,
        "credits_to_requester": credits_requester,
        "credits_to_provider": credits_provider,
        "requester_reputation_change": rep_requester,
        "provider_reputation_change": rep_provider,
        "liar_identified": None,
        "resolved_at": resolved_at,
    }

    dispute["resolved"] = True
    dispute["status"] = "resolved"
    dispute["resolution_outcome"] = outcome
    dispute["resolved_at"] = resolved_at
    dispute["resolution"] = resolution_record

    compliance_routes._record_event(
        "dispute_resolved",
        dispute_id=dispute_id,
        escrow_id=dispute["escrow_id"],
        requester_did=dispute.get("requester_did"),
        provider_did=dispute.get("provider_did"),
        outcome=outcome,
        credits_to_requester=credits_requester,
        credits_to_provider=credits_provider,
        resolved_by="arbiter",
    )

    return DisputeResolutionResponse(
        dispute_id=dispute_id,
        escrow_id=dispute["escrow_id"],
        **resolution_record,
    )


@router.get("/{dispute_id}/resolution", response_model=DisputeResolutionResponse)
async def get_resolution(
    dispute_id: str,
    principal: AuthPrincipal = AGENT_AUTH,
):
    """Get resolution for a resolved dispute."""
    dispute = _get_dispute_or_404(dispute_id)
    _authorize_dispute_participant(dispute, principal)

    resolution = dispute.get("resolution")
    if not dispute.get("resolved") or resolution is None:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "RESOLUTION_NOT_FOUND",
                "message": "Dispute has not been resolved yet",
            },
        )

    return DisputeResolutionResponse(
        dispute_id=dispute_id,
        escrow_id=dispute["escrow_id"],
        **resolution,
    )


@router.get("")
async def list_disputes(
    agent_did: Optional[str] = Query(default=None),
    resolved: Optional[bool] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
    principal: AuthPrincipal = AGENT_AUTH,
):
    """List disputes with optional filtering."""
    results = list(_disputes.values())

    if principal.is_admin:
        scoped_agent_did = agent_did
    else:
        scoped_agent_did = agent_did or principal.agent_did
        authorize_agent(scoped_agent_did, principal)

    if scoped_agent_did:
        results = [
            d
            for d in results
            if d.get("requester_did") == scoped_agent_did
            or d.get("provider_did") == scoped_agent_did
        ]

    if resolved is not None:
        results = [d for d in results if d["resolved"] == resolved]

    return {"disputes": results[:limit], "total": len(results)}


def _get_dispute_or_404(dispute_id: str) -> dict:
    if dispute_id not in _disputes:
        raise HTTPException(status_code=404, detail="Dispute not found")
    return _disputes[dispute_id]


def _authorize_dispute_participant(dispute: dict, principal: AuthPrincipal) -> None:
    if principal.is_admin:
        return
    if principal.agent_did in (dispute.get("requester_did"), dispute.get("provider_did")):
        return
    # Return 404 (not 403) so an unauthorized caller cannot enumerate dispute
    # IDs by distinguishing "exists but not yours" from "does not exist".
    raise HTTPException(
        status_code=404,
        detail={
            "error": "DISPUTE_NOT_FOUND",
            "message": f"Dispute {dispute.get('dispute_id')} not found",
        },
    )
