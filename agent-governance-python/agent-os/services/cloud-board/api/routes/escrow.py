# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Escrow Routes

API endpoints for the Proof-of-Outcome escrow system.
"""

import math
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field, field_validator

from ..auth import ADMIN_AUTH, AGENT_AUTH, AuthPrincipal, authorize_agent

router = APIRouter()


class CreateEscrowRequest(BaseModel):
    requester_did: str
    provider_did: str
    task_hash: str
    task_description: Optional[str] = None
    credits: int = Field(gt=0)
    timeout_seconds: int = Field(default=3600, gt=0)
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
    dispute_reason: Optional[str] = Field(default=None, max_length=1000)

    @field_validator("scak_drift_score")
    @classmethod
    def _validate_drift_finite(cls, value: Optional[float]) -> Optional[float]:
        # NaN/±Inf must not silently bypass the SCAK gate: ``NaN > threshold``
        # is ``False``, so a malicious caller could otherwise release a SCAK-
        # gated escrow without ever crossing the threshold. Reject explicitly.
        if value is not None and not math.isfinite(value):
            raise ValueError(
                "scak_drift_score must be a finite number (no NaN/Inf)"
            )
        return value


class EscrowResolutionResponse(BaseModel):
    escrow_id: str
    final_status: str
    credits_to_provider: int
    credits_to_requester: int
    provider_reputation_change: int
    requester_reputation_change: int
    resolution_reason: str
    resolved_by: str


class RaiseDisputeRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=1000)


# In-memory storage
_escrows: dict[str, dict] = {}
_agent_credits: dict[str, int] = {}


@router.post("", response_model=EscrowReceiptResponse)
async def create_escrow(
    request: CreateEscrowRequest,
    principal: AuthPrincipal = AGENT_AUTH,
):
    """
    Create an escrow for a task.

    Locks credits from requester until task completion or timeout.
    """
    authorize_agent(request.requester_did, principal)

    # Self-escrow is rejected: it has no economic meaning (a participant
    # would only be paying themselves) and provides a free primitive for
    # spamming compliance/audit state with no cost.
    if request.requester_did == request.provider_did:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "SELF_ESCROW_FORBIDDEN",
                "message": "requester_did and provider_did must differ",
            },
        )

    # Provider must be a registered agent. Otherwise a credit transfer can
    # be routed to an unowned DID (where no one holds the matching token to
    # ever spend the credits) — effectively burning credits in a way that
    # the requester cannot observe up-front.
    from . import registry as registry_routes
    if request.provider_did not in registry_routes._agents:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "PROVIDER_NOT_REGISTERED",
                "message": (
                    f"Provider DID {request.provider_did} is not registered "
                    "with the Cloud Board"
                ),
            },
        )

    # Check credits
    available = _agent_credits.get(request.requester_did, 0)
    if available < request.credits:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "INSUFFICIENT_CREDITS",
                "message": f"Insufficient credits: required={request.credits}, available={available}",
                "required": request.credits,
                "available": available,
            },
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
async def get_escrow(
    escrow_id: str,
    principal: AuthPrincipal = AGENT_AUTH,
):
    """Get escrow details."""
    escrow = _get_escrow_or_404(escrow_id)
    _authorize_escrow_participant(escrow, principal)
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
async def activate_escrow(
    escrow_id: str,
    principal: AuthPrincipal = AGENT_AUTH,
):
    """Mark escrow as active (task in progress)."""
    escrow = _get_escrow_or_404(escrow_id)
    if not principal.is_admin:
        authorize_agent(escrow["provider_did"], principal)

    if escrow["status"] != "pending":
        raise HTTPException(
            status_code=400, detail=f"Cannot activate escrow in status: {escrow['status']}"
        )

    escrow["status"] = "active"
    escrow["activated_at"] = datetime.now(timezone.utc).isoformat()

    return {"success": True, "status": "active"}


@router.post("/{escrow_id}/release", response_model=EscrowResolutionResponse)
async def release_escrow(
    escrow_id: str,
    request: ReleaseEscrowRequest,
    principal: AuthPrincipal = AGENT_AUTH,
):
    """
    Release escrow based on outcome.

    - success: Credits go to provider
    - failure: Credits returned to requester
    - dispute: Escalate to Arbiter
    """
    escrow = _get_escrow_or_404(escrow_id)

    # Authorization model:
    #   - success: requester confirms work was delivered and pays the provider.
    #     Only the requester (or admin) may release as success.
    #   - failure: provider confirms they did not deliver and credits go back to
    #     requester. Only the provider (or admin) may release as failure — the
    #     requester cannot unilaterally refund themselves; that is what /dispute
    #     is for.
    #   - dispute: either escrow participant (or admin) may escalate.
    if not principal.is_admin:
        if request.outcome == "success":
            authorize_agent(escrow["requester_did"], principal)
        elif request.outcome == "failure":
            authorize_agent(escrow["provider_did"], principal)
        else:  # dispute
            _authorize_escrow_participant(escrow, principal)

    if escrow["status"] not in ("pending", "active", "awaiting_validation"):
        raise HTTPException(status_code=400, detail=f"Escrow already resolved: {escrow['status']}")

    if request.outcome == "success":
        # SCAK gate: when the escrow requires SCAK we must have an explicit
        # drift score. A missing score is treated as a failure (fail-closed)
        # rather than silently allowing release.
        if escrow.get("require_scak"):
            if request.scak_drift_score is None:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "SCAK_DRIFT_SCORE_REQUIRED",
                        "message": (
                            "scak_drift_score is required when releasing an "
                            "escrow with require_scak=true"
                        ),
                    },
                )
            if request.scak_drift_score > escrow.get("scak_threshold", 0.15):
                return await _resolve_failure(escrow_id, escrow)

        return await _resolve_success(escrow_id, escrow)

    elif request.outcome == "failure":
        return await _resolve_failure(escrow_id, escrow)

    else:  # dispute
        escrow["status"] = "disputed"
        # Don't clobber an existing dispute_reason with None. If the caller
        # didn't provide one, preserve whatever was recorded previously (this
        # branch should only fire from a 'pending'/'active' state per the
        # status guard above, so dispute_reason is usually absent — but the
        # ``setdefault`` semantics protect us from audit-trail destruction in
        # any future code path that might re-enter the dispute branch.)
        if request.dispute_reason is not None:
            escrow["dispute_reason"] = request.dispute_reason
        else:
            escrow.setdefault("dispute_reason", None)

        return EscrowResolutionResponse(
            escrow_id=escrow_id,
            final_status="disputed",
            credits_to_provider=0,
            credits_to_requester=0,
            provider_reputation_change=0,
            requester_reputation_change=0,
            resolution_reason=(
                f"Dispute raised: {request.dispute_reason}"
                if request.dispute_reason is not None
                else "Dispute raised"
            ),
            resolved_by="arbiter",
        )


@router.post("/{escrow_id}/dispute")
async def raise_dispute(
    escrow_id: str,
    request: RaiseDisputeRequest,
    principal: AuthPrincipal = AGENT_AUTH,
):
    """Raise a dispute on an escrow.

    Only escrows in an open state (``pending``, ``active``, ``awaiting_validation``)
    may be transitioned to ``disputed``. Reopening a terminal escrow (``released``,
    ``refunded``, ``split``, ``resolved``) is rejected to prevent double-disbursement
    via re-dispute and re-resolution.
    """
    escrow = _get_escrow_or_404(escrow_id)
    _authorize_escrow_participant(escrow, principal)
    if escrow["status"] not in ("pending", "active", "awaiting_validation", "disputed"):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "ESCROW_ALREADY_RESOLVED",
                "message": (
                    f"Cannot dispute escrow in terminal state '{escrow['status']}'"
                ),
            },
        )
    if escrow["status"] == "disputed":
        # Idempotent re-raise must preserve the original dispute reason so
        # audit history cannot be rewritten by a subsequent participant call.
        return {
            "success": True,
            "escrow_id": escrow_id,
            "status": "disputed",
            "message": "Dispute already open",
        }
    escrow["status"] = "disputed"
    escrow["dispute_reason"] = request.reason

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
    principal: AuthPrincipal = AGENT_AUTH,
):
    """List escrows with optional filtering."""
    results = list(_escrows.values())

    if principal.is_admin:
        scoped_agent_did = agent_did
    else:
        scoped_agent_did = agent_did or principal.agent_did
        authorize_agent(scoped_agent_did, principal)

    if scoped_agent_did:
        results = [
            e
            for e in results
            if e["requester_did"] == scoped_agent_did or e["provider_did"] == scoped_agent_did
        ]

    if status:
        results = [e for e in results if e["status"] == status]

    return {"escrows": results[:limit], "total": len(results)}


# Credit management endpoints


@router.get("/credits/{agent_did}")
async def get_credits(
    agent_did: str,
    principal: AuthPrincipal = AGENT_AUTH,
):
    """Get credit balance for an agent."""
    authorize_agent(agent_did, principal)
    credits = _agent_credits.get(agent_did, 0)
    return {"agent_did": agent_did, "credits": credits}


@router.post("/credits/{agent_did}/add")
async def add_credits(
    agent_did: str,
    amount: int,
    _principal: AuthPrincipal = ADMIN_AUTH,
):
    """Add credits to an agent's balance."""
    if amount <= 0:
        raise HTTPException(
            status_code=400,
            detail={"error": "INVALID_CREDIT_AMOUNT", "message": "Amount must be positive"},
        )
    current = _agent_credits.get(agent_did, 0)
    _agent_credits[agent_did] = current + amount
    return {"agent_did": agent_did, "credits": _agent_credits[agent_did]}


async def _resolve_success(escrow_id: str, escrow: dict) -> EscrowResolutionResponse:
    """Resolve escrow as success."""
    credits = escrow["credits"]
    provider = escrow["provider_did"]

    # Transfer credits to provider
    _agent_credits[provider] = _agent_credits.get(provider, 0) + credits

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
    _agent_credits[requester] = _agent_credits.get(requester, 0) + credits

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


def get_escrow_parties(escrow_id: str) -> Optional[dict[str, str]]:
    """Return requester/provider DIDs for an escrow."""
    escrow = _escrows.get(escrow_id)
    if escrow is None:
        return None
    return {
        "requester": escrow["requester_did"],
        "provider": escrow["provider_did"],
    }


def get_escrow_credits(escrow_id: str) -> Optional[int]:
    """Return the locked credit amount for an escrow, or ``None`` if unknown."""
    escrow = _escrows.get(escrow_id)
    if escrow is None:
        return None
    return int(escrow.get("credits", 0))


def mark_escrow_disputed(escrow_id: str, reason: str) -> None:
    """Atomically transition an escrow into ``disputed`` for arbiter handling.

    Raises ``HTTPException`` if the escrow does not exist or is in a terminal
    state. This is the only way to lock an escrow against further releases
    while a dispute is being processed.
    """
    escrow = _get_escrow_or_404(escrow_id)
    if escrow["status"] in ("released", "refunded", "split"):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "ESCROW_ALREADY_RESOLVED",
                "message": f"Escrow {escrow_id} is already resolved",
            },
        )
    if escrow["status"] == "disputed":
        # Idempotent: already locked. Preserve the original reason.
        return
    escrow["status"] = "disputed"
    escrow["dispute_reason"] = reason


def disburse_disputed_escrow(
    escrow_id: str,
    *,
    credits_to_requester: int,
    credits_to_provider: int,
    resolution_reason: str,
    resolved_by: str = "arbiter",
) -> None:
    """Distribute locked credits for a disputed escrow and mark it resolved.

    Only callable for escrows that are currently in the ``disputed`` state.
    The caller is responsible for ensuring the split sums to the escrow's
    locked credit total — over- or under-payment is rejected to make
    misuse fail loudly.
    """
    escrow = _get_escrow_or_404(escrow_id)
    if escrow["status"] != "disputed":
        raise HTTPException(
            status_code=400,
            detail={
                "error": "ESCROW_NOT_DISPUTED",
                "message": (
                    f"Escrow {escrow_id} must be in 'disputed' state for arbiter "
                    f"disbursement (current: {escrow['status']})"
                ),
            },
        )
    # Defense-in-depth: even if a regression somewhere allows a terminal escrow
    # to be flipped back to 'disputed', refuse to disburse twice. A prior
    # resolved_at marker indicates credits have already been distributed.
    if escrow.get("resolved_at") is not None:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "ESCROW_ALREADY_DISBURSED",
                "message": (
                    f"Escrow {escrow_id} has already been disbursed and cannot be "
                    "paid out again"
                ),
            },
        )
    if credits_to_requester < 0 or credits_to_provider < 0:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "INVALID_DISBURSEMENT",
                "message": "Disbursement amounts must be non-negative",
            },
        )
    locked = int(escrow.get("credits", 0))
    if credits_to_requester + credits_to_provider != locked:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "DISBURSEMENT_MISMATCH",
                "message": (
                    f"Sum of split ({credits_to_requester + credits_to_provider}) "
                    f"does not match locked credits ({locked})"
                ),
            },
        )

    if credits_to_requester:
        requester = escrow["requester_did"]
        _agent_credits[requester] = _agent_credits.get(requester, 0) + credits_to_requester
    if credits_to_provider:
        provider = escrow["provider_did"]
        _agent_credits[provider] = _agent_credits.get(provider, 0) + credits_to_provider

    if credits_to_provider and not credits_to_requester:
        final_status = "released"
    elif credits_to_requester and not credits_to_provider:
        final_status = "refunded"
    else:
        final_status = "split"

    escrow["status"] = final_status
    escrow["resolved_at"] = datetime.now(timezone.utc).isoformat()
    escrow["resolved_by"] = resolved_by
    escrow["resolution_reason"] = resolution_reason


def _get_escrow_or_404(escrow_id: str) -> dict:
    if escrow_id not in _escrows:
        raise HTTPException(
            status_code=404,
            detail={
                "error": "ESCROW_NOT_FOUND",
                "message": f"Escrow {escrow_id} not found",
            },
        )
    return _escrows[escrow_id]


def _authorize_escrow_participant(escrow: dict, principal: AuthPrincipal) -> None:
    if principal.is_admin:
        return
    if principal.agent_did in (escrow["requester_did"], escrow["provider_did"]):
        return
    # Return 404 (not 403) so an unauthorized caller cannot distinguish
    # "escrow exists but not yours" from "escrow does not exist". This closes
    # the object-existence oracle for escrow IDs.
    raise HTTPException(
        status_code=404,
        detail={
            "error": "ESCROW_NOT_FOUND",
            "message": f"Escrow {escrow['escrow_id']} not found",
        },
    )
