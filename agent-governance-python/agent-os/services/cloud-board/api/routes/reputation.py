# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Reputation Routes

API endpoints for reputation management and trust scoring.
"""

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel
from typing import Optional, Literal
from datetime import datetime, timezone

router = APIRouter()


class ReportOutcomeRequest(BaseModel):
    task_id: str
    reporter_did: str
    outcome: Literal["success", "failure", "partial"]
    duration_ms: Optional[int] = None
    output_hash: Optional[str] = None


class TrustScoreResponse(BaseModel):
    agent_did: str
    total_score: int
    tier: str
    base_score: int
    behavioral_modifier: int
    capability_modifier: int
    successful_tasks: int
    failed_tasks: int
    disputes_won: int
    disputes_lost: int
    calculated_at: str


class SlashRequest(BaseModel):
    reason: Literal["hallucination", "policy_violation", "mute_triggered", "dispute_lost", "timeout", "fraud"]
    severity: Literal["critical", "high", "medium", "low"]
    evidence_hash: Optional[str] = None
    trace_id: Optional[str] = None
    broadcast: bool = True


class SlashResponse(BaseModel):
    agent_did: str
    slash_id: str
    reason: str
    severity: str
    score_before: int
    score_reduction: int
    score_after: int
    broadcast_to_network: bool


class LeaderboardEntry(BaseModel):
    rank: int
    agent_did: str
    trust_score: int
    tier: str
    successful_tasks: int


# In-memory storage
_reputation_history: dict[str, dict] = {}
_slash_events: list[dict] = []


@router.get("/{agent_did}", response_model=TrustScoreResponse)
async def get_reputation(agent_did: str):
    """Get detailed reputation for an agent."""
    history = _reputation_history.get(agent_did, {
        "successful_tasks": 0,
        "failed_tasks": 0,
        "disputes_won": 0,
        "disputes_lost": 0,
        "times_slashed": 0,
    })
    
    # Calculate score
    base_score = 400  # Would check verification level
    
    behavioral = 0
    behavioral += history.get("successful_tasks", 0) * 2
    behavioral -= history.get("failed_tasks", 0) * 10
    behavioral -= history.get("disputes_lost", 0) * 50
    behavioral += history.get("disputes_won", 0) * 10
    behavioral -= history.get("times_slashed", 0) * 75
    behavioral = max(-300, min(300, behavioral))
    
    capability = 50  # Would calculate from manifest
    
    total = max(0, min(1000, base_score + behavioral + capability))
    
    return TrustScoreResponse(
        agent_did=agent_did,
        total_score=total,
        tier=_get_tier(total),
        base_score=base_score,
        behavioral_modifier=behavioral,
        capability_modifier=capability,
        successful_tasks=history.get("successful_tasks", 0),
        failed_tasks=history.get("failed_tasks", 0),
        disputes_won=history.get("disputes_won", 0),
        disputes_lost=history.get("disputes_lost", 0),
        calculated_at=datetime.now(timezone.utc).isoformat(),
    )


@router.post("/{agent_did}/report")
async def report_outcome(agent_did: str, request: ReportOutcomeRequest):
    """Report a task outcome to update reputation."""
    if agent_did not in _reputation_history:
        _reputation_history[agent_did] = {
            "successful_tasks": 0,
            "failed_tasks": 0,
            "disputes_won": 0,
            "disputes_lost": 0,
            "times_slashed": 0,
            "total_tasks": 0,
        }
    
    history = _reputation_history[agent_did]
    history["total_tasks"] = history.get("total_tasks", 0) + 1
    
    if request.outcome == "success":
        history["successful_tasks"] += 1
    elif request.outcome == "failure":
        history["failed_tasks"] += 1
    else:  # partial
        history["successful_tasks"] += 0.5
        history["failed_tasks"] += 0.5
    
    return {
        "success": True,
        "agent_did": agent_did,
        "outcome_recorded": request.outcome,
        "new_task_count": history["total_tasks"],
    }


@router.post("/{agent_did}/slash", response_model=SlashResponse)
async def slash_reputation(agent_did: str, request: SlashRequest):
    """
    Slash an agent's reputation for misbehavior.
    
    When triggered, can broadcast to the network so all agents
    immediately block the offending agent.
    """
    # Get current score
    history = _reputation_history.get(agent_did, {"times_slashed": 0})
    
    # Calculate score before
    base = 400
    behavioral = (
        history.get("successful_tasks", 0) * 2 -
        history.get("failed_tasks", 0) * 10 -
        history.get("disputes_lost", 0) * 50 -
        history.get("times_slashed", 0) * 75
    )
    score_before = max(0, min(1000, base + behavioral + 50))
    
    # Calculate reduction
    penalties = {
        "critical": 200,
        "high": 100,
        "medium": 50,
        "low": 25,
    }
    reduction = penalties[request.severity]
    score_after = max(0, score_before - reduction)
    
    # Update history
    if agent_did not in _reputation_history:
        _reputation_history[agent_did] = {"times_slashed": 0}
    _reputation_history[agent_did]["times_slashed"] = (
        _reputation_history[agent_did].get("times_slashed", 0) + 1
    )
    
    # Create slash event
    slash_id = f"slash_{agent_did}_{datetime.now(timezone.utc).timestamp()}"
    slash_event = {
        "slash_id": slash_id,
        "agent_did": agent_did,
        "reason": request.reason,
        "severity": request.severity,
        "score_before": score_before,
        "score_reduction": reduction,
        "score_after": score_after,
        "evidence_hash": request.evidence_hash,
        "trace_id": request.trace_id,
        "broadcast": request.broadcast,
        "occurred_at": datetime.now(timezone.utc).isoformat(),
    }
    _slash_events.append(slash_event)
    
    return SlashResponse(
        agent_did=agent_did,
        slash_id=slash_id,
        reason=request.reason,
        severity=request.severity,
        score_before=score_before,
        score_reduction=reduction,
        score_after=score_after,
        broadcast_to_network=request.broadcast,
    )


@router.get("/sync")
async def sync_reputation(
    agent_dids: Optional[str] = Query(default=None),
):
    """
    Get reputation scores for syncing to local cache.
    
    Used by NexusClient.sync_reputation()
    """
    scores = {}
    
    # If specific DIDs requested
    if agent_dids:
        dids = agent_dids.split(",")
        for did in dids:
            history = _reputation_history.get(did, {})
            scores[did] = _calculate_score(history)
    else:
        # Return all known agents
        for did, history in _reputation_history.items():
            scores[did] = _calculate_score(history)
    
    return {"scores": scores, "synced_at": datetime.now(timezone.utc).isoformat()}


@router.get("/leaderboard", response_model=list[LeaderboardEntry])
async def get_leaderboard(
    limit: int = Query(default=100, ge=1, le=1000),
):
    """Get top agents by trust score."""
    entries = []
    
    for did, history in _reputation_history.items():
        score = _calculate_score(history)
        entries.append({
            "agent_did": did,
            "trust_score": score,
            "successful_tasks": history.get("successful_tasks", 0),
        })
    
    # Sort by score
    entries.sort(key=lambda e: e["trust_score"], reverse=True)
    
    # Add rank and tier
    results = []
    for i, entry in enumerate(entries[:limit]):
        results.append(LeaderboardEntry(
            rank=i + 1,
            agent_did=entry["agent_did"],
            trust_score=entry["trust_score"],
            tier=_get_tier(entry["trust_score"]),
            successful_tasks=entry["successful_tasks"],
        ))
    
    return results


@router.get("/slashes")
async def get_slash_history(
    agent_did: Optional[str] = Query(default=None),
    since: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=1000),
):
    """Get slash event history."""
    events = _slash_events
    
    if agent_did:
        events = [e for e in events if e["agent_did"] == agent_did]
    
    if since:
        events = [e for e in events if e["occurred_at"] >= since]
    
    return {"events": events[:limit], "total": len(events)}


def _calculate_score(history: dict) -> int:
    """Calculate trust score from history."""
    base = 400
    behavioral = (
        history.get("successful_tasks", 0) * 2 -
        history.get("failed_tasks", 0) * 10 -
        history.get("disputes_lost", 0) * 50 -
        history.get("times_slashed", 0) * 75
    )
    behavioral = max(-300, min(300, behavioral))
    return max(0, min(1000, base + behavioral + 50))


def _get_tier(score: int) -> str:
    """Get trust tier from score."""
    if score >= 900:
        return "verified_partner"
    elif score >= 700:
        return "trusted"
    elif score >= 500:
        return "standard"
    elif score >= 300:
        return "probationary"
    else:
        return "untrusted"
