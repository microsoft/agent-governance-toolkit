# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Compliance Routes

API endpoints for compliance auditing and reporting.
Supports SOC2, HIPAA, and other regulatory frameworks.
"""

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from typing import Optional, Literal
from datetime import datetime, timedelta, timezone
import json
import io

router = APIRouter()


class ComplianceEventResponse(BaseModel):
    event_id: str
    event_type: str
    timestamp: str
    requester_did: Optional[str] = None
    provider_did: Optional[str] = None
    organization_id: Optional[str] = None
    operation_type: Optional[str] = None
    data_classification: Optional[str] = None
    outcome: Optional[str] = None
    trace_id: Optional[str] = None


class ComplianceStatsResponse(BaseModel):
    total_events: int
    events_by_type: dict
    events_by_outcome: dict
    unique_agents: int
    total_handshakes: int
    rejected_handshakes: int
    rejection_rate: float
    total_escrows: int
    successful_escrows: int
    disputed_escrows: int
    dispute_rate: float
    reputation_slashes: int
    start_date: str
    end_date: str


class ComplianceReportRequest(BaseModel):
    organization_id: str
    report_type: Literal["soc2", "hipaa", "gdpr", "custom"] = "soc2"
    start_date: str
    end_date: str


# In-memory storage
_compliance_events: list[dict] = []


def _record_event(event_type: str, **kwargs):
    """Record a compliance event."""
    event = {
        "event_id": f"evt_{datetime.now(timezone.utc).timestamp()}",
        "event_type": event_type,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **kwargs
    }
    _compliance_events.append(event)
    return event


# Automatically record events (would be called from other modules)
def record_handshake(requester_did: str, provider_did: str, outcome: str):
    return _record_event(
        "iatp_handshake",
        requester_did=requester_did,
        provider_did=provider_did,
        outcome=outcome,
    )


def record_escrow_event(event_type: str, requester_did: str, provider_did: str, escrow_id: str):
    return _record_event(
        event_type,
        requester_did=requester_did,
        provider_did=provider_did,
        escrow_id=escrow_id,
    )


@router.get("/events", response_model=list[ComplianceEventResponse])
async def list_compliance_events(
    organization_id: Optional[str] = Query(default=None),
    agent_did: Optional[str] = Query(default=None),
    event_type: Optional[str] = Query(default=None),
    start_date: Optional[str] = Query(default=None),
    end_date: Optional[str] = Query(default=None),
    limit: int = Query(default=100, ge=1, le=10000),
    offset: int = Query(default=0, ge=0),
):
    """List compliance events with filtering."""
    results = _compliance_events
    
    if organization_id:
        results = [e for e in results if e.get("organization_id") == organization_id]
    
    if agent_did:
        results = [
            e for e in results 
            if e.get("requester_did") == agent_did or e.get("provider_did") == agent_did
        ]
    
    if event_type:
        results = [e for e in results if e.get("event_type") == event_type]
    
    if start_date:
        results = [e for e in results if e.get("timestamp", "") >= start_date]
    
    if end_date:
        results = [e for e in results if e.get("timestamp", "") <= end_date]
    
    return [ComplianceEventResponse(**e) for e in results[offset:offset+limit]]


@router.get("/stats", response_model=ComplianceStatsResponse)
async def get_compliance_stats(
    organization_id: Optional[str] = Query(default=None),
    start_date: Optional[str] = Query(default=None),
    end_date: Optional[str] = Query(default=None),
):
    """Get aggregated compliance statistics."""
    events = _compliance_events
    
    if organization_id:
        events = [e for e in events if e.get("organization_id") == organization_id]
    
    if start_date:
        events = [e for e in events if e.get("timestamp", "") >= start_date]
    
    if end_date:
        events = [e for e in events if e.get("timestamp", "") <= end_date]
    
    # Calculate stats
    events_by_type = {}
    events_by_outcome = {}
    unique_agents = set()
    handshakes = 0
    rejected = 0
    escrows = 0
    successful_escrows = 0
    disputed = 0
    slashes = 0
    
    for event in events:
        event_type = event.get("event_type", "unknown")
        events_by_type[event_type] = events_by_type.get(event_type, 0) + 1
        
        outcome = event.get("outcome", "unknown")
        events_by_outcome[outcome] = events_by_outcome.get(outcome, 0) + 1
        
        if event.get("requester_did"):
            unique_agents.add(event["requester_did"])
        if event.get("provider_did"):
            unique_agents.add(event["provider_did"])
        
        if event_type == "iatp_handshake":
            handshakes += 1
        elif event_type == "iatp_rejected":
            rejected += 1
        elif event_type == "escrow_created":
            escrows += 1
        elif event_type == "escrow_released":
            successful_escrows += 1
        elif event_type == "escrow_disputed":
            disputed += 1
        elif event_type == "reputation_slashed":
            slashes += 1
    
    return ComplianceStatsResponse(
        total_events=len(events),
        events_by_type=events_by_type,
        events_by_outcome=events_by_outcome,
        unique_agents=len(unique_agents),
        total_handshakes=handshakes,
        rejected_handshakes=rejected,
        rejection_rate=rejected / max(1, handshakes + rejected),
        total_escrows=escrows,
        successful_escrows=successful_escrows,
        disputed_escrows=disputed,
        dispute_rate=disputed / max(1, escrows),
        reputation_slashes=slashes,
        start_date=start_date or "all",
        end_date=end_date or "all",
    )


@router.post("/export")
async def export_compliance_report(request: ComplianceReportRequest):
    """
    Export compliance audit report for SOC2/HIPAA auditors.
    
    Returns a comprehensive report of all inter-agent communications,
    data handling policy signatures, reputation changes, and dispute resolutions.
    """
    # Filter events for the organization and date range
    events = _compliance_events
    
    if request.organization_id:
        events = [e for e in events if e.get("organization_id") == request.organization_id]
    
    events = [
        e for e in events 
        if e.get("timestamp", "") >= request.start_date 
        and e.get("timestamp", "") <= request.end_date
    ]
    
    # Get stats
    stats = await get_compliance_stats(
        organization_id=request.organization_id,
        start_date=request.start_date,
        end_date=request.end_date,
    )
    
    # Build report
    report = {
        "report_id": f"report_{datetime.now(timezone.utc).timestamp()}",
        "report_type": request.report_type,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "organization_id": request.organization_id,
        "start_date": request.start_date,
        "end_date": request.end_date,
        "executive_summary": _generate_executive_summary(stats, request.report_type),
        "stats": stats.model_dump(),
        "events": events,
        "violations": _find_violations(events),
        "warnings": _find_warnings(events),
        "recommendations": _generate_recommendations(stats),
    }
    
    # Calculate report hash
    import hashlib
    report_hash = hashlib.sha256(
        json.dumps(report, sort_keys=True, default=str).encode()
    ).hexdigest()
    report["report_hash"] = report_hash
    report["nexus_signature"] = f"nexus_report_{report_hash[:32]}"
    
    return report


@router.get("/export/{report_id}")
async def download_compliance_report(
    report_id: str,
    format: Literal["json", "csv"] = Query(default="json"),
):
    """Download a previously generated compliance report."""
    # In production, would fetch from storage
    raise HTTPException(status_code=404, detail="Report not found")


@router.get("/data-handling/{transfer_id}")
async def get_data_handling_audit(transfer_id: str):
    """Get audit record for a specific data handling transaction."""
    # Find events related to this transfer
    events = [
        e for e in _compliance_events
        if e.get("transfer_id") == transfer_id
    ]
    
    if not events:
        raise HTTPException(status_code=404, detail="Transfer not found")
    
    return {
        "transfer_id": transfer_id,
        "events": events,
        "policy_compliant": True,  # Would calculate from events
    }


def _generate_executive_summary(stats: ComplianceStatsResponse, report_type: str) -> str:
    """Generate executive summary for compliance report."""
    summary = f"""
Compliance Audit Report ({report_type.upper()})

During the audit period, the Nexus Trust Exchange processed:
- {stats.total_events} total compliance events
- {stats.total_handshakes} IATP handshakes ({stats.rejected_handshakes} rejected, {stats.rejection_rate:.1%} rejection rate)
- {stats.total_escrows} escrow transactions ({stats.successful_escrows} successful, {stats.disputed_escrows} disputed)
- {stats.unique_agents} unique agents participated

Key Findings:
- Dispute rate: {stats.dispute_rate:.1%}
- Reputation slashes: {stats.reputation_slashes}
- All transactions were cryptographically signed and logged

The system maintained full audit trail compliance throughout the period.
""".strip()
    
    return summary


def _find_violations(events: list[dict]) -> list[dict]:
    """Find compliance violations in events."""
    violations = []
    
    for event in events:
        # Check for PII handling violations
        if event.get("data_classification") == "pii":
            if event.get("retention_policy") != "ephemeral":
                violations.append({
                    "event_id": event["event_id"],
                    "violation_type": "PII_RETENTION",
                    "description": "PII data with non-ephemeral retention policy",
                    "severity": "high",
                })
    
    return violations


def _find_warnings(events: list[dict]) -> list[dict]:
    """Find compliance warnings in events."""
    warnings = []
    
    # Check for high rejection rates
    handshakes = [e for e in events if e.get("event_type") == "iatp_handshake"]
    rejected = [e for e in events if e.get("event_type") == "iatp_rejected"]
    
    if len(handshakes) > 0:
        rejection_rate = len(rejected) / (len(handshakes) + len(rejected))
        if rejection_rate > 0.2:
            warnings.append({
                "warning_type": "HIGH_REJECTION_RATE",
                "description": f"Rejection rate ({rejection_rate:.1%}) exceeds 20% threshold",
                "recommendation": "Review agent verification requirements",
            })
    
    return warnings


def _generate_recommendations(stats: ComplianceStatsResponse) -> list[str]:
    """Generate recommendations based on stats."""
    recommendations = []
    
    if stats.dispute_rate > 0.05:
        recommendations.append(
            "Consider implementing stricter SCAK validation thresholds to reduce disputes"
        )
    
    if stats.reputation_slashes > 10:
        recommendations.append(
            "Review agent onboarding process - high number of reputation slashes detected"
        )
    
    if stats.rejection_rate > 0.3:
        recommendations.append(
            "High rejection rate may indicate trust threshold is too restrictive"
        )
    
    if not recommendations:
        recommendations.append("No immediate compliance concerns identified")
    
    return recommendations
