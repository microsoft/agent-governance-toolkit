# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Audit Collector Server

Captures and stores agent interaction audit logs with Merkle integrity.
Wraps agentmesh.services.audit.AuditService and agentmesh.governance.audit_backends.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Optional

from pydantic import BaseModel, Field

from agentmesh.governance.audit import AuditEntry
from agentmesh.services.audit import AuditService
from agentmesh.governance.audit_backends import FileAuditSink
from agentmesh.server import create_base_app, run_server

logger = logging.getLogger(__name__)

app = create_base_app(
    "audit-collector",
    "Captures and stores agent interaction audit logs with Merkle integrity.",
)

AUDIT_DATA_DIR = os.getenv("AGENTMESH_AUDIT_DATA_DIR", "/data/audit")
RETENTION_DAYS = int(os.getenv("AGENTMESH_AUDIT_RETENTION_DAYS", "90"))

# Service instance
_audit_service = AuditService()
_file_sink: Optional[FileAuditSink] = None


@app.on_event("startup")
async def startup() -> None:
    global _file_sink
    data_path = Path(AUDIT_DATA_DIR)
    if data_path.exists() or data_path.parent.exists():
        data_path.mkdir(parents=True, exist_ok=True)
        _file_sink = FileAuditSink(audit_dir=data_path)
        logger.info("Audit persistence enabled at %s (retention: %d days)", data_path, RETENTION_DAYS)
    else:
        logger.warning("Audit data dir %s not available — running in-memory only", AUDIT_DATA_DIR)


# ── Request / Response models ────────────────────────────────────────


class LogEntryRequest(BaseModel):
    event_type: str = Field(..., description="Type of event (agent_action, policy_decision, etc.)")
    agent_did: str = Field(..., description="DID of the acting agent")
    action: str = Field(..., description="Action performed")
    resource: Optional[str] = None
    target_did: Optional[str] = None
    data: dict[str, Any] = Field(default_factory=dict)
    outcome: str = Field(default="success")
    policy_decision: Optional[str] = None
    trace_id: Optional[str] = None


class LogEntryResponse(BaseModel):
    entry_id: str
    entry_hash: str
    timestamp: str


class BatchLogRequest(BaseModel):
    entries: list[LogEntryRequest]


class QueryParams(BaseModel):
    agent_did: Optional[str] = None
    event_type: Optional[str] = None
    limit: int = Field(default=100, ge=1, le=1000)


# ── Endpoints ────────────────────────────────────────────────────────


@app.post("/api/v1/audit/log", tags=["audit"], response_model=LogEntryResponse)
async def log_entry(req: LogEntryRequest) -> LogEntryResponse:
    """Log a single audit entry."""
    entry = _audit_service.log_action(
        agent_did=req.agent_did,
        action=req.action,
        outcome=req.outcome,
        resource=req.resource,
        data=req.data,
        trace_id=req.trace_id,
    )

    if _file_sink is not None:
        _file_sink.write(entry)

    return LogEntryResponse(
        entry_id=entry.entry_id,
        entry_hash=entry.entry_hash,
        timestamp=entry.timestamp.isoformat(),
    )


@app.post("/api/v1/audit/batch", tags=["audit"])
async def log_batch(req: BatchLogRequest) -> dict[str, Any]:
    """Log a batch of audit entries."""
    results = []
    entries_for_sink = []

    for item in req.entries:
        entry = _audit_service.log_action(
            agent_did=item.agent_did,
            action=item.action,
            outcome=item.outcome,
            resource=item.resource,
            data=item.data,
            trace_id=item.trace_id,
        )
        entries_for_sink.append(entry)
        results.append({"entry_id": entry.entry_id, "entry_hash": entry.entry_hash})

    if _file_sink is not None and entries_for_sink:
        _file_sink.write_batch(entries_for_sink)

    return {"logged": len(results), "entries": results}


@app.post("/api/v1/audit/query", tags=["audit"])
async def query_entries(params: QueryParams) -> dict[str, Any]:
    """Query audit entries by agent DID or event type."""
    if params.agent_did:
        entries = _audit_service.query_by_agent(params.agent_did)
    elif params.event_type:
        entries = _audit_service.query_by_type(params.event_type)
    else:
        entries = _audit_service.query_by_agent("")  # returns empty for unknown

    limited = entries[: params.limit]
    return {
        "total": len(entries),
        "returned": len(limited),
        "entries": [e.model_dump(mode="json") for e in limited],
    }


@app.get("/api/v1/audit/verify", tags=["audit"])
async def verify_integrity() -> dict[str, Any]:
    """Verify Merkle chain integrity of the audit log."""
    valid = _audit_service.verify_chain()
    return {"chain_valid": valid, "entry_count": _audit_service.entry_count}


@app.get("/api/v1/audit/summary", tags=["audit"])
async def audit_summary() -> dict[str, Any]:
    """Get audit service statistics."""
    summary = _audit_service.summary()
    summary["retention_days"] = RETENTION_DAYS
    summary["persistence_enabled"] = _file_sink is not None
    return summary


def main() -> None:
    run_server(app, default_port=8445)


if __name__ == "__main__":
    main()
