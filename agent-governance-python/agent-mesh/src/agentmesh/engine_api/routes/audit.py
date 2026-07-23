# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""``GET /api/v1/audit/log`` - tamper-evident audit log (contract section 7.7).

Placeholder surface: the route, its capability flags, pagination, and query parameters are
contract-conformant, but the audit backend is delivered by a later epic. Until then the
endpoint returns an empty, well-formed paginated payload rather than fabricated entries.

A later epic wires this to the real audit store to return persisted
:class:`~agentmesh.engine_api.models.AuditLogEntry` records.
"""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query, Request

from agentmesh.engine_api.capabilities import capability_flags
from agentmesh.engine_api.models import AuditLogResponse
from agentmesh.engine_api.pagination import PaginationParams, paginate

router = APIRouter()

# TODO(#2729): Epic 9 replaces this placeholder with the real audit backend.


@router.get(
    "/api/v1/audit/log",
    operation_id="getAuditLog",
    tags=["audit"],
    response_model=AuditLogResponse,
)
@capability_flags(runtime_mutating=False, user_intent_required=False, read_only_surface=True)
async def get_audit_log(
    request: Request,
    pagination: PaginationParams = Depends(),
    agent_did: str | None = Query(None, description="Filter by acting agent DID"),
    from_: datetime | None = Query(
        None, alias="from", description="Start of time range (date-time)"
    ),
    to: datetime | None = Query(None, description="End of time range (date-time)"),
) -> AuditLogResponse:
    """Return audit log entries (empty until the audit backend ships)."""
    items, page = paginate([], pagination)
    return AuditLogResponse(items=items, pagination=page)
