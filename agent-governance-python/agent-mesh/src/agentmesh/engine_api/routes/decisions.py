# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""``GET /api/v1/decisions`` - recent policy decisions (contract section 7.11).

Placeholder surface: contract-conformant shape, real backend delivered by a later epic.

A later epic wires this to the decision log to return persisted
:class:`~agentmesh.engine_api.models.Decision` records.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request

from agentmesh.engine_api.capabilities import capability_flags
from agentmesh.engine_api.models import DecisionListResponse, Verdict
from agentmesh.engine_api.pagination import PaginationParams, paginate

router = APIRouter()

# Tracked by #2729, Epic 7: replace this placeholder with the real decision log backend.


@router.get(
    "/api/v1/decisions",
    operation_id="listDecisions",
    tags=["decisions"],
    response_model=DecisionListResponse,
)
@capability_flags(runtime_mutating=False, user_intent_required=False, read_only_surface=True)
async def list_decisions(
    request: Request,
    pagination: PaginationParams = Depends(),
    agent_did: str | None = Query(None, description="Filter by agent DID"),
    verdict: Verdict | None = Query(None, description="Filter by decision verdict"),
) -> DecisionListResponse:
    """Return recent policy decisions (empty until the decision log ships)."""
    items, page = paginate([], pagination)
    return DecisionListResponse(items=items, pagination=page)
