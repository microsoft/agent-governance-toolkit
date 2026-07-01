# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""``GET /api/v1/agents`` - registered agents (contract section 7.10).

Placeholder surface: contract-conformant shape, real backend delivered by a later epic.

A later epic wires this to the agent registry to return persisted
:class:`~agentmesh.engine_api.models.AgentSummary` records.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from agentmesh.engine_api.capabilities import capability_flags
from agentmesh.engine_api.models import AgentListResponse
from agentmesh.engine_api.pagination import PaginationParams, paginate

router = APIRouter()


@router.get(
    "/api/v1/agents",
    operation_id="listAgents",
    tags=["agents"],
    response_model=AgentListResponse,
)
@capability_flags(runtime_mutating=False, user_intent_required=False, read_only_surface=True)
async def list_agents(
    request: Request,
    pagination: PaginationParams = Depends(),
) -> AgentListResponse:
    """Return registered agents (empty until the agent registry ships)."""
    items, page = paginate([], pagination)
    return AgentListResponse(items=items, pagination=page)
