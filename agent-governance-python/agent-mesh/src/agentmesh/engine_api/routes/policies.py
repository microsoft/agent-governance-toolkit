# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Policy read routes (contract sections 7.2, 7.3).

``GET /api/v1/policies`` returns a paginated list of :class:`PolicySummary` objects. This is
the fix for the counts-only gap in ``agentmesh.server.policy_server`` (which returns only
totals). ``GET /api/v1/policies/{id}`` returns full :class:`PolicyDetail` or a
``POLICY_NOT_FOUND`` envelope.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request

from agentmesh.engine_api.capabilities import capability_flags
from agentmesh.engine_api.errors import POLICY_NOT_FOUND, ApiError
from agentmesh.engine_api.models import PolicyDetail, PolicyListResponse
from agentmesh.engine_api.pagination import PaginationParams, paginate
from agentmesh.engine_api.policy_registry import PolicyRegistry

router = APIRouter()


def _registry(request: Request) -> PolicyRegistry:
    return request.app.state.policy_registry


@router.get(
    "/api/v1/policies",
    operation_id="listPolicies",
    tags=["policy"],
    response_model=PolicyListResponse,
)
@capability_flags(runtime_mutating=False, user_intent_required=False, read_only_surface=True)
async def list_policies(
    request: Request,
    pagination: PaginationParams = Depends(),
) -> PolicyListResponse:
    """List all policies currently loaded in the engine, paginated."""
    summaries = _registry(request).list_summaries()
    page_items, page = paginate(summaries, pagination)
    return PolicyListResponse(items=page_items, pagination=page)


@router.get(
    "/api/v1/policies/{id}",
    operation_id="getPolicy",
    tags=["policy"],
    response_model=PolicyDetail,
)
@capability_flags(runtime_mutating=False, user_intent_required=False, read_only_surface=True)
async def get_policy(request: Request, id: str) -> PolicyDetail:
    """Retrieve full detail for a single policy, or 404 if it does not exist."""
    detail = _registry(request).get_detail(id)
    if detail is None:
        raise ApiError(
            404,
            POLICY_NOT_FOUND,
            f"Policy with id '{id}' not found",
            {"id": id},
        )
    return detail
