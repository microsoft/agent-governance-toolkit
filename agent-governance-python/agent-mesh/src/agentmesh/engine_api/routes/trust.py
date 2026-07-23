# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Trust routes (contract sections 7.8, 7.9).

``GET /api/v1/trust/scores`` is paginated; ``GET /api/v1/trust/graph`` returns a single
:class:`~agentmesh.engine_api.models.TrustGraph` object and is NOT paginated. Both are
placeholder surfaces: contract-conformant shape, real backend delivered by a later epic.

A later epic wires both routes to the trust engine (scores from the trust store, graph from
the delegation and sponsorship relationships).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request

from agentmesh.engine_api.capabilities import capability_flags
from agentmesh.engine_api.models import TrustGraph, TrustScoreListResponse
from agentmesh.engine_api.pagination import PaginationParams, paginate

router = APIRouter()

# TODO(#2729): Epic 8 replaces these placeholders with the real trust backends.


@router.get(
    "/api/v1/trust/scores",
    operation_id="getTrustScores",
    tags=["trust"],
    response_model=TrustScoreListResponse,
)
@capability_flags(runtime_mutating=False, user_intent_required=False, read_only_surface=True)
async def get_trust_scores(
    request: Request,
    pagination: PaginationParams = Depends(),
    agent_did: str | None = Query(None, description="Filter by agent DID"),
) -> TrustScoreListResponse:
    """Return per-agent trust scores (empty until the trust backend ships)."""
    items, page = paginate([], pagination)
    return TrustScoreListResponse(items=items, pagination=page)


@router.get(
    "/api/v1/trust/graph",
    operation_id="getTrustGraph",
    tags=["trust"],
    response_model=TrustGraph,
)
@capability_flags(runtime_mutating=False, user_intent_required=False, read_only_surface=True)
async def get_trust_graph(request: Request) -> TrustGraph:
    """Return the trust relationship graph (empty until the trust backend ships)."""
    return TrustGraph(nodes=[], edges=[])
