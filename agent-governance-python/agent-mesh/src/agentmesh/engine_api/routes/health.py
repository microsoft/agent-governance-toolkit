# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""``GET /api/v1/health`` - engine liveness probe (contract section 7.1)."""

from __future__ import annotations

import time

from fastapi import APIRouter, Request

from agentmesh.engine_api.capabilities import capability_flags
from agentmesh.engine_api.models import HealthResponse
from agentmesh.engine_api.routes.versions import engine_version

router = APIRouter()


@router.get(
    "/api/v1/health",
    operation_id="getHealth",
    tags=["health"],
    response_model=HealthResponse,
)
@capability_flags(runtime_mutating=False, user_intent_required=False, read_only_surface=True)
async def get_health(request: Request) -> HealthResponse:
    """Report engine status, version, and uptime."""
    start = getattr(request.app.state, "start_time", None)
    uptime = max(0.0, time.monotonic() - start) if start is not None else 0.0
    return HealthResponse(status="ok", version=engine_version(), uptime_seconds=uptime)
