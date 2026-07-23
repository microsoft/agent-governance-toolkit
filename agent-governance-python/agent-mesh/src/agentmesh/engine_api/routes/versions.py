# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""``GET /api/v1/versions`` - engine and API contract versions (contract section 7.12)."""

from __future__ import annotations

import platform
from typing import Final

from fastapi import APIRouter

from agentmesh.engine_api.capabilities import capability_flags
from agentmesh.engine_api.models import VersionsResponse

#: The API contract version this adapter implements (contract section 9, rule 9).
API_VERSION: Final = "1.0.0"

#: Distribution name to resolve the engine version from package metadata.
_ENGINE_DISTRIBUTION: Final = "agentmesh-platform"
#: Capability identifiers advertised via ``GET /api/v1/versions`` (contract section 5.1).
ENGINE_CAPABILITIES: Final[list[str]] = [
    "agents",
    "audit_log",
    "decisions",
    "policies",
    "policy_save",
    "policy_test",
    "policy_validate",
    "trust_graph",
    "trust_scores",
]

router = APIRouter()


def engine_version() -> str:
    """Resolve the engine software version.

    Prefers installed package metadata (``importlib.metadata``); falls back to the
    in-tree ``agentmesh.__version__`` when the distribution is not installed.
    """
    try:
        from importlib.metadata import PackageNotFoundError, version

        try:
            return version(_ENGINE_DISTRIBUTION)
        except PackageNotFoundError:
            pass
    except Exception:  # pragma: no cover - importlib.metadata always present on 3.11
        pass

    try:
        import agentmesh

        return getattr(agentmesh, "__version__", "0.0.0")
    except Exception:  # pragma: no cover - agentmesh is the parent package
        return "0.0.0"


@router.get(
    "/api/v1/versions",
    operation_id="getVersions",
    tags=["versions"],
    response_model=VersionsResponse,
)
@capability_flags(runtime_mutating=False, user_intent_required=False, read_only_surface=True)
async def get_versions() -> VersionsResponse:
    """Report engine software version and API contract version."""
    return VersionsResponse(
        engine=engine_version(),
        api=API_VERSION,
        python=platform.python_version(),
        capabilities=list(ENGINE_CAPABILITIES),
    )
