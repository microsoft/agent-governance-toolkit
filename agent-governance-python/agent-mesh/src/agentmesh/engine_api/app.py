# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Application factory for the Engine API reference adapter.

:func:`create_app` assembles a single :class:`fastapi.FastAPI` instance that exposes every
v1 Engine API route (contract section 7), each decorated with capability flags, wires the
section 10 error envelope, and applies :func:`inject_capability_extension` last so the
generated OpenAPI carries ``x-capability-flags`` on every operation.

This is the canonical reference adapter referenced by ``docs/studio/engine-api-contract.md``.
It is intentionally self-contained: one app, one process, one OpenAPI document.
"""

from __future__ import annotations

import os
import time

from fastapi import APIRouter, FastAPI

from agentmesh.engine_api.errors import register_error_handlers
from agentmesh.engine_api.openapi import inject_capability_extension
from agentmesh.engine_api.policy_registry import PolicyRegistry
from agentmesh.engine_api.routes import (
    agents,
    audit,
    decisions,
    health,
    policies,
    policy_ops,
    trust,
    versions,
)
from agentmesh.engine_api.routes.versions import API_VERSION

#: Environment variable consulted for the policy directory when no override is passed.
POLICY_DIR_ENV = "AGENTMESH_POLICY_DIR"

#: Default policy directory used when neither the argument nor the env var is set.
DEFAULT_POLICY_DIR = "/etc/agentmesh/policies"

#: Environment variable that enables the single write endpoint (``POST /api/v1/policy/save``).
#: Defaults off so the reference adapter never accepts an unauthenticated policy mutation out of
#: the box; a deployment opts in once it has placed its own auth in front of the engine.
POLICY_SAVE_ENV = "AGENTMESH_ENABLE_POLICY_SAVE"

#: Values (case-insensitive) that count as "on" for a boolean environment flag.
_TRUTHY_ENV_VALUES = frozenset({"1", "true", "yes", "on"})


def _env_truthy(name: str) -> bool:
    """Return ``True`` when environment variable ``name`` is set to a truthy value."""
    return os.getenv(name, "").strip().lower() in _TRUTHY_ENV_VALUES

#: Route modules included by the app, in contract order.
_ROUTE_MODULES = (
    health,
    policies,
    policy_ops,
    audit,
    trust,
    agents,
    decisions,
    versions,
)


def _register_routes_flat(app: FastAPI, router: APIRouter) -> None:
    """Register a router's routes directly onto ``app`` at the top level.

    FastAPI 0.118+/Starlette 1.x changed :meth:`FastAPI.include_router` so it
    appends a single ``_IncludedRouter`` proxy to ``app.router.routes`` instead
    of flattening the sub-router's :class:`~fastapi.routing.APIRoute` objects
    into the app's route list. :func:`inject_capability_extension` iterates
    ``app.routes`` looking for top-level ``APIRoute`` instances, so routes hidden
    behind that proxy never receive their ``x-capability-flags`` extension (and,
    worse, the loop cannot tell they are missing). Appending each ``APIRoute``
    directly keeps every operation visible to the capability hook across all
    supported FastAPI versions. The route modules use plain, prefix-free routers
    with absolute ``/api/v1`` paths and per-route tags, so direct registration is
    equivalent to ``include_router`` here.
    """
    # Tied to the ``fastapi>=0.137.1,<1.0`` pin in this package's pyproject.toml, which keeps
    # the 0.118+/Starlette 1.x proxy behavior described above; revisit if that pin changes.
    app.router.routes.extend(router.routes)


def create_app(policy_dir: str | None = None, enable_policy_save: bool | None = None) -> FastAPI:
    """Build and return the Engine API FastAPI application.

    Args:
        policy_dir: Directory of policy files backing ``/policies`` and ``/policy/save``.
            Falls back to the ``AGENTMESH_POLICY_DIR`` environment variable, then to
            :data:`DEFAULT_POLICY_DIR`. The directory need not exist at startup.
        enable_policy_save: Whether the single write endpoint ``POST /api/v1/policy/save``
            accepts writes. Defaults to ``None``, which falls back to the
            ``AGENTMESH_ENABLE_POLICY_SAVE`` environment variable (off unless set truthy).
            While disabled, ``savePolicy`` returns ``403 FORBIDDEN`` and nothing is written,
            so the reference adapter never accepts an unauthenticated policy mutation out of
            the box. A deployment turns it on once it fronts the engine with its own auth.

    Returns:
        A fully wired :class:`fastapi.FastAPI` instance. The capability-extension OpenAPI
        hook is applied last, so accessing ``app.openapi()`` raises ``ValueError`` if any
        in-schema operation is missing capability flags.
    """
    resolved_dir = policy_dir or os.getenv(POLICY_DIR_ENV, DEFAULT_POLICY_DIR)
    if enable_policy_save is None:
        save_enabled = _env_truthy(POLICY_SAVE_ENV)
    else:
        save_enabled = bool(enable_policy_save)

    app = FastAPI(
        title="AGT Studio Engine API",
        version=API_VERSION,
        description="Reference FastAPI adapter for the AGT Studio Engine API contract.",
    )

    app.state.start_time = time.monotonic()
    app.state.policy_registry = PolicyRegistry(resolved_dir)
    app.state.policy_save_enabled = save_enabled

    register_error_handlers(app)

    for module in _ROUTE_MODULES:
        _register_routes_flat(app, module.router)

    # Must run after every router is registered: it validates that every in-schema
    # operation carries capability flags and injects the x-capability-flags extension.
    inject_capability_extension(app)

    return app
