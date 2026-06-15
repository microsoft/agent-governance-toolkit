# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
OpenAPI integration for Engine API capability metadata.

This module provides two functions:

* :func:`inject_capability_extension` walks a FastAPI app's routes, reads the
  :class:`~agentmesh.engine_api.capabilities.CapabilityFlags` attached by the
  :func:`~agentmesh.engine_api.capabilities.capability_flags` decorator, and
  writes them into the generated OpenAPI document as the ``x-capability-flags``
  extension on each operation object. The shape matches
  ``docs/studio/openapi.yaml``.

* :func:`derive_studio_client_allowlist` reads a generated OpenAPI document and
  returns the sorted list of ``operationId`` values whose
  ``x-capability-flags.runtime_mutating`` is ``false``. This is the function the
  Epic 1d CI invariant test calls to machine-derive the read-only Studio client
  allowlist (no hand-maintained route list).

**Hook timing.** :func:`inject_capability_extension` overrides ``app.openapi``
with a wrapper that generates the schema via the app's existing generator and
then injects the extension. It is safe to call once, after all routes are
registered and before serving. The generated schema is cached on
``app.openapi_schema`` by FastAPI, so injection happens on first access.

**Failure mode.** If a route is included in the OpenAPI schema as an operation
but its endpoint carries no attached flags, :func:`inject_capability_extension`
raises :class:`ValueError`. Failing loudly here makes it impossible to ship a
Studio surface with an unknown-flag endpoint.

FastAPI is imported lazily inside :func:`inject_capability_extension` so this
package imposes no hard import-time dependency on FastAPI.
"""

from __future__ import annotations

from typing import Any

from agentmesh.engine_api.capabilities import CAPABILITY_FLAGS_ATTR, CapabilityFlags

#: HTTP methods that correspond to OpenAPI operation objects within a path item.
_OPENAPI_OPERATION_METHODS = frozenset(
    {"get", "put", "post", "delete", "options", "head", "patch", "trace"}
)

#: The OpenAPI extension key under which the three capability flags are emitted.
CAPABILITY_EXTENSION_KEY = "x-capability-flags"


def inject_capability_extension(app: Any) -> None:
    """Wire capability-flag emission into a FastAPI app's OpenAPI generation.

    Overrides ``app.openapi`` so the generated document carries an
    ``x-capability-flags`` object (with ``runtime_mutating``,
    ``user_intent_required``, and ``read_only_surface``) on every operation
    whose endpoint was decorated with
    :func:`~agentmesh.engine_api.capabilities.capability_flags`.

    Args:
        app: A ``fastapi.FastAPI`` instance with its routes already registered.

    Raises:
        ValueError: when the schema is generated and an operation present in the
            OpenAPI document has no attached capability flags.
    """
    from fastapi.routing import APIRoute

    original_openapi = app.openapi

    def openapi_with_capabilities() -> dict[str, Any]:
        schema = original_openapi()
        paths: dict[str, Any] = schema.get("paths", {})

        for route in app.routes:
            if not isinstance(route, APIRoute):
                continue
            if not route.include_in_schema:
                continue

            path_item = paths.get(route.path)
            if path_item is None:
                continue

            flags: CapabilityFlags | None = getattr(route.endpoint, CAPABILITY_FLAGS_ATTR, None)

            for method in route.methods:
                operation = path_item.get(method.lower())
                if operation is None:
                    continue
                if flags is None:
                    raise ValueError(
                        "missing capability flags for operation "
                        f"{method.upper()} {route.path!r} (endpoint "
                        f"{route.endpoint.__name__!r}). Decorate the endpoint "
                        "with @capability_flags(...) before calling "
                        "inject_capability_extension()."
                    )
                operation[CAPABILITY_EXTENSION_KEY] = flags.model_dump()

        app.openapi_schema = schema
        return schema

    app.openapi = openapi_with_capabilities


def derive_studio_client_allowlist(openapi_doc: dict[str, Any]) -> list[str]:
    """Return the sorted read-only Studio client allowlist from an OpenAPI doc.

    Iterates over every operation in the document and keeps the ``operationId``
    of each operation whose ``x-capability-flags.runtime_mutating`` is ``false``.
    By the read-only invariant this is exactly the set of read-only operations.

    Args:
        openapi_doc: A generated OpenAPI document (as produced by
            :func:`inject_capability_extension`).

    Returns:
        ``operationId`` values in deterministic ascending sorted order. An
        operation without an ``x-capability-flags`` object, without an
        ``operationId``, or with ``runtime_mutating: true`` is excluded.
    """
    allowlist: list[str] = []

    paths: dict[str, Any] = openapi_doc.get("paths", {})
    for path_item in paths.values():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in _OPENAPI_OPERATION_METHODS:
                continue
            if not isinstance(operation, dict):
                continue
            flags = operation.get(CAPABILITY_EXTENSION_KEY)
            if not isinstance(flags, dict):
                continue
            operation_id = operation.get("operationId")
            if not operation_id:
                continue
            if flags.get("runtime_mutating") is False:
                allowlist.append(operation_id)

    return sorted(allowlist)
