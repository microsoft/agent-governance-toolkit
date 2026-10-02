# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
OpenAPI integration for Engine API metadata.

This module provides the OpenAPI integration functions:

* :func:`inject_error_responses` replaces FastAPI's generated validation error
  schema with the Engine API's section 10 envelope and adds reusable 4XX/5XX
  responses to every in-schema operation.
* :func:`inject_capability_extension` walks a FastAPI app's effective route contexts, reads the
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

**Hook timing.** Both injection functions override ``app.openapi`` with a
wrapper that calls the previously installed generator before modifying its
result. They are therefore composable: the error wrapper can be installed
before or after the capability wrapper without dropping either transformation.
They are safe to call once, after all routes are registered and before serving.
The generated schema is cached on ``app.openapi_schema`` by FastAPI, so
injection happens on first access.

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

#: The component reference used by generated 4XX and 5XX responses.
_ERROR_RESPONSE_REF = "#/components/responses/ErrorResponse"

#: The component reference used by validation responses and ErrorResponse.
_ERROR_ENVELOPE_REF = "#/components/schemas/ErrorEnvelope"

#: Marker attached to the error wrapper and wrappers composed around it.
_ERROR_RESPONSES_WRAPPER_ATTR = "__agentmesh_error_responses_wrapper__"


def _error_response_ref() -> dict[str, str]:
    """Return a fresh reference to the reusable standard error response."""
    return {"$ref": _ERROR_RESPONSE_REF}


def _error_envelope_content() -> dict[str, Any]:
    """Return JSON content that references the standard error envelope."""
    return {"application/json": {"schema": {"$ref": _ERROR_ENVELOPE_REF}}}


def _contains_ref(value: Any, reference: str) -> bool:
    """Return whether ``value`` contains an OpenAPI ``$ref`` equal to ``reference``."""
    if isinstance(value, dict):
        return any(_contains_ref(item, reference) for item in value.values())
    if isinstance(value, list):
        return any(_contains_ref(item, reference) for item in value)
    return value == reference


def _inject_error_responses_into_schema(schema: dict[str, Any]) -> None:
    """Add the Engine API error components and responses to a generated schema."""
    from agentmesh.engine_api.errors import ErrorEnvelope

    components = schema.setdefault("components", {})
    schemas = components.setdefault("schemas", {})
    schemas["ErrorEnvelope"] = ErrorEnvelope.model_json_schema()

    responses = components.setdefault("responses", {})
    responses["ErrorResponse"] = {
        "description": "Engine API error response",
        "content": _error_envelope_content(),
    }

    paths: dict[str, Any] = schema.get("paths", {})
    for path_item in paths.values():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in _OPENAPI_OPERATION_METHODS:
                continue
            if not isinstance(operation, dict):
                continue

            operation_responses = operation.setdefault("responses", {})
            operation_responses.setdefault("4XX", _error_response_ref())
            operation_responses.setdefault("5XX", _error_response_ref())

            validation_response = operation_responses.get("422")
            if isinstance(validation_response, dict) and _contains_ref(
                validation_response, "#/components/schemas/HTTPValidationError"
            ):
                if "$ref" in validation_response:
                    operation_responses["422"] = _error_response_ref()
                else:
                    validation_response["content"] = _error_envelope_content()

    # FastAPI adds these components only for its implicit validation response. Remove them
    # once no operation or component references them, while preserving legitimate user models
    # with the same names in a custom app.
    for schema_name in ("HTTPValidationError", "ValidationError"):
        schema_ref = f"#/components/schemas/{schema_name}"
        if not _contains_ref(schema, schema_ref):
            schemas.pop(schema_name, None)


def inject_error_responses(app: Any) -> None:
    """Wire standard Engine API error responses into a FastAPI app's OpenAPI generation.

    The wrapper preserves route-specific response entries such as ``404`` and
    only changes the generated ``422`` response body to the standard
    :class:`~agentmesh.engine_api.errors.ErrorEnvelope`.

    Args:
        app: A ``fastapi.FastAPI`` instance with its routes already registered.
    """
    if getattr(app.openapi, _ERROR_RESPONSES_WRAPPER_ATTR, False):
        return

    original_openapi = app.openapi

    def openapi_with_error_responses() -> dict[str, Any]:
        schema = original_openapi()
        _inject_error_responses_into_schema(schema)
        app.openapi_schema = schema
        return schema

    setattr(openapi_with_error_responses, _ERROR_RESPONSES_WRAPPER_ATTR, True)
    app.openapi = openapi_with_error_responses


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
    from fastapi.routing import APIRoute, iter_route_contexts

    original_openapi = app.openapi

    def openapi_with_capabilities() -> dict[str, Any]:
        schema = original_openapi()
        paths: dict[str, Any] = schema.get("paths", {})

        for route_context in iter_route_contexts(app.routes):
            if not isinstance(route_context.original_route, APIRoute):
                continue
            if not route_context.include_in_schema:
                continue

            route_path = route_context.path_format or route_context.path
            path_item = paths.get(route_path)
            if path_item is None:
                continue

            endpoint = route_context.endpoint
            flags: CapabilityFlags | None = getattr(endpoint, CAPABILITY_FLAGS_ATTR, None)

            for method in route_context.methods or ():
                operation = path_item.get(method.lower())
                if operation is None:
                    continue
                if flags is None:
                    endpoint_name = getattr(endpoint, "__name__", repr(endpoint))
                    raise ValueError(
                        "missing capability flags for operation "
                        f"{method.upper()} {route_path!r} (endpoint "
                        f"{endpoint_name!r}). Decorate the endpoint "
                        "with @capability_flags(...) before calling "
                        "inject_capability_extension()."
                    )
                operation[CAPABILITY_EXTENSION_KEY] = flags.model_dump()

        app.openapi_schema = schema
        return schema

    if getattr(original_openapi, _ERROR_RESPONSES_WRAPPER_ATTR, False):
        setattr(openapi_with_capabilities, _ERROR_RESPONSES_WRAPPER_ATTR, True)
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
            runtime_mutating = flags.get("runtime_mutating")
            if isinstance(runtime_mutating, bool) and not runtime_mutating:
                allowlist.append(operation_id)

    return sorted(allowlist)
