# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for the Engine API OpenAPI error documentation."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from fastapi import FastAPI, Query  # noqa: E402

from agentmesh.engine_api import (  # noqa: E402
    CAPABILITY_EXTENSION_KEY,
    capability_flags,
    inject_capability_extension,
)
from agentmesh.engine_api.openapi import inject_error_responses  # noqa: E402

_OPENAPI_OPERATION_METHODS = {
    "get",
    "put",
    "post",
    "delete",
    "options",
    "head",
    "patch",
    "trace",
}
_ERROR_ENVELOPE_REF = "#/components/schemas/ErrorEnvelope"
_ERROR_RESPONSE_REF = "#/components/responses/ErrorResponse"


def _operations(schema: dict) -> list[dict]:
    """Return all operation objects in an OpenAPI document."""
    return [
        operation
        for path_item in schema["paths"].values()
        for method, operation in path_item.items()
        if method.lower() in _OPENAPI_OPERATION_METHODS and isinstance(operation, dict)
    ]


def _build_wrapped_app(error_wrapper_first: bool) -> FastAPI:
    """Build a small app with the two OpenAPI wrappers in either order."""
    app = FastAPI()

    @app.get("/validated", operation_id="validated")
    @capability_flags(runtime_mutating=False, user_intent_required=False, read_only_surface=True)
    async def validated(value: int = Query(...)):
        return {"value": value}

    if error_wrapper_first:
        inject_error_responses(app)
        inject_capability_extension(app)
    else:
        inject_capability_extension(app)
        inject_error_responses(app)
    return app


def _build_explicit_422_app() -> FastAPI:
    """Build an app whose explicit 422 response is not FastAPI's default."""
    app = FastAPI()

    @app.get(
        "/custom-422",
        responses={
            422: {
                "description": "Custom validation response",
                "content": {"application/json": {"schema": {"type": "string"}}},
            }
        },
    )
    async def custom_422():
        return "ok"

    inject_error_responses(app)
    return app


class TestEngineApiOpenApiErrors:
    def test_validation_response_uses_error_envelope(self, app):
        operation = app.openapi()["paths"]["/api/v1/policies"]["get"]

        assert operation["responses"]["422"]["content"]["application/json"]["schema"] == {
            "$ref": _ERROR_ENVELOPE_REF
        }

    def test_no_operation_references_fastapi_validation_error(self, app):
        schema = app.openapi()

        for operation in _operations(schema):
            for response in operation["responses"].values():
                assert "HTTPValidationError" not in str(response)

        assert "HTTPValidationError" not in schema["components"]["schemas"]

    def test_every_operation_has_reusable_client_error_responses(self, app):
        for operation in _operations(app.openapi()):
            assert operation["responses"]["4XX"] == {"$ref": _ERROR_RESPONSE_REF}
            assert operation["responses"]["5XX"] == {"$ref": _ERROR_RESPONSE_REF}

    def test_explicit_not_found_response_is_preserved(self, app):
        response = app.openapi()["paths"]["/api/v1/policies/{id}"]["get"]["responses"]["404"]

        assert response["description"] == "Policy not found"
        assert response["content"]["application/json"]["schema"] == {"$ref": _ERROR_ENVELOPE_REF}

    def test_explicit_custom_422_response_is_preserved(self):
        response = _build_explicit_422_app().openapi()["paths"]["/custom-422"]["get"]["responses"][
            "422"
        ]

        assert response == {
            "description": "Custom validation response",
            "content": {"application/json": {"schema": {"type": "string"}}},
        }

    def test_success_response_and_capability_metadata_remain_present(self, app):
        operation = app.openapi()["paths"]["/api/v1/policies/{id}"]["get"]

        assert operation["responses"]["200"]["content"]["application/json"]["schema"] == {
            "$ref": "#/components/schemas/PolicyDetail"
        }
        assert CAPABILITY_EXTENSION_KEY in operation

    def test_error_envelope_component_has_standard_fields(self, app):
        component = app.openapi()["components"]["schemas"]["ErrorEnvelope"]

        assert {"status", "code", "message", "details"} <= set(component["properties"])

    def test_repeated_openapi_calls_are_equivalent(self, app):
        first = app.openapi()
        second = app.openapi()

        assert first == second

    def test_wrappers_are_composable_in_either_order(self):
        error_first = _build_wrapped_app(error_wrapper_first=True).openapi()
        capability_first = _build_wrapped_app(error_wrapper_first=False).openapi()

        assert error_first == capability_first
