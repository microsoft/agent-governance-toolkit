# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""OpenAPI-document structure tests: operationId/path/method mapping and flag shape."""

from __future__ import annotations

import pytest

pytest.importorskip("fastapi")

from agentmesh.engine_api import CAPABILITY_EXTENSION_KEY  # noqa: E402

# operationId -> (HTTP method, path) per contract section 7.
_OPERATION_ROUTES = {
    "getHealth": ("get", "/api/v1/health"),
    "listPolicies": ("get", "/api/v1/policies"),
    "getPolicy": ("get", "/api/v1/policies/{id}"),
    "validatePolicy": ("post", "/api/v1/policy/validate"),
    "testPolicy": ("post", "/api/v1/policy/test"),
    "savePolicy": ("post", "/api/v1/policy/save"),
    "getAuditLog": ("get", "/api/v1/audit/log"),
    "getTrustScores": ("get", "/api/v1/trust/scores"),
    "getTrustGraph": ("get", "/api/v1/trust/graph"),
    "listAgents": ("get", "/api/v1/agents"),
    "listDecisions": ("get", "/api/v1/decisions"),
    "getVersions": ("get", "/api/v1/versions"),
}

_FLAG_FIELDS = {"runtime_mutating", "user_intent_required", "read_only_surface"}


@pytest.fixture
def schema(app):
    return app.openapi()


class TestOperationRoutes:
    @pytest.mark.parametrize("operation_id,route", _OPERATION_ROUTES.items())
    def test_operation_mapped_to_expected_path_and_method(self, schema, operation_id, route):
        method, path = route
        assert path in schema["paths"], f"missing path {path}"
        operation = schema["paths"][path][method]
        assert operation["operationId"] == operation_id

    def test_every_operation_flag_shape(self, schema):
        for path_item in schema["paths"].values():
            for method, operation in path_item.items():
                if method.lower() not in {"get", "post"}:
                    continue
                flags = operation[CAPABILITY_EXTENSION_KEY]
                assert set(flags) == _FLAG_FIELDS
                assert all(isinstance(v, bool) for v in flags.values())

    def test_no_unexpected_operations(self, schema):
        found = {
            op["operationId"]
            for path_item in schema["paths"].values()
            for method, op in path_item.items()
            if method.lower() in {"get", "post"} and isinstance(op, dict) and "operationId" in op
        }
        assert found == set(_OPERATION_ROUTES)

    def test_openapi_info_block(self, schema):
        assert schema["info"]["title"] == "AGT Studio Engine API"
        assert schema["info"]["version"] == "1.0.0"

    def test_timestamp_fields_carry_date_time_format(self, schema):
        # Faithful to the companion openapi.yaml, which types these as `format: date-time`.
        detail = schema["components"]["schemas"]["PolicyDetail"]["properties"]
        assert detail["last_modified"]["format"] == "date-time"
        save = schema["components"]["schemas"]["SaveResponse"]["properties"]
        assert save["saved_at"]["format"] == "date-time"
