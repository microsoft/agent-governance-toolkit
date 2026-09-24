# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Focused tests for conformance loader, schema, and target helper edge cases."""

from __future__ import annotations

import copy
import json
from pathlib import Path

import httpx
import pytest

from .contract import (
    _schema_for_operation,
    _server_base_path,
    assert_target_contract,
    assert_target_schema_compatibility,
    capability_flags,
    iter_operations,
    load_contract,
    normalize_path,
    operation_map,
    required_fields,
    request_schema,
    schema_validator,
    validate_request_payload,
    validate_payload,
)
from . import target as target_module
from .target import (
    EngineTarget,
    external_target_from_environment,
    metadata_to_openapi,
)

_DEFAULT = object()


def _document(
    *,
    response: object = _DEFAULT,
    flags: object = _DEFAULT,
    path: str = "/health",
) -> dict:
    return {
        "openapi": "3.1.0",
        "servers": [{"url": "http://127.0.0.1:{port}/api/v1"}],
        "components": {
            "schemas": {
                "Result": {"type": "object", "required": ["ok"], "properties": {"ok": {"type": "boolean"}}},
            },
            "responses": {
                "Error": {
                    "content": {
                        "application/json": {
                            "schema": {"$ref": "#/components/schemas/Result"}
                        }
                    }
                }
            },
        },
        "paths": {
            path: {
                "summary": "path item metadata",
                "get": {
                    "operationId": "getHealth",
                    "x-capability-flags": (
                        {
                            "runtime_mutating": False,
                            "user_intent_required": False,
                            "read_only_surface": True,
                        }
                        if flags is _DEFAULT
                        else flags
                    ),
                    "responses": response
                    if response is not _DEFAULT
                    else {
                        "200": {
                            "content": {
                                "application/json": {
                                    "schema": {"$ref": "#/components/schemas/Result"}
                                }
                            }
                        }
                    },
                },
            }
        },
    }


def test_contract_loader_rejects_non_object_documents(tmp_path: Path):
    path = tmp_path / "invalid.yaml"
    path.write_text("- not-an-object\n", encoding="utf-8")
    with pytest.raises(ValueError, match="must be an object"):
        load_contract(path)


@pytest.mark.parametrize(
    ("document", "expected"),
    [
        ({}, ""),
        ({"servers": "not-a-list"}, ""),
        ({"servers": [None]}, ""),
        ({"servers": [{}]}, ""),
        ({"servers": [{"url": "api/v1"}]}, "/api/v1"),
    ],
)
def test_server_base_path_handles_metadata_shapes(document, expected):
    assert _server_base_path(document) == expected


def test_path_normalization_handles_base_and_wire_paths():
    document = {"servers": [{"url": "http://localhost/api/v1"}]}
    assert normalize_path(document, "/health") == "/api/v1/health"
    assert normalize_path(document, "/api/v1/health") == "/api/v1/health"
    assert normalize_path(document, "/api/v1") == "/api/v1"
    assert normalize_path({}, "") == "/"


def test_operation_iteration_ignores_path_metadata_and_rejects_missing_ids():
    document = _document()
    assert len(list(iter_operations(document))) == 1
    assert list(iter_operations({"paths": None})) == []
    assert list(iter_operations({"paths": {"/x": "not-a-path-item"}})) == []

    broken = _document()
    broken["paths"]["/health"]["get"].pop("operationId")
    with pytest.raises(AssertionError, match="lacks operationId"):
        list(iter_operations(broken))


def test_operation_map_rejects_duplicate_ids():
    broken = _document()
    broken["paths"]["/other"] = copy.deepcopy(broken["paths"]["/health"])
    with pytest.raises(AssertionError, match="duplicate operationId"):
        operation_map(broken)


@pytest.mark.parametrize(
    ("flags", "message"),
    [
        (None, "missing"),
        ({"runtime_mutating": False}, "exactly"),
        (
            {
                "runtime_mutating": False,
                "user_intent_required": False,
                "read_only_surface": "true",
            },
            "boolean",
        ),
        (
            {
                "runtime_mutating": False,
                "user_intent_required": False,
                "read_only_surface": False,
            },
            "inverse",
        ),
    ],
)
def test_capability_flag_validation_rejects_drift(flags, message):
    operation = next(iter_operations(_document(flags=flags)))
    with pytest.raises(AssertionError, match=message):
        capability_flags(operation)


def test_schema_resolution_uses_exact_wildcard_default_and_inline_schemas():
    document = _document(
        response={
            "200": {"$ref": "#/components/responses/Error"},
            "4XX": {
                "content": {
                    "application/json": {
                        "schema": {"type": "object", "required": ["error"]}
                    }
                }
            },
        }
    )
    operation = next(iter_operations(document))
    assert _schema_for_operation(operation, 200)["required"] == ["ok"]
    assert _schema_for_operation(operation, 404)["required"] == ["error"]

    default_document = _document(
        response={
            "default": {
                "content": {
                    "application/json": {
                        "schema": {"type": "object", "required": ["fallback"]}
                    }
                }
            }
        }
    )
    assert _schema_for_operation(next(iter_operations(default_document)), 500)["required"] == [
        "fallback"
    ]


@pytest.mark.parametrize(
    "response",
    [
        {},
        {"200": {"description": "missing content"}},
        {"200": {"content": {"text/plain": {}}}},
        {"200": {"content": {"application/json": {}}}},
        {"200": {"content": {"application/json": {"schema": "not-a-schema"}}}},
    ],
)
def test_schema_resolution_rejects_incomplete_metadata(response):
    operation = next(iter_operations(_document(response=response)))
    with pytest.raises(AssertionError):
        _schema_for_operation(operation, 200)


def test_schema_resolution_rejects_non_local_refs_and_missing_status():
    document = _document(
        response={
            "200": {
                "content": {
                    "application/json": {
                        "schema": {"$ref": "https://example.invalid/schema"}
                    }
                }
            }
        }
    )
    operation = next(iter_operations(document))
    with pytest.raises(ValueError, match="Only local"):
        _schema_for_operation(operation, 200)
    with pytest.raises(AssertionError, match="lacks a JSON schema"):
        _schema_for_operation(operation, 404)


def test_schema_validation_and_required_all_of_resolution():
    document = _document()
    operation = next(iter_operations(document))
    validate_payload(document, operation, 200, {"ok": True})
    with pytest.raises(AssertionError, match="violates"):
        validate_payload(document, operation, 200, {"ok": "yes"})
    assert schema_validator(document, {"type": "boolean"}).is_valid(True)

    composed = {
        "allOf": [
            {"$ref": "#/components/schemas/Result"},
            {"type": "object", "required": ["extra"]},
        ]
    }
    assert required_fields(document, composed) == {"ok", "extra"}


def test_request_schema_validation_uses_canonical_refs(canonical_contract):
    operation = operation_map(canonical_contract)["validatePolicy"]
    payload = {"content": "rules: []", "format": "yaml"}
    assert request_schema(operation)["required"] == ["content", "format"]
    validate_request_payload(canonical_contract, operation, payload)
    with pytest.raises(AssertionError, match="request violates"):
        validate_request_payload(canonical_contract, operation, {"format": "yaml"})


def test_schema_compatibility_reports_missing_target_schema(canonical_contract):
    target = copy.deepcopy(canonical_contract)
    target["paths"]["/health"]["get"]["responses"].pop("200")
    target["paths"]["/health"]["get"]["responses"].pop("4XX")
    with pytest.raises(AssertionError, match="getHealth lacks"):
        assert_target_schema_compatibility(canonical_contract, target)


def test_contract_assertion_reports_missing_and_misplaced_operations(canonical_contract):
    target = copy.deepcopy(canonical_contract)
    target["paths"]["/health"]["get"]["operationId"] = "renamed"
    with pytest.raises(AssertionError, match="missing operation getHealth"):
        assert_target_contract(canonical_contract, target)


def test_target_transport_and_metadata_helpers(tmp_path: Path, monkeypatch):
    metadata_path = tmp_path / "metadata.json"
    metadata_path.write_text(json.dumps({"operations": []}), encoding="utf-8")

    class Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"openapi": "3.1.0", "paths": {}}

    class Client:
        def __init__(self, *args, **kwargs):
            self.closed = False

        def close(self):
            self.closed = True

        def request(self, method, path, **kwargs):
            return (method, path, kwargs)

    monkeypatch.setattr(target_module.httpx, "get", lambda *args, **kwargs: Response())
    monkeypatch.setattr(target_module.httpx, "Client", Client)
    monkeypatch.setenv("AGT_ENGINE_API_URL", "http://127.0.0.1:8080")
    monkeypatch.setenv("AGT_ENGINE_API_METADATA", str(metadata_path))
    target = external_target_from_environment()
    assert target.external is True
    assert target.request("GET", "/health")[0] == "GET"
    with pytest.raises(PermissionError, match="AGT_ENGINE_API_ALLOW_WRITES"):
        target.request("POST", "/api/v1/policy/save")
    target.close()


def test_metadata_operations_are_normalized_for_route_checks():
    document = metadata_to_openapi(
        {
            "operations": [
                {
                    "method": "GET",
                    "path": "/api/v1/health",
                    "operationId": "getHealth",
                    "x-capability-flags": {
                        "runtime_mutating": False,
                        "user_intent_required": False,
                        "read_only_surface": True,
                    },
                }
            ]
        }
    )
    assert document["paths"]["/api/v1/health"]["get"]["operationId"] == "getHealth"
    assert metadata_to_openapi({"paths": {}}) == {"paths": {}}
    with pytest.raises(ValueError, match="operations list"):
        metadata_to_openapi({})
    with pytest.raises(ValueError, match="must be an object"):
        metadata_to_openapi({"operations": ["invalid"]})
    with pytest.raises(ValueError, match="require method"):
        metadata_to_openapi({"operations": [{}]})
    with pytest.raises(ValueError, match="lacks x-capability"):
        metadata_to_openapi(
            {"operations": [{"method": "GET", "path": "/api/v1/health", "operationId": "getHealth"}]}
        )


def test_external_target_requires_metadata_when_openapi_is_unavailable(monkeypatch):
    class Client:
        def __init__(self, *args, **kwargs):
            self.closed = False

        def close(self):
            self.closed = True

    def fail(*args, **kwargs):
        raise httpx.ConnectError("offline")

    monkeypatch.setattr(target_module.httpx, "get", fail)
    monkeypatch.setattr(target_module.httpx, "Client", Client)
    monkeypatch.setenv("AGT_ENGINE_API_URL", "http://127.0.0.1:8080")
    monkeypatch.delenv("AGT_ENGINE_API_METADATA", raising=False)
    with pytest.raises(RuntimeError, match="must expose"):
        external_target_from_environment()


def test_engine_target_close_without_closeable_client():
    target = EngineTarget(client=object(), openapi=None, metadata=None, external=False, origin="test")
    target.close()
