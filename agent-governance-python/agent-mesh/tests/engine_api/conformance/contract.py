# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Canonical OpenAPI loading and validation helpers for Engine API conformance."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlparse

import yaml
from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

OPENAPI_METHODS = frozenset({"get", "put", "post", "delete", "options", "head", "patch", "trace"})
CAPABILITY_FLAGS = frozenset({"runtime_mutating", "user_intent_required", "read_only_surface"})


@dataclass(frozen=True)
class Operation:
    """An OpenAPI operation with a normalized HTTP path."""

    method: str
    path: str
    operation_id: str
    document_path: str
    document: dict[str, Any]
    root: dict[str, Any]


def default_contract_path() -> Path:
    """Return the checked-in Studio OpenAPI contract path."""
    return Path(__file__).resolve().parents[5] / "docs" / "studio" / "openapi.yaml"


def load_contract(path: Path | None = None) -> dict[str, Any]:
    """Load the canonical OpenAPI document from disk."""
    contract_path = path or default_contract_path()
    with contract_path.open("r", encoding="utf-8") as handle:
        document = yaml.safe_load(handle)
    if not isinstance(document, dict):
        raise ValueError(f"OpenAPI document must be an object: {contract_path}")
    return document


def _server_base_path(document: dict[str, Any]) -> str:
    servers = document.get("servers", [])
    if not isinstance(servers, list) or not servers:
        return ""
    first_server = servers[0]
    if not isinstance(first_server, dict):
        return ""
    url = first_server.get("url")
    if not isinstance(url, str):
        return ""
    path = urlparse(url).path.rstrip("/")
    return path if path.startswith("/") else f"/{path}" if path else ""


def normalize_path(document: dict[str, Any], path: str) -> str:
    """Normalize a document path to the wire path used by the adapter."""
    base = _server_base_path(document)
    if not base or path == base or path.startswith(f"{base}/"):
        return path or "/"
    return f"{base}/{path.lstrip('/')}"


def iter_operations(document: dict[str, Any]) -> Iterator[Operation]:
    """Yield callable OpenAPI operations, ignoring path-item metadata fields."""
    paths = document.get("paths", {})
    if not isinstance(paths, dict):
        return
    for document_path, path_item in paths.items():
        if not isinstance(document_path, str) or not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() not in OPENAPI_METHODS or not isinstance(operation, dict):
                continue
            operation_id = operation.get("operationId")
            if not isinstance(operation_id, str) or not operation_id:
                raise AssertionError(f"Operation {method.upper()} {document_path} lacks operationId")
            yield Operation(
                method=method.lower(),
                path=normalize_path(document, document_path),
                operation_id=operation_id,
                document_path=document_path,
                document=operation,
                root=document,
            )


def operation_map(document: dict[str, Any]) -> dict[str, Operation]:
    """Return operations keyed by operation ID and reject duplicate IDs."""
    result: dict[str, Operation] = {}
    for operation in iter_operations(document):
        if operation.operation_id in result:
            previous = result[operation.operation_id]
            raise AssertionError(
                f"duplicate operationId {operation.operation_id!r}: "
                f"{previous.method.upper()} {previous.path} and "
                f"{operation.method.upper()} {operation.path}"
            )
        result[operation.operation_id] = operation
    return result


def operation_key(operation: Operation) -> tuple[str, str]:
    """Return the normalized method/path identity for an operation."""
    return operation.method, operation.path


def capability_flags(operation: Operation) -> dict[str, bool]:
    """Return and validate the three capability flags on an operation."""
    raw_flags = operation.document.get("x-capability-flags")
    if not isinstance(raw_flags, dict):
        raise AssertionError(f"{operation.operation_id} is missing x-capability-flags")
    if set(raw_flags) != CAPABILITY_FLAGS:
        raise AssertionError(
            f"{operation.operation_id} must declare exactly {sorted(CAPABILITY_FLAGS)}, "
            f"got {sorted(raw_flags)}"
        )
    if any(not isinstance(raw_flags[name], bool) for name in CAPABILITY_FLAGS):
        raise AssertionError(f"{operation.operation_id} capability flags must all be boolean")
    if raw_flags["read_only_surface"] == raw_flags["runtime_mutating"]:
        raise AssertionError(
            f"{operation.operation_id} must make read_only_surface the inverse "
            "of runtime_mutating"
        )
    return {name: raw_flags[name] for name in CAPABILITY_FLAGS}


def _json_pointer(document: dict[str, Any], reference: str) -> Any:
    if not reference.startswith("#/"):
        raise ValueError(f"Only local OpenAPI references are supported: {reference}")
    value: Any = document
    for token in reference[2:].split("/"):
        value = value[token.replace("~1", "/").replace("~0", "~")]
    return value


def _schema_for_operation(operation: Operation, status: int) -> dict[str, Any]:
    """Resolve a response schema while retaining the document root privately."""
    responses = operation.document.get("responses", {})
    if not isinstance(responses, dict):
        raise AssertionError(f"{operation.operation_id} has no response map")
    for key in (str(status), f"{status // 100}XX", "default"):
        if key not in responses:
            continue
        response = responses[key]
        if isinstance(response, dict) and "$ref" in response:
            response = _json_pointer(operation.root, response["$ref"])
        if not isinstance(response, dict):
            break
        media_type = response.get("content", {}).get("application/json")
        if not isinstance(media_type, dict):
            break
        schema = media_type.get("schema")
        if not isinstance(schema, dict):
            break
        return _json_pointer(operation.root, schema["$ref"]) if "$ref" in schema else schema
    raise AssertionError(f"{operation.operation_id} lacks a JSON schema for HTTP {status}")


def request_schema(operation: Operation) -> dict[str, Any]:
    """Resolve the application/json request schema for an operation."""
    request_body = operation.document.get("requestBody")
    if not isinstance(request_body, dict):
        raise AssertionError(f"{operation.operation_id} has no request body schema")
    if "$ref" in request_body:
        request_body = _json_pointer(operation.root, request_body["$ref"])
    content = request_body.get("content", {})
    media_type = content.get("application/json") if isinstance(content, dict) else None
    if not isinstance(media_type, dict) or not isinstance(media_type.get("schema"), dict):
        raise AssertionError(f"{operation.operation_id} lacks an application/json request schema")
    schema = media_type["schema"]
    return _json_pointer(operation.root, schema["$ref"]) if "$ref" in schema else schema


def schema_validator(document: dict[str, Any], schema: dict[str, Any]) -> Draft202012Validator:
    """Build a JSON Schema 2020-12 validator with local OpenAPI references."""
    root_uri = "urn:agt:studio:engine-api"
    registry = Registry().with_resource(
        root_uri,
        Resource.from_contents(document, default_specification=DRAFT202012),
    )
    root_validator = Draft202012Validator(
        document,
        registry=registry,
        format_checker=FormatChecker(),
    )
    return root_validator.evolve(schema={"$id": root_uri, **schema})


def validate_payload(
    document: dict[str, Any],
    operation: Operation,
    status: int,
    payload: Any,
) -> None:
    """Validate a payload against an operation's advertised response schema."""
    schema = _schema_for_operation(operation, status)
    validator = schema_validator(document, schema)
    errors = sorted(validator.iter_errors(payload), key=lambda error: list(error.path))
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.path) or "<response>"
        raise AssertionError(
            f"{operation.operation_id} HTTP {status} violates its schema at {location}: "
            f"{error.message}"
        )


def validate_request_payload(
    document: dict[str, Any],
    operation: Operation,
    payload: Any,
) -> None:
    """Validate a request payload against an operation's canonical schema."""
    schema = request_schema(operation)
    validator = schema_validator(document, schema)
    errors = sorted(validator.iter_errors(payload), key=lambda error: list(error.path))
    if errors:
        error = errors[0]
        location = ".".join(str(part) for part in error.path) or "<request>"
        raise AssertionError(
            f"{operation.operation_id} request violates its schema at {location}: "
            f"{error.message}"
        )


def required_fields(document: dict[str, Any], schema: dict[str, Any]) -> set[str]:
    """Collect required object fields through local refs and allOf composition."""
    if "$ref" in schema:
        return required_fields(document, _json_pointer(document, schema["$ref"]))
    required = set(schema.get("required", []))
    for child in schema.get("allOf", []):
        if isinstance(child, dict):
            required.update(required_fields(document, child))
    return required


def assert_target_contract(
    canonical: dict[str, Any],
    target: dict[str, Any],
    *,
    require_exact_operations: bool = False,
) -> None:
    """Validate target operation identity and capability metadata against the contract."""
    expected = operation_map(canonical)
    actual = operation_map(target)
    errors: list[str] = []

    if require_exact_operations and set(actual) != set(expected):
        errors.append(
            f"operation IDs differ: expected {sorted(expected)}, got {sorted(actual)}"
        )

    for operation_id, expected_operation in expected.items():
        actual_operation = actual.get(operation_id)
        if actual_operation is None:
            errors.append(f"missing operation {operation_id}")
            continue
        if operation_key(actual_operation) != operation_key(expected_operation):
            errors.append(
                f"{operation_id} is at {actual_operation.method.upper()} "
                f"{actual_operation.path}, expected {expected_operation.method.upper()} "
                f"{expected_operation.path}"
            )
        try:
            expected_flags = capability_flags(expected_operation)
            actual_flags = capability_flags(actual_operation)
        except AssertionError as exc:
            errors.append(str(exc))
        else:
            if actual_flags != expected_flags:
                errors.append(
                    f"{operation_id} flags differ: expected {expected_flags}, got {actual_flags}"
                )

    if errors:
        raise AssertionError("\n".join(errors))


def assert_target_schema_compatibility(
    canonical: dict[str, Any],
    target: dict[str, Any],
) -> None:
    """Ensure target schemas retain the canonical required fields for advertised responses."""
    expected = operation_map(canonical)
    actual = operation_map(target)
    errors: list[str] = []
    for operation_id, expected_operation in expected.items():
        actual_operation = actual.get(operation_id)
        if actual_operation is None:
            continue
        for status in (200, 404, 422, 403, 503):
            try:
                expected_schema = _schema_for_operation(expected_operation, status)
            except AssertionError:
                continue
            try:
                actual_schema = _schema_for_operation(actual_operation, status)
            except AssertionError:
                errors.append(f"{operation_id} lacks an advertised JSON schema for HTTP {status}")
                continue
            expected_required = required_fields(canonical, expected_schema)
            actual_required = required_fields(target, actual_schema)
            missing = expected_required - actual_required
            if missing:
                errors.append(
                    f"{operation_id} HTTP {status} omits canonical required fields "
                    f"{sorted(missing)}"
                )
    if errors:
        raise AssertionError("\n".join(errors))


def canonical_allowlist(document: dict[str, Any]) -> list[str]:
    """Derive the read-only operation allowlist from canonical flags."""
    return sorted(
        operation.operation_id
        for operation in iter_operations(document)
        if capability_flags(operation)["read_only_surface"]
    )
