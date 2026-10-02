# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Shared HTTP assertions used by reference and custom Engine API targets."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .contract import validate_payload


def assert_json_content_type(response: Any) -> None:
    """Require an HTTP response to advertise JSON without over-constraining parameters."""
    content_type = response.headers.get("content-type", "")
    assert content_type.lower().startswith("application/json"), content_type


def assert_contract_response(
    response: Any,
    contract: dict[str, Any],
    operation_id: str,
    status: int,
) -> dict[str, Any]:
    """Validate status, JSON transport, and the canonical response schema."""
    assert response.status_code == status, response.text
    assert_json_content_type(response)
    body = response.json()
    from .contract import operation_map

    operation = operation_map(contract)[operation_id]
    validate_payload(contract, operation, status, body)
    return body


def assert_error_response(
    response: Any,
    contract: dict[str, Any],
    operation_id: str,
    status: int,
    code: str,
) -> dict[str, Any]:
    """Validate the standard error envelope and its status/code invariants."""
    body = assert_contract_response(response, contract, operation_id, status)
    assert body["status"] == status
    assert body["code"] == code
    assert isinstance(body["message"], str) and body["message"]
    if "details" in body:
        assert isinstance(body["details"], dict)
    return body


def assert_api_version(body: dict[str, Any], contract: dict[str, Any]) -> None:
    """Require a versions response to negotiate the canonical API version."""
    expected = contract.get("info", {}).get("version")
    assert isinstance(expected, str) and expected
    assert body.get("api") == expected, (
        f"target advertises API {body.get('api')!r}; expected {expected!r}"
    )


def snapshot_tree(root: Path) -> dict[str, bytes]:
    """Capture policy-directory contents for read-only side-effect assertions."""
    if not root.exists():
        return {}
    return {
        str(path.relative_to(root)): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def assert_read_only_request(
    client: Any,
    root: Path,
    method: str,
    path: str,
    **kwargs: Any,
) -> Any:
    """Assert that an HTTP request leaves persistent policy state unchanged."""
    before = snapshot_tree(root)
    response = client.request(method, path, **kwargs)
    after = snapshot_tree(root)
    assert after == before, f"{method} {path} changed persistent policy state"
    return response
