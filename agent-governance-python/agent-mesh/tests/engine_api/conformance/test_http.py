# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Deterministic HTTP conformance cases for the reference Engine API adapter."""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agentmesh.engine_api import create_app

from .assertions import (
    assert_api_version,
    assert_contract_response,
    assert_error_response,
    assert_json_content_type,
    assert_read_only_request,
)

_TEST_REQUEST = {
    "fixtures": [
        {
            "id": "allow-read",
            "input": {"action": "read"},
            "expected_verdict": "allow",
        }
    ]
}


def test_versions_and_health_are_contract_shaped(client, canonical_contract):
    health = assert_contract_response(
        client.get("/api/v1/health"), canonical_contract, "getHealth", 200
    )
    assert health["status"] in {"ok", "degraded"}
    assert health["version"]
    assert health["uptime_seconds"] >= 0

    versions = assert_contract_response(
        client.get("/api/v1/versions"), canonical_contract, "getVersions", 200
    )
    assert_api_version(versions, canonical_contract)
    assert versions["engine"]


def test_policy_inventory_detail_and_unknown_id(client, policy_dir, canonical_contract):
    listing = assert_contract_response(
        client.get("/api/v1/policies"), canonical_contract, "listPolicies", 200
    )
    assert {item["id"] for item in listing["items"]} == {"alpha", "beta"}
    assert listing["pagination"] == {"page": 1, "limit": 20, "total": 2, "has_next": False}
    assert all("rules_count" not in item for item in listing["items"])

    detail = assert_contract_response(
        client.get("/api/v1/policies/alpha"), canonical_contract, "getPolicy", 200
    )
    assert detail["id"] == "alpha"
    assert detail["format"] == "yaml"
    assert detail["rules_count"] == 1
    assert detail["content"] == (policy_dir / "alpha.yaml").read_text(encoding="utf-8")
    assert detail["last_modified"]

    assert_error_response(
        client.get("/api/v1/policies/missing"),
        canonical_contract,
        "getPolicy",
        404,
        "POLICY_NOT_FOUND",
    )


@pytest.mark.parametrize(
    ("content_fixture", "fmt"),
    [("yaml_policy_content", "yaml"), ("json_policy_content", "json")],
)
def test_validate_accepts_yaml_and_json(
    client, canonical_contract, request, content_fixture, fmt
):
    content = request.getfixturevalue(content_fixture)
    body = assert_contract_response(
        client.post("/api/v1/policy/validate", json={"content": content, "format": fmt}),
        canonical_contract,
        "validatePolicy",
        200,
    )
    assert body == {"valid": True, "errors": []}


@pytest.mark.parametrize(
    ("content", "fmt"),
    [("rules: [", "yaml"), ('{"rules":', "json")],
)
def test_validate_parse_failures_use_error_envelope(
    client, canonical_contract, content, fmt
):
    assert_error_response(
        client.post("/api/v1/policy/validate", json={"content": content, "format": fmt}),
        canonical_contract,
        "validatePolicy",
        422,
        "POLICY_PARSE_ERROR",
    )


def test_validate_schema_failure_is_a_typed_success_response(client, canonical_contract):
    body = assert_contract_response(
        client.post(
            "/api/v1/policy/validate",
            json={"content": "just a scalar", "format": "yaml"},
        ),
        canonical_contract,
        "validatePolicy",
        200,
    )
    assert body["valid"] is False
    assert body["errors"]
    assert "line" not in body["errors"][0]
    assert "col" not in body["errors"][0]


def test_default_disabled_save_is_forbidden_without_mutation(
    disabled_client, policy_dir, canonical_contract, yaml_policy_content
):
    before = {
        path.name: path.read_bytes()
        for path in policy_dir.iterdir()
        if path.is_file()
    }
    assert_error_response(
        disabled_client.post(
            "/api/v1/policy/save",
            json={"id": "new-policy", "content": yaml_policy_content, "format": "yaml"},
        ),
        canonical_contract,
        "savePolicy",
        403,
        "FORBIDDEN",
    )
    after = {
        path.name: path.read_bytes()
        for path in policy_dir.iterdir()
        if path.is_file()
    }
    assert after == before
    assert not (policy_dir / "new-policy.yaml").exists()


def test_enabled_save_is_visible_and_invalid_save_does_not_overwrite(
    policy_dir, canonical_contract, yaml_policy_content
):
    client = TestClient(create_app(policy_dir=str(policy_dir), enable_policy_save=True))
    try:
        response = assert_contract_response(
            client.post(
                "/api/v1/policy/save",
                json={"id": "gamma", "content": yaml_policy_content, "format": "yaml"},
            ),
            canonical_contract,
            "savePolicy",
            200,
        )
        assert response["id"] == "gamma"
        assert response["version"]
        assert_contract_response(
            client.get("/api/v1/policies/gamma"),
            canonical_contract,
            "getPolicy",
            200,
        )

        original = (policy_dir / "gamma.yaml").read_bytes()
        assert_error_response(
            client.post(
                "/api/v1/policy/save",
                json={"id": "gamma", "content": "rules: [", "format": "yaml"},
            ),
            canonical_contract,
            "savePolicy",
            422,
            "POLICY_PARSE_ERROR",
        )
        assert (policy_dir / "gamma.yaml").read_bytes() == original
    finally:
        client.close()


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/audit/log",
        "/api/v1/trust/scores",
        "/api/v1/agents",
        "/api/v1/decisions",
    ],
)
def test_all_paginated_lists_use_contract_pagination(client, canonical_contract, path):
    operation_id = {
        "/api/v1/audit/log": "getAuditLog",
        "/api/v1/trust/scores": "getTrustScores",
        "/api/v1/agents": "listAgents",
        "/api/v1/decisions": "listDecisions",
    }[path]
    body = assert_contract_response(
        client.get(path), canonical_contract, operation_id, 200
    )
    assert body["pagination"] == {"page": 1, "limit": 20, "total": 0, "has_next": False}


@pytest.mark.parametrize(
    "path",
    [
        "/api/v1/policies",
        "/api/v1/audit/log",
        "/api/v1/trust/scores",
        "/api/v1/agents",
        "/api/v1/decisions",
    ],
)
@pytest.mark.parametrize("query", ["page=0", "limit=0", "limit=101", "page=not-an-int"])
def test_pagination_bounds_are_contract_validation_errors(
    client, canonical_contract, path, query
):
    operation_id = {
        "/api/v1/policies": "listPolicies",
        "/api/v1/audit/log": "getAuditLog",
        "/api/v1/trust/scores": "getTrustScores",
        "/api/v1/agents": "listAgents",
        "/api/v1/decisions": "listDecisions",
    }[path]
    assert_error_response(
        client.get(f"{path}?{query}"),
        canonical_contract,
        operation_id,
        422,
        "VALIDATION_ERROR",
    )


def test_policy_pagination_covers_final_and_beyond_final_pages(
    tmp_path: Path, canonical_contract, yaml_policy_content
):
    for index in range(25):
        (tmp_path / f"policy-{index:02d}.yaml").write_text(
            yaml_policy_content, encoding="utf-8"
        )
    client = TestClient(create_app(policy_dir=str(tmp_path), enable_policy_save=False))
    try:
        first = assert_contract_response(
            client.get("/api/v1/policies?page=1&limit=10"),
            canonical_contract,
            "listPolicies",
            200,
        )
        final = assert_contract_response(
            client.get("/api/v1/policies?page=3&limit=10"),
            canonical_contract,
            "listPolicies",
            200,
        )
        beyond = assert_contract_response(
            client.get("/api/v1/policies?page=4&limit=10"),
            canonical_contract,
            "listPolicies",
            200,
        )
        assert len(first["items"]) == 10
        assert len(final["items"]) == 5
        assert final["pagination"]["has_next"] is False
        assert beyond["items"] == []
        assert beyond["pagination"]["total"] == 25
        assert beyond["pagination"]["has_next"] is False
    finally:
        client.close()


def test_trust_graph_is_not_a_paginated_list(client, canonical_contract):
    body = assert_contract_response(
        client.get("/api/v1/trust/graph"), canonical_contract, "getTrustGraph", 200
    )
    assert body == {"nodes": [], "edges": []}
    assert "pagination" not in body


def test_policy_test_failure_paths_are_enveloped_and_read_only(
    client, policy_dir, canonical_contract
):
    before = {
        path.name: path.read_bytes()
        for path in policy_dir.iterdir()
        if path.is_file()
    }
    response = client.post("/api/v1/policy/test", json=_TEST_REQUEST)
    assert response.status_code in {200, 422, 503}
    if response.status_code == 503 and os.getenv("AGT_ENGINE_API_REQUIRE_REPLAY") == "1":
        pytest.fail("real replay is required for the Engine API conformance profile")
    assert_json_content_type(response)
    if response.status_code != 200:
        body = response.json()
        assert body["status"] == response.status_code
        assert body["code"] in {"FIXTURE_LOAD_ERROR", "ENGINE_UNAVAILABLE"}
    assert {
        path.name: path.read_bytes()
        for path in policy_dir.iterdir()
        if path.is_file()
    } == before


def test_policy_fixture_override_failure_uses_contract_error_envelope(
    client, tmp_path, canonical_contract
):
    outside = tmp_path.parent / "outside-policy"
    outside.mkdir()
    assert_error_response(
        client.post(
            "/api/v1/policy/test",
            json={**_TEST_REQUEST, "policy_dir": str(outside)},
        ),
        canonical_contract,
        "testPolicy",
        422,
        "FIXTURE_LOAD_ERROR",
    )


def test_policy_test_profile_uses_real_replay_when_installed(
    client, policy_dir, canonical_contract
):
    probe_dir = policy_dir / "replay-profile"
    probe_dir.mkdir()
    (probe_dir / "manifest.yaml").write_text(
        "\n".join(
            (
                "agent_control_specification_version: 0.4.0-alpha.1",
                "metadata:",
                "  name: engine-api-conformance",
                "extends: []",
                "policies:",
                "  smoke:",
                "    type: rego",
                "    bundle: ./policy",
                "    query: data.agent_control_specification.smoke.verdict",
                "intervention_points:",
                "  input:",
                "    policy_target: $.input",
                "    policy_target_kind: user_input",
                "    policy:",
                "      id: smoke",
                "      query: data.agent_control_specification.smoke.input_verdict",
                "tools: {}",
                "annotators: {}",
                "",
            )
        ),
        encoding="utf-8",
    )
    policy_dir_path = probe_dir / "policy"
    policy_dir_path.mkdir()
    (policy_dir_path / "smoke.rego").write_text(
        "\n".join(
            (
                "package agent_control_specification.smoke",
                "",
                'default input_verdict := {"decision": "allow"}',
                "",
            )
        ),
        encoding="utf-8",
    )
    response = client.post(
        "/api/v1/policy/test",
        json={
            "policy_dir": str(probe_dir),
            "fixtures": [
                {
                    "id": "allow-safe",
                    "input": {"action": "safe"},
                    "expected_verdict": "allow",
                },
                {
                    "id": "mismatch-safe",
                    "input": {"action": "safe"},
                    "expected_verdict": "deny",
                },
            ],
        },
    )
    if response.status_code == 503:
        assert_error_response(
            response,
            canonical_contract,
            "testPolicy",
            503,
            "ENGINE_UNAVAILABLE",
        )
        if os.getenv("AGT_ENGINE_API_REQUIRE_REPLAY") == "1":
            pytest.fail("real replay is required for the Engine API conformance profile")
        return
    body = assert_contract_response(response, canonical_contract, "testPolicy", 200)
    assert body["total"] == 2
    assert body["passed"] == 1
    assert body["failed"] == 1


def test_internal_errors_are_sanitized_on_an_isolated_hidden_route(
    policy_dir, canonical_contract
):
    app = create_app(policy_dir=str(policy_dir), enable_policy_save=False)

    @app.get("/test-only/internal-error", include_in_schema=False)
    async def internal_error():
        raise RuntimeError("secret implementation detail")

    client = TestClient(app, raise_server_exceptions=False)
    try:
        response = client.get("/test-only/internal-error")
        body = assert_error_response(
            response,
            canonical_contract,
            "getHealth",
            500,
            "INTERNAL_ERROR",
        )
        assert "secret implementation detail" not in response.text
        assert body["message"] == "Internal engine error"
    finally:
        client.close()


@pytest.mark.parametrize(
    ("method", "path", "kwargs"),
    [
        ("GET", "/api/v1/health", {}),
        ("GET", "/api/v1/policies", {}),
        ("GET", "/api/v1/policies/alpha", {}),
        ("GET", "/api/v1/audit/log", {}),
        ("GET", "/api/v1/trust/scores", {}),
        ("GET", "/api/v1/trust/graph", {}),
        ("GET", "/api/v1/agents", {}),
        ("GET", "/api/v1/decisions", {}),
        ("GET", "/api/v1/versions", {}),
        (
            "POST",
            "/api/v1/policy/validate",
            {"json": {"content": "rules: [", "format": "yaml"}},
        ),
        ("POST", "/api/v1/policy/test", {"json": _TEST_REQUEST}),
    ],
)
def test_read_only_operations_do_not_change_persistent_state(
    client, policy_dir, method, path, kwargs
):
    response = assert_read_only_request(client, policy_dir, method, path, **kwargs)
    assert response.status_code < 500 or response.status_code in {503}


def test_excluded_reload_route_is_unreachable(client, app):
    assert "/api/v1/policy/reload" not in app.openapi()["paths"]
    assert client.post("/api/v1/policy/reload").status_code == 404
