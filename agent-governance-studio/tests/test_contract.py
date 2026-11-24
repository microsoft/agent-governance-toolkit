# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import time

import pytest

from conftest import POLICY


def test_full_metadata_and_exact_read_only_projection(client, app, canonical):
    contract, _ = canonical
    baseline = contract.operation_map(contract.load_contract())
    actual = contract.operation_map(client.get("/openapi.json").json())
    assert len(actual) == len(baseline) == 12
    for name, operation in baseline.items():
        assert contract.operation_key(actual[name]) == contract.operation_key(operation)
        assert contract.capability_flags(actual[name]) == contract.capability_flags(operation)
    assert set(app.read_only_operations) == {
        name for name, operation in baseline.items() if not contract.capability_flags(operation)["runtime_mutating"]
    }
    assert len(app.read_only_operations) == 11
    assert client.get("/openapi.json").json()["openapi"] == "3.1.0"


@pytest.mark.parametrize("path,operation_id", [
    ("/api/v1/health", "getHealth"), ("/api/v1/versions", "getVersions"),
    ("/api/v1/policies", "listPolicies"), ("/api/v1/policies/alpha", "getPolicy"),
    ("/api/v1/audit/log", "getAuditLog"), ("/api/v1/trust/scores", "getTrustScores"),
    ("/api/v1/trust/graph", "getTrustGraph"), ("/api/v1/agents", "listAgents"),
    ("/api/v1/decisions", "listDecisions"),
])
def test_real_read_routes_canonical_and_persistent_state_unchanged(client, policy_root, canonical, path, operation_id):
    contract, assertions = canonical
    response = assertions.assert_read_only_request(client, policy_root.parent, "GET", path)
    assertions.assert_contract_response(response, contract.load_contract(), operation_id, 200)


@pytest.mark.parametrize("content,fmt,status,code", [
    (POLICY, "yaml", 200, None), ('{"name":"JSON","rules":[]}', "json", 200, None),
    ("rules: [", "yaml", 422, "POLICY_PARSE_ERROR"), ('{"rules":', "json", 422, "POLICY_PARSE_ERROR"),
])
def test_real_validation_semantics(client, canonical, content, fmt, status, code):
    contract, assertions = canonical
    response = client.post("/api/v1/policy/validate", json={"content": content, "format": fmt})
    if code:
        assertions.assert_error_response(response, contract.load_contract(), "validatePolicy", status, code)
    else:
        result = assertions.assert_contract_response(response, contract.load_contract(), "validatePolicy", status)
        assert result == {"valid": True, "errors": []}


def test_real_native_replay_success_and_cleanup(client, app, policy_root, canonical):
    contract, assertions = canonical
    before = assertions.snapshot_tree(policy_root.parent)
    response = client.post("/api/v1/policy/test", json={
        "policy_dir": str(policy_root / "replay"),
        "fixtures": [{"id": "allow-safe", "input": {"action": "read"}, "expected_verdict": "allow"}],
    })
    result = assertions.assert_contract_response(response, contract.load_contract(), "testPolicy", 200)
    assert result["total"] == result["passed"] == 1 and result["failed"] == 0
    assert not app.workers.active
    assert assertions.snapshot_tree(policy_root.parent) == before


@pytest.mark.parametrize("query", ["page=0", "limit=0", "limit=101", "page=secret-invalid-value"])
def test_pagination_errors_preserve_canonical_semantics(client, canonical, query):
    contract, assertions = canonical
    response = client.get("/api/v1/policies?" + query)
    assertions.assert_error_response(response, contract.load_contract(), "listPolicies", 422, "VALIDATION_ERROR")
    assert "secret-invalid-value" not in response.text


def test_server_lifetime_uptime_inventory_and_versions(client, policy_root):
    first = client.get("/api/v1/health").json()
    versions = client.get("/api/v1/versions").json()
    page = client.get("/api/v1/policies?page=1&limit=1").json()
    detail = client.get("/api/v1/policies/alpha").json()
    (policy_root / "alpha.yaml").write_text("name: externally changed\nrules: []\n", encoding="utf-8")
    (policy_root / "extra.yaml").write_text(POLICY, encoding="utf-8")
    time.sleep(0.05)
    second = client.get("/api/v1/health").json()
    assert second["uptime_seconds"] > first["uptime_seconds"] + 0.05
    assert client.get("/api/v1/versions").json() == versions
    assert client.get("/api/v1/policies?page=1&limit=1").json() == page
    assert client.get("/api/v1/policies/alpha").json() == detail
    assert detail["content"] == POLICY and detail["rules_count"] == 1
    assert client.get("/api/v1/policies?page=2&limit=1").json()["items"][0]["id"] == "beta"
