# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import json

import pytest

from conftest import POLICY


def envelope(response, status, code):
    assert response.status_code == status, response.text
    body = response.json()
    assert body["status"] == status and body["code"] == code
    assert set(body) == {"status", "code", "message", "details"}
    assert response.headers["cache-control"] == "no-store, private"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "access-control-allow-origin" not in response.headers


@pytest.mark.parametrize("method,path", [
    ("GET", "/api/v1/health"), ("GET", "/api/v1/policies"), ("GET", "/openapi.json"),
    ("GET", "/docs"), ("OPTIONS", "/api/v1/policy/test"), ("POST", "/api/v1/policy/validate"),
])
@pytest.mark.parametrize("origin", [
    "null", "https://evil.example", "http://127.0.0.1:8081",
    "https://127.0.0.1:8080", "http://127.0.0.1:8080/evil",
    "http://user@127.0.0.1:8080", "http://127.0.0.1:8080?query",
])
def test_all_surfaces_reject_untrusted_origin(client, method, path, origin):
    envelope(client.request(method, path, headers={"Origin": origin}), 403, "FORBIDDEN")


@pytest.mark.parametrize("host", [
    "evil.example:8080", "localhost:8080", "127.0.0.1", "127.0.0.1:8081",
    "127.0.0.1:8080.evil", "[::1]:8080", "127.0.0.1:8080,evil.example",
])
def test_exact_host_and_port(client, host):
    envelope(client.get("/api/v1/health", headers={"Host": host}), 403, "FORBIDDEN")


@pytest.mark.parametrize("header,value", [
    ("Forwarded", "host=127.0.0.1:8080;for=127.0.0.1"),
    ("X-Forwarded-Host", "127.0.0.1:8080"), ("X-Forwarded-For", "127.0.0.1"),
    ("X-Forwarded-Proto", "http"), ("Sec-Fetch-Site", "cross-site"),
    ("Sec-Fetch-Site", "same-site"), ("Sec-Fetch-Site", "invalid"),
])
def test_proxy_and_fetch_spoofing(client, header, value):
    envelope(client.get("/openapi.json", headers={header: value}), 403, "FORBIDDEN")


@pytest.mark.parametrize("header", ["Authorization", "Proxy-Authorization", "Cookie", "X-Api-Key", "X-AGT-Studio-Token", "X-Access-Token", "X-Auth-Token"])
def test_supplied_credentials_fail_closed(client, header):
    response = client.get("/api/v1/health", headers={header: "private-test-credential"})
    envelope(response, 401, "UNAUTHORIZED")
    assert "private-test-credential" not in response.text


@pytest.mark.parametrize("query", ["token=secret", "access_token=secret", "api_key=secret", "authorization=secret", "studio_token=secret", "agt_studio_token=secret"])
def test_query_credentials_fail_closed(client, query):
    response = client.get(f"/api/v1/health?{query}")
    envelope(response, 401, "UNAUTHORIZED")
    assert "secret" not in response.text


@pytest.mark.parametrize("path", ["/api/v1/policy/validate", "/api/v1/policy/test", "/api/v1/policy/save"])
def test_post_requires_non_simple_header_and_origin(client, path):
    headers = dict(client.headers)
    for missing in ("origin", "x-agt-studio-request"):
        client.headers.pop(missing)
        envelope(client.post(path, json={}), 403, "FORBIDDEN")
        client.headers.update(headers)
    envelope(client.post(path, json={}, headers={"X-AGT-Studio-Request": "0"}), 403, "FORBIDDEN")
    for content_type in ("text/plain", "application/x-www-form-urlencoded", "multipart/form-data"):
        envelope(client.post(path, content="{}", headers={"Content-Type": content_type}), 422, "VALIDATION_ERROR")


def test_preflight_is_checked_not_reflected(client):
    headers = {
        "Access-Control-Request-Method": "POST",
        "Access-Control-Request-Headers": "Content-Type, X-AGT-Studio-Request",
    }
    response = client.options("/api/v1/policy/test", headers=headers)
    assert response.status_code == 204 and response.content == b""
    assert response.headers["access-control-allow-origin"] == "http://127.0.0.1:8080"
    assert "access-control-allow-credentials" not in response.headers
    for replacement in (
        {"Access-Control-Request-Method": "DELETE"},
        {"Access-Control-Request-Headers": "Authorization"},
        {"Access-Control-Request-Headers": "Content-Type"},
        {"Origin": "null"},
    ):
        envelope(client.options("/api/v1/policy/test", headers={**headers, **replacement}), 403, "FORBIDDEN")
    envelope(client.options("/api/v1/policy/reload", headers=headers), 403, "FORBIDDEN")


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/docs/oauth2-redirect", "/api/v1/policy/reload", "/api/v1/events"])
def test_auxiliary_html_and_runtime_control_absent(client, path):
    envelope(client.get(path), 404, "POLICY_NOT_FOUND")
    assert "text/html" not in client.get(path).headers["content-type"]


def test_non_browser_get_and_documented_post(client):
    client.headers.pop("origin")
    assert client.get("/api/v1/health").status_code == 200
    client.headers["origin"] = "http://127.0.0.1:8080"
    assert client.post("/api/v1/policy/validate", json={"content": POLICY, "format": "yaml"}).status_code == 200


@pytest.mark.parametrize("header", ["Host", "Origin", "Sec-Fetch-Site", "Content-Type", "X-AGT-Studio-Request", "Access-Control-Request-Method", "Access-Control-Request-Headers"])
def test_duplicate_security_headers_denied(client, header):
    value = client.headers.get(header, "application/json")
    envelope(client.get("/openapi.json", headers=[(header, value), (header, value)]), 403, "FORBIDDEN")


@pytest.mark.parametrize("fmt", ["yaml", "json"])
def test_save_is_always_forbidden_after_valid_gates(client, policy_root, monkeypatch, fmt, canonical):
    monkeypatch.setenv("AGENTMESH_ENABLE_POLICY_SAVE", "1")
    contract, assertions = canonical
    before = assertions.snapshot_tree(policy_root.parent)
    response = client.post("/api/v1/policy/save", json={
        "id": "new-policy", "format": fmt,
        "content": POLICY if fmt == "yaml" else json.dumps({"name": "new", "rules": []}),
    })
    assertions.assert_error_response(response, contract.load_contract(), "savePolicy", 403, "FORBIDDEN")
    assert assertions.snapshot_tree(policy_root.parent) == before
    assert "AGENTMESH_ENABLE_POLICY_SAVE" not in response.text


def test_validation_error_fields_preserved_without_sensitive_input(client):
    response = client.post("/api/v1/policy/validate", json={"format": "private-secret-format", "content": "sensitive policy"})
    envelope(response, 422, "VALIDATION_ERROR")
    errors = response.json()["details"]["errors"]
    assert errors[0]["loc"] == ["body", "format"] and errors[0]["type"] == "literal_error"
    assert "private-secret-format" not in response.text and "sensitive policy" not in response.text
