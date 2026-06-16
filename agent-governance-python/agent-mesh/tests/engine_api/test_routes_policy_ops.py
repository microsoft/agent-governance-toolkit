# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the policy operation routes: validate, test, save (sections 7.4 - 7.6)."""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from agentmesh.engine_api.routes import policy_ops  # noqa: E402

_VALID_POLICY_YAML = """\
version: "1.0"
name: Valid Policy
rules:
  - name: allow-reads
    condition:
      field: action
      operator: eq
      value: read
    action: allow
"""

_VALID_POLICY_JSON = json.dumps(
    {
        "version": "1.0",
        "name": "Valid JSON Policy",
        "rules": [
            {"name": "r", "condition": {"field": "a", "operator": "eq", "value": 1}, "action": "allow"}
        ],
    }
)


# ── /policy/validate ─────────────────────────────────────────────────────────
class TestValidatePolicy:
    def test_valid_yaml(self, client):
        resp = client.post(
            "/api/v1/policy/validate", json={"content": _VALID_POLICY_YAML, "format": "yaml"}
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["valid"] is True
        assert body["errors"] == []

    def test_valid_json(self, client):
        resp = client.post(
            "/api/v1/policy/validate", json={"content": _VALID_POLICY_JSON, "format": "json"}
        )
        assert resp.status_code == 200
        assert resp.json()["valid"] is True

    def test_parseable_but_lint_failing_is_200_invalid(self, client):
        # A bare scalar parses as YAML but is not a policy mapping -> lint error, not parse error.
        resp = client.post(
            "/api/v1/policy/validate", json={"content": "just a string", "format": "yaml"}
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["valid"] is False
        assert len(body["errors"]) >= 1
        assert body["errors"][0]["message"]

    def test_malformed_yaml_is_parse_error(self, client):
        resp = client.post(
            "/api/v1/policy/validate", json={"content": "foo: [1, 2", "format": "yaml"}
        )
        assert resp.status_code == 422
        assert resp.json()["code"] == "POLICY_PARSE_ERROR"

    def test_malformed_json_is_parse_error(self, client):
        resp = client.post(
            "/api/v1/policy/validate", json={"content": "{not valid json", "format": "json"}
        )
        assert resp.status_code == 422
        assert resp.json()["code"] == "POLICY_PARSE_ERROR"


# ── /policy/test ─────────────────────────────────────────────────────────────
def _fake_report():
    result = SimpleNamespace(
        fixture_id="f1",
        passed=True,
        expected_verdict="allow",
        actual_verdict="allow",
        expected_rule="allow-reads",
        actual_rule="allow-reads",
        fixture_path="f1.json",
        resolution_metadata={"strategy": "first-match"},
    )
    return SimpleNamespace(total=1, passed=1, failed=0, results=[result])


_TEST_BODY = {
    "fixtures": [
        {"id": "f1", "input": {"action": "read"}, "expected_verdict": "allow", "expected_rule": "allow-reads"}
    ]
}


class TestTestPolicyWithFakeEngine:
    def test_success_path(self, client, monkeypatch):
        monkeypatch.setattr(policy_ops, "_load_replay", lambda: (lambda p, f: _fake_report()))
        resp = client.post("/api/v1/policy/test", json=_TEST_BODY)
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 1
        assert body["passed"] == 1
        assert body["failed"] == 0
        assert body["results"][0]["fixture_id"] == "f1"
        assert body["results"][0]["resolution_metadata"] == {"strategy": "first-match"}

    def test_engine_unavailable_returns_503(self, client, monkeypatch):
        def _raise_import_error():
            raise ImportError("agent_compliance not installed")

        monkeypatch.setattr(policy_ops, "_load_replay", _raise_import_error)
        resp = client.post("/api/v1/policy/test", json=_TEST_BODY)
        assert resp.status_code == 503
        assert resp.json()["code"] == "ENGINE_UNAVAILABLE"

    def test_fixture_load_error_returns_422(self, client, monkeypatch):
        def _bad_replay(_policy_dir, _fixtures):
            raise ValueError("could not parse fixtures")

        monkeypatch.setattr(policy_ops, "_load_replay", lambda: _bad_replay)
        resp = client.post("/api/v1/policy/test", json=_TEST_BODY)
        assert resp.status_code == 422
        assert resp.json()["code"] == "FIXTURE_LOAD_ERROR"

    def test_uses_policy_dir_override(self, client, monkeypatch, tmp_path):
        captured = {}

        def _capturing_replay(policy_dir, _fixtures):
            captured["policy_dir"] = policy_dir
            return _fake_report()

        monkeypatch.setattr(policy_ops, "_load_replay", lambda: _capturing_replay)
        body = dict(_TEST_BODY, policy_dir=str(tmp_path))
        resp = client.post("/api/v1/policy/test", json=body)
        assert resp.status_code == 200
        assert captured["policy_dir"] == str(tmp_path)


class TestTestPolicyWithRealEngine:
    """End-to-end against the real replay engine when agent-compliance is installed."""

    def test_real_replay_round_trip(self, client, tmp_path):
        pytest.importorskip("agent_compliance.policy_test")
        pytest.importorskip("agent_os.policies.evaluator")

        # Isolated policy directory so only the probe policy drives the verdicts.
        probe_dir = tmp_path / "probe_policies"
        probe_dir.mkdir()
        (probe_dir / "probe.yaml").write_text(
            'version: "1.0"\n'
            "name: probe\n"
            "rules:\n"
            "  - name: deny-danger\n"
            "    condition:\n"
            "      field: action\n"
            "      operator: eq\n"
            "      value: dangerous\n"
            "    action: deny\n"
            "    priority: 100\n"
            "defaults:\n"
            "  action: allow\n",
            encoding="utf-8",
        )

        resp = client.post(
            "/api/v1/policy/test",
            json={
                "policy_dir": str(probe_dir),
                "fixtures": [
                    {
                        "id": "f-deny",
                        "input": {"action": "dangerous"},
                        "expected_verdict": "deny",
                        "expected_rule": "deny-danger",
                    },
                    {"id": "f-allow", "input": {"action": "safe"}, "expected_verdict": "allow"},
                ],
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["total"] == 2
        assert body["passed"] == 2
        assert body["failed"] == 0


# ── /policy/save ─────────────────────────────────────────────────────────────
class TestSavePolicy:
    def test_save_creates_file_and_returns_version(self, client, policy_dir):
        resp = client.post(
            "/api/v1/policy/save",
            json={"id": "gamma", "content": _VALID_POLICY_YAML, "format": "yaml"},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["id"] == "gamma"
        assert body["saved_at"]
        assert len(body["version"]) == 16
        assert (policy_dir / "gamma.yaml").exists()

    def test_saved_policy_appears_in_listing(self, client):
        client.post(
            "/api/v1/policy/save",
            json={"id": "delta", "content": _VALID_POLICY_JSON, "format": "json"},
        )
        body = client.get("/api/v1/policies").json()
        assert "delta" in [i["id"] for i in body["items"]]

    def test_invalid_id_is_validation_error(self, client):
        resp = client.post(
            "/api/v1/policy/save",
            json={"id": "Bad ID!", "content": _VALID_POLICY_YAML, "format": "yaml"},
        )
        assert resp.status_code == 422
        assert resp.json()["code"] == "VALIDATION_ERROR"

    def test_save_to_missing_directory_creates_it(self, tmp_path):
        from fastapi.testclient import TestClient

        from agentmesh.engine_api import create_app

        missing = tmp_path / "not_yet"
        app = create_app(policy_dir=str(missing))
        local = TestClient(app)
        resp = local.post(
            "/api/v1/policy/save",
            json={"id": "epsilon", "content": _VALID_POLICY_YAML, "format": "yaml"},
        )
        assert resp.status_code == 200
        assert (missing / "epsilon.yaml").exists()
