# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the policy operation routes: validate, test, save (sections 7.4 - 7.6)."""

from __future__ import annotations

import json
import os
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
        body = resp.json()
        assert body["code"] == "FIXTURE_LOAD_ERROR"
        assert body["message"] == "Could not load fixtures or policies"
        assert body["details"] == {}
        assert "could not parse fixtures" not in json.dumps(body)

    def test_fixture_load_error_only_echoes_explicit_override(
        self, client, monkeypatch, policy_dir
    ):
        leaked_path = str(policy_dir / "internal" / "secret.yaml")

        def _bad_replay(_policy_dir, _fixtures):
            raise FileNotFoundError(leaked_path)

        override = policy_dir / "subset"
        override.mkdir()
        monkeypatch.setattr(policy_ops, "_load_replay", lambda: _bad_replay)
        resp = client.post(
            "/api/v1/policy/test",
            json=dict(_TEST_BODY, policy_dir=str(override)),
        )
        assert resp.status_code == 422
        body = resp.json()
        assert body["details"] == {"policy_dir": str(override)}
        assert leaked_path not in body["message"]

    def test_oversized_fixture_list_is_validation_error(self, client):
        one = {"id": "f", "input": {"action": "read"}, "expected_verdict": "allow"}
        resp = client.post("/api/v1/policy/test", json={"fixtures": [one] * 1001})
        assert resp.status_code == 422
        assert resp.json()["code"] == "VALIDATION_ERROR"

    def test_uses_policy_dir_override(self, client, monkeypatch, policy_dir):
        captured = {}

        def _capturing_replay(policy_dir_arg, _fixtures):
            captured["policy_dir"] = policy_dir_arg
            return _fake_report()

        monkeypatch.setattr(policy_ops, "_load_replay", lambda: _capturing_replay)
        # The override must resolve within the engine policy root, so use a subdirectory
        # of the configured policy directory rather than an unrelated temp path.
        override = policy_dir / "subset"
        override.mkdir()
        body = dict(_TEST_BODY, policy_dir=str(override))
        resp = client.post("/api/v1/policy/test", json=body)
        assert resp.status_code == 200
        assert captured["policy_dir"] == os.path.realpath(str(override))

    def test_policy_dir_override_outside_root_is_rejected(self, client, monkeypatch, tmp_path_factory):
        def _capturing_replay(_policy_dir, _fixtures):
            raise AssertionError("replay must not run for an out-of-root override")

        monkeypatch.setattr(policy_ops, "_load_replay", lambda: _capturing_replay)
        # A directory outside the configured policy root (the engine policy dir is the
        # per-test ``policy_dir`` fixture; this factory dir is a sibling, not a child).
        outside = tmp_path_factory.mktemp("outside_root")
        body = dict(_TEST_BODY, policy_dir=str(outside))
        resp = client.post("/api/v1/policy/test", json=body)
        assert resp.status_code == 422
        assert resp.json()["code"] == "FIXTURE_LOAD_ERROR"

    def test_policy_dir_override_too_long_is_validation_error(self, client):
        # The field is bounded (max_length=1024) so an oversized value is rejected by request
        # validation before any filesystem path operation runs.
        body = dict(_TEST_BODY, policy_dir="x" * 1025)
        resp = client.post("/api/v1/policy/test", json=body)
        assert resp.status_code == 422
        assert resp.json()["code"] == "VALIDATION_ERROR"


class TestTestPolicyWithRealEngine:
    """End-to-end against the real replay engine when agent-compliance is installed."""

    def test_real_replay_round_trip(self, client, policy_dir):
        pytest.importorskip("agent_compliance.policy_test")
        pytest.importorskip("agent_os.policies.evaluator")

        # Isolated policy directory (within the engine policy root) so only the probe
        # policy drives the verdicts and the containment guard accepts the override.
        probe_dir = policy_dir / "probe_policies"
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
        app = create_app(policy_dir=str(missing), enable_policy_save=True)
        local = TestClient(app)
        resp = local.post(
            "/api/v1/policy/save",
            json={"id": "epsilon", "content": _VALID_POLICY_YAML, "format": "yaml"},
        )
        assert resp.status_code == 200
        assert (missing / "epsilon.yaml").exists()

    def test_invalid_content_is_422_and_not_written(self, client, policy_dir):
        # A bare scalar parses but is not a policy mapping, so schema validation fails and the
        # file must never be written (a malformed doc cannot shadow a valid policy on reload).
        resp = client.post(
            "/api/v1/policy/save",
            json={"id": "zeta", "content": "just a string", "format": "yaml"},
        )
        assert resp.status_code == 422
        assert resp.json()["code"] == "POLICY_PARSE_ERROR"
        assert not (policy_dir / "zeta.yaml").exists()

    def test_unparseable_content_is_422_and_not_written(self, client, policy_dir):
        resp = client.post(
            "/api/v1/policy/save",
            json={"id": "eta", "content": "foo: [1, 2", "format": "yaml"},
        )
        assert resp.status_code == 422
        assert resp.json()["code"] == "POLICY_PARSE_ERROR"
        assert not (policy_dir / "eta.yaml").exists()

    def test_oversized_content_is_validation_error(self, client):
        oversized = "name: x\n" + ("#" * (1_048_576 + 1))
        resp = client.post(
            "/api/v1/policy/save",
            json={"id": "theta", "content": oversized, "format": "yaml"},
        )
        assert resp.status_code == 422
        assert resp.json()["code"] == "VALIDATION_ERROR"

    def test_save_replaces_cross_format_sibling(self, client, policy_dir):
        # Saving "iota" as YAML then re-saving as JSON must leave exactly one file so the
        # listing never shows a shadowed duplicate.
        client.post(
            "/api/v1/policy/save",
            json={"id": "iota", "content": _VALID_POLICY_YAML, "format": "yaml"},
        )
        client.post(
            "/api/v1/policy/save",
            json={"id": "iota", "content": _VALID_POLICY_JSON, "format": "json"},
        )
        assert not (policy_dir / "iota.yaml").exists()
        assert (policy_dir / "iota.json").exists()
        items = client.get("/api/v1/policies").json()["items"]
        assert [i["id"] for i in items].count("iota") == 1


# ── /policy/save write-path gate (AGENTMESH_ENABLE_POLICY_SAVE) ───────────────
class TestSavePolicyGate:
    """The single write endpoint is disabled by default and opts in via env or argument.

    Keeps the reference adapter from accepting an unauthenticated policy mutation out of the
    box; a deployment enables it once it fronts the engine with its own auth (contract 4).
    """

    _SAVE_ENV = "AGENTMESH_ENABLE_POLICY_SAVE"

    def _client(self, policy_dir, **kwargs):
        from fastapi.testclient import TestClient

        from agentmesh.engine_api import create_app

        return TestClient(create_app(policy_dir=str(policy_dir), **kwargs))

    def _post_save(self, client):
        return client.post(
            "/api/v1/policy/save",
            json={"id": "gated", "content": _VALID_POLICY_YAML, "format": "yaml"},
        )

    def test_disabled_by_default_returns_403_and_does_not_write(self, policy_dir, monkeypatch):
        monkeypatch.delenv(self._SAVE_ENV, raising=False)
        client = self._client(policy_dir)  # no flag, no env -> disabled
        resp = self._post_save(client)
        assert resp.status_code == 403
        body = resp.json()
        assert body["code"] == "FORBIDDEN"
        assert body["details"]["env"] == self._SAVE_ENV
        assert not (policy_dir / "gated.yaml").exists()

    def test_enabled_by_argument(self, policy_dir, monkeypatch):
        monkeypatch.delenv(self._SAVE_ENV, raising=False)
        client = self._client(policy_dir, enable_policy_save=True)
        resp = self._post_save(client)
        assert resp.status_code == 200
        assert (policy_dir / "gated.yaml").exists()

    @pytest.mark.parametrize("value", ["1", "true", "TRUE", "yes", "on"])
    def test_enabled_by_truthy_env(self, policy_dir, monkeypatch, value):
        monkeypatch.setenv(self._SAVE_ENV, value)
        client = self._client(policy_dir)  # argument omitted -> defers to env
        assert self._post_save(client).status_code == 200

    @pytest.mark.parametrize("value", ["0", "false", "no", "off", ""])
    def test_falsy_env_stays_disabled(self, policy_dir, monkeypatch, value):
        monkeypatch.setenv(self._SAVE_ENV, value)
        client = self._client(policy_dir)
        assert self._post_save(client).status_code == 403

    def test_argument_false_overrides_truthy_env(self, policy_dir, monkeypatch):
        monkeypatch.setenv(self._SAVE_ENV, "1")
        client = self._client(policy_dir, enable_policy_save=False)
        assert self._post_save(client).status_code == 403

    def test_argument_true_overrides_falsy_env(self, policy_dir, monkeypatch):
        monkeypatch.setenv(self._SAVE_ENV, "0")
        client = self._client(policy_dir, enable_policy_save=True)
        assert self._post_save(client).status_code == 200

    def test_disabled_save_short_circuits_before_validation(self, policy_dir, monkeypatch):
        # A disabled engine rejects with 403 even when the content is invalid, proving the
        # gate runs before any schema work (no POLICY_PARSE_ERROR leaks through).
        monkeypatch.delenv(self._SAVE_ENV, raising=False)
        client = self._client(policy_dir)
        resp = client.post(
            "/api/v1/policy/save",
            json={"id": "gated", "content": "just a string", "format": "yaml"},
        )
        assert resp.status_code == 403
        assert resp.json()["code"] == "FORBIDDEN"
