# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for governance sidecar application."""

from __future__ import annotations

import hashlib
import json
import os
import sys
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    """Create a test client for the sidecar app."""
    from agentmesh.server.sidecar import create_sidecar_app

    app = create_sidecar_app()
    return TestClient(app)


class TestHealthProbes:
    """Test sidecar health and readiness endpoints."""

    def test_health(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["component"] == "governance-sidecar"

    def test_ready(self, client):
        resp = client.get("/ready")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ready"
        assert "policies_loaded" in data

    def test_healthz(self, client):
        resp = client.get("/healthz")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    def test_readyz(self, client):
        resp = client.get("/readyz")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ready"


class TestMetricsEndpoint:
    """Test sidecar Prometheus metrics endpoint."""

    def test_metrics_returns_200(self, client):
        resp = client.get("/metrics")
        assert resp.status_code == 200

    def test_metrics_content_type(self, client):
        resp = client.get("/metrics")
        assert "text/plain" in resp.headers["content-type"]

    def test_metrics_contains_uptime(self, client):
        resp = client.get("/metrics")
        assert "agt_sidecar_uptime_seconds" in resp.text

    def test_metrics_has_help_lines(self, client):
        resp = client.get("/metrics")
        assert "# HELP" in resp.text
        assert "# TYPE" in resp.text


class TestPolicyEvaluation:
    """Test sidecar policy evaluation endpoint."""

    def test_evaluate_returns_decision(self, client):
        resp = client.post(
            "/api/v1/policy/evaluate",
            json={
                "agent_did": "did:mesh:test-agent",
                "action": "file.read",
                "resource": "/data/file.txt",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "decision" in data

    def test_evaluate_with_context(self, client):
        resp = client.post(
            "/api/v1/policy/evaluate",
            json={
                "agent_did": "did:mesh:test-agent",
                "action": "shell.execute",
                "resource": "/bin/bash",
                "context": {"ring": 3, "trust_score": 400},
            },
        )
        assert resp.status_code == 200

    def test_evaluate_missing_required_fields(self, client):
        resp = client.post(
            "/api/v1/policy/evaluate",
            json={"action": "file.read"},
        )
        assert resp.status_code == 422  # Validation error

    def test_list_policies(self, client):
        resp = client.get("/api/v1/policies")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_loaded" in data
        assert "policy_dir" in data

    def test_reload_policies(self, client):
        resp = client.post("/api/v1/policy/reload")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "reloaded"


class TestPolicyWithFiles:
    """Test sidecar with actual policy files loaded."""

    @pytest.fixture
    def policy_client(self, tmp_path):
        """Create a client with policies loaded from a temp directory."""
        policy_file = tmp_path / "test-policy.yaml"
        policy_file.write_text(
            "name: test-policy\n"
            "version: '1.0'\n"
            "rules:\n"
            "  - name: deny-shell\n"
            "    condition: \"action == 'shell.execute'\"\n"
            "    action: deny\n"
            "    reason: 'Shell execution blocked'\n"
        )
        with patch.dict(os.environ, {"AGT_POLICY_DIR": str(tmp_path)}):
            from agentmesh.server.sidecar import _load_policies, create_sidecar_app

            app = create_sidecar_app()
            _load_policies()
            return TestClient(app)

    def test_policy_loaded(self, policy_client):
        resp = policy_client.get("/api/v1/policies")
        data = resp.json()
        assert data["total_loaded"] >= 1

    def test_evaluate_with_loaded_policy(self, policy_client):
        resp = policy_client.post(
            "/api/v1/policy/evaluate",
            json={
                "agent_did": "did:mesh:test-agent",
                "action": "shell.execute",
                "resource": "/bin/bash",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["decision"] == "deny"


class TestOpenAPIDocs:
    """Test sidecar OpenAPI docs endpoint."""

    def test_docs_available(self, client):
        resp = client.get("/docs")
        assert resp.status_code == 200

    def test_openapi_json(self, client):
        resp = client.get("/openapi.json")
        assert resp.status_code == 200
        data = resp.json()
        assert "AGT Governance Sidecar" in data["info"]["title"]


@pytest.fixture
def generation_client(tmp_path, monkeypatch):
    from agentmesh.server import sidecar

    monkeypatch.setenv("AGT_POLICY_DIR", str(tmp_path))
    monkeypatch.setattr(sidecar, "_policy_state", sidecar._policy_state)
    monkeypatch.setattr(sidecar, "_policy_dir", sidecar._policy_dir)
    sidecar._load_policies()
    return TestClient(sidecar.create_sidecar_app())


def test_generation_records_success_and_rejected_files(generation_client, tmp_path, caplog):
    (tmp_path / "allow.yaml").write_text("name: allow\nrules: []\n", encoding="utf-8")
    (tmp_path / "deny.json").write_text('{"name": "deny", "rules": []}', encoding="utf-8")
    rejected = tmp_path / "broken.yaml"
    rejected.write_text("rules: [", encoding="utf-8")
    with caplog.at_level("INFO", logger="agentmesh.server.sidecar"):
        response = generation_client.post("/api/v1/policy/reload").json()
    manifest = generation_client.get("/api/v1/policies").json()
    assert response["policies_discovered"] == 3
    assert response["policies_loaded"] == 2
    assert response["policies_failed"] == 1
    assert response["policy_set_status"] == "degraded"
    assert response["policy_set_id"] in caplog.text
    assert "rules: [" not in caplog.text
    failed = next(f for f in manifest["files"] if f["name"] == "broken.yaml")
    assert failed["status"] == "failed"
    assert failed["error_type"]
    assert failed["content_sha256"] == hashlib.sha256(rejected.read_bytes()).hexdigest()
    canonical = json.dumps(
        {"directory_status": manifest["directory_status"], "files": manifest["files"]},
        sort_keys=True,
        separators=(",", ":"),
    )
    assert response["policy_set_id"] == "sha256:" + hashlib.sha256(canonical.encode()).hexdigest()
    decision = generation_client.post(
        "/api/v1/policy/evaluate",
        json={"agent_did": "did:mesh:test", "action": "read"},
    ).json()
    assert decision["policy_set_id"] == response["policy_set_id"]
    assert decision["policy_set_status"] == "degraded"
    assert generation_client.get("/ready").json()["policy_set_id"] == response["policy_set_id"]


def test_generation_identity_tracks_failed_content_and_absence(generation_client, tmp_path):
    def reload_id():
        return generation_client.post("/api/v1/policy/reload").json()["policy_set_id"]

    empty = reload_id()
    assert reload_id() == empty
    rejected = tmp_path / "broken.json"
    rejected.write_text("{", encoding="utf-8")
    first = reload_id()
    assert first != empty
    assert reload_id() == first
    rejected.write_text("{ ", encoding="utf-8")
    assert reload_id() != first
    rejected.unlink()
    assert reload_id() == empty


def test_unavailable_directory_is_not_complete_empty_load(generation_client, tmp_path, monkeypatch):
    complete = generation_client.get("/api/v1/policies").json()
    monkeypatch.setenv("AGT_POLICY_DIR", str(tmp_path / "absent"))
    degraded = generation_client.post("/api/v1/policy/reload").json()
    assert complete["policy_set_status"] == "complete"
    assert degraded["policy_set_status"] == "degraded"
    assert degraded["directory_status"] == "unavailable"
    assert degraded["policies_discovered"] == degraded["policies_failed"] == 0
    assert complete["policy_set_id"] != degraded["policy_set_id"]


def test_unreadable_file_is_recorded(generation_client, tmp_path):
    # A directory with a policy extension is discovered but cannot be read as a file.
    (tmp_path / "unreadable.yaml").mkdir()
    generation_client.post("/api/v1/policy/reload")
    manifest = generation_client.get("/api/v1/policies").json()
    assert manifest["policies_failed"] == 1
    assert manifest["files"][0]["content_sha256"] is None
    assert manifest["files"][0]["error_type"]


@pytest.mark.skipif(sys.platform != "linux", reason="Undecodable byte filename test requires Linux")
def test_generation_handles_undecodable_filenames(generation_client, tmp_path, caplog):
    content = b"name: unusual\nrules: []\n"
    names = [b"bad\xff.yaml", b"bad\\udcff.yaml", "café.yaml".encode()]
    for name in names:
        with open(os.fsencode(tmp_path) + b"/" + name, "wb") as policy:
            policy.write(content)

    # Entering the client runs startup, including policy loading and JSON logging.
    with caplog.at_level("INFO", logger="agentmesh.server.sidecar"), generation_client:
        response = generation_client.get("/api/v1/policies")
        assert response.status_code == 200
        manifest = response.json()
        assert manifest["policies_loaded"] == 3
        assert {entry["name"] for entry in manifest["files"]} == {
            "bad\\udcff.yaml",
            "bad\\\\udcff.yaml",
            "caf\\xe9.yaml",
        }
        assert all(
            entry["content_sha256"] == hashlib.sha256(content).hexdigest()
            for entry in manifest["files"]
        )
        reload = generation_client.post("/api/v1/policy/reload")
        assert reload.status_code == 200
        assert reload.json()["policy_set_id"] == manifest["policy_set_id"]
        assert manifest["policy_set_id"] in caplog.text


def test_serialization_failure_preserves_published_state(generation_client, tmp_path, monkeypatch):
    from agentmesh.server import sidecar

    previous = sidecar._policy_state
    (tmp_path / "new.yaml").write_text("name: new\nrules: []\n", encoding="utf-8")

    def fail_serialization(self, *args, **kwargs):
        raise ValueError("manifest serialization failed")

    monkeypatch.setattr(sidecar.PolicyLoadGeneration, "model_dump_json", fail_serialization)
    with pytest.raises(ValueError, match="manifest serialization failed"):
        generation_client.post("/api/v1/policy/reload")
    assert sidecar._policy_state is previous
    assert generation_client.get("/ready").json()["policy_set_id"] == previous[1].policy_set_id


def test_evaluation_keeps_its_generation_when_reload_publishes(
    generation_client, tmp_path, monkeypatch
):
    from agentmesh.server import sidecar

    policy = tmp_path / "policy.yaml"
    policy.write_text(
        "name: guard\nagents: ['*']\nrules:\n"
        "- name: block\n  condition: \"action == 'send'\"\n  action: deny\n",
        encoding="utf-8",
    )
    old_generation = sidecar._load_policies()
    old_engine = sidecar._policy_state[0]
    evaluate = old_engine.evaluate

    def evaluate_while_reloading(*args, **kwargs):
        policy.write_text(
            "name: guard\nagents: ['*']\nrules:\n"
            "- name: permit\n  condition: \"action == 'send'\"\n  action: allow\n",
            encoding="utf-8",
        )
        sidecar._load_policies()
        return evaluate(*args, **kwargs)

    monkeypatch.setattr(old_engine, "evaluate", evaluate_while_reloading)
    result = generation_client.post(
        "/api/v1/policy/evaluate",
        json={"agent_did": "did:mesh:test", "action": "send"},
    ).json()
    assert result["decision"] == "deny"
    assert result["matched_rule"] == "block"
    assert result["policy_set_id"] == old_generation.policy_set_id
    assert sidecar._policy_state[1].policy_set_id != old_generation.policy_set_id
    next_result = generation_client.post(
        "/api/v1/policy/evaluate",
        json={"agent_did": "did:mesh:test", "action": "send"},
    ).json()
    assert next_result["decision"] == "allow", next_result
    assert next_result["matched_rule"] == "permit"
    assert next_result["policy_set_id"] == sidecar._policy_state[1].policy_set_id
