# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for governance sidecar application."""

from __future__ import annotations

import os
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
            from agentmesh.server.sidecar import create_sidecar_app, _load_policies
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
