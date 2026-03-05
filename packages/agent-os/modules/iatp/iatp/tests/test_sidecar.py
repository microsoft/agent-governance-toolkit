# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Integration tests for the IATP Sidecar.
"""
import pytest
from fastapi.testclient import TestClient

from iatp.models import (
    AgentCapabilities,
    CapabilityManifest,
    PrivacyContract,
    RetentionPolicy,
    ReversibilityLevel,
    TrustLevel,
)
from iatp.sidecar import create_sidecar


@pytest.fixture
def trusted_manifest():
    """Create a trusted agent manifest for testing."""
    return CapabilityManifest(
        agent_id="test-trusted-agent",
        agent_version="1.0.0",
        trust_level=TrustLevel.VERIFIED_PARTNER,
        capabilities=AgentCapabilities(
            idempotency=True,
            reversibility=ReversibilityLevel.FULL,
            undo_window="24h",
            sla_latency="1000ms"
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.EPHEMERAL,
            storage_location="us-east",
            human_review=False
        )
    )


@pytest.fixture
def untrusted_manifest():
    """Create an untrusted agent manifest for testing."""
    return CapabilityManifest(
        agent_id="test-untrusted-agent",
        agent_version="0.1.0",
        trust_level=TrustLevel.UNTRUSTED,
        capabilities=AgentCapabilities(
            idempotency=False,
            reversibility=ReversibilityLevel.NONE
        ),
        privacy_contract=PrivacyContract(
            retention=RetentionPolicy.FOREVER,
            storage_location="unknown",
            human_review=True
        )
    )


def test_health_check(trusted_manifest):
    """Test the health check endpoint."""
    sidecar = create_sidecar(
        agent_url="http://localhost:9999",
        manifest=trusted_manifest
    )
    client = TestClient(sidecar.app)

    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["agent_id"] == "test-trusted-agent"


def test_get_manifest(trusted_manifest):
    """Test getting the capability manifest."""
    sidecar = create_sidecar(
        agent_url="http://localhost:9999",
        manifest=trusted_manifest
    )
    client = TestClient(sidecar.app)

    response = client.get("/.well-known/agent-manifest")
    assert response.status_code == 200
    data = response.json()
    assert data["agent_id"] == "test-trusted-agent"
    assert data["trust_level"] == "verified_partner"
    assert data["capabilities"]["idempotency"] is True


def test_invalid_json_payload(trusted_manifest):
    """Test that invalid JSON is rejected."""
    sidecar = create_sidecar(
        agent_url="http://localhost:9999",
        manifest=trusted_manifest
    )
    client = TestClient(sidecar.app)

    response = client.post(
        "/proxy",
        content="invalid json",
        headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 400
    data = response.json()
    assert "Invalid JSON" in data["error"]


def test_blocked_credit_card_permanent_storage(untrusted_manifest):
    """Test that credit cards are blocked for permanent storage."""
    sidecar = create_sidecar(
        agent_url="http://localhost:9999",
        manifest=untrusted_manifest
    )
    client = TestClient(sidecar.app)

    response = client.post(
        "/proxy",
        json={
            "task": "purchase",
            "card": "4532-0151-1283-0366"  # Valid test card
        }
    )
    assert response.status_code == 403
    data = response.json()
    assert "Privacy Violation" in data["error"]
    assert data["blocked"] is True


def test_warning_without_override(untrusted_manifest):
    """Test that untrusted agents trigger warnings."""
    sidecar = create_sidecar(
        agent_url="http://localhost:9999",
        manifest=untrusted_manifest
    )
    client = TestClient(sidecar.app)

    response = client.post(
        "/proxy",
        json={"task": "test", "data": {}}
    )
    assert response.status_code == 449
    data = response.json()
    assert "warning" in data
    assert "requires_override" in data
    assert data["requires_override"] is True


def test_trace_id_injection(trusted_manifest):
    """Test that trace IDs are properly handled."""
    sidecar = create_sidecar(
        agent_url="http://localhost:9999",
        manifest=trusted_manifest
    )
    client = TestClient(sidecar.app)

    # Provide a custom trace ID
    custom_trace_id = "custom-trace-123"
    response = client.post(
        "/proxy",
        json={"task": "test"},
        headers={"X-Agent-Trace-ID": custom_trace_id}
    )

    # Even if backend fails, trace ID should be in error response
    data = response.json()
    assert "trace_id" in data
