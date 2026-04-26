# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for managed identity adapters (Azure, AWS, GCP).

All cloud metadata endpoints are mocked — no real cloud calls are made.
"""

import json
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
from unittest.mock import patch, MagicMock

import pytest

from agentmesh.exceptions import IdentityError
from agentmesh.identity.managed_identity import (
    ManagedIdentityAdapter,
    EntraManagedIdentity,
    AWSIAMIdentity,
    GCPWorkloadIdentity,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

VALID_DID = "did:mesh:abc123"
FAKE_JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature_placeholder"


class _FakeHandler(BaseHTTPRequestHandler):
    """Minimal HTTP handler that returns pre-configured responses."""

    # Class-level response map: path-prefix → (status, body-dict | str)
    responses: dict = {}

    def do_GET(self, method="GET"):  # noqa: N802
        path = self.path.split("?")[0]
        for prefix, (status, body) in self.responses.items():
            if path.startswith(prefix):
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                payload = json.dumps(body) if isinstance(body, dict) else body
                self.wfile.write(payload.encode())
                return
        self.send_response(404)
        self.end_headers()

    def do_PUT(self):  # noqa: N802
        # AWS IMDSv2 token endpoint
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"fake-imds-token")

    def log_message(self, format, *args):
        pass  # suppress noisy logs during tests


def _start_fake_server(responses: dict) -> tuple[HTTPServer, str]:
    """Start a local HTTP server with canned responses."""
    _FakeHandler.responses = responses
    server = HTTPServer(("127.0.0.1", 0), _FakeHandler)
    port = server.server_address[1]
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, f"http://127.0.0.1:{port}"


# ---------------------------------------------------------------------------
# ManagedIdentityAdapter (abstract base)
# ---------------------------------------------------------------------------

class TestManagedIdentityAdapterBase:
    """Tests for the abstract base class behaviour."""

    def test_invalid_did_raises(self):
        with pytest.raises(IdentityError, match="Invalid agent DID"):
            EntraManagedIdentity(agent_did="not-a-did")

    def test_empty_did_raises(self):
        with pytest.raises(IdentityError, match="Invalid agent DID"):
            EntraManagedIdentity(agent_did="")

    def test_validate_token_structural_ok(self):
        adapter = EntraManagedIdentity(agent_did=VALID_DID)
        result = adapter.validate_token(FAKE_JWT)
        assert result["valid"] is True
        assert result["agent_did"] == VALID_DID

    def test_validate_token_empty_raises(self):
        adapter = EntraManagedIdentity(agent_did=VALID_DID)
        with pytest.raises(IdentityError, match="non-empty string"):
            adapter.validate_token("")

    def test_validate_token_non_jwt_raises(self):
        adapter = EntraManagedIdentity(agent_did=VALID_DID)
        with pytest.raises(IdentityError, match="valid JWT"):
            adapter.validate_token("not-a-jwt")

    def test_get_agent_mapping_base(self):
        adapter = EntraManagedIdentity(agent_did=VALID_DID)
        mapping = adapter.get_agent_mapping()
        assert mapping["agent_did"] == VALID_DID
        assert "provider" in mapping

    def test_token_caching(self):
        adapter = EntraManagedIdentity(agent_did=VALID_DID)
        adapter._cache_token("scope1", "tok1", ttl=9999)
        assert adapter._get_cached_token("scope1") == "tok1"
        assert adapter._get_cached_token("scope2") is None

    def test_token_cache_expiry(self):
        adapter = EntraManagedIdentity(agent_did=VALID_DID)
        adapter._cache_token("scope1", "tok1", ttl=0)
        assert adapter._get_cached_token("scope1") is None


# ---------------------------------------------------------------------------
# Azure Entra Managed Identity
# ---------------------------------------------------------------------------

class TestEntraManagedIdentity:
    """Tests for the Azure Managed Identity adapter."""

    def test_get_token_success(self):
        responses = {
            "/metadata/identity/oauth2/token": (
                200,
                {"access_token": FAKE_JWT, "expires_in": "3600"},
            ),
        }
        server, base_url = _start_fake_server(responses)
        try:
            adapter = EntraManagedIdentity(
                agent_did=VALID_DID, imds_url=f"{base_url}/metadata/identity/oauth2/token"
            )
            token = adapter.get_token()
            assert token == FAKE_JWT
        finally:
            server.shutdown()

    def test_get_token_with_client_id(self):
        responses = {
            "/metadata/identity/oauth2/token": (
                200,
                {"access_token": FAKE_JWT, "expires_in": "600"},
            ),
        }
        server, base_url = _start_fake_server(responses)
        try:
            adapter = EntraManagedIdentity(
                agent_did=VALID_DID,
                client_id="my-client-id",
                imds_url=f"{base_url}/metadata/identity/oauth2/token",
            )
            token = adapter.get_token()
            assert token == FAKE_JWT
        finally:
            server.shutdown()

    def test_get_token_failure_raises(self):
        adapter = EntraManagedIdentity(
            agent_did=VALID_DID, imds_url="http://127.0.0.1:1/nonexistent"
        )
        with pytest.raises(IdentityError, match="Failed to acquire Azure token"):
            adapter.get_token()

    def test_get_token_missing_access_token(self):
        responses = {
            "/metadata/identity/oauth2/token": (200, {"error": "no token"}),
        }
        server, base_url = _start_fake_server(responses)
        try:
            adapter = EntraManagedIdentity(
                agent_did=VALID_DID, imds_url=f"{base_url}/metadata/identity/oauth2/token"
            )
            with pytest.raises(IdentityError, match="access_token"):
                adapter.get_token()
        finally:
            server.shutdown()

    def test_validate_token_includes_provider(self):
        adapter = EntraManagedIdentity(agent_did=VALID_DID, client_id="cid")
        result = adapter.validate_token(FAKE_JWT)
        assert result["provider"] == "azure"
        assert result["client_id"] == "cid"

    def test_agent_mapping(self):
        adapter = EntraManagedIdentity(
            agent_did=VALID_DID, client_id="cid"
        )
        mapping = adapter.get_agent_mapping()
        assert mapping["provider"] == "azure_managed_identity"
        assert mapping["client_id"] == "cid"
        assert mapping["agent_did"] == VALID_DID

    def test_token_is_cached(self):
        call_count = 0

        class _CountingHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                nonlocal call_count
                call_count += 1
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(
                    {"access_token": FAKE_JWT, "expires_in": "3600"}
                ).encode())

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), _CountingHandler)
        port = server.server_address[1]
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            adapter = EntraManagedIdentity(
                agent_did=VALID_DID,
                imds_url=f"http://127.0.0.1:{port}/metadata/identity/oauth2/token",
            )
            adapter.get_token()
            adapter.get_token()  # second call should hit cache
            assert call_count == 1
        finally:
            server.shutdown()


# ---------------------------------------------------------------------------
# AWS IAM Identity
# ---------------------------------------------------------------------------

class TestAWSIAMIdentity:
    """Tests for the AWS IAM adapter."""

    def test_get_token_success(self):
        call_log = []

        class _AWSHandler(BaseHTTPRequestHandler):
            def do_PUT(self):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"fake-imds-token")

            def do_GET(self):
                path = self.path.split("?")[0]
                call_log.append(path)
                if path.endswith("/security-credentials/"):
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"my-role")
                elif path.endswith("/security-credentials/my-role"):
                    body = json.dumps({
                        "AccessKeyId": "AKIAI...",
                        "Token": "aws-session-token",
                    })
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(body.encode())
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), _AWSHandler)
        port = server.server_address[1]
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            base = f"http://127.0.0.1:{port}"
            adapter = AWSIAMIdentity(
                agent_did=VALID_DID,
                role_arn="arn:aws:iam::123456:role/my-role",
                metadata_url=f"{base}/latest/meta-data/iam",
                token_url=f"{base}/latest/api/token",
            )
            token = adapter.get_token()
            assert token == "aws-session-token"
        finally:
            server.shutdown()

    def test_get_token_failure_raises(self):
        adapter = AWSIAMIdentity(
            agent_did=VALID_DID,
            metadata_url="http://127.0.0.1:1/bad",
            token_url="http://127.0.0.1:1/bad",
        )
        with pytest.raises(IdentityError):
            adapter.get_token()

    def test_validate_token_aws(self):
        adapter = AWSIAMIdentity(
            agent_did=VALID_DID,
            role_arn="arn:aws:iam::123456:role/my-role",
        )
        result = adapter.validate_token("some-aws-token")
        assert result["provider"] == "aws"
        assert result["role_arn"] == "arn:aws:iam::123456:role/my-role"

    def test_validate_token_empty_raises(self):
        adapter = AWSIAMIdentity(agent_did=VALID_DID)
        with pytest.raises(IdentityError, match="non-empty string"):
            adapter.validate_token("")

    def test_agent_mapping(self):
        adapter = AWSIAMIdentity(
            agent_did=VALID_DID,
            role_arn="arn:aws:iam::123456:role/r",
        )
        mapping = adapter.get_agent_mapping()
        assert mapping["provider"] == "aws_iam"
        assert mapping["role_arn"] == "arn:aws:iam::123456:role/r"


# ---------------------------------------------------------------------------
# GCP Workload Identity
# ---------------------------------------------------------------------------

class TestGCPWorkloadIdentity:
    """Tests for the GCP Workload Identity adapter."""

    def test_get_token_success(self):
        responses = {
            "/computeMetadata/v1/instance/service-accounts": (
                200,
                {"access_token": "gcp-token-123", "expires_in": 3600},
            ),
        }
        server, base_url = _start_fake_server(responses)
        try:
            adapter = GCPWorkloadIdentity(
                agent_did=VALID_DID,
                metadata_url=f"{base_url}/computeMetadata/v1/instance/service-accounts",
            )
            token = adapter.get_token()
            assert token == "gcp-token-123"
        finally:
            server.shutdown()

    def test_get_token_custom_service_account(self):
        responses = {
            "/computeMetadata/v1/instance/service-accounts": (
                200,
                {"access_token": "gcp-sa-token", "expires_in": 1800},
            ),
        }
        server, base_url = _start_fake_server(responses)
        try:
            adapter = GCPWorkloadIdentity(
                agent_did=VALID_DID,
                service_account="my-sa@project.iam.gserviceaccount.com",
                metadata_url=f"{base_url}/computeMetadata/v1/instance/service-accounts",
            )
            token = adapter.get_token()
            assert token == "gcp-sa-token"
        finally:
            server.shutdown()

    def test_get_token_failure_raises(self):
        adapter = GCPWorkloadIdentity(
            agent_did=VALID_DID,
            metadata_url="http://127.0.0.1:1/bad",
        )
        with pytest.raises(IdentityError):
            adapter.get_token()

    def test_get_token_missing_access_token(self):
        responses = {
            "/computeMetadata/v1/instance/service-accounts": (200, {"error": "nope"}),
        }
        server, base_url = _start_fake_server(responses)
        try:
            adapter = GCPWorkloadIdentity(
                agent_did=VALID_DID,
                metadata_url=f"{base_url}/computeMetadata/v1/instance/service-accounts",
            )
            with pytest.raises(IdentityError, match="access_token"):
                adapter.get_token()
        finally:
            server.shutdown()

    def test_validate_token_gcp(self):
        adapter = GCPWorkloadIdentity(agent_did=VALID_DID)
        result = adapter.validate_token(FAKE_JWT)
        assert result["provider"] == "gcp"
        assert result["service_account"] == "default"

    def test_agent_mapping(self):
        adapter = GCPWorkloadIdentity(
            agent_did=VALID_DID,
            service_account="sa@proj.iam.gserviceaccount.com",
        )
        mapping = adapter.get_agent_mapping()
        assert mapping["provider"] == "gcp_workload_identity"
        assert mapping["service_account"] == "sa@proj.iam.gserviceaccount.com"


# ---------------------------------------------------------------------------
# DID mapping cross-provider
# ---------------------------------------------------------------------------

class TestDIDMapping:
    """Verify DID ↔ cloud principal mapping across providers."""

    def test_all_adapters_preserve_did(self):
        for cls, kwargs in [
            (EntraManagedIdentity, {"client_id": "c1"}),
            (AWSIAMIdentity, {"role_arn": "arn:aws:iam::1:role/r"}),
            (GCPWorkloadIdentity, {"service_account": "sa@p.iam.gserviceaccount.com"}),
        ]:
            adapter = cls(agent_did=VALID_DID, **kwargs)
            mapping = adapter.get_agent_mapping()
            assert mapping["agent_did"] == VALID_DID

    def test_each_adapter_reports_distinct_provider(self):
        providers = set()
        for cls, kwargs in [
            (EntraManagedIdentity, {}),
            (AWSIAMIdentity, {}),
            (GCPWorkloadIdentity, {}),
        ]:
            adapter = cls(agent_did=VALID_DID, **kwargs)
            providers.add(adapter.get_agent_mapping()["provider"])
        assert len(providers) == 3
