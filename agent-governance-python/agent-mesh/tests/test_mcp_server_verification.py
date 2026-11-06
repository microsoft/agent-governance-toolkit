# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Phase 1 MCP server identity discovery and verification.

Covers :mod:`agentmesh.integrations.mcp.server_identity` and the
trust-gated ``TrustGatedMCPClient`` wiring: valid and invalid discovery,
registry binding, signatures, freshness, challenge-response with replay
protection, SSRF guards, transport failures, and fail-closed
``connect()`` behavior.

Network is never touched: DNS resolution is patched where a test needs a
positive ``discovery_url``, and HTTP is served by ``httpx.MockTransport``.
"""

from __future__ import annotations

import base64
import json
import socket
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, Optional

import httpx
import pytest

from agentmesh.identity import AgentIdentity
from agentmesh.identity.agent_id import IdentityRegistry
from agentmesh.integrations.mcp import TrustGatedMCPClient
from agentmesh.integrations.mcp.server_identity import (
    ChallengeResponse,
    DiscoveryConfig,
    InMemoryReplayCache,
    ServerChallenge,
    ServerIdentityDocument,
    afetch_server_document,
    aresolve_and_check_host,
    build_challenge_payload,
    build_document_payload,
    discovery_url,
    mint_challenge,
    parse_server_document,
    resolve_and_check_host,
    verify_challenge_response,
    verify_server,
    verify_server_document,
)

SERVER_URL = "https://mcp.example.com:8443"


def _make_identity(name: str = "agent", capabilities: list | None = None) -> AgentIdentity:
    return AgentIdentity.create(
        name=name,
        sponsor="admin@test.com",
        capabilities=capabilities or [],
    )


@pytest.fixture()
def registry() -> IdentityRegistry:
    return IdentityRegistry()


@pytest.fixture()
def server_identity() -> AgentIdentity:
    return _make_identity(name="tool-server")


@pytest.fixture()
def registered(registry: IdentityRegistry, server_identity: AgentIdentity) -> AgentIdentity:
    registry.register(server_identity)
    return server_identity


@pytest.fixture()
def client_identity() -> AgentIdentity:
    return _make_identity(name="tool-client")


def _issued_at(now: datetime | None = None) -> str:
    return (now or datetime.now(UTC)).isoformat()


def _signed_doc(
    server: AgentIdentity,
    *,
    issued_at: str | None = None,
    public_key: str | None = None,
    key_id: str | None = "default",
    challenge_endpoint: str | None = None,
    sign_with: AgentIdentity | None = None,
) -> Dict[str, Any]:
    """Build a well-formed document dict signed by ``sign_with``."""
    doc = ServerIdentityDocument(
        did=str(server.did),
        public_key=public_key if public_key is not None else server.public_key,
        key_id=key_id if key_id != "default" else server.verification_key_id,
        issued_at=issued_at if issued_at is not None else _issued_at(),
        challenge_endpoint=challenge_endpoint,
    )
    signer = sign_with or server
    return {
        "did": doc.did,
        "public_key": doc.public_key,
        "key_id": doc.key_id,
        "issued_at": doc.issued_at,
        "challenge_endpoint": doc.challenge_endpoint,
        "signature": signer.sign(build_document_payload(doc)),
    }


def _mock_transport(
    routes: Dict[str, Any],
    *,
    default_status: int = 404,
) -> httpx.MockTransport:
    """Serve ``routes`` mapping ``"METHOD path"`` to ``(status, body, content-type)``."""

    def handler(request: httpx.Request) -> httpx.Response:
        key = f"{request.method} {request.url.path}"
        if key in routes:
            status, body, content_type = routes[key]
            if isinstance(body, dict):
                body = json.dumps(body).encode()
            return httpx.Response(status, content=body, headers={"Content-Type": content_type})
        return httpx.Response(default_status, content=b"nope")

    return httpx.MockTransport(handler)


@pytest.fixture()
def open_resolver(monkeypatch: pytest.MonkeyPatch) -> None:
    """Pretend every DNS answer is globally routable (HTTP is mocked anyway)."""
    import agentmesh.integrations.mcp.server_identity as si

    async def _always_global(
        host: str, port: int, max_answers: int, *, deadline_seconds: float
    ) -> bool:
        del host, port, max_answers, deadline_seconds
        return True

    monkeypatch.setattr(si, "aresolve_and_check_host", _always_global)


@pytest.fixture()
def doc_routes(registered: AgentIdentity) -> Dict[str, Any]:
    return {
        "GET /.well-known/agent.json": (
            200,
            _signed_doc(registered),
            "application/json",
        )
    }


class TestParseServerDocument:
    def test_valid_document(self, registered: AgentIdentity) -> None:
        doc = parse_server_document(json.dumps(_signed_doc(registered)).encode())
        assert doc is not None
        assert doc.did == str(registered.did)
        assert doc.public_key == registered.public_key

    @pytest.mark.parametrize(
        "raw",
        [
            b"\xff\xfe not utf-8",
            b"not json {",
            b"[1, 2]",
            b'"just a string"',
            b"{}",
            json.dumps({"did": "did:mesh:abc"}).encode(),
            json.dumps({"did": "not-a-did", "public_key": "e30="}).encode(),
            json.dumps({"did": "did:mesh:abc", "public_key": "!!!"}).encode(),
        ],
    )
    def test_malformed_documents_rejected(self, raw: bytes) -> None:
        assert parse_server_document(raw) is None

    def test_oversized_challenge_endpoint_rejected(self, registered: AgentIdentity) -> None:
        body = _signed_doc(registered, challenge_endpoint="https://x/" + "y" * 2048)
        assert parse_server_document(json.dumps(body).encode()) is None


class TestDiscoveryUrl:
    def test_builds_well_known_url(self) -> None:
        # Pure URL-shape check: no resolver fixture needed, no I/O.
        url = discovery_url(SERVER_URL, DiscoveryConfig())
        assert url == "https://mcp.example.com:8443/.well-known/agent.json"

    @pytest.mark.parametrize(
        "server_url",
        [
            "http://mcp.example.com/",  # plain HTTP rejected by default
            "ftp://mcp.example.com/",
            "not a url",
            "https://localhost/",
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://10.0.0.5/",
            "https://192.168.1.10/",
            "https://169.254.169.254/",
            "https://metadata.google.internal/",
            "https://2130706433/",  # decimal IPv4 literal for 127.0.0.1
            "https://user:pw@mcp.example.com/",
            "https://mcp.example.com:8443@evil.example/",
        ],
    )
    def test_unsafe_urls_rejected(self, server_url: str) -> None:
        assert discovery_url(server_url, DiscoveryConfig()) is None

    def test_wss_maps_to_https(self) -> None:
        url = discovery_url("wss://mcp.example.com:8443/chat", DiscoveryConfig())
        assert url == "https://mcp.example.com:8443/.well-known/agent.json"

    def test_ws_rejected_when_https_required(self) -> None:
        assert discovery_url("ws://mcp.example.com/chat", DiscoveryConfig()) is None

    def test_ws_maps_to_http_when_permitted(self) -> None:
        cfg = DiscoveryConfig(require_https=False)
        url = discovery_url("ws://mcp.example.com/chat", cfg)
        assert url == "http://mcp.example.com/.well-known/agent.json"

    def test_plain_http_allowed_when_not_required(self) -> None:
        cfg = DiscoveryConfig(require_https=False)
        assert discovery_url("http://mcp.example.com/", cfg) == (
            "http://mcp.example.com/.well-known/agent.json"
        )

    def test_userinfo_never_forwarded(self) -> None:
        # Even with HTTP explicitly permitted, credentials are rejected.
        cfg = DiscoveryConfig(require_https=False)
        assert discovery_url("http://user@mcp.example.com/", cfg) is None
        assert discovery_url("http://user:pw@mcp.example.com/", cfg) is None


def _sockaddr(ip: str) -> Any:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return (family, socket.SOCK_STREAM, 6, "", (ip, 443))


class TestResolveAndCheckHost:
    def test_private_answer_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import agentmesh.integrations.mcp.server_identity as si

        monkeypatch.setattr(si.socket, "getaddrinfo", lambda *a, **k: [_sockaddr("10.0.0.1")])
        assert si.resolve_and_check_host("example.com", 443, 16) is False

    def test_mixed_answers_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import agentmesh.integrations.mcp.server_identity as si

        answers = [_sockaddr("93.184.216.34"), _sockaddr("192.168.0.1")]
        monkeypatch.setattr(si.socket, "getaddrinfo", lambda *a, **k: answers)
        assert si.resolve_and_check_host("example.com", 443, 16) is False

    def test_answer_cap_enforced(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import agentmesh.integrations.mcp.server_identity as si

        answers = [_sockaddr(f"93.184.216.{i}") for i in range(1, 20)]
        monkeypatch.setattr(si.socket, "getaddrinfo", lambda *a, **k: answers)
        assert si.resolve_and_check_host("example.com", 443, 4) is False

    def test_lookup_failure_rejected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import agentmesh.integrations.mcp.server_identity as si

        def boom(*a: Any, **k: Any) -> Any:
            raise socket.gaierror("no such host")

        monkeypatch.setattr(si.socket, "getaddrinfo", boom)
        assert si.resolve_and_check_host("nonexistent.invalid", 443, 16) is False
        assert si.resolve_and_check_host("", 443, 16) is False

    def test_decimal_literal_resolves_loopback(self) -> None:
        # No monkeypatching: numeric literals never touch the network.
        # 2130706433 == 127.0.0.1, so the guard must reject it.
        assert resolve_and_check_host("2130706433", 443, 16) is False

    @pytest.mark.parametrize(
        "url",
        [
            "https://224.0.0.1/",
            "https://[ff02::1]/",
            # Unbracketed IPv6 is not a valid URL authority: must fail
            # closed (None), never raise.
            "https://ff02::1/",
        ],
    )
    def test_multicast_urls_rejected(self, url: str) -> None:
        # is_global alone admits multicast; the guard excludes it
        # explicitly. No network: literals never leave the process.
        assert discovery_url(url, DiscoveryConfig()) is None

    def test_multicast_literals_unsafe(self) -> None:
        from agentmesh.integrations.mcp.server_identity import _is_safe_literal_ip

        assert _is_safe_literal_ip("224.0.0.1") is False
        assert _is_safe_literal_ip("ff02::1") is False

    def test_resolvers_exported_consistently(self) -> None:
        import agentmesh.integrations.mcp.server_identity as si

        assert "resolve_and_check_host" in si.__all__
        assert "aresolve_and_check_host" in si.__all__


class TestVerifyServerDocument:
    def test_valid_document_verified(
        self, registry: IdentityRegistry, registered: AgentIdentity
    ) -> None:
        doc = parse_server_document(json.dumps(_signed_doc(registered)).encode())
        assert doc is not None
        result = verify_server_document(doc, registry)
        assert result.verified is True
        assert result.did == str(registered.did)
        assert result.reason == "verified"

    def test_unknown_did(self, registry: IdentityRegistry) -> None:
        stranger = _make_identity(name="stranger")
        doc = parse_server_document(json.dumps(_signed_doc(stranger)).encode())
        assert doc is not None
        result = verify_server_document(doc, registry)
        assert result.verified is False
        assert result.reason == "unknown-did"

    def test_document_key_must_match_registry(
        self, registry: IdentityRegistry, registered: AgentIdentity
    ) -> None:
        impostor = _make_identity(name="impostor")
        # Attacker substitutes their own key but keeps the victim DID.
        doc = parse_server_document(
            json.dumps(_signed_doc(registered, public_key=impostor.public_key)).encode()
        )
        assert doc is not None
        result = verify_server_document(doc, registry)
        assert result.verified is False
        assert result.reason == "key-mismatch"

    def test_signature_by_wrong_key_rejected(
        self, registry: IdentityRegistry, registered: AgentIdentity
    ) -> None:
        impostor = _make_identity(name="impostor")
        # Document carries the registry key, but someone else signed it.
        body = _signed_doc(registered, sign_with=impostor)
        doc = parse_server_document(json.dumps(body).encode())
        assert doc is not None
        result = verify_server_document(doc, registry)
        assert result.verified is False
        assert result.reason == "bad-signature"

    def test_missing_signature_rejected(
        self, registry: IdentityRegistry, registered: AgentIdentity
    ) -> None:
        body = _signed_doc(registered)
        del body["signature"]
        doc = parse_server_document(json.dumps(body).encode())
        assert doc is not None
        result = verify_server_document(doc, registry)
        assert result.verified is False
        assert result.reason == "missing-signature"

    def test_stale_document_rejected(
        self, registry: IdentityRegistry, registered: AgentIdentity
    ) -> None:
        old = (datetime.now(UTC) - timedelta(seconds=3600)).isoformat()
        doc = parse_server_document(json.dumps(_signed_doc(registered, issued_at=old)).encode())
        assert doc is not None
        result = verify_server_document(doc, registry)
        assert result.verified is False
        assert result.reason == "stale-or-missing-issued-at"

    def test_missing_issued_at_rejected(
        self, registry: IdentityRegistry, registered: AgentIdentity
    ) -> None:
        body = _signed_doc(registered)
        del body["issued_at"]
        # Re-sign without issued_at so the failure is freshness, not signature.
        unsigned = ServerIdentityDocument(
            did=body["did"], public_key=body["public_key"], key_id=body.get("key_id")
        )
        body["signature"] = registered.sign(build_document_payload(unsigned))
        doc = parse_server_document(json.dumps(body).encode())
        assert doc is not None
        result = verify_server_document(doc, registry)
        assert result.verified is False
        assert result.reason == "stale-or-missing-issued-at"

    def test_revoked_identity_rejected(
        self, registry: IdentityRegistry, registered: AgentIdentity
    ) -> None:
        registry.revoke(str(registered.did), "key rotation")
        doc = parse_server_document(json.dumps(_signed_doc(registered)).encode())
        assert doc is not None
        result = verify_server_document(doc, registry)
        assert result.verified is False
        assert result.reason == "identity-inactive"

    def test_untrusted_registry_entry_rejected(self, registered: AgentIdentity) -> None:
        class DistrustfulRegistry(IdentityRegistry):
            def is_trusted(self, agent_did: str) -> bool:
                return False

        registry = DistrustfulRegistry()
        registry.register(registered)
        doc = parse_server_document(json.dumps(_signed_doc(registered)).encode())
        assert doc is not None
        result = verify_server_document(doc, registry)
        assert result.verified is False
        assert result.reason == "identity-untrusted"

    def test_key_id_mismatch_rejected(
        self, registry: IdentityRegistry, registered: AgentIdentity
    ) -> None:
        doc = parse_server_document(
            json.dumps(_signed_doc(registered, key_id="key-deadbeefdeadbeef")).encode()
        )
        assert doc is not None
        result = verify_server_document(doc, registry)
        assert result.verified is False
        assert result.reason == "key-id-mismatch"

    def test_canonical_encoding_is_field_order_independent(
        self, registered: AgentIdentity
    ) -> None:
        first = ServerIdentityDocument(did=str(registered.did), public_key=registered.public_key)
        second = ServerIdentityDocument(public_key=registered.public_key, did=str(registered.did))
        assert build_document_payload(first) == build_document_payload(second)

    def test_signature_does_not_transfer_across_documents(
        self, registry: IdentityRegistry, registered: AgentIdentity
    ) -> None:
        other = _make_identity(name="other")
        registry.register(other)
        doc = parse_server_document(json.dumps(_signed_doc(registered)).encode())
        assert doc is not None
        # Transplant the valid signature onto a document for another DID.
        # key_id is dropped so the transplant reaches the signature check
        # rather than failing earlier on key-id mismatch (also fail-closed).
        transplanted = ServerIdentityDocument(
            did=str(other.did),
            public_key=other.public_key,
            key_id=None,
            issued_at=doc.issued_at,
            signature=doc.signature,
        )
        result = verify_server_document(transplanted, registry)
        assert result.verified is False
        assert result.reason == "bad-signature"


def _challenge_response_for(
    challenge: ServerChallenge, server: AgentIdentity, *, timestamp: str | None = None
) -> ChallengeResponse:
    moment = timestamp or _issued_at()
    payload = build_challenge_payload(
        server_did=challenge.server_did,
        client_did=challenge.client_did,
        client_nonce=challenge.client_nonce,
        timestamp=moment,
        audience=challenge.audience,
    )
    return ChallengeResponse(
        server_did=challenge.server_did,
        client_nonce=challenge.client_nonce,
        timestamp=moment,
        signature=server.sign(payload),
    )


class TestChallengeResponse:
    def test_valid_challenge_verified(
        self, registry: IdentityRegistry, registered: AgentIdentity, client_identity: AgentIdentity
    ) -> None:
        challenge = mint_challenge(str(registered.did), str(client_identity.did), SERVER_URL)
        response = _challenge_response_for(challenge, registered)
        result = verify_challenge_response(challenge, response, registry, InMemoryReplayCache())
        assert result.verified is True

    def test_replayed_nonce_rejected(
        self, registry: IdentityRegistry, registered: AgentIdentity, client_identity: AgentIdentity
    ) -> None:
        challenge = mint_challenge(str(registered.did), str(client_identity.did), SERVER_URL)
        response = _challenge_response_for(challenge, registered)
        cache = InMemoryReplayCache()
        assert verify_challenge_response(challenge, response, registry, cache).verified is True
        second = verify_challenge_response(challenge, response, registry, cache)
        assert second.verified is False
        assert second.reason == "replay-detected"

    def test_nonce_mismatch_rejected(
        self, registry: IdentityRegistry, registered: AgentIdentity, client_identity: AgentIdentity
    ) -> None:
        challenge = mint_challenge(str(registered.did), str(client_identity.did), SERVER_URL)
        response = _challenge_response_for(challenge, registered)
        tampered = ChallengeResponse(
            server_did=response.server_did,
            client_nonce=mint_challenge("x", "y", "z").client_nonce,
            timestamp=response.timestamp,
            signature=response.signature,
        )
        result = verify_challenge_response(challenge, tampered, registry, InMemoryReplayCache())
        assert result.verified is False
        assert result.reason == "challenge-nonce-mismatch"

    def test_did_mismatch_rejected(
        self, registry: IdentityRegistry, registered: AgentIdentity, client_identity: AgentIdentity
    ) -> None:
        challenge = mint_challenge(str(registered.did), str(client_identity.did), SERVER_URL)
        response = _challenge_response_for(challenge, registered)
        tampered = ChallengeResponse(
            server_did="did:mesh:00000000000000000000000000000000",
            client_nonce=response.client_nonce,
            timestamp=response.timestamp,
            signature=response.signature,
        )
        result = verify_challenge_response(challenge, tampered, registry, InMemoryReplayCache())
        assert result.verified is False
        assert result.reason == "challenge-did-mismatch"

    def test_stale_challenge_rejected(
        self, registry: IdentityRegistry, registered: AgentIdentity, client_identity: AgentIdentity
    ) -> None:
        challenge = mint_challenge(str(registered.did), str(client_identity.did), SERVER_URL)
        old = (datetime.now(UTC) - timedelta(seconds=3600)).isoformat()
        response = _challenge_response_for(challenge, registered, timestamp=old)
        result = verify_challenge_response(challenge, response, registry, InMemoryReplayCache())
        assert result.verified is False
        assert result.reason == "challenge-stale"

    def test_wrong_key_signature_rejected(
        self, registry: IdentityRegistry, registered: AgentIdentity, client_identity: AgentIdentity
    ) -> None:
        impostor = _make_identity(name="impostor")
        challenge = mint_challenge(str(registered.did), str(client_identity.did), SERVER_URL)
        # Sign the real challenge payload with the wrong key.
        moment = _issued_at()
        payload = build_challenge_payload(
            server_did=str(registered.did),
            client_did=challenge.client_did,
            client_nonce=challenge.client_nonce,
            timestamp=moment,
            audience=challenge.audience,
        )
        forged = ChallengeResponse(
            server_did=str(registered.did),
            client_nonce=challenge.client_nonce,
            timestamp=moment,
            signature=impostor.sign(payload),
        )
        result = verify_challenge_response(challenge, forged, registry, InMemoryReplayCache())
        assert result.verified is False
        assert result.reason == "bad-signature"

    def test_minted_nonces_are_unique(self, registered: AgentIdentity) -> None:
        seen = {
            mint_challenge(str(registered.did), "did:mesh:c", SERVER_URL).client_nonce
            for _ in range(50)
        }
        assert len(seen) == 50


class TestFetchServerDocument:
    async def test_fetch_success(
        self, open_resolver: None, doc_routes: Dict[str, Any], registered: AgentIdentity
    ) -> None:
        body = await afetch_server_document(
            SERVER_URL, transport=_mock_transport(doc_routes)
        )
        assert body is not None
        doc = parse_server_document(body)
        assert doc is not None
        assert doc.did == str(registered.did)

    async def test_fetch_404_fails_closed(self, open_resolver: None) -> None:
        body = await afetch_server_document(SERVER_URL, transport=_mock_transport({}))
        assert body is None

    async def test_redirect_not_followed(
        self, open_resolver: None, doc_routes: Dict[str, Any]
    ) -> None:
        routes = {
            "GET /.well-known/agent.json": (302, b"", "application/json"),
        }
        body = await afetch_server_document(SERVER_URL, transport=_mock_transport(routes))
        assert body is None

    async def test_wrong_content_type_rejected(self, open_resolver: None) -> None:
        routes = {"GET /.well-known/agent.json": (200, b'{"did": "x"}', "text/html")}
        body = await afetch_server_document(SERVER_URL, transport=_mock_transport(routes))
        assert body is None

    async def test_oversized_body_rejected(
        self, open_resolver: None, doc_routes: Dict[str, Any]
    ) -> None:
        cfg = DiscoveryConfig(max_bytes=10)
        body = await afetch_server_document(
            SERVER_URL, cfg, transport=_mock_transport(doc_routes)
        )
        assert body is None

    async def test_transport_error_fails_closed(self, open_resolver: None) -> None:
        def boom(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("slow server")

        body = await afetch_server_document(
            SERVER_URL, transport=httpx.MockTransport(boom)
        )
        assert body is None

    async def test_unsafe_url_never_fetched(self) -> None:
        # No transport needed: URL guards reject before any I/O.
        assert await afetch_server_document("http://mcp.example.com/") is None
        assert await afetch_server_document("https://127.0.0.1/") is None


class TestVerifyServerPipeline:
    async def test_full_pipeline_verified(
        self,
        open_resolver: None,
        registry: IdentityRegistry,
        registered: AgentIdentity,
        client_identity: AgentIdentity,
    ) -> None:
        routes = {"GET /.well-known/agent.json": (200, _signed_doc(registered), "application/json")}
        result = await verify_server(
            SERVER_URL,
            registry,
            str(client_identity.did),
            transport=_mock_transport(routes),
        )
        assert result.verified is True
        assert result.did == str(registered.did)

    async def test_pipeline_with_challenge_endpoint(
        self,
        open_resolver: None,
        registry: IdentityRegistry,
        registered: AgentIdentity,
        client_identity: AgentIdentity,
    ) -> None:
        endpoint = "https://mcp.example.com:8443/.well-known/agent-challenge"
        doc = _signed_doc(registered, challenge_endpoint=endpoint)
        state: Dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return httpx.Response(
                    200,
                    content=json.dumps(doc).encode(),
                    headers={"Content-Type": "application/json"},
                )
            assert request.method == "POST"
            asked = json.loads(request.content.decode())
            challenge = ServerChallenge(
                server_did=asked["server_did"],
                client_did=asked["client_did"],
                client_nonce=asked["client_nonce"],
                timestamp=asked["timestamp"],
                audience=SERVER_URL,
            )
            state["nonce"] = asked["client_nonce"]
            moment = _issued_at()
            payload = build_challenge_payload(
                server_did=challenge.server_did,
                client_did=challenge.client_did,
                client_nonce=challenge.client_nonce,
                timestamp=moment,
                audience=challenge.audience,
            )
            answer = {
                "server_did": str(registered.did),
                "client_nonce": challenge.client_nonce,
                "timestamp": moment,
                "signature": registered.sign(payload),
            }
            return httpx.Response(
                200,
                content=json.dumps(answer).encode(),
                headers={"Content-Type": "application/json"},
            )

        result = await verify_server(
            SERVER_URL,
            registry,
            str(client_identity.did),
            transport=httpx.MockTransport(handler),
        )
        assert result.verified is True
        assert state["nonce"]

    async def test_cross_origin_challenge_endpoint_ignored(
        self,
        open_resolver: None,
        registry: IdentityRegistry,
        registered: AgentIdentity,
        client_identity: AgentIdentity,
    ) -> None:
        # A document advertising an off-origin endpoint must not cause an
        # outbound challenge there; document verification still passes.
        doc = _signed_doc(registered, challenge_endpoint="https://evil.example/steal")
        routes = {"GET /.well-known/agent.json": (200, doc, "application/json")}
        result = await verify_server(
            SERVER_URL,
            registry,
            str(client_identity.did),
            transport=_mock_transport(routes),
        )
        assert result.verified is True

    async def test_pipeline_bad_signature(
        self,
        open_resolver: None,
        registry: IdentityRegistry,
        registered: AgentIdentity,
        client_identity: AgentIdentity,
    ) -> None:
        impostor = _make_identity(name="impostor")
        routes = {
            "GET /.well-known/agent.json": (
                200,
                _signed_doc(registered, sign_with=impostor),
                "application/json",
            )
        }
        result = await verify_server(
            SERVER_URL,
            registry,
            str(client_identity.did),
            transport=_mock_transport(routes),
        )
        assert result.verified is False
        assert result.reason == "bad-signature"


class TestClientConnect:
    def _client(
        self,
        client_identity: AgentIdentity,
        registry: IdentityRegistry | None = None,
        transport: Any = None,
    ) -> TrustGatedMCPClient:
        return TrustGatedMCPClient(
            client_identity,
            registry=registry,
            http_transport=transport,
        )

    async def test_connect_verified(
        self,
        open_resolver: None,
        registry: IdentityRegistry,
        registered: AgentIdentity,
        client_identity: AgentIdentity,
        doc_routes: Dict[str, Any],
    ) -> None:
        client = self._client(
            client_identity, registry, _mock_transport(doc_routes)
        )
        assert await client.connect(SERVER_URL) is True
        assert SERVER_URL in client._connected_servers

    async def test_connect_unverified_fails_closed(
        self,
        open_resolver: None,
        registry: IdentityRegistry,
        client_identity: AgentIdentity,
    ) -> None:
        # The served document belongs to a stranger the registry never saw.
        stranger = _make_identity(name="stranger")
        routes = {"GET /.well-known/agent.json": (200, _signed_doc(stranger), "application/json")}
        client = self._client(client_identity, registry, _mock_transport(routes))
        assert await client.connect(SERVER_URL) is False
        assert SERVER_URL not in client._connected_servers

    async def test_verify_without_registry_fails_closed(
        self, client_identity: AgentIdentity
    ) -> None:
        client = self._client(client_identity)
        result = await client.verify_server_identity(SERVER_URL)
        assert result.verified is False
        assert result.reason == "no-registry-configured"

    async def test_discover_returns_did(
        self,
        open_resolver: None,
        client_identity: AgentIdentity,
        doc_routes: Dict[str, Any],
        registered: AgentIdentity,
    ) -> None:
        client = self._client(client_identity, None, _mock_transport(doc_routes))
        assert await client._discover_server_did(SERVER_URL) == str(registered.did)

    async def test_discover_returns_none_on_failure(
        self, open_resolver: None, client_identity: AgentIdentity
    ) -> None:
        client = self._client(client_identity, None, _mock_transport({}))
        assert await client._discover_server_did(SERVER_URL) is None


class _CountingTransport(httpx.AsyncBaseTransport):
    """Serve fixed chunks while recording how many the client pulls.

    Proves early termination: the client must stop consuming once the
    running total passes ``max_bytes``, instead of buffering everything.
    """

    def __init__(self, chunks: list, status: int = 200) -> None:
        self._chunks = chunks
        self.pulled = 0
        self._status = status

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        pulled = self

        async def body() -> Any:
            for chunk in pulled._chunks:
                pulled.pulled += 1
                yield chunk

        return httpx.Response(
            self._status,
            content=body(),
            headers={"Content-Type": "application/json"},
        )


class TestStreamingCaps:
    async def test_get_stops_early(
        self, open_resolver: None, doc_routes: Dict[str, Any]
    ) -> None:
        chunks = [b"x" * 8192 for _ in range(100)]
        transport = _CountingTransport(chunks)
        cfg = DiscoveryConfig(max_bytes=65_536)
        body = await afetch_server_document(SERVER_URL, cfg, transport=transport)
        assert body is None
        # 8 full 8 KiB chunks fit; the 9th trips the cap. Anything near
        # 100 would mean the whole body was buffered first.
        assert transport.pulled <= 10
        assert transport.pulled < len(chunks)

    async def test_post_stops_early(
        self,
        open_resolver: None,
        registry: IdentityRegistry,
        registered: AgentIdentity,
        client_identity: AgentIdentity,
    ) -> None:
        endpoint = "https://mcp.example.com:8443/.well-known/agent-challenge"
        doc = _signed_doc(registered, challenge_endpoint=endpoint)
        chunks = [b"y" * 8192 for _ in range(100)]

        async def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return httpx.Response(
                    200,
                    content=json.dumps(doc).encode(),
                    headers={"Content-Type": "application/json"},
                )
            pulled = handler  # type: ignore[attr-defined]

            async def body() -> Any:
                for chunk in chunks:
                    pulled.count += 1  # type: ignore[attr-defined]
                    yield chunk

            return httpx.Response(
                200,
                content=body(),
                headers={"Content-Type": "application/json"},
            )

        handler.count = 0  # type: ignore[attr-defined]
        result = await verify_server(
            SERVER_URL,
            registry,
            str(client_identity.did),
            transport=httpx.MockTransport(handler),
        )
        assert result.verified is False
        assert result.reason == "challenge-transport-failed"
        assert handler.count <= 10  # type: ignore[attr-defined]


class TestSharedDefaultCache:
    async def test_direct_calls_share_default_replay_protection(
        self,
        open_resolver: None,
        registry: IdentityRegistry,
        registered: AgentIdentity,
        client_identity: AgentIdentity,
    ) -> None:
        import agentmesh.integrations.mcp.server_identity as si

        endpoint = "https://mcp.example.com:8443/.well-known/agent-challenge"
        doc = _signed_doc(registered, challenge_endpoint=endpoint)
        seen: Dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "GET":
                return httpx.Response(
                    200,
                    content=json.dumps(doc).encode(),
                    headers={"Content-Type": "application/json"},
                )
            asked = json.loads(request.content.decode())
            seen.update(asked)
            moment = _issued_at()
            payload = build_challenge_payload(
                server_did=asked["server_did"],
                client_did=asked["client_did"],
                client_nonce=asked["client_nonce"],
                timestamp=moment,
                audience=SERVER_URL,
            )
            return httpx.Response(
                200,
                content=json.dumps(
                    {
                        "server_did": str(registered.did),
                        "client_nonce": asked["client_nonce"],
                        "timestamp": moment,
                        "signature": registered.sign(payload),
                    }
                ).encode(),
                headers={"Content-Type": "application/json"},
            )

        transport = httpx.MockTransport(handler)
        first = await verify_server(
            SERVER_URL, registry, str(client_identity.did), transport=transport
        )
        assert first.verified is True
        # Replaying the captured answer against the shared default cache
        # must be detected: the pipeline consumed that nonce already.
        challenge = ServerChallenge(
            server_did=seen["server_did"],
            client_did=seen["client_did"],
            client_nonce=seen["client_nonce"],
            timestamp=seen["timestamp"],
            audience=SERVER_URL,
        )
        moment = _issued_at()
        payload = build_challenge_payload(
            server_did=challenge.server_did,
            client_did=challenge.client_did,
            client_nonce=challenge.client_nonce,
            timestamp=moment,
            audience=challenge.audience,
        )
        replayed = ChallengeResponse(
            server_did=challenge.server_did,
            client_nonce=challenge.client_nonce,
            timestamp=moment,
            signature=registered.sign(payload),
        )
        assert (
            verify_challenge_response(
                challenge, replayed, registry, si._DEFAULT_REPLAY_CACHE
            ).verified
            is False
        )


class TestCredentialHygiene:
    @pytest.mark.parametrize(
        "server_url",
        [
            "https://user:pw@mcp.example.com:8443/",
            "https://user@mcp.example.com:8443/",
            "ftp://user:pw@mcp.example.com/",
        ],
    )
    async def test_userinfo_rejected_without_network_or_logs(
        self, server_url: str, client_identity: AgentIdentity, caplog: pytest.LogCaptureFixture
    ) -> None:
        def explode(request: httpx.Request) -> httpx.Response:
            raise AssertionError("no network request may be made")

        client = TrustGatedMCPClient(
            client_identity, http_transport=httpx.MockTransport(explode)
        )
        with caplog.at_level("WARNING", logger="agentmesh.integrations.mcp"):
            assert await client.connect(server_url) is False
        assert server_url not in client._connected_servers
        logged = caplog.text
        assert "user:pw" not in logged
        assert "pw@" not in logged

    @pytest.mark.parametrize(
        "server_url",
        [
            "https://ff02::1/",
            "https://[::1",
            "https://user:pw@:8443/",
        ],
    )
    async def test_malformed_urls_fail_closed_without_raising(
        self,
        server_url: str,
        client_identity: AgentIdentity,
        registry: IdentityRegistry,
    ) -> None:
        # A registry-configured client must fail closed (False, never an
        # exception) on malformed authorities. A trustless client stays
        # permissive by design; that path is covered elsewhere.
        client = TrustGatedMCPClient(client_identity, registry=registry)
        assert await client.connect(server_url) is False
        assert server_url not in client._connected_servers

    async def test_invoke_with_userinfo_returns_error(
        self, client_identity: AgentIdentity, caplog: pytest.LogCaptureFixture
    ) -> None:
        client = TrustGatedMCPClient(client_identity)
        with caplog.at_level("WARNING", logger="agentmesh.integrations.mcp"):
            result = await client.invoke("https://user:pw@mcp.example.com:8443/", "t", {})
        assert result == {"error": "Failed to connect to server"}
        assert "user:pw" not in caplog.text

    def test_safe_host_label(self) -> None:
        from agentmesh.integrations.mcp import _safe_host_label

        assert _safe_host_label("https://user:pw@mcp.example.com:8443/x") == (
            "mcp.example.com"
        )
        assert _safe_host_label("not a url") == "unparseable-server-url"


class TestSharedReplayCache:
    async def test_cache_reused_across_verifications(
        self,
        open_resolver: None,
        registry: IdentityRegistry,
        registered: AgentIdentity,
        client_identity: AgentIdentity,
        doc_routes: Dict[str, Any],
    ) -> None:
        client = TrustGatedMCPClient(
            client_identity,
            registry=registry,
            http_transport=_mock_transport(doc_routes),
        )
        first = client.replay_cache
        assert (await client.verify_server_identity(SERVER_URL)).verified is True
        assert client.replay_cache is first
        assert (await client.verify_server_identity(SERVER_URL)).verified is True
        # The shared cache enforces single-use for direct callers too.
        challenge = mint_challenge(str(registered.did), str(client_identity.did), SERVER_URL)
        response = _challenge_response_for(challenge, registered)
        assert verify_challenge_response(challenge, response, registry, first).verified is True
        assert (
            verify_challenge_response(challenge, response, registry, first).verified is False
        )


class TestOverallDeadline:
    async def test_hanging_pipeline_fails_closed(
        self, open_resolver: None, registry: IdentityRegistry, client_identity: AgentIdentity
    ) -> None:
        import asyncio

        async def hang(request: httpx.Request) -> httpx.Response:
            await asyncio.sleep(3600)
            raise AssertionError("unreachable")

        cfg = DiscoveryConfig(timeout_seconds=5.0, total_deadline_seconds=0.05)
        client = TrustGatedMCPClient(
            client_identity,
            registry=registry,
            discovery_config=cfg,
            http_transport=httpx.MockTransport(hang),
        )
        result = await client.verify_server_identity(SERVER_URL)
        assert result.verified is False
        assert result.reason == "deadline-exceeded"


class TestAsyncDns:
    def test_dedicated_executor_configured(self) -> None:
        import agentmesh.integrations.mcp.server_identity as si
        from concurrent.futures import ThreadPoolExecutor

        assert isinstance(si._DNS_EXECUTOR, ThreadPoolExecutor)
        assert si._DNS_EXECUTOR._max_workers == si._MAX_CONCURRENT_DNS == 16

    async def test_lookup_runs_on_dedicated_executor(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import agentmesh.integrations.mcp.server_identity as si

        calls: list = []
        real_submit = si._DNS_EXECUTOR.submit

        def counting_submit(*a: Any, **k: Any) -> Any:
            calls.append(a)
            return real_submit(*a, **k)

        monkeypatch.setattr(si._DNS_EXECUTOR, "submit", counting_submit)
        monkeypatch.setattr(
            si.socket, "getaddrinfo", lambda *a, **k: [_sockaddr("93.184.216.34")]
        )
        assert (
            await aresolve_and_check_host("example.com", 443, 16, deadline_seconds=5.0)
            is True
        )
        assert len(calls) == 1

    async def test_slow_resolver_times_out(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import agentmesh.integrations.mcp.server_identity as si
        import time

        def slow(*a: Any, **k: Any) -> Any:
            time.sleep(30)
            return [_sockaddr("93.184.216.34")]

        monkeypatch.setattr(si.socket, "getaddrinfo", slow)
        try:
            assert (
                await aresolve_and_check_host("example.com", 443, 16, deadline_seconds=0.05)
                is False
            )
        finally:
            # Release the wedged slot so later tests are unaffected.
            for _ in range(32):
                try:
                    si._DNS_SEMAPHORE.release()
                except ValueError:
                    break

    async def test_submission_failure_restores_permit(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import agentmesh.integrations.mcp.server_identity as si

        def boom(*a: Any, **k: Any) -> Any:
            raise RuntimeError("executor shut down")

        monkeypatch.setattr(si._DNS_EXECUTOR, "submit", boom)
        assert (
            await aresolve_and_check_host("example.com", 443, 16, deadline_seconds=5.0)
            is False
        )
        # Exactly one permit was released: a fresh acquire succeeds, and a
        # full drain still yields the configured bound (no leak, no double).
        assert si._DNS_SEMAPHORE.acquire(blocking=False) is True
        si._DNS_SEMAPHORE.release()
        drained = 0
        try:
            while si._DNS_SEMAPHORE.acquire(blocking=False):
                drained += 1
        finally:
            for _ in range(drained):
                si._DNS_SEMAPHORE.release()
        assert drained == si._MAX_CONCURRENT_DNS

    async def test_saturated_lookups_fail_closed(self) -> None:
        import agentmesh.integrations.mcp.server_identity as si

        acquired = 0
        try:
            for _ in range(64):
                if si._DNS_SEMAPHORE.acquire(blocking=False):
                    acquired += 1
                else:
                    break
            assert acquired == si._MAX_CONCURRENT_DNS
            assert (
                await aresolve_and_check_host("example.com", 443, 16, deadline_seconds=1.0)
                is False
            )
        finally:
            for _ in range(acquired):
                si._DNS_SEMAPHORE.release()
