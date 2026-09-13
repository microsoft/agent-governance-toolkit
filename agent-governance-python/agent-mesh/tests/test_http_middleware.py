# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for HTTP trust middleware (#118).

Covers TrustMiddleware request authentication, fail-closed configuration,
signature/freshness/replay enforcement, registry-anchored authorization, error
responses, and framework-specific decorators (Flask/FastAPI).

Regression focus: ``X-Agent-DID`` is attacker-controlled. Presenting one must
never, on its own, authenticate a caller.
"""

import base64
import importlib.util
import secrets
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from unittest import mock

import pytest

from agentmesh.identity.agent_id import AgentIdentity, IdentityRegistry
from agentmesh.integrations import http_middleware as _http
from agentmesh.integrations.http_middleware import (
    PeerCredential,
    TrustConfig,
    TrustMiddleware,
    VerificationResult,
    registry_resolver,
)
from agentmesh.integrations.http_middleware import BODY_LIMIT_SCOPE_KEY
from agentmesh.integrations.request_auth import (
    REQUEST_SIGNATURE_VERSION,
    InMemoryReplayCache,
    ReplayCacheFull,
    build_request_signature_payload,
    capability_satisfied,
    replay_key,
    sanitize_did,
)

AUDIENCE = "tests.agentmesh.example"

# Framework-dependent tests are skipped per class or per test, never at module
# scope: a module-level importorskip would silently drop the bypass regressions
# that need no framework at all.
flask = pytest.mark.skipif(
    importlib.util.find_spec("flask") is None, reason="Flask not installed"
)

TARGET = "/protected"
BODY = b""
# None means "no Content-Type header", which is what a real client sends on a
# GET with no body. An empty string is not a valid wire value: Werkzeug drops an
# empty CONTENT_TYPE when iterating headers, so signing "" would produce an
# envelope no server could ever reproduce.
CONTENT_TYPE = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_identity(name: str = "test-agent", capabilities=("read", "write")) -> AgentIdentity:
    return AgentIdentity.create(
        name=name,
        sponsor=f"{name}@test.example.com",
        capabilities=list(capabilities),
    )


def _registry(*identities: AgentIdentity) -> IdentityRegistry:
    registry = IdentityRegistry()
    for identity in identities:
        registry.register(identity)
    return registry


def _middleware(
    registry: IdentityRegistry,
    config: TrustConfig | None = None,
    *,
    identity: AgentIdentity | None = None,
) -> TrustMiddleware:
    return TrustMiddleware.from_registry(
        registry,
        config or TrustConfig(audience=AUDIENCE),
        identity=identity,
        allow_insecure_replay_cache=True,
    )


def _nonce() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(16)).decode().rstrip("=")


def _signed_headers(
    signer: AgentIdentity,
    *,
    did: str | None = None,
    audience: str = AUDIENCE,
    timestamp: str | None = None,
    nonce: str | None = None,
    method: str = "GET",
    request_target: str = TARGET,
    target_mode: str = "raw",
    body: bytes = BODY,
    content_type: str | None = CONTENT_TYPE,
    extra: dict[str, str] | None = None,
) -> dict[str, str]:
    """Build correctly signed AgentMesh auth headers.

    ``timestamp``/``nonce`` are auto-generated only when ``None``; an explicit
    empty string is passed through so malformed-input cases stay testable.

    ``content_type`` is both signed and emitted as a real header, because the
    server derives the covered header set from the request it actually
    received. Pass ``None`` to omit it entirely.
    """
    did = did if did is not None else str(signer.did)
    timestamp = datetime.now(UTC).isoformat() if timestamp is None else timestamp
    nonce = _nonce() if nonce is None else nonce
    signed_header_values = {} if content_type is None else {"content-type": content_type}
    payload = build_request_signature_payload(
        agent_did=did,
        audience=audience,
        timestamp=timestamp,
        nonce=nonce,
        method=method,
        request_target=request_target,
        target_mode=target_mode,
        body=body,
        signed_headers=signed_header_values,
    )
    headers = {
        "X-Agent-DID": did,
        "X-Agent-Signature": signer.sign(payload),
        "X-Agent-Timestamp": timestamp,
        "X-Agent-Nonce": nonce,
    }
    if content_type is not None:
        headers["Content-Type"] = content_type
    headers.update(extra or {})
    return headers


def _ctx(**overrides):
    ctx = {
        "method": "GET",
        "request_target": TARGET,
        "body": BODY,
    }
    ctx.update(overrides)
    return ctx


def _credential(identity: AgentIdentity, trust_score: float = 750.0) -> PeerCredential:
    """Build the credential a registry would return for this identity."""
    return PeerCredential(
        public_key=identity.public_key,
        capabilities=tuple(identity.capabilities),
        trust_score=trust_score,
    )


# ---------------------------------------------------------------------------
# Authentication bypass regressions
# ---------------------------------------------------------------------------

class TestSpoofedDidRejected:
    """A bare or spoofed X-Agent-DID header must never authenticate."""

    def test_bare_spoofed_did_rejected(self):
        """Unsigned request with an invented DID is rejected (was: score 1.0)."""
        agent = _make_identity()
        mw = _middleware(_registry(agent))

        result, err = mw.verify_request({"X-Agent-DID": "did:mesh:attacker"}, **_ctx())

        assert result.verified is False
        assert result.authenticated is False
        assert result.trust_score == 0.0
        assert err["status"] == 401

    def test_spoofing_registered_did_without_signature_rejected(self):
        """Knowing a real agent's DID grants nothing without its private key."""
        agent = _make_identity(capabilities=("admin",))
        mw = _middleware(_registry(agent))

        result, err = mw.verify_request({"X-Agent-DID": str(agent.did)}, **_ctx())

        assert result.verified is False
        assert err["status"] == 401

    def test_self_asserted_capabilities_ignored(self):
        """X-Agent-Capabilities cannot grant capabilities the registry withholds."""
        agent = _make_identity(capabilities=("read",))
        mw = _middleware(
            _registry(agent),
            TrustConfig(audience=AUDIENCE, required_capabilities=["admin"]),
        )
        headers = _signed_headers(agent, extra={"X-Agent-Capabilities": "admin,read,write"})

        result, err = mw.verify_request(headers, **_ctx())

        assert result.authenticated is True
        assert result.verified is False
        assert err["status"] == 403
        assert "admin" in err["missing"]

    def test_attacker_key_beside_victim_did_rejected(self):
        """Signing with an attacker key while claiming a victim DID fails."""
        victim = _make_identity("victim", capabilities=("admin",))
        attacker = _make_identity("attacker", capabilities=("admin",))
        mw = _middleware(_registry(victim))

        headers = _signed_headers(attacker, did=str(victim.did))
        result, err = mw.verify_request(headers, **_ctx())

        assert result.verified is False
        assert err["status"] == 401

    def test_presented_public_key_must_match_registry(self):
        """A mismatched X-Agent-Public-Key is a key-confusion attempt."""
        agent = _make_identity()
        attacker = _make_identity("attacker")
        mw = _middleware(_registry(agent))

        headers = _signed_headers(agent, extra={"X-Agent-Public-Key": attacker.public_key})
        result, err = mw.verify_request(headers, **_ctx())

        assert result.verified is False
        assert "public key" in result.reason.lower()
        # The client-visible body must not explain *why* authentication failed.
        assert "reason" not in err
        assert err["status"] == 401

    def test_unregistered_agent_rejected(self):
        """A validly signed request from an unknown DID is still rejected."""
        stranger = _make_identity("stranger")
        mw = _middleware(_registry(_make_identity()))

        result, err = mw.verify_request(_signed_headers(stranger), **_ctx())

        assert result.verified is False
        assert err["status"] == 401

    def test_lowercased_headers_cannot_bypass(self):
        """Starlette lowercases headers; lookup must stay case-insensitive."""
        agent = _make_identity()
        mw = _middleware(_registry(agent))

        spoof = {"x-agent-did": "did:mesh:attacker", "x-agent-capabilities": "admin"}
        result, _ = mw.verify_request(spoof, **_ctx())
        assert result.verified is False

        signed = {k.lower(): v for k, v in _signed_headers(agent).items()}
        result, err = mw.verify_request(signed, **_ctx())
        assert result.verified is True, err

    def test_missing_request_context_fails_closed(self):
        """Without method/target/body the signature cannot be bound."""
        agent = _make_identity()
        mw = _middleware(_registry(agent))

        result, err = mw.verify_request(_signed_headers(agent))

        assert result.verified is False
        assert err["status"] == 500


# ---------------------------------------------------------------------------
# Happy path
# ---------------------------------------------------------------------------

class TestSignedRequestAccepted:
    """Correctly signed requests from registered agents are accepted."""

    def test_valid_signed_request_passes(self):
        agent = _make_identity(capabilities=("read", "write"))
        mw = _middleware(
            _registry(agent),
            TrustConfig(audience=AUDIENCE, required_capabilities=["read"]),
        )

        result, err = mw.verify_request(_signed_headers(agent), **_ctx())

        assert err is None
        assert result.verified is True
        assert result.authenticated is True
        assert result.peer_did == str(agent.did)
        assert result.capabilities == ("read", "write")

    def test_signature_covers_body_and_target(self):
        agent = _make_identity()
        mw = _middleware(_registry(agent))
        headers = _signed_headers(
            agent, method="POST", request_target="/deploy?env=prod",
            body=b'{"replicas":1}', content_type="application/json",
        )

        result, err = mw.verify_request(
            headers,
            **_ctx(method="POST", request_target="/deploy?env=prod",
                   body=b'{"replicas":1}'),
        )
        assert result.verified is True, err

    def test_permissive_mode_is_not_authenticated(self):
        """Anonymous pass-through must be distinguishable from proven identity."""
        mw = _middleware(
            _registry(),
            TrustConfig(audience=AUDIENCE, permissive_mode=True, required_trust_score=0.0),
        )

        result, err = mw.verify_request({}, **_ctx())

        assert err is None
        assert result.verified is True
        assert result.authenticated is False
        assert result.trust_score == 0.0
        assert result.peer_did == ""

    def test_permissive_mode_still_verifies_a_presented_did(self):
        """Permissive mode admits *no* credentials; it never accepts bad ones.

        This is the regression guard for the original MSRC bypass: if the
        permissive branch ever moves below the DID lookup, a bare X-Agent-DID
        header would be admitted again.
        """
        agent = _make_identity()
        mw = _middleware(
            _registry(agent),
            TrustConfig(audience=AUDIENCE, permissive_mode=True, required_trust_score=0.0),
        )

        result, err = mw.verify_request({"X-Agent-DID": str(agent.did)}, **_ctx())

        assert result.verified is False
        assert result.authenticated is False
        assert err["status"] == 401

    def test_missing_did_strict_rejected(self):
        mw = _middleware(_registry(), TrustConfig(audience=AUDIENCE))

        result, err = mw.verify_request({}, **_ctx())

        assert result.verified is False
        assert "Missing X-Agent-DID" in result.reason
        assert "reason" not in err
        assert err["status"] == 401


# ---------------------------------------------------------------------------
# Tamper / freshness / replay
# ---------------------------------------------------------------------------

class TestTamperAndReplay:
    """Signature binding, freshness, and single-use nonce enforcement."""

    @pytest.mark.parametrize(
        ("ctx_override", "header_override"),
        [
            ({"method": "DELETE"}, {}),
            ({"request_target": "/admin/delete"}, {}),
            ({"body": b"tampered"}, {}),
            ({}, {"Content-Type": "text/plain"}),
            # Presence is signed, not just the value: stripping a covered
            # header must not silently narrow what the signature protects.
            ({}, {"Content-Type": None}),
        ],
        ids=["method", "target", "body", "content_type", "content_type_removed"],
    )
    def test_request_tampering_rejected(self, ctx_override, header_override):
        agent = _make_identity()
        mw = _middleware(_registry(agent))
        headers = _signed_headers(agent, content_type="application/json")
        for name, value in header_override.items():
            if value is None:
                headers.pop(name, None)
            else:
                headers[name] = value

        result, err = mw.verify_request(headers, **_ctx(**ctx_override))

        assert result.verified is False
        assert err["status"] == 401

    def test_unsigned_content_type_cannot_be_added(self):
        """A header absent at signing time must not be accepted at verify time."""
        agent = _make_identity()
        mw = _middleware(_registry(agent))
        headers = _signed_headers(agent, content_type=None)
        headers["Content-Type"] = "application/json"

        result, err = mw.verify_request(headers, **_ctx())

        assert result.verified is False
        assert err["status"] == 401

    def test_cross_audience_replay_rejected(self):
        """A signature captured at another service must not work here."""
        agent = _make_identity()
        mw = _middleware(_registry(agent))

        headers = _signed_headers(agent, audience="other.service.example")
        result, err = mw.verify_request(headers, **_ctx())

        assert result.verified is False
        assert err["status"] == 401

    def test_replayed_request_rejected(self):
        agent = _make_identity()
        mw = _middleware(_registry(agent))
        headers = _signed_headers(agent)

        first, err = mw.verify_request(headers, **_ctx())
        assert first.verified is True, err

        second, err = mw.verify_request(headers, **_ctx())
        assert second.verified is False
        assert "Replay" in second.reason

    @pytest.mark.parametrize("delta", [timedelta(hours=2), timedelta(hours=-2)])
    def test_stale_or_future_timestamp_rejected(self, delta):
        agent = _make_identity()
        mw = _middleware(_registry(agent))

        stamp = (datetime.now(UTC) + delta).isoformat()
        result, err = mw.verify_request(_signed_headers(agent, timestamp=stamp), **_ctx())

        assert result.verified is False
        assert err["status"] == 401

    def test_naive_timestamp_rejected(self):
        agent = _make_identity()
        mw = _middleware(_registry(agent))

        stamp = datetime.now(UTC).replace(tzinfo=None).isoformat()
        result, _ = mw.verify_request(_signed_headers(agent, timestamp=stamp), **_ctx())

        assert result.verified is False

    @pytest.mark.parametrize("nonce", ["", "short", "!!!not-base64!!!", "A" * 200])
    def test_malformed_nonce_rejected(self, nonce):
        agent = _make_identity()
        mw = _middleware(_registry(agent))

        result, _ = mw.verify_request(_signed_headers(agent, nonce=nonce), **_ctx())

        assert result.verified is False

    @pytest.mark.parametrize("signature", ["", "not-base64!", base64.b64encode(b"short").decode()])
    def test_malformed_signature_rejected(self, signature):
        agent = _make_identity()
        mw = _middleware(_registry(agent))

        headers = _signed_headers(agent)
        headers["X-Agent-Signature"] = signature
        result, _ = mw.verify_request(headers, **_ctx())

        assert result.verified is False

    def test_oversized_body_rejected(self):
        agent = _make_identity()
        mw = _middleware(
            _registry(agent), TrustConfig(audience=AUDIENCE, max_signed_body_bytes=16)
        )

        body = b"x" * 64
        result, err = mw.verify_request(
            _signed_headers(agent, body=body), **_ctx(body=body)
        )

        assert result.verified is False
        assert err["status"] == 413

    def test_nonce_burned_only_after_signature_verifies(self):
        """A bad signature must not consume the nonce of a pending good request."""
        agent = _make_identity()
        mw = _middleware(_registry(agent))
        headers = _signed_headers(agent)

        forged = dict(headers)
        forged["X-Agent-Signature"] = base64.b64encode(b"\x00" * 64).decode()
        bad, _ = mw.verify_request(forged, **_ctx())
        assert bad.verified is False

        good, err = mw.verify_request(headers, **_ctx())
        assert good.verified is True, err


# ---------------------------------------------------------------------------
# Fail-closed configuration
# ---------------------------------------------------------------------------

class TestFailClosedConfiguration:
    """Insecure middleware configurations must be refused at construction."""

    def test_missing_peer_resolver_refused(self):
        with pytest.raises(ValueError, match="peer_resolver is required"):
            TrustMiddleware(config=TrustConfig(audience=AUDIENCE))

    def test_missing_audience_refused(self):
        with pytest.raises(ValueError, match="audience"):
            TrustMiddleware(
                config=TrustConfig(),
                peer_resolver=lambda did: None,
                allow_insecure_replay_cache=True,
            )

    def test_missing_replay_cache_refused(self):
        with pytest.raises(ValueError, match="replay_cache is required"):
            TrustMiddleware(
                config=TrustConfig(audience=AUDIENCE),
                peer_resolver=lambda did: None,
            )

    @pytest.mark.parametrize(
        "kwargs",
        [{"replay_window_seconds": 0}, {"replay_window_seconds": -1},
         {"max_signed_body_bytes": 0}],
    )
    def test_invalid_config_values_refused(self, kwargs):
        with pytest.raises(ValueError):
            TrustConfig(audience=AUDIENCE, **kwargs)

    def test_required_capabilities_are_immutable(self):
        cfg = TrustConfig(audience=AUDIENCE, required_capabilities=["admin"])
        assert cfg.required_capabilities == ("admin",)
        with pytest.raises(AttributeError):
            cfg.required_capabilities.append("root")  # type: ignore[attr-defined]

    def test_config_is_frozen_so_the_permissive_guard_cannot_be_bypassed(self):
        """The permissive_mode invariant lives in __post_init__; mutation would void it."""
        cfg = TrustConfig(audience=AUDIENCE, required_capabilities=("admin",))
        with pytest.raises(FrozenInstanceError):
            cfg.permissive_mode = True  # type: ignore[misc]
        assert cfg.permissive_mode is False

    def test_required_capabilities_rejects_a_bare_string(self):
        """tuple("admin") would silently become five unsatisfiable capabilities."""
        with pytest.raises(ValueError, match="not a single string"):
            TrustConfig(audience=AUDIENCE, required_capabilities="admin")  # type: ignore[arg-type]

    def test_resolver_exception_fails_closed(self):
        def boom(did: str):
            raise RuntimeError("registry offline")

        agent = _make_identity()
        mw = TrustMiddleware(
            config=TrustConfig(audience=AUDIENCE),
            peer_resolver=boom,
            allow_insecure_replay_cache=True,
        )

        result, err = mw.verify_request(_signed_headers(agent), **_ctx())

        assert result.verified is False
        assert result.authenticated is False
        # 503, not 401: a registry outage is a server fault, and the caller's
        # credentials were never assessed.
        assert err["status"] == 503

    def test_replay_cache_failure_fails_closed(self):
        class BrokenCache:
            def add(self, key: str, ttl_seconds: int) -> bool:
                raise RuntimeError("redis down")

        agent = _make_identity()
        mw = TrustMiddleware(
            config=TrustConfig(audience=AUDIENCE),
            peer_resolver=registry_resolver(_registry(agent)),
            replay_cache=BrokenCache(),
        )

        result, _ = mw.verify_request(_signed_headers(agent), **_ctx())

        assert result.verified is False

    def test_revoked_identity_resolves_to_none(self):
        agent = _make_identity()
        registry = _registry(agent)
        registry.revoke(str(agent.did), "compromised")
        mw = _middleware(registry)

        result, err = mw.verify_request(_signed_headers(agent), **_ctx())

        assert result.verified is False
        assert err["status"] == 401

    def test_trust_score_threshold_enforced(self):
        agent = _make_identity()
        mw = TrustMiddleware(
            config=TrustConfig(audience=AUDIENCE, required_trust_score=0.9),
            peer_resolver=lambda did: PeerCredential(
                public_key=agent.public_key, capabilities=("read",), trust_score=0.4
            ),
            allow_insecure_replay_cache=True,
        )

        result, err = mw.verify_request(_signed_headers(agent), **_ctx())

        assert result.authenticated is True
        assert result.verified is False
        assert err["status"] == 403
        assert err["actual"] == 0.4


class TestInMemoryReplayCache:
    """Bounded single-process nonce cache."""

    def test_add_is_single_use(self):
        cache = InMemoryReplayCache()
        assert cache.add("k", 60) is True
        assert cache.add("k", 60) is False

    def test_expired_entry_is_reusable(self):
        cache = InMemoryReplayCache()
        assert cache.add("k", 1) is True
        cache._entries["k"] = 0.0  # force expiry on the monotonic clock
        assert cache.add("k", 60) is True

    def test_non_positive_ttl_refused(self):
        cache = InMemoryReplayCache()
        assert cache.add("k", 0) is False

    def test_capacity_is_bounded_and_fails_closed(self):
        cache = InMemoryReplayCache(max_entries=2)
        assert cache.add("a", 60) is True
        assert cache.add("b", 60) is True
        # Exhaustion is not a replay, so it must be distinguishable from one.
        with pytest.raises(ReplayCacheFull):
            cache.add("c", 60)
        assert len(cache) == 2

    def test_purge_reclaims_expired_capacity(self):
        cache = InMemoryReplayCache(max_entries=2)
        cache.add("a", 60)
        cache.add("b", 60)
        cache._entries["a"] = 0.0
        assert cache.add("c", 60) is True

    def test_concurrent_add_grants_exactly_one_winner(self):
        import threading

        cache = InMemoryReplayCache()
        barrier = threading.Barrier(8)
        results: list[bool] = []
        lock = threading.Lock()

        def worker() -> None:
            barrier.wait()
            won = cache.add("contended", 60)
            with lock:
                results.append(won)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=10)

        assert not any(t.is_alive() for t in threads)
        assert results.count(True) == 1
        assert len(results) == 8

    def test_invalid_capacity_refused(self):
        with pytest.raises(ValueError):
            InMemoryReplayCache(max_entries=0)


class TestResponseHeaders:
    """Outgoing response headers."""

    def test_response_headers_with_identity(self):
        identity = _make_identity()
        mw = _middleware(_registry(identity), identity=identity)
        hdrs = mw.response_headers()

        assert hdrs["X-Agent-DID"] == str(identity.did)
        assert "X-Agent-Public-Key" in hdrs

    def test_response_headers_without_identity(self):
        assert _middleware(_registry()).response_headers() == {}


class TestVerificationResult:
    """Result contract consumed by downstream handlers."""

    def test_defaults_are_untrusted(self):
        result = VerificationResult(verified=False)
        assert result.authenticated is False
        assert result.trust_score == 0.0
        assert result.capabilities == ()

    def test_result_is_immutable(self):
        result = VerificationResult(verified=False)
        with pytest.raises(Exception):
            result.verified = True  # type: ignore[misc]

    def test_positional_field_order_is_preserved(self):
        """Published dataclasses are a positional API for external callers.

        Inserting a field ahead of an existing one silently rebinds every
        positional construction in downstream code, so new fields go last.
        """
        result = VerificationResult(True, 750.0, "ok", "did:mesh:abc")
        assert result.verified is True
        assert result.trust_score == 750.0
        assert result.reason == "ok"
        assert result.peer_did == "did:mesh:abc"

    def test_trust_config_positional_field_order_is_preserved(self):
        config = TrustConfig(600.0, ("read",), False, audience=AUDIENCE)
        assert config.required_trust_score == 600.0
        assert config.required_capabilities == ("read",)
        assert config.permissive_mode is False


# ---------------------------------------------------------------------------
# Envelope compatibility, input bounding, and never-raise guarantees
# ---------------------------------------------------------------------------

class TestCanonicalEnvelope:
    """The signed envelope is a wire contract shared by Django/Flask/FastAPI."""

    GOLDEN = (
        b'agentmesh-http-request-v2\n'
        b'{"agent_did":"did:mesh:0123456789abcdef0123456789abcdef",'
        b'"audience":"golden.agentmesh.example",'
        b'"body_sha256":"93a23971a914e5eacbf0a8d25154cda309c3c1c72fbb9914d47c60f3cb681588",'
        b'"method":"POST",'
        b'"nonce":"Z29sZGVuLW5vbmNlLTAwMQ","request_target":"/v1/resource?x=1",'
        b'"signed_headers":{"content-type":"application/json"},'
        b'"target_mode":"raw",'
        b'"timestamp":"2026-01-02T03:04:05+00:00"}'
    )

    @staticmethod
    def _golden_kwargs():
        return {
            "agent_did": "did:mesh:0123456789abcdef0123456789abcdef",
            "audience": "golden.agentmesh.example",
            "timestamp": "2026-01-02T03:04:05+00:00",
            "nonce": "Z29sZGVuLW5vbmNlLTAwMQ",
            "method": "post",
            "request_target": "/v1/resource?x=1",
            "target_mode": "raw",
            "body": b'{"hello":"world"}',
            "signed_headers": {"Content-Type": "application/json"},
        }

    def test_payload_matches_frozen_vector(self):
        """Changing these bytes breaks every already-deployed signer."""
        assert build_request_signature_payload(**self._golden_kwargs()) == self.GOLDEN

    def test_version_prefix_is_stable(self):
        assert REQUEST_SIGNATURE_VERSION == "agentmesh-http-request-v2"

    def test_django_and_generic_share_one_implementation(self):
        """Django must not drift into a second, incompatible envelope."""
        from agentmesh.integrations.django_middleware.request_auth import (
            build_request_signature_payload as django_builder,
        )

        assert django_builder is build_request_signature_payload
        assert django_builder(**self._golden_kwargs()) == self.GOLDEN

    def test_percent_encoded_separator_is_distinguishable_from_a_real_one(self):
        """Regression: the envelope claims to bind the request target.

        Signing the framework-decoded path made ``/files/a%2Fb`` and
        ``/files/a/b`` produce identical bytes, so one signature authorised
        both. Anything downstream that re-reads the raw target — a proxy, a
        gateway, an audit log — could be pointed at a path the signer never
        approved.
        """
        common = {
            "agent_did": "did:mesh:0123456789abcdef0123456789abcdef",
            "audience": AUDIENCE,
            "timestamp": "2026-01-02T03:04:05+00:00",
            "nonce": "Z29sZGVuLW5vbmNlLTAwMQ",
            "method": "GET",
            "target_mode": "raw",
            "body": b"",
            "signed_headers": {},
        }
        encoded = build_request_signature_payload(request_target="/files/a%2Fb", **common)
        literal = build_request_signature_payload(request_target="/files/a/b", **common)

        assert encoded != literal

    def test_target_mode_is_part_of_the_signed_bytes(self):
        """A raw signature must not be replayable as a decoded one."""
        common = {
            "agent_did": "did:mesh:0123456789abcdef0123456789abcdef",
            "audience": AUDIENCE,
            "timestamp": "2026-01-02T03:04:05+00:00",
            "nonce": "Z29sZGVuLW5vbmNlLTAwMQ",
            "method": "GET",
            "request_target": "/files/a/b",
            "body": b"",
            "signed_headers": {},
        }
        assert (
            build_request_signature_payload(target_mode="raw", **common)
            != build_request_signature_payload(target_mode="decoded", **common)
        )

    def test_absent_header_is_not_signed_as_empty(self):
        """"Not sent" and "sent empty" must not collapse to the same envelope."""
        common = {
            "agent_did": "did:mesh:0123456789abcdef0123456789abcdef",
            "audience": AUDIENCE,
            "timestamp": "2026-01-02T03:04:05+00:00",
            "nonce": "Z29sZGVuLW5vbmNlLTAwMQ",
            "method": "GET",
            "request_target": "/x",
            "target_mode": "raw",
            "body": b"",
        }
        assert (
            build_request_signature_payload(signed_headers={}, **common)
            != build_request_signature_payload(signed_headers={"content-type": ""}, **common)
        )

    def test_select_signed_headers_omits_absent_headers(self):
        from agentmesh.integrations.request_auth import select_signed_headers

        present = {"content-type": "application/json"}
        assert select_signed_headers(
            ("content-type", "x-not-sent"), present.get
        ) == {"content-type": "application/json"}


class TestRawRequestTarget:
    """The signed target must reflect the wire, not the framework's decoding."""

    def test_raw_target_is_preferred_over_the_decoded_path(self):
        from agentmesh.integrations.request_auth import asgi_raw_target, wsgi_raw_target

        assert asgi_raw_target(
            {"raw_path": b"/files/a%2Fb", "query_string": b"q=x%2Fy"}
        ) == "/files/a%2Fb?q=x%2Fy"
        assert wsgi_raw_target({"RAW_URI": "/files/a%2Fb?q=x%2Fy"}) == "/files/a%2Fb?q=x%2Fy"
        assert wsgi_raw_target({"REQUEST_URI": "/files/a%2Fb"}) == "/files/a%2Fb"

    def test_absolute_form_is_reduced_to_origin_form(self):
        """A proxy may forward an absolute target; it must sign the same bytes."""
        from agentmesh.integrations.request_auth import wsgi_raw_target

        assert wsgi_raw_target({"RAW_URI": "https://svc.example/files?a=1"}) == "/files?a=1"

    def test_missing_raw_target_is_reported_not_guessed(self):
        from agentmesh.integrations.request_auth import asgi_raw_target, wsgi_raw_target

        assert wsgi_raw_target({"PATH_INFO": "/files/a/b"}) is None
        assert asgi_raw_target({"path": "/files/a/b"}) is None

    @staticmethod
    def _request_without_raw_target(agent):
        """A real Flask request from a server that hides the wire target.

        Werkzeug's EnvironBuilder sets both RAW_URI and REQUEST_URI; stripping
        them reproduces wsgiref-style servers (Django's runserver among them)
        without hand-rolling a request fake that could drift from the real one.
        """
        from flask import Request
        from werkzeug.test import EnvironBuilder

        environ = EnvironBuilder(
            path="/protected", headers={"X-Agent-DID": str(agent.did)}
        ).get_environ()
        environ.pop("RAW_URI", None)
        environ.pop("REQUEST_URI", None)
        return Request(environ)

    @flask
    def test_flask_adapter_fails_closed_without_a_raw_target(self):
        """A server that cannot prove the wire target must not authenticate."""
        from agentmesh.integrations.http_middleware import _flask_verify

        agent = _make_identity()
        mw = _middleware(_registry(agent))

        result, err = _flask_verify(mw, None, self._request_without_raw_target(agent))

        assert result is None
        assert err["status"] == 500
        assert "REQUEST_URI" in err["reason"]

    @flask
    def test_decoded_mode_is_an_explicit_opt_out(self):
        """Servers without a raw target can still run, but must say so."""
        from agentmesh.integrations.http_middleware import _flask_verify

        agent = _make_identity()
        mw = _middleware(
            _registry(agent),
            TrustConfig(audience=AUDIENCE, request_target_mode="decoded"),
        )

        _result, err = _flask_verify(mw, None, self._request_without_raw_target(agent))

        # Reaches real verification and fails on the bare DID, not on config.
        assert err["status"] == 401


class TestVerificationDeadline:
    """Verification runs on a bounded budget shared by every I/O port."""

    def test_budget_is_passed_to_a_timeout_aware_resolver(self):
        agent = _make_identity()
        credential = _credential(agent)
        observed: list[float] = []

        def resolver(did: str, *, timeout_seconds: float) -> PeerCredential:
            observed.append(timeout_seconds)
            return credential

        mw = TrustMiddleware(
            config=TrustConfig(audience=AUDIENCE, io_timeout_seconds=2.5),
            peer_resolver=resolver,
            allow_insecure_replay_cache=True,
        )

        result, err = mw.verify_request(_signed_headers(agent), **_ctx())

        assert result.authenticated is True, err
        assert observed and 0 < observed[0] <= 2.5

    def test_resolver_without_a_timeout_parameter_is_still_called(self):
        """Deadline support is optional; a plain resolver must keep working."""
        agent = _make_identity()
        credential = _credential(agent)

        def resolver(did: str) -> PeerCredential:
            return credential

        mw = TrustMiddleware(
            config=TrustConfig(audience=AUDIENCE),
            peer_resolver=resolver,
            allow_insecure_replay_cache=True,
        )

        result, err = mw.verify_request(_signed_headers(agent), **_ctx())
        assert result.authenticated is True, err

    def test_exhausted_budget_denies_with_503_before_the_nonce_is_burned(self):
        """A slow registry is our fault, not the caller's, and must not
        consume their single-use nonce."""
        agent = _make_identity()
        credential = _credential(agent)
        cache = InMemoryReplayCache()
        clock = iter([0.0, 0.0, 99.0, 99.0, 99.0, 99.0])

        def resolver(did: str) -> PeerCredential:
            return credential

        mw = TrustMiddleware(
            config=TrustConfig(audience=AUDIENCE, io_timeout_seconds=1.0),
            peer_resolver=resolver,
            replay_cache=cache,
        )
        headers = _signed_headers(agent)

        with mock.patch.object(_http.time, "monotonic", lambda: next(clock)):
            result, err = mw.verify_request(headers, **_ctx())

        assert result.authenticated is False
        assert err["status"] == 503
        # The nonce survives, so a well-behaved caller can retry.
        assert cache.add(replay_key(str(agent.did), AUDIENCE, b"x" * 16), 60) is True

    def test_timeout_aware_replay_cache_receives_the_remaining_budget(self):
        agent = _make_identity()
        credential = _credential(agent)
        observed: list[float] = []

        class _TimeoutAwareCache:
            def add(self, key, ttl_seconds, *, timeout_seconds=None):
                observed.append(timeout_seconds)
                return True

        mw = TrustMiddleware(
            config=TrustConfig(audience=AUDIENCE, io_timeout_seconds=3.0),
            peer_resolver=lambda did: credential,
            replay_cache=_TimeoutAwareCache(),
        )

        result, err = mw.verify_request(_signed_headers(agent), **_ctx())

        assert result.authenticated is True, err
        assert observed and 0 < observed[0] <= 3.0

    def test_replay_cache_timeout_is_503_not_401(self):
        agent = _make_identity()
        credential = _credential(agent)

        class _StalledCache:
            def add(self, key, ttl_seconds, *, timeout_seconds=None):
                raise TimeoutError("replay store did not answer")

        mw = TrustMiddleware(
            config=TrustConfig(audience=AUDIENCE),
            peer_resolver=lambda did: credential,
            replay_cache=_StalledCache(),
        )

        result, err = mw.verify_request(_signed_headers(agent), **_ctx())

        assert result.authenticated is False
        assert err["status"] == 503

    def test_io_timeout_must_be_positive(self):
        with pytest.raises(ValueError, match="io_timeout_seconds"):
            TrustConfig(audience=AUDIENCE, io_timeout_seconds=0)


class TestReplayKeyNamespacing:
    """A nonce is only valid for one audience."""

    def test_key_is_namespaced_by_audience(self):
        """Two services sharing a cache must not burn each other's nonces."""
        nonce = b"\x01" * 16
        assert replay_key("did:mesh:a", "svc-a", nonce) != replay_key(
            "did:mesh:a", "svc-b", nonce
        )

    def test_fields_are_length_delimited(self):
        nonce = b"\x01" * 16
        assert replay_key("did:mesh:a", "b", nonce) != replay_key("did:mesh:a\0b", "", nonce)

    def test_nonce_is_not_stored_verbatim(self):
        key = replay_key("did:mesh:a", "svc", b"\x02" * 16)
        assert "\x02" not in key
        assert key.startswith("agentmesh:request-nonce:")


class TestDidSanitization:
    """Untrusted DIDs are bounded before they reach a resolver or a log sink."""

    @pytest.mark.parametrize(
        "value",
        [
            "",
            "not-a-did",
            "did:mesh:" + "a" * 300,
            "did:mesh:abc\ninjected log line",
            "did:mesh:abc\r\nSet-Cookie: x",
            "did:mesh:abc\x00",
            "did:mesh:café",
        ],
    )
    def test_hostile_dids_are_rejected(self, value):
        assert sanitize_did(value) is None

    @pytest.mark.parametrize(
        "value",
        ["did:mesh:0123456789abcdef", "did:web:example.com", "did:key:z6Mk"],
    )
    def test_plausible_dids_are_accepted(self, value):
        assert sanitize_did(value) == value

    def test_middleware_rejects_hostile_did_without_resolving_it(self):
        seen: list[str] = []

        def resolver(did: str):
            seen.append(did)
            return None

        mw = TrustMiddleware(
            config=TrustConfig(audience=AUDIENCE),
            peer_resolver=resolver,
            allow_insecure_replay_cache=True,
        )
        result, err = mw.verify_request({"X-Agent-DID": "did:mesh:x\nFAKE"}, **_ctx())

        assert result.verified is False
        assert err["status"] == 401
        assert seen == []


class TestNeverRaises:
    """Every input here is attacker-controlled; none may produce a 500."""

    def test_non_ascii_public_key_header_is_denied_not_crashed(self):
        """Header values decode as latin-1, so this used to raise TypeError."""
        agent = _make_identity()
        mw = _middleware(_registry(agent))
        headers = _signed_headers(agent, extra={"X-Agent-Public-Key": "\xe9\xff"})

        result, err = mw.verify_request(headers, **_ctx())

        assert result.verified is False
        assert err["status"] == 401

    @pytest.mark.parametrize(
        "bad_key",
        ["not base64!!", "\xe9", "AAAA", "", "  "],
    )
    def test_malformed_public_key_headers_are_denied(self, bad_key):
        agent = _make_identity()
        mw = _middleware(_registry(agent))
        headers = _signed_headers(agent, extra={"X-Agent-Public-Key": bad_key})

        result, err = mw.verify_request(headers, **_ctx())

        # An empty/whitespace key is treated as absent; anything present but
        # unusable is a key-confusion attempt and denied.
        if bad_key.strip():
            assert result.verified is False
            assert err["status"] == 401

    def test_resolver_exception_is_503_not_a_credential_failure(self):
        """A registry outage must not present as "everyone has bad credentials"."""
        def boom(did: str):
            raise RuntimeError("registry down")

        mw = TrustMiddleware(
            config=TrustConfig(audience=AUDIENCE),
            peer_resolver=boom,
            allow_insecure_replay_cache=True,
        )
        agent = _make_identity()
        result, err = mw.verify_request(_signed_headers(agent), **_ctx())

        assert result.verified is False
        assert result.authenticated is False
        assert err["status"] == 503

    def test_duck_typed_credential_is_503_not_a_credential_failure(self):
        """A resolver returning a malformed object is a server bug, not an attack."""
        class NoPublicKey:
            capabilities = ()

        mw = TrustMiddleware(
            config=TrustConfig(audience=AUDIENCE),
            peer_resolver=lambda did: NoPublicKey(),
            allow_insecure_replay_cache=True,
        )
        agent = _make_identity()
        result, err = mw.verify_request(_signed_headers(agent), **_ctx())

        assert result.verified is False
        assert err["status"] == 503

    def test_unregistered_did_is_still_401(self):
        """An unknown DID is a genuine credential failure and stays 401."""
        mw = TrustMiddleware(
            config=TrustConfig(audience=AUDIENCE),
            peer_resolver=lambda did: None,
            allow_insecure_replay_cache=True,
        )
        agent = _make_identity()
        result, err = mw.verify_request(_signed_headers(agent), **_ctx())

        assert result.verified is False
        assert err["status"] == 401

    def test_hostile_headers_object_cannot_escape_the_never_raise_boundary(self):
        """The error path re-reads headers; that read must not itself escape."""
        class Hostile(dict):
            def __iter__(self):
                raise RuntimeError("hostile mapping")

            def items(self):
                raise RuntimeError("hostile mapping")

            def get(self, *a, **k):
                raise RuntimeError("hostile mapping")

        mw = _middleware(_registry())
        result, err = mw.verify_request(Hostile(), **_ctx())

        assert result.verified is False
        assert result.authenticated is False
        assert err["status"] == 503

    def test_pre_auth_tracebacks_are_rate_limited(self, caplog, monkeypatch):
        """logger.exception writes a full traceback; unauthenticated callers must
        not be able to drive one per request."""
        monkeypatch.setattr(_http, "_denial_signal", _http._DenialSignal(60.0))

        def boom(did: str):
            raise RuntimeError("registry down")

        mw = TrustMiddleware(
            config=TrustConfig(audience=AUDIENCE),
            peer_resolver=boom,
            allow_insecure_replay_cache=True,
        )
        agent = _make_identity()

        with caplog.at_level("DEBUG", logger=_http.__name__):
            for _ in range(50):
                result, err = mw.verify_request(_signed_headers(agent), **_ctx())
                assert err["status"] == 503

        errors = [r for r in caplog.records if r.levelname == "ERROR"]
        assert len(errors) == 1, "traceback flood: an unauthenticated caller can spam ERROR"
        assert errors[0].exc_info is not None, "the first fault must keep its traceback"
        assert any(
            "traceback suppressed" in r.getMessage()
            for r in caplog.records
            if r.levelname == "DEBUG"
        ), "suppressed faults must still leave a DEBUG breadcrumb"

    def test_first_traceback_per_interval_is_always_emitted(self, caplog, monkeypatch):
        """Throttling must never hide a fault entirely."""
        monkeypatch.setattr(_http, "_denial_signal", _http._DenialSignal(0.0))

        mw = TrustMiddleware(
            config=TrustConfig(audience=AUDIENCE),
            peer_resolver=lambda did: (_ for _ in ()).throw(RuntimeError("down")),
            allow_insecure_replay_cache=True,
        )
        agent = _make_identity()

        with caplog.at_level("DEBUG", logger=_http.__name__):
            mw.verify_request(_signed_headers(agent), **_ctx())
            mw.verify_request(_signed_headers(agent), **_ctx())

        assert len([r for r in caplog.records if r.levelname == "ERROR"]) == 2

    def test_replay_cache_exhaustion_is_503_not_a_replay_report(self):
        """Capacity failure is an availability fault, not an attack."""
        agent = _make_identity()
        mw = TrustMiddleware.from_registry(
            _registry(agent),
            TrustConfig(audience=AUDIENCE),
            replay_cache=InMemoryReplayCache(max_entries=1),
        )
        assert mw.verify_request(_signed_headers(agent), **_ctx())[1] is None

        result, err = mw.verify_request(_signed_headers(agent), **_ctx())

        assert result.verified is False
        assert err["status"] == 503
        assert "Replay protection unavailable" in result.reason


class TestDenialTelemetry:
    """Pre-auth denials log at DEBUG; an aggregate WARNING keeps them visible."""

    def test_denial_emits_a_warning_at_default_log_levels(self, caplog):
        signal = _http._DenialSignal(min_interval_seconds=60.0)
        with caplog.at_level("WARNING", logger=_http.__name__):
            signal.record(401, "Signature verification failed")

        assert "Signature verification failed" in caplog.text
        assert "status=401" in caplog.text

    def test_repeated_denials_are_rate_limited_not_flooded(self, caplog):
        signal = _http._DenialSignal(min_interval_seconds=60.0)
        with caplog.at_level("WARNING", logger=_http.__name__):
            for _ in range(500):
                signal.record(401, "Signature verification failed")

        warnings = [r for r in caplog.records if r.levelname == "WARNING"]
        assert len(warnings) == 1, "an unauthenticated caller must not be able to flood logs"

    def test_suppressed_count_is_reported_on_the_next_emission(self, caplog):
        signal = _http._DenialSignal(min_interval_seconds=0.0)
        with caplog.at_level("WARNING", logger=_http.__name__):
            signal.record(401, "reason-a")
            signal.record(401, "reason-a")

        assert len([r for r in caplog.records if r.levelname == "WARNING"]) == 2

    def test_distinct_reasons_are_tracked_separately(self, caplog):
        signal = _http._DenialSignal(min_interval_seconds=60.0)
        with caplog.at_level("WARNING", logger=_http.__name__):
            signal.record(401, "Unknown or untrusted agent DID")
            signal.record(503, "Replay protection unavailable")

        warnings = [r for r in caplog.records if r.levelname == "WARNING"]
        assert len(warnings) == 2

    def test_denial_signal_never_logs_the_did(self, caplog, monkeypatch):
        """The reason label is coarse by design; DIDs must not reach WARNING."""
        # Use a fresh signal so an earlier test's rate limit cannot suppress this one.
        monkeypatch.setattr(_http, "_denial_signal", _http._DenialSignal(0.0))
        agent = _make_identity()
        mw = _middleware(_registry(agent))
        headers = _signed_headers(agent)
        headers["X-Agent-DID"] = "did:mesh:" + "ab" * 16

        with caplog.at_level("WARNING", logger=_http.__name__):
            mw.verify_request(headers, **_ctx())

        warnings = [r for r in caplog.records if r.levelname == "WARNING"]
        assert warnings, "a denial must be visible at WARNING"
        assert "deadbeef" not in "\n".join(r.getMessage() for r in warnings)


class TestCapabilityMatching:
    """Registry capabilities keep the same semantics they have on AgentIdentity."""

    @pytest.mark.parametrize(
        ("required", "granted", "expected"),
        [
            ("admin", ("admin",), True),
            ("admin", ("*",), True),
            ("read:data", ("read:*",), True),
            ("read:data", ("write:*",), False),
            ("admin", ("read", "write"), False),
            ("admin", (), False),
            ("read", (":*",), False),
        ],
    )
    def test_matcher_mirrors_agent_identity(self, required, granted, expected):
        assert capability_satisfied(required, granted) is expected

    def test_authorization_failure_is_logged_with_the_agent_did(self, caplog):
        """Post-auth: capability probing by a known agent must be visible."""
        agent = _make_identity(capabilities=("read",))
        mw = _middleware(
            _registry(agent),
            TrustConfig(audience=AUDIENCE, required_capabilities=("admin",)),
        )

        with caplog.at_level("WARNING", logger=_http.__name__):
            result, err = mw.verify_request(_signed_headers(agent), **_ctx())

        assert err["status"] == 403
        assert result.authenticated is True
        assert str(agent.did) in caplog.text
        assert "admin" in caplog.text

    def test_wildcard_identity_satisfies_required_capability(self):
        agent = _make_identity(capabilities=("*",))
        mw = _middleware(
            _registry(agent),
            TrustConfig(audience=AUDIENCE, required_capabilities=("admin",)),
        )

        result, err = mw.verify_request(_signed_headers(agent), **_ctx())

        assert err is None
        assert result.verified is True

    def test_header_capabilities_are_still_ignored(self):
        """The registry is the only source of authorization facts."""
        agent = _make_identity(capabilities=("read",))
        mw = _middleware(
            _registry(agent),
            TrustConfig(audience=AUDIENCE, required_capabilities=("admin",)),
        )
        headers = _signed_headers(agent, extra={"X-Agent-Capabilities": "admin,*"})

        result, err = mw.verify_request(headers, **_ctx())

        assert result.verified is False
        assert result.authenticated is True
        assert err["status"] == 403


# ---------------------------------------------------------------------------
# Flask decorator tests (skipped if Flask not installed)
# ---------------------------------------------------------------------------


@flask
class TestFlaskDecorator:
    """Tests for flask_trust_required decorator."""

    def _app(self, middleware: TrustMiddleware):
        from flask import Flask, g, jsonify

        from agentmesh.integrations.http_middleware import flask_trust_required

        app = Flask(__name__)

        @app.route("/protected", methods=["GET", "POST"])
        @flask_trust_required(middleware)
        def protected():
            return jsonify({"ok": True, "peer_did": g.peer_did})

        return app

    def test_signed_request_passes(self):
        agent = _make_identity()
        mw = _middleware(_registry(agent))
        app = self._app(mw)

        with app.test_client() as client:
            resp = client.get("/protected", headers=_signed_headers(agent))
            assert resp.status_code == 200, resp.get_json()
            assert resp.get_json()["peer_did"] == str(agent.did)

    def test_spoofed_did_blocked(self):
        agent = _make_identity()
        app = self._app(_middleware(_registry(agent)))

        with app.test_client() as client:
            resp = client.get("/protected", headers={"X-Agent-DID": str(agent.did)})
            assert resp.status_code == 401
            assert "error" in resp.get_json()

    def test_missing_did_blocked(self):
        app = self._app(_middleware(_registry()))

        with app.test_client() as client:
            resp = client.get("/protected")
            assert resp.status_code == 401

    def test_replay_blocked_end_to_end(self):
        agent = _make_identity()
        app = self._app(_middleware(_registry(agent)))
        headers = _signed_headers(agent)

        with app.test_client() as client:
            assert client.get("/protected", headers=headers).status_code == 200
            assert client.get("/protected", headers=headers).status_code == 401

    def test_query_string_is_signed(self):
        agent = _make_identity()
        app = self._app(_middleware(_registry(agent)))
        headers = _signed_headers(agent, request_target="/protected?a=1")

        with app.test_client() as client:
            assert client.get("/protected?a=1", headers=headers).status_code == 200
            assert client.get(
                "/protected?a=2", headers=_signed_headers(agent, request_target="/protected?a=1")
            ).status_code == 401

    def test_permissive_mode_does_not_admit_anonymous_to_required(self):
        """H-1 regression: `err is None` is not proof of identity."""
        mw = _middleware(
            _registry(),
            TrustConfig(audience=AUDIENCE, permissive_mode=True, required_trust_score=0.0),
        )

        with self._app(mw).test_client() as client:
            resp = client.get("/protected")
            assert resp.status_code == 401

    def test_trust_optional_admits_anonymous_but_marks_it(self):
        from flask import Flask, g, jsonify

        from agentmesh.integrations.http_middleware import flask_trust_optional

        mw = _middleware(
            _registry(),
            TrustConfig(audience=AUDIENCE, permissive_mode=True, required_trust_score=0.0),
        )
        app = Flask(__name__)

        @app.route("/open")
        @flask_trust_optional(mw)
        def open_route():
            return jsonify({"authenticated": g.trust_result.authenticated, "did": g.peer_did})

        with app.test_client() as client:
            body = client.get("/open").get_json()
            assert body == {"authenticated": False, "did": ""}

    def test_endpoint_can_still_read_the_body_after_verification(self):
        """The bounded read must not consume the body the view needs."""
        from flask import Flask, g, jsonify, request

        from agentmesh.integrations.http_middleware import flask_trust_required

        agent = _make_identity()
        app = Flask(__name__)

        @app.route("/echo", methods=["POST"])
        @flask_trust_required(_middleware(_registry(agent)))
        def echo():
            return jsonify({"body": request.get_json(), "did": g.peer_did})

        body = b'{"amount":100}'
        headers = _signed_headers(
            agent, method="POST", request_target="/echo",
            body=body, content_type="application/json",
            extra={"Content-Type": "application/json"},
        )

        with app.test_client() as client:
            resp = client.post("/echo", headers=headers, data=body)
            assert resp.status_code == 200, resp.get_json()
            assert resp.get_json() == {"body": {"amount": 100}, "did": str(agent.did)}

    def test_app_body_cap_is_clamped_not_raised(self):
        """The middleware may lower an app's body cap, never raise it."""
        from flask import Flask, jsonify, request

        from agentmesh.integrations.http_middleware import flask_trust_required

        agent = _make_identity()
        app = Flask(__name__)
        app.config["MAX_CONTENT_LENGTH"] = 1024
        mw = _middleware(
            _registry(agent),
            TrustConfig(audience=AUDIENCE, max_signed_body_bytes=2_621_440),
        )

        @app.route("/echo", methods=["POST"])
        @flask_trust_required(mw)
        def echo():
            return jsonify({"len": len(request.get_data())})

        with app.test_client() as client:
            resp = client.post(
                "/echo",
                headers={"X-Agent-DID": str(agent.did)},
                data=b"x" * 100_000,
            )
            assert resp.status_code == 413

    def test_oversized_body_is_rejected_without_buffering(self):
        """M-1 regression: the cap must bound memory, not just reject after the fact."""
        agent = _make_identity()
        mw = _middleware(
            _registry(agent),
            TrustConfig(audience=AUDIENCE, max_signed_body_bytes=64),
        )
        app = self._app(mw)

        with app.test_client() as client:
            resp = client.post(
                "/protected",
                headers={"X-Agent-DID": str(agent.did)},
                data=b"x" * 100_000,
            )
            assert resp.status_code == 413

    def test_client_disconnect_mid_body_is_503_not_a_500(self):
        """N-8 regression: the body read sits outside verify_request's never-raise boundary."""
        from werkzeug.exceptions import ClientDisconnected

        agent = _make_identity()
        app = self._app(_middleware(_registry(agent)))

        def _disconnect(*args, **kwargs):
            raise ClientDisconnected()

        with app.test_client() as client:
            with mock.patch("flask.Request.get_data", _disconnect):
                resp = client.post(
                    "/protected",
                    headers=_signed_headers(agent, method="POST"),
                    data=b"partial",
                )
            assert resp.status_code == 503, resp.get_data(as_text=True)

    def test_non_utf8_query_string_does_not_crash(self):
        """N-8/N-9: the query is signed as latin-1, so arbitrary bytes must not 500."""
        agent = _make_identity()
        app = self._app(_middleware(_registry(agent)))

        with app.test_client() as client:
            resp = client.get(
                "/protected?q=%FF%FE",
                headers={"X-Agent-DID": str(agent.did)},
            )
            assert resp.status_code == 401, resp.get_data(as_text=True)


# ---------------------------------------------------------------------------
# FastAPI dependency tests (skipped if FastAPI not installed)
# ---------------------------------------------------------------------------

fastapi = pytest.mark.skipif(
    importlib.util.find_spec("fastapi") is None or importlib.util.find_spec("httpx") is None,
    reason="FastAPI/httpx not installed",
)


@fastapi
class TestFastAPIDependency:
    """Tests for FastAPI integration with TrustMiddleware."""

    def _app(self, middleware: TrustMiddleware):
        from fastapi import Depends, FastAPI

        from agentmesh.integrations.http_middleware import (
            _error_status,
            install_fastapi_trust,
        )

        app = FastAPI()
        trust = install_fastapi_trust(app, middleware)

        @app.post("/protected")
        async def protected(result=Depends(trust)):
            return {"ok": True, "peer_did": result.peer_did}

        assert callable(_error_status)
        return app

    def test_signed_request_passes(self):
        from starlette.testclient import TestClient

        agent = _make_identity()
        client = TestClient(self._app(_middleware(_registry(agent))))
        headers = _signed_headers(
            agent, method="POST", request_target="/protected",
            body=b'{"a":1}', content_type="application/json",
            extra={"Content-Type": "application/json"},
        )

        resp = client.post("/protected", headers=headers, content=b'{"a":1}')
        assert resp.status_code == 200, resp.json()
        assert resp.json()["peer_did"] == str(agent.did)

    def test_spoofed_did_blocked(self):
        from starlette.testclient import TestClient

        agent = _make_identity()
        client = TestClient(self._app(_middleware(_registry(agent))))

        resp = client.post("/protected", headers={"X-Agent-DID": str(agent.did)})
        assert resp.status_code == 401

    def test_missing_did_blocked(self):
        from starlette.testclient import TestClient

        client = TestClient(self._app(_middleware(_registry())))
        resp = client.post("/protected")
        assert resp.status_code == 401
        assert "detail" in resp.json()

    def test_body_tamper_blocked(self):
        from starlette.testclient import TestClient

        agent = _make_identity()
        client = TestClient(self._app(_middleware(_registry(agent))))
        headers = _signed_headers(
            agent, method="POST", request_target="/protected",
            body=b'{"a":1}', content_type="application/json",
            extra={"Content-Type": "application/json"},
        )

        resp = client.post("/protected", headers=headers, content=b'{"a":999}')
        assert resp.status_code == 401

    def test_permissive_mode_does_not_admit_anonymous_to_required(self):
        """H-1 regression: the dependency must reject unauthenticated results."""
        from starlette.testclient import TestClient

        mw = _middleware(
            _registry(),
            TrustConfig(audience=AUDIENCE, permissive_mode=True, required_trust_score=0.0),
        )

        resp = TestClient(self._app(mw)).post("/protected")
        assert resp.status_code == 401

    def test_trust_optional_admits_anonymous_but_marks_it(self):
        from fastapi import Depends, FastAPI
        from starlette.testclient import TestClient

        from agentmesh.integrations.http_middleware import install_fastapi_trust

        mw = _middleware(
            _registry(),
            TrustConfig(audience=AUDIENCE, permissive_mode=True, required_trust_score=0.0),
        )
        app = FastAPI()
        trust = install_fastapi_trust(app, mw, optional=True)

        @app.post("/open")
        async def open_route(result=Depends(trust)):
            return {"authenticated": result.authenticated, "did": result.peer_did}

        resp = TestClient(app).post("/open")
        assert resp.status_code == 200
        assert resp.json() == {"authenticated": False, "did": ""}

    def test_dependency_is_usable_directly_with_depends(self):
        """``Depends(install_fastapi_trust(...))`` must not need a wrapper.

        This module uses ``from __future__ import annotations`` and imports
        ``fastapi`` lazily, so the dependency's ``request: Request`` annotation
        is the string ``"Request"`` and ``Request`` is absent from the module
        globals FastAPI resolves against. Left alone, FastAPI silently treats
        ``request`` as a *query parameter* and every call fails with 422 —
        including correctly signed ones. Hand-wrapping the dependency in the
        caller's own annotated function hides the defect, so this test uses the
        dependency exactly as the docs tell people to.
        """
        import inspect

        from fastapi import Depends, FastAPI, Request
        from starlette.testclient import TestClient

        from agentmesh.integrations.http_middleware import install_fastapi_trust

        agent = _make_identity()
        mw = _middleware(_registry(agent))
        app = FastAPI()
        trust = install_fastapi_trust(app, mw)

        assert inspect.signature(trust).parameters["request"].annotation is Request

        @app.post("/direct")
        async def direct(result=Depends(trust)):
            return {"did": result.peer_did}

        client = TestClient(app)
        assert client.post("/direct").status_code == 401  # not 422

        headers = _signed_headers(
            agent, method="POST", request_target="/direct",
            body=b'{"a":1}', content_type="application/json",
        )
        resp = client.post("/direct", headers=headers, content=b'{"a":1}')
        assert resp.status_code == 200, resp.json()
        assert resp.json() == {"did": str(agent.did)}

    def test_dependency_without_the_body_guard_fails_closed(self):
        """The dependency cannot bound a declared body, so it must refuse to try.

        FastAPI reads a declared body in ``get_request_handler`` before it
        solves dependencies. Silently authenticating without the ASGI guard
        would leave an unauthenticated caller able to make the server buffer an
        unbounded body, so a missing guard is a 500, not a pass.
        """
        from fastapi import Depends, FastAPI, Request
        from starlette.testclient import TestClient

        from agentmesh.integrations.http_middleware import fastapi_trust_required

        agent = _make_identity()
        app = FastAPI()
        dependency = fastapi_trust_required(_middleware(_registry(agent)))

        async def trust_dep(request: Request):
            return await dependency(request)

        @app.post("/protected")
        async def protected(result=Depends(trust_dep)):
            return {"ok": True}

        headers = _signed_headers(
            agent, method="POST", request_target="/protected",
            body=b'{"a":1}', content_type="application/json",
        )
        resp = TestClient(app).post("/protected", headers=headers, content=b'{"a":1}')

        assert resp.status_code == 500
        assert "SignedBodyLimitMiddleware" in resp.json()["detail"]["reason"]

    def test_installer_bounds_declared_body_routes(self):
        """install_fastapi_trust must wire the guard, not just the dependency."""
        from fastapi import Depends, FastAPI, Request
        from pydantic import BaseModel
        from starlette.testclient import TestClient

        from agentmesh.integrations.http_middleware import install_fastapi_trust

        agent = _make_identity()
        mw = _middleware(
            _registry(agent),
            TrustConfig(audience=AUDIENCE, max_signed_body_bytes=64),
        )
        app = FastAPI()
        dependency = install_fastapi_trust(app, mw)

        class Payload(BaseModel):
            blob: str

        async def trust_dep(request: Request):
            return await dependency(request)

        @app.post("/declared")
        async def declared(payload: Payload, result=Depends(trust_dep)):
            return {"ok": True}

        resp = TestClient(app).post(
            "/declared",
            headers={"X-Agent-DID": str(agent.did)},
            content=b'{"blob":"' + b"x" * 100_000 + b'"}',
        )
        assert resp.status_code == 413

    def test_oversized_body_is_rejected_without_buffering(self):
        """M-1 regression: `await request.body()` buffers without bound."""
        from starlette.testclient import TestClient

        agent = _make_identity()
        mw = _middleware(
            _registry(agent),
            TrustConfig(audience=AUDIENCE, max_signed_body_bytes=64),
        )

        resp = TestClient(self._app(mw)).post(
            "/protected",
            headers={"X-Agent-DID": str(agent.did)},
            content=b"x" * 100_000,
        )
        assert resp.status_code == 413

    def test_asgi_middleware_bounds_routes_that_declare_a_body(self):
        """A dependency runs after FastAPI has already buffered a declared body.

        Only ASGI middleware, which runs ahead of routing, can bound those
        routes — so this asserts the layer that actually enforces the limit.
        """
        from fastapi import Depends, FastAPI, Request
        from pydantic import BaseModel
        from starlette.testclient import TestClient

        from agentmesh.integrations.http_middleware import (
            SignedBodyLimitMiddleware,
            fastapi_trust_required,
        )

        class Payload(BaseModel):
            blob: str

        agent = _make_identity()
        mw = _middleware(
            _registry(agent),
            TrustConfig(audience=AUDIENCE, max_signed_body_bytes=64),
        )
        app = FastAPI()
        app.add_middleware(SignedBodyLimitMiddleware, max_body_bytes=64)
        dependency = fastapi_trust_required(mw)

        async def trust_dep(request: Request):
            return await dependency(request)

        @app.post("/with-body")
        async def with_body(payload: Payload, result=Depends(trust_dep)):
            return {"len": len(payload.blob)}

        resp = TestClient(app).post(
            "/with-body",
            headers={"X-Agent-DID": str(agent.did)},
            json={"blob": "x" * 100_000},
        )
        assert resp.status_code == 413

    def test_asgi_middleware_passes_through_requests_within_the_limit(self):
        from fastapi import Depends, FastAPI, Request
        from starlette.testclient import TestClient

        from agentmesh.integrations.http_middleware import (
            SignedBodyLimitMiddleware,
            fastapi_trust_required,
        )

        agent = _make_identity()
        app = FastAPI()
        app.add_middleware(SignedBodyLimitMiddleware, max_body_bytes=4096)
        dependency = fastapi_trust_required(_middleware(_registry(agent)))

        async def trust_dep(request: Request):
            return await dependency(request)

        @app.post("/protected")
        async def protected(result=Depends(trust_dep)):
            return {"did": result.peer_did}

        body = b'{"a":1}'
        headers = _signed_headers(
            agent, method="POST", request_target="/protected",
            body=body, content_type="application/json",
            extra={"Content-Type": "application/json"},
        )

        resp = TestClient(app).post("/protected", headers=headers, content=body)
        assert resp.status_code == 200, resp.json()
        assert resp.json()["did"] == str(agent.did)

    def test_asgi_middleware_rejects_malformed_content_length(self):
        import asyncio

        from fastapi import FastAPI

        from agentmesh.integrations.http_middleware import SignedBodyLimitMiddleware

        app = FastAPI()
        sent: list[dict] = []

        async def send(message):
            sent.append(message)

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        guard = SignedBodyLimitMiddleware(app, max_body_bytes=64)
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/x",
            "headers": [(b"content-length", b"not-a-number")],
        }

        asyncio.run(guard(scope, receive, send))
        assert sent[0]["status"] == 413

    def test_asgi_middleware_ignores_non_http_scopes(self):
        import asyncio

        from agentmesh.integrations.http_middleware import SignedBodyLimitMiddleware

        seen: list[str] = []

        async def inner(scope, receive, send):
            seen.append(scope["type"])

        guard = SignedBodyLimitMiddleware(inner, max_body_bytes=64)
        asyncio.run(guard({"type": "lifespan"}, None, None))
        assert seen == ["lifespan"]

    def test_endpoint_can_still_read_the_body_after_verification(self):
        """The bounded read must not consume the body the route needs."""
        from fastapi import Depends, FastAPI, Request
        from starlette.testclient import TestClient

        from agentmesh.integrations.http_middleware import install_fastapi_trust

        agent = _make_identity()
        mw = _middleware(_registry(agent))
        app = FastAPI()
        dependency = install_fastapi_trust(app, mw)

        async def trust_dep(request: Request):
            return await dependency(request)

        @app.post("/echo")
        async def echo(request: Request, result=Depends(trust_dep)):
            return {"body": await request.json(), "did": result.peer_did}

        body = b'{"amount":100}'
        headers = _signed_headers(
            agent, method="POST", request_target="/echo",
            body=body, content_type="application/json",
            extra={"Content-Type": "application/json"},
        )

        resp = TestClient(app).post("/echo", headers=headers, content=body)
        assert resp.status_code == 200, resp.json()
        assert resp.json() == {"body": {"amount": 100}, "did": str(agent.did)}

    def test_non_ascii_public_key_header_returns_401_not_500(self):
        """Issue 1 regression: latin-1 header bytes used to raise TypeError.

        Driven through a raw ASGI scope rather than the test client, because
        httpx refuses to *send* a non-ASCII header while h11 will happily
        deliver one — so only the server-side boundary can be exercised here.
        """
        import asyncio

        from fastapi import HTTPException, Request

        from agentmesh.integrations.http_middleware import fastapi_trust_required

        agent = _make_identity()
        dependency = fastapi_trust_required(_middleware(_registry(agent)))
        scope = {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "path": "/protected",
            "raw_path": b"/protected",
            "query_string": b"",
            "root_path": "",
            "scheme": "http",
            "headers": [
                (b"x-agent-did", str(agent.did).encode("latin-1")),
                (b"x-agent-public-key", b"\xe9"),
            ],
            "client": ("127.0.0.1", 5000),
            "server": ("testserver", 80),
            BODY_LIMIT_SCOPE_KEY: 2_621_440,
        }

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def run():
            with pytest.raises(HTTPException) as exc:
                await dependency(Request(scope, receive))
            return exc.value

        error = asyncio.run(run())
        assert error.status_code == 401

    def test_non_utf8_query_string_returns_401_not_500(self):
        """N-8 regression: Starlette's URL.query decodes strict UTF-8 and would raise.

        Driven through a raw ASGI scope because httpx percent-encodes the query
        client-side; a real server delivers the raw bytes untouched.
        """
        import asyncio

        from fastapi import HTTPException, Request

        from agentmesh.integrations.http_middleware import fastapi_trust_required

        agent = _make_identity()
        dependency = fastapi_trust_required(_middleware(_registry(agent)))
        scope = {
            "type": "http",
            "http_version": "1.1",
            "method": "POST",
            "path": "/protected",
            "raw_path": b"/protected",
            "query_string": b"q=\xff\xfe",
            "root_path": "",
            "scheme": "http",
            "headers": [(b"x-agent-did", str(agent.did).encode("latin-1"))],
            "client": ("127.0.0.1", 5000),
            "server": ("testserver", 80),
            BODY_LIMIT_SCOPE_KEY: 2_621_440,
        }

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def run():
            with pytest.raises(HTTPException) as exc:
                await dependency(Request(scope, receive))
            return exc.value

        error = asyncio.run(run())
        assert error.status_code == 401

    def test_query_string_bytes_are_signed_identically_to_flask(self):
        """N-9 partial: both frameworks must decode the raw query the same way."""
        raw_query = b"q=caf\xe9&x=1"
        flask_target = f"/protected?{raw_query.decode('latin-1')}"

        from starlette.datastructures import Headers  # noqa: F401
        from starlette.requests import Request

        scope = {
            "type": "http", "http_version": "1.1", "method": "GET",
            "path": "/protected", "raw_path": b"/protected",
            "query_string": raw_query, "root_path": "", "scheme": "http",
            "headers": [], "client": ("127.0.0.1", 5000), "server": ("testserver", 80),
        }
        request = Request(scope, lambda: None)
        starlette_query = request.scope.get("query_string", b"").decode("latin-1")
        starlette_target = f"{request.scope['path']}?{starlette_query}"

        assert starlette_target == flask_target

    def test_client_disconnect_mid_body_is_503_not_a_500(self):
        """N-8 regression: the body read is outside verify_request's never-raise boundary."""
        import asyncio

        from fastapi import HTTPException, Request

        from agentmesh.integrations.http_middleware import fastapi_trust_required

        agent = _make_identity()
        dependency = fastapi_trust_required(_middleware(_registry(agent)))
        scope = {
            "type": "http", "http_version": "1.1", "method": "POST",
            "path": "/protected", "raw_path": b"/protected", "query_string": b"",
            "root_path": "", "scheme": "http",
            "headers": [(b"x-agent-did", str(agent.did).encode("latin-1"))],
            "client": ("127.0.0.1", 5000), "server": ("testserver", 80),
            BODY_LIMIT_SCOPE_KEY: 2_621_440,
        }

        async def receive():
            return {"type": "http.disconnect"}

        async def run():
            with pytest.raises(HTTPException) as exc:
                await dependency(Request(scope, receive))
            return exc.value

        error = asyncio.run(run())
        assert error.status_code == 503

    def test_error_detail_mutation_does_not_leak_across_requests(self):
        """N-10 regression: module-level error bodies were handed out by reference."""
        import asyncio

        from fastapi import HTTPException, Request

        from agentmesh.integrations.http_middleware import fastapi_trust_required

        agent = _make_identity()
        mw = _middleware(
            _registry(agent),
            TrustConfig(audience=AUDIENCE, permissive_mode=True, required_trust_score=0.0),
        )
        dependency = fastapi_trust_required(mw)

        def _scope():
            return {
                "type": "http", "http_version": "1.1", "method": "POST",
                "path": "/protected", "raw_path": b"/protected", "query_string": b"",
                "root_path": "", "scheme": "http", "headers": [],
                "client": ("127.0.0.1", 5000), "server": ("testserver", 80),
                BODY_LIMIT_SCOPE_KEY: 2_621_440,
            }

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def run():
            with pytest.raises(HTTPException) as exc:
                await dependency(Request(_scope(), receive))
            return exc.value

        first = asyncio.run(run())
        # A custom exception handler annotating the detail must not corrupt
        # process-global state for every subsequent request.
        first.detail["trace_id"] = "leaked"

        second = asyncio.run(run())
        assert "trace_id" not in second.detail
        assert "trace_id" not in _http._NOT_AUTHENTICATED

    def test_content_type_is_signed(self):
        """Content-Type confusion must not survive signature verification."""
        from starlette.testclient import TestClient

        agent = _make_identity()
        client = TestClient(self._app(_middleware(_registry(agent))))
        headers = _signed_headers(
            agent, method="POST", request_target="/protected",
            body=b'{"a":1}', content_type="application/json",
            extra={"Content-Type": "text/plain"},
        )

        resp = client.post("/protected", headers=headers, content=b'{"a":1}')
        assert resp.status_code == 401
