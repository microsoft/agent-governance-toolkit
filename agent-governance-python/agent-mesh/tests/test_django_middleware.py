# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Copyright (c) Agent-Mesh Contributors. All rights reserved.
# Licensed under the MIT License.
"""Tests for Django trust verification middleware and decorators."""

from __future__ import annotations

import base64
import importlib
import json
import secrets
import sys
from datetime import UTC, datetime, timedelta, timezone

import pytest

# Skip the entire module when Django is not installed.
django = pytest.importorskip("django")

# Minimal Django settings — must be configured before any Django import.
from django.conf import settings

if not settings.configured:
    settings.configure(
        DEBUG=True,
        DATABASES={},
        ROOT_URLCONF="tests.test_django_middleware",  # self-referencing
        MIDDLEWARE=[],
        SECRET_KEY="test-secret-key",
        CACHES={
            "default": {
                "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
                "LOCATION": "agentmesh-django-tests",
            }
        },
        AGENTMESH_AUDIENCE="test-service",
        AGENTMESH_REPLAY_CACHE_ALIAS="default",
        AGENTMESH_ALLOW_LOCAL_REPLAY_CACHE=True,
    )

import django as _django  # noqa: E402

_django.setup()

from django.core.cache import caches  # noqa: E402
from django.core.cache.backends.dummy import DummyCache  # noqa: E402
from django.core.cache.backends.filebased import FileBasedCache  # noqa: E402
from django.core.exceptions import ImproperlyConfigured  # noqa: E402
from django.http import HttpResponse, JsonResponse  # noqa: E402
from django.test import RequestFactory  # noqa: E402
from django.urls import path  # noqa: E402

from agentmesh.integrations.django_middleware import (  # noqa: E402
    AgentTrustMiddleware,
    build_request_signature_payload,
    trust_exempt,
    trust_required,
)
from agentmesh.integrations.django_middleware import middleware as middleware_module  # noqa: E402

# ── Dummy views & URL configuration ─────────────────────────────────


def _ok_view(request):
    """Simple view that returns 200."""
    return JsonResponse({"status": "ok", "agent_did": getattr(request, "agent_did", None)})


@trust_required(min_score=800)
def _high_trust_view(request):
    return JsonResponse({"status": "ok"})


@trust_exempt
def _exempt_view(request):
    return JsonResponse({"status": "ok"})


# URL patterns used by the middleware's resolve step.
urlpatterns = [
    path("api/data/", _ok_view, name="data"),
    path("api/high/", _high_trust_view, name="high_trust"),
    path("api/exempt/", _exempt_view, name="exempt"),
    path("health/", _ok_view, name="health"),
]


# ── Helpers ──────────────────────────────────────────────────────────

def _make_middleware(get_response=None):
    """Create an AgentTrustMiddleware wrapping a dummy get_response."""
    if get_response is None:
        get_response = _ok_view
    return AgentTrustMiddleware(get_response)


def _get(path: str, *, did: str = "", sig: str = "", factory=None):
    """Build a GET request with optional trust headers."""
    factory = factory or RequestFactory()
    headers = {}
    if did:
        headers["HTTP_X_AGENT_DID"] = did
    if sig:
        headers["HTTP_X_AGENT_SIGNATURE"] = sig
    return factory.get(path, **headers)


def _signed_request(
    private_key,
    agent_did: str,
    path: str = "/api/data/",
    *,
    method: str = "GET",
    body: bytes = b"",
    content_type: str = "application/octet-stream",
    timestamp: str | None = None,
    nonce: str | None = None,
    audience: str = "test-service",
    factory=None,
):
    """Build a request carrying a valid, request-bound AgentMesh signature."""
    factory = factory or RequestFactory()
    timestamp = timestamp or datetime.now(UTC).isoformat()
    nonce = nonce or secrets.token_urlsafe(16)
    request = factory.generic(method, path, data=body, content_type=content_type)
    query_string = request.META.get("QUERY_STRING", "")
    request_target = request.path + (f"?{query_string}" if query_string else "")
    payload = build_request_signature_payload(
        agent_did=agent_did,
        audience=audience,
        timestamp=timestamp,
        nonce=nonce,
        method=method,
        request_target=request_target,
        body=body,
        content_type=request.META.get("CONTENT_TYPE", ""),
    )
    signature = base64.b64encode(private_key.sign(payload)).decode()
    request.META.update(
        HTTP_X_AGENT_DID=agent_did,
        HTTP_X_AGENT_SIGNATURE=signature,
        HTTP_X_AGENT_TIMESTAMP=timestamp,
        HTTP_X_AGENT_NONCE=nonce,
    )
    return request


@pytest.fixture(autouse=True)
def _clear_replay_cache():
    caches["default"].clear()
    yield
    caches["default"].clear()


# ── Test class ───────────────────────────────────────────────────────


class TestAgentTrustMiddleware:
    """Tests for AgentTrustMiddleware."""

    def test_missing_did_returns_403(self):
        mw = _make_middleware()
        request = _get("/api/data/")
        response = mw(request)
        assert response.status_code == 403
        body = json.loads(response.content)
        assert "Missing agent DID" in body["error"]

    def test_valid_did_with_signature_passes(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        agent_did = "did:mesh:abc123"

        settings.AGENTMESH_AGENT_KEYS = {agent_did: public_key}
        try:
            mw = _make_middleware()
            request = _signed_request(private_key, agent_did)
            response = mw(request)
            assert response.status_code == 200
            assert request.agent_did == agent_did  # type: ignore[attr-defined]
            assert request.agent_trust_score == 750  # type: ignore[attr-defined]
        finally:
            del settings.AGENTMESH_AGENT_KEYS

    def test_did_without_signature_rejected(self):
        """DID-only requests (no signature) get score 0, below 500 default."""
        mw = _make_middleware()
        request = _get("/api/data/", did="did:mesh:low")
        response = mw(request)
        assert response.status_code == 403
        body = json.loads(response.content)
        assert body["error"] == "Trust verification failed"
        # V24: response must NOT leak trust_score or required_score
        assert "trust_score" not in body
        assert "required_score" not in body

    def test_invalid_signature_rejected(self):
        """A fabricated signature string is rejected."""
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        agent_did = "did:mesh:badactor"

        settings.AGENTMESH_AGENT_KEYS = {agent_did: public_key}
        try:
            mw = _make_middleware()
            request = _signed_request(private_key, agent_did)
            request.META["HTTP_X_AGENT_SIGNATURE"] = "totally-not-a-valid-sig"
            response = mw(request)
            assert response.status_code == 403
            body = json.loads(response.content)
            assert body["error"] == "Trust verification failed"
            assert "trust_score" not in body
        finally:
            del settings.AGENTMESH_AGENT_KEYS

    def test_unregistered_agent_rejected(self):
        """Agent DID not in AGENTMESH_AGENT_KEYS gets score 0."""
        settings.AGENTMESH_AGENT_KEYS = {}
        try:
            mw = _make_middleware()
            request = _get("/api/data/", did="did:mesh:unknown", sig="some_sig")
            response = mw(request)
            assert response.status_code == 403
        finally:
            del settings.AGENTMESH_AGENT_KEYS

    def test_exempt_path_bypasses_verification(self):
        """Paths listed in AGENTMESH_EXEMPT_PATHS skip trust checks."""
        settings.AGENTMESH_EXEMPT_PATHS = ["/health/"]
        try:
            mw = _make_middleware()
            request = _get("/health/")  # no DID header at all
            response = mw(request)
            assert response.status_code == 200
        finally:
            del settings.AGENTMESH_EXEMPT_PATHS

    def test_settings_override_defaults(self):
        """Custom settings override the built-in defaults."""
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        agent_did = "did:mesh:low_ok"

        settings.AGENTMESH_MIN_TRUST_SCORE = 300
        settings.AGENTMESH_AGENT_KEYS = {agent_did: public_key}
        try:
            mw = _make_middleware()
            request = _signed_request(private_key, agent_did)
            response = mw(request)
            # score 750 >= new threshold 300 → should pass
            assert response.status_code == 200
        finally:
            del settings.AGENTMESH_MIN_TRUST_SCORE
            del settings.AGENTMESH_AGENT_KEYS

    def test_custom_did_header(self):
        """AGENTMESH_DID_HEADER changes which header is read."""
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        agent_did = "did:mesh:custom"

        settings.AGENTMESH_DID_HEADER = "X-Custom-DID"
        settings.AGENTMESH_AGENT_KEYS = {agent_did: public_key}
        try:
            mw = _make_middleware()
            request = _signed_request(private_key, agent_did)
            request.META["HTTP_X_CUSTOM_DID"] = request.META.pop("HTTP_X_AGENT_DID")
            response = mw(request)
            assert response.status_code == 200
            assert request.agent_did == agent_did  # type: ignore[attr-defined]
        finally:
            del settings.AGENTMESH_DID_HEADER
            del settings.AGENTMESH_AGENT_KEYS

    def test_replayed_request_is_rejected(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        agent_did = "did:mesh:replay"
        settings.AGENTMESH_AGENT_KEYS = {agent_did: private_key.public_key()}
        try:
            mw = _make_middleware()
            original = _signed_request(private_key, agent_did)
            replay = RequestFactory().get(
                "/api/data/",
                **{
                    key: value
                    for key, value in original.META.items()
                    if key.startswith("HTTP_X_AGENT_")
                },
            )

            assert mw(original).status_code == 200
            assert mw(replay).status_code == 403
        finally:
            del settings.AGENTMESH_AGENT_KEYS

    def test_concurrent_replayed_requests_accept_only_one(self, monkeypatch):
        from concurrent.futures import ThreadPoolExecutor
        from threading import Barrier

        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        agent_did = "did:mesh:concurrent-replay"
        settings.AGENTMESH_AGENT_KEYS = {agent_did: private_key.public_key()}
        try:
            mw = _make_middleware()
            original = _signed_request(private_key, agent_did)
            headers = {
                key: value
                for key, value in original.META.items()
                if key.startswith("HTTP_X_AGENT_")
            }
            requests = [RequestFactory().get("/api/data/", **headers) for _ in range(2)]
            barrier = Barrier(2)
            original_add = mw._replay_cache.add

            def _simultaneous_add(*args, **kwargs):
                barrier.wait(timeout=5)
                return original_add(*args, **kwargs)

            monkeypatch.setattr(mw._replay_cache, "add", _simultaneous_add)

            with ThreadPoolExecutor(max_workers=2) as executor:
                statuses = list(executor.map(lambda request: mw(request).status_code, requests))

            assert sorted(statuses) == [200, 403]
        finally:
            del settings.AGENTMESH_AGENT_KEYS

    def test_future_timestamp_nonce_is_cached_until_signature_expires(self, monkeypatch):
        from cryptography.hazmat.primitives.asymmetric import ed25519

        now = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)
        private_key = ed25519.Ed25519PrivateKey.generate()
        agent_did = "did:mesh:future-replay"
        timestamp = (now + timedelta(seconds=299)).isoformat()
        settings.AGENTMESH_AGENT_KEYS = {agent_did: private_key.public_key()}
        try:
            mw = _make_middleware()
            original_add = mw._replay_cache.add
            observed_timeout = None

            def _recording_add(key, value, timeout=None, version=None):
                nonlocal observed_timeout
                observed_timeout = timeout
                return original_add(key, value, timeout=timeout, version=version)

            monkeypatch.setattr(middleware_module, "_utcnow", lambda: now)
            monkeypatch.setattr(mw._replay_cache, "add", _recording_add)

            request = _signed_request(private_key, agent_did, timestamp=timestamp)
            assert mw(request).status_code == 200
            assert observed_timeout == 599
        finally:
            del settings.AGENTMESH_AGENT_KEYS

    def test_timestamp_expiring_while_body_is_read_is_rejected(self, monkeypatch):
        from cryptography.hazmat.primitives.asymmetric import ed25519

        signed_at = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)
        current_time = signed_at
        private_key = ed25519.Ed25519PrivateKey.generate()
        agent_did = "did:mesh:slow-replay"
        settings.AGENTMESH_AGENT_KEYS = {agent_did: private_key.public_key()}
        try:
            request = _signed_request(
                private_key,
                agent_did,
                method="POST",
                body=b"delayed body",
                timestamp=signed_at.isoformat(),
            )
            request_read = request.read

            def _delayed_read(*args, **kwargs):
                nonlocal current_time
                current_time = signed_at + timedelta(seconds=301)
                return request_read(*args, **kwargs)

            monkeypatch.setattr(request, "read", _delayed_read)
            monkeypatch.setattr(middleware_module, "_utcnow", lambda: current_time)

            assert _make_middleware()(request).status_code == 403
        finally:
            del settings.AGENTMESH_AGENT_KEYS

    def test_timestamp_expiring_while_nonce_is_claimed_is_rejected(self, monkeypatch):
        from cryptography.hazmat.primitives.asymmetric import ed25519

        signed_at = datetime(2026, 8, 18, 12, 0, tzinfo=UTC)
        current_time = signed_at
        private_key = ed25519.Ed25519PrivateKey.generate()
        agent_did = "did:mesh:slow-cache"
        settings.AGENTMESH_AGENT_KEYS = {agent_did: private_key.public_key()}
        try:
            mw = _make_middleware()
            original_add = mw._replay_cache.add

            def _delayed_add(*args, **kwargs):
                nonlocal current_time
                result = original_add(*args, **kwargs)
                current_time = signed_at + timedelta(seconds=301)
                return result

            monkeypatch.setattr(middleware_module, "_utcnow", lambda: current_time)
            monkeypatch.setattr(mw._replay_cache, "add", _delayed_add)
            request = _signed_request(
                private_key,
                agent_did,
                timestamp=signed_at.isoformat(),
            )

            assert mw(request).status_code == 403
        finally:
            del settings.AGENTMESH_AGENT_KEYS

    @pytest.mark.parametrize("include_content_length", [True, False])
    def test_oversized_signed_body_is_rejected(self, include_content_length):
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        agent_did = "did:mesh:oversized-body"
        settings.AGENTMESH_AGENT_KEYS = {agent_did: private_key.public_key()}
        settings.AGENTMESH_MAX_SIGNED_BODY_BYTES = 4
        try:
            request = _signed_request(
                private_key,
                agent_did,
                method="POST",
                body=b"12345",
            )
            if not include_content_length:
                request.META.pop("CONTENT_LENGTH", None)

            assert _make_middleware()(request).status_code == 403
        finally:
            del settings.AGENTMESH_AGENT_KEYS
            del settings.AGENTMESH_MAX_SIGNED_BODY_BYTES

    def test_signed_body_remains_available_to_view(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        agent_did = "did:mesh:body-preserved"
        body = b"signed body"
        settings.AGENTMESH_AGENT_KEYS = {agent_did: private_key.public_key()}

        def _body_view(request):
            return HttpResponse(request.body)

        try:
            request = _signed_request(
                private_key,
                agent_did,
                method="POST",
                body=body,
            )

            response = _make_middleware(get_response=_body_view)(request)

            assert response.status_code == 200
            assert response.content == body
        finally:
            del settings.AGENTMESH_AGENT_KEYS

    @pytest.mark.parametrize("offset", [timedelta(minutes=-6), timedelta(minutes=6)])
    def test_timestamp_outside_replay_window_is_rejected(self, offset):
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        agent_did = "did:mesh:stale"
        timestamp = (datetime.now(UTC) + offset).isoformat()
        settings.AGENTMESH_AGENT_KEYS = {agent_did: private_key.public_key()}
        try:
            request = _signed_request(private_key, agent_did, timestamp=timestamp)
            assert _make_middleware()(request).status_code == 403
        finally:
            del settings.AGENTMESH_AGENT_KEYS

    def test_legacy_bare_did_signature_is_rejected(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        agent_did = "did:mesh:legacy"
        request = _signed_request(private_key, agent_did)
        request.META["HTTP_X_AGENT_SIGNATURE"] = base64.b64encode(
            private_key.sign(agent_did.encode("utf-8"))
        ).decode()
        settings.AGENTMESH_AGENT_KEYS = {agent_did: private_key.public_key()}
        try:
            assert _make_middleware()(request).status_code == 403
        finally:
            del settings.AGENTMESH_AGENT_KEYS

    @pytest.mark.parametrize(
        ("changed_method", "changed_path", "changed_body"),
        [
            ("POST", "/api/data/", b""),
            ("GET", "/api/high/", b""),
            ("POST", "/api/data/", b"changed"),
        ],
    )
    def test_signature_is_bound_to_request(self, changed_method, changed_path, changed_body):
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        agent_did = "did:mesh:bound"
        signed = _signed_request(private_key, agent_did)
        tampered = RequestFactory().generic(
            changed_method,
            changed_path,
            data=changed_body,
            content_type="application/octet-stream",
            **{
                key: value
                for key, value in signed.META.items()
                if key.startswith("HTTP_X_AGENT_")
            },
        )
        settings.AGENTMESH_AGENT_KEYS = {agent_did: private_key.public_key()}
        try:
            assert _make_middleware()(tampered).status_code == 403
        finally:
            del settings.AGENTMESH_AGENT_KEYS

    @pytest.mark.parametrize(
        "nonce", ["not base64!", base64.b64encode(b"short").decode(), "a" * 129]
    )
    def test_malformed_or_undersized_nonce_is_rejected(self, nonce):
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        agent_did = "did:mesh:bad-nonce"
        settings.AGENTMESH_AGENT_KEYS = {agent_did: private_key.public_key()}
        try:
            request = _signed_request(private_key, agent_did, nonce=nonce)
            assert _make_middleware()(request).status_code == 403
        finally:
            del settings.AGENTMESH_AGENT_KEYS

    def test_signature_is_bound_to_query_string(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        agent_did = "did:mesh:query-bound"
        signed = _signed_request(private_key, agent_did, path="/api/data/?scope=read")
        tampered = RequestFactory().get(
            "/api/data/?scope=write",
            **{
                key: value
                for key, value in signed.META.items()
                if key.startswith("HTTP_X_AGENT_")
            },
        )
        settings.AGENTMESH_AGENT_KEYS = {agent_did: private_key.public_key()}
        try:
            assert _make_middleware()(tampered).status_code == 403
        finally:
            del settings.AGENTMESH_AGENT_KEYS

    def test_signature_is_bound_to_audience(self):
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        agent_did = "did:mesh:audience-bound"
        request = _signed_request(private_key, agent_did, audience="another-service")
        settings.AGENTMESH_AGENT_KEYS = {agent_did: private_key.public_key()}
        try:
            assert _make_middleware()(request).status_code == 403
        finally:
            del settings.AGENTMESH_AGENT_KEYS

    def test_replay_cache_failure_is_fail_closed(self, monkeypatch):
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        agent_did = "did:mesh:cache-failure"
        settings.AGENTMESH_AGENT_KEYS = {agent_did: private_key.public_key()}
        try:
            mw = _make_middleware()

            def _cache_failure(*args, **kwargs):
                raise RuntimeError("cache unavailable")

            monkeypatch.setattr(mw._replay_cache, "add", _cache_failure)
            request = _signed_request(private_key, agent_did)
            assert mw(request).status_code == 403
        finally:
            del settings.AGENTMESH_AGENT_KEYS

    def test_local_replay_cache_requires_explicit_development_opt_in(self):
        settings.AGENTMESH_ALLOW_LOCAL_REPLAY_CACHE = False
        try:
            with pytest.raises(ImproperlyConfigured, match="cannot prevent replay"):
                _make_middleware()
        finally:
            settings.AGENTMESH_ALLOW_LOCAL_REPLAY_CACHE = True

    @pytest.mark.parametrize("opt_in", ["True", "False", 1])
    def test_local_replay_cache_requires_literal_boolean_opt_in(self, opt_in):
        settings.AGENTMESH_ALLOW_LOCAL_REPLAY_CACHE = opt_in
        try:
            with pytest.raises(ImproperlyConfigured, match="cannot prevent replay"):
                _make_middleware()
        finally:
            settings.AGENTMESH_ALLOW_LOCAL_REPLAY_CACHE = True

    @pytest.mark.parametrize("backend_type", [DummyCache, FileBasedCache])
    def test_unsupported_replay_cache_backend_fails_at_startup(
        self, backend_type, monkeypatch, tmp_path
    ):
        cache_alias = "unsupported-replay-cache"
        location = str(tmp_path) if backend_type is FileBasedCache else "unused"
        backend = backend_type(location, {})
        monkeypatch.setattr(middleware_module, "caches", {cache_alias: backend})
        settings.AGENTMESH_REPLAY_CACHE_ALIAS = cache_alias
        try:
            with pytest.raises(ImproperlyConfigured, match="RedisCache or a shared memcached"):
                _make_middleware()
        finally:
            settings.AGENTMESH_REPLAY_CACHE_ALIAS = "default"

    def test_missing_audience_fails_at_startup(self):
        audience = settings.AGENTMESH_AUDIENCE
        settings.AGENTMESH_AUDIENCE = ""
        try:
            with pytest.raises(ImproperlyConfigured, match="AGENTMESH_AUDIENCE"):
                _make_middleware()
        finally:
            settings.AGENTMESH_AUDIENCE = audience

    def test_invalid_replay_window_fails_at_startup(self):
        settings.AGENTMESH_REPLAY_WINDOW_SECONDS = 0
        try:
            with pytest.raises(ImproperlyConfigured, match="REPLAY_WINDOW_SECONDS"):
                _make_middleware()
        finally:
            del settings.AGENTMESH_REPLAY_WINDOW_SECONDS

    def test_invalid_max_signed_body_size_fails_at_startup(self):
        settings.AGENTMESH_MAX_SIGNED_BODY_BYTES = 0
        try:
            with pytest.raises(ImproperlyConfigured, match="MAX_SIGNED_BODY_BYTES"):
                _make_middleware()
        finally:
            del settings.AGENTMESH_MAX_SIGNED_BODY_BYTES


class TestTrustRequiredDecorator:
    """Tests for @trust_required decorator."""

    def test_per_view_threshold_enforced(self):
        """@trust_required(min_score=800) rejects score 750 even with valid sig."""
        from cryptography.hazmat.primitives.asymmetric import ed25519

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        agent_did = "did:mesh:abc"

        settings.AGENTMESH_AGENT_KEYS = {agent_did: public_key}
        try:
            mw = _make_middleware(get_response=_high_trust_view)
            request = _signed_request(private_key, agent_did, path="/api/high/")
            response = mw(request)
            # score 750 < per-view 800 → 403
            assert response.status_code == 403
            body = json.loads(response.content)
            assert body["error"] == "Trust verification failed"
            assert "required_score" not in body
        finally:
            del settings.AGENTMESH_AGENT_KEYS

    def test_decorator_preserves_function_name(self):
        assert _high_trust_view.__name__ == "_high_trust_view"


class TestTrustExemptDecorator:
    """Tests for @trust_exempt decorator."""

    def test_exempt_skips_verification(self):
        mw = _make_middleware(get_response=_exempt_view)
        request = _get("/api/exempt/", did="did:mesh:any")
        response = mw(request)
        assert response.status_code == 200

    def test_exempt_preserves_function_name(self):
        assert _exempt_view.__name__ == "_exempt_view"

    def test_exempt_sets_agent_did(self):
        """Even exempt views get agent_did set on request."""
        mw = _make_middleware(get_response=_exempt_view)
        request = _get("/api/exempt/", did="did:mesh:exempt_agent")
        mw(request)
        assert request.agent_did == "did:mesh:exempt_agent"  # type: ignore[attr-defined]


class TestImportWithoutDjango:
    """Verify the package is importable when Django is absent."""

    def test_import_does_not_crash_without_django(self, monkeypatch):
        """Simulate Django not installed by temporarily removing it from sys.modules."""
        # Save originals
        saved = {}
        for mod_name in list(sys.modules):
            if mod_name == "django" or mod_name.startswith("django."):
                saved[mod_name] = sys.modules.pop(mod_name)

        # Also make sure import machinery can't find django
        import builtins

        _real_import = builtins.__import__

        def _no_django(name, *args, **kwargs):
            if name == "django" or name.startswith("django."):
                raise ImportError(f"No module named '{name}'")
            return _real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", _no_django)

        # Remove cached django_middleware modules so they re-import
        for mod_name in list(sys.modules):
            if "django_middleware" in mod_name:
                del sys.modules[mod_name]

        try:
            mod = importlib.import_module(
                "agentmesh.integrations.django_middleware"
            )
            # Should import without error; __all__ is empty
            assert mod.__all__ == [] or isinstance(mod.__all__, list)
        finally:
            # Restore django modules
            sys.modules.update(saved)
            monkeypatch.undo()
            # Re-import to restore state
            for mod_name in list(sys.modules):
                if "django_middleware" in mod_name:
                    del sys.modules[mod_name]
