# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Copyright (c) Agent-Mesh Contributors. All rights reserved.
# Licensed under the MIT License.
"""Tests for Django trust verification middleware and decorators."""

from __future__ import annotations

import importlib
import json
import sys

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
    )

import django as _django  # noqa: E402

_django.setup()

from django.http import HttpResponse, JsonResponse  # noqa: E402
from django.test import RequestFactory  # noqa: E402
from django.urls import path  # noqa: E402

from agentmesh.integrations.django_middleware import (  # noqa: E402
    AgentTrustMiddleware,
    trust_exempt,
    trust_required,
)

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
        import base64

        # Create agent keypair and sign the DID
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        agent_did = "did:mesh:abc123"
        sig = base64.b64encode(private_key.sign(agent_did.encode("utf-8"))).decode()

        settings.AGENTMESH_AGENT_KEYS = {agent_did: public_key}
        try:
            mw = _make_middleware()
            request = _get("/api/data/", did=agent_did, sig=sig)
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
            request = _get("/api/data/", did=agent_did, sig="totally-not-a-valid-sig")
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
        import base64

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        agent_did = "did:mesh:low_ok"
        sig = base64.b64encode(private_key.sign(agent_did.encode("utf-8"))).decode()

        settings.AGENTMESH_MIN_TRUST_SCORE = 300
        settings.AGENTMESH_AGENT_KEYS = {agent_did: public_key}
        try:
            mw = _make_middleware()
            request = _get("/api/data/", did=agent_did, sig=sig)
            response = mw(request)
            # score 750 >= new threshold 300 → should pass
            assert response.status_code == 200
        finally:
            del settings.AGENTMESH_MIN_TRUST_SCORE
            del settings.AGENTMESH_AGENT_KEYS

    def test_custom_did_header(self):
        """AGENTMESH_DID_HEADER changes which header is read."""
        from cryptography.hazmat.primitives.asymmetric import ed25519
        import base64

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        agent_did = "did:mesh:custom"
        sig = base64.b64encode(private_key.sign(agent_did.encode("utf-8"))).decode()

        settings.AGENTMESH_DID_HEADER = "X-Custom-DID"
        settings.AGENTMESH_AGENT_KEYS = {agent_did: public_key}
        try:
            mw = _make_middleware()
            factory = RequestFactory()
            request = factory.get(
                "/api/data/",
                HTTP_X_CUSTOM_DID=agent_did,
                HTTP_X_AGENT_SIGNATURE=sig,
            )
            response = mw(request)
            assert response.status_code == 200
            assert request.agent_did == agent_did  # type: ignore[attr-defined]
        finally:
            del settings.AGENTMESH_DID_HEADER
            del settings.AGENTMESH_AGENT_KEYS


class TestTrustRequiredDecorator:
    """Tests for @trust_required decorator."""

    def test_per_view_threshold_enforced(self):
        """@trust_required(min_score=800) rejects score 750 even with valid sig."""
        from cryptography.hazmat.primitives.asymmetric import ed25519
        import base64

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        agent_did = "did:mesh:abc"
        sig = base64.b64encode(private_key.sign(agent_did.encode("utf-8"))).decode()

        settings.AGENTMESH_AGENT_KEYS = {agent_did: public_key}
        try:
            mw = _make_middleware(get_response=_high_trust_view)
            request = _get("/api/high/", did=agent_did, sig=sig)
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
