# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests that the GitHub `_api` helpers retry on transient failures.

Both `credential_audit._api` and `contributor_check._api` previously
retried HTTP 403 with Retry-After but let every other failure
propagate immediately — including URLError (DNS hiccups, TLS resets,
connection refused) and 5xx responses, which are the most common
transient errors in a long-running scan. These tests pin the new
retry envelope:

  * URLError -> exponential-backoff retry (up to 3 attempts total)
  * 5xx HTTPError -> exponential-backoff retry
  * 403 with Retry-After -> honoured (existing behaviour)
  * 404 -> returns None (existing behaviour)
  * Non-retryable HTTPError on the final attempt -> re-raised
"""

from __future__ import annotations

import io
import json
from typing import Any
from urllib.error import HTTPError, URLError

import pytest

from agent_compliance.cli import contributor_check, credential_audit


@pytest.fixture(autouse=True)
def _silence_token(monkeypatch):
    """Bypass token resolution so _api doesn't fail trying to read
    GITHUB_TOKEN or shell out to `gh`."""
    monkeypatch.setattr(contributor_check, "_get_token", lambda: "test-token")
    monkeypatch.setattr(credential_audit, "_get_token", lambda: "test-token")
    # Reset module-level cache too.
    monkeypatch.setattr(contributor_check, "_TOKEN", None)
    monkeypatch.setattr(credential_audit, "_TOKEN", None)


@pytest.fixture(autouse=True)
def _no_sleep(monkeypatch):
    """Retries shouldn't actually wait during tests."""
    monkeypatch.setattr(contributor_check.time, "sleep", lambda _s: None)
    monkeypatch.setattr(credential_audit.time, "sleep", lambda _s: None)


class _FakeResponse:
    def __init__(self, payload: dict[str, Any]) -> None:
        self._body = json.dumps(payload).encode("utf-8")

    def __enter__(self) -> "_FakeResponse":
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


def _make_urlopen(side_effects: list):
    """Return a fake urlopen that walks through `side_effects` on each call.

    Each side effect is either an Exception (raised) or a dict (wrapped
    into a _FakeResponse).
    """
    calls = {"count": 0}

    def _fake(*_args, **_kwargs):
        idx = calls["count"]
        calls["count"] += 1
        if idx >= len(side_effects):
            raise AssertionError(f"unexpected urlopen call #{idx + 1}")
        effect = side_effects[idx]
        if isinstance(effect, Exception):
            raise effect
        return _FakeResponse(effect)

    return _fake, calls


@pytest.mark.parametrize(
    "module", [contributor_check, credential_audit],
    ids=["contributor_check", "credential_audit"],
)
class TestApiRetry:
    """Both CLI modules share the same retry shape — assert against both."""

    def test_url_error_retried_then_succeeds(self, monkeypatch, module):
        fake, calls = _make_urlopen([
            URLError("temporary DNS failure"),
            {"ok": True, "items": []},
        ])
        monkeypatch.setattr(module, "urlopen", fake)
        result = module._api("/users/x")
        assert result == {"ok": True, "items": []}
        assert calls["count"] == 2

    def test_url_error_persists_then_raises(self, monkeypatch, module):
        fake, calls = _make_urlopen([
            URLError("connection refused"),
            URLError("connection refused"),
            URLError("connection refused"),
        ])
        monkeypatch.setattr(module, "urlopen", fake)
        with pytest.raises(URLError):
            module._api("/users/x")
        # _RETRY_MAX_ATTEMPTS == 3
        assert calls["count"] == 3

    def test_server_error_retried_then_succeeds(self, monkeypatch, module):
        fake, calls = _make_urlopen([
            HTTPError(
                "https://api.github.com/x", 503, "Service Unavailable",
                {}, io.BytesIO(b""),
            ),
            {"ok": True},
        ])
        monkeypatch.setattr(module, "urlopen", fake)
        result = module._api("/users/x")
        assert result == {"ok": True}
        assert calls["count"] == 2

    def test_403_with_retry_after_honoured(self, monkeypatch, module):
        import email.message
        headers = email.message.Message()
        headers["Retry-After"] = "5"
        fake, calls = _make_urlopen([
            HTTPError(
                "https://api.github.com/x", 403, "Rate Limited",
                headers, io.BytesIO(b""),
            ),
            {"ok": True},
        ])
        monkeypatch.setattr(module, "urlopen", fake)
        result = module._api("/users/x")
        assert result == {"ok": True}
        assert calls["count"] == 2

    def test_404_returns_none_without_retry(self, monkeypatch, module):
        fake, calls = _make_urlopen([
            HTTPError(
                "https://api.github.com/x", 404, "Not Found",
                {}, io.BytesIO(b""),
            ),
        ])
        monkeypatch.setattr(module, "urlopen", fake)
        result = module._api("/users/x")
        assert result is None
        assert calls["count"] == 1

    def test_401_unauthorized_raised_immediately(self, monkeypatch, module):
        # Non-retryable status: a bad token won't fix itself.
        fake, calls = _make_urlopen([
            HTTPError(
                "https://api.github.com/x", 401, "Unauthorized",
                {}, io.BytesIO(b""),
            ),
        ])
        monkeypatch.setattr(module, "urlopen", fake)
        with pytest.raises(HTTPError) as exc:
            module._api("/users/x")
        assert exc.value.code == 401
        assert calls["count"] == 1


class TestCredentialAudit422:
    """credential_audit._api treats 422 as a missing-resource sentinel
    (consistent with /search endpoints returning 422 on stale results).
    contributor_check._api does NOT (it only suppresses 404)."""

    def test_422_returns_none(self, monkeypatch):
        fake, calls = _make_urlopen([
            HTTPError(
                "https://api.github.com/x", 422, "Unprocessable",
                {}, io.BytesIO(b""),
            ),
        ])
        monkeypatch.setattr(credential_audit, "urlopen", fake)
        result = credential_audit._api("/x")
        assert result is None
        assert calls["count"] == 1
