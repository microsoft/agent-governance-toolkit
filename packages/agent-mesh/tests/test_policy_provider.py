# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the API gateway policy provider endpoint.

Covers:
* ``PolicyProviderHandler.handle_check`` — policy evaluation via REST
* ``PolicyProviderHandler.handle_health`` — health-check response
* ``PolicyProviderHandler.handle_policies`` — policy listing
* ``to_asgi_app`` — raw ASGI protocol compliance
* Error handling for malformed requests
"""

from __future__ import annotations

import asyncio
import json
from typing import Any
from unittest.mock import MagicMock

import pytest

from agentmesh.gateway.policy_provider import PolicyProviderHandler


# ---------------------------------------------------------------------------
# Helpers — lightweight mock objects
# ---------------------------------------------------------------------------


class _StubDecision:
    """Mimics a ``PolicyDecision`` with the attributes the handler reads."""

    def __init__(
        self,
        allowed: bool = True,
        action: str = "allow",
        reason: str = "",
    ):
        self.allowed = allowed
        self.action = action
        self.reason = reason

    def label(self) -> str:
        return self.action

    def __str__(self) -> str:
        return self.reason if self.reason else self.action


def _make_engine(
    decision: _StubDecision | None = None,
    policies: list[str] | None = None,
) -> MagicMock:
    """Create a mock policy engine."""
    engine = MagicMock(spec=[])
    engine.evaluate = MagicMock(return_value=decision or _StubDecision())
    engine.list_policies = MagicMock(return_value=policies or [])
    return engine


def _make_handler(
    decision: _StubDecision | None = None,
    policies: list[str] | None = None,
    trust_score: float | None = None,
    with_audit: bool = False,
) -> PolicyProviderHandler:
    """Create a ``PolicyProviderHandler`` with mock dependencies."""
    engine = _make_engine(decision, policies)

    trust_mgr = None
    if trust_score is not None:
        trust_mgr = MagicMock()
        trust_mgr.get_trust_score.return_value = trust_score

    audit = MagicMock() if with_audit else None
    return PolicyProviderHandler(engine, trust_manager=trust_mgr, audit_logger=audit)


# ---------------------------------------------------------------------------
# ASGI protocol helpers
# ---------------------------------------------------------------------------


async def _asgi_request(
    app,
    method: str,
    path: str,
    body: bytes = b"",
) -> tuple[int, dict]:
    """Send a single ASGI HTTP request and return (status, parsed JSON body)."""
    scope: dict[str, Any] = {
        "type": "http",
        "method": method,
        "path": path,
        "headers": [],
    }

    body_sent = False

    async def receive():
        nonlocal body_sent
        if not body_sent:
            body_sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return {"type": "http.disconnect"}

    status_code = 0
    response_body = b""

    async def send(message: dict):
        nonlocal status_code, response_body
        if message["type"] == "http.response.start":
            status_code = message["status"]
        elif message["type"] == "http.response.body":
            response_body += message.get("body", b"")

    await app(scope, receive, send)
    return status_code, json.loads(response_body) if response_body else {}


# =========================================================================
# handle_check tests
# =========================================================================


class TestHandleCheck:
    """Tests for POST /check — policy evaluation."""

    def test_allowed_decision(self):
        handler = _make_handler(decision=_StubDecision(allowed=True, action="allow"))
        result = handler.handle_check(
            {"agent_id": "agent-1", "action": "read", "context": {}}
        )
        assert result["allowed"] is True
        assert result["decision"] == "allow"
        assert "evaluation_ms" in result

    def test_denied_decision(self):
        handler = _make_handler(
            decision=_StubDecision(allowed=False, action="deny", reason="policy violation")
        )
        result = handler.handle_check(
            {"agent_id": "agent-2", "action": "delete", "context": {}}
        )
        assert result["allowed"] is False
        assert result["decision"] == "deny"
        assert result["reason"] == "policy violation"

    def test_includes_trust_score(self):
        handler = _make_handler(trust_score=0.92)
        result = handler.handle_check(
            {"agent_id": "agent-3", "action": "read", "context": {}}
        )
        assert result["trust_score"] == 0.92

    def test_trust_score_none_when_no_manager(self):
        handler = _make_handler()
        result = handler.handle_check(
            {"agent_id": "agent-4", "action": "read", "context": {}}
        )
        assert result["trust_score"] is None

    def test_passes_agent_id_to_engine(self):
        engine = _make_engine()
        handler = PolicyProviderHandler(engine)
        handler.handle_check(
            {"agent_id": "agent-5", "action": "write", "context": {"key": "val"}}
        )
        call_args = engine.evaluate.call_args
        assert call_args[0][0] == "write"

    def test_audit_logger_called(self):
        handler = _make_handler(with_audit=True)
        handler.handle_check(
            {"agent_id": "agent-6", "action": "export", "context": {}}
        )
        handler.audit_logger.log.assert_called_once()

    def test_missing_fields_use_defaults(self):
        handler = _make_handler()
        result = handler.handle_check({})
        assert result["allowed"] is True


# =========================================================================
# handle_health tests
# =========================================================================


class TestHandleHealth:
    """Tests for GET /health."""

    def test_health_response_structure(self):
        handler = _make_handler(policies=["p1", "p2"])
        result = handler.handle_health()
        assert result["status"] == "healthy"
        assert result["policies_loaded"] == 2

    def test_health_with_no_policies(self):
        handler = _make_handler()
        result = handler.handle_health()
        assert result["status"] == "healthy"
        assert result["policies_loaded"] == 0


# =========================================================================
# handle_policies tests
# =========================================================================


class TestHandlePolicies:
    """Tests for GET /policies."""

    def test_lists_loaded_policies(self):
        handler = _make_handler(policies=["deny-exports", "rate-limit"])
        result = handler.handle_policies()
        assert result["policies"] == ["deny-exports", "rate-limit"]

    def test_empty_when_no_policies(self):
        handler = _make_handler()
        result = handler.handle_policies()
        assert result["policies"] == []


# =========================================================================
# ASGI app tests
# =========================================================================


class TestAsgiApp:
    """Tests for the raw ASGI application."""

    def test_health_endpoint(self):
        handler = _make_handler(policies=["p1"])
        app = handler.to_asgi_app()
        status, body = asyncio.get_event_loop().run_until_complete(
            _asgi_request(app, "GET", "/health")
        )
        assert status == 200
        assert body["status"] == "healthy"

    def test_policies_endpoint(self):
        handler = _make_handler(policies=["my-policy"])
        app = handler.to_asgi_app()
        status, body = asyncio.get_event_loop().run_until_complete(
            _asgi_request(app, "GET", "/policies")
        )
        assert status == 200
        assert "my-policy" in body["policies"]

    def test_check_endpoint(self):
        handler = _make_handler(
            decision=_StubDecision(allowed=True, action="allow")
        )
        app = handler.to_asgi_app()
        payload = json.dumps(
            {"agent_id": "a1", "action": "read", "context": {}}
        ).encode()
        status, body = asyncio.get_event_loop().run_until_complete(
            _asgi_request(app, "POST", "/check", payload)
        )
        assert status == 200
        assert body["allowed"] is True

    def test_check_invalid_json(self):
        handler = _make_handler()
        app = handler.to_asgi_app()
        status, body = asyncio.get_event_loop().run_until_complete(
            _asgi_request(app, "POST", "/check", b"not-json")
        )
        assert status == 400
        assert "error" in body

    def test_not_found(self):
        handler = _make_handler()
        app = handler.to_asgi_app()
        status, body = asyncio.get_event_loop().run_until_complete(
            _asgi_request(app, "GET", "/unknown")
        )
        assert status == 404
        assert "error" in body
