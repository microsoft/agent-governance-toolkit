# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Policy provider HTTP endpoint for API gateway integration.

Serves policy decisions via a minimal ASGI app so API gateways
(Azure APIM, Kong, Envoy) can call AGT for authorization checks
without a framework dependency.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

logger = logging.getLogger(__name__)


class PolicyProviderHandler:
    """HTTP request handler for policy provider endpoint."""

    def __init__(self, policy_engine: Any, trust_manager: Any = None, audit_logger: Any = None) -> None:
        self.policy_engine = policy_engine
        self.trust_manager = trust_manager
        self.audit_logger = audit_logger

    def handle_check(self, request: dict) -> dict:
        """Evaluate a policy decision.

        Request: {"agent_id": "...", "action": "...", "context": {...}}
        Response: {"allowed": bool, "decision": "...", "reason": "...", "trust_score": float}

        Policy evaluation failures are fail-closed: they return ``decision`` of
        ``"deny"`` with a fixed ``error`` string. No part of the exception --
        class name, message, or traceback -- reaches the response, so internal
        exception details are not exposed to API gateway clients; the full
        traceback goes to the log.

        The audit trail records the failure as its own ``"evaluation_error"``
        outcome rather than ``"deny"``, so an audit reader can tell an engine
        outage apart from an actual policy denial. ``"deny"`` in the audit log
        would read as "the policy said no", which is a claim this path cannot
        make: the policy engine never answered.
        """
        agent_id = request.get("agent_id", "")
        action = request.get("action", "")
        context = request.get("context", {})

        start = time.monotonic()
        try:
            decision = self.policy_engine.evaluate(action, context)
        except Exception as exc:
            duration_ms = (time.monotonic() - start) * 1000
            logger.error("Policy evaluation failed for agent %s: %s", agent_id, exc, exc_info=True)

            if self.audit_logger is not None:
                try:
                    # "evaluation_error", not "deny": the engine never returned a
                    # decision, so a "deny" here would attribute to the policy
                    # something the policy did not say.
                    self.audit_logger.log(agent_id, action, "evaluation_error")
                except Exception:  # noqa: S110 — intentional silent catch for audit logging
                    pass
            return {
                "allowed": False,
                "decision": "deny",
                "reason": "policy evaluation failed",
                # Fixed string, not type(exc).__name__: #4172 requires that no
                # internal detail reach clients, and the class name is detail.
                "error": "policy evaluation failed",
                "trust_score": None,
                "evaluation_ms": round(duration_ms, 2),
            }
        duration_ms = (time.monotonic() - start) * 1000

        trust_score = None
        if self.trust_manager is not None:
            try:
                score = self.trust_manager.get_trust_score(agent_id)
                trust_score = getattr(score, "score", score) if score else None
            except Exception:
                trust_score = None

        decision_label = getattr(decision, "label", lambda: str(decision))()
        allowed = decision_label == "allow"
        reason = str(decision) if not allowed else ""

        if self.audit_logger is not None:
            try:
                self.audit_logger.log(agent_id, action, decision_label)
            except Exception:  # noqa: S110 — intentional silent catch for audit logging
                pass
        return {
            "allowed": allowed,
            "decision": decision_label,
            "reason": reason,
            "trust_score": trust_score,
            "evaluation_ms": round(duration_ms, 2),
        }

    def handle_health(self) -> dict:
        """Health check endpoint."""
        policies_loaded = 0
        if hasattr(self.policy_engine, "is_loaded"):
            policies_loaded = 1 if self.policy_engine.is_loaded() else 0
        elif hasattr(self.policy_engine, "list_policies"):
            policies_loaded = len(self.policy_engine.list_policies())
        return {"status": "healthy", "policies_loaded": policies_loaded}

    def handle_policies(self) -> dict:
        """List loaded policies."""
        names: list[str] = []
        if hasattr(self.policy_engine, "list_policies"):
            names = self.policy_engine.list_policies()
        return {"policies": names}

    async def asgi_app(self, scope: dict, receive: Any, send: Any) -> None:
        """Minimal ASGI application -- no framework dependency."""
        if scope["type"] != "http":
            return

        path = scope.get("path", "")
        method = scope.get("method", "GET")

        if method == "GET" and path == "/health":
            body = json.dumps(self.handle_health()).encode()
            status = 200
        elif method == "GET" and path == "/policies":
            body = json.dumps(self.handle_policies()).encode()
            status = 200
        elif method == "POST" and path == "/check":
            request_body = b""
            while True:
                message = await receive()
                request_body += message.get("body", b"")
                if not message.get("more_body", False):
                    break
            try:
                request = json.loads(request_body)
            except (json.JSONDecodeError, ValueError):
                body = json.dumps({"error": "invalid JSON"}).encode()
                status = 400
            else:
                if not isinstance(request, dict):
                    body = json.dumps({"error": "request body must be a JSON object"}).encode()
                    status = 400
                else:
                    result = self.handle_check(request)
                    body = json.dumps(result).encode()
                    # A policy engine failure is an unusable policy state, so mirror
                    # server/policy_server.py and answer 503 rather than 200.
                    status = 503 if "error" in result else 200
        else:
            body = json.dumps({"error": "not found"}).encode()
            status = 404

        await send({
            "type": "http.response.start",
            "status": status,
            "headers": [[b"content-type", b"application/json"]],
        })
        await send({"type": "http.response.body", "body": body})

    def to_asgi_app(self) -> Any:
        """Return the ASGI callable."""
        return self.asgi_app
