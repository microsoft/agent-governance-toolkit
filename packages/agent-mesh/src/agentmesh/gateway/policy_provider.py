# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Policy provider HTTP endpoint for API gateway integration.

Serves policy decisions via a minimal ASGI app so API gateways
(Azure APIM, Kong, Envoy) can call AGT for authorization checks
without a framework dependency.
"""

from __future__ import annotations

import json
import time
from typing import Any


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
        """
        agent_id = request.get("agent_id", "")
        action = request.get("action", "")
        context = request.get("context", {})

        start = time.monotonic()
        decision = self.policy_engine.evaluate(action, context)
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
            except Exception:
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
                body = json.dumps(self.handle_check(request)).encode()
                status = 200
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
