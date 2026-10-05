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

        Engine exceptions propagate to the caller: a failure is not a
        decision, so it is never converted into an allow or deny here.
        Direct callers of this method receive the evaluation exception
        itself; the ASGI boundary is responsible for converting that
        failure into a structured 503 error response.

        Audit trade-off: because no decision was reached, no allow/deny
        record is written to the decision audit stream. Recording a deny
        would be misleading, so the failure is represented by server-side
        exception logging instead. Callers that rely exclusively on
        decision audit records will not see a record for a failed
        evaluation.
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
                # Valid JSON is not necessarily a valid check request:
                # only an object has the agent_id/action/context fields.
                if not isinstance(request, dict):
                    body = json.dumps({"error": "invalid request"}).encode()
                    status = 400
                else:
                    try:
                        body = json.dumps(self.handle_check(request)).encode()
                    except Exception:
                        # Engine failure is not a decision: report a 503 with the
                        # same {"error": ...} shape as the other error responses.
                        # 503 rather than 500 because unusable policy state is a
                        # transient, retryable condition (consistent with
                        # server/policy_server.py). Diagnostics stay server-side
                        # via exc_info; the client sees only a fixed message,
                        # and never an allow.
                        logger.exception("Policy evaluation failed")
                        body = json.dumps({"error": "policy evaluation failed"}).encode()
                        status = 503
                    else:
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
