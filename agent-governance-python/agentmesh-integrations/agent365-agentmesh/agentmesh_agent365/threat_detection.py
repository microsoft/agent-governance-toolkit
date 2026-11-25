# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Copilot Studio external threat detection backed by AGT policy.

Copilot Studio calls an external threat detection service each time a
generative agent is about to invoke a tool:

* ``POST {base}/validate?api-version=2025-05-01`` with an empty body, which
  must return ``{"isSuccessful": true, "status": "OK"}``;
* ``POST {base}/analyze-tool-execution?api-version=2025-05-01`` with the
  planner context, tool definition, input values and conversation metadata,
  which must return ``{"blockAction": bool, "reasonCode"?, "reason"?,
  "diagnostics"?}``.

**Copilot Studio treats a response slower than 1,000 ms as "allow".** This
handler therefore runs the AGT decision under an internal budget (default
700 ms) and returns ``blockAction: true`` itself when the budget is exceeded
or the decision raises, so that the outcome stays fail-closed whenever the
service is able to answer at all. Network-level timeouts remain fail-open by
Copilot Studio's design; document that residual risk in deployments.

Callers authenticate with Microsoft Entra ID. :func:`create_app` validates the
bearer token through a caller-supplied verifier (for example
``agentmesh.identity.entra_verifier.EntraTokenVerifier``) and an allow-list of
caller application IDs.
"""

# No ``from __future__ import annotations``: FastAPI must resolve the
# ``Request`` annotation of endpoints defined inside ``create_app``.
import asyncio
import inspect
import json
import logging
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

API_VERSION = "2025-05-01"
#: Copilot Studio allows the tool call if no answer arrives within this time.
COPILOT_STUDIO_TIMEOUT_MS = 1000
DEFAULT_BUDGET_MS = 700

REASON_POLICY_DENY = 1001
REASON_EVALUATION_TIMEOUT = 1002
REASON_EVALUATION_ERROR = 1003
REASON_INVALID_REQUEST = 1004

ERROR_AUTH = 2003


@dataclass(frozen=True)
class ToolExecutionRequest:
    """The parts of an ``analyze-tool-execution`` request AGT evaluates."""

    agent_id: str
    tenant_id: str
    environment_id: str
    tool_id: str
    tool_name: str
    tool_type: str
    input_values: Mapping[str, Any]
    conversation_id: str
    user_id: str | None = None
    user_message: str = ""
    planner_thought: str = ""
    plan_id: str | None = None
    plan_step_id: str | None = None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "ToolExecutionRequest":
        """Parse a request body, tolerating unknown fields.

        Raises:
            ValueError: If a required field is missing.
        """
        if not isinstance(payload, Mapping):
            raise ValueError("body must be a JSON object")
        planner = payload.get("plannerContext")
        tool = payload.get("toolDefinition")
        inputs = payload.get("inputValues")
        meta = payload.get("conversationMetadata")
        for name, value in (
            ("plannerContext", planner),
            ("toolDefinition", tool),
            ("inputValues", inputs),
            ("conversationMetadata", meta),
        ):
            if not isinstance(value, Mapping):
                raise ValueError(f"Missing required field: {name}")
        agent = meta.get("agent")
        if not isinstance(agent, Mapping):
            raise ValueError("Missing required field: conversationMetadata.agent")
        for name in ("id", "name"):
            if not isinstance(tool.get(name), str) or not tool.get(name):
                raise ValueError(f"Missing required field: toolDefinition.{name}")
        for name in ("id", "tenantId"):
            if not isinstance(agent.get(name), str) or not agent.get(name):
                raise ValueError(f"Missing required field: conversationMetadata.agent.{name}")
        user = meta.get("user") if isinstance(meta.get("user"), Mapping) else {}
        return cls(
            agent_id=agent["id"],
            tenant_id=agent["tenantId"],
            environment_id=str(agent.get("environmentId", "")),
            tool_id=tool["id"],
            tool_name=tool["name"],
            tool_type=str(tool.get("type", "")),
            input_values=dict(inputs),
            conversation_id=str(meta.get("conversationId", "")),
            user_id=user.get("id") if isinstance(user.get("id"), str) else None,
            user_message=str(planner.get("userMessage", "")),
            planner_thought=str(planner.get("thought", "")),
            plan_id=meta.get("planId") if isinstance(meta.get("planId"), str) else None,
            plan_step_id=meta.get("planStepId") if isinstance(meta.get("planStepId"), str) else None,
            raw=payload,
        )


@dataclass(frozen=True)
class ThreatDecision:
    """An allow/block decision for one tool execution."""

    allowed: bool
    reason: str = ""
    reason_code: int | None = None

    def to_response(self, diagnostics: Mapping[str, Any] | None = None) -> dict[str, Any]:
        body: dict[str, Any] = {"blockAction": not self.allowed}
        if not self.allowed:
            body["reasonCode"] = self.reason_code or REASON_POLICY_DENY
            if self.reason:
                body["reason"] = self.reason[:512]
        if diagnostics:
            # The contract requires diagnostics to be a pre-serialized string.
            body["diagnostics"] = json.dumps(dict(diagnostics), separators=(",", ":"))
        return body


Decider = Callable[[ToolExecutionRequest], "ThreatDecision | Awaitable[ThreatDecision]"]


class ThreatDetectionHandler:
    """Turn ``analyze-tool-execution`` requests into AGT decisions.

    Args:
        decide: Sync or async callable returning a :class:`ThreatDecision`.
            Sync callables run in a worker thread so the budget applies.
        budget_ms: Internal deadline; must be below Copilot Studio's 1,000 ms.
    """

    def __init__(self, decide: Decider, *, budget_ms: int = DEFAULT_BUDGET_MS) -> None:
        if not 0 < budget_ms < COPILOT_STUDIO_TIMEOUT_MS:
            raise ValueError("budget_ms must be between 1 and 999")
        self._decide = decide
        self.budget_ms = budget_ms

    @staticmethod
    def validate() -> dict[str, Any]:
        """Return the ``/validate`` response body."""
        return {"isSuccessful": True, "status": "OK"}

    async def analyze(self, payload: Mapping[str, Any], *, correlation_id: str | None = None) -> dict[str, Any]:
        """Return the ``/analyze-tool-execution`` response body (never raises)."""
        try:
            request = ToolExecutionRequest.from_payload(payload)
        except ValueError as exc:
            return ThreatDecision(False, str(exc), REASON_INVALID_REQUEST).to_response()
        try:
            decision = await asyncio.wait_for(self._run(request), timeout=self.budget_ms / 1000)
            if not isinstance(decision, ThreatDecision):
                raise TypeError("decide() must return ThreatDecision")
        except asyncio.TimeoutError:
            logger.warning(
                "AGT threat decision exceeded %d ms — blocking | agent=%s tool=%s correlation=%s",
                self.budget_ms, request.agent_id, request.tool_name, correlation_id,
            )
            decision = ThreatDecision(False, "Governance evaluation timed out (fail closed)", REASON_EVALUATION_TIMEOUT)
        except Exception:
            logger.error(
                "AGT threat decision failed — blocking | agent=%s tool=%s correlation=%s",
                request.agent_id, request.tool_name, correlation_id, exc_info=True,
            )
            decision = ThreatDecision(False, "Governance evaluation error (fail closed)", REASON_EVALUATION_ERROR)
        logger.info(
            "Copilot Studio tool decision | agent=%s tool=%s blocked=%s correlation=%s",
            request.agent_id, request.tool_name, not decision.allowed, correlation_id,
        )
        diagnostics = {"correlationId": correlation_id} if correlation_id else None
        return decision.to_response(diagnostics)

    async def _run(self, request: ToolExecutionRequest) -> ThreatDecision:
        if inspect.iscoroutinefunction(self._decide):
            return await self._decide(request)
        result = await asyncio.to_thread(self._decide, request)
        if inspect.isawaitable(result):
            return await result
        return result


def gateway_decider(gateway: Any, *, agent_prefix: str = "copilot-studio") -> Callable[[ToolExecutionRequest], ThreatDecision]:
    """Adapt an ``agent_os.mcp_gateway.MCPGateway`` into a decider.

    The gateway's deny list, parameter sanitization, ACS runtime policy,
    approval rules, call budget and audit log all apply. Tools that require
    human approval are blocked because Copilot Studio cannot wait for one.
    """

    def decide(request: ToolExecutionRequest) -> ThreatDecision:
        allowed, reason = gateway.intercept_tool_call(
            f"{agent_prefix}:{request.agent_id}",
            request.tool_name,
            dict(request.input_values),
        )
        return ThreatDecision(allowed, reason, None if allowed else REASON_POLICY_DENY)

    return decide


def create_app(
    handler: ThreatDetectionHandler,
    *,
    verify_token: Callable[[str], Any],
    allowed_client_ids: set[str],
) -> Any:
    """Create a FastAPI app exposing ``/validate`` and ``/analyze-tool-execution``.

    Args:
        handler: The decision handler.
        verify_token: Sync or async callable that validates a bearer token
            (signature, issuer, audience, expiry) and returns its claims;
            raises on failure. For example ``EntraTokenVerifier(cfg).verify``.
        allowed_client_ids: Caller application IDs (``azp``/``appid``) that
            may call the service. Must be non-empty.
    """
    if not allowed_client_ids:
        raise ValueError("allowed_client_ids must not be empty")
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse

    app = FastAPI(title="AGT threat detection for Copilot Studio", docs_url=None, redoc_url=None, openapi_url=None)

    def _error(code: int, message: str, status: int) -> JSONResponse:
        return JSONResponse({"errorCode": code, "message": message, "httpStatus": status}, status_code=status)

    async def _authorize(request: Request) -> JSONResponse | None:
        header = request.headers.get("authorization", "")
        if not header.lower().startswith("bearer "):
            return _error(ERROR_AUTH, "Missing bearer token", 401)
        try:
            token = header[7:].strip()
            if inspect.iscoroutinefunction(verify_token):
                claims = await verify_token(token)
            else:
                # Sync verifiers may fetch signing keys; keep the loop free.
                claims = await asyncio.to_thread(verify_token, token)
                if inspect.isawaitable(claims):
                    claims = await claims
            if not isinstance(claims, Mapping):
                raise TypeError("verify_token must return a claims mapping")
        except Exception:
            logger.info("Rejected threat-detection call with invalid token", exc_info=True)
            return _error(ERROR_AUTH, "Invalid token", 401)
        client_id = claims.get("azp") or claims.get("appid")
        if client_id not in allowed_client_ids:
            return _error(ERROR_AUTH, "Caller is not authorized", 403)
        return None

    @app.post("/validate")
    async def validate(request: Request) -> Any:
        denied = await _authorize(request)
        return denied or JSONResponse(handler.validate())

    @app.post("/analyze-tool-execution")
    async def analyze(request: Request) -> Any:
        denied = await _authorize(request)
        if denied:
            return denied
        try:
            payload = await request.json()
        except ValueError:
            # Treated as an invalid request and blocked by the handler.
            payload = None
        body = await handler.analyze(payload, correlation_id=request.headers.get("x-ms-correlation-id"))
        return JSONResponse(body)

    return app
