# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the Copilot Studio external threat detection bridge."""
from __future__ import annotations

import asyncio
import copy
import json
import time
from typing import Any

import pytest
from fastapi.testclient import TestClient

from agentmesh_agent365 import (
    ThreatDecision,
    ThreatDetectionHandler,
    ToolExecutionRequest,
    create_app,
    gateway_decider,
)
from agentmesh_agent365.threat_detection import (
    REASON_EVALUATION_ERROR,
    REASON_EVALUATION_TIMEOUT,
    REASON_INVALID_REQUEST,
    REASON_POLICY_DENY,
)

# Request body from the Copilot Studio developer documentation.
PAYLOAD: dict[str, Any] = {
    "plannerContext": {
        "userMessage": "Send an email to the customer",
        "thought": "User wants to notify customer",
        "chatHistory": [{"id": "m1", "role": "user", "content": "Send an email to the customer"}],
    },
    "toolDefinition": {
        "id": "tool-123",
        "type": "PrebuiltToolDefinition",
        "name": "Send email",
        "description": "Sends an email to specified recipients.",
        "inputParameters": [{"name": "to"}, {"name": "bcc"}],
    },
    "inputValues": {"to": "customer@foobar.com", "bcc": "hacker@evil.com"},
    "conversationMetadata": {
        "agent": {"id": "agent-guid", "tenantId": "tenant-guid", "environmentId": "env-guid", "isPublished": True},
        "user": {"id": "user-guid", "tenantId": "tenant-guid"},
        "conversationId": "conv-id",
        "planId": "plan-guid",
        "planStepId": "step-1",
        "futureField": {"ignored": True},
    },
}


def _block_external_bcc(request: ToolExecutionRequest) -> ThreatDecision:
    bcc = str(request.input_values.get("bcc", ""))
    if bcc and not bcc.endswith("@foobar.com"):
        return ThreatDecision(False, "External BCC recipient", 112)
    return ThreatDecision(True)


def test_parses_documented_payload() -> None:
    request = ToolExecutionRequest.from_payload(PAYLOAD)
    assert request.agent_id == "agent-guid"
    assert request.tool_name == "Send email"
    assert request.input_values["bcc"] == "hacker@evil.com"
    assert request.plan_step_id == "step-1"


async def test_allow_and_block_responses() -> None:
    handler = ThreatDetectionHandler(_block_external_bcc)
    blocked = await handler.analyze(PAYLOAD, correlation_id="corr-1")
    assert blocked["blockAction"] is True
    assert blocked["reasonCode"] == 112
    assert blocked["reason"] == "External BCC recipient"
    assert json.loads(blocked["diagnostics"]) == {"correlationId": "corr-1"}
    clean = copy.deepcopy(PAYLOAD)
    clean["inputValues"]["bcc"] = "audit@foobar.com"
    assert await handler.analyze(clean) == {"blockAction": False}


async def test_slow_sync_decider_is_blocked_within_budget() -> None:
    def slow(_: ToolExecutionRequest) -> ThreatDecision:
        time.sleep(0.5)
        return ThreatDecision(True)

    handler = ThreatDetectionHandler(slow, budget_ms=100)
    started = time.perf_counter()
    response = await handler.analyze(PAYLOAD)
    assert time.perf_counter() - started < 0.4
    assert response["blockAction"] is True
    assert response["reasonCode"] == REASON_EVALUATION_TIMEOUT


async def test_slow_async_decider_is_blocked() -> None:
    async def slow(_: ToolExecutionRequest) -> ThreatDecision:
        await asyncio.sleep(1)
        return ThreatDecision(True)

    response = await ThreatDetectionHandler(slow, budget_ms=50).analyze(PAYLOAD)
    assert response["reasonCode"] == REASON_EVALUATION_TIMEOUT


@pytest.mark.parametrize("result", [RuntimeError("boom"), "not a decision"])
async def test_errors_and_bad_results_fail_closed(result: Any) -> None:
    def broken(_: ToolExecutionRequest) -> Any:
        if isinstance(result, Exception):
            raise result
        return result

    response = await ThreatDetectionHandler(broken).analyze(PAYLOAD)
    assert response["blockAction"] is True
    assert response["reasonCode"] == REASON_EVALUATION_ERROR


@pytest.mark.parametrize("missing", ["toolDefinition", "inputValues", "conversationMetadata"])
async def test_invalid_payload_is_blocked(missing: str) -> None:
    payload = copy.deepcopy(PAYLOAD)
    del payload[missing]
    response = await ThreatDetectionHandler(lambda _: ThreatDecision(True)).analyze(payload)
    assert response["blockAction"] is True
    assert response["reasonCode"] == REASON_INVALID_REQUEST


def test_budget_must_stay_below_copilot_studio_timeout() -> None:
    with pytest.raises(ValueError):
        ThreatDetectionHandler(lambda _: ThreatDecision(True), budget_ms=1000)


class _FakeGateway:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict[str, Any]]] = []

    def intercept_tool_call(self, agent_id: str, tool_name: str, params: dict[str, Any]) -> tuple[bool, str]:
        self.calls.append((agent_id, tool_name, params))
        return (tool_name != "Send email", "Tool 'Send email' is on the deny list")


async def test_gateway_decider_routes_through_mcp_gateway() -> None:
    gateway = _FakeGateway()
    response = await ThreatDetectionHandler(gateway_decider(gateway)).analyze(PAYLOAD)
    assert response["blockAction"] is True
    assert response["reasonCode"] == REASON_POLICY_DENY
    assert gateway.calls[0][0] == "copilot-studio:agent-guid"
    assert gateway.calls[0][2]["bcc"] == "hacker@evil.com"


def test_gateway_decider_with_real_mcp_gateway() -> None:
    mcp_gateway = pytest.importorskip("agent_os.mcp_gateway")
    from agent_control_specification import Decision, InterventionPointResult, Verdict

    class _Runtime:
        manifest = None

        async def evaluate_intervention_point(self, point, snapshot, mode=None):
            return InterventionPointResult(verdict=Verdict(decision=Decision("allow"), reason="", message=""))

    gateway = mcp_gateway.MCPGateway(_Runtime(), denied_tools=["Send email"])
    decision = gateway_decider(gateway)(ToolExecutionRequest.from_payload(PAYLOAD))
    assert decision.allowed is False
    assert gateway.audit_log[-1].agent_id == "copilot-studio:agent-guid"


def _client() -> TestClient:
    def verify(token: str) -> dict[str, Any]:
        if token == "good":
            return {"azp": "copilot-studio-app"}
        if token == "other":
            return {"appid": "someone-else"}
        raise ValueError("bad signature")

    app = create_app(
        ThreatDetectionHandler(_block_external_bcc),
        verify_token=verify,
        allowed_client_ids={"copilot-studio-app"},
    )
    return TestClient(app)


def test_app_requires_authenticated_allow_listed_caller() -> None:
    client = _client()
    url = "/analyze-tool-execution?api-version=2025-05-01"
    assert client.post(url, json=PAYLOAD).status_code == 401
    assert client.post(url, json=PAYLOAD, headers={"Authorization": "Bearer forged"}).status_code == 401
    forbidden = client.post(url, json=PAYLOAD, headers={"Authorization": "Bearer other"})
    assert forbidden.status_code == 403
    assert forbidden.json()["errorCode"] == 2003


def test_app_validate_and_analyze() -> None:
    client = _client()
    auth = {"Authorization": "Bearer good", "x-ms-correlation-id": "c-9"}
    validate = client.post("/validate?api-version=2025-05-01", headers=auth)
    assert validate.json() == {"isSuccessful": True, "status": "OK"}
    analyzed = client.post("/analyze-tool-execution?api-version=2099-01-01", json=PAYLOAD, headers=auth)
    assert analyzed.status_code == 200
    assert analyzed.json()["blockAction"] is True
    garbage = client.post("/analyze-tool-execution", content=b"{not json", headers=auth)
    assert garbage.json()["blockAction"] is True


def test_app_accepts_async_verifier_like_entra_token_verifier() -> None:
    async def verify(token: str) -> dict[str, Any]:
        if token != "good":
            raise ValueError("bad")
        return {"azp": "copilot-studio-app"}

    client = TestClient(
        create_app(ThreatDetectionHandler(_block_external_bcc), verify_token=verify, allowed_client_ids={"copilot-studio-app"})
    )
    assert client.post("/validate", headers={"Authorization": "Bearer good"}).status_code == 200
    assert client.post("/validate", headers={"Authorization": "Bearer bad"}).status_code == 401


def test_app_requires_allow_list() -> None:
    with pytest.raises(ValueError):
        create_app(ThreatDetectionHandler(_block_external_bcc), verify_token=lambda t: {}, allowed_client_ids=set())
