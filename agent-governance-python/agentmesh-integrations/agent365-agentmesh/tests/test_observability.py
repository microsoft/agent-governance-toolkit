# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for Agent 365 observability helpers."""
from __future__ import annotations

import httpx
import pytest
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

from agentmesh_agent365 import (
    A365_OBO_SCOPE,
    A365_S2S_SCOPE,
    GovernanceSpanRecorder,
    check_eligibility,
    otlp_exporter_settings,
    traces_url,
)

TENANT = "11111111-2222-3333-4444-555555555555"
AGENT = "agent/with space"


def test_traces_url_s2s_and_obo() -> None:
    assert traces_url(TENANT, "a1") == (
        f"https://agent365.svc.cloud.microsoft/observabilityService/tenants/{TENANT}/otlp/agents/a1/traces?api-version=1"
    )
    assert "/observability/tenants/" in traces_url(TENANT, "a1", on_behalf_of=True)
    assert "agent%2Fwith%20space" in traces_url(TENANT, AGENT)


@pytest.mark.parametrize("tenant", ["", "contoso.onmicrosoft.com", "../../evil"])
def test_traces_url_rejects_non_guid_tenant(tenant: str) -> None:
    with pytest.raises(ValueError):
        traces_url(tenant, "a1")


def test_exporter_settings_pick_scope() -> None:
    s2s = otlp_exporter_settings(TENANT, "a1", "tok")
    assert s2s.headers == {"Authorization": "Bearer tok"}
    assert s2s.scope == A365_S2S_SCOPE
    assert otlp_exporter_settings(TENANT, "a1", "tok", on_behalf_of=True).scope == A365_OBO_SCOPE
    with pytest.raises(ValueError):
        otlp_exporter_settings(TENANT, "a1", "")


def _recorder() -> tuple[GovernanceSpanRecorder, InMemorySpanExporter]:
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return GovernanceSpanRecorder(provider.get_tracer("test"), tenant_id=TENANT, agent_id="a1"), exporter


def test_recorder_emits_one_root_and_governed_tool_spans() -> None:
    recorder, exporter = _recorder()
    with recorder.invoke_agent(agent_name="claims", conversation_id="c1"):
        recorder.record_tool_decision("read_file", allowed=True, reason="ok", tool_call_id="t1")
        recorder.record_tool_decision("send_mail", allowed=False, reason="bcc outside tenant", stage="runtime")
    spans = exporter.get_finished_spans()
    roots = [s for s in spans if s.parent is None]
    assert len(roots) == 1
    root = roots[0]
    assert root.attributes["gen_ai.operation.name"] == "invoke_agent"
    assert root.attributes["microsoft.tenant.id"] == TENANT
    tools = {s.attributes["gen_ai.tool.name"]: s for s in spans if s.parent is not None}
    assert tools["read_file"].attributes["agt.policy.decision"] == "allow"
    assert tools["read_file"].attributes["gen_ai.tool.call.id"] == "t1"
    denied = tools["send_mail"]
    assert denied.attributes["gen_ai.operation.name"] == "execute_tool"
    assert denied.attributes["agt.policy.decision"] == "deny"
    assert denied.attributes["agt.policy.stage"] == "runtime"
    assert denied.status.status_code == StatusCode.ERROR
    assert all(s.parent.span_id == root.context.span_id for s in tools.values())


def test_recorder_enforces_single_root_and_scoping() -> None:
    recorder, _ = _recorder()
    with pytest.raises(RuntimeError):
        recorder.record_tool_decision("x", allowed=True)
    with recorder.invoke_agent():
        with pytest.raises(RuntimeError):
            with recorder.invoke_agent():
                pass
    with recorder.invoke_agent():  # root can be reopened for the next run
        pass


def test_eligibility_check_is_conservative() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer tok"
        assert request.url.path.endswith(f"/tenants/{TENANT}/eligibility")
        return httpx.Response(200, json={"isEligible": True})

    assert check_eligibility(httpx.Client(transport=httpx.MockTransport(handler)), TENANT, "tok") is True
    forbidden = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(403)))
    assert check_eligibility(forbidden, TENANT, "tok") is False
    unknown = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"status": "?"})))
    assert check_eligibility(unknown, TENANT, "tok") is False
