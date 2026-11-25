# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Emit AGT governance decisions as Microsoft Agent 365 observability spans.

Agent 365 accepts OTLP/HTTP traces for an agent at::

    POST https://agent365.svc.cloud.microsoft/observabilityService/tenants/{tenantId}/otlp/agents/{agentId}/traces?api-version=1

(service-to-service) or ``/observability/...`` for on-behalf-of user tokens.
Spans must use the GenAI semantic conventions: ``gen_ai.operation.name`` is
one of ``invoke_agent``, ``execute_tool``, ``chat`` or ``output_messages``,
each agent run has exactly one root ``invoke_agent`` span, and
``microsoft.tenant.id`` must equal the tenant in the URL. Ingestion requires
the tenant to hold an Agent 365 (or Microsoft 365 E7) licence; check with
:func:`eligibility_url` before enabling export.

This module records AGT policy decisions on those spans (``agt.policy.*``
attributes) so that governance outcomes appear alongside the agent's own
telemetry in Agent 365. It depends only on the OpenTelemetry API; configure an
OTLP/HTTP exporter with :func:`otlp_exporter_settings`.
"""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any

A365_HOST = "https://agent365.svc.cloud.microsoft"
#: Entra resource (application) ID of the Agent 365 observability service.
A365_OBSERVABILITY_RESOURCE = "9b975845-388f-4429-889e-eab1ef63949c"
#: Scope for app-only (service-to-service) tokens.
A365_S2S_SCOPE = f"{A365_OBSERVABILITY_RESOURCE}/.default"
#: Delegated scope for on-behalf-of tokens.
A365_OBO_SCOPE = f"{A365_OBSERVABILITY_RESOURCE}/Agent365.Observability.OtelWrite"

OPERATION_INVOKE_AGENT = "invoke_agent"
OPERATION_EXECUTE_TOOL = "execute_tool"
OPERATION_CHAT = "chat"
OPERATION_OUTPUT_MESSAGES = "output_messages"
ALLOWED_OPERATIONS = frozenset(
    {OPERATION_INVOKE_AGENT, OPERATION_EXECUTE_TOOL, OPERATION_CHAT, OPERATION_OUTPUT_MESSAGES}
)

_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def _require_guid(value: str, name: str) -> str:
    if not _GUID.match(value or ""):
        raise ValueError(f"{name} must be a GUID")
    return value


def traces_url(tenant_id: str, agent_id: str, *, on_behalf_of: bool = False) -> str:
    """Return the Agent 365 OTLP/HTTP traces endpoint for one agent."""
    _require_guid(tenant_id, "tenant_id")
    if not agent_id:
        raise ValueError("agent_id is required")
    service = "observability" if on_behalf_of else "observabilityService"
    agent = urllib.parse.quote(agent_id, safe="")
    return f"{A365_HOST}/{service}/tenants/{tenant_id}/otlp/agents/{agent}/traces?api-version=1"


def eligibility_url(tenant_id: str) -> str:
    """Return the endpoint that reports whether a tenant may ingest traces."""
    _require_guid(tenant_id, "tenant_id")
    return f"{A365_HOST}/observabilityService/tenants/{tenant_id}/eligibility?api-version=1"


@dataclass(frozen=True)
class ExporterSettings:
    """Settings for an OTLP/HTTP span exporter targeting Agent 365."""

    endpoint: str
    headers: dict[str, str]
    scope: str


def otlp_exporter_settings(
    tenant_id: str,
    agent_id: str,
    access_token: str,
    *,
    on_behalf_of: bool = False,
) -> ExporterSettings:
    """Build exporter settings, e.g. for ``OTLPSpanExporter(endpoint=..., headers=...)``.

    Tokens expire; recreate the exporter (or use a header-refreshing session)
    before the token's ``exp``. Acquire the token for :attr:`ExporterSettings.scope`.
    """
    if not access_token:
        raise ValueError("access_token is required")
    return ExporterSettings(
        endpoint=traces_url(tenant_id, agent_id, on_behalf_of=on_behalf_of),
        headers={"Authorization": f"Bearer {access_token}"},
        scope=A365_OBO_SCOPE if on_behalf_of else A365_S2S_SCOPE,
    )


def governance_attributes(
    *,
    allowed: bool,
    reason: str = "",
    policy_id: str | None = None,
    stage: str | None = None,
) -> dict[str, Any]:
    """Return the ``agt.policy.*`` attributes recorded for one decision."""
    attributes: dict[str, Any] = {
        "agt.policy.decision": "allow" if allowed else "deny",
        "agt.policy.reason": reason[:1024],
    }
    if policy_id:
        attributes["agt.policy.id"] = policy_id
    if stage:
        attributes["agt.policy.stage"] = stage
    return attributes


class GovernanceSpanRecorder:
    """Create Agent 365-shaped spans that carry AGT governance decisions.

    Example::

        recorder = GovernanceSpanRecorder(tracer, tenant_id=TENANT, agent_id=AGENT_ID)
        with recorder.invoke_agent(agent_name="claims-agent", conversation_id=cid):
            allowed, reason = gateway.intercept_tool_call(AGENT_ID, "send_mail", args)
            recorder.record_tool_decision("send_mail", allowed=allowed, reason=reason)
    """

    def __init__(self, tracer: Any, *, tenant_id: str, agent_id: str) -> None:
        self._tracer = tracer
        self.tenant_id = _require_guid(tenant_id, "tenant_id")
        self.agent_id = agent_id
        self._root_open = False

    def _base(self, operation: str) -> dict[str, Any]:
        if operation not in ALLOWED_OPERATIONS:
            raise ValueError(f"unsupported gen_ai.operation.name {operation!r}")
        return {
            "gen_ai.operation.name": operation,
            "gen_ai.agent.id": self.agent_id,
            "microsoft.tenant.id": self.tenant_id,
        }

    @contextmanager
    def invoke_agent(
        self,
        *,
        agent_name: str | None = None,
        conversation_id: str | None = None,
        attributes: Mapping[str, Any] | None = None,
    ) -> Iterator[Any]:
        """Open the single root ``invoke_agent`` span for an agent run."""
        if self._root_open:
            raise RuntimeError("an invoke_agent span is already open for this run")
        attrs = self._base(OPERATION_INVOKE_AGENT)
        if agent_name:
            attrs["gen_ai.agent.name"] = agent_name
        if conversation_id:
            attrs["gen_ai.conversation.id"] = conversation_id
        attrs.update(attributes or {})
        name = f"{OPERATION_INVOKE_AGENT} {agent_name}" if agent_name else OPERATION_INVOKE_AGENT
        self._root_open = True
        try:
            with self._tracer.start_as_current_span(name, attributes=attrs) as span:
                yield span
        finally:
            self._root_open = False

    def record_tool_decision(
        self,
        tool_name: str,
        *,
        allowed: bool,
        reason: str = "",
        tool_call_id: str | None = None,
        policy_id: str | None = None,
        stage: str | None = None,
    ) -> None:
        """Record an ``execute_tool`` span for a governed tool call.

        Must be called inside :meth:`invoke_agent`. A denied call ends with an
        error status so that it stands out in Agent 365 views.
        """
        if not self._root_open:
            raise RuntimeError("record_tool_decision must be called inside invoke_agent()")
        attrs = self._base(OPERATION_EXECUTE_TOOL)
        attrs["gen_ai.tool.name"] = tool_name
        if tool_call_id:
            attrs["gen_ai.tool.call.id"] = tool_call_id
        attrs.update(governance_attributes(allowed=allowed, reason=reason, policy_id=policy_id, stage=stage))
        with self._tracer.start_as_current_span(f"{OPERATION_EXECUTE_TOOL} {tool_name}", attributes=attrs) as span:
            if not allowed:
                try:
                    from opentelemetry.trace import Status, StatusCode

                    span.set_status(Status(StatusCode.ERROR, "denied by AGT policy"))
                except ImportError:  # pragma: no cover - OTel API is an install extra
                    pass


def check_eligibility(client: Any, tenant_id: str, access_token: str) -> bool:
    """Return True when the tenant is eligible to ingest Agent 365 traces.

    ``client`` is an ``httpx.Client``. Any non-2xx response is treated as not
    eligible so callers do not silently export into a rejected endpoint.
    """
    response = client.get(
        eligibility_url(tenant_id),
        headers={"Authorization": f"Bearer {access_token}"},
        timeout=10.0,
    )
    if response.status_code // 100 != 2:
        return False
    try:
        body = response.json()
    except ValueError:
        return False
    if isinstance(body, Mapping):
        for key in ("isEligible", "eligible"):
            if isinstance(body.get(key), bool):
                return body[key]
    return False
