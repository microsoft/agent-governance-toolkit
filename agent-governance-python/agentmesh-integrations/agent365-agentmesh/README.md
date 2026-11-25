# agentmesh-agent365

Bridge between the Agent Governance Toolkit (AGT) and **Microsoft Agent 365**
(A365). AGT stays the policy decision point; Agent 365, Copilot Studio,
Microsoft Purview and Microsoft Entra Agent ID stay the systems of record for
the agent estate.

> **Community extension, alpha.** Interfaces follow the public Microsoft
> documentation as of the Ignite 2026 wave. Several of the underlying Microsoft
> services are in preview; check their current status before production use.

| Module | Microsoft surface | What it does |
|---|---|---|
| `observability` | Agent 365 OTLP traces endpoint | Emits `invoke_agent` / `execute_tool` spans with `agt.policy.*` attributes; builds endpoint, scope and exporter settings; checks tenant eligibility |
| `threat_detection` | Copilot Studio external threat detection (`/validate`, `/analyze-tool-execution`, API version `2025-05-01`) | Runs AGT policy for each tool call a Copilot Studio agent plans, under a 700 ms budget, and fails closed |
| `purview` | Microsoft Graph `protectionScopes/compute` + `processContent` | Checks prompts and tool payloads against Purview DLP with ETag-aware scope caching |
| `registry_sync` | Microsoft Graph `servicePrincipals/microsoft.graph.agentIdentity` | Suspends AGT bindings when the Entra agent identity is disabled; reports drift |

## Install

```bash
pip install -e "agent-governance-python/agentmesh-integrations/agent365-agentmesh[otel,server]"
```

`httpx` is the only required dependency. `otel` adds the OpenTelemetry API and
`server` adds FastAPI for the threat detection endpoint.

## Copilot Studio threat detection backed by AGT policy

```python
from agent_os.mcp_gateway import MCPGateway
from agentmesh.identity.entra_verifier import EntraTokenVerifier, EntraVerifierConfig
from agentmesh_agent365 import ThreatDetectionHandler, create_app, gateway_decider

gateway = MCPGateway(runtime, denied_tools=["Delete records"], sensitive_tools=["Send email"])
# AGENTMESH_ENTRA_AUDIENCE must be the API scope base URL, e.g. https://security.contoso.com
verifier = EntraTokenVerifier(EntraVerifierConfig.from_env())

app = create_app(
    ThreatDetectionHandler(gateway_decider(gateway)),
    verify_token=verifier.verify,
    allowed_client_ids={COPILOT_STUDIO_CALLER_APP_ID},
)
```

`gateway_decider` sends each planned tool call through the AGT MCP gateway:
deny lists, parameter sanitization, the ACS policy runtime, approvals and the
per-agent call budget all apply, and every decision is audited. Tools that
need human approval are **blocked**, because Copilot Studio cannot wait for an
approval.

**Latency and failure semantics.** Copilot Studio allows the tool call if the
service does not answer within 1,000 ms. The handler evaluates under an
internal budget (`budget_ms`, default 700) and answers `blockAction: true` on
timeout, error or a malformed request. If the service cannot answer at all
(network failure, host down), Copilot Studio proceeds — monitor availability
and pair this control with Microsoft Defender real-time protection.

Register the endpoint in the Power Platform admin center or Copilot Studio as
described in [Enable external threat detection for Copilot Studio
agents](https://learn.microsoft.com/microsoft-copilot-studio/external-security-provider).
Expose the API scope as the base URL of the service, as the Copilot Studio
contract requires.

## Agent 365 observability

```python
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
from agentmesh_agent365 import GovernanceSpanRecorder, otlp_exporter_settings

settings = otlp_exporter_settings(TENANT, AGENT_ID, token)  # token for settings.scope
exporter = OTLPSpanExporter(endpoint=settings.endpoint, headers=settings.headers)

recorder = GovernanceSpanRecorder(tracer, tenant_id=TENANT, agent_id=AGENT_ID)
with recorder.invoke_agent(agent_name="claims-agent", conversation_id=conversation_id):
    allowed, reason = gateway.intercept_tool_call(AGENT_ID, "send_mail", args)
    recorder.record_tool_decision("send_mail", allowed=allowed, reason=reason)
```

Agent 365 requires exactly one root `invoke_agent` span per run,
`gen_ai.operation.name` values from `invoke_agent`, `execute_tool`, `chat` and
`output_messages`, and a `microsoft.tenant.id` that matches the URL tenant.
The recorder enforces these. Ingestion needs an Agent 365 or Microsoft 365 E7
licence; `check_eligibility` treats any unrecognised response as *not
eligible*. App-only tokens use `A365_S2S_SCOPE`; on-behalf-of tokens use
`A365_OBO_SCOPE` and the `/observability/` path. Tokens expire, so recreate the
exporter before `exp`.

## Purview DLP

```python
from agentmesh_agent365 import AgentInfo, PurviewClient

purview = PurviewClient(httpx.Client(), get_graph_token, app_id=APP_ID, app_name="Claims agent")
verdict = purview.check_text(user_object_id, prompt, agent=AgentInfo(AGENT_ID, "Claims agent", blueprint_id=BLUEPRINT_ID))
if verdict.blocked:
    ...
```

The client computes protection scopes once per user, sends the cached `ETag`
as `If-None-Match`, and refreshes the scopes when Purview reports
`protectionScopeState: modified`. It calls `processContent` only when a scope
covers the activity with inline evaluation. Graph errors **block** unless you
pass `fail_closed=False`.

## Entra Agent ID registry sync

```python
from agentmesh.identity.entra import EntraAgentRegistry
from agentmesh_agent365 import EntraRegistrySync, iter_agent_identities

syncer = EntraRegistrySync(registry, did_for=lambda identity: did_by_object_id.get(identity["id"]))
report = syncer.sync(iter_agent_identities(httpx.Client(), get_graph_token))
```

An identity disabled in Entra is suspended in AGT; it is reactivated only if
this syncer suspended it. AgentMesh DIDs derive from agent keys, so you supply
`did_for`; identities without a mapping are reported in `report.unmapped`
rather than assigned an invented DID. Bindings whose Entra identity no longer
exists are listed in `report.missing_in_entra`.

## Foundry guardrails and ACS intervention points

Microsoft Foundry guardrails and AGT evaluate at matching points. Use both:
Foundry for model-level content safety, AGT for deterministic policy.

| Foundry guardrail intervention point | ACS intervention point |
|---|---|
| User input | `input` |
| Tool call (preview) | `pre_tool_call` |
| Tool response (preview) | `post_tool_call` |
| Output | `output` |

## Tests

```bash
pip install -e ".[dev]"
pytest
```

Tests use `httpx.MockTransport`, the OpenTelemetry in-memory exporter and
FastAPI's test client; they make no network calls. Tests that use the real
`MCPGateway` and `EntraAgentRegistry` are skipped when those packages are not
installed.

## Related documentation

- [Agent 365 + AGT reference architecture](../../../docs/a365-agt-reference-architecture.md)
- [Entra Agent ID bridge tutorial](../../../docs/tutorials/31-entra-agent-id-bridge.md)
- [SECURITY.md](SECURITY.md)
