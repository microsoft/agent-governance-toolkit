---
title: "A365 + AGT Reference Architecture"
last_reviewed: 2026-11-25
owner: agt-maintainers
---

# A365 + AGT Reference Architecture

> How to augment Microsoft Agent 365 with the Agent Governance Toolkit for comprehensive AI agent security.

## Overview

Microsoft Agent 365 (A365) is the control plane for an organisation's agents: Entra Agent ID identities and blueprints, the agent registry, Purview data security, Defender threat protection, observability and the Tools Gateway for MCP servers. The Agent Governance Toolkit (AGT) is a runtime policy decision point: deterministic, per-action policy evaluation inside or in front of the agent, with audit evidence.

They are complementary. A365 decides *which agents exist, who owns them and what they may reach*; AGT decides *whether this specific action, with these arguments, in this context, may proceed*. The [`agentmesh-agent365`](https://github.com/microsoft/agent-governance-toolkit/tree/main/agent-governance-python/agentmesh-integrations/agent365-agentmesh) package connects the two.

This document describes the integration patterns. Capability descriptions follow Microsoft's public documentation as of the Ignite 2026 wave; several A365 features are in preview, so confirm their status before relying on them.

### What changed at Ignite 2026

| A365 / Microsoft capability | Status | How AGT relates |
|---|---|---|
| Entra Agent ID tokens with agent facets (`xms_act_fct`, `xms_sub_fct`) and blueprint attribution (`xms_par_app_azp`) | Available | AgentMesh relay and registry classify callers as agent, agent-on-behalf-of-user, agent user, user or application, and can require an agent identity (`AGENTMESH_ENTRA_REQUIRE_AGENT_IDENTITY`) |
| Agent 365 observability (direct OTLP ingestion) | Available, licence-gated | `GovernanceSpanRecorder` emits `invoke_agent` / `execute_tool` spans with `agt.policy.*` decision attributes |
| Copilot Studio external threat detection | Preview | `ThreatDetectionHandler` answers `/analyze-tool-execution` with AGT policy, fail-closed within the 1,000 ms window |
| Defender real-time protection for agent tooling | GA | Complementary detection; keep it on alongside AGT policy |
| AI Gateway tool threat protection (Defender + Purview; Disabled / Audit / Block) | Preview | Complementary; AGT adds deterministic organisation policy at the same gateway ([Foundry PDP sample](https://github.com/microsoft/agent-governance-toolkit/blob/main/examples/foundry-ai-gateway-pdp/README.md)) |
| Tools Gateway (bring-your-own MCP servers via the A365 CLI) | Preview | Register the AGT-governed endpoint, not the raw MCP backend |
| Purview `processContent` for agents (`aiAgentInfo`) | Available | `PurviewClient` checks prompts and tool payloads with scope caching |
| MCP `2026-07-28` (stateless, header mirroring, multi round-trip) | Released spec | `MCPGateway.intercept_request` validates envelopes; `intercept_input_required` governs MRTR results |

---

## Architecture at a Glance

```
+------------------------------------------------------------------+
|                    Enterprise Agent Platform                       |
|                                                                    |
|  +---------------------------+  +------------------------------+  |
|  |     Microsoft A365        |  |   Agent Governance Toolkit   |  |
|  |                           |  |                              |  |
|  |  - Entra Agent IDs        |  |  - Per-action policy eval    |  |
|  |  - Conditional Access     |  |  - Intent-based authz        |  |
|  |  - Purview DLP            |  |  - Trust scoring (0-1000)    |  |
|  |  - Defender protection    |  |  - Behavioral anomaly det.   |  |
|  |  - Tools Gateway (MCP)    |  |  - MCP governance gateway    |  |
|  |  - Agent registry         |  |  - Red-team / chaos testing  |  |
|  |  - Observability (OTLP)   |  |  - Kill switch / rings       |  |
|  +---------------------------+  +------------------------------+  |
|                                                                    |
|  +-------------------------------------------------------------+  |
|  |              Shared Observability (OpenTelemetry)            |  |
|  |   A365 observability + Defender + AGT governance telemetry   |  |
|  +-------------------------------------------------------------+  |
+------------------------------------------------------------------+
```

### What Each Layer Handles

| Concern | A365 | AGT | Together |
|---------|------|-----|----------|
| **Identity** | Entra Agent IDs and blueprints, conditional access | Agent DIDs, SPIFFE identity, Ed25519; Entra token verification with agent facet classification | A365 is the identity source; AGT verifies Entra tokens and maps them to fine-grained DIDs |
| **Authorization** | On-behalf-of and app-only access to resources | Per-action policy eval, intent-based authorization | A365 gates access, AGT gates individual actions within that access |
| **Data Protection** | Purview DLP, sensitivity labels, `processContent` for agents | PII detection in tool call params | AGT can call Purview inline and enforce its block decision |
| **Threat Detection** | Defender real-time protection, AI Gateway tool threat protection, Copilot Studio built-in UPIA/XPIA protection | Prompt injection strategies, ring breach detection, behavioral anomaly scoring; Copilot Studio external threat detection provider | Layered: platform detection plus deterministic organisation policy |
| **Security Testing** | Microsoft AI Red Teaming Agent (Foundry) | `agt red-team` CLI (scan, attack, report), chaos engineering | Use both: Foundry for model-level probing, AGT for policy and tool-path testing |
| **Observability** | Agent 365 observability, Defender dashboards | OpenTelemetry traces/metrics/logs | AGT decisions appear as spans in Agent 365 and in your own OTel backend |
| **MCP Governance** | Tools Gateway, MCP server registration | MCP security gateway (runtime policy on every tool call, MCP `2026-07-28` envelope validation) | A365 registers servers, AGT enforces what they can do |
| **Lifecycle** | Agent registry, sponsors, deployment, retirement | CI/CD shift-left scanning (GitHub Action), registry sync | A365 owns lifecycle; AGT suspends bindings when Entra disables an agent |

---

## For CISOs: Why Augmentation Matters

Use AGT on top of A365 where agents take consequential actions:

1. **Intent-based runtime authorization** - A365's conditional access operates at the identity level. AGT adds action-level authorization where agents declare intent before acting, with drift detection when behavior deviates from the plan.

2. **Agent security testing** - Microsoft's AI Red Teaming Agent probes model behaviour. AGT's `agt red-team` CLI adds policy and tool-path testing, adversarial attack simulation and compliance reporting.

3. **Fine-grained, deterministic policy** - Platform protections detect threats probabilistically. AGT evaluates organisation-specific policy per action, per parameter and per context, fails closed, and produces audit evidence.

4. **Cost**: AGT is MIT-licensed and free. No per-user fees on top of existing A365 licensing.

### Risk-Based Adoption

| Agent Criticality | Recommended Stack |
|-------------------|------------------|
| Low (internal tools, simple automation) | A365 alone is sufficient |
| Medium (customer-facing, handles PII) | A365 + AGT policy enforcement + trust scoring |
| High (financial transactions, healthcare, regulated) | A365 + AGT full stack (intent auth, red-team, rings, kill switch) |
| Multi-agent orchestration | A365 + AGT multi-agent policy evaluation |

---

## For Platform Engineers: Integration Patterns

### Pattern 1: .NET Extension (Shipping Today)

The simplest integration. Wrap any Microsoft Agent Framework agent with AGT governance middleware.

```bash
dotnet add package Microsoft.AgentGovernance.Extensions.Microsoft.Agents
```

```csharp
using Microsoft.AgentGovernance.Extensions.Microsoft.Agents;

// Wrap your existing agent with governance
var governedAgent = agent.WithGovernance(options =>
{
    options.PolicyPath = "policies/";
    options.EnableTrustScoring = true;
    options.EnableAuditLog = true;
});
```

**What this gives you:**
- Policy evaluation on every function invocation
- Audit events for compliance
- Blocked responses on policy deny
- Trust scoring per agent session

**Tutorial**: See Tutorial 34 for end-to-end walkthrough.

### Pattern 2: MCP Governance Gateway behind the Tools Gateway

The A365 Tools Gateway registers MCP servers (including bring-your-own servers added with the A365 CLI, in preview) and can connect through Azure AI Gateway. Register the URL of an AGT-governed MCP gateway, not the raw backend, so every tool call passes AGT policy.

```
Agent -> A365 Tools Gateway -> AGT MCP gateway -> MCP Server
                                     |
                               Policy Engine
                               (per-call eval)
```

**What this gives you:**
- A365 manages which MCP servers are available
- AGT governs what those servers can do per call
- MCP `2026-07-28` envelope validation: `Mcp-Method` / `Mcp-Name` / `Mcp-Param-*` headers must match the body (`MCPGateway.intercept_request`)
- Governance of multi round-trip `input_required` results: sampling and roots denied by default, URL elicitation needs approval (`MCPGateway.intercept_input_required`)
- Tool poisoning detection, parameter-level policy, credential redaction in responses

See [MCP Security Gateway](tutorials/07-mcp-security-gateway.md).

### Pattern 3: Agent 365 Observability

Emit AGT decisions as spans that Agent 365 ingests next to the agent's own telemetry.

```python
from agentmesh_agent365 import GovernanceSpanRecorder, otlp_exporter_settings

settings = otlp_exporter_settings(TENANT_ID, AGENT_ID, token)  # OTLP/HTTP endpoint + auth header
recorder = GovernanceSpanRecorder(tracer, tenant_id=TENANT_ID, agent_id=AGENT_ID)
with recorder.invoke_agent(agent_name="claims-agent"):
    allowed, reason = gateway.intercept_tool_call(AGENT_ID, "send_mail", args)
    recorder.record_tool_decision("send_mail", allowed=allowed, reason=reason)
```

Agent 365 requires one root `invoke_agent` span per run, `gen_ai.operation.name` from `invoke_agent` / `execute_tool` / `chat` / `output_messages`, and a `microsoft.tenant.id` matching the endpoint tenant; ingestion needs an Agent 365 or Microsoft 365 E7 licence. AGT also emits OpenTelemetry to any other backend (Azure Monitor, Datadog, Splunk, Grafana and others).

### Pattern 4: Copilot Studio External Threat Detection

Copilot Studio calls an external threat detection service before each tool call of a generative agent. Answer it with AGT policy:

```python
from agentmesh_agent365 import ThreatDetectionHandler, create_app, gateway_decider

app = create_app(
    ThreatDetectionHandler(gateway_decider(gateway)),
    verify_token=EntraTokenVerifier(EntraVerifierConfig.from_env()).verify,
    allowed_client_ids={COPILOT_STUDIO_CALLER_APP_ID},
)
```

Copilot Studio **allows** the tool call when no answer arrives within 1,000 ms. The handler decides within a 700 ms budget and answers `blockAction: true` on timeout, error or malformed input; an unreachable service remains fail-open by platform design, so monitor its availability.

### Pattern 5: Entra Agent ID verification and registry sync

Set `AGENTMESH_ENTRA_AUDIENCE` and `AGENTMESH_ENTRA_TENANT_ID` to verify Entra-signed tokens at the AgentMesh relay and registry. The verifier classifies the caller from the agent facet claims and logs the blueprint; set `AGENTMESH_ENTRA_REQUIRE_AGENT_IDENTITY=true` to reject users and plain applications. Use `EntraRegistrySync` to suspend AGT bindings whose Entra agent identity was disabled. See [Entra Agent ID bridge](tutorials/31-entra-agent-id-bridge.md).

### Pattern 6: Purview inline checks

`PurviewClient.check_text()` calls Purview `processContent` with the agent attributed (`aiAgentInfo`) and blocks when policy returns a `restrictAccess` block action. Scopes are cached per user and refreshed when Purview reports a policy change; Graph errors block by default.

### Pattern 7: Shift-Left CI/CD + A365 Lifecycle

AGT's GitHub Action scans agent code pre-deployment. A365 manages the agent post-deployment. Full SDLC coverage.

```yaml
# .github/workflows/agent-governance.yml
- uses: microsoft/agent-governance-toolkit/actions/scan@v3
  with:
    policy-path: policies/
    fail-on-violation: true
```

**What this catches pre-deployment:**
- Policy violations in agent configuration
- Prompt injection vulnerabilities
- Missing capability restrictions
- Overly broad tool permissions

---

## For Product Teams: Complementary Capabilities

### Where A365 Leads

- **Entra identity management** - agent registration, lifecycle, suspension
- **Microsoft ecosystem integration** - Teams, Copilot, Power Platform agents
- **Purview compliance** - DLP, sensitivity labels, data residency
- **Enterprise deployment** - agent catalog, approval workflows

### Where AGT Leads

- **Sub-millisecond policy enforcement** - <0.1ms per evaluation, 47K ops/sec
- **Intent-based authorization** - agents declare plans before acting, drift detection
- **Multi-agent governance** - inter-agent policy evaluation, trust propagation
- **Security testing** - `agt red-team` CLI with automated scanning and attack simulation
- **4-tier execution rings** - hardware-inspired isolation (Ring 0-3)
- **Kill switch** - deterministic agent termination with audit trail
- **Framework-agnostic** - works with LangChain, AutoGen, CrewAI, Semantic Kernel, PydanticAI, and 16 more
- **21 integration packages** - not limited to the Microsoft agent ecosystem

### Where They Overlap (and How to Reconcile)

| Overlap Area | Resolution |
|-------------|-----------|
| Threat detection | Defender and AI Gateway tool threat protection detect threats; AGT enforces deterministic policy and can be the Copilot Studio external threat detection provider. Use both. |
| Authorization | A365 conditional access gates identity-level access. AGT gates action-level authorization within that access. Layered, not redundant. |
| Audit logging | Send AGT decisions to Agent 365 observability and to your own backend via OpenTelemetry. |

---

## Deployment Checklist

For teams adding AGT to an A365-managed environment:

- [ ] Install AGT Python SDK: `pip install agent-compliance`
- [ ] Define policies in `policies/` directory (YAML format)
- [ ] For .NET agents: add `Microsoft.AgentGovernance.Extensions.Microsoft.Agents` NuGet package
- [ ] Configure OpenTelemetry export to your observability backend
- [ ] For Agent 365 observability: confirm tenant eligibility and export AGT spans with `agentmesh-agent365`
- [ ] For Copilot Studio agents: register the AGT threat detection endpoint and monitor its availability
- [ ] Enable Entra token verification on the AgentMesh relay/registry; consider `AGENTMESH_ENTRA_REQUIRE_AGENT_IDENTITY=true`
- [ ] Register AGT-governed MCP endpoints (not raw backends) in the A365 Tools Gateway
- [ ] Add `agt scan` to CI/CD pipeline (GitHub Action or CLI)
- [ ] Run `agt red-team scan` against each agent before production deployment
- [ ] Set up trust score thresholds and alert webhooks
- [ ] For multi-agent: configure AgentMesh router with inter-agent policies

---

## Performance Impact

Adding AGT to an A365-governed agent adds minimal overhead:

| Metric | Value |
|--------|-------|
| Policy evaluation latency | <0.1ms per action |
| Throughput | 47,000 ops/sec at 1,000 concurrent agents |
| Trust score computation | <0.05ms |
| Memory overhead | ~15MB per agent instance |
| Network overhead | Zero (all evaluation is local, telemetry is async) |

---

## Further Reading

- [AGT Architecture](ARCHITECTURE.md)
- [`agentmesh-agent365` integration package](https://github.com/microsoft/agent-governance-toolkit/blob/main/agent-governance-python/agentmesh-integrations/agent365-agentmesh/README.md)
- [Foundry AI Gateway PDP sample](https://github.com/microsoft/agent-governance-toolkit/blob/main/examples/foundry-ai-gateway-pdp/README.md)
- [Tutorial 31: Entra Agent ID Bridge](tutorials/31-entra-agent-id-bridge.md)
- [Tutorial 34: Microsoft Agent Framework Integration](tutorials/34-maf-integration.md)
- [Tutorial 45: CI/CD Shift-Left Scanning](tutorials/45-shift-left-governance.md)
- [Tutorial 47: Red-Team Testing](tutorials/47-red-team-testing.md)
- [OWASP Agentic Top 10 Compliance](./compliance/owasp-agentic-top10-architecture.md)
- [Benchmarks](BENCHMARKS.md)
