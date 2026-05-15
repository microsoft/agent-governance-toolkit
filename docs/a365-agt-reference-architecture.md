# A365 + AGT Reference Architecture

> How to augment Microsoft Agent 365 with the Agent Governance Toolkit for comprehensive AI agent security.

## Overview

Microsoft Agent 365 (A365) provides foundational agent lifecycle management: Entra-based identity, Purview DLP integration, and Defender threat signals. However, industry analysts consistently identify gaps in fine-grained runtime authorization, agent security testing, and advanced observability for mission-critical deployments.

The Agent Governance Toolkit (AGT) provides the runtime governance layer that complements A365. Together they cover the full agent security stack: A365 manages identity and lifecycle, AGT enforces per-action policies and behavioral governance.

This document describes how they work together across three deployment patterns.

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
|  |  - Defender signals       |  |  - Behavioral anomaly det.   |  |
|  |  - MCP server registry    |  |  - MCP governance proxy      |  |
|  |  - Agent lifecycle mgmt   |  |  - Red-team / chaos testing  |  |
|  |  - JIT authorization      |  |  - Kill switch / rings       |  |
|  +---------------------------+  +------------------------------+  |
|                                                                    |
|  +-------------------------------------------------------------+  |
|  |              Shared Observability (OpenTelemetry)            |  |
|  |    A365 Defender signals + AGT governance telemetry          |  |
|  +-------------------------------------------------------------+  |
+------------------------------------------------------------------+
```

### What Each Layer Handles

| Concern | A365 | AGT | Together |
|---------|------|-----|----------|
| **Identity** | Entra Agent IDs, conditional access | Agent DIDs, SPIFFE identity, Ed25519 | A365 manages identity source, AGT maps to fine-grained DIDs |
| **Authorization** | JIT on-behalf-of authorization | Per-action policy eval, intent-based authorization | A365 gates access, AGT gates individual actions within that access |
| **Data Protection** | Purview DLP, sensitivity labels | PII detection in tool call params | Layered protection at data and action level |
| **Threat Detection** | Defender for Cloud signals | 7 prompt injection strategies, ring breach detection, behavioral anomaly scoring | A365 catches infra threats, AGT catches agent-level threats |
| **Security Testing** | N/A | `agt red-team` CLI (scan, attack, report), chaos engineering | AGT fills the gap |
| **Observability** | Defender dashboards | OpenTelemetry traces/metrics/logs, 11 platform integrations | Unified observability via shared OTel backends |
| **MCP Governance** | MCP server registry | MCP Governance Proxy (runtime policy on every tool call) | A365 registers servers, AGT enforces what they can do |
| **Lifecycle** | Agent deployment, updates, retirement | CI/CD shift-left scanning (GitHub Action) | A365 manages runtime lifecycle, AGT catches issues pre-deployment |

---

## For CISOs: Why Augmentation Matters

Industry analysis consistently recommends augmenting A365 with third-party or open-source agent security platforms for mission-critical deployments. The rationale:

1. **Intent-based runtime authorization** - A365's conditional access operates at the identity level. AGT adds action-level authorization where agents declare intent before acting, with drift detection when behavior deviates from the plan.

2. **Agent security testing** - No built-in red-team tooling in A365. AGT's `agt red-team` CLI provides automated security scanning, adversarial attack simulation, and compliance reporting.

3. **Fine-grained policy enforcement** - A365 provides broad allow/deny via conditional access. AGT evaluates policies per action, per parameter, per context, at sub-millisecond latency (<0.1ms, 47K ops/sec).

4. **Cost**: AGT is MIT-licensed and free. No per-user fees on top of existing A365 licensing. No vendor lock-in, no acquisition risk.

### Risk-Based Adoption

| Agent Criticality | Recommended Stack |
|-------------------|------------------|
| Low (internal tools, simple automation) | A365 alone is sufficient |
| Medium (customer-facing, handles PII) | A365 + AGT policy enforcement + trust scoring |
| High (financial transactions, healthcare, regulated) | A365 + AGT full stack (intent auth, red-team, rings, kill switch) |
| Multi-agent orchestration | A365 + AGT (only AGT provides multi-agent policy evaluation today) |

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

### Pattern 2: MCP Governance Proxy

A365 GA introduced an MCP server management pane for registering and managing MCP servers. AGT's MCP Governance Proxy sits between the agent and MCP servers, enforcing runtime policies on every tool call.

```
Agent -> A365 MCP Registry -> AGT MCP Proxy -> MCP Server
                                    |
                              Policy Engine
                              (per-call eval)
```

**What this gives you:**
- A365 manages which MCP servers are available
- AGT governs what those servers can do per call
- Tool poisoning detection (7 strategies)
- Parameter-level policy enforcement
- Credential redaction in MCP responses

### Pattern 3: OpenTelemetry Unified Observability

Route AGT governance telemetry into the same backends as A365 Defender signals. Single pane of glass for security operations.

```python
from agent_os import StatelessKernel

kernel = StatelessKernel(
    enable_tracing=True,  # Emits OTel spans
)
```

AGT emits OpenTelemetry traces for:
- Every policy evaluation (action, result, latency)
- Trust score changes (agent_id, old_score, new_score, reason)
- Intent lifecycle events (declare, approve, drift, verify)
- Kill switch activations
- Ring breach detections

**Supported backends**: Azure Monitor, Datadog, Splunk, Grafana, New Relic, Elastic, Jaeger, Zipkin, Prometheus, AWS CloudWatch, GCP Cloud Trace.

### Pattern 4: Shift-Left CI/CD + A365 Lifecycle

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
- **Framework-agnostic** - works with LangChain, AutoGen, CrewAI, Semantic Kernel, PydanticAI, and 14 more
- **19 framework integrations** - not limited to the Microsoft agent ecosystem

### Where They Overlap (and How to Reconcile)

| Overlap Area | Resolution |
|-------------|-----------|
| Threat detection | A365 Defender catches infrastructure threats, AGT catches agent-behavioral threats. Use both. |
| Authorization | A365 conditional access gates identity-level access. AGT gates action-level authorization within that access. Layered, not redundant. |
| Audit logging | Route both to the same backend via OpenTelemetry for unified audit. |

---

## Deployment Checklist

For teams adding AGT to an A365-managed environment:

- [ ] Install AGT Python SDK: `pip install agent-compliance`
- [ ] Define policies in `policies/` directory (YAML format)
- [ ] For .NET agents: add `Microsoft.AgentGovernance.Extensions.Microsoft.Agents` NuGet package
- [ ] Configure OpenTelemetry export to your observability backend
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
- [Tutorial 34: Microsoft Agent Framework Integration](tutorials/34-microsoft-agents-integration.md)
- [Tutorial 45: CI/CD Shift-Left Scanning](tutorials/45-cicd-governance.md)
- [Tutorial 47: Red-Team Testing](tutorials/47-red-team-testing.md)
- [OWASP Agentic Top 10 Compliance](OWASP-COMPLIANCE.md)
- [Benchmarks](BENCHMARKS.md)
