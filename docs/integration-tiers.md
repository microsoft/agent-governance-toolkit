# Integration Tiers: What You Get at Each Depth

This document explains what governance capabilities are available at each
level of integration with the Agent Governance Toolkit. Not every deployment
requires source code changes. Understanding the tiers helps platform teams,
security architects, and agent developers decide how deeply to integrate.

---

## Why This Matters

A managed agent hosting platform evaluating AGT needs to know: what security
controls can be deployed as infrastructure (sidecar, proxy, config) without
touching agent code? What requires the agent developer to import an SDK?
What needs deep runtime hooks?

The OWASP ASI and LLM Top 10 mappings in this repo document *what* AGT
mitigates. This document documents *how* you get each mitigation and what
integration effort it requires.

---

## The Three Tiers

| Tier | Integration Effort | Who Does the Work |
|------|-------------------|-------------------|
| **Tier 0: Sidecar / Proxy / CLI** | Zero app code changes. Deploy a container, mount a policy YAML, call HTTP endpoints. | Platform / infra team |
| **Tier 1: SDK Init** | Import the SDK, initialize a few classes, call them at key points in your agent loop. 10-50 lines of code. | Agent developer |
| **Tier 2: Deep Integration** | Wire middleware pipelines, decorators, behavior monitors, memory guards into your agent runtime. 100+ lines, framework-specific. | Agent developer + platform team |

---

## Tier 0: Sidecar / Proxy / CLI (No Code Changes)

Deploy the governance sidecar as a container alongside your agent. The agent
(or an API gateway / service mesh in front of it) calls the sidecar HTTP API
before executing tool calls. No changes to agent source code are required,
but the orchestration layer must route requests through the sidecar.

### What you get

| Capability | How | Endpoint / Tool |
|---|---|---|
| **Prompt injection detection** | HTTP call before passing input to agent | `POST /api/v1/detect/injection` |
| **Policy check (allow/deny)** | HTTP call before executing a tool | `POST /api/v1/execute` |
| **Blocked pattern matching** | Loaded from policy YAML ConfigMap at startup | Policy YAML `blocked_patterns` |
| **MCP tool scanning (static)** | CLI scan of MCP server configs | `agent-os mcp-scan` CLI |
| **Health / readiness probes** | Kubernetes liveness/readiness | `GET /health`, `GET /ready` |
| **Governance metrics** | Prometheus-compatible scrape target | `GET /api/v1/metrics` |
| **MCP allowlist enforcement** | Config-driven MCP server allowlist | Policy YAML `allowed_tools` |

### What you do NOT get

- **No transparent interception.** The sidecar does not automatically
  intercept tool calls. Your orchestration layer or service mesh must
  explicitly call the sidecar API. This is a deliberate design choice
  (the sidecar is a mediation layer, not a network proxy), but it means
  an agent that bypasses the orchestration layer bypasses governance too.
- **No trust scoring or agent identity.** DID-based identity, trust
  decay, and agent-to-agent handshake verification require SDK-level
  integration.
- **No tamper-evident audit trail.** The hash-chain audit log requires
  the SDK to instrument the agent's execution pipeline.
- **No behavior monitoring.** Anomaly detection, quarantine, and kill
  switch require runtime hooks.
- **No output redaction.** PII scrubbing of agent responses requires
  the SDK in the response path.

### Deployment example

```yaml
# docker-compose.yaml (simplified)
services:
  agent:
    image: your-agent:latest
    ports: ["8080:8080"]
  governance-sidecar:
    image: ghcr.io/microsoft/agentmesh/governance:latest
    ports: ["8081:8081"]
    volumes:
      - ./policy.yaml:/app/policy.yaml
    environment:
      - POLICY_PATH=/app/policy.yaml
```

### OWASP coverage at Tier 0

| OWASP ASI Risk | Tier 0 Coverage | Notes |
|---|---|---|
| ASI01 Goal Hijack | ⚠️ Partial | Blocked patterns via sidecar, but only if orchestration routes through it |
| ASI02 Tool Misuse | ⚠️ Partial | Allow/deny list via policy YAML, but enforcement depends on orchestration calling sidecar |
| ASI03 Identity Abuse | ❌ None | Requires SDK trust/identity stack |
| ASI04 Supply Chain | ⚠️ Partial | Static MCP scanning via CLI, no runtime enforcement |
| ASI05 Code Execution | ❌ None | Requires SDK rings/sandbox integration |
| ASI06 Memory & Context Poisoning | ❌ None | Requires deep runtime integration |
| ASI07 Inter-Agent Comms | ❌ None | Requires SDK trust gate |
| ASI08 Cascading Agent Failures | ❌ None | Circuit breaker requires SDK wiring |
| ASI09 Human-Agent Trust | ⚠️ Partial | Audit via metrics endpoint, no attribution |
| ASI10 Rogue Agents | ❌ None | Requires behavior monitor in runtime |
| ASI11 Untraceability | ⚠️ Partial | Request-level logging via sidecar, no hash-chain |

**Honest assessment: ~3/11 partial coverage. Tier 0 catches obvious prompt
injection and enforces tool allowlists, but cannot enforce identity, trust,
behavior monitoring, or tamper-evident auditing.**

---

## Tier 1: SDK Init (Thin Wrapper)

Import the AGT SDK into your agent code. Initialize the core classes and
call them at the key decision points in your agent loop: before processing
input, before executing tools, and after getting results.

### What you add on top of Tier 0

| Capability | SDK Class | Integration Point |
|---|---|---|
| **Trust scoring with decay** | `TrustManager` | Call at agent-to-agent handoff |
| **DID-based agent identity** | `AgentIdentity` | Initialize at agent startup |
| **Policy evaluation (programmatic)** | `PolicyEvaluator` | Call before tool execution |
| **MCP session authentication** | `MCPSessionAuthenticator` | Wrap MCP client connections |
| **Credential redaction** | `CredentialRedactor` | Call on tool outputs |
| **Tamper-evident audit log** | `AuditLogger` (hash-chain) | Call after each action |
| **Token budget tracking** | `TokenBudgetTracker` | Call before LLM requests |
| **Rate limiting** | `RateLimiter` | Call before tool execution |

### Code example (Python)

```python
from agent_os import PolicyEvaluator, AuditLogger
from agentmesh import TrustManager

# Initialize once
policy = PolicyEvaluator.from_yaml("policy.yaml")
audit = AuditLogger(chain=True)
trust = TrustManager()

# In your agent loop
def handle_tool_call(tool_name, params, agent_did):
    # Trust check
    score = trust.evaluate(agent_did)
    if score < policy.trust_threshold:
        audit.log("deny", tool=tool_name, reason="trust_below_threshold")
        return deny()

    # Policy check
    decision = policy.evaluate(tool_name, params)
    if not decision.allowed:
        audit.log("deny", tool=tool_name, reason=decision.reason)
        return deny()

    # Execute and audit
    result = execute_tool(tool_name, params)
    audit.log("allow", tool=tool_name, result_hash=hash(result))
    return result
```

### OWASP coverage at Tier 1

| OWASP ASI Risk | Tier 1 Coverage | What Changed |
|---|---|---|
| ASI01 Goal Hijack | ✅ Full | Injection detection in agent loop |
| ASI02 Tool Misuse | ✅ Full | Programmatic policy enforcement |
| ASI03 Identity Abuse | ✅ Full | DID identity + trust scoring |
| ASI04 Supply Chain | ⚠️ Partial | Tool pinning + MCP scanning, no SBOM |
| ASI05 Code Execution | ⚠️ Partial | Rate limiting + token budgets, no sandbox |
| ASI06 Memory & Context Poisoning | ❌ None | Still requires deep integration |
| ASI07 Inter-Agent Comms | ✅ Full | Trust gate with DID verification |
| ASI08 Cascading Agent Failures | ✅ Full | Circuit breaker + rate limiter wired |
| ASI09 Human-Agent Trust | ⚠️ Partial | Audit trail, no UI-level guardrails |
| ASI10 Rogue Agents | ⚠️ Partial | Audit logging, no behavior monitoring |
| ASI11 Untraceability | ✅ Full | Hash-chain audit log |

**Honest assessment: ~6/11 full coverage. The SDK integration closes the
identity, trust, and audit gaps that Tier 0 cannot reach.**

---

## Tier 2: Deep Integration (Full Runtime)

Wire AGT into your agent framework's middleware pipeline. This gives you
the complete governance surface including behavior monitoring, execution
rings, memory guards, and framework-specific adapters.

### What you add on top of Tier 1

| Capability | SDK Class | Integration Point |
|---|---|---|
| **Behavior monitoring + quarantine** | `AgentBehaviorMonitor` | Wrap agent lifecycle |
| **Execution rings (privilege levels)** | `ExecutionRing` | Decorate tool handlers |
| **Kill switch** | `KillSwitch` | Register shutdown hook |
| **Governance middleware pipeline** | `GovernanceMiddleware` | Framework adapter |
| **Output drift detection** | `DriftDetector` | Post-execution hook |
| **Memory/context integrity** | `MemoryGuard` | Wrap memory store |
| **Rogue agent detection** | `RogueDetector` | Background monitor |
| **Framework adapters** | LangChain, SK, CrewAI, ADK, AutoGen | Framework-specific wiring |
| **MCP gateway (5-stage pipeline)** | `MCPGateway` | MCP server wrapper |

### OWASP coverage at Tier 2

| OWASP ASI Risk | Tier 2 Coverage | What Changed |
|---|---|---|
| ASI01 Goal Hijack | ✅ Full | + middleware pipeline enforcement |
| ASI02 Tool Misuse | ✅ Full | + execution rings |
| ASI03 Identity Abuse | ✅ Full | (same as Tier 1) |
| ASI04 Supply Chain | ⚠️ Partial | + SBOM scanning, still no dep vuln DB |
| ASI05 Code Execution | ✅ Full | Execution rings + sandbox |
| ASI06 Memory & Context Poisoning | ⚠️ Partial | MemoryGuard, no full memory sandbox |
| ASI07 Inter-Agent Comms | ✅ Full | (same as Tier 1) |
| ASI08 Cascading Agent Failures | ✅ Full | + kill switch + rogue detection |
| ASI09 Human-Agent Trust | ⚠️ Partial | + audit attribution, no UI guardrails |
| ASI10 Rogue Agents | ✅ Full | Behavior monitor + quarantine |
| ASI11 Untraceability | ✅ Full | (same as Tier 1) |

**Honest assessment: ~8/11 full coverage, 3/11 partial. The remaining
gaps (supply chain SBOM depth, memory sandboxing, UI-level human
guardrails) are documented in the OWASP mapping.**

---

## Decision Guide

| If you are... | Start with | Then consider |
|---|---|---|
| **Managed platform team** evaluating AGT for a hosting service | Tier 0 sidecar | Tier 1 SDK for trust + identity |
| **Agent developer** building a new agent | Tier 1 SDK | Tier 2 if you need behavior monitoring |
| **Security team** running a compliance assessment | Tier 2 (full) | Tier 0 + Tier 1 may satisfy specific controls |
| **Doing a quick POC** | Tier 0 sidecar + CLI | Low effort, shows value fast |

---

## Relationship to OWASP Mappings

The detailed OWASP mappings in this repo document mitigation mechanisms
and code evidence:

- [OWASP ASI 2026 mapping](compliance/owasp-agentic-top10-architecture.md) (11 agentic risks)
- [OWASP LLM Top 10 mapping](compliance/owasp-llm-top10-mapping.md) (10 LLM risks)
- [MCP OWASP mapping](compliance/mcp-owasp-top10-mapping.md) (MCP-specific risks)

Those documents describe *what* AGT mitigates. This document describes
*how much integration effort* each mitigation requires. Read them together.

---

## Known Limitations

1. **Transparent interception is not implemented.** The sidecar requires
   explicit API calls from the orchestration layer. A service mesh
   integration (Istio, Envoy) that intercepts tool-call traffic
   transparently is on the roadmap but not shipped.

2. **Detection without enforcement.** Several detection modules
   (`PromptInjectionDetector`, `TokenBudgetTracker`, `RateLimiter`,
   `ScopeGuard`, `SupplyChainGuard`) exist as standalone utilities but
   are not auto-wired into the `BaseIntegration` lifecycle. They require
   explicit SDK integration to enforce. See the
   [LLM Top 10 mapping](compliance/owasp-llm-top10-mapping.md#cross-cutting-finding-detection-without-enforcement)
   for details.

3. **Framework adapter coverage varies.** The MAF/Semantic Kernel adapter
   has the deepest enforcement wiring. Other framework adapters may
   require manual wiring for some Tier 2 capabilities.
