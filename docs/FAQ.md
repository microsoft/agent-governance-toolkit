<!-- Copyright (c) Microsoft Corporation. Licensed under the MIT License. -->

# Frequently Asked Questions

Technical Q&A for customers, partners, and evaluators of the Agent Governance
Toolkit.

> **See also:** [Quick Start](../QUICKSTART.md) · [Architecture](ARCHITECTURE.md) · [Known Limitations](LIMITATIONS.md) · [OWASP Compliance](OWASP-COMPLIANCE.md)

---

## Table of Contents

1. [What is the relationship between AGT and the Foundry Control Plane?](#1-what-is-the-relationship-between-agt-and-the-foundry-control-plane)
2. [Is the Agent Mesh sidecar only intercepting network-related agent actions?](#2-is-the-agent-mesh-sidecar-only-intercepting-network-related-agent-actions)
3. [What is the practical impact of the different SDK integration types?](#3-what-is-the-practical-impact-of-the-different-sdk-integration-types)
4. [How many SDKs are actually supported — 12 or 6?](#4-how-many-sdks-are-actually-supported--12-or-6)
5. [Can an agent identity be linked to Entra IDs?](#5-can-an-agent-identity-be-linked-to-entra-ids)
6. [If I update a policy at runtime, do I need to restart the agent?](#6-if-i-update-a-policy-at-runtime-do-i-need-to-restart-the-agent)
7. [What is the Microsoft product integration roadmap?](#7-what-is-the-microsoft-product-integration-roadmap)
8. [How does Agent Mesh Runtime interact with Agent Mesh and the Sidecar?](#8-how-does-agent-mesh-runtime-interact-with-agent-mesh-and-the-sidecar)
9. [How does Agent Mesh govern authentications to internal and external resources?](#9-how-does-agent-mesh-govern-authentications-to-internal-and-external-resources)
10. [What is the difference between agent-hypervisor and agent-runtime?](#10-what-is-the-difference-between-agent-hypervisor-and-agent-runtime)

---

## 1. What is the relationship between AGT and the Foundry Control Plane?

**Short answer:** They are complementary — AGT enforces governance at the agent execution level (runtime), while the Foundry Control Plane provides centralized fleet management, observability, and lifecycle operations at the organizational level. Think of AGT as the enforcement engine and the Foundry Control Plane as the management dashboard.

| Aspect | Agent Governance Toolkit | Foundry Control Plane |
|--------|------------------------|-----------------------|
| **Scope** | Per-agent runtime security and policy enforcement | Organization-wide fleet management, monitoring, and lifecycle |
| **Where it runs** | In-process middleware or sidecar alongside each agent | Centralized Azure service |
| **What it does** | Intercepts every agent action, enforces policy, verifies identity, audits | Provides agent inventory, health monitoring, lifecycle operations, centralized policy definition |
| **Latency** | Sub-millisecond (<0.1ms p99) | Dashboard/API-level |
| **License** | Open-source (MIT) | Azure managed service |

### How They Work Together

```
┌────────────────────────────────────────────────────────┐
│              Foundry Control Plane                      │
│  ┌──────────────┐  ┌───────────┐  ┌────────────────┐  │
│  │ Agent        │  │ Health    │  │ Policy         │  │
│  │ Inventory    │  │ Monitoring│  │ Definition     │  │
│  └──────────────┘  └───────────┘  └────────────────┘  │
└────────────────────────┬───────────────────────────────┘
                         │  Publishes policies, collects telemetry
                         ▼
┌────────────────────────────────────────────────────────┐
│              Agent Governance Toolkit                    │
│  (runs alongside each agent — middleware or sidecar)    │
│                                                         │
│  Policy Engine ──► Identity Verification ──► Audit Log  │
│      (<0.1ms)        (Ed25519 + DID)        (immutable) │
└────────────────────────────────────────────────────────┘
```

In practice:

- The **Control Plane** defines and distributes policies, aggregates telemetry, and provides a single pane of glass for operators.
- The **Toolkit** enforces those policies deterministically at runtime — every tool call, resource access, and inter-agent message is evaluated before execution.
- Foundry Control Plane can report on AGT-enforced events (blocked actions, identity assertions, trust scores) as part of its observability features.

### Deployment Patterns

- **Azure AI Foundry Agent Service** — AGT plugs directly into Foundry's middleware pipeline. No sidecar needed. This is the tightest integration.
- **AKS Sidecar** — AGT runs as a sidecar container in the same Kubernetes Pod as your agent. The Control Plane manages the fleet; AGT governs each agent.
- **Azure Container Apps** — Serverless container deployment with AGT governance.
- **Hybrid** — Foundry middleware for Foundry-native agents + AKS sidecar for custom agents, both feeding into the same Control Plane.

---

## 2. Is the Agent Mesh sidecar only intercepting network-related agent actions?

**Short answer:** No. The sidecar operates at the **application layer** — intercepting JSON-RPC tool calls, enforcing policy decisions, verifying trust, managing identity, auditing actions, and sanitizing outputs. It is not a network packet inspector; it is a governance proxy.

### What the Sidecar Intercepts

| Category | What It Does | Layer |
|----------|-------------|-------|
| Tool call interception | Intercepts JSON-RPC `tools/call` messages (MCP protocol) before they reach the target server | Application (L7) |
| Policy enforcement | Evaluates every action against YAML/OPA/Cedar policy rules — allow, deny, or flag | Application |
| Identity verification | Verifies agent DID (Ed25519 signature), checks trust score thresholds | Cryptographic |
| Capability gating | Ensures the agent has the required capabilities before allowing tool execution | Application |
| Output sanitization | Sanitizes tool results, strips PII, appends verification footers | Application |
| Non-JSON smuggling prevention | Blocks non-JSON payloads that could bypass policy inspection | Application |
| Audit logging | Logs every governance check, violation, and action for compliance | Observability |
| Prompt injection scanning | Scans inputs for injection attacks before they reach the agent | Security |
| Rate limiting | Enforces per-agent, per-tool rate limits | Application |
| Health/readiness probes | Kubernetes `/health` and `/ready` endpoints for orchestration | Infrastructure |
| Metrics export | Governance check counts, violation rates, latency via `/api/v1/metrics` | Observability |

### Key Distinction

- **Service mesh sidecars** (e.g., Envoy/Istio) operate at Layer 3–4 (TCP/TLS) — they handle mTLS, load balancing, and network routing.
- **AGT sidecar** operates at Layer 7 (application) — it understands the *semantics* of agent actions (tool calls, MCP messages, A2A protocol) and makes governance decisions based on *what the agent is trying to do*, not just where the traffic is going.

> **Current limitation:** Transparent tool-call interception is not yet implemented in the sidecar. The agent or orchestration layer must call the sidecar API explicitly (HTTP calls to `localhost:8081`). Transparent interception (via iptables or eBPF) is on the roadmap.

---

## 3. What is the practical impact of the different SDK integration types?

**Short answer:** The integration type determines how deeply governance is woven into the agent framework's execution pipeline — from a single line of configuration (native middleware) to a lightweight adapter you wrap around your agent. The governance capabilities are identical regardless of type; the difference is developer experience and coupling depth.

### Integration Types

| Type | Coupling | Developer Effort | What It Means |
|------|----------|-----------------|---------------|
| **Native Middleware** | Deepest | Minimal — add middleware to existing pipeline | Governance runs as a first-class middleware layer. Every action passes through it automatically. No code changes to agent logic. |
| **Native** | Deep | Minimal — import and configure | Hooks directly into the framework's native extension points (e.g., Semantic Kernel filters/plugins). |
| **Adapter** | Moderate | Low — wrap your agent/kernel | A thin wrapper class that bridges the framework's API to AGT. Typical: `LangChainKernel(agent=my_agent)`. |
| **Middleware/Pipeline** | Moderate | Low — register as callback/component | Hooks into lifecycle callbacks or pipeline stages. In Haystack, it's a pipeline component; in OpenAI Agents SDK, it's an async hook. |
| **Plugin** | Lightest | Minimal — install from marketplace | Drop-in plugin in platforms that support marketplaces. In Dify, governance appears as a tool in the Dify Marketplace. |
| **Deployment Guide** | N/A | Varies | Not a code integration — a documented deployment pattern. For Azure AI Foundry, governance is deployed via infrastructure configuration. |

### Framework-by-Framework Mapping

| Framework | Integration Type | Governance Class | Practical Impact |
|-----------|-----------------|-----------------|-----------------|
| Microsoft Agent Framework | Native Middleware | `GovernanceMiddleware` | Add 1 middleware registration. All tool calls governed automatically. |
| Semantic Kernel | Native (.NET + Python) | `SemanticKernelAdapter` | Register as a Semantic Kernel filter. Transparent governance. |
| AutoGen | Adapter | `AutoGenKernel` | Wrap your AutoGen agent. Governance injected at tool-call boundaries. |
| LangChain / LangGraph | Adapter | `LangChainKernel` / `LangGraphKernel` | Wrap chains/graphs. Published on PyPI (`langgraph-trust`). |
| CrewAI | Adapter | `CrewAIKernel` | Wrap crew tasks. Trust verification before inter-agent delegation. |
| OpenAI Agents SDK | Middleware | `OpenAIAgentsKernel` | Async hooks on tool calls. Published on PyPI (`openai-agents-trust`). |
| Google ADK | Adapter | `GoogleADKKernel` | Plugin-style integration via ADK's extension system. |
| LlamaIndex | Middleware | `LlamaIndexAdapter` | `TrustedAgentWorker` + `TrustGatedQueryEngine` merged upstream. |
| Haystack | Pipeline | `HaystackAdapter` | `GovernancePolicyChecker` + `TrustGate` pipeline components. |
| Dify | Plugin | `DifyPlugin` | Install from Dify Marketplace. Zero-code governance. |
| Azure AI Foundry | Deployment Guide | MAF Middleware | `GovernancePolicyMW`, `CapabilityGuardMW`, `AuditTrailMW`, `RogueDetectionMW`. |

### Which Should You Choose?

- **Microsoft Agent Framework or Semantic Kernel** → Use native middleware — governance is invisible and automatic.
- **LangChain, CrewAI, AutoGen, or Google ADK** → Use the adapter — 2–3 lines of code.
- **Dify** → Install the plugin from the marketplace.
- **Azure AI Foundry** → Follow the deployment guide for MAF middleware.

All types deliver the same governance capabilities — policy enforcement, identity verification, audit logging, trust scoring.

---

## 4. How many SDKs are actually supported — 12 or 6?

**Short answer:** The numbers refer to different things:

- **5 language SDKs** — Python, TypeScript, .NET, Rust, Go
- **6 production framework integrations** (for AgentMesh specifically) — Dify, LlamaIndex, Agent-Lightning, LangGraph, OpenAI Agents, Haystack
- **12+ framework integrations** (for the full toolkit) — includes all 6 above plus Microsoft Agent Framework, Semantic Kernel, AutoGen, LangChain, CrewAI, Google ADK, PydanticAI, and more

### Language SDKs (5)

| Language | Package | Status |
|----------|---------|--------|
| Python | `agent-governance-toolkit[full]` | ✅ Full-featured, primary SDK |
| TypeScript | `@microsoft/agentmesh-sdk` | ✅ Published on npm |
| .NET | `Microsoft.AgentGovernance` | ✅ Published on NuGet |
| Rust | `agentmesh` crate | ✅ Published on crates.io |
| Go | `github.com/microsoft/agent-governance-toolkit/sdks/go` | ✅ Module available |

### AgentMesh Framework Integrations (6)

The AgentMesh package README lists 6 production integrations specific to the trust/identity layer:

| Framework | Stars | Status |
|-----------|-------|--------|
| Dify | 65K ⭐ | ✅ Merged in Marketplace |
| LlamaIndex | 47K ⭐ | ✅ Merged upstream |
| Agent-Lightning | 15K ⭐ | ✅ Merged |
| LangGraph | 24K ⭐ | 📦 Published on PyPI |
| OpenAI Agents SDK | — | 📦 Published on PyPI |
| Haystack | 22K ⭐ | 🔄 In Review |

### Full Toolkit Framework Integrations (12+)

The root README lists all frameworks the entire toolkit supports, including Agent OS policy engine integrations: Microsoft Agent Framework, Semantic Kernel, AutoGen, LangGraph, LangChain, CrewAI, OpenAI Agents SDK, Google ADK, LlamaIndex, Haystack, Dify, Azure AI Foundry, plus community adapters for PydanticAI, Mistral, Anthropic, and Gemini.

### Why the Discrepancy?

The AgentMesh README counts only its own production-merged or PyPI-published integrations (6). The root README counts all integrations across all 7 packages in the toolkit (12+). Both numbers are accurate — they just scope differently.

---

## 5. Can an agent identity be linked to Entra IDs?

**Short answer:** Yes. AgentMesh provides first-class Microsoft Entra Agent ID integration that bridges the toolkit's DID-based identity system with enterprise Entra ID. Agents can authenticate via Azure Managed Identities (both system-assigned and user-assigned), and the toolkit maps DIDs to Entra tenant/client/object IDs.

### Architecture

```
┌──────────────────────────────────────────────────────────┐
│  Agent Governance Toolkit Identity Layer                  │
│                                                           │
│  ┌────────────────────────────────────────────────────┐  │
│  │  AgentIdentity (DID: did:mesh:<agent-name>)         │  │
│  │  ├── Ed25519 keypair (signing/verification)         │  │
│  │  ├── Human sponsor (alice@company.com)              │  │
│  │  ├── Capabilities (["read:data", "write:reports"])  │  │
│  │  └── Trust score (0–1000)                           │  │
│  └──────────────────────┬─────────────────────────────┘  │
│                          │ bridges to                      │
│  ┌──────────────────────▼─────────────────────────────┐  │
│  │  EntraAgentID (Entra integration adapter)           │  │
│  │  ├── Entra Tenant ID                                │  │
│  │  ├── Entra Client ID                                │  │
│  │  ├── Entra Object ID                                │  │
│  │  ├── JWT claim validation                           │  │
│  │  └── Conditional Access policy support              │  │
│  └──────────────────────┬─────────────────────────────┘  │
│                          │ authenticates via               │
│  ┌──────────────────────▼─────────────────────────────┐  │
│  │  Azure Managed Identity                             │  │
│  │  ├── System-assigned (VM, App Service, AKS)         │  │
│  │  ├── User-assigned (shared across resources)        │  │
│  │  └── IMDS token acquisition (169.254.169.254)       │  │
│  └────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Source File | Purpose |
|-----------|------------|---------|
| `AgentIdentity` | `identity/agent_id.py` | Core DID identity with Ed25519 keys, sponsor, capabilities |
| `EntraAgentID` | `identity/entra_agent_id.py` | Maps DID ↔ Entra tenant/client IDs, bootstraps from IMDS or env vars |
| `EntraAgentIdentity` | `identity/entra.py` | Extended identity binding DID to Entra object IDs, sponsor, scopes, lifecycle states |
| `EntraAgentRegistry` | `identity/entra.py` | Registry of Entra-backed agent identities with lookup by DID or Entra object ID |
| `EntraManagedIdentity` | `identity/managed_identity.py` | Uses Azure IMDS to acquire tokens for Managed Identities |

### Practical Usage

```python
from agentmesh.identity import AgentIdentity
from agentmesh.identity.entra_agent_id import EntraAgentID

# Create an agent identity linked to Entra
identity = AgentIdentity.create(
    name="trading-agent",
    sponsor="alice@contoso.com",
    capabilities=["read:market-data", "execute:trades"],
)

# Bridge to Entra ID
entra = EntraAgentID(
    agent_identity=identity,
    tenant_id="your-entra-tenant-id",    # or auto-detected from AZURE_TENANT_ID
    client_id="your-app-registration-id", # or auto-detected from AZURE_CLIENT_ID
)

# On Azure (AKS, App Service, VM), use Managed Identity
from agentmesh.identity.managed_identity import EntraManagedIdentity

managed = EntraManagedIdentity()  # Auto-detects IMDS
token = managed.get_token(scope="https://graph.microsoft.com/.default")
```

### What This Enables

- **Enterprise SSO** — Agents authenticate with the same Entra ID used by your organization.
- **Conditional Access** — Apply Entra Conditional Access policies to agent identities.
- **Lifecycle Management** — Entra-backed agents inherit lifecycle states from both AGT and Entra ID.
- **RBAC Integration** — Agents can be assigned Azure RBAC roles through their Managed Identity.
- **Audit Trail** — Entra sign-in logs capture agent authentication events alongside human events.
- **Credential-less** — Managed Identity means no secrets to manage in code or configuration.

> **Multi-cloud:** The toolkit also provides adapters for AWS IAM (instance roles, STS assume-role) and GCP Workload Identity (service accounts, metadata server) in `identity/managed_identity.py`.

---

## 6. If I update a policy at runtime, do I need to restart the agent?

**Short answer:** No. Policies can be reloaded at runtime without restarting the agent.

### In-Process Reload (Explicit)

```python
from agent_os.policies import AsyncPolicyEvaluator

evaluator = AsyncPolicyEvaluator(policy_dir="./policies")

# Later, when policies have been updated on disk:
await evaluator.reload_policies(directory="./policies")
# All subsequent evaluations use the new policies — no restart needed
```

The reload operation:
1. Acquires a write lock (blocking concurrent reads momentarily)
2. Clears the existing policy cache
3. Loads all policy files from the directory
4. Releases the lock
5. All subsequent evaluations use the new policies

### OPA Remote Server (Hot Reload)

When using OPA as the policy backend in Remote Server mode, you get true policy hot-reload — OPA watches the policy bundle and applies changes automatically:

| Feature | Remote OPA Server | Local CLI | Built-in Fallback |
|---------|:-----------------:|:---------:|:-----------------:|
| Policy hot-reload | ✅ | ❌ | ❌ |
| Sub-millisecond latency | ✅ | ❌ | ✅ |
| Centralized management | ✅ | ❌ | ❌ |

### Sidecar Deployment

In sidecar deployments, the governance sidecar can be updated independently of the agent container:

1. Update the policy ConfigMap in Kubernetes
2. The sidecar picks up the new policies
3. The agent container continues running uninterrupted

### Practical Recommendation

| Scenario | Approach |
|----------|---------|
| Development/testing | Call `reload_policies()` explicitly after editing policy files |
| Production (single agent) | Use OPA Remote Server for automatic hot-reload |
| Production (fleet) | Use Foundry Control Plane to distribute policy updates → sidecar picks up changes via ConfigMap |

---

## 7. What is the Microsoft product integration roadmap?

### Current State (as of April 2026)

| Microsoft Product | Status | Details |
|-------------------|--------|---------|
| Azure AI Foundry Agent Service | ✅ Available | Native MAF middleware |
| Azure Kubernetes Service (AKS) | ✅ Available | Sidecar deployment with Helm charts |
| Azure Container Apps | ✅ Available | Serverless deployment guide |
| Semantic Kernel | ✅ Available | Native .NET + Python integration |
| Microsoft Agent Framework | ✅ Available | Native middleware integration |
| Microsoft AutoGen | ✅ Available | Adapter integration |
| Microsoft Agent-Lightning | ✅ Merged | RL training governance — merged upstream |
| VS Code Extension | ✅ Available | `agent-os-vscode` package |
| Azure Monitor | ✅ Available | OpenTelemetry + Prometheus metrics export |
| Microsoft Entra Agent ID | ✅ Available | DID ↔ Entra identity bridge with Managed Identity support |
| Microsoft Defender | 🔄 Planned | Integration for threat detection alignment |
| Foundry Control Plane | 🔄 Planned | Deeper fleet governance integration |

### Published Package Ecosystem

| Ecosystem | Package | Status |
|-----------|---------|--------|
| PyPI | `agent-governance-toolkit[full]`, `agent-os-kernel`, `agentmesh-platform`, `agentmesh-runtime`, `agent-sre`, `agentmesh-marketplace`, `agentmesh-lightning`, `openai-agents-trust`, `langgraph-trust` | ✅ Published |
| npm | `@microsoft/agentmesh-sdk` | ✅ Published |
| NuGet | `Microsoft.AgentGovernance` | ✅ Published |
| crates.io | `agentmesh` | ✅ Published |
| Dify Marketplace | Trust verification plugin | ✅ Merged |

### Open-Source Community Direction

The project is MIT-licensed and Microsoft has stated the aspiration to move it into a foundation home for shared community stewardship. Active engagements include OWASP Agent Security Initiative, LF AI & Data Foundation, and CoSAI (Coalition for Secure AI) working groups.

---

## 8. How does Agent Mesh Runtime interact with Agent Mesh and the Sidecar?

**Short answer:** These are three distinct layers of the governance stack:

| Component | Role | Analogy |
|-----------|------|---------|
| **AgentMesh** (platform) | Trust, identity, and governance layer — the "brain" | SSL/TLS for the web |
| **Agent Mesh Sidecar** | Deployment mode — a local governance proxy in a Kubernetes Pod | Envoy sidecar in Istio |
| **Agent Mesh Runtime** (agent-runtime / agent-hypervisor) | Execution supervisor — privilege rings, sagas, kill switch | OS kernel / hypervisor |

### How They Interact

```
┌───────────────────────────────────────────────────────────────┐
│                     Kubernetes Pod                             │
│                                                               │
│  ┌──────────────────────┐  ┌───────────────────────────────┐ │
│  │  Agent Container      │  │  Governance Sidecar            │ │
│  │                       │  │                                │ │
│  │  Your AI Agent        │  │  ┌───────────────────────┐    │ │
│  │  (any framework)      │  │  │  AgentMesh (Layer 1)  │    │ │
│  │                       │  │  │  Identity + Trust     │    │ │
│  │  ┌─────────────────┐ │  │  │  DID, Ed25519, IATP   │    │ │
│  │  │ Agent Runtime    │ │  │  └───────────┬───────────┘    │ │
│  │  │ (in-process)     │ │  │              │                 │ │
│  │  │ Execution rings  │ │  │  ┌───────────▼───────────┐    │ │
│  │  │ Saga orchestr.   │ │  │  │  Agent OS (Layer 2)   │    │ │
│  │  │ Kill switch      │ │  │  │  Policy Engine        │    │ │
│  │  └─────────────────┘ │  │  │  YAML / OPA / Cedar   │    │ │
│  │           │           │  │  └───────────┬───────────┘    │ │
│  │  Tool call ───────────────► Governance  │  Proxy          │ │
│  │           ◄─────────────── Allow/Deny   │                 │ │
│  └──────────────────────┘  └──────────────┼────────────────┘ │
│                                            ▼                  │
│                                    External APIs / MCP        │
└───────────────────────────────────────────────────────────────┘
```

### Interaction Flow

1. **Agent wants to act** — e.g., call a tool, send a message to another agent, access a resource.
2. **Agent Runtime checks execution ring** — Is this agent in Ring 2 (standard) or Ring 3 (sandbox)? Does it have the privilege level?
3. **Request goes to AgentMesh** (via sidecar or in-process):
   - **Identity check** — Is the caller's DID valid and active?
   - **Trust check** — Does the peer meet the trust score threshold?
   - **Policy check** — Does the Agent OS policy engine allow this action?
4. **If allowed** → Forward to target (MCP server, another agent, external API)
5. **If denied** → Block, return reason, log the violation
6. **Always** → Audit log entry written

### When Each Component Is Used

| Scenario | AgentMesh | Sidecar | Runtime |
|----------|:---------:|:-------:|:-------:|
| Single agent, in-process governance | ✅ (library) | ❌ | Optional |
| Multi-agent on Kubernetes | ✅ | ✅ | ✅ |
| Azure AI Foundry | ✅ (middleware) | ❌ | Optional |
| Multi-step workflows with rollback | ✅ | Optional | ✅ (saga) |
| Emergency agent termination | ✅ | Optional | ✅ (kill switch) |

---

## 9. How does Agent Mesh govern authentications to internal and external resources?

**Short answer:** AgentMesh uses different mechanisms for internal (agent-to-agent) and external (agent-to-service) authentication, but both are governed through the same policy engine.

### Internal Authentication (Agent-to-Agent)

```
Agent A                    TrustBridge                    Agent B
  │                            │                             │
  ├─── verify_peer(B, min=700)──►                            │
  │                            ├──── IATP Challenge ─────────►
  │                            │     (nonce + timestamp)      │
  │                            ◄──── Signed Response ────────┤
  │                            │     (Ed25519 signature)      │
  │                    Verify:                                │
  │                    1. DID registered in registry?          │
  │                    2. Identity active (not revoked)?       │
  │                    3. Ed25519 signature valid?             │
  │                    4. Public key matches registry?         │
  │                    5. Trust score ≥ threshold?             │
  │                    6. Required capabilities present?       │
  ◄─── Result (verified/denied)│                              │
```

Key controls:

- **DID-based identity** — Every agent gets a `did:mesh:` identifier with Ed25519 keypair
- **Ed25519 challenge-response** — Cryptographic proof the peer owns the claimed DID
- **Registry-backed verification** — Peer must be registered and active
- **Trust scoring** — Dynamic trust scores (0–1000) with behavioral decay
- **Capability scoping** — Agents only get access to capabilities they're registered for
- **Protocol bridges** — A2A, MCP, IATP translated through a unified trust model

### External Authentication (Agent-to-Service)

| External Resource | How AgentMesh Governs It |
|-------------------|--------------------------|
| **MCP Servers** (tools) | Proxy intercepts tool calls → policy check → allow/deny → audit. Supports allowlists, rate limits, output sanitization. |
| **LLM APIs** (OpenAI, Azure OpenAI, etc.) | Policy engine can restrict which models, endpoints, and parameters an agent can use. Rate limiting per agent. |
| **Databases** | Tool-call governance — if the agent accesses a DB through a tool, the proxy enforces policy on that tool call. |
| **External APIs** | Same tool-call interception pattern. Capability gating ensures agents only call APIs they're authorized for. |
| **Cloud Resources** | Managed Identity adapters (Entra, AWS IAM, GCP WI) handle authentication. AGT governance layer controls authorization. |

**Key distinction:**

- **Authentication** (proving who you are) to external services is handled via managed identities / workload identity — the same credential-less approach used by any Azure service.
- **Authorization** (what you're allowed to do) is where AgentMesh adds governance — policy enforcement, capability gating, rate limiting, and audit logging sit between the agent and the external resource.

---

## 10. What is the difference between agent-hypervisor and agent-runtime?

**Short answer:** They are the same subsystem with different package names. `agent-hypervisor` is the canonical upstream implementation; `agentmesh-runtime` (`agent-runtime`) is a thin re-export wrapper created to avoid a PyPI naming collision with Microsoft AutoGen's `agent-runtime` package.

| Aspect | agent-hypervisor | agent-runtime (agentmesh-runtime) |
|--------|-----------------|----------------------------------|
| **PyPI Package** | `agent-hypervisor` | `agentmesh-runtime` |
| **Role** | Canonical implementation | Thin re-export wrapper |
| **Why it exists** | Primary development package | PyPI name collision avoidance with AutoGen |
| **Tests** | 644+ tests | Import compatibility tests |
| **Install** | `pip install agent-hypervisor` | `pip install agentmesh-runtime` |
| **Import** | `from hypervisor import Hypervisor` | `from hypervisor import Hypervisor` (same) |

### What the Hypervisor / Runtime Provides

| Feature | Description |
|---------|-------------|
| **Execution Rings (Ring 0–3)** | Graduated privilege levels based on trust score. Ring 0 = system (highest), Ring 3 = sandbox (most restricted). |
| **Session Isolation** | Multi-agent sessions with VFS namespacing and DID-bound identity. |
| **Saga Orchestration** | Multi-step transactions with automatic compensation (rollback). |
| **Kill Switch** | Immediate or graceful termination of runaway agents with audit trail. |
| **Joint Liability** | Attribution tracking across multi-agent collaborations. Bonded reputation with collateral slashing. |
| **Rate Limiting** | Per-agent rate limits to prevent resource exhaustion. |
| **Hash-Chained Audit Trail** | Tamper-evident, append-only execution logs. |
| **Temporary Ring Elevation (Sudo)** | Agents can request temporary privilege escalation with a TTL that auto-expires. |

### OS Concepts Mapping

| OS / VM Hypervisor | Agent Hypervisor | Why It Matters |
|-------------------|-----------------|----------------|
| CPU rings (Ring 0–3) | Execution Rings — privilege levels based on trust score | Graduated access, not binary allow/deny |
| Process isolation | Session isolation — VFS namespacing, DID-bound identity | Rogue agents can't corrupt other sessions |
| Memory protection | Liability protection — bonded reputation, collateral slash | Sponsors have skin in the game |
| System calls | Saga transactions — multi-step ops with automatic rollback | Failed workflows undo themselves |
| Watchdog timer | Kill switch — graceful termination with step handoff | Stop runaway agents without data loss |

---

## Appendix: Quick Reference — All Packages

| Package | PyPI | Purpose |
|---------|------|---------|
| Agent OS | `agent-os-kernel` | Stateless policy engine — YAML, OPA/Rego, Cedar policies |
| AgentMesh | `agentmesh-platform` | Trust, identity, governance — DID, Ed25519, trust scoring, protocol bridges |
| Agent Runtime | `agentmesh-runtime` | Execution rings, saga orchestration, kill switch (re-exports from agent-hypervisor) |
| Agent Hypervisor | `agent-hypervisor` | Canonical runtime — session isolation, privilege rings, joint liability |
| Agent SRE | `agent-sre` | SLOs, error budgets, circuit breakers, chaos engineering, replay debugging |
| Agent Marketplace | `agentmesh-marketplace` | Plugin lifecycle — Ed25519 signing, trust-tiered capability gating |
| Agent Lightning | `agentmesh-lightning` | RL training governance — policy-enforced runners, reward shaping |
| Agent Compliance | `agent-governance-toolkit` | Unified installer + compliance verification (EU AI Act, HIPAA, SOC2, OWASP) |
| Agent Discovery | `agent-discovery` | Shadow AI discovery — find unregistered agents across processes, configs, repos |

## Appendix: Key Links

| Resource | URL |
|----------|-----|
| GitHub Repository | https://github.com/microsoft/agent-governance-toolkit |
| Launch Blog Post | https://opensource.microsoft.com/blog/2026/04/02/introducing-the-agent-governance-toolkit-open-source-runtime-security-for-ai-agents/ |
| PyPI (Full Stack) | https://pypi.org/project/agent-governance-toolkit/ |
| npm (TypeScript) | `@microsoft/agentmesh-sdk` |
| NuGet (.NET) | `Microsoft.AgentGovernance` |
| DeepWiki | https://deepwiki.com/microsoft/agent-governance-toolkit |
| OWASP Agentic Top 10 | https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/ |
| Quick Start Guide | [QUICKSTART.md](../QUICKSTART.md) |
| Deployment Guides | [docs/deployment/](deployment/) |
