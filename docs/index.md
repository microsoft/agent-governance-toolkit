---
hide:
  - navigation
  - toc
---

<div class="agt-hero" markdown>

# Ship agents to production without losing sleep

Policy enforcement, identity, sandboxing, and SRE for autonomous AI agents. One `pip install`, any framework.

```
pip install agent-governance-toolkit
```

<div class="agt-hero-badges">
  <a href="quickstart/">🚀 Quick Start</a>
  <a href="https://pypi.org/project/agent-governance-toolkit/">📦 PyPI</a>
  <a href="https://github.com/microsoft/agent-governance-toolkit">💻 GitHub</a>
  <a href="tutorials/index/">📚 Tutorials</a>
  <a href="reference/comparison/">⚖️ How AGT Compares</a>
</div>

<div class="agt-stats">
  <div class="agt-stat"><span class="agt-stat-value">1,590+</span><span class="agt-stat-label">GitHub Stars</span></div>
  <div class="agt-stat"><span class="agt-stat-value">10</span><span class="agt-stat-label">Formal Specs</span></div>
  <div class="agt-stat"><span class="agt-stat-value">5</span><span class="agt-stat-label">Languages</span></div>
  <div class="agt-stat"><span class="agt-stat-value">19</span><span class="agt-stat-label">Integrations</span></div>
</div>

</div>

<div class="agt-section" markdown>

## The problem

Your AI agents call tools, browse the web, query databases, and delegate to other agents. Once deployed, they make decisions autonomously. You need answers to three questions:

**1. Is this action allowed?** An agent with access to `send_email` and `query_database` should not be able to `drop_table`. OAuth scopes and IAM roles control which services an agent can reach, not what it does once connected.

**2. Which agent did this?** In a multi-agent system, five agents might share a single API key. When something goes wrong, "an agent did it" is not an incident response.

**3. Can you prove what happened?** Auditors and regulators need tamper-evident records of every decision: what policy was active, what the agent requested, and why it was allowed or denied.

</div>

<div class="agt-section" markdown>

## Govern any agent in 2 lines

Wrap any tool function with `govern()`. Policy enforcement, audit logging, and denial handling are automatic.

```python
from agentmesh.governance import govern

safe_tool = govern(my_tool, policy="policy.yaml")
```

That's it. `safe_tool` evaluates your YAML policy on every call, logs the decision, and raises `GovernanceDenied` if the action is blocked. Works with LangChain, CrewAI, OpenAI Agents, AutoGen, Google ADK, and any other framework.

```yaml
# policy.yaml
apiVersion: governance.toolkit/v1
name: production-policy
default_action: allow
rules:
  - name: block-destructive
    condition: "action.type in ['drop', 'delete', 'truncate']"
    action: deny
    description: "Destructive operations require human approval"

  - name: require-approval-for-send
    condition: "action.type == 'send_email'"
    action: require_approval
    approvers: ["security-team"]
```

```
>>> safe_tool(action="read", table="users")
{'table': 'users', 'rows': 42}

>>> safe_tool(action="drop", table="users")
GovernanceDenied: Action denied by policy rule 'block-destructive':
  Destructive operations require human approval
```

</div>

<div class="agt-section" markdown>

## How it works

```mermaid
flowchart LR
    A[🤖 Agent] -->|"govern()"| GK

    subgraph GK ["Agent Governance Toolkit"]
        direction LR
        PE["⚙️ Policy Engine\nYAML · OPA · Cedar"]
        ID["🔑 Identity\nSPIFFE · DID · mTLS"]
        AL["📋 Audit Log\nTamper-evident"]
        PE --> ID --> AL
    end

    GK -->|"✅ Allowed"| T[🔧 Tool]
    GK -->|"🚫 Denied"| D[GovernanceDenied]

    style GK fill:#0078D4,stroke:#005A9E,color:#fff
    style PE fill:#1a5276,stroke:#0078D4,color:#fff
    style ID fill:#1a5276,stroke:#0078D4,color:#fff
    style AL fill:#1a5276,stroke:#0078D4,color:#fff
    style A fill:#2C3E50,stroke:#566573,color:#fff
    style T fill:#1E8449,stroke:#196F3D,color:#fff
    style D fill:#922B21,stroke:#7B241C,color:#fff
```

<div class="agt-cards" style="margin-top: 1.5rem;">
<div class="agt-card" style="cursor:default;">
<span class="agt-card-title">⚙️ Agent OS</span>
<span class="agt-card-desc">Policies · Lifecycle · Approval workflows</span>
</div>
<div class="agt-card" style="cursor:default;">
<span class="agt-card-title">🔗 Agent Mesh</span>
<span class="agt-card-desc">Identity · Routing · Trust scoring</span>
</div>
<div class="agt-card" style="cursor:default;">
<span class="agt-card-title">📊 Agent SRE</span>
<span class="agt-card-desc">SLOs · Chaos testing · Cost budgets</span>
</div>
<div class="agt-card" style="cursor:default;">
<span class="agt-card-title">🛡️ Sandbox</span>
<span class="agt-card-desc">Execution rings · Isolation · Kill switch</span>
</div>
</div>

Every layer is optional. Start with `govern()` and add layers as your risk profile grows. Most teams run policy enforcement + audit logging and never need the full stack.

</div>

<div class="agt-section" markdown>

## Packages

<div class="agt-cards">
<a class="agt-card" data-pkg="os" href="packages/agent-os.md">
<img class="agt-card-icon" src="assets/icons/agent-os.svg" alt="Agent OS">
<span class="agt-card-body"><span class="agt-card-title">Agent OS</span>
<span class="agt-card-desc">Policy engine, agent lifecycle, governance gate</span></span>
</a>
<a class="agt-card" data-pkg="mesh" href="packages/agent-mesh.md">
<img class="agt-card-icon" src="assets/icons/agent-mesh.svg" alt="Agent Mesh">
<span class="agt-card-body"><span class="agt-card-title">Agent Mesh</span>
<span class="agt-card-desc">Agent discovery, routing, and trust mesh</span></span>
</a>
<a class="agt-card" data-pkg="runtime" href="packages/agent-runtime.md">
<img class="agt-card-icon" src="assets/icons/agent-runtime.svg" alt="Agent Runtime">
<span class="agt-card-body"><span class="agt-card-title">Agent Runtime</span>
<span class="agt-card-desc">Execution sandboxing with four privilege rings</span></span>
</a>
<a class="agt-card" data-pkg="sre" href="packages/agent-sre.md">
<img class="agt-card-icon" src="assets/icons/agent-sre.svg" alt="Agent SRE">
<span class="agt-card-body"><span class="agt-card-title">Agent SRE</span>
<span class="agt-card-desc">Kill switch, SLO monitoring, chaos testing</span></span>
</a>
<a class="agt-card" data-pkg="compliance" href="packages/agent-compliance.md">
<img class="agt-card-icon" src="assets/icons/agent-compliance.svg" alt="Agent Compliance">
<span class="agt-card-body"><span class="agt-card-title">Agent Compliance</span>
<span class="agt-card-desc">OWASP verification, policy linting, integrity checks</span></span>
</a>
<a class="agt-card" data-pkg="marketplace" href="packages/agent-marketplace.md">
<img class="agt-card-icon" src="assets/icons/agent-marketplace.svg" alt="Agent Marketplace">
<span class="agt-card-body"><span class="agt-card-title">Agent Marketplace</span>
<span class="agt-card-desc">Plugin governance and trust scoring</span></span>
</a>
<a class="agt-card" data-pkg="lightning" href="packages/agent-lightning.md">
<img class="agt-card-icon" src="assets/icons/agent-lightning.svg" alt="Agent Lightning">
<span class="agt-card-body"><span class="agt-card-title">Agent Lightning</span>
<span class="agt-card-desc">RL training governance with violation penalties</span></span>
</a>
<a class="agt-card" data-pkg="hypervisor" href="packages/agent-hypervisor.md">
<img class="agt-card-icon" src="assets/icons/agent-hypervisor.svg" alt="Agent Hypervisor">
<span class="agt-card-body"><span class="agt-card-title">Agent Hypervisor</span>
<span class="agt-card-desc">Execution audit, delta engine, commitment anchoring</span></span>
</a>
</div>
</div>

<div class="agt-section" markdown>

## Language SDKs

| SDK | Install |
|-----|---------|
| 🐍 [Python](packages/agent-compliance.md) | `pip install agent-governance-toolkit` |
| 📘 TypeScript | `npm install @microsoft/agent-governance-sdk` |
| 🔷 [.NET](packages/dotnet-sdk.md) | `dotnet add package Microsoft.AgentGovernance` |
| 🦀 Rust | `cargo add agent-governance` |
| 🐹 Go | `go get github.com/microsoft/agent-governance-toolkit/agent-governance-golang` |

</div>

<div class="agt-section" markdown>

## Framework Integrations

Works with any agent framework: LangChain, CrewAI, AutoGen, Google ADK, OpenAI Agents, LlamaIndex, Haystack, Mastra, MCP, A2A, and more. See the [full list](packages/index.md#framework-integrations-19).

</div>

<div class="agt-section" markdown>

## Examples

| Example | Framework | What it demonstrates |
|---------|-----------|---------------------|
| [openai-agents-governed](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/openai-agents-governed) | OpenAI Agents SDK | Policy-gated tool calls with trust tiers |
| [crewai-governed](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/crewai-governed) | CrewAI | Multi-agent governance with role-based policies |
| [smolagents-governed](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/smolagents-governed) | HuggingFace smolagents | Lightweight agent governance |
| [maf-integration](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/maf-integration) | MAF | Microsoft Agent Framework integration |
| [mcp-trust-verified-server](https://github.com/microsoft/agent-governance-toolkit/tree/main/examples/mcp-trust-verified-server) | MCP | Trust-verified MCP server implementation |

</div>

<div class="agt-section" markdown>

## Specifications

Every major component has a formal RFC 2119 specification with conformance tests.

| Specification | Tests |
|---|---|
| [Agent OS Policy Engine](specs/AGENT-OS-POLICY-ENGINE-1.0.md) | 68 |
| [AgentMesh Identity and Trust](specs/AGENTMESH-IDENTITY-TRUST-1.0.md) | 135 |
| [Agent Hypervisor Execution Control](specs/AGENT-HYPERVISOR-EXECUTION-CONTROL-1.0.md) | 80 |
| [AgentMesh Trust and Coordination](specs/AGENTMESH-TRUST-COORDINATION-1.0.md) | 62 |
| [Agent SRE Governance](specs/AGENT-SRE-GOVERNANCE-1.0.md) | 111 |
| [MCP Security Gateway](specs/MCP-SECURITY-GATEWAY-1.0.md) | 127 |
| [Agent Lightning Fast-Path](specs/AGENT-LIGHTNING-FAST-PATH-1.0.md) | 100 |
| [Framework Adapter Contract](specs/FRAMEWORK-ADAPTER-CONTRACT-1.0.md) | 152 |
| [Audit and Compliance](specs/AUDIT-COMPLIANCE-1.0.md) | 157 |
| [AgentMesh Wire Protocol](specs/AGENTMESH-WIRE-1.0.md) | -- |

[25 Architecture Decision Records](adr/) document the reasoning behind key design choices.

</div>

<div class="agt-section" markdown>

## Standards Compliance

| Standard | Coverage |
|----------|----------|
| [OWASP Agentic AI Top 10](security/owasp-compliance.md) | All 10 risks covered with deterministic controls |
| [NIST AI RMF 1.0](reference/nist-rfi-mapping.md) | Full GOVERN, MAP, MEASURE, MANAGE alignment |
| [EU AI Act](compliance/) | Compliance mapping with automated evidence |
| [SOC 2](compliance/soc2-mapping.md) | Control mapping with audit trail export |

</div>
