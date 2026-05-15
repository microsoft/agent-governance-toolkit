---
hide:
  - navigation
  - toc
---

<style>
/* Hero section */
.agt-hero {
  background: linear-gradient(135deg, #0078D4 0%, #005A9E 100%);
  color: white;
  padding: 3rem 2rem;
  border-radius: 8px;
  margin-bottom: 2rem;
  text-align: center;
}
.agt-hero h1 { color: white; border: none; margin: 0 0 0.5rem; font-size: 2rem; }
.agt-hero p { color: rgba(255,255,255,0.9); font-size: 1.05rem; max-width: 700px; margin: 0 auto 1.5rem; }
.agt-hero-badges { display: flex; gap: 0.5rem; justify-content: center; flex-wrap: wrap; }
.agt-hero-badges a {
  display: inline-block;
  background: rgba(255,255,255,0.15);
  color: white;
  padding: 0.5rem 1.2rem;
  border-radius: 4px;
  text-decoration: none;
  font-weight: 600;
  font-size: 0.85rem;
  transition: background 0.2s;
}
.agt-hero-badges a:hover { background: rgba(255,255,255,0.25); }

/* Card grid */
.agt-cards {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(260px, 1fr));
  gap: 1rem;
  margin: 1.5rem 0;
}
.agt-card {
  border: 1px solid #E0E0E0;
  border-radius: 6px;
  padding: 1.2rem;
  transition: box-shadow 0.2s, border-color 0.2s;
  text-decoration: none;
  color: inherit;
  display: block;
}
.agt-card:hover {
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
  border-color: #0078D4;
}
.agt-card-title { display: block; margin: 0 0 0.4rem; font-size: 0.95rem; font-weight: 600; color: #0078D4; }
.agt-card-desc { display: block; margin: 0; font-size: 0.82rem; color: #616161; }

[data-md-color-scheme="slate"] .agt-card { border-color: #3A3A3E; }
[data-md-color-scheme="slate"] .agt-card:hover { border-color: #4DB8FF; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }
[data-md-color-scheme="slate"] .agt-card-title { color: #4DB8FF; }
[data-md-color-scheme="slate"] .agt-card-desc { color: #B0B0B0; }
[data-md-color-scheme="slate"] .agt-hero { background: linear-gradient(135deg, #1A3F5C 0%, #0D2137 100%); }

/* Section headers */
.agt-section { margin-top: 2.5rem; }
.agt-section h2 { font-size: 1.3rem; }

/* Stats row */
.agt-stats {
  display: flex;
  gap: 2rem;
  justify-content: center;
  margin: 1.5rem 0 0;
  flex-wrap: wrap;
}
.agt-stat { text-align: center; }
.agt-stat-value { font-size: 1.5rem; font-weight: 700; color: white; display: block; }
.agt-stat-label { font-size: 0.78rem; color: rgba(255,255,255,0.7); }
</style>

<div class="agt-hero" markdown>

# Agent Governance Toolkit

Runtime governance for AI agents: deterministic policy enforcement, zero-trust identity, execution sandboxing, and SRE for autonomous agents.

<div class="agt-hero-badges">
  <a href="quickstart/">🚀 Quick Start</a>
  <a href="https://pypi.org/project/agent-governance-toolkit/">📦 PyPI</a>
  <a href="https://github.com/microsoft/agent-governance-toolkit">💻 GitHub</a>
  <a href="tutorials/index/">📚 Tutorials</a>
</div>

<div class="agt-stats">
  <div class="agt-stat"><span class="agt-stat-value">13,000+</span><span class="agt-stat-label">Tests</span></div>
  <div class="agt-stat"><span class="agt-stat-value">8</span><span class="agt-stat-label">Core packages</span></div>
  <div class="agt-stat"><span class="agt-stat-value">5</span><span class="agt-stat-label">Languages</span></div>
  <div class="agt-stat"><span class="agt-stat-value">19</span><span class="agt-stat-label">Integrations</span></div>
</div>

</div>

<div class="agt-section" markdown>

## Packages

<div class="agt-cards">
<a class="agt-card" href="packages/agent-os.md">
<span class="agt-card-title">⚙️ Agent OS</span>
<span class="agt-card-desc">Policy engine, agent lifecycle, governance gate</span>
</a>
<a class="agt-card" href="packages/agent-mesh.md">
<span class="agt-card-title">🔗 Agent Mesh</span>
<span class="agt-card-desc">Agent discovery, routing, and trust mesh</span>
</a>
<a class="agt-card" href="packages/agent-runtime.md">
<span class="agt-card-title">🛡️ Agent Runtime</span>
<span class="agt-card-desc">Execution sandboxing with four privilege rings</span>
</a>
<a class="agt-card" href="packages/agent-sre.md">
<span class="agt-card-title">📊 Agent SRE</span>
<span class="agt-card-desc">Kill switch, SLO monitoring, chaos testing</span>
</a>
<a class="agt-card" href="packages/agent-compliance.md">
<span class="agt-card-title">✅ Agent Compliance</span>
<span class="agt-card-desc">Audit logging, compliance frameworks</span>
</a>
<a class="agt-card" href="packages/agent-marketplace.md">
<span class="agt-card-title">🏪 Agent Marketplace</span>
<span class="agt-card-desc">Plugin governance and trust scoring</span>
</a>
<a class="agt-card" href="packages/agent-lightning.md">
<span class="agt-card-title">⚡ Agent Lightning</span>
<span class="agt-card-desc">High-performance agent orchestration</span>
</a>
<a class="agt-card" href="packages/agent-hypervisor.md">
<span class="agt-card-title">🔒 Agent Hypervisor</span>
<span class="agt-card-desc">Hardware-level workload isolation</span>
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
| 🦀 Rust | `cargo add agentmesh` |
| 🐹 Go | `go get github.com/microsoft/agent-governance-toolkit` |

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

## Standards Compliance

| Standard | Coverage |
|----------|----------|
| [OWASP Agentic AI Top 10](security/owasp-compliance.md) | All 10 risks covered with deterministic controls |
| [NIST AI RMF 1.0](reference/nist-rfi-mapping.md) | Full GOVERN, MAP, MEASURE, MANAGE alignment |
| [Ed25519 (RFC 8032)](adr/0001-use-ed25519-for-agent-identity.md) | Agent identity signatures |
| [RFC 9334 (RATS)](adr/0009-rfc-9334-rats-architecture-alignment.md) | Remote attestation alignment |

</div>
