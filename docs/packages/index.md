# Packages

AGT provides 14 packages covering every layer of agent governance.

```
+------------------+     +------------------+     +------------------+
|    Agent OS      |     |   Agent Mesh     |     |  Agent Runtime   |
|  Policy engine   |     |  Discovery &     |     |  Sandboxing &    |
|  & lifecycle     |     |  trust mesh      |     |  privilege rings  |
+------------------+     +------------------+     +------------------+
        |                        |                        |
+------------------+     +------------------+     +------------------+
|   Agent SRE      |     | Agent Compliance |     | Agent Marketplace|
|  Reliability &   |     |  Audit logging   |     |  Plugin trust    |
|  monitoring      |     |  & frameworks    |     |  & governance    |
+------------------+     +------------------+     +------------------+
        |                        |                        |
+------------------+     +------------------+     +------------------+
| Agent Lightning  |     | Agent Hypervisor |     | Language + Tools |
|  High-perf       |     |  HW isolation    |     |  .NET, TS, Rust  |
|  orchestration   |     |  for workloads   |     |  Go, VS Code     |
+------------------+     +------------------+     +------------------+
```

## Core Packages

| Package | Description | Install |
|---------|------------|---------|
| [Agent OS](agent-os.md) | Policy engine, agent lifecycle, governance gate | `pip install agent-os-kernel` |
| [Agent Mesh](agent-mesh.md) | Agent discovery, routing, trust mesh | `pip install agentmesh-platform` |
| [Agent Runtime](agent-runtime.md) | Execution sandboxing, four privilege rings | `pip install agentmesh-runtime` |
| [Agent SRE](agent-sre.md) | Kill switch, SLO monitoring, chaos testing | `pip install agent-sre` |
| [Agent Compliance](agent-compliance.md) | Audit logging, compliance frameworks | `pip install agent-governance-toolkit` |
| [Agent Marketplace](agent-marketplace.md) | Plugin governance, marketplace trust | `pip install agentmesh-marketplace` |
| [Agent Lightning](agent-lightning.md) | High-performance orchestration | `pip install agentmesh-lightning` |
| [Agent Hypervisor](agent-hypervisor.md) | Hardware-level workload isolation | `pip install agent-hypervisor` |
| [Agent Control Specification](agent-control-specification.md) | Stateless policy decision runtime for the AGT 5.0 policy layer | vendored in `policy-engine/` |

## Language Packages & Tooling

| Package | Language | Install |
|---------|---------|---------|
| [Antigravity CLI governance package](antigravity-cli-governance.md) | Antigravity CLI / Node.js | `npm install -g @microsoft/agent-governance-antigravity-cli && agt-antigravity install` |
| [OpenCode CLI governance package](opencode-governance.md) | OpenCode CLI / Node.js | `npm install @microsoft/agent-governance-opencode` |
| [.NET package](dotnet-sdk.md) | C# / .NET | `dotnet add package Microsoft.AgentGovernance` |
| [VS Code Extension](agent-os-vscode.md) | VS Code | Install from marketplace |
