# Packages

AGT provides 11 packages covering every layer of agent governance.

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
| Agent Lightning  |     | Agent Hypervisor |     |   SDK Packages   |
|  High-perf       |     |  HW isolation    |     |  .NET, TS, Rust  |
|  orchestration   |     |  for workloads   |     |  Go, VS Code     |
+------------------+     +------------------+     +------------------+
```

## Core Packages

| Package | Description | Install |
|---------|------------|---------|
| [Agent OS](agent-os.md) | Policy engine, agent lifecycle, governance gate | `pip install agent-os` |
| [Agent Mesh](agent-mesh.md) | Agent discovery, routing, trust mesh | `pip install agent-mesh` |
| [Agent Runtime](agent-runtime.md) | Execution sandboxing, four privilege rings | `pip install agent-runtime` |
| [Agent SRE](agent-sre.md) | Kill switch, SLO monitoring, chaos testing | `pip install agent-sre` |
| [Agent Compliance](agent-compliance.md) | Audit logging, compliance frameworks | `pip install agent-compliance` |
| [Agent Marketplace](agent-marketplace.md) | Plugin governance, marketplace trust | `pip install agent-marketplace` |
| [Agent Lightning](agent-lightning.md) | High-performance orchestration | `pip install agent-lightning` |
| [Agent Hypervisor](agent-hypervisor.md) | Hardware-level workload isolation | `pip install agent-hypervisor` |

## SDK Packages

| Package | Language | Install |
|---------|---------|---------|
| [.NET SDK](agent-governance-dotnet.md) | C# / .NET | `dotnet add package AgentGovernance` |
| [VS Code Extension](agent-os-vscode.md) | VS Code | Install from marketplace |
