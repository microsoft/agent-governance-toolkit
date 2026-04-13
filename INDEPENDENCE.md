<!--
  MIT License — Copyright (c) Microsoft Corporation.
-->

# Independence & Dependency Policy

The Agent Governance Toolkit is designed to be a **standalone governance standard** with zero vendor lock-in in its core packages.

## Core Independence Rule

> **No core package may import from any vendor framework at module level without a try/except guard.**

Core paths (`agent_os/`, `agentmesh/`, `agent_hypervisor/`, `agent_sre/`) must function with only standard-library and widely-adopted infrastructure dependencies (pydantic, cryptography, pyyaml).

## Package Independence Matrix

| Package | Hard Vendor Deps | Status |
|---------|-----------------|--------|
| **agent-os-kernel** (Python) | None — pydantic only | ✅ Independent |
| **agentmesh-platform** (Python) | None — pydantic + cryptography | ✅ Independent |
| **agent-hypervisor** (Python) | None — pydantic only | ✅ Independent |
| **agent-sre** (Python) | None — pydantic + structlog | ✅ Independent |
| **agent-governance-toolkit** (Python) | None — pydantic only | ✅ Independent |
| **agentmesh** (Rust) | None — pure crypto + serde | ✅ Independent |
| **agentmesh-mcp** (Rust) | None — pure crypto + serde | ✅ Independent |
| **agentmesh** (Go) | None — yaml.v3 only | ✅ Independent |
| **@microsoft/agentmesh-sdk** (TypeScript) | None — zero runtime deps | ✅ Independent |
| **Microsoft.AgentGovernance** (.NET) | None — YamlDotNet only | ✅ Independent |

## Adapter Pattern

Framework integrations are published as **separate packages** that depend on AGT core + the target framework. This keeps the core clean while enabling any ecosystem:

| Adapter Package | Framework | Install |
|-----------------|-----------|---------|
| `langchain-agentmesh` | LangChain | `pip install langchain-agentmesh` |
| `llamaindex-agentmesh` | LlamaIndex | `pip install llamaindex-agentmesh` |
| `crewai-agentmesh` | CrewAI | `pip install crewai-agentmesh` |
| `openai-agents-agentmesh` | OpenAI Agents | `pip install openai-agents-agentmesh` |
| `pydantic-ai-governance` | Pydantic AI | `pip install pydantic-ai-governance` |
| `aps-agentmesh` | APS | `pip install aps-agentmesh` |
| `scopeblind-protect-mcp` | ScopeBlind | `pip install scopeblind-protect-mcp` |

Adapters **must** use try/except for all framework imports so they fail gracefully when the framework isn't installed.

## Observability Integrations

`agent-sre` supports 12+ observability platforms as **optional dependencies**. None are required:

```bash
pip install agent-sre                    # Core only — zero vendor deps
pip install agent-sre[arize]             # + Arize Phoenix
pip install agent-sre[langfuse]          # + Langfuse
pip install agent-sre[wandb]             # + Weights & Biases
pip install agent-sre[datadog]           # + DataDog
pip install agent-sre[full]              # All integrations
```

All vendor integrations live under `agent_sre/integrations/` and use try/except import guards.

## Policy Engine Backends

The policy engine supports multiple backends without hard dependencies:

| Backend | Dependency | Required? |
|---------|-----------|-----------|
| Native YAML | Built-in | ✅ Always available |
| OPA/Rego | `opa` CLI (external) | Optional |
| Cedar | `cedarpy` | Optional |

## What This Means for Adopters

1. **`pip install agent-governance-toolkit`** gives you full governance with zero vendor deps
2. Add framework adapters only for frameworks you actually use
3. Core packages will never require LangChain, OpenAI, Anthropic, or any specific LLM provider
4. Rust, Go, .NET, and TypeScript SDKs follow the same zero-vendor-dep principle

## Contributing

When adding new code to core packages:
- ❌ Do not add vendor framework imports at module level
- ✅ Use try/except guards for any optional imports
- ✅ Place framework-specific code in `integrations/` directories or separate adapter packages
- ✅ Add new dependencies to `[project.optional-dependencies]`, not `[project.dependencies]`
