---
title: Packages
last_reviewed: 2026-07-15
owner: docs-team
---

# Packages

AGT ships a small set of canonical package families. Start with the Python
toolkit unless you need one specific runtime surface or another language SDK.

!!! important "Public Preview"
    Package APIs may change before general availability. Prefer the canonical
    names below for new projects; older component names remain compatibility
    packages during migration.

## Python toolkit

The meta-package is the recommended starting point. The `[full]` extra installs
the core runtime, framework integrations, CLI tools, and protocol surfaces used
throughout the documentation.

```bash
pip install "agent-governance-toolkit[full]"
```

Use a smaller extra when one framework is enough:

```bash
pip install "agent-governance-toolkit[langchain]"
pip install "agent-governance-toolkit[crewai]"
pip install "agent-governance-toolkit[openai-agents]"
```

Source: `agent-governance-python/agent-compliance`

## Python core

`agent-governance-toolkit-core` contains policy, trust, identity, audit, and
runtime primitives. It is the current distribution behind the legacy
`agent_os`, `agentmesh`, runtime, and hypervisor compatibility imports.

```bash
pip install agent-governance-toolkit-core
```

Source: `agent-governance-python/agent-governance-toolkit-core`

## Framework integrations

`agent-governance-toolkit-integrations` packages optional adapters without
forcing every framework dependency into the core installation.

```bash
pip install "agent-governance-toolkit-integrations[langchain]"
pip install "agent-governance-toolkit-integrations[crewai,openai-agents]"
```

Available extras include LangChain, CrewAI, OpenAI Agents, LangGraph,
LlamaIndex, Haystack, PydanticAI, Google ADK, Cedarling, and OpenShell.

Source: `agent-governance-python/agent-governance-toolkit-integrations`

## CLI and operations

`agent-governance-toolkit-cli` contains operator commands, SRE and
observability tooling, sandbox integrations, and MCP trust services.

```bash
pip install agent-governance-toolkit-cli
```

Source: `agent-governance-python/agent-governance-toolkit-cli`

## Protocol governance

`agent-governance-toolkit-protocols` contains governance surfaces for MCP, A2A,
trust protocols, and verifiable MCP receipts.

```bash
pip install agent-governance-toolkit-protocols
```

Source: `agent-governance-python/agent-governance-toolkit-protocols`

## Agent Control Specification

Agent Control Specification, or ACS, is the stateless policy decision runtime.
Use it when a host needs deterministic intervention-point verdicts without the
full Python runtime.

```bash
pip install agent-control-specification
```

See the [ACS package guide](agent-control-specification.md).

## Language SDKs

| SDK | Install | Source |
|---|---|---|
| TypeScript | `npm install @microsoft/agent-governance-sdk` | `agent-governance-typescript/` |
| .NET | `dotnet add package Microsoft.AgentGovernance` | `agent-governance-dotnet/` |
| Rust | `cargo add agentmesh` | `agent-governance-rust/agentmesh/` |
| Rust MCP | `cargo add agentmesh-mcp` | `agent-governance-rust/agentmesh-mcp/` |
| Go | `go get github.com/microsoft/agent-governance-toolkit/agent-governance-golang` | `agent-governance-golang/` |

## Other shipped surfaces

Standalone Python packages, developer-tool integrations, ACS SDKs, and OCI
images remain separate where consolidation would obscure their lifecycle or
consumer. The authoritative identity and migration map is
[`../package-migration.md`](../package-migration.md).

## Status labels

| Status | Meaning |
|---|---|
| Shipped | Released in a current package and covered by package-local validation. |
| Compatibility | Existing Microsoft-origin or legacy package identity retained temporarily. |
| Experimental | Runnable but not guaranteed stable. |
| Proposed | ADR/RFC/spec exists but implementation is not a shipped guarantee. |
| Vendor integration | Requires a vendor product, account, or platform. |

Package pages should use these labels when a capability is not part of the
canonical core release.

## Compatibility and migration

Legacy distributions such as `agent-os-kernel`, `agentmesh-platform`,
`agentmesh-runtime`, `agent-sre`, and `agent-hypervisor` are not recommended for
new projects. Their compatibility pages remain available because existing
imports and installations still need migration guidance.

Use [`../package-migration.md`](../package-migration.md) before changing package
names, install snippets, release workflow matrices, or registry metadata.
