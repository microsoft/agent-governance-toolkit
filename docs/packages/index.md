---
title: Packages
last_reviewed: 2026-08-03
owner: docs-team
---

# Packages

AGT publishes a small set of canonical package families. Most Python users
should start with the toolkit; choose a narrower package only for a specific
runtime surface or language SDK.

!!! important "Public Preview"
    Package APIs may change before general availability. Use the canonical names
    below for new projects. Older component names remain as temporary
    compatibility packages.

## Python toolkit

The meta-package is the recommended starting point. Its `[full]` extra installs
the core runtime, framework integrations, CLI tools, and protocol packages used
by the convenience-wrapper examples.

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
runtime primitives. It provides the current implementation behind the legacy
`agent_os`, `agentmesh`, runtime, and hypervisor imports.

```bash
pip install agent-governance-toolkit-core
```

Source: `agent-governance-python/agent-governance-toolkit-core`

## Framework integrations

`agent-governance-toolkit-integrations` contains optional adapters, so the core
package does not install every framework dependency.

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

Agent Control Specification, or ACS, is AGT's canonical stateless policy
decision runtime. Python hosts use the native SDK to load manifests, build
snapshots, call ACS, and enforce verdicts.

```bash
pip install agent-control-specification
```

`agt-policies` now ships the one-way `agt migrate v4-to-v5` conversion tool. See
the [ACS package guide](agent-control-specification.md).

## Language SDKs

| SDK | Install | Source |
|---|---|---|
| TypeScript | `npm install @microsoft/agent-governance-sdk` | `agent-governance-typescript/` |
| .NET | `dotnet add package Microsoft.AgentGovernance` | `agent-governance-dotnet/` |
| Rust | `cargo add agentmesh` | `agent-governance-rust/agentmesh/` |
| Rust MCP | `cargo add agentmesh-mcp` | `agent-governance-rust/agentmesh-mcp/` |
| Go | `go get github.com/microsoft/agent-governance-toolkit/agent-governance-golang` | `agent-governance-golang/` |

## Other shipped surfaces

Some Python packages, developer tools, ACS SDKs, and OCI images remain separate
where consolidation would obscure their lifecycle or intended consumer.

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
