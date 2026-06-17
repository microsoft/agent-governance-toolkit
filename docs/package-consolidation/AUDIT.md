# Python Package Audit: Agent Governance Toolkit

Tracks issue [#2482](https://github.com/microsoft/agent-governance-toolkit/issues/2482)
Audit date: 2026-05-23

## Summary

The repository contains 45 Python packages spread across two top-level groupings. Of these, 11 are confirmed on PyPI with meaningful download traffic. The remaining 34 exist in the repo but are either unpublished or receive negligible traffic. All packages are versioned at 3.7.0 except `cedarling-agentmesh` which sits at 3.5.0, already showing the version-skew problem this consolidation effort is trying to solve.

## PyPI-Published Packages

Download numbers are from pypistats.org (last 30 days).

| PyPI name | Downloads/month | Tier | Internal deps |
|-----------|----------------|------|---------------|
| `agent-governance-toolkit` | ~63,555 | meta installer | `agent-os-kernel`, `agentmesh-platform`, `agentmesh-runtime`, `agent-sre` as optional extras |
| `agent-os-kernel` | ~59,220 | core kernel | none |
| `agent-sandbox` | ~87,213 | core runtime | none |
| `agent-sre` | ~46,636 | core SRE | none |
| `agentmesh-runtime` | ~37,686 | core runtime | `agent-hypervisor` |
| `agentmesh-primitives` | ~19,944 | shared primitives | none |
| `agentmesh-mcp-trust` | ~774 | MCP governance | none |
| `agent-mcp-governance` | ~772 | MCP governance | `agent-os-kernel` |
| `agentmesh-marketplace` | ~1,442 | tooling | none |
| `agentmesh-drift` | ~750 | observability | none |
| `agentmesh-openai-agents-trust` | ~564 | integration | none |

## All Packages by Directory Group

### Core packages under `agent-governance-python/`

| Directory | PyPI name | Version | Description | On PyPI |
|-----------|-----------|---------|-------------|---------|
| `agent-compliance` | `agent-governance-toolkit` | 3.7.0 | Meta-package and unified installer | yes |
| `agent-primitives` | `agentmesh-primitives` | 3.7.0 | Shared primitive data models | yes |
| `agent-mesh` | `agentmesh-platform` | 3.7.0 | Secure nervous system for agent ecosystems | no |
| `agent-mesh/packages/mcp-trust-server` | `agentmesh-mcp-trust` | 3.7.0 | MCP trust server | yes |
| `agent-os` | `agent-os-kernel` | 3.7.0 | OS kernel for governing autonomous agents | yes |
| `agent-runtime` | `agentmesh-runtime` | 3.7.0 | Multi-agent session execution supervisor | yes |
| `agent-hypervisor` | `agent-hypervisor` | 3.7.0 | Runtime supervisor for Shared Sessions | no |
| `agent-sre` | `agent-sre` | 3.7.0 | Reliability engineering for AI agent systems | yes |
| `agent-sandbox` | `agent-sandbox` | 3.7.0 | Docker-based execution isolation for agents | yes |
| `agent-discovery` | `agentmesh-discovery` | 3.7.0 | Shadow AI agent discovery and inventory | no |
| `agent-lightning` | `agentmesh-lightning` | 3.7.0 | RL integration for governed training | no |
| `agent-marketplace` | `agentmesh-marketplace` | 3.7.0 | Plugin marketplace | yes |
| `agent-mcp-governance` | `agent-mcp-governance` | 3.7.0 | MCP governance primitives | yes |
| `agent-rag-governance` | `agent-rag-governance` | 3.7.0 | RAG pipeline policy enforcement | no |

### Agent OS Modules under `agent-governance-python/agent-os/modules/`

None of these 10 modules are published to PyPI. They appear to be internal kernel primitives not yet ready for external consumption.

| Module | PyPI name | Description |
|--------|-----------|-------------|
| `amb` | `agent-governance-toolkit-message-bus` | Broker-agnostic message bus for agents |
| `atr` | `agent-governance-toolkit-tool-registry` | Decentralized agent capability marketplace |
| `caas` | `agent-governance-toolkit-context` | Context routing and RAG window management |
| `cmvk` | `agent-governance-toolkit-drift` | Drift and hallucination score detection |
| `control-plane` | `agent-governance-toolkit-control-plane` | Deterministic governance kernel with POSIX signals |
| `emk` | `agent-governance-toolkit-memory` | Episodic Memory Kernel |
| `iatp` | `agent-governance-toolkit-trust-protocol` | Inter-Agent Trust Protocol sidecar |
| `mcp-kernel-server` | `agent-governance-toolkit-mcp-server` | MCP Server for Claude Desktop kernel primitives |
| `nexus` | `agent-governance-toolkit-nexus` | Agent Trust Exchange (research prototype) |
| `observability` | `agent-governance-toolkit-observability` | OTel traces, Prometheus metrics, Grafana dashboards |

### Framework Integrations under `agent-governance-python/agentmesh-integrations/`

| Package directory | PyPI name | Downloads/month | On PyPI |
|-------------------|-----------|----------------|---------|
| `a2a-protocol` | `a2a-agentmesh` | not tracked | no |
| `adk-agentmesh` | `adk-agentmesh` | not tracked | no |
| `agentmesh-avp` | `avp-agentmesh` | not tracked | no |
| `audit-accountability-export` | `agentmesh-audit-export` | not tracked | no |
| `cedarling-agentmesh` | `cedarling-agentmesh` | not tracked | no, v3.5.0 (behind core) |
| `crewai-agentmesh` | `crewai-agentmesh` | not tracked | no |
| `flowise-agentmesh` | `flowise-agentmesh` | not tracked | no |
| `haystack-agentmesh` | `haystack-agentmesh` | ~698 | yes |
| `langchain-agentmesh` | `agentmesh-langchain` | not tracked | no |
| `langflow-agentmesh` | `langflow-agentmesh` | not tracked | no |
| `langgraph-trust` | `langgraph-agentmesh` | ~752 | yes |
| `llamaindex-agentmesh` | `llamaindex-agentmesh` | not tracked | no |
| `mcp-receipt-governed` | `agentmesh-mcp-receipts` | not tracked | no |
| `mcp-trust-proxy` | `agentmesh-mcp-proxy` | not tracked | no |
| `nostr-wot` | `nostr-wot-agentmesh` | ~753 | yes |
| `openai-agents-agentmesh` | `openai-agents-agentmesh` | ~764 | yes |
| `openai-agents-trust` | `agentmesh-openai-agents-trust` | ~564 | yes |
| `openshell-skill` | `openshell-agentmesh` | ~713 | yes |
| `pydantic-ai-governance` | `pydantic-ai-agentmesh` | ~527 | yes |
| `structural-authz-agentmesh` | `structural-authz-agentmesh` | ~511 | yes |
| `template-agentmesh` | `template-agentmesh` | not tracked | no |

## Internal Dependency Graph

```
agent-governance-toolkit (meta)
    [extra: kernel]   agent-os-kernel
    [extra: mesh]     agentmesh-platform
    [extra: runtime]  agentmesh-runtime
                          agent-hypervisor
    [extra: sre]      agent-sre
    [extra: cedar]    cedarpy (external)

agent-mcp-governance
    agent-os-kernel

cedarling-agentmesh
    agent-os-kernel

agent-governance-toolkit-nexus
    agent-governance-toolkit-trust-protocol
        agentmesh-primitives
```

All framework integrations are leaf packages. They depend on external frameworks like langchain and crewai but declare no internal AGT dependencies in their `pyproject.toml`. They consume AGT APIs at runtime via optional imports.

## Version Skew

Every package is at 3.7.0 except `cedarling-agentmesh` which is at 3.5.0. That 0.2 version lag is exactly the kind of cross-package drift the issue warns about. Right now it is just one package. With 45 `pyproject.toml` files to bump manually on every release, this will happen again.

## Key Findings

**34 packages have no measurable PyPI presence.** They are either unpublished or receive traffic too low for pypistats to register. Folding them into consolidated distributions is straightforward since there are no existing consumers to break.

**Five packages drive almost all downloads.** `agent-sandbox` at 87K, `agent-governance-toolkit` at 63K, `agent-os-kernel` at 59K, `agent-sre` at 46K, and `agentmesh-runtime` at 37K together account for the vast majority of monthly installs. Any consolidation must preserve these package names or provide clear aliases.

**Framework integrations are small but uniform.** Each integration gets 500 to 760 downloads per month and all follow the same structural pattern. Shipping them as extras on a single distribution rather than 21 separate packages cuts the release overhead significantly with no real downside for users.

**Agent OS modules are entirely unpublished.** All 10 modules under `agent-os/modules/` have no PyPI presence and are likely not ready for external use. They should stay internal and not be part of the first consolidation pass.

**Naming is inconsistent.** Packages use `agent_*`, `agentmesh_*`, `a2a_*`, `avp_*`, `cedarling_*`, and `nostr_*` prefixes with no shared namespace. The consolidation is a good time to fix this by moving everything under the `agent-governance-toolkit-*` prefix.
