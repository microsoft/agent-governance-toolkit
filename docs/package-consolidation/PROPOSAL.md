---
title: "Package Consolidation Proposal"
last_reviewed: 2026-05-24
owner: agt-maintainers
---

# Package Consolidation Proposal

Tracks issue [#2482](https://github.com/microsoft/agent-governance-toolkit/issues/2482)
Date: 2026-05-23

## Problem

The repo ships 45 Python packages, 11 of which have any PyPI presence. Maintaining 45 separate `pyproject.toml` files, version pins, and CI jobs for packages that get under 1000 downloads a month creates overhead without proportional value. The `cedarling-agentmesh` version lag (3.5.0 vs core 3.7.0) is an early warning of what happens as the package count grows.

See [AUDIT.md](AUDIT.md) for the full data behind this proposal.

## Proposed Structure

The goal is to go from 45 packages to 5 top-level distributions, with framework integrations as optional extras on a single integrations package rather than 21 separate ones.

### Package 1: `agent-governance-toolkit`

This package already exists and already uses optional extras. It stays as-is and becomes the single recommended install entry point. The extras list expands to cover all integrations that today ship as standalone packages.

```
pip install agent-governance-toolkit
pip install agent-governance-toolkit[langchain]
pip install agent-governance-toolkit[crewai]
pip install agent-governance-toolkit[openai-agents]
pip install agent-governance-toolkit[full]
```

### Package 2: `agent-governance-toolkit-core`

Consolidates the runtime kernel packages that currently require separate installs. Absorbs `agent-os-kernel`, `agentmesh-primitives`, `agentmesh-runtime`, `agent-hypervisor`, and `agentmesh-platform`. This is the policy engine, trust scoring, audit, identity, and execution ring layer. Everything needed to govern an agent programmatically without a CLI or framework adapter.

### Package 3: `agent-governance-toolkit-integrations`

A single distribution for all framework adapters. Each adapter ships as an optional extra so users only pull in what they need. Absorbs all 21 packages under `agentmesh-integrations/` including langchain, crewai, openai-agents, langgraph, llamaindex, haystack, pydantic-ai, flowise, langflow, and adk. Adapters with independent community adoption above 5000 downloads per month are evaluated individually before folding in.

### Package 4: `agent-governance-toolkit-cli`

CLI tools and proxy servers that operators install on infrastructure rather than in application code. Absorbs `agent-sre`, `agent-sandbox`, `agentmesh-mcp-proxy`, `agentmesh-mcp-server`, and `agentmesh-mcp-trust`.

### Package 5: `agent-governance-toolkit-protocols`

Protocol implementations that may have consumers outside of AGT. Absorbs `agent-mcp-governance`, `agentmesh-trust-protocol`, `a2a-agentmesh`, and `agentmesh-mcp-receipts`. These are kept separate because protocol packages sometimes get pinned independently by downstream consumers who do not want the full governance stack.

### Packages that stay standalone

`agent-discovery`, `agentmesh-lightning`, `agent-rag-governance`, `agentmesh-drift`, `agentmesh-observability`, and `agentmesh-marketplace` stay as standalone packages for now. Their scope is focused enough that pulling them into a larger distribution adds confusion without meaningfully reducing maintenance burden.

The 10 Agent OS kernel modules (`agentmesh-message-bus`, `agentmesh-tool-registry`, `agentmesh-context`, `agentmesh-control-plane`, `agentmesh-memory`, `agentmesh-nexus`, and others) are not published today and should remain internal until they have a clearer external use case.

## Naming

All new package names use the `agent-governance-toolkit-*` prefix. This resolves the inconsistency where packages currently span `agent_*`, `agentmesh_*`, `avp_*`, `cedarling_*`, and `nostr_*` with no shared namespace.

## What Does Not Change

Source code does not move. The directory layout under `agent-governance-python/` stays the same. Only packaging metadata changes: `pyproject.toml` files in absorbed packages are updated to declare their content as part of the parent distribution, and old package names become thin aliases via the migration plan in [MIGRATION.md](MIGRATION.md).

## Before Implementing

This proposal requires a community feedback period per the [RFC process](../RFC_PROCESS.md). Open a discussion on the issue before merging any code changes. The minimum review window is 7 days.
