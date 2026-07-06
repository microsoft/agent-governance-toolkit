# Agent Governance Python

This directory is the top-level home for first-party published Python packages in the
Agent Governance Toolkit repository.

It exists to give Python the same contributor-facing repository shape as other standalone language
surfaces such as `agent-governance-dotnet/` and `agent-governance-golang/`, while still allowing
Python to publish multiple focused distributions instead of a single monolithic SDK package.

## Installing

The recommended install for most users is the meta-package, which pulls in the core runtime and lets you add framework integrations as extras:

```
pip install agent-governance-toolkit
pip install agent-governance-toolkit[langchain]
pip install agent-governance-toolkit[crewai]
pip install agent-governance-toolkit[openai-agents]
pip install agent-governance-toolkit[full]
```

If you only need a specific component, each package can also be installed on its own. See the package listing below for names.

## Scope

This directory is for published Python SDK and package surfaces, reusable foundational Python packages, and package-specific tests, metadata, and documentation.

It is not for applications or dashboards, demos or examples, monorepo-only product composition code, or framework-specific integration packages that are not part of the core first-party Python package story. Those surfaces belong in the repo root, `examples/`, `examples/demos/`, or other existing homes.

## Package Overview

**Core packages** are the runtime kernel, execution supervisor, sandbox, SRE layer, and shared primitives. Most users need only the meta-package or `agent-governance-toolkit-core` once the consolidation in issue #2482 lands.

**Framework integrations** live under `agentmesh-integrations/` and each wraps a specific framework like LangChain, CrewAI, LlamaIndex, or Haystack with AGT governance middleware.

**Agent OS modules** under `agent-os/modules/` are internal kernel primitives. They are not published to PyPI and are not intended for direct external consumption at this time.

## Current Packages

`agent-compliance/`, `agent-discovery/`, `agent-hypervisor/`, `agent-lightning/`, `agent-marketplace/`, `agent-mcp-governance/`, `agent-mesh/`, `agent-os/`, `agent-primitives/`, `agent-rag-governance/`, `agent-runtime/`, `agent-sandbox/`, `agent-sre/`, `agentmesh-integrations/`

## Package Consolidation (v4.1.0 — Complete)

As of v4.1.0, 45 packages have been consolidated into 5 top-level distributions: `agent-governance-toolkit-core`, `agent-governance-toolkit-runtime`, `agent-governance-toolkit-sre`, `agent-governance-toolkit-cli`, and the `agent-governance-toolkit[full]` meta-package. See [issue #2482](https://github.com/microsoft/agent-governance-toolkit/issues/2482) for details. The consolidation plan, audit data, and migration guide are in `docs/package-consolidation/`. Previous package names remain installable as stub packages that redirect to the consolidated distributions.
