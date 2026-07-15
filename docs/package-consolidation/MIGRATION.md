---
title: "Migration Plan: Package Consolidation"
last_reviewed: 2026-05-24
owner: agt-maintainers
---

# Migration Plan: Package Consolidation

Tracks issue [#2482](https://github.com/microsoft/agent-governance-toolkit/issues/2482)
Date: 2026-05-23

## Guiding Principle

No existing install command should break. Users who have `agent-os-kernel` or `agentmesh-runtime` in their requirements files today must still get a working install after consolidation. This is handled through stub packages that redirect pip installs to the new distributions.

## Phase 1: Stub Packages

Before the new distributions are published, a stub package is published under each old name that declares the new package as its only dependency. This means someone pinned to `agentmesh-runtime==3.7.0` will install the stub, which pulls in `agent-governance-toolkit-core`, and their code continues to work.

Example stub `pyproject.toml` for `agentmesh-runtime`:

```toml
[project]
name = "agentmesh-runtime"
version = "4.0.0"
description = "Deprecated. Replaced by agent-governance-toolkit-core."
dependencies = ["agent-governance-toolkit-core>=4.0.0"]
```

The stub packages are published at the same time as the first release of the consolidated distributions so there is no window where one exists and the other does not.

## Phase 2: Deprecation Warnings

Once stubs are live, any import of a deprecated package name at runtime emits a `DeprecationWarning` pointing to the replacement. This gives developers who install via stubs a clear signal to update their requirements files without breaking their builds.

```python
import warnings
warnings.warn(
    "agentmesh-runtime is deprecated. Use agent-governance-toolkit-core instead. "
    "See https://github.com/microsoft/agent-governance-toolkit/blob/main/docs/package-consolidation/MIGRATION.md",
    DeprecationWarning,
    stacklevel=2,
)
```

The warning ships in the first consolidated release and stays present for at least two minor versions before the stub is marked unsupported.

## Phase 3: Stub Removal

After two minor release cycles, roughly 6 months at the normal AGT release cadence, the stub packages are yanked from PyPI. The deprecation warnings make the removal unsurprising for anyone who has run their tests recently.

## Package Mapping

The table below lists every package being consolidated and its replacement.

| Old package name | Replacement | Stub needed |
|-----------------|-------------|-------------|
| `agent-os-kernel` | `agent-governance-toolkit-core` | yes |
| `agentmesh-platform` | `agent-governance-toolkit-core` | yes |
| `agentmesh-runtime` | `agent-governance-toolkit-core` | yes |
| `agent-hypervisor` | `agent-governance-toolkit-core` | yes |
| `agentmesh-primitives` | `agent-governance-toolkit-core` | yes |
| `agentmesh-langchain` | `agent-governance-toolkit-integrations[langchain]` | yes |
| `crewai-agentmesh` | `agent-governance-toolkit-integrations[crewai]` | yes |
| `openai-agents-agentmesh` | `agent-governance-toolkit-integrations[openai-agents]` | yes |
| `agentmesh-openai-agents-trust` | `agent-governance-toolkit-integrations[openai-agents]` | yes |
| `langgraph-agentmesh` | `agent-governance-toolkit-integrations[langgraph]` | yes |
| `llamaindex-agentmesh` | `agent-governance-toolkit-integrations[llamaindex]` | yes |
| `haystack-agentmesh` | `agent-governance-toolkit-integrations[haystack]` | yes |
| `pydantic-ai-agentmesh` | `agent-governance-toolkit-integrations[pydantic-ai]` | yes |
| `flowise-agentmesh` | `agent-governance-toolkit-integrations[flowise]` | yes |
| `langflow-agentmesh` | `agent-governance-toolkit-integrations[langflow]` | yes |
| `adk-agentmesh` | `agent-governance-toolkit-integrations[adk]` | yes |
| `avp-agentmesh` | `agent-governance-toolkit-integrations[avp]` | yes |
| `cedarling-agentmesh` | `agent-governance-toolkit-integrations[cedarling]` | yes |
| `nostr-wot-agentmesh` | `agent-governance-toolkit-integrations[nostr-wot]` | yes |
| `structural-authz-agentmesh` | `agent-governance-toolkit-integrations[structural-authz]` | yes |
| `openshell-agentmesh` | `agent-governance-toolkit-integrations[openshell]` | yes |
| `agentmesh-audit-export` | `agent-governance-toolkit-integrations[audit-export]` | no (unpublished) |
| `agent-sre` | `agent-governance-toolkit-cli` | yes |
| `agent-sandbox` | `agent-governance-toolkit-cli` | yes |
| `agentmesh-mcp-proxy` | `agent-governance-toolkit-cli` | no (unpublished) |
| `agentmesh-mcp-server` | `agent-governance-toolkit-cli` | no (unpublished) |
| `agentmesh-mcp-trust` | `agent-governance-toolkit-cli` | yes |
| `agent-mcp-governance` | `agent-governance-toolkit-protocols` | yes |
| `agentmesh-trust-protocol` | `agent-governance-toolkit-protocols` | no (unpublished) |
| `a2a-agentmesh` | `agent-governance-toolkit-protocols` | no (unpublished) |
| `agentmesh-mcp-receipts` | `agent-governance-toolkit-protocols` | no (unpublished) |

Packages in the standalone category (`agent-discovery`, `agentmesh-lightning`, `agent-rag-governance`, `agentmesh-drift`, `agentmesh-observability`, `agentmesh-marketplace`) are not being consolidated and do not appear in this table.

## Import Compatibility

Where two old packages merge into one distribution, the public Python module names and class names must not change. Users import classes directly, not package metadata names. Moving code between distributions is fine as long as existing import paths keep working.

If a module path must change, add a compatibility shim at the old location:

```python
# agentmesh/openai_agents_trust/__init__.py  (compatibility shim)
import warnings
from agentmesh.integrations.openai_agents import *  # noqa: F401, F403

warnings.warn(
    "agentmesh.openai_agents_trust is deprecated. Import from agentmesh.integrations.openai_agents.",
    DeprecationWarning,
    stacklevel=2,
)
```

## Version Numbering

The consolidated packages start at version 4.0.0. The major bump signals the restructuring and gives dependency management tools a clear signal to review the update. Stub packages that redirect old names also publish at 4.0.0 for consistency.

## Rollout Order

Implement `agent-governance-toolkit-core` first since it covers the packages with the highest download counts and the clearest scope. Publish stubs for all packages absorbed into core at the same time. Once core is stable, implement `agent-governance-toolkit-integrations` and publish its stubs simultaneously. Follow with `agent-governance-toolkit-cli` and `agent-governance-toolkit-protocols`. After two minor releases, yank the stubs for core and integrations.
