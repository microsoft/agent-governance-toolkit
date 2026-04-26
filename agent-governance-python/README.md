# Agent Governance Python

This directory is the top-level home for first-party published Python packages in the
Agent Governance Toolkit repository.

It exists to give Python the same contributor-facing repository shape as other standalone language
surfaces such as `agent-governance-dotnet/` and `agent-governance-golang/`, while still allowing
Python to publish multiple focused distributions instead of a single monolithic SDK package.

## Scope

This directory is for:

- published Python SDK/package surfaces
- reusable foundational Python packages
- package-specific tests, metadata, and documentation

This directory is **not** for:

- applications or dashboards
- demos or examples
- monorepo-only product composition code
- framework-specific integration packages that are not part of the core first-party Python package story

Those surfaces should stay in the repo root, `examples/`, `demo/`, or other existing homes.

## Current Packages

- `agent-primitives/`
- `agent-mcp-governance/`
