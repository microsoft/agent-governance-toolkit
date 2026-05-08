# Agent Governance Python — Coding Agent Instructions

## Project Overview

`agent-governance-python/` is the top-level home for first-party **published Python packages**
in Agent Governance Toolkit. Use this directory for reusable SDK/package surfaces that are meant
to be consumed directly by external Python users.

Applications, dashboards, demos, and larger runtime/product assemblies should stay in
the repo root, `examples/`, or other existing homes unless maintainers explicitly decide to promote
them into this package workspace.

## Key Paths

| Path | Purpose |
|------|---------|
| `agent-primitives/` | Shared foundational Python primitives package |
| `agent-mcp-governance/` | Published MCP governance facade package |

## Routing Rules

- Prefer this directory for first-party Python packages that are published independently.
- Keep package names, import paths, and release metadata aligned with the actual published surface.
- Do not move apps or monorepo-only tooling here just for symmetry.
- If a package is foundational and consumed across multiple Python surfaces, prefer extracting it
  here rather than nesting it under a larger application/runtime package.

## Validation

- Run the narrowest package-local checks for the package you changed.
- If a package here is consumed by `agent-governance-python/agent-os/`, verify that consumer still installs and
  imports correctly after your changes.
