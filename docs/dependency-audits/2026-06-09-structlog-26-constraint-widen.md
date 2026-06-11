# Dependency Audit: structlog upper-bound widened to <27.0

**Date:** 2026-06-09
**PR:** fix/structlog-widen-to-27
**Files changed:** `agent-governance-toolkit-core/pyproject.toml`, `agent-discovery/pyproject.toml`, `agent-os/pyproject.toml`

## Dependencies changed

| Package | From | To | Reason |
|---|---|---|---|
| `structlog` (upper bound, core) | `<26.0` | `<27.0` | Enable Dependabot upgrades in agent-mesh (#2884) and agent-hypervisor (#2879) |
| `structlog` (upper bound, agent-discovery) | `<26.0` | `<27.0` | Consistency — same package ecosystem |
| `structlog` (upper bound, agent-os) | `<26.0` | `<27.0` | Consistency — same package ecosystem |

## Security advisory relevance

No CVEs associated with structlog 26.x. Structlog maintains API compatibility across major versions for the public logging interface used in these packages.

## Breaking change risk

**Risk: low.** structlog 26.x is backward-compatible with the `structlog.get_logger()` / `structlog.configure()` API used throughout this codebase. No behavior changes expected.

## Rollback plan

Revert the three `pyproject.toml` files to `structlog<26.0` and re-run tests.
