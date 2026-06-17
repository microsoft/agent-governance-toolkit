# Dependency Audit: @typescript-eslint/parser 8.60.1 to 8.61.0 (mcp-server)

**Date:** 2026-06-11
**PR:** #2889
**Lockfiles changed:** `agent-governance-python/agent-os/extensions/mcp-server/package-lock.json`

## Dependencies changed

| Package | From | To | Reason |
|---|---|---|---|
| `@typescript-eslint/parser` | 8.60.1 | 8.61.0 | Routine minor bump by Dependabot |

## Security advisory relevance

No CVEs associated with this change. Dev-only linting dependency; no shipped runtime code affected.

## Breaking change risk

**Risk: low.** Minor bump within the same major. No user-facing API changes expected for a linting tool.

## Rollback plan

Revert `agent-governance-python/agent-os/extensions/mcp-server/package-lock.json` to the prior version and re-run `npm install` in `agent-governance-python/agent-os/extensions/mcp-server`.
