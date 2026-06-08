# Dependency Audit: @typescript-eslint/parser 8.60.0 to 8.60.1

**Date:** 2026-06-03
**PR:** #2826
**Lockfiles changed:** `agent-governance-typescript/package-lock.json`

## Dependencies changed

| Package | From | To | Reason |
|---|---|---|---|
| `@typescript-eslint/parser` | 8.60.0 | 8.60.1 | Routine patch bump by Dependabot |

## Security advisory relevance

No CVEs are associated with this change. This is a dev dependency; no shipped runtime code is affected.

## Breaking change risk

**Risk: low.** Patch-level bump within the same minor. No API changes expected.

## Rollback plan

Revert `package-lock.json` in `agent-governance-typescript` to the prior version and re-run `npm install`.