# Dependency Audit: agent-governance-toolkit >=4.0.0 to >=4.1.0 (agent-compliance examples)

**Date:** 2026-06-12
**PR:** #2980
**Lockfiles changed:** `agent-governance-python/agent-compliance/examples/requirements.txt`

## Dependencies changed

| Package | From | To | Reason |
|---|---|---|---|
| `agent-governance-toolkit` | `>=4.0.0` | `>=4.1.0` | Routine floor bump by Dependabot to align the agent-compliance examples with the current published umbrella package version |

## Security advisory relevance

No CVEs involved. `agent-governance-toolkit` is the first-party umbrella package (registered in the dependency-confusion allowlist). This only raises the minimum version floor in an examples requirements file.

## Breaking change risk

**Risk: low.** Floor bump within the same major series (`>=4.1.0` still `<5` by the package's own constraints). Affects only the example install instructions under `agent-compliance/examples/`, not any shipped package's runtime dependencies.

## Rollback plan

Revert `agent-governance-python/agent-compliance/examples/requirements.txt` to `agent-governance-toolkit>=4.0.0`.
