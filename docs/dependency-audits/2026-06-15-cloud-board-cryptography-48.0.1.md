# Dependency Audit: cryptography 46.0.7 to 48.0.1 (agent-os cloud-board service)

**Date:** 2026-06-15
**PR:** #3036
**Lockfiles changed:** `agent-governance-python/agent-os/services/cloud-board/requirements.txt`

## Dependencies changed

| Package | From | To | Reason |
|---|---|---|---|
| `cryptography` | 46.0.7 | 48.0.1 | Routine Dependabot bump |

## Security advisory relevance

No specific CVE motivates this bump. cryptography 48.0.1 is a maintenance release in the 48.x series. Keeping the cryptography package current is good hygiene for a governance framework — the library underpins TLS, key operations, and certificate handling throughout the agent-os stack.

## Breaking change risk

**Risk: low.** The cloud-board service uses cryptography for standard TLS and certificate operations. The 46.x to 48.x range follows semantic versioning; no breaking API changes affect the surface used here. The 7-day cooling-off gate provides additional assurance before merge.

## Rollback plan

Revert `agent-governance-python/agent-os/services/cloud-board/requirements.txt` to pin `cryptography==46.0.7`.
