# Dependency Audit: flowise-governance example requirements.txt

**Date:** 2026-06-17
**PR:** #3105
**Lockfiles changed:** `examples/flowise-governance/requirements.txt`

## Dependencies added

| Package | Version | Reason |
|---|---|---|
| `flowise-agentmesh` | (latest) | First-party AGT package providing GovernanceNode, AuditNode, RateLimiterNode, TrustGateNode for the Flowise sidecar example |
| `fastapi` | `>=0.115.0` | HTTP framework for the governance sidecar server |
| `uvicorn[standard]` | `>=0.27.0` | ASGI server to run the FastAPI sidecar |

## Security advisory relevance

No CVEs involved. All three packages are well-established:

- `flowise-agentmesh` is a first-party package in this repo (registered in the dep-confusion allowlist).
- `fastapi` and `uvicorn` are already runtime dependencies of `agent-governance-toolkit-core` and `agent-mesh`; their version floors here match the existing pinning in those packages.

## Breaking change risk

**Risk: none.** This is a new `examples/` directory. No existing package or CI job depends on it. The requirements file is only used by developers following the Flowise quickstart guide.

## Rollback plan

Delete `examples/flowise-governance/requirements.txt`. The governance sidecar will not start without these packages but no other component is affected.
