# 2026-05-30 — Entra-signed JWT verification for AgentMesh relay + registry

PR: [microsoft/agent-governance-toolkit#2659](https://github.com/microsoft/agent-governance-toolkit/pull/2659)

## What changed and why

This PR adds **opt-in Entra-signed JWT verification** to the AgentMesh
relay and registry so peers can register and connect under a
cryptographically verifiable identity (Entra tenant + `appid`) instead
of the existing anonymous-tier registration path. Closes the gap
between the mesh SDK (which has been attempting verified-tier
registration via `MeshClient.verify()` since v3.5) and the server side,
which until now ignored the presented JWT.

The change is **opt-in everywhere**. With `AGENTMESH_ENTRA_AUDIENCE` /
`AGENTMESH_ENTRA_TENANT_ID` unset, the relay and registry preserve
byte-identical pre-v3.7.x behavior (anonymous tier; shared-secret auth
or open accept on the relay; no verify endpoint on the registry).

### Files touched (capability-path scope)

| File | Change |
|------|--------|
| `agent-governance-python/agent-mesh/src/agentmesh/identity/entra_verifier.py` | New module — JWKS fetcher + RS256/RS384/RS512 signature verifier with `aud`, `tid`, `exp`, `iat` claim enforcement, JWKS caching with hard staleness ceiling, header-`alg` pre-validation against an allowlist. |
| `agent-governance-python/agent-mesh/src/agentmesh/relay/app.py` | Three-mode connect-frame auth: Entra → shared-secret → open. When Entra is enabled, an empty/missing `token` is rejected immediately. The new mode is **orthogonal to** and runs **after** the upstream DID-PoP gate. |
| `agent-governance-python/agent-mesh/src/agentmesh/registry/app.py` | New `POST /v1/registry/verify` endpoint that upgrades an agent from `tier: anonymous` to `tier: verified` after JWT verification. Stamps `verified_app_id`, `verified_tenant_id`, `verified_at` on the agent record. Also adds per-agent session counters (`total_sessions`, `successful_sessions`, `failed_sessions`, `timeout_sessions`, `completion_rate`) that are bumped by both the existing reputation endpoints. |

## Threat model impact

| Dimension | Direction |
|---|---|
| **Peer identity verification** | **Strengthened (when opt-in).** Previously the relay had no way to bind a connecting peer's DID to a verifiable identity. With Entra verification enabled, the relay rejects WebSocket connects without a valid Entra-signed JWT and stamps `appid` on the connection for trust-scoring downstream. |
| **Auth bypass surface** | **Closed.** The connect-handler restructure (`if Entra → require token; elif legacy → shared-secret`) eliminates the silent fall-through that the original PR had where an empty/missing token would skip Entra verification and land on the legacy shared-secret check (raised in review and fixed in commit `324f270d`). |
| **JWKS poisoning / stale-key reuse** | **Bounded.** Refetch failures fall back to the cached JWKS for availability, but only within a hard `AGENTMESH_ENTRA_JWKS_MAX_STALE_SECS` budget (default 24h). Beyond the budget, the verifier drops the stale client and fails closed. This bounds the window in which a key rotated OUT of the live JWKS can still verify a token. |
| **Algorithm confusion** | **Defended.** Header `alg` is pre-validated against `ALLOWED_SIGNING_ALGORITHMS` (`RS256`/`RS384`/`RS512`) **before** the JWKS lookup. PyJWT's `algorithms=` parameter would also reject it inside `decode()`, but the pre-check (a) avoids a wasted JWKS network round-trip on obviously-bad tokens and (b) makes the defense visible in our code path rather than relying on a downstream library's allowlist. |
| **Self-reporting reputation** | **Already mitigated upstream.** Reputation endpoints now require `Ed25519-Timestamp` auth (upstream `main`, predates this PR) and reject self-reporting. This PR's session-counter additions inherit that auth contract. |
| **Backward compatibility** | **Preserved.** Both `AGENTMESH_ENTRA_AUDIENCE` and `AGENTMESH_ENTRA_TENANT_ID` must be set for verification to be enabled. With either unset, the relay's pre-existing shared-secret + open-accept paths are reached unchanged. The registry's `/v1/registry/verify` returns 503 when the verifier is disabled. |
| **Fail-closed contract** | **Honored everywhere.** Verifier-init failure (e.g. JWKS unreachable on cold cache) returns 503 from the registry and closes the WebSocket with code 4003 on the relay — never silently downgrades to a weaker auth path. |

### Specific mitigations applied

- **Hard JWKS staleness ceiling** (`AGENTMESH_ENTRA_JWKS_MAX_STALE_SECS`, default 86400s, floors at `JWKS_TTL_SECS`). Closes [PR review point 1](https://github.com/microsoft/agent-governance-toolkit/pull/2659#pullrequestreview-…) — stale cache had no upper bound, signing keys rotated out of Entra could be reused indefinitely.
- **Connect-frame token-required check** when Entra is enabled. Closes PR review point 2 — empty/missing `token` no longer falls through to the legacy shared-secret path.
- **Header `alg` pre-validation** against the explicit allowlist. Closes PR review point 3 — defense-in-depth against algorithm-confusion exploit shapes.
- **Verifier-init failure fail-closed.** Even when both Entra is enabled AND `AGENTMESH_RELAY_TOKEN` is set, a verifier-init failure does not downgrade to the shared-secret path. An attacker who can trigger JWKS unreachability does not get a weaker auth surface as a result.
- **DID PoP independence.** The new Entra branch runs **after** the upstream `_REQUIRE_DID_POP` check. The two gates are orthogonal — PoP binds the WebSocket to the private-key holder (identity layer); Entra/shared-secret authenticates the token (token layer). Either can be disabled without weakening the other.

### Specific bypass tests (regression guards)

- **`TestEntraAuthBypassFix::test_missing_token_field_rejected_when_entra_enabled`** — connect with `{from: ..., (no token)}` must be rejected with `Authentication required (Entra)` and WebSocket code 4003.
- **`TestEntraAuthBypassFix::test_empty_token_rejected_when_entra_enabled`** — `token: ""`.
- **`TestEntraAuthBypassFix::test_null_token_rejected_when_entra_enabled`** — `token: null`.
- **`TestEntraAuthBypassFix::test_verifier_init_failure_fails_closed`** — even with `_RELAY_TOKEN` set, verifier-init failure does NOT silently downgrade to the shared-secret path.
- **`TestEntraAuthBypassFix::test_shared_secret_still_works_when_entra_disabled`** — backward-compat guard: when Entra is OFF, the legacy shared-secret path behaves identically.
- **`TestAlgConfusionGuard::test_hs256_token_rejected_before_jwks_lookup`** — hand-crafted HS256 token (PyJWT refuses to encode HS256 with a PEM key, mirroring the attacker's wire-format path). Asserts the JWKS resolver is **never** called.
- **`TestAlgConfusionGuard::test_none_alg_token_rejected_before_jwks_lookup`** — CVE-2022-29217 class.
- **`TestJwksStaleCeiling::test_stale_serve_beyond_budget_fails_closed`** — cache aged 25h, refetch throws, MUST raise + drop the stale client.

### Specific verify-route tests

- **`TestIdentityVerify::test_verify_disabled_returns_503`** — operator has not opted in; route returns 503 with `"not configured"`.
- **`TestIdentityVerify::test_verify_rejects_bad_token`** — bad token → 401 AND agent tier stays `anonymous` (no partial stamping).
- **`TestIdentityVerify::test_verify_rejects_token_missing_appid`** — verified token without `appid`/`azp` → 401 (no principal claim to stamp).
- **`TestIdentityVerify::test_verify_success_stamps_record`** — happy path: `tier: verified`, `verified_app_id`, `verified_tenant_id`, `verified_at` all populated, `GET /v1/agents/{did}` reflects.
- **`TestIdentityVerify::test_verify_falls_back_to_azp_when_appid_missing`** — v2.0 Entra tokens use `azp` instead of `appid`; route accepts either.

## Test coverage for security-relevant behavior

- `tests/test_entra_verifier.py` — 20 tests covering the verifier in isolation (config, signature, claims, alg-confusion, stale-ceiling).
- `tests/test_relay.py::TestEntraAuthBypassFix` — 5 tests covering the connect-handler restructure.
- `tests/test_registry.py::TestIdentityVerify` — 6 tests covering the verify route.
- `tests/test_registry.py::TestRegistryAPI::test_session_counters_*` — 5 tests covering the counter bumps (initial-zero invariant, success bump, receiver-only-on-failure, completion-rate computation, mixed-outcome accounting).

All **97 tests in the touched test files pass post-merge** with `origin/main`. Pre-existing failures elsewhere in the suite (`test_policy_provider`, `test_server`, `test_spec_identity_trust_conformance`) are Python 3.14 `asyncio.get_event_loop()` API churn, unrelated to this PR.
