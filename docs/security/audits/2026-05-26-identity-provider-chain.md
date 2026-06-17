# Security Audit: IdentityProviderChain and HandshakeResult.external_identity

- **Date:** 2026-05-26
- **PR:** #2596 (closed), superseded by #3094
- **Author:** @miyannishar
- **ADR:** 0007 — External JWKS federation for cross-org agent identity

## What changed and why

This PR adds three components specified in ADR-0007:

1. **`IdentityProviderChain`** — an ordered resolution chain that lets `TrustHandshake` try multiple identity backends (local registry, Entra bridge, external JWKS) without hardcoding provider logic into the handshake path.

2. **`HandshakeResult.external_identity`** — a new nullable field on handshake results, populated only when the peer was verified through external JWKS federation. Carries issuer domain, federation tier, and delegation claims.

3. **Federation policy config schema** — example YAML for operator-managed trusted-endpoint allowlists.

None of these changes alter the existing handshake wire protocol or the Ed25519 challenge/response flow. The chain is an abstraction layer *above* the existing verification logic.

## Threat model impact

### New attack surfaces

| Surface | Risk | Mitigation |
|---------|------|------------|
| Chain ordering bypass | An attacker could try to exploit provider ordering to get a weaker provider to resolve first | Providers are tried in explicit registration order set by the operator. `LocalRegistryProvider` (strongest trust) is intended to be first. Order is not configurable at runtime. |
| Provider error swallowing | A failing provider is logged and skipped. An attacker could try to force errors in a strict provider to fall through to a permissive one | Errors are logged at WARNING with full stack traces. The chain only *skips* on exception, not on explicit rejection (returning `None`). A provider that positively rejects a DID should return `None`, not raise. |
| `external_identity` spoofing | A caller could construct a `HandshakeResult` with a fake `external_identity` | `HandshakeResult` is only constructed internally by the handshake engine via `success()` / `failure()` factories. It is not deserialized from untrusted input. The field is typed as `Optional[Any]` for forward compatibility but is only populated by `ExternalJWKSProviderAdapter` which delegates to the existing `ExternalJWKSProvider.verify()` with full JWT signature validation. |
| Token stashing on adapter | `ExternalJWKSProviderAdapter.set_pending_token()` holds a JWT briefly | Fixed: `_pending_token` replaced with `contextvars.ContextVar`. Each asyncio Task gets task-local storage; concurrent callers cannot overwrite each other's tokens. Token is cleared after every `resolve()` call (consumed or not). |

### Unchanged surfaces

- The Ed25519 challenge/response protocol is not modified.
- `IdentityRegistry` lookup behavior is unchanged — `LocalRegistryProvider` is a thin wrapper.
- Trust score calculation, tier thresholds, and the 200ms SLA budget are unaffected.
- No new network calls are introduced by the chain itself; network calls happen inside individual providers (existing code).

### No new dependencies

No new third-party packages were added. The chain uses only stdlib (`abc`, `contextvars`, `dataclasses`, `logging`) and existing `agentmesh` types.

## Test coverage for security-relevant behavior

| Scenario | Test | File |
|----------|------|------|
| Chain returns first matching provider | `test_chain_returns_first_hit` | `test_provider_chain.py` |
| Chain skips providers that don't handle the DID | `test_chain_skips_miss` | `test_provider_chain.py` |
| Chain returns None when nothing matches | `test_chain_returns_none_when_no_provider_matches` | `test_provider_chain.py` |
| Failing provider is skipped, next provider succeeds | `test_chain_skips_failing_provider` | `test_provider_chain.py` |
| Empty chain returns None (safe default) | `test_empty_chain_returns_none` | `test_provider_chain.py` |
| LocalRegistryProvider ignores non-mesh DIDs | `test_local_registry_provider_ignores_non_mesh` | `test_provider_chain.py` |
| JWKS adapter ignores non-web DIDs | `test_external_jwks_adapter_ignores_non_web` | `test_provider_chain.py` |
| JWKS adapter returns None without a token | `test_external_jwks_adapter_returns_none_without_token` | `test_provider_chain.py` |
| Token is cleared after use (no stale token reuse) | `test_external_jwks_adapter_clears_token_after_use` | `test_provider_chain.py` |
| HandshakeResult.external_identity defaults to None | `test_handshake_result_external_identity_default` | `test_provider_chain.py` |
| Existing handshake security tests still pass | 26 tests in `test_handshake_security.py` | `test_handshake_security.py` |

Total: **17 new tests + 26 existing tests = 43 tests passing** with no regressions.
