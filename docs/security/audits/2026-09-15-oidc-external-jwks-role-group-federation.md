---
title: "2026-09-15 — OIDC (RS256/ES256) support in ExternalJWKSProvider + role/group claim federation"
last_reviewed: 2026-09-16
owner: agt-maintainers
---

# 2026-09-15 — OIDC (RS256/ES256) support in ExternalJWKSProvider + role/group claim federation

PR: [microsoft/agent-governance-toolkit#3956](https://github.com/microsoft/agent-governance-toolkit/pull/3956)

## What changed and why

`ExternalJWKSProvider` (ADR-0007's cross-org agent-identity federation
piece) could only verify Ed25519-signed tokens, so it never worked
against a standard OIDC provider (Keycloak, Okta, etc.) whose default
signing key is RS256, not Ed25519 — confirmed against a real Keycloak
realm's production JWKS. `_verify_signature` now dispatches on the
JWK's own `kty`/`crv` (never the JWT header's unverified `alg`, to
avoid algorithm-confusion) to add RS256 and ES256 alongside the
existing Ed25519 path.

Separately, a verified external identity carried no role/group
information at all, so it had no path into `govern()`'s policy
context. `FederationPolicy`/`TrustedEndpoint` gain configurable
(Keycloak-defaulted) dotted-path claim extraction, and
`ExternalIdentity.as_policy_kwargs()` bridges the result into a
governed call (`safe(**identity.as_policy_kwargs(), ...)`).

This PR went through three rounds of maintainer review, each surfacing
real gaps that are fixed here rather than deferred — see "Specific
mitigations applied" below.

## Files touched (capability-path scope)

| File | Change |
|------|--------|
| `agent-governance-python/agent-mesh/src/agentmesh/identity/external_jwks.py` | RS256/ES256 dispatch by JWK `kty`/`crv`; `aud`/`nbf` verification; JWK `use`/`key_ops` validation; `TrustedEndpoint.audience` field validator; role/group dotted-path claim extraction; `as_policy_kwargs()` bridge into `govern()`. |
| `agent-governance-python/agent-mesh/tests/test_external_jwks.py` | New/updated tests for every item below, including two govern()-level tests pinning the DSL name-grammar limitation in both fail directions. |
| `agent-governance-python/agent-mesh/docs/identity.md` | Replaced the dead OIDC/SAML doc section with a runnable example against this provider; documents the audience/name-grammar limitations inline. |

## Threat model impact

| Dimension | Direction |
|---|---|
| **Algorithm confusion** | **Defended.** Signature verification dispatches on the JWK's own `kty`/`crv` (`OKP`/`Ed25519` → Ed25519, `RSA` → RS256, `EC`/`P-256` → ES256), never on the JWT header's attacker-controlled `alg`. A token whose header claims one algorithm cannot force verification down a different code path than the actual key type supports. |
| **Audience confusion (token substitution)** | **Closed.** Before this PR, `ExternalJWKSProvider` verified only signature/expiry — any RS256 token the issuer minted for *any* client (e.g. one stolen from an unrelated browser SPA) would verify identically to a token actually intended for this integration. `TrustedEndpoint.audience` (str or list, checked against the token's own `aud`, itself str-or-list per RFC 7519) closes this, fail-closed when configured but the token has no `aud` at all. Leaving `audience` unset is now an explicit, documented opt-out rather than a silent gap. |
| **`audience` misconfiguration cases** | **Rejected at construction.** `""`, `[]`, `[""]`, and `["", "x"]` are all rejected by a `field_validator` on `TrustedEndpoint.audience` — each would otherwise either match a token's own empty `aud` (silently accepting an audience-less token) or lock out every token with no signal that the field was misconfigured. |
| **Token not-yet-valid (`nbf`)** | **Closed.** `nbf` is now checked symmetrically with the existing `exp` check (reject if present and in the future; reject if non-numeric — fail-closed rather than raising or silently passing). |
| **JWK `use`/`key_ops` fail-open** | **Closed.** A non-list `key_ops` (e.g. a malformed string like `"noverify"`) previously could pass a substring-based `"verify" not in key_ops` check; the check now requires `isinstance(key_ops, list)` first, so a malformed value fails closed instead of being silently accepted or raising. `use` not in `(None, "sig")` is rejected outright. |
| **Role/group claim propagation into policy** | **New surface, scoped defensively.** `as_policy_kwargs()` exposes `caller_roles`/`caller_groups` as dicts (`{"admin": True, ...}`), not lists — `GovernedCallable._build_context` passes dict kwargs through as-is, and a list value would silently never match `PolicyRule._eval_expression`'s scalar-only matcher. There is no singular `caller_role`: an earlier draft picked `roles[0]`, which made a deny-by-role rule's outcome depend on the issuer's unspecified claim-serialization order — removed entirely in favor of the order-independent dict shape. |
| **Policy DSL name-grammar gap (group paths / hyphenated roles)** | **Documented and pinned, not fixed here.** `PolicyRule`'s bare-attribute matcher only addresses dict keys matching `\w+` — a Keycloak group path (`/engineering`) or a hyphenated role (`default-roles-company`) can never be referenced by a YAML condition. An allow rule against such a name silently denies (default_action takes over). A deny rule against one also currently denies, but only because `policy.py`'s generic fail-closed-on-unrecognized-condition fallback treats an unparseable condition on any non-allow rule as a match — not because the name was actually addressed. This PR does not change `policy.py`; it documents the limitation on `as_policy_kwargs()` and in `docs/identity.md`, and pins both fail directions with a test so a future change to that fallback (or a real list/dict membership operator) is caught rather than silently regressing the deny-side's incidental safety. |

### Specific mitigations applied

- **RS256/ES256 dispatch on JWK `kty`/`crv`, never on JWT header `alg`.** Closes the "provider only works with Ed25519" gap while avoiding algorithm-confusion by construction.
- **`TrustedEndpoint.audience` + `_audience_satisfied` check.** Fail-closed when configured but the token's `aud` is absent. Closes review round 1's top finding.
- **`TrustedEndpoint.audience` field validator.** Rejects `""`, `[]`, `[""]`, `["", "x"]` at construction. Extended across review rounds 2 and 3 as narrower misconfiguration cases (a list containing an empty-string member) were found.
- **`nbf` check symmetric with `exp`.** Closes review round 1; hardened for non-numeric values in review round 2.
- **JWK `key_ops` `isinstance(list)` guard before the `"verify" not in key_ops` check.** Closes review round 2's fail-open finding (a malformed string value could substring-match past the check).
- **`caller_roles`/`caller_groups` as order-independent dicts, no singular `caller_role`.** Closes the claim-order-dependent deny-bypass risk identified in review round 1.
- **Name-grammar limitation documented + pinned** (see above) rather than silently left as a surprise for the next person configuring a Keycloak-shaped policy.

### Specific review-round findings and fixes

- **Round 1** (`5200914330`): DCO trailer missing; no `aud` check; `nbf` unchecked; Ed25519-only docstring; `role_claim_path=""` didn't disable default extraction; dotted-client-id group paths not addressable; PS256/RS512/ES384 rejection undocumented. Fixed in `db2172ce` (pre-rebase: `d48413ab`).
- **Round 2** (`5212140767`/`5213038855`): `key_ops` fail-open on non-list values; `nbf`/`exp` asymmetry; empty audience (`""`/`[]`) not rejected; docs example missing a `None` check; then a follow-up catching that the empty-audience validator's `len(v) == 0` check didn't cover a list containing an empty-string member (`[""]`, `["", "x"]`). Fixed in `d1ad7fda` and `78687ab8`.
- **Round 3** (`5214954370`): stale test assumption after `#3924` changed the policy evaluator's fail-closed behavior for unrecognized conditions; missing license headers; this security-audit doc. Fixed in `920ca893`.
- **Round 4** (`5233792859`): this doc's first version introduced 5 new cspell misses of its own (a reviewer's name written out plus two other terms not yet recognized), and cited a pre-rebase commit hash that no longer exists on this branch. Fixed in the commit accompanying this revision.

## Test coverage for security-relevant behavior

- `tests/test_external_jwks.py` — 58 tests covering: RS256 (real Keycloak-shaped keypair) and ES256 signature verification, rejection of an unsupported key type, `aud` match/mismatch/list-form/absent-when-configured, `nbf` future/non-numeric rejection, JWK `use`/`key_ops` rejection (including the non-list-`key_ops` fail-closed case), `TrustedEndpoint.audience` construction-time rejection of all four empty-audience shapes, default/per-endpoint role and group claim-path extraction (including dotted-client-id and list-of-segments forms), `as_policy_kwargs()` order-independence, and the two govern()-level tests pinning the name-grammar limitation in both fail directions.
- `tests/test_govern.py` — unaffected by this PR; re-run as part of the pre-push regression pass since `as_policy_kwargs()` output feeds directly into `govern()`.
- All 58 tests in `test_external_jwks.py` pass against current `main` (post-rebase, post-`#3924`). The `cspell` added-lines gate passes on this document's current revision (re-verified after review round 4's findings against the doc itself), alongside the license headers added for review round 3.
