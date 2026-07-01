# 2026-06-25 - Falsy-default thresholds (agent-mesh)

PR: microsoft/agent-governance-toolkit#3184

## What changed and why

Seven numeric parameters in agent-mesh used the idiom `value = param or default`,
which treats an explicit `0` as falsy and silently replaces it with the default.
The fix uses `value = default if param is None else param` so a caller-supplied
`0` is honored.

Security-surface sites touched by this change:

| File | Parameter | Effect of honoring `0` |
|------|-----------|------------------------|
| `trust/bridge.py` `verify_peer`, `is_peer_trusted`, `get_trusted_peers` | trust floor | `0` means no floor (admit any verified peer) instead of being forced to the default 700 |
| `encryption/bridge.py` `open_secure_channel` | `required_trust_score` | `0` floor forwarded to `verify_peer` before opening an E2E channel |
| `identity/credentials.py` `CredentialManager.issue` | `ttl_seconds` | `0` yields an immediately invalid credential (fails closed) |
| `identity/risk.py` `get_high_risk_agents` | `threshold` | `0` returns an empty list (scores are `ge=0`, so `< 0` is never true) |
| `core/identity/ca.py` `_issue_svid_certificate` | `ttl_minutes` | `0` yields a zero-lifetime (immediately expired) certificate |

The certificate path also had a coupled defect that the fix exposed. The method
called `datetime.now()` twice, so a `ttl_minutes=0` certificate had
`expires_at` computed before `not_valid_before`, which the x509 builder rejects
with `ValueError`. Both timestamps now anchor to a single `issued_at`, which
also removes a sub-second drift on every issued certificate.

Out of audit scope but related, the marketplace plugin sandbox `execute`
timeout was fixed in the same change (`timeout=0` is passed through to the
subprocess and fails closed by timing out immediately).

## Threat model impact

The defaults are unchanged (700 trust floor, 300 server MCP floor, 15 minute
certificate TTL, 15 minute credential TTL, 30 second sandbox timeout). The
behavior change is observable only when a caller passes an explicit `0`.

| Dimension | Direction |
|-----------|-----------|
| Trust gating (`verify_peer`, `is_peer_trusted`, `get_trusted_peers`, `open_secure_channel`, MCP per-tool `min_trust_score`) | Fail-safe to fail-open at the caller's explicit request. Before the fix an explicit `0` was silently raised to the safe default; after, `0` configures an admit-any floor. This is the documented intent of the bug report and is opt-in. No default is lowered. |
| Identity and integrity | Preserved. Honoring a `0` floor changes only the numeric score comparison. Ed25519 signature verification, registry-authoritative score lookup, and the in-process HMAC integrity check on peer records still run before any peer is admitted. |
| Untrusted input reachability | None. No internal caller passes any of the seven parameters, and the verified ingress points (LangGraph request defaults, the trust CLI, the approval TTL handler) do not feed the modified functions. An attacker-influenced value cannot reach these parameters to set a `0` floor. |
| Certificate and credential lifetime | Strengthened or neutral. A `0` TTL produces an already-expired artifact that verifiers reject, which is safer than the prior silent 15 minute lifetime. |
| New attack surface | None. No new inputs, network exposure, secrets, or trust decisions are introduced. |

The fail-open opt-in is now documented in the docstrings of each trust-gating
site so it cannot be a silent hazard.

### Known pre-existing issue (out of scope, tracked separately)

A deep multi-lens review of this change surfaced a pre-existing weakness in
`trust/handshake.py` that this PR does not touch. The handshake result cache is
keyed on `peer_did` only and ignores `required_trust_score`, so a verification
that succeeded under a low threshold is reused by a later higher-threshold call.
This reproduces on the base commit with non-zero thresholds, so it is not
introduced by this change. It is a trust-model change that warrants its own
maintainer-reviewed PR. This change marginally widens its reach by making a `0`
threshold reachable.

## Test coverage

Regression tests assert that an explicit `0` is honored, and each was verified
to fail on the old `x or default` form and pass on the fix.

| Test | Validates |
|------|-----------|
| `tests/test_trust.py::test_get_trusted_peers_zero_threshold_includes_all_verified` | `get_trusted_peers(0)` returns a verified peer scored below the default floor |
| `tests/test_trust.py::test_is_peer_trusted_zero_required_score` | `is_peer_trusted(required_score=0)` admits a verified peer below the default, after the integrity check |
| `tests/test_ca_security.py::test_zero_ttl_minutes_honored` | `ttl_minutes=0` yields a certificate expiring within the call window, not the 15 minute default |
| `tests/test_sandbox.py::test_zero_timeout_passed_through` | `execute(timeout=0)` raises with `exceeded 0s timeout`, proving passthrough |
| `tests/test_mcp_integration.py::test_zero_min_trust_score_admits_any` | a tool registered with `min_trust_score=0` admits a caller scored `0` |
| `tests/test_credential_lifecycle.py::test_manager_issue_zero_ttl_honored` | `CredentialManager.issue(ttl_seconds=0)` is immediately invalid |

The full agent-mesh suite passes (3370 passed, 73 skipped) apart from four
pre-existing failures in `tests/governance/test_trace_sink.py` caused by a
missing optional dependency, which reproduce on the base commit.
