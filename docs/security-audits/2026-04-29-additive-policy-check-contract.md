# 2026-04-29 — Additive Policy-Check Contract

PR: [microsoft/agent-governance-toolkit#1594](https://github.com/microsoft/agent-governance-toolkit/pull/1594)
ADR: [docs/adr/0011-additive-policy-check-contract.md](../adr/0011-additive-policy-check-contract.md)

## What changed and why

This PR introduces an **additive** structured policy-check contract under
`agent_os.policies.*`:

- `agent_os.policies.decision` — `ViolationCategory` enum and `PolicyCheckResult`
  Pydantic model with `to_legacy_tuple()` and `to_public_dict()` serializers.
- `agent_os.policies.decision_factory` — single source of truth for denial-result
  construction; sanitized public-message templates keyed by category.
- `PolicyViolationError.from_check_result(result)` — additive classmethod on the
  canonical exception. The legacy `(message, error_code, details)` constructor is
  preserved verbatim. `str(e)` is the sanitized public message; audit fidelity
  lives in `e.details["detail"]` and `e.check_result`.
- `BaseIntegration.{pre,post}_execute_check` (sync + async) — return
  `PolicyCheckResult`. The legacy tuple-returning methods are reimplemented as
  thin wrappers over the new methods; reason strings are byte-identical.
- Internal migration of `AsyncGovernedWrapper` and `PolicyInterceptor` to the
  `*_check` variants. External adapter API is unchanged.

**Why now:** adapter denial sites currently interpolate raw regex tokens,
allow-list contents, and limit numbers into user-visible error text. Hosts
have no programmatic way to dispatch on violation category without
substring-matching free-form English. This contract gives the kernel a single
canonical way to represent a policy decision so that every denial path can
deliver a sanitized public message at the source while preserving full audit
fidelity in restricted, server-side fields.

## Threat model impact

This change **reduces** the kernel's attack surface; it does not add any new
capability or power.

| Dimension | Direction |
|---|---|
| Information leakage in user-visible error text | **Reduced.** Public messages are fixed by `ViolationCategory` and never include matched user input, raw regex patterns, allow-list contents, or limit numbers. Sensitive values live only in restricted structured fields. |
| Policy bypass surface | **Unchanged.** No existing check is removed, weakened, or made conditional. All previously denying paths still deny. Legacy callers continue to receive byte-identical reason strings via `to_legacy_tuple()`. |
| Authentication / identity | **Unchanged.** No identity, signing, or trust-handshake code is modified. |
| Privilege boundaries | **Unchanged.** Execution rings, kill switch, and approval gates are untouched. |
| New trust assumptions | **None.** The new types are pure data carriers; they do not perform privileged actions. |
| External input handling | **Tightened.** `decision_factory` factories default to `redact_user_text=True` for input/tool/output/memory denials, so user-supplied text cannot reach `PolicyCheckResult.matched_text`. |
| Audit fidelity | **Preserved.** The audit channel (`details["detail"]`, `check_result.audit_entry`, `matched_pattern`) retains every value the legacy path logged. |
| Backward compatibility | **Preserved.** Public exception constructor signature is unchanged; legacy tuple methods produce byte-identical strings; no breaking API change. |

### Specific mitigations applied

- **Public message templates are static.** `decision_factory._PUBLIC_MESSAGES`
  is a fixed dict keyed by `ViolationCategory`. There is no string-interpolation
  path from policy data into the public message.
- **`redact_user_text=True` is the default for user-input categories.**
  Factories for `BLOCKED_PATTERN_INPUT`, `BLOCKED_PATTERN_TOOL`,
  `BLOCKED_PATTERN_OUTPUT`, and `BLOCKED_PATTERN_MEMORY` never persist the
  matched user text in the result.
- **Cedar / `PolicyEvaluator` gate is preserved.** `pre_execute_check` runs the
  declarative policy evaluator first and routes its denials through
  `deny_policy_error()` so existing Cedar deny text is unchanged.
- **Lazy imports inside `BaseIntegration` methods** keep the
  `policies` package free of import cycles, so the new contract cannot be
  trivially short-circuited by import-order tricks.

### Surfaces not yet converted (out of scope for this PR)

The 14 adapter modules and the `bridge.py`, `lite.py`, `trust_root.py`, and
finance-soc2 example denial sites that still interpolate policy internals are
explicitly **out of scope** for this PR. They are tracked in the parity harness
PR ([#1598](https://github.com/microsoft/agent-governance-toolkit/pull/1598))
and converted one-by-one in subsequent per-adapter PRs (d / eᵢ). Each
conversion removes one `xfail` entry from the harness, so the remediation is
both visible and gated.

## Test coverage

All new tests live in `agent-governance-python/agent-os/tests/`:

| File | Purpose | Tests |
|---|---|---|
| `test_policy_check_result_no_leak.py` | Verifies `to_public_dict()` and `decision_factory` outputs never carry matched user text, raw regex tokens, allow-list contents, or limit numbers. | 27 |
| `test_policy_violation_error_safety.py` | Verifies `str(e)` is the sanitized public message; `e.details["detail"]` and `e.check_result.audit_entry` retain audit fidelity; `from_check_result` round-trips. | 24 |
| `test_legacy_constructors.py` | Verifies the pre-existing `PolicyViolationError(message, error_code, details)` constructor still produces byte-identical instances. | 6 |
| `test_pre_execute_check_contract.py` | Asserts `*_check(...).to_legacy_tuple()` is byte-identical to the legacy `*_execute(...)` tuple for every denial category, sync and async. | 32 |
| `test_public_api_surface.py` | `inspect.signature` snapshot of every previously-public symbol the foundation touches; catches any future regression of the additive guarantee. | 31 |

Total: **120 new tests, all passing.** Combined run on touched packages
(`pytest tests/ --ignore=tests/test_cmd_sign.py`) is **3308 baseline + 120 new
= 3428 passed**, 52 skipped, 0 failed. Full Docker test suite green across all
packages.

A local manual verification script (run by the author, not committed) exercises
the legacy-tuple parity, structured `PolicyCheckResult`, sanitized exception,
legacy constructor preservation, and `redact_user_text` honoring in five
end-to-end checks.

## Reviewer focus

Concentrate review on:

1. **Sanitization invariants in `decision_factory.py`.** Every factory for a
   user-input category must set `redact_user_text=True` by default and must
   route raw values only into `matched_pattern` or `audit_entry`, never into
   `public_message` or `matched_text`.
2. **Reason-string identity for legacy callers.** Inspect the `*_check` →
   `to_legacy_tuple()` chain in `BaseIntegration`; the snapshot tests in
   `test_pre_execute_check_contract.py` should fail loudly if any reason text
   diverges by even one character.
3. **`PolicyViolationError.__init__` is still byte-compatible.** Any change to
   the constructor signature is out of scope and would break legacy callers.
