# 2026-06-10 — Policy Engine Default-Deny Parity

PR: [microsoft/agent-governance-toolkit#2949](https://github.com/microsoft/agent-governance-toolkit/pull/2949)

Issue: [microsoft/agent-governance-toolkit#2926](https://github.com/microsoft/agent-governance-toolkit/issues/2926)

## What changed and why

The Python, TypeScript, and .NET policy engines disagreed on the authorization
outcome for the same input. For an omitted `defaults.action` or an empty policy
set, Python was fail-open (default allow) while TypeScript and .NET were
inconsistent, and a matched `warn`/`log` rule denied in TypeScript while it
allowed in Python and .NET. For a governance toolkit, a trust-boundary that
behaves differently per SDK is itself a security defect: the same policy bundle
could authorize a tool call in one runtime and block it in another.

This PR standardizes all three SDKs on **fail-closed default-deny** and on
treating a matched `warn`/`log` rule as **allowed**:

- **Python** (`agent_os.policies`): `PolicyDefaults.action` now defaults to
  `DENY` (`schema.py`), and `PolicyEvaluator.evaluate()` uses `DENY` as the
  fallback default action when no policies are loaded (`evaluator.py`). When a
  policy *is* loaded, its explicit `defaults.action` still governs, so an
  operator can opt back into permissive behavior with `defaults.action: allow`.
- **.NET** (`AgentGovernance.Policy.PolicyEngine`): the zero-policy path now
  returns `PolicyDecision.DenyDefault(...)` instead of
  `PolicyDecision.AllowDefault(...)`.
- **TypeScript**: a matched `warn` or `log` rule now counts as allowed, matching
  the .NET and Python SDKs.
- `BREAKING_CHANGES.md` documents the new default and the explicit opt-out.

## Threat model impact

This change **tightens** the trust boundary; it does not introduce a new attack
surface.

| Dimension | Direction |
|---|---|
| Authorization default | **Strengthened (fail-open → fail-closed).** A missing or empty policy configuration now denies rather than allows. A misconfigured or unloaded policy bundle can no longer silently authorize every tool call. |
| Cross-SDK consistency | **Strengthened.** The same policy bundle now yields the same allow/deny decision in Python, TypeScript, and .NET, removing a class of "works in one runtime, blocked in another" trust-boundary bugs. |
| Policy bypass surface | **Reduced.** There is no longer an implicit allow path reachable by simply omitting `defaults.action` or shipping an empty policy set. |
| Privilege boundaries | **Unchanged.** Execution rings, kill switch, and approval gates are untouched. |
| Authentication / identity | **Unchanged.** No identity, signing, or trust-handshake code is modified. |
| Availability | **Operational regression risk only.** Deployments that relied on the implicit default-allow will start denying. This is the intended fail-closed behavior; the documented mitigation is an explicit `defaults.action: allow` for environments that genuinely want permissive defaults. |

### Specific notes

- **Explicit allow is preserved.** When a policy is loaded with
  `defaults.action: allow`, behavior is unchanged. Only the *implicit* fallback
  changed from allow to deny.
- **No new code execution or input paths.** This is a default-value and
  branch-outcome change in existing evaluation logic; it adds no parsing, no new
  caller-supplied input, and no dynamic evaluation.
- **Audit/warn/log semantics aligned.** `AUDIT` and matched `warn`/`log` rules
  remain allowed across all SDKs, so observability rules do not accidentally
  become deny gates.

## Test coverage

Default-deny and warn/log parity are asserted in all three SDKs:

- **.NET** (`agent-governance-dotnet/tests/AgentGovernance.Tests`):
  - `PolicyEngineTests.Evaluate_NoPoliciesLoaded_DeniesByDefault` and the
    `PolicyDecision_DenyDefault_HasExpectedShape` shape test.
  - `GovernanceClientAndPolicyEvaluationTests.EvaluateToolCall_NoPolicies_DeniesByDefault`
    (updated from the former `_AllowsByDefault` to assert deny via the kernel).
  - `PolicyAdvancedTests.Evaluate_NoPolicies_DefaultsToDeny` (updated from the
    former `_DefaultsToAllow`).
  - Tests that isolate rule-matching semantics load an explicit
    `default_action: allow` so they exercise rule behavior, not the default.
- **Python / TypeScript**: conformance tests assert that an empty policy set and
  an unmatched request both deny, and that a matched `warn`/`log` rule is
  allowed; tests that previously depended on the implicit default-allow were
  updated to set an explicit allow default.
