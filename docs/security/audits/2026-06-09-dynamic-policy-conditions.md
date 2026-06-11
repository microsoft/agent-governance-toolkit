# 2026-06-09 — Dynamic Policy Conditions

PR: [microsoft/agent-governance-toolkit#2870](https://github.com/microsoft/agent-governance-toolkit/pull/2870)

## What changed and why

This PR adds runtime-dynamic condition support to the `agent_os.policies` engine:

- `agent_os.policies.dynamic_context` — four new dataclasses (`TimeContext`,
  `CostContext`, `QuotaContext`, `SystemContext`) and a top-level `DynamicContext`
  wrapper. These carry runtime state (current time, session budget, API quota,
  system load) that callers inject at evaluation time.
- `PolicyEvaluator.evaluate()` gains an optional `dynamic_context` parameter.
  When supplied, its fields are merged into the evaluation dict under namespaced
  keys (`context.time.*`, `context.cost.*`, etc.) before rule matching. Existing
  callers that omit the argument are unaffected.
- `PolicyDecision` gains a `metadata` field (dict, default `{}`) to carry
  structured adaptation hints back to callers (e.g. `backoff_seconds`,
  `blocked_tools`).

**Why now:** Agent workloads increasingly need policy rules that adapt to
real-world resource state — blocking operations outside business hours,
throttling when budget is exhausted, or shedding load under high error rates.
Previously, callers had to pre-filter requests before passing them to the
evaluator. This change lets that logic live inside policy YAML, making it
auditable, version-controlled, and consistent across all callers.

## Threat model impact

This change is **additive and backward-compatible**. It does not remove,
weaken, or bypass any existing gate.

| Dimension | Direction |
|---|---|
| Policy bypass surface | **Unchanged.** All existing deny rules continue to fire. Dynamic context keys are additive; they cannot shadow action-context keys because the merge puts dynamic fields under `context.*` namespaces not occupied by action fields. |
| Information leakage | **No new exposure.** `DynamicContext` fields are runtime values provided by the caller, not user-supplied input. They never appear in public error messages; they are captured in `audit_entry.context_snapshot` only (same as existing action-context fields). |
| Privilege boundaries | **Unchanged.** Execution rings, kill switch, and approval gates are untouched. |
| Authentication / identity | **Unchanged.** No identity, signing, or trust-handshake code is modified. |
| New trust assumptions | **Caller-supplied only.** `DynamicContext` is trust-equivalent to the existing `context` dict — both are caller-supplied at evaluation time. The policy engine never fetches runtime state itself; it only evaluates what the caller provides. An attacker who controls the caller can already supply arbitrary context values. |
| Denial-of-service via expensive evaluation | **No change.** Merging a flat dict of prefixed keys is O(n) in the number of dynamic fields (at most 10). Rule-matching complexity is unchanged. |
| Backward compatibility | **Preserved.** `dynamic_context` defaults to `None`; existing call sites require no changes. `PolicyDecision.metadata` defaults to `{}` and is purely additive. |

### Specific mitigations applied

- **Namespace isolation.** Dynamic keys are always prefixed with `context.time.`,
  `context.cost.`, `context.quota.`, or `context.system.`. Action-context keys
  are never prefixed with `context.`, so dynamic fields cannot shadow or override
  them.
- **No eval / no dynamic code.** `_match_condition` is a pure switch over
  `PolicyOperator` enum values; it does not execute arbitrary expressions from
  policy YAML or dynamic context.
- **Optional injection.** When `dynamic_context` is `None` (the default), the
  evaluation dict is identical to the existing behavior. The merge path is not
  reached.
- **Sub-context presence check.** `DynamicContext.to_flat_dict()` only includes
  sub-contexts that are not `None`. Rules referencing a dynamic key will not
  match (and will not error) when that sub-context is absent, preserving
  fail-open behavior for missing runtime context.

## Test coverage

All new tests are in
`agent-governance-python/agent-os/tests/test_dynamic_policy_conditions.py`:

| Class | Purpose | Tests |
|---|---|---|
| `TestTimeContext` | Construction, `now()`, `to_dict()`, invalid timezone fallback | 4 |
| `TestCostContext` | Construction, `to_dict()`, negative remaining | 3 |
| `TestQuotaContext` | `to_dict()` | 1 |
| `TestSystemContext` | `to_dict()` | 1 |
| `TestDynamicContextFlatDict` | Empty context, per-namespace key prefixes, combined | 6 |
| `TestDynamicContextFromDict` | Deserialization, unknown key tolerance | 4 |
| `TestBackwardCompatibility` | Callers omitting `dynamic_context`, `metadata` field default | 3 |
| `TestTimeBasedConditions` | Business-hours and weekend blocking, no-context fallthrough | 5 |
| `TestCostAwareConditions` | Budget exhausted/critical/healthy/negative, no-context fallthrough | 5 |
| `TestQuotaAwareConditions` | Quota exhausted and available | 2 |
| `TestCombinedConditions` | Priority ordering, action-context not shadowed by dynamic keys | 2 |

Total: **36 new tests, all passing.**
