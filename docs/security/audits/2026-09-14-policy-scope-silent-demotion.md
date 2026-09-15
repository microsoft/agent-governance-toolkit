---
title: "Security Audit: Misspelled Policy.scope silently demotes to GLOBAL, flipping deny→allow"
last_reviewed: 2026-09-14
owner: agt-maintainers
---

# 2026-09-14 — Misspelled Policy.scope silently demotes to GLOBAL

Issue: microsoft/agent-governance-toolkit#3536

## What changed and why

`Policy.scope` is a free-form `str` (Python) / `string` (TS, .NET).
`PolicyEngine.evaluate` maps it to the `PolicyScope` enum and falls back to
`GLOBAL` when the mapping fails.  Because `GLOBAL` is the **least specific**
rank (`_SCOPE_SPECIFICITY: GLOBAL=0, TENANT=1, ORGANIZATION=2, AGENT=3`), a
typo silently demotes the policy below every correctly-scoped one.  Under
`most_specific_wins`, an agent-scoped deny whose scope is misspelled loses to
a global allow — the failure direction is **permissive**, which is the wrong
direction for a governance component.

The fix validates scope at the earliest possible point in each SDK:

| SDK | Validation site | Mechanism |
|-----|-----------------|-----------|
| Python | `Policy` model | `field_validator("scope")` derives accepted values from `PolicyScope` |
| TypeScript | `dataToPolicy()` | Checks against `VALID_SCOPE_VALUES` set derived from enum |
| .NET | `Policy.FromDocument()` | Checks against `PolicyConflictResolver.ValidScopes` |

All three SDKs also retain the runtime fallback in `evaluate()` /
`evaluatePolicy()` but now **log a warning** instead of demoting silently.
The fallback is kept because pydantic (Python) does not re-validate on
attribute assignment, and the TS/NET engines accept hand-built policy objects
via `loadPolicy()`.

Additionally, the TypeScript `PolicyScope` enum gains the `Organization`
member for parity with Python and .NET.

## Cross-language parity

| Aspect | Python | TypeScript | .NET |
|--------|--------|------------|------|
| PolicyScope members | global, tenant, organization, agent | global, tenant, **organization** (added), agent | global, tenant, organization, agent |
| SCOPE_SPECIFICITY | 0, 1, 2, 3 | 0, 1, **2** (added), **3** (bumped) | 0, 1, 2, 3 |
| Load-time rejection | `field_validator` raises `ValueError` | `dataToPolicy` throws `Error` | `FromDocument` throws `ArgumentException` |
| Runtime warning | `logger.warning` | `console.warn` | `Trace.TraceWarning` |
| `validate_policy_schema` / lint | Checks scope field | N/A (no schema validator) | N/A (no schema validator) |

## Threat model impact

| Dimension | Direction |
|-----------|-----------|
| Authorization bypass via scope typo | **Closed.** A misspelled scope is now rejected at load time. The failure mode moves from silent permissive demotion to a loud construction error. |
| Existing valid configurations | **Unchanged.** All four valid scope values (`global`, `tenant`, `organization`, `agent`) are accepted. The `organization` scope was already supported in Python and .NET; it is now added to TypeScript. |
| Backwards compatibility | **Breaking for invalid configurations only.** Any policy file with a misspelled scope that was previously loaded (and silently weakened) will now fail to load. This is the desired behavior — those policies were never enforced at their intended scope. |
| New attack surface | **None.** No new inputs, network exposure, secrets, or trust decisions are introduced. The fix only narrows acceptance at existing decision points. |

## AST call-chain analysis

The fix touches 15 code nodes across three languages:

```
Python (6 nodes):
  Policy.scope [field]
    → Policy._validate_scope [field_validator — NEW]
    → PolicyEngine.evaluate → PolicyScope(policy.scope) → fallback + WARNING
    → validate_policy_schema → scope check [NEW]

TypeScript (5 nodes):
  Policy.scope [interface field]
    → dataToPolicy → VALID_SCOPE_VALUES check [NEW]
    → PolicyEngine.evaluatePolicy → VALID_SCOPE_VALUES check + console.warn
    → SCOPE_SPECIFICITY[Organization] [NEW entry]

.NET (4 nodes):
  Policy.Scope [property]
    → Policy.FromDocument → ValidScopes check [NEW]
    → PolicyConflictResolver.ParseScope → Trace.TraceWarning [NEW]
    → PolicyConflictResolver.ValidScopes [NEW constant]
```

## Test coverage

Each regression test was verified to fail with its fix reverted and pass with
it applied.

| Test file | Test | Validates |
|-----------|------|-----------|
| `test_policy_scope_validation.py` | `TestScopeFieldValidator::test_invalid_scope_rejected[organisation]` | British spelling rejected |
| `test_policy_scope_validation.py` | `TestScopeFieldValidator::test_invalid_scope_rejected[Agent]` | Case-sensitive rejection |
| `test_policy_scope_validation.py` | `TestScopeFieldValidator::test_valid_scope_accepted[organization]` | Previously-undocumented scope works |
| `test_policy_scope_validation.py` | `TestIssue3536Reproduction::test_correct_scope_denies` | Agent-scoped deny beats global allow |
| `test_policy_scope_validation.py` | `TestIssue3536Reproduction::test_bad_scope_rejected_at_construction` | All four bad scopes from issue rejected |
| `test_policy_scope_validation.py` | `TestEvaluateScopeWarning::test_evaluate_warns_on_bad_scope` | Runtime fallback logs warning |
| `test_policy_scope_validation.py` | `TestScopeFieldDescription::test_description_lists_organization` | Field description accuracy |
| `test_policy_schema.py` | `TestSchemaValidationScope::test_invalid_scope_reported` | `validate_policy_schema` catches bad scope |
| `test_conflict_resolution.py` | `test_organization_specificity_between_tenant_and_agent` | ORGANIZATION ranks correctly |
| `policy-parity.test.ts` | `rejects misspelled scope at load time` | TS parity: British spelling rejected |
| `policy-parity.test.ts` | `Organization scope ranks between Tenant and Agent` | TS parity: specificity ordering |
| `PolicyAdvancedTests.cs` | `FromYaml_InvalidScope_Throws[organisation]` | .NET parity: British spelling rejected |
| `PolicyAdvancedTests.cs` | `Organization_RanksBetweenTenantAndAgent` | .NET parity: enum ordering |
