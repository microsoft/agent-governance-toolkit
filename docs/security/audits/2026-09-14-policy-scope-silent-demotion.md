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
| TypeScript | `dataToPolicy()` + `loadPolicy()` | Checks against `VALID_SCOPE_VALUES` set derived from enum |
| .NET | `Policy.FromDocument()` | Checks against `PolicyConflictResolver.ValidScopes` |
| Go | `NewPolicyEngine()` | Calls `ValidateScope()`, corrects to `"agent"` (fail-closed) |
| Rust | serde deserialization | `rename_all = "snake_case"` rejects unknown variants (pre-existing) |

All SDKs retain the runtime fallback in `evaluate()` / `evaluatePolicy()` but
now **log a warning and rank at AGENT** (max specificity, fail-closed) instead
of silently demoting to GLOBAL. The fallback is kept because pydantic (Python)
does not re-validate on attribute assignment, and the TS/NET engines accept
hand-built policy objects via `loadPolicy()`.

The Python sidecar and policy-server loaders (`sidecar.py`, `policy_server.py`)
have been hardened to fail-closed: if any policy file fails to load, the entire
directory is rejected instead of silently skipping the broken file.

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
| Authorization bypass via scope typo | **In progress.** A misspelled scope is rejected at `Policy` construction and at `loadPolicy()` / `FromDocument()`.  The sidecar uses the generation model (#3909): a load generation with any failed file sets `policy_set_status="rejected"` (added to the `EvaluateResponse` and `PolicyLoadGeneration` Literal types), and `evaluate_policy` denies all actions when the generation is rejected.  The policy-server loader loads into a local engine and assigns globals only after all files succeed; a failed reload returns 500 without replacing the running engine, and a reload without trust policies clears the stale `_trust_evaluator`.  The runtime evaluate() fallback now ranks an unrecognised scope at AGENT (max specificity, fail-closed) instead of GLOBAL.  .NET `ParseScope(null)` returns Global (documented default), not Agent. |
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
    -> dataToPolicy -> VALID_SCOPE_VALUES check [NEW]
    -> loadPolicy -> VALID_SCOPE_VALUES check [NEW]
    -> PolicyEngine.evaluatePolicy -> VALID_SCOPE_VALUES check + console.warn
    -> SCOPE_SPECIFICITY[Organization] [NEW entry]

.NET (4 nodes):
  Policy.Scope [property]
    → Policy.FromDocument → ValidScopes check [NEW]
    → PolicyConflictResolver.ParseScope → Trace.TraceWarning [NEW]
    → PolicyConflictResolver.ValidScopes [NEW constant]
```

## Test coverage

Python tests pass locally.  TS and .NET tests require their respective
toolchains; they should be verified in CI.

| Test file | Test | Validates |
|-----------|------|-----------|
| `test_policy_scope_validation.py` | `TestScopeFieldValidator::test_invalid_scope_rejected[organisation]` | British spelling rejected |
| `test_policy_scope_validation.py` | `TestScopeFieldValidator::test_invalid_scope_rejected[Agent]` | Case-sensitive rejection |
| `test_policy_scope_validation.py` | `TestScopeFieldValidator::test_valid_scope_accepted[organization]` | Previously-undocumented scope works |
| `test_policy_scope_validation.py` | `TestIssue3536Reproduction::test_correct_scope_denies` | Agent-scoped deny beats global allow |
| `test_policy_scope_validation.py` | `TestIssue3536Reproduction::test_bad_scope_rejected_at_construction` | All four bad scopes from issue rejected |
| `test_policy_scope_validation.py` | `TestEvaluateScopeWarning::test_evaluate_warns_on_bad_scope` | Runtime fallback logs warning |
| `test_policy_scope_validation.py` | `TestEvaluateScopeWarning::test_corrupted_deny_beats_global_allow` | Multi-candidate: AGENT ranking proven |
| `test_policy_schema.py` | `TestSchemaValidationScope::test_non_string_scope_reported` | Non-string scope returns error list |
| `test_policy_scope_validation.py` | `TestScopeFieldDescription::test_description_lists_organization` | Field description accuracy |
| `test_policy_schema.py` | `TestSchemaValidationScope::test_invalid_scope_reported` | `validate_policy_schema` catches bad scope |
| `test_conflict_resolution.py` | `test_organization_specificity_between_tenant_and_agent` | ORGANIZATION ranks correctly |
| `policy-parity.test.ts` | `rejects misspelled scope at load time` | TS parity: British spelling rejected |
| `policy-parity.test.ts` | `Organization scope ranks between Tenant and Agent` | TS parity: specificity ordering |
| `PolicyAdvancedTests.cs` | `FromYaml_InvalidScope_Throws[organisation]` | .NET parity: British spelling rejected |
| `PolicyAdvancedTests.cs` | `Organization_RanksBetweenTenantAndAgent` | .NET parity: enum ordering |
