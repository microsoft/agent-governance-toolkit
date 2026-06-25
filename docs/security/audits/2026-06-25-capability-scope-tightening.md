# 2026-06-25 - Capability scope tightening (qualifier and resource_id)

PR: microsoft/agent-governance-toolkit#3176

## What changed and why

`CapabilityGrant.matches()` in
`agent-governance-python/agent-mesh/src/agentmesh/trust/capability.py` is the
authorization predicate behind `CapabilityRegistry.check()` (the decision a
policy enforcement point calls) and `CapabilityScope.has_capability()`.
Capabilities are strings of the form `action:resource[:qualifier]`, optionally
narrowed by a grant's `resource_ids` list.

Two clauses under-restricted authorization by treating a value the *checker*
omitted as "match any", so a narrow grant satisfied a broader check (a privilege
escalation):

```python
# before — qualifier only compared when BOTH sides had one
if req_qualifier and self.qualifier:
    if self.qualifier != "*" and self.qualifier != req_qualifier:
        return False

# before — resource scope only checked when the caller passed a resource_id
if self.resource_ids and resource_id:
    if resource_id not in self.resource_ids:
        return False
```

After the fix:

```python
# a grant scoped to a specific (non-"*") qualifier requires the request to
# name that exact qualifier; omitting it is broader than the grant
if self.qualifier is not None and self.qualifier != "*":
    if req_qualifier != self.qualifier:
        return False

# a grant restricted to resource_ids is denied unless the request names an
# in-scope resource; omitting resource_id is broader than the grant
if self.resource_ids:
    if resource_id is None or resource_id not in self.resource_ids:
        return False
```

Concretely: `grant("write:database:table_users")` no longer satisfies
`check("write:database")`, and `grant("read:db", resource_ids=["r1"])` no longer
satisfies `check("read:db")` with no `resource_id`. The dangerous part was that
the simplest, coarsest call (the natural `check(agent, "write:database")` before
allowing a write to any table) was the insecure one.

## Threat model impact

This is a **least-privilege tightening** of an authorization decision. It only
removes permissive matches; it never grants a new match. Per the AgentMesh
boundary "Never weaken trust thresholds — only tighten", the direction is
correct.

| Dimension | Direction |
|---|---|
| Authorization (escalation) | **Strengthened.** Closes the narrow-grant-satisfies-broad-check escalation for the qualifier and `resource_ids` dimensions. |
| Correct broad→narrow direction | **Preserved.** A broad grant (`write:database`) still satisfies a narrower check (`write:database:table_users`) via the existing colon-boundary prefix branch. |
| Fail-closed behavior | **Preserved/extended.** Malformed requests still fail closed; an omitted qualifier/resource_id is now treated as broader-than-grant and denied rather than silently allowed. |
| Delegation guard (`grant(require_grantor_capability=True)`) | **Strengthened.** A grantor whose grant is scoped to `resource_ids` can no longer use an unscoped `has_capability()` to delegate a broader (unscoped) capability. The grant request model mints only unscoped grants, so the prior behavior was itself a scope-escalation; the new behavior fails closed. |
| Discovery (`get_agents_with_capability`, `filter_capabilities`) | **More restrictive (intended).** A resource-scoped grant no longer counts as holding the unscoped capability in these unscoped queries. No production caller relied on the old behavior. |
| New attack surface | **None.** No new inputs, network exposure, secrets, or trust decisions; signature of `matches()`/`check()` unchanged. |
| Backward compatibility | A caller that relied on the permissive behavior (e.g. probing `has_capability` without a `resource_id` for a resource-scoped grant) now receives `False`. This is the intended security fix; such callers must pass the qualifier/`resource_id` explicitly. |

### Known residual (out of scope, tracked separately)

`CapabilityGrant.parse_capability()` truncates capabilities to three components,
dropping everything after the second colon, so a 4+ segment grant such as
`write:database:table_users:row_1` still escalates to its parent and siblings.
This reproduces identically on `main` and is **not** introduced by this change;
it lives in the parser, not the matcher. Tracked in
microsoft/agent-governance-toolkit#3180. A correct fix changes the capability
data model and warrants its own audited change.

## Test coverage

Added to `agent-governance-python/agent-mesh/tests/test_coverage_boost.py`
(`TestCapabilityGrant` and `TestCapabilityRegistry`):

| Test | Purpose |
|---|---|
| `test_matches_narrow_qualifier_does_not_satisfy_broad_check` | A qualifier-scoped grant matches its exact capability but NOT the unqualified parent. |
| `test_matches_broad_grant_satisfies_narrow_qualifier_check` | The correct broad→narrow direction is preserved. |
| `test_matches_resource_scoped_requires_resource_id` | A `resource_ids`-scoped grant matches only with an in-scope `resource_id`; omitted/out-of-scope are denied. |
| `test_check_narrow_qualifier_grant_rejects_broad_request` | Registry-level: an agent granted write to one table fails a check for the whole database. |
| `test_check_resource_scoped_grant_rejects_unscoped_request` | Registry-level: a resource-scoped grant is denied when the check omits `resource_id`. |

These regression tests fail on `main` and pass on this branch. The existing
capability, negative-security, and spec-conformance suites (380 + 62 tests)
continue to pass, and the change was reviewed by a multi-lens deep code review
(dual-model correctness, domain-semantics over a 192-case authorization truth
table, and fit/scope/fidelity gate runs) with no reproduced blockers introduced.
The spec at `docs/specs/AGENTMESH-TRUST-COORDINATION-1.0.md` §8.5 was updated to
document the tightened, fail-closed scoping rules.
