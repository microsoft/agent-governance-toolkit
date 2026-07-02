# 2026-07-02 - Capability sub-resource path preservation (4+ segment escalation)

PR: microsoft/agent-governance-toolkit#3246

## What changed and why

`CapabilityGrant.parse_capability()` in
`agent-governance-python/agent-mesh/src/agentmesh/trust/capability.py` splits a
capability string of the form `action:resource[:qualifier]` and is the source of
the derived `action`/`resource`/`qualifier` fields that `matches()` (the
authorization predicate behind `CapabilityRegistry.check()` and
`CapabilityScope.has_capability()`) compares.

It truncated the capability to three components, dropping everything after the
second colon:

```python
# before — parts[3:] discarded
qualifier = parts[2] if len(parts) > 2 else None
```

So `write:database:table_users:row_1` parsed to
`('write', 'database', 'table_users')`. A grant scoped to a single leaf was
stored and compared as its parent, authorizing the parent and every sibling:

```python
reg.grant("write:database:table_users:row_1", "child", "admin")
reg.check("child", "write:database:table_users")        # True  (parent — escalation)
reg.check("child", "write:database:table_users:row_2")  # True  (sibling — escalation)
```

This is the **4+ segment** variant tracked as the "Known residual" of
#3176 (`2026-06-25-capability-scope-tightening.md`). It lives in the parser, not
the matcher, and reproduced identically on `main` and on the #3176 branch.

After the fix:

```python
# preserve the full sub-resource path
qualifier = ":".join(parts[2:]) if len(parts) > 2 else None
```

`matches()` is unchanged: it already compares `qualifier` as an opaque
exact-match token, and the correct broad->narrow direction is served by the
separate colon-boundary prefix branch (`requested.startswith(capability + ":")`)
which reads the untruncated `capability` string. Widening `qualifier` to the full
remainder therefore denies the parent and siblings while the exact leaf and any
strictly-deeper (narrowing) request still match.

Because the derived fields are what `matches()` trusts, a second change hardens
the model so those fields can never disagree with `capability`:

- a `model_validator(mode="after")` re-derives `action`/`resource`/`qualifier`
  from `capability` on every construction, `model_validate`, and (via
  `ConfigDict(validate_assignment=True)`) every field reassignment, regardless of
  input type (dict, `UserDict`/mapping, model instance);
- `create()` no longer passes the derived fields explicitly.

## Threat model impact

This is a **least-privilege tightening** of an authorization decision. It only
removes permissive matches (parent/sibling of a leaf grant); it never grants a
new match. Per the AgentMesh boundary "Never weaken trust thresholds — only
tighten", the direction is correct.

| Dimension | Direction |
|---|---|
| Authorization (escalation) | **Strengthened.** A 4+ segment leaf grant authorizes only that exact leaf; parent, siblings, and uncles are denied. |
| Correct broad->narrow direction | **Preserved.** A broad grant (`write:database`, or a 3-segment `write:database:table_users`) still satisfies a narrower/deeper check via the colon-boundary prefix branch. |
| #3176 behavior | **Preserved.** The 3-segment qualifier and `resource_ids` tightening is unaffected; regression tests for it continue to pass. |
| Derived-field integrity | **Strengthened.** The `mode="after"` validator plus `validate_assignment` prevent a grant constructed or mutated with a stale/truncated `qualifier` from re-authorizing the parent. |
| Delegation guard (`grant(require_grantor_capability=True)`) | **Strengthened.** A grantor holding only a leaf can no longer delegate the parent or a sibling; it can still delegate a strictly-deeper child. |
| Wildcard grammar | **Clarified / fail-closed.** Only a whole-segment action/resource `*` and a trailing `:*` are wildcards; a `*` in the middle of the remainder (`write:database:*:row`) is now a literal qualifier segment (stricter). |
| Fail-closed behavior | **Preserved.** Malformed requests (no colon) still fail closed. Malformed `capability` at construction still raises a `ValueError` (now a `pydantic.ValidationError`, which subclasses `ValueError`, so the `/api/v1/capabilities/grant` handler's `except ValueError` still returns HTTP 400, not 500). |
| New attack surface | **None.** No new inputs, network exposure, secrets, or trust decisions; the signatures of `matches()`/`check()`/`grant()` are unchanged. |
| Backward compatibility | A caller that relied on a 4+ segment leaf grant implicitly authorizing its parent/siblings now receives `False`. This is the intended security fix. |

### Known residual (out of scope)

Pydantic's `model_copy(update={"capability": ...})` does **not** run validators,
so a copy that rewrites `capability` without also updating the derived fields
keeps stale components. No caller in the repository does this (grants are never
`model_copy`-ed, serialized, or deserialized; the registry is in-memory). The
`_derive_components` docstring instructs callers needing a re-scoped grant to use
`CapabilityGrant.create()` rather than `model_copy`. Closing this fully would
require overriding `model_copy` and is not warranted for the current call graph.

## Test coverage

Added to `agent-governance-python/agent-mesh/tests/test_coverage_boost.py`
(`TestCapabilityFourSegmentEscalation`):

| Test | Purpose |
|---|---|
| `test_parse_preserves_full_remainder` | `parse_capability` keeps `table_users:row_1`, not `table_users`. |
| `test_leaf_grant_authorizes_only_exact_leaf` | Leaf grant matches the exact leaf; denies parent, siblings, grandparent. |
| `test_registry_check_leaf_grant_flips_escalation` | Registry-level reproduction of the #3180 escalation, now denied. |
| `test_leaf_grant_authorizes_deeper_narrowing` | A leaf grant still authorizes strictly-deeper (narrowing) requests. |
| `test_deep_leaf_grant_denies_parent_and_sibling` | A 5-segment leaf grant denies its 4-segment parent and 5-segment siblings. |
| `test_broad_grant_satisfies_narrower_leaf` / `test_three_segment_broad_grant_satisfies_four_segment_leaf` | Correct broad->narrow direction preserved (incl. #3176 3-segment guard). |
| `test_resource_scoped_leaf_grant` | `resource_ids` composes with a 4-segment scope. |
| `test_leaf_grantor_cannot_delegate_parent_or_sibling` / `test_parent_grantor_can_delegate_child` | Delegation boundary under `require_grantor_capability=True`. |
| `test_get_capabilities_returns_full_leaf_string` / `test_deny_exact_leaf_only` | Scope-level surfaces stay consistent. |
| `test_validator_reheals_truncated_qualifier` / `test_model_validate_derives_components` / `test_reassigning_capability_reheals_via_validate_assignment` / `test_non_dict_mapping_input_reheals` | Derived fields are re-healed on construction, `model_validate`, reassignment, and non-dict mapping input. |
| `test_trailing_wildcard_still_matches_prefix` / `test_mid_remainder_wildcard_is_literal_fail_closed` / `test_empty_trailing_segment_behavior_pinned` | Wildcard and empty-segment grammar pins. |

The full `agent-mesh` suite passes (3426 passed, 73 skipped; the only failures
are 4 pre-existing `ModuleNotFoundError: agentrust_trace` cases in
`tests/governance/test_trace_sink.py`, unrelated to this change). The change was
reviewed by a multi-lens deep code review (dual-model correctness and
domain-semantics over an adversarial authorization matrix, plus a
consequence-graph / obligation gate that surfaced this audit-doc requirement and
the stale-derived-field hardening). The spec at
`docs/specs/AGENTMESH-TRUST-COORDINATION-1.0.md` §8.2 and §8.5 was updated to
document that `qualifier` is the full sub-resource path compared as one opaque
token.
