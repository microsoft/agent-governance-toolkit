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
- `model_copy` is overridden to re-derive the components from the copy's
  `capability`, since Pydantic's `model_copy` does not run validators;
- `create()` no longer passes the derived fields explicitly.

Two further follow-ups (maintainer-approved) landed in the same change:

- **Empty-segment rejection.** `parse_capability` now rejects any empty
  colon-separated segment (`write:database:`, `write::table`, `:data`) with a
  `ValueError`, so malformed scopes fail closed at parse/construction time instead
  of being accepted as a distinct `""` qualifier.
- **Single shared matcher.** The string-scope decision was extracted into
  `capability_scope_matches(granted, requested)`; both `CapabilityGrant.matches()`
  and the MCP tool gate (`integrations/mcp` `_check_capability`) now delegate to
  it, so the MCP path can no longer drift from the core semantics (it previously
  did exact + trailing-wildcard only). This intentionally *widens* the MCP gate:
  it gains the colon-boundary broad→narrow branch, so a `use:sql` grant now
  satisfies a `use:sql:read` tool requirement it previously did not (see the
  MCP tool gating row below).

### Cross-language surface

The same capability-string parser/matcher pattern exists in the other SDKs; all
were audited:

| SDK | Parser truncates? | Matcher escalates leaf→parent? | Action |
|---|---|---|---|
| Rust (`agent-governance-rust/agentmesh/src/trust_support.rs`) | **Yes** (`parts.get(2)`) | No (matcher keys on the full `capability` string, not the parsed qualifier) | **Fixed** parser to preserve the full remainder + reject empty segments; added regression tests. The truncated `qualifier` was still serialized (`Serialize`/`Deserialize`), a data-integrity defect. |
| .NET (`agent-governance-dotnet`, `AgentIdentity.HasCapability`) | No parser | No (exact + trailing `:*` only) | None needed. |
| Go (`agent-governance-golang`) | No capability-string parser/matcher | N/A (opaque exact strings) | None needed. |
| TypeScript (`agent-governance-typescript`, `identity.hasCapability`) | No parser | No (exact + trailing `:*` only) | None needed. |

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
| Derived-field integrity | **Serialization consistency (not an authz safeguard).** The authorization path re-derives from `capability` on each call (`matches()` → `capability_scope_matches`) and does not read the stored `action`/`resource`/`qualifier`. The `mode="after"` validator, `validate_assignment`, and the `model_copy` override keep the *serialized* mirror of those fields consistent with `capability`, so a consumer reading a serialized grant never sees a stale/truncated qualifier. |
| MCP tool gating | **Unified — and widened.** `integrations/mcp` `_check_capability` now delegates to the core `capability_scope_matches` instead of its previous exact + trailing-`:*`-only check. This adds the colon-boundary broad→narrow branch to the MCP path: a client granted `use:sql` now satisfies a tool requiring `use:sql:read`/`use:sql:admin` (previously it did not). This is the intended hierarchical-capability model and removes a divergent checker, but it is a behavior widening of the MCP gate — call it out in release notes. A 4+ segment leaf capability still cannot satisfy a *parent* tool requirement. |
| Empty/malformed segments | **Fail-closed.** `write:database:`, `write::table`, `:data` and similar are rejected at parse/grant time rather than accepted as an empty-`""` qualifier. Also note `CapabilityGrant(capability="*")` (bare global wildcard) now raises at construction, because `parse_capability` requires ≥2 non-empty segments; global scope must be expressed as `admin:*` etc. The matcher's literal-`"*"` branch is retained and still authorizes everything, because it is reachable via raw capability strings that do NOT go through `CapabilityGrant` construction — notably an MCP client's `client_capabilities` list, where a `"*"` entry grants any tool. So `"*"` is no longer a constructible *grant* but remains a valid *raw capability*; only the parsed-grant path is tightened. |
| Delegation guard (`grant(require_grantor_capability=True)`) | **Strengthened.** A grantor holding only a leaf can no longer delegate the parent or a sibling; it can still delegate a strictly-deeper child. |
| Wildcard grammar | **Clarified / fail-closed.** Only a whole-segment action/resource `*` and a trailing `:*` are wildcards; a `*` in the middle of the remainder (`write:database:*:row`) is now a literal qualifier segment (stricter). Concretely, a grant `*:db:schema` previously authorized `write:db:schema:table` (the request's `:table` was truncated away, so qualifiers matched) and now denies it (`True`→`False`, fail-closed), because the full qualifier `schema` no longer equals `schema:table`. |
| Fail-closed behavior | **Preserved.** Malformed requests (no colon) still fail closed. Malformed `capability` at construction still raises a `ValueError` (now a `pydantic.ValidationError`, which subclasses `ValueError`, so the `/api/v1/capabilities/grant` handler's `except ValueError` still returns HTTP 400, not 500). |
| New attack surface | **None.** No new inputs, network exposure, secrets, or trust decisions; the signatures of `matches()`/`check()`/`grant()` are unchanged. |
| Backward compatibility | A caller that relied on a 4+ segment leaf grant implicitly authorizing its parent/siblings now receives `False`; a caller that relied on empty-segment capabilities now gets a `ValueError`. Both are the intended security fix. |

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
| `test_validator_re_derives_truncated_qualifier` / `test_model_validate_derives_components` / `test_reassigning_capability_re_derives_via_validate_assignment` / `test_non_dict_mapping_input_re_derives` | Derived fields are re-derived on construction, `model_validate`, reassignment, and non-dict mapping input. |
| `test_model_copy_re_derives_and_denies_parent` / `test_model_copy_rejects_malformed_capability_update` | `model_copy` re-derives components (parent/sibling denied) and fails closed on a malformed capability update. |
| `test_trailing_wildcard_still_matches_prefix` / `test_mid_remainder_wildcard_is_literal_fail_closed` | Wildcard grammar pins. |
| `test_empty_segment_rejected_at_parse_and_construction` | Empty colon-separated segments are rejected at parse and construction. |

Rust regression tests in `agent-governance-rust/agentmesh/src/trust_support.rs`
(`parse_capability_preserves_full_sub_resource_path`,
`parse_capability_rejects_empty_segments`,
`leaf_grant_does_not_authorize_parent_or_sibling`).

The full `agent-mesh` Python suite passes (3428 passed, 73 skipped; the only
failures are 4 pre-existing `ModuleNotFoundError: agentrust_trace` cases in
`tests/governance/test_trace_sink.py`, unrelated to this change), and the Rust
workspace passes `cargo test --release --workspace` (376 + crate tests, 0
failures). Correctness was validated against an adversarial authorization matrix
(exact leaf, parent, siblings, deeper nesting, delegation, and the #3176
regressions), and the cross-language surface was reviewed to confirm no other SDK
escalates a leaf grant to its parent or siblings. The spec at
`docs/specs/AGENTMESH-TRUST-COORDINATION-1.0.md` §8.2, §8.3, and §8.5 was updated
to document that `qualifier` is the full sub-resource path compared as one opaque
token.
