# AGT-RESOLUTION-1.0.md — AGT manifest resolution layer

**Status:** Draft. **Version:** `1.0.0-alpha`. **Layer:** above the engine, below the framework adapters.

This document specifies the AGT-side manifest resolution layer. Per the user
decision in Q6, AGT keeps the folder discovery + scope filter + merge feature
from v4 but runs it in the host before the engine is called.

## 1. Inputs and outputs

The resolution layer is a pure function from a (root, action_path) pair to a
flat ACS manifest with `extends: []`.

```
resolve_manifest(root: Path, action_path: Path) -> Manifest
```

The output manifest is what the engine sees.

## 2. Algorithm

The algorithm is the AGT v4 algorithm, lifted out of the engine and into the
host:

### 2.1 Discovery

1. Starting at `action_path` (parent directory if a file), walk upward toward
   `root`.
2. At each directory level, look for `governance.yaml` (preferred) or
   `governance.yml`. If found, add to the candidate list.
3. Stop at `root` (inclusive). If the resolved `action_path` is not under
   `root` (symlinks, `..` segments, attacker-influenced inputs), the
   resolution layer MUST fail closed with the reserved reason
   `runtime_error:resolution_path_traversal` (see §3). The engine is then
   never called for this evaluation.

This matches the v4 `agent_os.policies.discovery.discover_policies` behaviour
exactly except for the path-traversal handling: v4 returned an empty list,
which let downstream code default to allow. v5 fails closed.

### 2.2 Inherit-truncation

Walking from most-specific to least-specific, the first PolicyDocument with
`inherit: false` becomes the new effective root. Everything above it is
discarded.

### 2.3 Scope filtering

Each surviving document MAY declare a `scope` field of type `string` (a glob
pattern). For each document, compute the action path relative to root, normalize
to forward slashes, and `fnmatch` against `scope`. Documents whose scope does
not match are dropped.

Documents with no `scope` always apply.

### 2.4 Merge

Documents are merged root-first. Rules are merged per the v4 invariants:

1. Rules from all surviving documents are collected.
2. Same-`name` collisions:
   - If the child rule has `override: true` AND the parent rule has
     `action: deny`, the **child override MUST be dropped**. This is the
     deny-immutability invariant; v5 preserves it as a property of the
     resolution layer (not the engine).
   - If the child rule has `override: true` and the parent rule is non-deny,
     the child rule replaces the parent.
   - Otherwise (same name, `override: false` or omitted): the child rule is
     dropped, parent kept.
3. Rules with unique names are appended.
4. The merged rule list is sorted by priority descending.

### 2.5 Translation to ACS manifest

The merged rule list is translated into a Rego bundle on disk, then bound
through a `type: rego` policy that points at that bundle. The bundle layout
is:

```
.agt/resolved-bundle/
├── manifest.yaml          # the produced ACS manifest
├── policy/
│   ├── agt_legacy.rego    # generated from merged rule list
│   └── lib/               # stock library copied in by reference
```

`policies.{id}.bundle` points at `.agt/resolved-bundle/policy/`. The `query`
member is `data.agt.legacy.verdict`. The generated `agt_legacy.rego` carries a
`package agt.legacy` header and a `verdict` rule synthesized from the rule list.

The full translation algorithm is described in `AGT-RULES-TO-REGO-1.0.md` (M5
deliverable). The translation MUST preserve the deny-immutability invariant
from §2.4 step 2 by emitting deny rules with explicit precedence over child
rules that share a name.

Output manifest:

```yaml
agent_control_specification_version: "0.3.0-alpha-agt"
metadata:
  name: agt_resolved
  resolved_from:
    root: <root>
    action_path: <action_path>
extends: []                              # always empty after resolution
policies:
  agt_legacy_rules:
    type: rego
    bundle: .agt/resolved-bundle/policy/
    query: data.agt.legacy.verdict
intervention_points: { ... }              # bindings per v4 rule targets
tools: { ... }                            # merged tools catalogs
annotators: { ... }                       # merged annotators
limits: { ... }                           # merged limits
approval: { ... }                         # merged approval config (last writer wins)
```

The resolution layer MUST write the bundle to a host-writable directory and
clean it up at session end. The bundle path SHOULD be inside the project's
build directory, not the project's source tree.

## 3. Failure modes

All failures in the resolution layer MUST cause the engine call to fail closed
with a deny decision and one of these reasons:

| Reason | Cause |
| --- | --- |
| `runtime_error:resolution_path_traversal` | `action_path` resolved outside `root`. |
| `runtime_error:resolution_cycle` | An `extends` cycle was detected during translation. |
| `runtime_error:resolution_invalid_governance` | A `governance.yaml` failed validation. |
| `runtime_error:resolution_merge_conflict` | Two non-rule sections (e.g., conflicting `approval` blocks) could not be merged. |

These reasons are AGT-host-level. They MUST be reported through the engine's
telemetry sink as `policy.failed` events with `policy_id: agt_resolution`.

## 4. Cache

The resolution layer MAY cache its output keyed on the canonical hash of all
input governance.yaml file contents. Cache eviction is host-defined.

## 5. Empty manifest

There is no fallback empty manifest. A workspace with no `governance.yaml`
files anywhere from `action_path` up to `root` SHOULD be configured with a
single `governance.yaml` at the root that establishes a default verdict for
all intervention points. A workspace whose discovery returns an empty
candidate list MAY (host policy) either:

1. Fail closed with `runtime_error:resolution_invalid_governance` so that
   missing governance is an explicit deployment error, or
2. Substitute a host-supplied default manifest registered at host startup.

The previous "default to empty manifest that allows" behaviour from
`plan v2` is removed because it implicitly opened a fail-open path.

## 6. Interaction with ACS `extends`

The engine's own `extends` machinery (ACS §2.2) is NOT invoked when AGT hosts
use the resolution layer. AGT manifests always carry `extends: []`. A caller
that wants direct ACS semantics MAY skip the resolution layer and pass a
manifest with non-empty `extends` to the engine; the engine handles it per
§2.2.

## 7. Implementation pointers (M3)

The Python implementation lives at:

| File | Role |
| --- | --- |
| `agt/manifest_resolution/discover.py` | §2.1 + §2.2 |
| `agt/manifest_resolution/scope.py` | §2.3 |
| `agt/manifest_resolution/merge.py` | §2.4 |
| `agt/manifest_resolution/translate.py` | §2.5 |
| `agt/manifest_resolution/__init__.py` | `resolve_manifest()` entry point |
