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
   `root` (symlinks, `..` segments, attacker-influenced inputs), refuse to
   resolve and return the **empty manifest** (defined in §5).

This matches the v4 `agent_os.policies.discovery.discover_policies` behaviour
exactly.

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

The merged rule list is then translated into one ACS `policies.{id}` entry of
type `rego`, plus an `intervention_points.<ip>` binding for each intervention
point the v4 rule set targeted. The translation algorithm is described in
detail in `AGT-RULES-TO-REGO-1.0.md` (M5 deliverable).

Output:

```yaml
agent_control_specification_version: "0.3.0-alpha-agt"
extends: []                              # always empty after resolution
policies:
  agt_legacy_rules:
    type: rego
    policy_set: |
      # generated Rego from merged rule list
      package agt.legacy
      ...
    query: data.agt.legacy.verdict
intervention_points: { ... }              # bindings per v4 rule targets
tools: { ... }                            # merged tools catalogs
annotators: { ... }                       # merged annotators
limits: { ... }                           # merged limits
approval: { ... }                         # merged approval config (last writer wins)
```

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

The empty manifest is:

```yaml
agent_control_specification_version: "0.3.0-alpha-agt"
metadata: { name: "agt_empty" }
extends: []
policies:
  default_allow:
    type: rego
    policy_set: |
      package agt.default
      verdict := {"decision": "allow"}
    query: data.agt.default.verdict
intervention_points: {}
```

An engine that receives the empty manifest evaluates every intervention point
to `allow`.

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
