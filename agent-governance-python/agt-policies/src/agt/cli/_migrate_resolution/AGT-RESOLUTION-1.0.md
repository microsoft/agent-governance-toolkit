# AGT-RESOLUTION-1.0.md — migration-only governance resolution

**Status:** Migration-only. **Version:** `1.0.0-alpha`. **Layer:** one-way v4 conversion.

This document specifies how `agt migrate v4-to-v5` reads the removed folder
discovery, scope, and merge format once and emits a flat native ACS manifest.
Runtime modules do not import or execute this algorithm.

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
   migration MUST stop with the `resolution_path_traversal` diagnostic.

This matches the removed v4
`agent_os.policies.discovery.discover_policies` behavior except for path
traversal. The old code returned an empty list. Migration refuses to emit an
artifact.

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

The migration command MUST stage the bundle outside the final output path and
publish it only after project-wide preflight succeeds. It MUST NOT overwrite
an existing manifest, bundle, or backup.

## 3. Failure modes

All failures stop migration and produce one of these report diagnostics. No
engine is constructed.

| Diagnostic | Cause |
| --- | --- |
| `resolution_path_traversal` | `action_path` resolved outside `root`. |
| `resolution_cycle` | An `extends` cycle was detected during translation. |
| `resolution_invalid_governance` | A `governance.yaml` failed validation. |
| `resolution_merge_conflict` | Two non-rule sections could not be merged. |

## 4. Cache

The migration command does not cache output. Existing output paths are a hard
error.

## 5. Empty manifest

There is no fallback empty manifest. If discovery finds no governance file,
the migration report records no chain. Users author a native ACS manifest
directly.

## 6. Interaction with ACS `extends`

The emitted flat manifest carries `extends: []`. After migration, users MAY
replace flat composition with native ACS `extends`.

## 7. Implementation pointers (M3)

The Python implementation lives at:

| File | Role |
| --- | --- |
| `agt/cli/_migrate_resolution/discover.py` | §2.1 + §2.2 |
| `agt/cli/_migrate_resolution/scope.py` | §2.3 |
| `agt/cli/_migrate_resolution/merge.py` | §2.4 |
| `agt/cli/_migrate_resolution/build.py` | §2.5 |
| `agt/cli/_migrate_resolution/__init__.py` | `resolve_manifest()` entry point |
