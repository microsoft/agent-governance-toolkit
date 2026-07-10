# agt-policies (5.0.0a1)

Agent Control Specification, or ACS, is the AGT policy engine. It is a
stateless, deterministic, fail-closed policy decision runtime for agent
security. A host acts as the policy enforcement point, calls ACS at
defined intervention points with a complete snapshot, receives a
normalized verdict, and enforces that verdict before the agent action
proceeds.

ACS gives AGT one portable contract for policy decisions across the
agent lifecycle. Instead of scattering governance through prompts,
framework callbacks, and application-specific checks, hosts submit the
same manifest and snapshot shape at each point in the loop.

```text
Input -> Model -> Tool Call -> Tool Result -> Output
```

ACS covers the full agent loop: input, model calls, tool calls, tool
results, output, startup, and shutdown. A manifest declares which
policy runs at each intervention point, what part of the snapshot is
the policy target, which tool metadata is projected, and which
annotators contribute additional context.

`agt-policies` is the Python package that exposes ACS to AGT hosts and
adapters. Use it when host code needs to:

- discover, scope, merge, and materialize AGT governance manifests
- author and validate a lossless typed `AgtManifest`
- build complete AGT snapshots for ACS intervention points
- call the ACS Python SDK through `AgtRuntime`
- enforce `allow`, `warn`, `deny`, `escalate`, and `transform` verdicts
- preserve v4 Agent OS adapter behavior while routing through ACS

The native runtime evaluates; this package prepares the AGT host
context and turns the returned decision into the Python objects that
AGT adapters enforce.

## How ACS and `agt-policies` fit together

| Layer | Responsibility |
| --- | --- |
| AGT host | Intercepts the agent loop, owns side effects, and enforces the verdict. |
| `agt-policies` | Python-facing ACS package for AGT hosts. Validates manifests, builds snapshots, calls the runtime, and returns native `PolicyEvaluation` results. |
| ACS runtime | Evaluates the manifest and snapshot as a stateless policy decision runtime. |

## What is here

- `agt.manifest_resolution` — folder discovery + scope filtering +
  rule merge layer that runs in the host before the engine sees a
  manifest. Implements `spec/agt/AGT-RESOLUTION-1.0.md`.
  (`discover`, `scope`, `merge`, `build`.)
- `agt.policies.snapshot` — snapshot builder per
  `spec/agt/AGT-SNAPSHOT-1.0.md`.
- `agt.policies.manifest` provides lossless typed `AgtManifest`, provenance-aware
  local reference resolution, and adapter compatibility preflight.
- `agt.policies.bridge` — renders a v4 `GovernancePolicy` into an ACS
  manifest + OPA rego module.
- `agt.policies.result` provides native immutable `PolicyEvaluation` plus the
  temporary `EvaluationResult` compatibility surface.
- `agt.policies.session` provides `AdapterRuntimeSession`, which owns one
  session's snapshots and budget counters while sharing a stateless runtime.
- `agt.policies.runtime` — Python wrapper over the ACS Python SDK that
  loads a resolved manifest, runs intervention points, applies the
  transform verdict, enforces approval, and emits AGT telemetry events.

## Runtime flow

1. The host identifies the intervention point, such as `input` or
   `pre_tool_call`.
2. `SnapshotBuilder` creates the complete AGT snapshot for that call,
   including the agent/session envelope and current budget counters.
3. `AgtRuntime.from_manifest(...)` validates the typed manifest, resolves
   relative references from explicit provenance, and calls the ACS Python SDK.
4. The returned ACS verdict is mapped to immutable `PolicyEvaluation`,
   including `verdict`, namespaced `reason_code`, optional `transform`,
   optional `evidence`, result labels, and the
   `input_identity` / `enforced_identity` audit fields.
5. The host enforces the result. `allow`, `warn`, and `transform`
   proceed; `deny` blocks; `escalate` routes through the configured
   approval resolver or fails closed.

## Native host API

```python
from pathlib import Path

from agt.policies import AgtManifest, SnapshotBuilder
from agt.policies.runtime import AgtRuntime

manifest = AgtManifest.from_path(Path("manifest.yaml"))
runtime = AgtRuntime.from_manifest(manifest)
snapshot = SnapshotBuilder(agent_id="mail-agent", session_id="run-1").input(
    body={"body": "hello"}
)
result = runtime.evaluate("input", snapshot)
```

Mapping, typed, and YAML-text inputs must provide `base_dir` when they contain
relative references. The runtime does not use the process working directory as
an implicit trust boundary. The typed model preserves `limits`, but
`AgtRuntime.from_manifest(...)` rejects it until the Python SDK can enforce
those values rather than silently dropping them.
`PolicyEvaluation.audit_record()` emits schema `agt.policy_evaluation.v1`.
Policy-authored messages remain restricted audit detail, while host exceptions
use stable sanitized text.

The dependency-light
[`native_a2a_runtime.py`](../agent-os/examples/integrations/native_a2a_runtime.py)
example constructs an A2A adapter with the public `runtime=` argument and a
custom ACS policy dispatcher.

`AdapterRuntimeSession` charges every attempted tool call, including denied
and failed attempts, before the next policy evaluation. Model token usage is
recorded after `post_model_call`. Existing v4 adapters temporarily disable
those native charges because they still update their old execution context.
Phase 3 removes that compatibility override.

## Compatibility bridge

Existing Agent OS adapters still accept the v4 `GovernancePolicy`
dataclass. `agt.policies.bridge` renders that policy into an ACS
manifest plus a generated Rego bundle. The bridge preserves v4
semantics where they differ from the native ACS defaults, including an
empty `allowed_tools` list meaning no allowlist and `max_tool_calls=0`
meaning deny every tool call.

The generated compatibility policy is identified as `agt_legacy_rules`
inside the resolved ACS manifest. If merged governance rules are
present but no intervention point binds to `agt_legacy_rules`,
resolution fails closed rather than producing rules that never run.

The `agt migrate v4-to-v5` command does not import this runtime bridge. Its
private one-way translator accepts exact literals only. Dynamic constructor
expressions, host-only fields, unsupported pattern kinds, invalid patterns, and
existing output paths produce manual-review findings and no manifest. A write
run exits nonzero whenever any policy could not be translated exactly. REGEX
and GLOB migration uses OPA's Go RE2 validator. GLOB anchors are normalized to
RE2 `\z`; Python-only expressions such as backreferences are refused.

## Security invariants

The host layer is fail-closed by design. Notably: governance files
that resolve outside the workspace root are rejected; directory-style
scopes (`dir/`) cover their subtree; a parent `deny` cannot be
neutralised by a child `allow` whose condition overlaps it; malformed
budget counters and approval-resolver timeouts deny rather than
silently allow.

Resolved Rego bundles are materialized outside the governed workspace
for runtime use and cleaned up when the runtime closes. This prevents a
workspace-writable policy bundle from being overwritten between
resolution and evaluation.

## Install (development)

```sh
cd agent-governance-python/agt-policies
pip install -e ".[dev]"
pytest
```

Tests that exercise `agt.policies.runtime` require the native ACS Python
SDK from `policy-engine/sdk/python`. In a repository checkout, build it
first:

```sh
cd ../../policy-engine
pip install ./sdk/python
```

OPA-backed Rego evaluations also require `opa` on `PATH` or
`ACS_OPA_PATH` pointing at an OPA executable.
