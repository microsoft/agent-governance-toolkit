# Integrating Agent Control Specification

This is a step by step guide for adding ACS policy enforcement to an agent host. It starts from an empty manifest and ends with an agent loop that is mediated at every model and tool boundary. The manifest and policy steps are language neutral. The construction and evaluation steps show the Rust, Python, Node, and .NET SDKs, which expose the same surface.

If you only want to build the repository and run its tests, see the [SDK matrix](README.md#sdk-matrix) in the README. This guide is about wiring ACS into your own host.

## How ACS fits into a host

Your host owns the agent loop and acts as the Policy Enforcement Point. At each intervention point the host hands ACS a JSON snapshot of what is about to happen, such as the incoming request, a model call, or a concrete tool invocation. ACS acts as the Policy Decision Point. It evaluates the policy bound to that point and returns a verdict, an optional transformed policy target only when the verdict is `transform`, and the policy input that produced the decision.

ACS holds no state between calls, so the host supplies the full snapshot every time. The host is also responsible for acting on the verdict. ACS decides, the host enforces.

## Prerequisites

| Requirement | Used for |
| --- | --- |
| One SDK toolchain (Rust 1.85+, Python 3.11+, Node 18+, or .NET 8) | Building and calling ACS from your host |
| `opa` on `PATH` | The bundled dispatcher that runs Rego policies. Only needed when a manifest uses `rego` policies |

OPA is only required at runtime when a policy is evaluated through the bundled OPA dispatcher. A host that supplies its own policy dispatcher does not need it.

## Step 1. Install the SDK

| SDK | Install |
| --- | --- |
| Rust | `cargo add agent_control_specification` |
| Python | `python -m pip install agent-control-specification` |
| Node | `npm install agent-control-specification` |
| .NET | `dotnet add package AgentControlSpecification` |

Each SDK loads the same native core. The Rust crate links it directly, the Python and Node packages ship a compiled native extension, and the .NET package ships the native library alongside the managed assembly. To build from a checkout of this repository instead of a published package, follow the build commands in the [SDK matrix](README.md#sdk-matrix).

If you are using a standalone ACS artifact kit before packages are published, install from the kit instead of the public registries. Set `ACS_KIT` to the kit root that contains `artifacts/`.

| SDK | Artifact-only install |
| --- | --- |
| Rust | Extract `agent_control_specification_core-*.crate`, `agent_control_specification-*.crate`, and any integration crates you need such as `agent_control_specification_openai-*.crate`, `agent_control_specification_mcp-*.crate`, or `agent_control_specification_rig-*.crate`, then add `[patch.crates-io]` entries pointing to the extracted directories. |
| Python | `python -m pip install "$ACS_KIT"/artifacts/agent_control_specification-0.3.1b0-*.whl` |
| Node | `npm install "$ACS_KIT"/artifacts/agent-control-specification-0.3.1-beta.0.tgz "$ACS_KIT"/artifacts/agent-control-specification-linux-x64-gnu-0.3.1-beta.0.tgz "$ACS_KIT"/artifacts/agent-control-specification-opa-linux-x64-0.3.1-beta.0.tgz` |
| .NET | `dotnet add package AgentControlSpecification --version 0.3.1-beta.0 --source "$ACS_KIT/artifacts"` |
| Generator | `python -m pip install "$ACS_KIT"/artifacts/agent_control_specification-0.3.1b0-*.whl "$ACS_KIT"/artifacts/acs_generator-0.3.1b0-py3-none-any.whl` |
| C ABI | Compile against `"$ACS_KIT"/artifacts/include/agent_control_specification.h` and link or load `"$ACS_KIT"/artifacts/libagent_control_specification_core.so`. |

Python artifact installs may resolve third party wheel dependencies from your configured package index unless the kit also includes a Python dependency wheelhouse. Use `--no-index --find-links "$ACS_KIT/artifacts"` only with kits that contain that dependency closure.

For Node artifact installs, replace `agent-control-specification-linux-x64-gnu` and `agent-control-specification-opa-linux-x64` with the native and OPA packages matching the host platform.

## Step 2. Declare a manifest

A manifest binds named policies to intervention points. The smallest useful manifest declares one Rego policy and guards one point. Save this as `manifest.yaml` next to your host.

```yaml
agent_control_specification_version: "0.3.1-beta"
metadata:
  name: "my-agent"
policies:
  email_policy:
    type: rego
    bundle: ./policy
    query: data.my_agent.verdict
intervention_points:
  pre_tool_call:
    policy_target: "$.tool_call.args"
    policy_target_kind: tool_args
    tool_name_from: "$.tool_call.name"
    policy:
      id: email_policy
tools:
  send_email:
    type: Tool
    id: send_email
    clearance: internal
```

`policy_target` is the snapshot path for the value under evaluation. `tool_name_from` is required on the two tool points and names the path that carries the current tool name. The `tools` block is a catalog of projected tool metadata that policies can read. The manifest schema is summarized in the [README](README.md#manifest-schema-overview) and specified in [`spec/SPECIFICATION.md`](spec/SPECIFICATION.md).

## Step 3. Write the policy

The bundled dispatcher resolves the `bundle` path relative to the manifest, so create `policy/my_agent.rego`. This policy denies any tool call whose arguments mention an external recipient.

```rego
package my_agent

import rego.v1

default verdict := {"decision": "allow"}

verdict := {
	"decision": "deny",
	"reason": "external_recipient_blocked",
	"message": "This tool may not send to external recipients.",
} if {
	args := object.get(input.policy_target, "value", {})
	contains(lower(object.get(args, "to", "")), "@external.example")
}
```

A verdict must carry a `decision` of `allow`, `deny`, `warn`, `escalate`, or `transform`. The optional `reason` is a low cardinality code, and `message` is host facing text. A policy may return a `transform` body only with the `transform` decision; `allow`, `warn`, `deny`, and `escalate` never mutate the policy target. Reasons must not use the reserved `runtime_error:` prefix.

## Step 4. Construct the runtime

Use the zero-config `from_path` constructor. With no dispatcher arguments it wires the bundled OPA policy dispatcher against the manifest relative Rego bundle, so a Rego host needs no dispatcher code. See [Zero-config construction](README.md#zero-config-construction) for when to supply your own dispatchers.

```rust
use agent_control_specification::AgentControl;

let control = AgentControl::from_path("manifest.yaml")?;
```

```python
from agent_control_specification import AgentControl

control = AgentControl.from_path("manifest.yaml")
```

```javascript
const { AgentControl } = require("agent-control-specification");

const control = AgentControl.fromPath("manifest.yaml");
```

```csharp
using AgentControlSpecification;

var control = AgentControl.FromPath("manifest.yaml");
```

## Step 5. Evaluate at an intervention point

Call the SDK at the boundary you declared. Pass the intervention point and the snapshot. The result carries `verdict`, an optional transformed policy target for `transform`, and the policy input.

```rust
use agent_control_specification::{Decision, EnforcementMode, InterventionPoint};
use serde_json::json;

let result = control.evaluate_intervention_point(
    InterventionPoint::PreToolCall,
    json!({"tool_call": {"id": "t1", "name": "send_email", "args": {"to": "user@external.example"}}}),
    EnforcementMode::Enforce,
);
assert_eq!(result.verdict.decision, Decision::Deny);
```

```python
from agent_control_specification import InterventionPoint

result = await control.evaluate_intervention_point(
    InterventionPoint.PRE_TOOL_CALL,
    {"tool_call": {"id": "t1", "name": "send_email", "args": {"to": "user@external.example"}}},
)
assert result.verdict.decision.value == "deny"
```

```javascript
const { InterventionPoint } = require("agent-control-specification");

const result = await control.evaluateInterventionPoint(
  InterventionPoint.PreToolCall,
  { tool_call: { id: "t1", name: "send_email", args: { to: "user@external.example" } } },
);
```

```csharp
var result = await control.EvaluateInterventionPointAsync(
    InterventionPoint.PreToolCall,
    System.Text.Json.JsonDocument.Parse(
        """{"tool_call":{"id":"t1","name":"send_email","args":{"to":"user@external.example"}}}""").RootElement.Clone());
```

The Rust SDK takes the `EnforcementMode` on `evaluate_intervention_point`. The Python, Node, and .NET SDKs evaluate without a mode and apply enforcement through the `run` and `enforce` helpers described in Step 7.

## Step 6. Act on the verdict

`evaluate_intervention_point` returns the verdict. The host decides what to do with it.

| Decision | Host action |
| --- | --- |
| `allow` | Proceed with the original policy target. |
| `warn` | Proceed with the original policy target, but record the warning. |
| `deny` | Block the action. Surface `reason` and `message`. |
| `escalate` | Suspend the action and ask a human or an external authority for approval before proceeding. |
| `transform` | Proceed only with the returned transformed policy target. |

When a policy returns `transform`, the runtime validates the transform path, applies it to the policy target in `enforce` mode, and exposes the transformed value on the result. Read the transformed policy target rather than the original before executing a tool, sending a model request, storing a tool result, or disclosing output. Redaction is the common case, but the core never mutates on `allow`, `warn`, `deny`, or `escalate`.

## Step 7. Mediate the whole agent loop

A real host guards more than one point. Wire each relevant intervention point at the matching place in your loop.

| Intervention point | Call it when |
| --- | --- |
| `agent_startup` | A session or run starts, before the loop begins. |
| `input` | An external request arrives, before the agent acts on it. |
| `pre_model_call` | A model request is assembled, before the model call. |
| `post_model_call` | A model response returns, before the host acts on it. |
| `pre_tool_call` | A concrete tool invocation is ready, before execution. |
| `post_tool_call` | A tool result returns, before it reaches the agent or caller. |
| `output` | The final user visible response is assembled, before it is sent. |
| `agent_shutdown` | A session or run ends. |

Driving each point by hand with `evaluate_intervention_point` works, but every SDK also ships orchestration helpers that bundle evaluation, enforcement, transform application, and approval into one call. Prefer these for ordinary hosts.

| Helper | Points it guards |
| --- | --- |
| `run` | `input` and `output` around a run callable |
| `run_model` | `pre_model_call` and `post_model_call` around a model call |
| `run_tool` and `protect_tool` | `pre_tool_call` and `post_tool_call` around a tool execution |

In enforce mode these helpers raise a blocked error on `deny` and consult an approval resolver on `escalate`. The resolver is a host callback that returns allow, deny, or suspend. Wiring details and the per language method names are in the SDK READMEs under repository checkout path `sdk/` and in copied artifact docs such as `PYTHON_README.md`, `NODE_README.md`, and `DOTNET_README.md`.

## Step 8. Add annotators and redaction

Two common needs do not require host dispatcher code beyond the bundled defaults.

Annotators attach derived signals, such as a classifier score, under `annotations.<name>` in the policy input so a policy can read them. Declare them in the manifest `annotators` block and opt a point in with an `annotations` map. The bundled `classifier`, `llm`, and `endpoint` annotators issue network calls, so a zero-config annotator needs a reachable endpoint and any credentials it requires. Reference dispatcher examples live under repository checkout path `integrations/annotators`.

Redaction needs no custom dispatcher. Return a `transform` verdict whose `transform.value` contains the redacted policy target, then read the transformed policy target as described in Step 6. The repository checkout path `examples/support_agent` redacts PII this way.

## Step 9. Verify your integration

Confirm the SDK works against the native core in your environment. In artifact kits, install the package into a temporary host project from `artifacts/` and run a small allow and deny smoke test with the manifest you plan to ship. In repository checkouts, use the language specific test suites described by the project build instructions.

| SDK | Artifact smoke |
| --- | --- |
| Rust | Build a temporary crate that depends on the local `.crate` artifacts and evaluates one manifest. |
| Python | Install the wheel from `artifacts/` into a temporary virtual environment and call `NativeRuntimeClient.from_path`. |
| Node | Install the `.tgz` package from `artifacts/` into a temporary project and call `AgentControl.fromPath`. |
| .NET | Restore from the local nupkg source in `artifacts/` and call `AgentControl.FromPath`. |

Set `AGENT_CONTROL_REQUIRE_OPA=1` when validating CI parity locally so OPA backed tests fail loudly instead of skipping. The cross SDK parity fixtures under repository checkout path `tests/` assert that all four SDKs agree on the same snapshots.

For an artifact-only kit, validate the installed package from a temporary host project rather than running repository checkout tests.

| SDK | Artifact-only smoke check |
| --- | --- |
| Rust | `mkdir crates && for c in agent_control_specification_core agent_control_specification agent_control_specification_openai agent_control_specification_mcp agent_control_specification_rig; do tar -xzf "$ACS_KIT"/artifacts/$c-0.3.1-beta.0.crate -C crates 2>/dev/null || true; done`, then point `[patch.crates-io]` at the extracted `crates/<name>-0.3.1-beta.0` directories before `cargo check` |
| Python | `python -m venv .venv && .venv/bin/python -m pip install "$ACS_KIT"/artifacts/agent_control_specification-0.3.1b0-*.whl && .venv/bin/python -c "import agent_control_specification as acs; print(acs.AgentControl)"` |
| Node | `npm init -y && npm install "$ACS_KIT"/artifacts/agent-control-specification-0.3.1-beta.0.tgz "$ACS_KIT"/artifacts/agent-control-specification-linux-x64-gnu-0.3.1-beta.0.tgz "$ACS_KIT"/artifacts/agent-control-specification-opa-linux-x64-0.3.1-beta.0.tgz && node -e "const acs=require('agent-control-specification'); console.log(typeof acs.AgentControl)"` |
| .NET | `dotnet new console -n AcsSmoke && cd AcsSmoke && dotnet add package AgentControlSpecification --version 0.3.1-beta.0 --source "$ACS_KIT/artifacts" && dotnet build` |


## Guided generator init

Use the generator when the first ACS artifact set should be valid by construction rather than hand assembled. The guided init flow asks for the mediated intervention points, tool catalog entries, blocked keywords, approval gates, and output redaction patterns. It writes a manifest, Rego policy, report, and optional sample snapshots.

```bash
acs-generate init --non-interactive --name "Demo Agent" --points input,pre_tool_call,output --tool send_email:internal --deny-keyword secret --escalate-tool send_email --sample-snapshot --out build/demo-acs
```

The output directory must be empty unless `--force` is supplied. Add `--strict` when local OPA validation must match CI.

Use child manifests with `extends` for additive changes after generation. A child can add metadata keys, policies, annotators, tools, or new intervention points, but it cannot replace an existing intervention point policy, target, or `tool_name_from` with a different value.

File based `extends` stays inside the top level manifest root. Place a parent manifest below the child root, such as `base/manifest.yaml`, or use a manifest-chain constructor when loading sibling manifests through an SDK.

## Next steps

- Read the normative contract in [`spec/SPECIFICATION.md`](spec/SPECIFICATION.md).
- Review host obligations and boundaries in [`docs/security-model.md`](docs/security-model.md).
- Pick the right SDK surface with [`docs/sdk-surfaces.md`](docs/sdk-surfaces.md).
- Wrap a real agent framework using [`docs/adapter-matrix.md`](docs/adapter-matrix.md) and the [Framework adapters](README.md#framework-adapters) section of the README.
- Study runnable hosts under repository checkout path `examples/`.
