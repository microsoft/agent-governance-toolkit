# Agent Control Specification Node SDK

Phase A exposes the synchronous Rust core through a thin napi-rs binding. Build the native addon before using the package locally:

```sh
npm install
npm run build
```

```js
const { AgentControl, InterventionPoint } = require("agent-control-specification");

// Zero-config. With no dispatcher arguments the bundled OPA policy dispatcher and
// annotator dispatcher are wired from the manifest, so a Rego-policy host needs no
// dispatcher code.
const agentControl = AgentControl.fromPath("manifest.yaml");

const result = await agentControl.evaluateInterventionPoint(
  InterventionPoint.Input,
  { input: { text: "hello" } },
);
```

Supply host-specific dispatchers when annotators are local or policy outputs need post-processing. The dispatcher arguments are optional and default independently, so a host can override the annotator dispatcher while keeping the bundled OPA policy default:

```js
const agentControl = AgentControl.fromNative(manifestYamlOrJson, {
  async dispatch(annotatorName, annotatorConfig, preliminaryPolicyInput) {
    return { ok: true };
  },
});
```

`NativeRuntimeClient` accepts a manifest string or JSON value plus optional async-capable annotator and policy dispatchers, falling back to the bundled defaults when a dispatcher is omitted. The native layer calls the Rust core off the Node main thread and bridges dispatcher promises back into the synchronous core. `AgentControl.run`, `protectTool`, and `runTool` mirror the Python SDK orchestration. See [Zero-config construction](../../README.md#zero-config-construction).

## Escalation and approval

In enforce mode a `deny` verdict throws `AgentControlBlockedError`. An `escalate` verdict consults an optional approval resolver, a host callback that decides whether the action proceeds. Supply a resolver on the instance with `new AgentControl(runtimeClient, approvalResolver)` (or `AgentControl.fromNative(manifest, annotator, policy, approvalResolver)`) or override it per call with the `approvalResolver` option on `run`, `runTool`, and `protectTool`. The resolver returns `ApprovalResolution.allow()`, `ApprovalResolution.deny()`, or `ApprovalResolution.suspend(handle)`.

- allow proceeds without applying escalate effects, since only `allow` and `warn` apply effects
- deny, an unrecognized result, or a resolver that rejects throws `AgentControlBlockedError` (the original error is preserved as `cause`)
- suspend throws `AgentControlSuspendedError` carrying the opaque host handle
- with no resolver an `escalate` verdict fails closed to a block

The resolver is consulted only for `escalate` and only in enforce mode. A `deny` never consults it. `AgentControlBlockedError` and `AgentControlSuspendedError` both extend `AgentControlInterruptionError`. The GitHub Copilot permission hook integration maps `escalate` to a permission deny, since that surface exposes only allow and deny.
