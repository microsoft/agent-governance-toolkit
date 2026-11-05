# Agent Control Specification Java SDK

This package is the Java host API of the Agent Control Specification (ACS). Like the [.NET SDK](../dotnet/README.md), it keeps orchestration
in managed code and reaches the published [`agent-control-spec`](https://github.com/responsibleai/agent-control-spec) engine through AGT's
Rust host C ABI (`sdk/rust/src/ffi.rs`). It uses the **Foreign Function & Memory API** (`java.lang.foreign`, final since Java 22), so
there is no JNI glue and no native code in this project.

- Java language level **25**; built and tested on JDK 25 and later.
- No decision logic lives here. What the engine decides is what happens: a `deny` stops the action, a `transform` replaces the policy target,
  an approval is bound to the exact action. Every failure fails closed.
- One runtime dependency: Jackson (`jackson-databind`) for the JSON the engine speaks.

```java
try (AgentControl control = AgentControl.fromPath("manifest.yaml")) {
    AgentControl.ToolRunResult result = control.runTool("web_search", args, a -> search(a));
    use(result.value());
} catch (AgentControlBlockedException blocked) {
    // the engine denied the action; blocked.result().verdict().reason() says why
}
```

Values are Jackson `JsonNode`s, because the snapshot the engine sees is JSON and so is every answer.

## What is in it

- `AgentControl`: `evaluate*` for a single intervention point (`evaluateInput`, `evaluateOutput`, `evaluatePreModelCall`,
  `evaluatePostModelCall`, `evaluatePreToolCall`, `evaluatePostToolCall`, `evaluateAgentStartup`, `evaluateAgentShutdown`) and `run`,
  `runModel`, `runTool` / `protectTool` that guard an action end to end (`input` + `output`, `pre_model_call` + `post_model_call`,
  `pre_tool_call` + `post_tool_call`). `Options` carries the ambient snapshot, the enforcement mode, a per-call approval resolver and the tool call id.
- `NativeRuntime`: the Rust engine as an `AgentControlRuntime`; thread-safe, `AutoCloseable`. Built from a manifest path, YAML, JSON or a chain of YAML
  manifests, with optional host `AnnotatorDispatcher` / `PolicyDispatcher` (FFM upcalls) and `PerfTelemetry`. Without dispatchers the bundled ones run
  (Rego through the OPA executable).
- `ArtifactValidator`: the engine's validation of a manifest and its Rego modules, as diagnostics.
- `AgentControlRuntime`: the seam to replace the engine in tests or with another backend.
- Records and enums for the wire types: `InterventionPoint`, `EnforcementMode`, `Decision`, `Verdict`, `Transform`, `Evidence`, `Warning`,
  `InterventionPointRequest`, `InterventionPointResult`.
- `ApprovalResolver`, `ApprovalResolution`, `AgentControlBlockedException`, `AgentControlSuspendedException`.

Not in this first version (they are separate concerns that can follow): buffered SSE streaming, framework adapters, the MCP tool provider, and the
host telemetry sinks.

## Escalation and approval

In `ENFORCE` mode a `deny` throws `AgentControlBlockedException`. A `deny` that carries an `approval` block is *liftable*: the `ApprovalResolver`
(on the `AgentControl`, or per call in `Options`) decides whether the action proceeds. It returns `ApprovalResolution.allow(result.actionIdentity())`,
`deny()` or `suspend(handle, result.actionIdentity())`.

- An approval consents to one exact action. The identity the resolver names must be the one the engine reported, or the action is blocked with
  `host_error:approval_identity_mismatch`.
- The resolver receives a **copy** of the result: whatever it does to it cannot change what is enforced.
- With no resolver, a resolver that throws or returns `null`, the `deny` stands (`host_error:approval_unresolved` / `approval_resolver_failed`).
- A `deny` without an `approval` block is final and never consults the resolver.
- `SUSPEND` throws `AgentControlSuspendedException` carrying the handle, for an approval that is decided elsewhere.

## Transforms

A `transform` verdict replaces the policy target. The SDK places the replacement where the policy target was: a target that is the value passed
to the action (`$snap.tool_call.args`) replaces it whole, a target inside it (`$snap.tool_call.args.query`, `$.model_request.messages[1].content`)
replaces that member only. A target that is not part of the value the action receives (the tool *name*, the whole snapshot) cannot be applied, so the
action is blocked with `host_error:transform_target_unsupported` instead of running on a wrong value.

## Spring AI and MCP (`spring-ai/`)

The module `agent-control-specification-spring-ai` (Spring AI 2.x, `./gradlew :spring-ai:build`) puts the engine in front of a Spring AI agent:

- `GuardedToolCallback` wraps a `ToolCallback`: `pre_tool_call` before the tool runs, `post_tool_call` before the model sees the result. A refusal
  is returned to the model as text (`NOT EXECUTED: ...`, replaceable) so the chat carries on without the tool.
- `GuardedToolCallbackProvider` wraps a whole `ToolCallbackProvider`. Spring AI's MCP client (`SyncMcpToolCallbackProvider`) is one, so this is the
  MCP adapter: `new GuardedToolCallbackProvider(control, mcpProvider).getToolCallbacks()`. List the MCP tools under `tools:` in the manifest.
- `AgentControlAdvisor` is a `CallAdvisor`: `pre_model_call` on the messages, `post_model_call` on the answer. Only `allow` passes; a `deny`, a failure
  or a `transform` blocks (a Spring AI request or response cannot be rewritten faithfully; use `runModel` for transforms).

A streamed call is buffered (checked as one answer, then emitted). Not covered yet: an auto-configuration for Spring Boot.

## The native library

Build it once from `policy-engine`:

```bash
cargo build --release -p agent_control_specification --features opa,bundled-dispatchers
```

The SDK looks for `agent_control_specification.dll`, `libagent_control_specification.so` or `libagent_control_specification.dylib` in this order:

1. the system property `acs.native.library` (a file path);
2. the environment variable `ACS_NATIVE_LIBRARY` (a file path);
3. the jar resource `/native/<os>-<arch>/<file>` (copied to a temporary file), e.g. `native/linux-x86_64/libagent_control_specification.so`;
4. the library name itself, left to the operating system loader (`PATH`, `LD_LIBRARY_PATH`, ...).

A missing library fails with an `AcsException` that says how to build it.

### Shipping the library inside the jar

`./gradlew jar -Pacs.native.library=<built library>` stages the library under `build/native/<os>-<arch>/` (`stageNativeLibrary`) and puts it in the
jar at `/native/<os>-<arch>/<file>`, where the loader finds it with no property or environment variable; the jar then runs on that platform only.
For a jar that serves several platforms, build the library on each (a CI matrix), collect the files as `<os>-<arch>/<file>` (`windows-x86_64`,
`linux-x86_64`, `linux-aarch64`, `macos-aarch64`, ...) in one directory and pass it with `-Pacs.native.bundle=<dir>`.

Run the JVM with `--enable-native-access=ALL-UNNAMED` (or the module name) so that Java 24 and later do not warn about native access.

For Rego policies the bundled dispatcher runs the OPA executable. Put `opa` on the `PATH`, set `ACS_OPA_PATH` before the JVM starts, or call
`AgentControl.builder().opaPath("/path/to/opa")`, which sets `ACS_OPA_PATH` for the process (`System.getenv` is a read-only snapshot, so the SDK sets
it through the C runtime: `setenv`, or `SetEnvironmentVariableW` on Windows).

## Host callbacks

`AnnotatorDispatcher` and `PolicyDispatcher` are called by the engine, from any thread, through FFM upcall stubs: implementations must be
thread-safe. Nothing may escape an upcall (it would terminate the JVM), so every callback catches `Throwable` and answers `NULL`, which the engine reports
as a failed dispatch and turns into a deny. An annotator that times out throws an exception whose message contains
`AnnotatorDispatcher.ANNOTATION_TIMEOUT_REASON` to get the engine's reserved timeout reason.

## Build and test

```bash
cd policy-engine/sdk/java
./gradlew build -Pacs.native.library=../../target/release/libagent_control_specification.so
```

`JAVA_HOME` must be JDK 25 or later (pass `-Pacs.jdk=<n>` to pick a toolchain). Without the native library the tests that need the engine are
skipped and the pure Java tests still run. The conformance test (`ConformanceTest`) runs the shared corpus in `tests/conformance/cases` through the
binding; a case that does not name `java` in `sdk_support` is treated as the `dotnet` entry says, since both bind the same C ABI.

| Test class | What it checks | Needs the library |
|---|---|---|
| `AgentControlTest` | enforcement, approval, identity, transforms, modes, wire names, against a scripted runtime | no |
| `NativeLibraryTest` | where the library is looked for | no |
| `NativeRuntimeTest` | the binding against the engine: host callbacks, fail-closed upcalls, concurrency, close, manifest chain | yes |
| `AgentControlNativeTest` | a tool call guarded end to end: transform, deny, unknown tool, approval bound to the engine's identity | yes |
| `ArtifactValidatorTest` | the engine's manifest and Rego diagnostics (the valid case also needs OPA) | yes |
| `ConformanceTest` | the shared conformance corpus | yes |
