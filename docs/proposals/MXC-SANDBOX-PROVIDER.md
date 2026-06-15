# MXC Sandbox Provider Design

| Field        | Value                                              |
|--------------|----------------------------------------------------|
| **Status**   | Draft                                              |
| **Author**   | AGT Core Team                                       |
| **Reviewer** | AGT Core Team                                        |
| **Date**     | 2026-06-08                                          |
| **Package**  | `agent-sandbox`                                     |
| **Upstream** | [`microsoft/mxc`](https://github.com/microsoft/mxc) (MIT) |

## Motivation

`agent-sandbox` already ships three backends behind the `SandboxProvider`
ABC: `DockerSandboxProvider` (hardened containers), `HyperLightSandboxProvider`
(micro-VMs), and `ACASandboxProvider` (managed cloud sessions). Each occupies a
different point on the isolation/portability curve, but all three carry an
external dependency: a Docker daemon, a hypervisor plus the `hyperlight-sandbox`
SDK, or an Azure subscription.

[MXC](https://github.com/microsoft/mxc) (Microsoft eXecution Container) fills a
gap: a **single native binary** that runs untrusted code behind whichever
OS-native containment primitive the host already provides — no daemon, no
hypervisor SDK, no cloud account. It selects a platform-appropriate backend
automatically:

| Platform | Default backend | Additional backends |
|----------|-----------------|---------------------|
| Windows 11 24H2+ | `processcontainer` | `windows_sandbox`, `wslc`, `microvm`, `hyperlight`, `isolation_session` |
| Linux x64 / ARM64 | `bubblewrap` | `lxc`, `microvm`, `hyperlight` |
| macOS ARM64 / x64 | `seatbelt` | — |

MXC is configured entirely through a **versioned JSON schema** (current stable:
`0.6.0-alpha`) covering filesystem policy (read-only / read-write path lists),
network policy (outbound allow/block, host filtering), UI policy, and an
execution timeout. The stable one-shot backends (`processcontainer`,
`bubblewrap`, `lxc`) need no experimental opt-in; everything else requires
`--experimental`.

Adopting MXC as a backend gives AGT an OS-native sandbox that is cheap to run in
CI, on developer laptops, and in constrained environments where neither Docker
nor a hypervisor is available.

> **Security note.** MXC is published as an early preview. Per its README, "no
> MXC profiles should be treated as security boundaries currently" — the
> generated policies are known to be overly permissive while the project
> matures. `MxcSandboxProvider` should be used for defense-in-depth and
> developer ergonomics, not as a hard isolation guarantee, until MXC stabilizes.

## Integration Approach

MXC exposes **no Python SDK** — only a TypeScript SDK (`@microsoft/mxc-sdk`) and
the native binary. `MxcSandboxProvider` therefore integrates by driving the
native binary as a subprocess:

| Platform | Binary |
|----------|--------|
| Windows | `wxc-exec.exe` |
| Linux | `lxc-exec` (serves both LXC and Bubblewrap) |
| macOS | `mxc-exec-mac` |

The binary accepts a JSON config by file path (`wxc-exec config.json`) or
base64 (`--config-base64 <b64>`), couples the sandboxed process's stdio to the
caller, and exits when the process finishes. `MxcSandboxProvider`:

1. Resolves the binary from an explicit `binary_path`, then the `MXC_BINARY`
   environment variable, then `PATH`.
2. Renders an `MxcConfig` to the schema-`0.6.0-alpha` JSON document.
3. Spawns the binary with `subprocess.run`, capturing stdout/stderr with a hard
   timeout (the MXC `timeoutMs` budget plus a teardown grace period).
4. Maps the exit code and captured output into a `SandboxResult`.

The provider implements the same `SandboxProvider` ABC as the other backends, so
application code can swap to MXC without changes.

## Session Model

This is the most important design decision and the biggest difference from the
container/VM backends.

MXC's stable native binary is **one-shot**: it runs the full lifecycle
(provision → start → exec → stop → deprovision) for a single `commandLine` and
then tears the sandbox down. There is no long-lived, reusable guest the way a
Docker container or a Hyperlight micro-VM persists across `execute_code` calls.

To still honor the session-based ABC, a *session* is modelled as a durable
**bundle** rather than a running process:

- the resolved `MxcConfig`,
- the policy evaluator, and
- a per-session workspace directory on the host.

Each `execute_code` (or `run`) call spawns a **fresh one-shot MXC sandbox** from
that bundle. The consequences are explicit:

- **Guest state does not persist across executions.** In-memory variables,
  interpreter state, and writes outside the read-write workspace are discarded
  when each invocation exits.
- **The session's `output/` directory persists on the host** between
  executions. It is exposed to the sandbox as a read-write path, so callers that
  need cross-call persistence write there.
- **Submitted code is written to a file** in the session's read-only `scripts/`
  directory and executed as `<interpreter> <script>`. This avoids shell-quoting
  arbitrary code into `commandLine`.

MXC does offer a stateful provision/exec/stop lifecycle through its TypeScript
SDK and the `0.7.0-dev` schema. Wiring that path (e.g. via a long-lived helper
process) is a possible future enhancement and is out of scope for this
binary-driven provider.

## SandboxProvider Interface Mapping

The `SandboxProvider` ABC, its `create_session` / `execute_code` /
`destroy_session` lifecycle, and the returned handle/enum types are defined in
[DOCKER-SANDBOX-ISOLATION-DESIGN.md](./DOCKER-SANDBOX-ISOLATION-DESIGN.md#generic-sandboxprovider-interface)
and reused unchanged.

| Method | `MxcSandboxProvider` behavior |
|--------|-------------------------------|
| `create_session(agent_id, policy, config)` | Builds an `MxcConfig` from `config`, merges policy-derived fields (timeout, mounts, network allowlist), creates a per-session workspace with `scripts/` (read-only) and `output/` (read-write) directories, stores the bundle, and returns a `SessionHandle`. No process is spawned. |
| `execute_code(agent_id, session_id, code, *, context)` | Evaluates the policy on the host, runs the static `enforce_no_subprocess_execution` scan, writes `code` to a script file, and spawns a fresh one-shot MXC sandbox running `<interpreter> <script>`. Returns stdout/stderr/exit code in a `SandboxResult` wrapped in an `ExecutionHandle`. `context`, when given, is exposed to the guest as the JSON-encoded `MXC_CONTEXT` environment variable. |
| `destroy_session(agent_id, session_id)` | Removes the host-side workspace and the registry entry. No process to stop — MXC sandboxes are already torn down after each invocation. |
| `run(agent_id, command, config, *, session_id)` | Low-level escape hatch: spawns a one-shot MXC sandbox running `command` (a `list[str]` joined via `shlex.join`). Reuses a session bundle when one exists, otherwise builds an ephemeral config and a throwaway workspace. |
| `is_available()` | `True` if the MXC native binary was resolved (explicit path, `MXC_BINARY`, or `PATH`). |
| `get_session_status(...)` | `READY` while the bundle exists, else `DESTROYED`. |

In addition to the ABC surface, the provider offers a one-shot
convenience that needs no `session_id`:

| Method | `MxcSandboxProvider` behavior |
|--------|-------------------------------|
| `run_once(agent_id, code, *, policy, config, context)` | Creates a session, runs `execute_code`, and destroys the session in one call (cleanup in a `finally`, so it tears down on success, failure, or a guard violation). Applies the same host-side policy gate and code scan as `execute_code`. Use when no cross-call `output/` persistence is needed. `run_once_async` is the awaitable variant. |

`execute_code` keeps its required `session_id` because a *session* is the
durable bundle (config + policy evaluator + persistent `output/`
directory) that outlives the one-shot sandboxes; `run_once` is the
sugar for callers that do not need that bundle to persist.

Code written against the `SandboxProvider` ABC works unchanged on MXC.

## Configuration (`MxcConfig`)

`MxcConfig` models the well-known schema-`0.6.0-alpha` fields as a typed
dataclass and renders them to the JSON document MXC consumes:

| `MxcConfig` field | MXC schema field | Notes |
|-------------------|------------------|-------|
| `version` | `version` | Defaults to `0.6.0-alpha` (current stable). |
| `backend` | `backend` | `None` lets MXC pick the platform default. Experimental backends force `experimental=True`. |
| `readonly_paths` | `filesystem.readonlyPaths` | Host paths exposed read-only. |
| `readwrite_paths` | `filesystem.readwritePaths` | Host paths exposed read-write. |
| `allow_outbound` | `network.allowOutbound` | Defaults to `False` (no egress). |
| `allowed_hosts` | `network.allowedHosts` | Only emitted when `allow_outbound` is true. |
| `timeout_ms` | `timeoutMs` | Wall-clock budget. |
| `env_vars` | `process.environment` | Host-side environment for the guest. |
| `extra_config` | (deep-merged) | Verbatim passthrough for schema keys not modelled directly (e.g. UI policy). MXC validates the merged document; the provider does not interpret it. |

`mxc_config_from_policy(policy, base)` performs the same policy → config
translation as `docker_config_from_policy` and `hyperlight_config_from_policy`,
reading well-known attributes (`defaults.timeout_seconds`,
`sandbox_mounts.input_dir` / `output_dir`, `network_allowlist`) and leaving
missing attributes unchanged. `memory_mb` / `cpu_limit` from the generic
`SandboxConfig` are dropped because the `0.6.0-alpha` schema has no resource-cap
fields — MXC relies on the backend's own resource model.

### Policy → JSON conversion helpers

The config module exposes two convenience converters that tie the
translation and rendering steps together, so a governance policy can be
turned into the exact JSON document MXC consumes:

| Helper | Input | Output |
|--------|-------|--------|
| `policy_to_mxc_json(policy, command_line, *, base=None)` | An in-memory policy object (Agent-OS `PolicyDocument` or any duck-typed equivalent) | MXC JSON config `dict` |
| `policy_yaml_to_mxc_json(yaml_path, command_line, *, base=None)` | A policy **YAML file** path | MXC JSON config `dict` |

`policy_yaml_to_mxc_json` parses the YAML with `yaml.safe_load` and exposes
it to `mxc_config_from_policy` through a recursive attribute view
(`_AttrDict`). This keeps the converter dependency-free — it does not import
the Agent-OS `PolicyDocument` model — while still honoring the
`sandbox_mounts` block, which is a native `PolicyDocument` field
(`input_dir` mounted read-only, `output_dir` read-write).

What the converters deliberately do **not** emit:

- **`tool_allowlist`** — MXC's schema has no tool concept; tool-call
  admission is enforced **host-side** by the `PolicyEvaluator` before the
  sandbox is spawned (see Policy Enforcement Layers), never inside the
  MXC JSON.
- **`max_cpu` / `max_memory_mb`** — absent from the `0.6.0-alpha` schema;
  carried as informational on `MxcConfig` but not rendered, so the JSON
  never claims enforcement MXC does not provide.

Emitting either into the JSON would give a false sense of enforcement, so
they are intentionally omitted rather than silently ignored by MXC.

## Policy Enforcement Layers

`MxcSandboxProvider` applies the same defense-in-depth ordering as the other
providers:

1. **Host-side policy gate.** When a policy is attached, `PolicyEvaluator`
   (from `agent-os-kernel`, if installed) evaluates each execution before any
   sandbox is spawned. A denied decision raises `PermissionError` and MXC is
   never invoked.
2. **Static code scan.** `enforce_no_subprocess_execution(code)` rejects obvious
   process-spawning APIs before the code reaches the sandbox.
3. **MXC containment.** Filesystem and network policy from `MxcConfig` constrain
   what the guest can touch, enforced by the selected backend.
4. **Process isolation.** Only the explicitly configured environment (plus
   `PATH`) is passed to the child; the parent's full environment is **not**
   inherited, so host secrets are not leaked into the sandbox launcher.

## Availability and Usage

```python
from agent_sandbox import MxcSandboxProvider, SandboxConfig

# Auto-detects wxc-exec / lxc-exec / mxc-exec-mac on PATH (or MXC_BINARY).
provider = MxcSandboxProvider(backend="bubblewrap")  # Linux

if not provider.is_available():
    raise RuntimeError("MXC binary not found")

handle = provider.create_session(
    agent_id="agent-1",
    config=SandboxConfig(timeout_seconds=30, network_enabled=False),
)

result = provider.execute_code(
    handle.agent_id,
    handle.session_id,
    "print('hello from MXC')",
)
print(result.result.stdout)

provider.destroy_session(handle.agent_id, handle.session_id)
```

Because MXC ships no Python package, the provider adds **no new dependency** to
`agent-sandbox`. Operators install the MXC binary out of band (build from
source per the MXC README, or drop a release binary on `PATH`).

## Testing

| Suite | File | Gating |
|-------|------|--------|
| Unit | `tests/test_mxc_sandbox.py` | Always runs. Hermetic — binary discovery is satisfied with `sys.executable` and `subprocess.run` is monkeypatched with a fake that captures argv/env and reads back the rendered config JSON. No MXC install, OS sandbox, or network required. |
| Integration | `tests/test_mxc_integration.py` | Skipped unless `AGT_MXC_INTEGRATION=1` **and** a real MXC binary is discoverable (`MXC_BINARY` or `PATH`). Exercises a real OS sandbox end to end. |

Unit coverage spans `MxcConfig` validation/rendering, policy translation
(`mxc_config_from_policy`, `policy_to_mxc_json`, `policy_yaml_to_mxc_json`,
including the `sandbox_mounts` block and the deliberate omission of
`tool_allowlist` / CPU / memory), binary discovery, the
create/execute/destroy lifecycle, raw `run`, spawn behaviour
(`--experimental` / `--debug` argv flags, env isolation, timeout → killed,
output truncation, missing binary), and the security guards (code scanner
and policy-deny gate).

The integration suite verifies a real execute with captured stdout, that a
non-zero exit surfaces as a `SandboxResult` failure rather than a host
crash, and that the per-session workspace is removed on `destroy_session`.
To run it against a local MXC build:

```bash
export MXC_BINARY=/path/to/lxc-exec   # or wxc-exec / mxc-exec-mac
export AGT_MXC_INTEGRATION=1
pytest agent-governance-python/agent-sandbox/tests/test_mxc_integration.py -v
```

## Limitations and Future Work

- **No cross-execution guest state.** By design (see [Session Model](#session-model)).
  Use the persistent `output/` directory for state that must survive.
- **No resource caps in `0.6.0-alpha`.** Memory/CPU limits from `SandboxConfig`
  are not expressed. Revisit when the schema gains resource fields.
- **Early-preview security posture.** MXC profiles are not yet hard security
  boundaries; treat this provider as defense-in-depth.
- **State-aware lifecycle.** The `0.7.0-dev` provision/exec/stop API could back a
  truly persistent session in a follow-up.
- **Backend matrix testing.** Each containment backend has distinct filesystem
  and network semantics; integration coverage should expand per platform.
