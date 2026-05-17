# Azure Sandbox Isolation Design

| Field       | Value                                |
|-------------|--------------------------------------|
| **Status**  | Draft                                |
| **Author**  | Amol Ravande                         |
| **Reviewer**| AGT Core Team                        |
| **Date**    | 2026-04-29                           |
| **Package** | `agent-sandbox`                      |
| **Module**  | `agent_sandbox.azure_sandbox_provider` |

## Motivation

`agent-sandbox` already ships one backends: `DockerSandboxProvider`
(local Docker, optional gVisor / Kata). This require the agent to run on a host with
container or hypervisor privileges and provide isolation only on that
host.

`ACASandboxProvider` adds a **cloud backend** that maps a sandbox
session onto an **Azure Container Apps sandbox** inside an Azure
**sandbox group**.  This lets governance toolkits run agents:

- Without giving the host machine access to Docker, KVM, or Hyper-V.
- With Azure-native isolation (per-sandbox VM/microVM, managed identity,
  egress proxy) and Azure-native lifecycle features (auto-suspend,
  snapshot/commit, ports).
- Inside an Azure subscription that already has policy controls,
  metering, and audit logging.

The provider is a thin adapter: every Azure-specific verb already exists
on `azure.sandbox.SandboxClient` (data plane) and
`azure.mgmt.sandbox.SandboxGroupManagementClient` (control plane).  The
adapter's job is to translate `agent-os` policies into Azure primitives
and present a `SandboxProvider`-shaped API.

## Design Goals

1. Conform to the `SandboxProvider` ABC — `create_session`,
   `execute_code`, `destroy_session`, `is_available`, plus the default
   async / status methods inherited from the base class.
2. Reuse `azure-sandbox` and `azure-mgmt-sandbox` for all Azure I/O — no
   new HTTP code paths.
3. Apply `agent-os` policy at session creation time:
   - `defaults.max_memory_mb`, `defaults.max_cpu` → sandbox `memory` /
     `cpu`.
   - `network_allowlist` → sandbox `egressPolicy` with
     `defaultAction=Deny` plus per-host `Allow` rules.
   - `tool_allowlist` is enforced host-side via the per-call
     `PolicyEvaluator` gate (Azure exec is opaque to host tools, so the
     allowlist is checked before the call leaves the agent process).
4. Fail closed: if `azure-sandbox` is not installed, the provider
   reports `is_available() == False` and refuses to create sessions.
5. Be safe to construct without an active subscription — auth is lazy,
   the constructor does not call Azure.

## Non-Goals

- Wrapping the full surface of `azure-sandbox` (snapshots, ports,
  volumes, files, telemetry).  Those remain available through
  `ACASandboxProvider._data_client` for power users but are not part
  of the `SandboxProvider` contract.
- Multi-region / multi-subscription orchestration — one provider
  instance is bound to one subscription, resource group, and sandbox
  group.
- Implementing the optional `save_state` / `restore_state` checkpoint
  API.  Azure already exposes `commit_sandbox` and `create_snapshot` on
  the data-plane client; a future revision can surface those through
  the provider once the ABC formalizes them.

## Component Overview

```
┌──────────────────────────────────────────────────────────────┐
│                    SandboxProvider (ABC)                      │
│  create_session / execute_code / destroy_session              │
└──────────────┬─────────────────────────┬─────────────────────┘
               │                         │
   ┌───────────┴───────────┐  ┌──────────┴────────────┐
   │ DockerSandboxProvider │  │ ACASandboxProvider  │
   │   (local containers)  │  │  (Azure Container     │
   │                       │  │   Apps sandboxes)     │
   └───────────────────────┘  └──────────┬────────────┘
                                         │
                         ┌───────────────┴────────────────┐
                         │                                │
                ┌────────┴─────────┐         ┌────────────┴──────────┐
                │  azure-sandbox   │         │ azure-mgmt-sandbox    │
                │  (data plane)    │         │ (ARM control plane)   │
                │                  │         │                       │
                │ • create_sandbox │         │ • create_group        │
                │ • exec           │         │ • get_group           │
                │ • set_egress…    │         │ • delete_group        │
                │ • delete_sandbox │         │                       │
                └────────┬─────────┘         └───────────────────────┘
                         │
                         ▼
            management.containerapps.azure.com
            (per-sandbox container / microVM with
             egress proxy and managed identity)
```

## Mapping from `SandboxProvider` to Azure

| `SandboxProvider`              | `ACASandboxProvider` action                                        | Azure primitive |
|--------------------------------|----------------------------------------------------------------------|-----------------|
| `create_session(agent_id, policy, config)` | Bootstrap group (optional) → `create_sandbox` → `set_egress_policy` | `Microsoft.App/sandboxGroups/sandboxes` |
| `execute_code(agent_id, sid, code)`        | `PolicyEvaluator.evaluate` → `exec` (base64-piped python3)          | `…/sandboxes/{id}/executeShellCommand` |
| `destroy_session(agent_id, sid)`           | `delete_sandbox`                                                    | `DELETE …/sandboxes/{id}` |
| `get_session_status(agent_id, sid)`        | In-memory bookkeeping (READY / DESTROYED)                           | — |
| `is_available()`                           | Returns `True` only if `azure-sandbox` was importable               | — |

Async methods inherit the default `asyncio.to_thread` delegation from
the ABC.  A future revision can replace them with native async once
`azure-sandbox` exposes an async client.

## Lifecycle

### `create_session`

1. Validate `agent_id` and `sandbox_group` against
   `^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$` to keep them safe inside ARM and
   data-plane URLs.
2. Project the policy onto a `SandboxConfig` via
   `aca_config_from_policy`:
   - `defaults.max_memory_mb` → `memory_mb`
   - `defaults.max_cpu` → `cpu_limit`
   - `network_allowlist` non-empty → `network_enabled = True`
3. If a policy is supplied, instantiate
   `agent_os.policies.evaluator.PolicyEvaluator` and store it under
   `(agent_id, session_id)`.  When `agent-os-kernel` is not installed,
   log a warning and run ungated (matches the Docker provider).
4. Optionally bootstrap the sandbox group via
   `SandboxGroupManagementClient.create_group` when
   `ensure_group_location` is set and the group does not yet exist.
5. Call `SandboxClient.create_sandbox` with:
   - `disk` (default `"ubuntu"`) — the public disk image to provision
     from.
   - `cpu` — millicores derived from `cpu_limit`
     (`max(100, round(cpu_limit * 1000))m`).
   - `memory` — `max(128, memory_mb)Mi`.
   - `environment` — sanitized `env_vars` from the config (the host
     side does not pass through `LD_PRELOAD` etc; that filtering lives
     in the Docker provider and can be added here later if needed).
6. If the policy declares a `network_allowlist`, post an egress policy
   to the new sandbox:

   ```json
   {
     "defaultAction": "Deny",
     "hostRules": [
       {"pattern": "*.github.com", "action": "Allow"},
       {"pattern": "pypi.org",    "action": "Allow"}
     ]
   }
   ```

7. Persist `sandbox_id`, `evaluator`, and `config` in per-session maps
   guarded by an `RLock`, then return a `SessionHandle` whose
   `session_id` is the Azure sandbox ID.

### `execute_code`

1. Look up the sandbox / evaluator / config under
   `(agent_id, session_id)`; raise `RuntimeError` if missing.
2. If a `PolicyEvaluator` is bound to the session, evaluate
   `{"agent_id", "action": "execute", "code", **context}` and raise
   `PermissionError` on deny — exactly matching the Docker provider
   contract.
3. Base64-encode the source and invoke the data-plane `exec`:

   ```text
   echo <b64> | base64 -d | python3
   ```

   This avoids quoting hazards with multi-line code, embedded quotes,
   and shell metacharacters.
4. Wrap the response into `SandboxResult`:
   - `success = exitCode == 0`
   - `stdout` / `stderr` truncated at 10 KB to bound memory.
   - `duration_seconds` measured by the provider.
   - If `duration_seconds` exceeds `cfg.timeout_seconds`, set
     `killed=True` with a `kill_reason` so callers can detect runaway
     executions even though the data-plane API does not surface a kill.
5. Return an `ExecutionHandle` with status `COMPLETED` or `FAILED`.

### `destroy_session`

1. Pop the in-memory state under `(agent_id, session_id)`.
2. Call `SandboxClient.delete_sandbox`; log and swallow failures so
   `destroy_session` is idempotent and safe to call from `__exit__`.

## Policy → Azure Resource Mapping

| `agent-os` policy field | Azure primitive | Notes |
|-------------------------|-----------------|-------|
| `defaults.max_memory_mb` | sandbox `resources.memory` (`"{n}Mi"`) | Floor 128 MiB |
| `defaults.max_cpu`       | sandbox `resources.cpu` (`"{n}m"`)     | Floor 100 m |
| `network_allowlist`      | `egressPolicy.hostRules`               | Implies `defaultAction = "Deny"` |
| `tool_allowlist`         | host-side `PolicyEvaluator` gate       | Cannot be enforced inside the sandbox VM |
| `env_vars` (config)      | sandbox `environment`                  | Host-side blocked-vars filter not applied yet |
| `timeout_seconds`        | provider-side wall-clock check         | Surfaced through `SandboxResult.killed` |

`tool_allowlist` cannot be enforced inside the Azure sandbox itself —
the sandbox VM has no host-side `ToolCallProxy` because the host
process is not on the same machine.  The toolkit therefore enforces it
on the calling side via `PolicyEvaluator.evaluate`, which the provider
runs **before** every `exec` call.  Agents that need in-sandbox tool
brokering should run a proxy of their own and add it to
`network_allowlist`.

## Security Considerations

- **Auth**: `DefaultAzureCredential` by default; callers may inject any
  `azure.core.credentials.TokenCredential`.  No tokens are logged.
- **Name validation**: `agent_id` and `sandbox_group` are rejected if
  they do not match `[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}`, eliminating ARM
  path injection.
- **Code transport**: source is base64-encoded before the `exec` call
  so it is never interpolated into a shell command, blocking shell
  injection through the agent's own code.
- **Egress**: when a policy declares any allowlisted host, the egress
  policy is forced to `defaultAction = "Deny"` so the absence of a host
  rule is fail-closed.
- **Lifecycle**: `destroy_session` always tries `delete_sandbox`, even
  when local bookkeeping is missing, to limit orphan resources.
- **Fail-open vs fail-closed**: missing `agent-os-kernel` logs a warning
  and runs ungated.  This matches `DockerSandboxProvider` so policy
  behavior is consistent across backends; deployments that require
  fail-closed enforcement should pin `agent-os-kernel` as a hard
  dependency.

## Usage

```python
from agent_sandbox import ACASandboxProvider
from agent_os.policies import PolicyDocument

policy = PolicyDocument.from_yaml("policies/research_policy.yaml")

with ACASandboxProvider(
    resource_group="agents-rg",
    sandbox_group="agents",
    ensure_group_location="westus2",
) as provider:
    handle = provider.create_session("agent-1", policy=policy)
    exec_handle = provider.execute_code(
        "agent-1",
        handle.session_id,
        "import requests; print(requests.get('https://pypi.org').status_code)",
    )
    print(exec_handle.result.stdout)
    provider.destroy_session("agent-1", handle.session_id)
```

```python
import asyncio
from agent_sandbox import ACASandboxProvider

async def main() -> None:
    provider = ACASandboxProvider(
        resource_group="agents-rg",
        sandbox_group="agents",
    )
    handle = await provider.create_session_async("agent-1")
    try:
        exec_handle = await provider.execute_code_async(
            "agent-1", handle.session_id, "print('hello azure')"
        )
        print(exec_handle.result.stdout)
    finally:
        await provider.destroy_session_async("agent-1", handle.session_id)

asyncio.run(main())
```

## Open Questions

- Should we expose `commit_sandbox` / `create_snapshot` through the
  optional `save_state` / `restore_state` API?  The ABC currently
  documents these only on `DockerSandboxProvider`.
- Should `env_vars` go through the same `_BLOCKED_ENV_VARS` filter that
  the Docker provider uses?  The risk profile is different (no shared
  kernel) but consistency is valuable.
- Should the provider hold a single sandbox per `agent_id` and reuse it
  across sessions, mirroring Docker's session-scoped container reuse?
  Today every session creates and deletes a sandbox.

## Summary

`ACASandboxProvider` plugs Azure Container Apps sandboxes into the
existing `SandboxProvider` interface used by the agent governance
toolkit.  It composes the existing `azure-sandbox` and
`azure-mgmt-sandbox` clients, translates `agent-os` policy fields into
Azure CPU / memory / egress primitives, and runs the same
`PolicyEvaluator` gate as the Docker backend so policy semantics stay
uniform across local and cloud sandboxes.
