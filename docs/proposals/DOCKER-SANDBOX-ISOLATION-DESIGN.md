# Docker Sandbox Isolation Design

| Field       | Value                         |
|-------------|-------------------------------|
| **Status**  | Draft                         |
| **Author**  | Amol Ravande                  |
| **Reviewer**| AGT Core Team                 |
| **Date**    | 2026-04-20                    |
| **Package** | `agent-sandbox`               |

## Motivation

The agent governance toolkit currently has **no sandboxing capability**.  Governance policies can restrict which actions an agent is allowed to perform, but once an action is permitted, agent code runs directly on the host with full access to the filesystem, network, and system resources.  This means:

- A misbehaving or compromised agent can read/write arbitrary files, exfiltrate data, or consume unbounded resources — even if its policy only permits a narrow set of actions.
- There is no way to enforce resource limits (CPU, memory, network) on individual agents.
- There is no mechanism to checkpoint agent state and roll back after failures.
- Policy enforcement is limited to the action level — it cannot constrain the runtime environment (filesystem access, network egress, process creation) of permitted actions.

`agent-sandbox` closes this gap by providing a **generic sandbox provider interface** with pluggable backends.

## Generic SandboxProvider Interface

The `SandboxProvider` abstract base class defines a **backend-agnostic API** for sandboxed agent execution.  Any sandbox backend — Docker, Hyperlight micro-VMs, cloud sandbox services, or custom providers — implements three core lifecycle methods:

| Method | Purpose |
|--------|---------|
| `create_session(agent_id, policy, config)` → `SessionHandle` | Provision a sandbox with policy-driven resource limits, tool proxy, and network rules; returns `agent_id` + `session_id` |
| `execute_code(agent_id, session_id, code, *, ...)` → `ExecutionHandle` | Evaluate policy allow/deny, then run code in a session; returns `execution_id` + result |
| `destroy_session(agent_id, session_id)` | Tear down the sandbox and release resources |
| `get_session_status(agent_id, session_id)` → `SessionStatus` | Poll session lifecycle state |
| `get_execution_status(agent_id, session_id, execution_id)` → `ExecutionHandle` | Poll execution state (cloud providers) |
| `cancel_execution(agent_id, session_id, execution_id)` → `bool` | Cancel a running execution |
| `create_session_async(agent_id, policy, config)` → `SessionHandle` | Async version of `create_session` — delegates to sync via `asyncio.to_thread` by default |
| `execute_code_async(agent_id, session_id, code, *, ...)` → `ExecutionHandle` | Async version of `execute_code` — delegates to sync via `asyncio.to_thread` by default |
| `destroy_session_async(agent_id, session_id)` | Async version of `destroy_session` — delegates to sync via `asyncio.to_thread` by default |
| `cancel_execution_async(agent_id, session_id, execution_id)` → `bool` | Async version of `cancel_execution` — delegates to sync via `asyncio.to_thread` by default |

#### Data Types

| Type | Purpose |
|------|---------|
| `SessionHandle` | Returned by `create_session`; holds `agent_id`, `session_id`, `status` |
| `ExecutionHandle` | Returned by `execute_code`; holds `execution_id`, `agent_id`, `session_id`, `status`, `result` |
| `SessionStatus` | Enum: `PROVISIONING`, `READY`, `EXECUTING`, `DESTROYING`, `DESTROYED`, `FAILED` |
| `ExecutionStatus` | Enum: `PENDING`, `RUNNING`, `COMPLETED`, `CANCELLED`, `FAILED` |

```python
from abc import ABC, abstractmethod

class SandboxProvider(ABC):
    # --- Sync (required) ---
    @abstractmethod
    def create_session(
        self,
        agent_id: str,
        policy: PolicyDocument | None = None,
        config: SandboxConfig | None = None,
    ) -> SessionHandle: ...

    @abstractmethod
    def execute_code(
        self,
        agent_id: str,
        session_id: str,
        code: str,
        *,
        context: dict[str, Any] | None = None,
    ) -> ExecutionHandle: ...

    @abstractmethod
    def destroy_session(self, agent_id: str, session_id: str) -> None: ...

    @abstractmethod
    def is_available(self) -> bool: ...

    # --- Status tracking (defaults; cloud providers override) ---
    def get_session_status(self, agent_id, session_id) -> SessionStatus: ...
    def get_execution_status(self, agent_id, session_id, execution_id) -> ExecutionHandle: ...
    def cancel_execution(self, agent_id, session_id, execution_id) -> bool: ...

    # --- Async (default: delegates to sync via asyncio.to_thread) ---
    async def create_session_async(self, agent_id, policy=None, config=None) -> SessionHandle: ...
    async def execute_code_async(self, agent_id, session_id, code, *, context=None) -> ExecutionHandle: ...
    async def destroy_session_async(self, agent_id, session_id) -> None: ...
    async def cancel_execution_async(self, agent_id, session_id, execution_id) -> bool: ...
```

`SandboxProvider` defines the **minimum contract** that all backends must implement. Individual providers are free to add backend-specific methods beyond the ABC — for example, `DockerSandboxProvider` adds `save_state()`, `restore_state()`, `list_checkpoints()`, and `delete_checkpoint()` for filesystem-level checkpointing via `docker commit`. These are not on the ABC because not all backends support them (e.g. a stateless cloud sandbox has no local filesystem to checkpoint).

**Policy is loaded at session creation time.** When a `PolicyDocument` is passed to `create_session`, the provider:

1. Extracts resource limits (CPU, memory) from the policy and applies them to the container.
2. Extracts `tool_allowlist` → starts a `ToolCallProxy`, registers allowed tools, and injects the `_tool_client.py` stub into the container.
3. Extracts `network_allowlist` → starts a `NetworkProxy`, injects `HTTP_PROXY`/`HTTPS_PROXY` env vars, and applies iptables rules (Linux) to enforce the domain allowlist.

`execute_code` then evaluates the policy's rules on each call to make the allow/deny decision. If the policy denies execution, a `PermissionError` is raised and no code runs. This eliminates the need for separate executor wrapper classes — the provider handles the full policy lifecycle.

### Built-in Providers

| Provider | Backend | Isolation Level | Design doc |
|----------|---------|-----------------|------------|
| `DockerSandboxProvider` | Docker containers | Container-level (shared kernel), optional gVisor/Kata kernel isolation | this document |
| `ACASandboxProvider` | Azure Container Apps sandboxes (managed) | Container-level on Azure-managed infrastructure with egress proxy | planned |
| `HyperLightSandboxProvider` | Hyperlight micro-VMs (via [`hyperlight-sandbox`](https://github.com/hyperlight-dev/hyperlight-sandbox)) | Hardware-level (own kernel via KVM/MSHV/WHP) | [HYPERLIGHT-SANDBOX-ISOLATION-DESIGN.md](./HYPERLIGHT-SANDBOX-ISOLATION-DESIGN.md) |

### Implementing a Custom Provider

To add a new sandbox backend (e.g. cloud sandbox, Firecracker, WASM):

```python
from agent_os.sandbox_provider import (
    SandboxConfig, SandboxProvider, SandboxResult,
    SessionHandle, ExecutionHandle, ExecutionStatus,
)
import uuid

class CloudSandboxProvider(SandboxProvider):
    def create_session(self, agent_id, policy=None, config=None):
        session_id = self._provision_cloud_vm(agent_id, config)
        if policy is not None:
            self._evaluators[session_id] = PolicyEvaluator(policies=[policy])
        return SessionHandle(agent_id=agent_id, session_id=session_id)

    def execute_code(self, agent_id, session_id, code, *, context=None):
        evaluator = self._evaluators.get(session_id)
        if evaluator is not None:
            decision = evaluator.evaluate(
                {"agent_id": agent_id, "action": "execute", **(context or {})}
            )
            if not decision.allowed:
                raise PermissionError(f"Policy denied: {decision.reason}")
        result = self._run_in_cloud(agent_id, session_id, code)
        return ExecutionHandle(
            execution_id=uuid.uuid4().hex[:8],
            agent_id=agent_id,
            session_id=session_id,
            status=ExecutionStatus.COMPLETED,
            result=result,
        )

    def destroy_session(self, agent_id, session_id):
        self._teardown_cloud_vm(agent_id, session_id)

    def is_available(self):
        return True
```

### Async Interface

Every method has an async counterpart (`create_session_async`, `execute_code_async`, `destroy_session_async`, `cancel_execution_async`) for cloud and remote sandbox providers where provisioning and execution involve network I/O.

The default implementations delegate to the sync methods via `asyncio.to_thread`, so **local providers (Docker, Hyperlight) work in async code out of the box** — no override needed. Cloud providers should override with native async implementations for optimal performance.

```python
# Default async methods on SandboxProvider (no override needed for local providers):
async def create_session_async(self, agent_id, policy=None, config=None) -> SessionHandle:
    return await asyncio.to_thread(self.create_session, agent_id, policy, config)

async def execute_code_async(self, agent_id, session_id, code, *,
                              context=None) -> ExecutionHandle:
    return await asyncio.to_thread(self.execute_code, agent_id, session_id, code,
        context=context)

async def destroy_session_async(self, agent_id, session_id) -> None:
    await asyncio.to_thread(self.destroy_session, agent_id, session_id)

async def cancel_execution_async(self, agent_id, session_id, execution_id) -> bool:
    return await asyncio.to_thread(self.cancel_execution, agent_id, session_id, execution_id)
```

**Cloud provider with native async and execution polling:**

```python
import asyncio
import aiohttp
from agent_os.sandbox_provider import (
    SandboxConfig, SandboxProvider, SandboxResult,
    SessionHandle, ExecutionHandle, ExecutionStatus, SessionStatus,
)

class CloudSandboxProvider(SandboxProvider):
    """Cloud-hosted sandbox — async-first; sync methods delegate to async."""

    def __init__(self, api_url: str):
        self._api_url = api_url

    # --- Native async implementations (primary) ---

    async def create_session_async(self, agent_id, config=None):
        async with aiohttp.ClientSession() as http:
            resp = await http.post(f"{self._api_url}/sessions",
                                   json={"agent_id": agent_id})
            data = await resp.json()
            return SessionHandle(
                agent_id=agent_id,
                session_id=data["session_id"],
                status=SessionStatus.READY,
            )

    async def execute_code_async(self, agent_id, session_id, code, *,
                                  context=None):
        # Policy evaluation uses the evaluator stored during create_session_async
        async with aiohttp.ClientSession() as http:
            resp = await http.post(
                f"{self._api_url}/sessions/{session_id}/execute",
                json={"code": code},
            )
            data = await resp.json()
            return ExecutionHandle(
                execution_id=data["execution_id"],
                agent_id=agent_id,
                session_id=session_id,
                status=ExecutionStatus(data["status"]),
                result=SandboxResult(**data["result"]) if "result" in data else None,
            )

    async def cancel_execution_async(self, agent_id, session_id, execution_id):
        async with aiohttp.ClientSession() as http:
            resp = await http.post(
                f"{self._api_url}/sessions/{session_id}/executions/{execution_id}/cancel"
            )
            return resp.status == 200

    async def destroy_session_async(self, agent_id, session_id):
        async with aiohttp.ClientSession() as http:
            await http.delete(f"{self._api_url}/sessions/{session_id}")

    def is_available(self):
        return True
```

**Using async with any provider:**

```python
import asyncio
from agent_sandbox import DockerSandboxProvider

async def main():
    provider = DockerSandboxProvider()

    # Works with local providers via asyncio.to_thread
    handle = await provider.create_session_async("agent-1")
    exec_handle = await provider.execute_code_async(
        "agent-1", handle.session_id, "print('hello')"
    )
    print(exec_handle.result.stdout)
    await provider.destroy_session_async("agent-1", handle.session_id)

asyncio.run(main())
```

**Polling a long-running cloud execution:**

```python
import asyncio
from agent_os.sandbox_provider import ExecutionStatus

async def run_and_wait(provider, agent_id, code):
    handle = await provider.create_session_async(agent_id)
    exec_handle = await provider.execute_code_async(
        agent_id, handle.session_id, code
    )

    # Poll until complete (cloud providers return RUNNING immediately)
    while exec_handle.status in (ExecutionStatus.PENDING, ExecutionStatus.RUNNING):
        await asyncio.sleep(1)
        exec_handle = await provider.get_execution_status(
            agent_id, handle.session_id, exec_handle.execution_id
        )

    print(f"Done: {exec_handle.result.stdout}")
    await provider.destroy_session_async(agent_id, handle.session_id)
```

### Usage

```python
from agent_sandbox import DockerSandboxProvider
from agent_os.policies import PolicyDocument

# Create provider
provider = DockerSandboxProvider()

# Basic usage — no policy
handle = provider.create_session("agent-1")
exec_handle = provider.execute_code("agent-1", handle.session_id, "print('hello')")
print(exec_handle.result.stdout)
provider.destroy_session("agent-1", handle.session_id)

# With policy — resource limits, tool proxy, network proxy set up at session creation
doc = PolicyDocument.from_yaml("policies/research_policy.yaml")

handle = provider.create_session("agent-2", policy=doc)
exec_handle = provider.execute_code(
    "agent-2",
    handle.session_id,
    "print('governed execution')",
    context={"message": "run research task"},
)
provider.destroy_session("agent-2", handle.session_id)
```

## DockerSandboxProvider

`DockerSandboxProvider` implements the `SandboxProvider` interface using Docker containers.  Each agent gets its own Docker container **scoped to a session**.  A new provider instance (or a new `SandboxSession`) creates fresh containers even for the same `agent_id`.  Within a session, containers are reused across calls so that in-container state persists between runs.  State can be explicitly saved (committed) and restored from named checkpoints via `SandboxStateManager`.

## Goals

1. **Generic interface** — `SandboxProvider` defines `create_session`, `execute_code`, `destroy_session` so any backend (Docker, Hyperlight, cloud, custom) plugs in uniformly.
2. Each agent gets its own sandbox with hard resource limits (CPU, memory, network, filesystem).
3. Sandboxes persist across calls within a session — an agent can install packages, create files, and continue where it left off.  Each session gets a fresh sandbox; cross-session state requires explicit checkpointing.
4. State can be explicitly **checkpointed** and **restored** from any named checkpoint.
5. Policy evaluation is **optional and built-in** — pass a `PolicyDocument` to `create_session` to set up resource limits, tool/network proxies, and per-call allow/deny evaluation.  No separate executor class required.
6. Security hardening by default: `no-new-privileges`, all capabilities dropped, optional read-only root filesystem.

## Non-Goals

- Orchestrating multi-container agent topologies — each agent gets exactly one container.
- Providing a custom guest image build pipeline — users bring their own base image.

## Summary

`SandboxProvider` is the generic interface for all sandbox backends, with
three core methods: `create_session`, `execute_code` (with optional
`PolicyEvaluator`), and `destroy_session`.

`DockerSandboxProvider` implements this interface using hardened Docker
containers with all capabilities dropped, a read-only root filesystem,
non-root user, `pids_limit`, and optional gVisor or Kata kernel isolation.
`HyperLightSandboxProvider` implements the same interface using Hyperlight
micro-VMs with hardware-level isolation.  Additional providers (cloud
sandbox, Firecracker, WASM, etc.) can be added by implementing the
`SandboxProvider` ABC.

Network access is disabled by default; when a policy grants specific
domains, an HTTP proxy plus iptables rules (Linux) enforce the allowlist.
Tool calls are brokered through a host-side `ToolCallProxy` that enforces
the policy's `tool_allowlist`.  Containers are session-scoped and cleaned
up automatically via `SandboxSession`.

| Capability | Detail |
|------------|--------|
| Isolation | Per-agent Docker container (runc), with optional gVisor or Kata kernel isolation |
| State checkpoints | `docker commit` — filesystem-level snapshots as image layers |
| Tool enforcement | Host-side HTTP proxy (`ToolCallProxy`) |
| Network enforcement | HTTP proxy + iptables (Linux); proxy-only on macOS / Windows |
| File I/O | Bind mounts (`input_dir` / `output_dir`) or `copy_to()` tar upload |
| Platform support | Linux (full), macOS / Windows (proxy-only network) |

## Architecture

### Component Overview

```
┌──────────────────────────────────────────────────────────────┐
│                    SandboxProvider (ABC)                      │
│                                                              │
│  create_session(agent_id, config) -> SessionHandle           │
│  execute_code(agent_id, session_id, code, ...) -> ExecHandle │
│  destroy_session(agent_id, session_id)                       │
│  get_session_status / get_execution_status / cancel_execution│
│  is_available()                                              │
└──────────────┬──────────────────────────┬────────────────────┘
               │                          │
    ┌──────────┴──────────┐    ┌──────────┴──────────┐
    │ DockerSandboxProvider│    │HyperLightSandbox-   │
    │                     │    │       Provider       │
    │  Docker containers  │    │  Hyperlight micro-VMs│
    │  + gVisor / Kata    │    │  (KVM/MSHV/Hyper-V)  │
    │                     │    │                      │
    │ ┌─────────────────┐ │    │ ┌──────────────────┐ │
    │ │ Container: a-1  │ │    │ │  micro-VM: a-3   │ │
    │ └─────────────────┘ │    │ └──────────────────┘ │
    │ ┌─────────────────┐ │    │ ┌──────────────────┐ │
    │ │ Container: a-2  │ │    │ │  micro-VM: a-4   │ │
    │ └─────────────────┘ │    │ └──────────────────┘ │
    │                     │    │                      │
    │ ┌─────────────────┐ │    └──────────────────────┘
    │ │SandboxState-    │ │
    │ │   Manager       │ │    ┌──────────────────────┐
    │ │ • save (commit) │ │    │ CloudSandboxProvider  │
    │ │ • restore       │ │    │ (custom — user-impl)  │
    │ └─────────────────┘ │    └──────────────────────┘
    └─────────────────────┘
```

**Future provider extensibility:**

```
┌──────────────────────────────────────────────────────────────┐
│                    SandboxProvider (ABC)                      │
└──────┬──────────────┬──────────────┬──────────────┬──────────┘
       │              │              │              │
┌──────┴─────┐ ┌──────┴─────┐ ┌─────┴──────┐ ┌────┴───────────┐
│   Docker   │ │ Hyperlight │ │   Cloud    │ │  BYO Provider  │
│  Provider  │ │  Provider  │ │  Provider  │ │  (user-impl)   │
│            │ │            │ │            │ │                │
│ containers │ │ micro-VMs  │ │ async-first│ │ any backend    │
│ gVisor/Kata│ │ KVM/MSHV   │ │ REST API   │ │ implements ABC │
└────────────┘ └────────────┘ └──────┬─────┘ └────────┬───────┘
                                     │                 │
                              ┌──────┴─────┐    ┌──────┴──────┐
                              │ Cloud APIs │    │             │
                              │            │    │             │
                              │ • AKS      │    │ Podman      │
                              │ • ACA      │    │ LXC / LXD   │
                              │ • EKS      │    │ Nomad       │
                              │ • ACI      │    │ Modal       │
                              │            │    │ E2B         │
                              └────────────┘    └─────────────┘
```

The `CloudSandboxProvider` pattern targets managed cloud sandbox APIs (Azure Kubernetes Service, Azure Container Apps, Amazon EKS, Azure Container Instances) where provisioning and execution are async HTTP calls. The **BYO (Bring Your Own) Provider** pattern covers any custom backend —  Podman, LXC/LXD, HashiCorp Nomad, Modal, E2B, or proprietary infrastructure. Both implement the same `SandboxProvider` ABC.

### Key Classes

| Class | Module | Role |
|-------|--------|------|
| `SandboxProvider` | `agent_os.sandbox_provider` | Abstract base class defining `create_session`, `execute_code`, `destroy_session`, plus status tracking (`get_session_status`, `get_execution_status`, `cancel_execution`). All providers implement this. |
| `DockerSandboxProvider` | `agent_sandbox.provider` | Implements `SandboxProvider` using Docker containers. One container per agent, reused across calls. Adds `save_state()`, `restore_state()`, `list_checkpoints()`, `delete_checkpoint()` for filesystem checkpointing via `docker commit`. |
| `HyperLightSandboxProvider` | `agent_sandbox.hyperlight_provider` | Implements `SandboxProvider` using Hyperlight micro-VMs with hardware isolation. |
| `IsolationRuntime` | `agent_sandbox.provider` | Enum selecting the OCI runtime: `RUNC`, `GVISOR`, `KATA`, or `AUTO`. |
| `SandboxStateManager` | `agent_sandbox.state` | Internal helper used by `DockerSandboxProvider` to implement checkpoint operations. Not used directly — call the provider's `save_state()` / `restore_state()` methods instead. |
| `SandboxCheckpoint` | `agent_sandbox.state` | Dataclass holding checkpoint metadata (agent, name, image tag, timestamp). |
| `DockerSandboxExecutor` | `agent_sandbox.executor` | Legacy policy-gated executor. New code should pass `PolicyDocument` to `create_session` instead. |
| `SessionHandle` | `agent_os.sandbox_provider` | Dataclass returned by `create_session` — holds `agent_id`, `session_id`, `status`. |
| `ExecutionHandle` | `agent_os.sandbox_provider` | Dataclass returned by `execute_code` — holds `execution_id`, `agent_id`, `session_id`, `status`, `result`. |
| `SessionStatus` | `agent_os.sandbox_provider` | Enum: `PROVISIONING`, `READY`, `EXECUTING`, `DESTROYING`, `DESTROYED`, `FAILED`. |
| `ExecutionStatus` | `agent_os.sandbox_provider` | Enum: `PENDING`, `RUNNING`, `COMPLETED`, `CANCELLED`, `FAILED`. |

### Integration with agent-os Policy

Policy is loaded at session creation time via `create_session(agent_id, policy)`:

```
PolicyDocument (YAML)
  ├── rules[]            → stored as PolicyEvaluator; evaluated on each execute_code call
  ├── sandbox_mounts:    → mapped to SandboxConfig (input_dir, output_dir, etc.)
  ├── tool_allowlist:    → ToolCallProxy started; allowed tools registered
  ├── network_allowlist: → NetworkProxy started; iptables rules applied (Linux)
  └── resource limits    → CPU, memory applied to container cgroups
```

When `create_session` receives a `PolicyDocument`, it provisions the container with the policy's resource limits, starts the tool and network proxies, and stores a `PolicyEvaluator` for the session. On each `execute_code` call, the stored evaluator checks the policy's rules to make the allow/deny decision. If the policy denies the request, a `PermissionError` is raised and no code runs. When no policy is provided, sessions run without any gating — useful for trusted or development scenarios.

```python
from agent_os.policies import PolicyDocument
from agent_sandbox import DockerSandboxProvider

doc = PolicyDocument.from_yaml("policies/research_policy.yaml")
provider = DockerSandboxProvider()

# Policy loaded at session creation — resource limits, tool proxy,
# network proxy, and iptables rules are all set up here
handle = provider.create_session("research-agent", policy=doc)
exec_handle = provider.execute_code(
    "research-agent",
    handle.session_id,
    "print('hello')",
    context={"message": "run research"},
)

# Ungated session — no policy, no proxies, default resource limits
handle2 = provider.create_session("dev-agent")
exec_handle2 = provider.execute_code("dev-agent", handle2.session_id, "print('quick test')")
```

## Container Lifecycle

Sandboxes are **session-scoped** — a new sandbox is created for each
session, and all sandboxes are destroyed when the session ends or is
killed.  The `SandboxSession` context manager enforces this lifecycle.

```
  Session start                          Session end / kill / exception
       │                                          │
       ▼                                          ▼
┌─────────────┐                            ┌──────────┐
│ SandboxSession │                          │ close()  │
│   __enter__()  │                          │          │
└──────┬──────┘                            │ destroy  │
       │                                    │ all      │
       │ first execute()                    │ agents   │
       ▼                                    └──────────┘
┌─────────────┐                                  ▲
│   Running    │──── execute() (reuse) ───┐      │
│   Sandbox    │◄─────────────────────────┘      │
└──────┬──────┘                                  │
       │                                         │
       ├── save_state() → checkpoint             │
       │                                         │
       ├── restore_state() ← checkpoint          │
       │                                         │
       └── session ends ─────────────────────────┘
```


### Session Lifecycle Guarantees

`SandboxSession` ensures cleanup in **all** termination paths:

| Termination path | Cleanup mechanism |
|---|---|
| Normal `with`-block exit | `__exit__()` calls `close()` |
| Exception in `with`-block | `__exit__()` calls `close()` before re-raising |
| `SIGINT` (Ctrl-C) | Signal handler calls `close()`, then re-raises |
| `SIGTERM` | Signal handler calls `close()`, then re-raises |
| Process exit | `atexit` handler calls `close()` |
| Explicit `close()` | Immediate cleanup; idempotent (safe to call multiple times) |

After `close()`, the session rejects further operations with `RuntimeError`.

### How `DockerSandboxProvider` Implements Each Method

#### `create_session(agent_id, policy, config) → SessionHandle`

1. Checks that the Docker daemon is reachable (`_available`); raises `RuntimeError` if not.
2. **Policy extraction** — if a `PolicyDocument` is provided, extracts resource limits (`cpu_limit`, `memory_mb`), `sandbox_mounts` (input/output dirs), `tool_allowlist`, and `network_allowlist` from the policy. These override defaults in `SandboxConfig`.
3. **Container creation** — calls `_create_container(agent_id, config)` to create a new Docker container from the base image (e.g. `python:3.11-slim`) with all hardening applied (`cap_drop=ALL`, `no-new-privileges`, `read_only`, `pids_limit=256`, non-root user), policy-driven resource limits (CPU, memory), and host folder mounts from the policy's `sandbox_mounts` section (`input_dir` → `/input` read-only, `output_dir` → `/output` read-write). The container runs `sleep infinity` to stay alive.
4. **Tool proxy setup** — if the policy has a `tool_allowlist`, starts the provider's shared `ToolCallProxy` (if not already running), registers the container's IP and allowlist with the proxy, injects `_tool_client.py` into the container at `/workspace/`, and sets `TOOL_PROXY_URL` + `PYTHONPATH=/workspace` in the container's environment.
5. **Network proxy + iptables** — if the policy has a `network_allowlist`, starts the provider's shared `NetworkProxy` (if not already running), registers the container's IP and domain allowlist with the proxy, injects `HTTP_PROXY`/`HTTPS_PROXY` env vars into the container, and applies per-container iptables rules (Linux) so the container can only reach the proxy. On macOS/Windows, falls back to proxy-only enforcement.
6. **Policy evaluator** — creates a `PolicyEvaluator` from the policy document and stores it in `_evaluators[(agent_id, session_id)]` for use by `execute_code`.
7. Stores the container in `_containers[(agent_id, session_id)]` for reuse.
8. Returns a `SessionHandle(agent_id=agent_id, session_id=session_id, status=SessionStatus.READY)`.

The `session_id` is a unique 8-char hex generated per `create_session` call (`uuid4().hex[:8]`), so the same `agent_id` with a new `create_session` call gets a fresh container.

```python
def create_session(self, agent_id, policy=None, config=None):
    if not self._available:
        raise RuntimeError("Docker daemon is not available")

    session_id = uuid.uuid4().hex[:8]
    cfg = config or SandboxConfig()

    # 1. Extract policy constraints into SandboxConfig
    #    - cpu_limit, memory_mb → container cgroups
    #    - sandbox_mounts.input_dir → bind mount /input (ro)
    #    - sandbox_mounts.output_dir → bind mount /output (rw)
    if policy is not None:
        cfg = docker_config_from_policy(policy, cfg)
        evaluator = PolicyEvaluator(policies=[policy])
        self._evaluators[(agent_id, session_id)] = evaluator

    # 2. Create hardened container with policy-driven limits
    container = self._create_container(agent_id, session_id, cfg)
    self._containers[(agent_id, session_id)] = container

    # 3. Start (or reuse) tool proxy, register container's allowlist
    if policy and policy.tool_allowlist:
        if self._tool_proxy is None:
            self._tool_proxy = ToolCallProxy(tools=self._tools)
            self._tool_proxy.start()
        container_ip = container.attrs["NetworkSettings"]["IPAddress"]
        self._tool_proxy.register(container_ip, policy.tool_allowlist)
        self._inject_tool_stub(container)

    # 4. Start (or reuse) network proxy, register container's allowlist
    if policy and policy.network_allowlist:
        if self._network_proxy is None:
            self._network_proxy = NetworkProxy()
            self._network_proxy.start()
        container_ip = container.attrs["NetworkSettings"]["IPAddress"]
        self._network_proxy.register(container_ip, policy.network_allowlist)
        self._inject_proxy_env(container, self._network_proxy)
        if has_iptables():
            apply_container_network_rules(container, self._network_proxy.port)

    return SessionHandle(
        agent_id=agent_id,
        session_id=session_id,
        status=SessionStatus.READY,
    )
```

#### `execute_code(agent_id, session_id, code, *, context) → ExecutionHandle`

1. **Session check** — looks up `(agent_id, session_id)` in `_containers`. If no container exists, raises `RuntimeError` — callers must call `create_session` first.
2. **Policy gate** — looks up the `PolicyEvaluator` stored during `create_session` in `_evaluators[(agent_id, session_id)]`. If present, builds a context dict (`agent_id`, `action: "execute"`, `code`, plus any caller-supplied `context`) and calls `evaluator.evaluate()`. If the decision is denied, raises `PermissionError` immediately — no code runs. Sessions created without a policy skip this step.
3. **Container refresh** — calls `container.reload()` to refresh state from the daemon. If the container is not running, calls `container.start()` to restart it.
4. **Execution** — runs `container.exec_run(["python", "-c", code], demux=True)` inside the already-running container. `demux=True` separates stdout and stderr into distinct byte streams.
5. **Output processing** — decodes stdout/stderr as UTF-8, truncates each to 10,000 characters, and wraps them in a `SandboxResult(success, exit_code, stdout, stderr, duration_seconds)`.
6. **Return** — wraps the `SandboxResult` in `ExecutionHandle(execution_id=uuid4().hex[:8], status=ExecutionStatus.COMPLETED, result=sandbox_result)`. The caller accesses output via `exec_handle.result.stdout` / `exec_handle.result.stderr`.

```python
def execute_code(self, agent_id, session_id, code, *, context=None):
    # 1. Session check — container must already exist
    key = (agent_id, session_id)
    if key not in self._containers:
        raise RuntimeError(
            f"No active session for agent '{agent_id}' with session_id '{session_id}'. "
            "Call create_session() first."
        )

    # 2. Policy gate — evaluator was stored during create_session
    evaluator = self._evaluators.get(key)
    if evaluator is not None:
        eval_ctx = {"agent_id": agent_id, "action": "execute", "code": code}
        if context:
            eval_ctx.update(context)
        decision = evaluator.evaluate(eval_ctx)
        if not decision.allowed:
            raise PermissionError(f"Policy denied: {decision.reason}")

    # 3–5. Run code in the existing container
    result = self.run(agent_id, session_id, ["python", "-c", code])

    # 6. Wrap in ExecutionHandle
    return ExecutionHandle(
        execution_id=uuid.uuid4().hex[:8],
        agent_id=agent_id,
        session_id=session_id,
        status=ExecutionStatus.COMPLETED,
        result=result,
    )
```

#### `destroy_session(agent_id, session_id)`

1. **iptables cleanup** — if iptables rules were applied for this container, removes the per-container chain.
2. **Network proxy unregister** — unregisters the container's IP from the shared `NetworkProxy`. If no sessions remain, stops the proxy.
3. **Tool proxy unregister** — unregisters the container's IP from the shared `ToolCallProxy`. If no sessions remain, stops the proxy.
4. Looks up the container in `_containers[(agent_id, session_id)]`.
5. Calls `container.stop(timeout=5)` — sends SIGTERM, waits 5 seconds, then SIGKILL. In practice, `sleep infinity` handles SIGTERM immediately so the stop is near-instant.
6. Calls `container.remove(force=True)` — removes the container and its writable layer.
7. Removes entries from `_containers` and `_evaluators`.

After this call, any subsequent `create_session` for the same `agent_id` will provision a fresh container and register it with the existing proxies (or start new ones if no sessions remain).

```python
def destroy_session(self, agent_id, session_id):
    key = (agent_id, session_id)

    # 1. Remove iptables rules
    container = self._containers.get(key)
    if container and has_iptables():
        remove_container_network_rules(container)

    # 2. Unregister from network proxy; stop if last session
    if container and self._network_proxy is not None:
        container_ip = container.attrs["NetworkSettings"]["IPAddress"]
        self._network_proxy.unregister(container_ip)
        if self._network_proxy.is_empty():
            self._network_proxy.stop()
            self._network_proxy = None

    # 3. Unregister from tool proxy; stop if last session
    if container and self._tool_proxy is not None:
        container_ip = container.attrs["NetworkSettings"]["IPAddress"]
        self._tool_proxy.unregister(container_ip)
        if self._tool_proxy.is_empty():
            self._tool_proxy.stop()
            self._tool_proxy = None

    # 4–6. Stop and remove container
    if container:
        container.stop(timeout=5)
        container.remove(force=True)

    # 7. Clean up internal state
    self._containers.pop(key, None)
    self._evaluators.pop(key, None)
```

#### `is_available() → bool`

Returns `True` if the Docker daemon was reachable at initialization (i.e. `client.ping()` succeeded). All other methods check this flag before proceeding.

#### `get_session_status(agent_id, session_id) → SessionStatus`

Returns `SessionStatus.READY` if `(agent_id, session_id)` has a live container in `_containers`. Returns `SessionStatus.DESTROYED` otherwise.

#### `save_state()` / `restore_state()` / `list_checkpoints()` / `delete_checkpoint()`

These are **Docker-specific methods** not defined on the `SandboxProvider` ABC — they exist only on `DockerSandboxProvider` because they rely on `docker commit` for filesystem-level snapshots.

- **`save_state(agent_id, session_id, name)`** → `SandboxCheckpoint` — calls `docker commit` on the session's running container, producing a local image tagged as `agent-sandbox-<agent_id>:<name>`.
- **`restore_state(agent_id, session_id, name)`** — calls `destroy_session` to tear down the current container, then creates a new container from the checkpoint image and re-registers it with the tool/network proxies.
- **`list_checkpoints(agent_id)`** → `list[SandboxCheckpoint]` — lists all checkpoint images for the agent.
- **`delete_checkpoint(agent_id, name)`** — removes a checkpoint image. The `name` is the tag; the provider constructs the full image reference internally.

## Internal Implementation Details

### Docker SDK APIs Used

`DockerSandboxProvider` uses the [Docker SDK for Python](https://docker-py.readthedocs.io/) (`docker` package). Every Docker Engine interaction maps to a specific SDK call, which in turn maps to a Docker Engine API endpoint.

#### Initialization

| Step | SDK Call | Engine API | Purpose |
|------|----------|------------|---------|
| Connect | `docker.DockerClient(base_url=...)` | — | Open a session to the Docker daemon via Unix socket (`/var/run/docker.sock`) or TCP |
| Health check | `client.ping()` | `GET /_ping` | Verify daemon is reachable; sets `_available` flag |
| Runtime probe | `client.info()` | `GET /info` | Read `Runtimes` dict to auto-detect gVisor/Kata |

```python
# Initialization sequence (simplified)
self._client = docker.DockerClient(base_url=docker_url)
self._client.ping()                   # → GET /_ping
info = self._client.info()            # → GET /info
runtimes = info.get("Runtimes", {})   # {"runc": {}, "runsc": {}, ...}
```

#### Container Creation (`_create_container`)

A single `client.containers.run()` call creates and starts the container. This maps to two Engine API calls internally:

| SDK Call | Engine API | Purpose |
|----------|------------|---------|
| `client.containers.run(...)` | `POST /containers/create` + `POST /containers/{id}/start` | Create container from image with all constraints, then start it |

The full parameter mapping from `SandboxConfig` to Docker API fields:

```python
container = self._client.containers.run(
    image=self._image,                         # Base image (e.g. "python:3.11-slim")
    name=f"agent-sandbox-{agent_id}-{session_id}",  # Session-scoped container name
    command=["sleep", "infinity"],             # Keep-alive process
    detach=True,                               # Run in background (non-blocking)
    labels={                                   # Metadata for filtering/cleanup
        "agent-sandbox.managed": "true",
        "agent-sandbox.agent-id": agent_id,
    },
    mem_limit=f"{config.memory_mb}m",          # → HostConfig.Memory (bytes)
    nano_cpus=int(config.cpu_limit * 1e9),     # → HostConfig.NanoCpus
    network_disabled=not config.network_enabled, # → NetworkDisabled
    read_only=config.read_only_fs,             # → HostConfig.ReadonlyRootfs
    volumes={                                  # → HostConfig.Binds (from policy sandbox_mounts:)
        config.input_dir: {"bind": "/input", "mode": "ro"},
        config.output_dir: {"bind": "/output", "mode": "rw"},
    },
    tmpfs={                                    # → HostConfig.Tmpfs
        "/workspace": "size=128m,uid=65534,gid=65534",  # Always writable
        "/tmp": "size=64m,uid=65534,gid=65534",         # When read_only=True
    },
    security_opt=["no-new-privileges"],        # → HostConfig.SecurityOpt
    cap_drop=["ALL"],                          # → HostConfig.CapDrop
    runtime=runtime_arg,                       # → HostConfig.Runtime — config.runtime or self._runtime
    user="65534:65534",                        # → User (nobody — non-root)
    working_dir="/workspace",                  # → WorkingDir
    pids_limit=256,                            # → HostConfig.PidsLimit (fork-bomb prevention)
)
```

**Why `sleep infinity`?** The container needs a long-running foreground process to stay alive between `exec_run()` calls. `sleep infinity` consumes zero CPU and keeps the container in `running` state indefinitely. All actual agent work happens via `exec`.

#### Command Execution (`run`)

Each call to `provider.run(agent_id, session_id, command)` executes a command inside the already-running container:

| SDK Call | Engine API | Purpose |
|----------|------------|---------|
| `container.exec_run(cmd, environment, demux)` | `POST /containers/{id}/exec` + `POST /exec/{id}/start` | Create an exec instance and run it attached |

```python
exec_result = container.exec_run(
    cmd=command,              # e.g. ["python", "-c", "print('hello')"]
    environment=cfg.env_vars, # Per-call env vars merged into container env
    demux=True,               # Split stdout/stderr into separate byte streams
)
# exec_result.exit_code  → int
# exec_result.output     → (stdout_bytes, stderr_bytes)
```

**`demux=True`** is critical — without it, stdout and stderr are interleaved into a single byte stream and cannot be separated. With demux, the SDK reads the multiplexed Docker stream header (8-byte frame: stream type + length) and returns a `(stdout, stderr)` tuple.

#### Tool-Call Restriction (`ToolCallProxy`)

Docker containers can run arbitrary code. To restrict tool access, `agent-sandbox` uses a **host-side HTTP proxy** that brokers tool calls and enforces the policy's `tool_allowlist`.

**Architecture:**

```
┌────────────────────────────────────┐
│  Docker Container (agent)          │
│                                    │
│  from _tool_client import call_tool│
│  result = call_tool("web_search", │
│      {"query": "quantum"})         │
│         │                          │
│         │ HTTP POST                │
│         ▼                          │
└─────────┼──────────────────────────┘
          │  http://host.docker.internal:9100/call_tool
          ▼
┌────────────────────────────────────┐
│  ToolCallProxy (host, port 9100)   │
│                                    │
│  1. Parse {"tool": "...", "args":} │
│  2. Check tool_allowlist           │
│     ├─ Not in list → 403 denied   │
│     └─ Allowed → continue         │
│  3. Look up registered callable    │
│     ├─ Not found → 404            │
│     └─ Found → dispatch           │
│  4. Return {"result": ...} or     │
│     {"error": ...}                │
└────────────────────────────────────┘
```

**SDK/API calls involved:**

| Component | Call | Purpose |
|-----------|------|---------|
| Proxy (host) | `http.server.HTTPServer` | Standard-library HTTP server on port 9100 |
| Client (container) | `urllib.request.urlopen()` | No-dependency HTTP POST from inside container |
| Stub injection | `container.put_archive()` | `PUT /containers/{id}/archive` — copies `_tool_client.py` into `/workspace/` |
| Env var | `TOOL_PROXY_URL` | Container env var pointing to the proxy URL |

**How `create_session` sets up the tool proxy:**

When `create_session(agent_id, policy=doc)` is called and the policy has a `tool_allowlist`, the provider:

1. Starts the provider's shared `ToolCallProxy` on port 9100 (if not already running). Subsequent sessions reuse the same proxy instance.
2. Registers the container's IP and the policy's `tool_allowlist` with the proxy via `proxy.register(container_ip, allowlist)`. The proxy stores this in its `per_ip_allowlists` dict.
3. Injects `_tool_client.py` into the container at `/workspace/` via `container.put_archive()`.
4. Sets `TOOL_PROXY_URL` and `PYTHONPATH=/workspace` in the container's environment, so the stub can locate the proxy and `import _tool_client` works.
5. Adds `extra_hosts={"host.docker.internal": "host-gateway"}` to the container, so `host.docker.internal` resolves to the host IP on native Linux Docker (Docker Desktop does this automatically on macOS/Windows).

`destroy_session` unregisters the container's IP from the proxy. If no sessions remain, it stops the proxy.

```python
from agent_os.policies import PolicyDocument
from agent_sandbox import DockerSandboxProvider

provider = DockerSandboxProvider(
    tools={                                    # Host-side callables
        "web_search": lambda query: search(query),
        "read_file": lambda path: open(path).read(),
        "delete_file": lambda path: os.remove(path),  # dangerous
    },
)

doc = PolicyDocument.from_yaml("policies/research_policy.yaml")
# Policy YAML has:
#   tool_allowlist:
#     allow:
#       - action: web_search
#       - action: read_file
#
# "delete_file" is registered but NOT in the allowlist → blocked

handle = provider.create_session("research-agent", policy=doc)
# ToolCallProxy is now running; _tool_client.py is in the container
```

**Inside the container**, agent code calls tools with:

```python
from _tool_client import call_tool

result = call_tool("web_search", {"query": "quantum computing"})
# → {"result": {"results": [...]}}

result = call_tool("delete_file", {"path": "/etc/passwd"})
# → RuntimeError: Tool call denied: tool 'delete_file' is not in the tool_allowlist
```

**Per-agent tool allowlists:**

All sessions on the same provider share a single `ToolCallProxy` instance.
Each `create_session` call registers the container's IP and the policy's
tool allowlist with the proxy. The proxy identifies each container by its
**source IP** on the Docker bridge network and applies the correct
per-session tool allowlist.

```
┌─────────────────────────────┐  ┌─────────────────────────────┐
│  research-agent (172.17.0.2)│  │  code-agent (172.17.0.3)    │
│  allow: web_search          │  │  allow: read_file, write_file│
└──────────────┬──────────────┘  └──────────────┬──────────────┘
               │                                │
               └────────────┬───────────────────┘
                            ▼
               ┌────────────────────────────┐
               │  ToolCallProxy (port 9100) │
               │                            │
               │  per_ip_allowlists:        │
               │    172.17.0.2 → {search}   │
               │    172.17.0.3 → {read,wr}  │
               │                            │
               │  Request from 172.17.0.2   │
               │  to read_file → 403        │
               │  to web_search → dispatch  │
               └────────────────────────────┘
```

Each agent's tool allowlist is extracted from the `PolicyDocument` passed to
`create_session`:

```python
research_policy = PolicyDocument.from_yaml("policies/research_agent_policy.yaml")
code_policy = PolicyDocument.from_yaml("policies/code_agent_policy.yaml")

# Each create_session registers the container's allowlist with the shared proxy
handle1 = provider.create_session("research-agent", policy=research_policy)
handle2 = provider.create_session("code-agent", policy=code_policy)

# Each agent can only call tools defined in its own policy
provider.execute_code("research-agent", handle1.session_id,
    "call_tool('web_search', {'query': 'quantum'})")
provider.execute_code("code-agent", handle2.session_id,
    "call_tool('read_file', {'path': '/workspace/data.txt'})")
```

Sessions created **without** a policy have no tool proxy — all tool calls
from within the container will fail with a connection error (no proxy listening).

#### Network Domain Restriction (`NetworkProxy`)

The policy's `network_allowlist` specifies which domains a sandboxed agent can reach. Docker's `network_disabled` flag is all-or-nothing — either full network or none. To enforce per-domain restrictions, `agent-sandbox` runs a **host-side HTTP forward proxy** that validates domains before tunneling connections.

**How it works:**

```
┌──────────────────────────────────────┐
│  Docker Container (agent)            │
│                                      │
│  HTTP_PROXY=http://host:9101         │
│  HTTPS_PROXY=http://host:9101        │
│                                      │
│  import requests                     │
│  requests.get("https://api.arxiv.org/...")  ✅ allowed
│  requests.get("https://evil.com/...")        ❌ 403
└──────────────┬───────────────────────┘
               │  Routed via HTTP_PROXY
               ▼
┌──────────────────────────────────────┐
│  NetworkProxy (host, port 9101)      │
│                                      │
│  1. Extract domain from request      │
│     • CONNECT host:port (HTTPS)      │
│     • GET http://host/... (HTTP)     │
│  2. Check network_allowlist          │
│     ├─ Not in list → 403 Forbidden   │
│     └─ Allowed → tunnel/forward      │
│  3. Supports subdomain matching      │
│     "api.arxiv.org" allows           │
│     "sub.api.arxiv.org" too          │
└──────────────────────────────────────┘
```

**Key design decisions:**

| Decision | Rationale |
|----------|-----------|
| Uses `HTTP_PROXY`/`HTTPS_PROXY` env vars | Standard convention — `urllib`, `requests`, `httpx`, `aiohttp`, `curl` all respect it with zero code changes |
| HTTPS via CONNECT tunneling (no TLS interception) | The proxy validates the domain from the CONNECT header but does NOT decrypt traffic — the TLS session is end-to-end between agent and server |
| Both `HTTP_PROXY` and `http_proxy` set | Some libraries check lowercase, others uppercase |
| `NO_PROXY=localhost,127.0.0.1` | Prevents tool-proxy traffic from being routed through the network proxy |
| Subdomain matching | `domain: "arxiv.org"` allows `api.arxiv.org`, `export.arxiv.org`, etc. |

**Env vars injected into every container:**

```python
env = {
    "HTTP_PROXY": "http://host.docker.internal:9101",
    "HTTPS_PROXY": "http://host.docker.internal:9101",
    "http_proxy": "http://host.docker.internal:9101",
    "https_proxy": "http://host.docker.internal:9101",
    "NO_PROXY": "localhost,127.0.0.1",
    "no_proxy": "localhost,127.0.0.1",
}
```

**Policy example:**

```yaml
network_allowlist:
  allow:
    - domain: "api.arxiv.org"
    - domain: "pypi.org"
```

**When `create_session` receives** a policy with a `network_allowlist`, it:
1. Starts the provider's shared `NetworkProxy` on port 9101 (if not already running). Subsequent sessions reuse the same proxy instance.
2. Registers the container's IP and the policy's domain allowlist with the proxy via `proxy.register(container_ip, allowlist)`. The proxy stores this in its `per_ip_allowlists` dict.
3. Injects `HTTP_PROXY`/`HTTPS_PROXY` env vars into the container.
4. Enables network on the container (`network_enabled=True`) so it can reach the proxy.
5. Applies per-container iptables rules (Linux) so the container can only reach the proxy — even if the agent unsets `HTTP_PROXY`.

`destroy_session` unregisters the container's IP from the proxy. If no sessions remain, it stops the proxy. Sessions created without a `network_allowlist` have `network_disabled=True` (no network at all).

**Per-agent allowlists:**

All sessions on the same provider share a single `NetworkProxy` instance.
Each `create_session` call registers the container's IP and the policy's
domain allowlist with the proxy. The proxy identifies each container by its
**source IP** on the Docker bridge network and applies the correct
per-session domain allowlist.

```
┌─────────────────────────────┐  ┌─────────────────────────────┐
│  research-agent (172.17.0.2)│  │  code-agent (172.17.0.3)    │
│  allow: api.arxiv.org       │  │  allow: pypi.org, github.com│
└──────────────┬──────────────┘  └──────────────┬──────────────┘
               │                                │
               └────────────┬───────────────────┘
                            ▼
               ┌────────────────────────────┐
               │  NetworkProxy (port 9101)  │
               │                            │
               │  per_ip_allowlists:        │
               │    172.17.0.2 → {arxiv}    │
               │    172.17.0.3 → {pypi,gh}  │
               │                            │
               │  Request from 172.17.0.2   │
               │  to pypi.org → 403         │
               │  to arxiv.org → TUNNEL     │
               └────────────────────────────┘
```

Each agent's network allowlist is extracted from the `PolicyDocument` passed to
`create_session`:

```yaml
# policies/research_agent_policy.yaml
network_allowlist:
  allow:
    - domain: "api.arxiv.org"

# policies/code_agent_policy.yaml
network_allowlist:
  allow:
    - domain: "pypi.org"
    - domain: "github.com"
```

```python
research_policy = PolicyDocument.from_yaml("policies/research_agent_policy.yaml")
code_policy = PolicyDocument.from_yaml("policies/code_agent_policy.yaml")

# Each create_session registers the container's domain allowlist with the shared proxy
handle1 = provider.create_session("research-agent", policy=research_policy)
handle2 = provider.create_session("code-agent", policy=code_policy)

# Each agent can only reach domains defined in its own policy
provider.execute_code("research-agent", handle1.session_id, "import requests; requests.get('https://api.arxiv.org/...')")
provider.execute_code("code-agent", handle2.session_id, "import requests; requests.get('https://pypi.org/...')")
```

Sessions created **without** a `network_allowlist` have `network_disabled=True` —
no network access at all.

#### Kernel-Level Network Enforcement (`network_iptables`)

The HTTP proxy approach relies on env vars (`HTTP_PROXY`) which a malicious agent
could unset or bypass using raw sockets. For **un-bypassable** enforcement,
`create_session` optionally applies **iptables rules on the host** after the
container is created.

**How it works:**

```
┌─────────────────────────────────────────────┐
│  Linux Host (iptables / netfilter)          │
│                                             │
│  FORWARD chain:                             │
│    -s <container_ip> -j AGENT_SANDBOX_abc1  │
│                                             │
│  AGENT_SANDBOX_abc1 chain:                  │
│    ESTABLISHED,RELATED → ACCEPT             │
│    UDP/TCP :53 (DNS)   → ACCEPT             │
│    TCP → host:9101     → ACCEPT (proxy)     │
│    everything else     → DROP               │
└─────────────────────────────────────────────┘
```

After rules are applied, the container **physically cannot** open connections to
any host except the network proxy — even if the agent unsets `HTTP_PROXY`, uses
raw sockets, or spawns `curl` directly. DNS is permitted so domain resolution
works, but the proxy validates the domain before tunneling the connection.

**Per-container chains** ensure clean teardown: when a container is destroyed,
its chain is flushed and deleted without affecting other containers.

**Automatic lifecycle:**

| Event | Action |
|-------|--------|
| `create_session()` with `network_allowlist` | `apply_container_network_rules(container)` |
| `destroy_session()` | `remove_container_network_rules(container)`, unregister container IP from proxy, then destroy container. Stop proxy if last session. |

**Fallback behavior:** On platforms without `iptables` (macOS, Windows, CI), the
provider logs a warning and falls back to the proxy-only approach. The
`has_iptables()` helper is checked once at startup.


#### Container Reuse

The provider maintains an in-memory dict `_containers: dict[tuple[str, str], Container]` mapping `(agent_id, session_id)` tuples to their Docker container objects.  Containers are **session-scoped** — each `create_session` call generates a unique `session_id` (8-char hex from `uuid4`), and container names include this suffix (e.g. `agent-sandbox-research-agent-a3f1b2c0`).  This means:

* The **same agent_id** with a new `create_session` call gets a **fresh container** with a new `session_id`.
* Within a session, the container is **reused** across `execute_code` calls so in-container state persists.
* `execute_code` **requires** an existing container — it will not create one. Callers must call `create_session` first.

On each `execute_code()` / `run()`:

```
1. Look up (agent_id, session_id) in _containers dict
   ├── Found → container.reload()          # GET /containers/{id}/json
   │           ├── status == "running" → return container (reuse)
   │           └── status != "running" → container.start()  # POST /containers/{id}/start
   └── Not found → raise RuntimeError("No active session — call create_session() first")
```

`container.reload()` calls `GET /containers/{id}/json` to refresh the local object with current state from the daemon (status, network settings, etc.). This catches cases where a container was stopped externally.

#### Container Teardown (`destroy_session`)

| SDK Call | Engine API | Purpose |
|----------|------------|---------|
| `container.stop(timeout=5)` | `POST /containers/{id}/stop?t=5` | Send SIGTERM, wait 5s, then SIGKILL |
| `container.remove(force=True)` | `DELETE /containers/{id}?force=true` | Remove container and its writable layer |

The 5-second stop timeout is a grace period — `sleep infinity` handles SIGTERM immediately, so the stop is near-instant in practice.

### State Management APIs

`DockerSandboxProvider` adds four checkpoint methods **beyond the `SandboxProvider` ABC**. These are Docker-specific — they rely on `docker commit` to snapshot container filesystems as image layers. Not all providers support checkpointing (e.g. stateless cloud sandboxes), which is why these are not on the abstract class.

Internally, the provider delegates to `SandboxStateManager`, but callers use the provider methods directly.

#### `provider.save_state(agent_id, session_id, name)` → `SandboxCheckpoint`

Snapshots the session's running container via `docker commit`:

| SDK Call | Engine API | Purpose |
|----------|------------|---------|
| `container.commit(repository, tag, message, conf)` | `POST /commit?container={id}&repo=...&tag=...` | Snapshot container filesystem diff into a new image |

```python
# Called internally by save_state():
container = self._containers[(agent_id, session_id)]
container.commit(
    repository="agent-sandbox-research-agent",   # Image repo name
    tag="after-setup",                            # Image tag
    message="Checkpoint 'after-setup' for ...",   # Commit message
    conf={
        "Labels": {                               # Baked into the image config
            "agent-sandbox.checkpoint": "after-setup",
            "agent-sandbox.agent-id": "research-agent",
            "agent-sandbox.created-at": "2026-04-21T...",
        },
    },
)
# Produces local image: agent-sandbox-research-agent:after-setup
```

`docker commit` creates a new image layer containing only the filesystem diff from the base image. This is copy-on-write — only modified/added files are stored. A checkpoint of a container with `pip install numpy` is ~50 MB (the numpy files), not the full base image size.

#### `provider.restore_state(agent_id, session_id, name)`

Restores a checkpoint — tears down the current container and creates a new one from the checkpoint image:

```
1. client.images.get(image_tag)           # GET /images/{name}/json
   → Verify checkpoint image exists

2. provider.destroy_session(agent_id, session_id)
   → Unregisters from tool/network proxies, removes iptables,
     stops + removes the current container

3. provider._create_container(agent_id, session_id, cfg)
   → client.containers.run(              # POST /containers/create (image=checkpoint)
       image="agent-sandbox-agent:cp1",   # + POST /containers/{id}/start
       ...same hardening flags...
   )
   → Re-registers container IP with existing tool/network proxies
   → Re-injects _tool_client.py and proxy env vars
```

The provider temporarily swaps `self._image` to the checkpoint image tag, creates the container, then restores the original base image reference. Proxy registrations are refreshed for the new container's IP.

#### `provider.list_checkpoints(agent_id)` → `list[SandboxCheckpoint]`

Lists all checkpoint images for the agent:

| SDK Call | Engine API | Purpose |
|----------|------------|---------|
| `client.images.list(name=repo)` | `GET /images/json?filter={repo}` | Find all images matching the agent's repo prefix |

```python
images = client.images.list(name="agent-sandbox-research-agent")
# Returns all tags: ["agent-sandbox-research-agent:after-setup",
#                     "agent-sandbox-research-agent:epoch-5"]
```

#### `provider.delete_checkpoint(name)`

Removes a checkpoint image. The `name` is the tag (e.g. `"after-setup"`); the provider constructs the full image reference `agent-sandbox-<agent_id>:<name>` internally:

| SDK Call | Engine API | Purpose |
|----------|------------|---------|
| `client.images.remove(image=tag, force=True)` | `DELETE /images/{name}?force=true` | Remove checkpoint image and its layers |

### Internal Data Structures

```
DockerSandboxProvider
├── _client: docker.DockerClient          # SDK session to Docker daemon
├── _image: str                           # Base image ("python:3.11-slim")
├── _tools: dict[str, Callable]           # Host-side tool callables (registered by caller)
├── _runtime: IsolationRuntime            # OCI runtime (runc/runsc/kata)
├── _labels: dict[str, str]               # Labels applied to all containers
├── _available: bool                      # Whether daemon is reachable
├── _containers: dict[tuple[str, str], Container]      # (agent_id, session_id) → live Container
├── _evaluators: dict[tuple[str, str], PolicyEvaluator] # (agent_id, session_id) → policy evaluator
├── _tool_proxy: ToolCallProxy | None                     # Shared tool proxy (started on first need, stopped when last session ends)
├── _network_proxy: NetworkProxy | None                    # Shared network proxy (started on first need, stopped when last session ends)
│
└── Container (docker SDK object)
        ├── .id: str                      # Docker container ID (sha256)
        ├── .name: str                    # "agent-sandbox-<agent_id>-<session_id>"
        ├── .status: str                  # "running" / "exited" / ...
        ├── .exec_run(cmd, ...) → ExecResult
        ├── .commit(repo, tag, ...) → Image
        ├── .stop(timeout) → None
        ├── .remove(force) → None
        └── .reload() → None              # Refresh from daemon

SandboxStateManager
├── _provider: DockerSandboxProvider      # Owning provider reference
│
├── save(agent_id, name)                  # container.commit() → image tag
├── restore(agent_id, name)              # destroy + recreate from image
├── list_checkpoints(agent_id)           # client.images.list(name=repo)
├── get_checkpoint(agent_id, name)       # client.images.get() → metadata
└── delete_checkpoint(agent_id, name)    # client.images.remove()
```

### Request Flow: `execute_code()` End-to-End

```
caller
  │
  ▼
provider.execute_code(agent_id="a1", session_id="abc12345",
                      code="print('hello')", context={...})
  │
  ├─ 0. Session check
  │     └─ ("a1", "abc12345") not in _containers
  │        → raise RuntimeError("No active session — call create_session() first")
  │
  ├─ 1. Policy gate (evaluator stored during create_session)
  │     ├─ _evaluators[("a1", "abc12345")] exists
  │     │  → evaluator.evaluate({"agent_id": "a1", "action": "execute", ...})
  │     │     ├─ denied → raise PermissionError("Policy denied: ...")
  │     │     └─ allowed → continue
  │     └─ No evaluator (no policy) → skip
  │
  ├─ 2. Container refresh (idempotent — safe to call on every execute_code)
  │     ├─ container.reload()              ──→ GET /containers/{id}/json
  │     │  └─ status != "running" → container.start()
  │     └─ status == "running" → continue (no-op)
  │
  ├─ 3. start = time.monotonic()             # begin timing
  │
  ├─ 4. try:
  │     │  container.exec_run(               ──→ POST /containers/{id}/exec
  │     │    cmd=["python", "-c", code],           + POST /exec/{id}/start
  │     │    environment=cfg.env_vars or {},
  │     │    workdir="/workspace",
  │     │    demux=True,
  │     │  )
  │     │
  │     ├─ 5. Decode stdout/stderr (UTF-8, truncate to 10,000 chars)
  │     │
  │     └─ 6. Return ExecutionHandle(
  │           │   execution_id=uuid4().hex[:8],
  │           │   status=COMPLETED,
  │           │   result=SandboxResult(success, exit_code, stdout,
  │           │                        stderr, duration_seconds))
  │     │
  │     except Exception:
  │           └─ Return ExecutionHandle(status=FAILED,
  │                  result=SandboxResult(success=False, exit_code=-1,
  │                                      stderr=str(exc), duration_seconds))
```

### Request Flow: `create_session()` End-to-End

```
caller
  │
  ▼
provider.create_session(agent_id="a1", policy=doc, config=cfg)
  │
  ├─ 0. _available check
  │     └─ False → raise RuntimeError("Docker daemon is not available")
  │
  ├─ 1. session_id = uuid4().hex[:8]
  │
  ├─ 2. Policy extraction (if policy provided)
  │     └─ docker_config_from_policy(policy, cfg)
  │        → cpu_limit, memory_mb, sandbox_mounts → SandboxConfig
  │        → PolicyEvaluator → _evaluators[("a1", session_id)]
  │
  ├─ 3. _create_container("a1", session_id, cfg)
  │     └─ client.containers.run(...)      ──→ POST /containers/create
  │        cap_drop=ALL, no-new-privileges,      + POST /containers/{id}/start
  │        read_only, pids_limit=256,
  │        mem_limit, nano_cpus, volumes, tmpfs
  │     → _containers[("a1", session_id)] = container
  │
  ├─ 4. Tool proxy (if policy.tool_allowlist)
  │     ├─ _tool_proxy is None → ToolCallProxy(tools).start()
  │     ├─ _tool_proxy.register(container_ip, allowlist)
  │     └─ _inject_tool_stub(container)    ──→ PUT /containers/{id}/archive
  │
  ├─ 5. Network proxy + iptables (if policy.network_allowlist)
  │     ├─ _network_proxy is None → NetworkProxy().start()
  │     ├─ _network_proxy.register(container_ip, allowlist)
  │     ├─ _inject_proxy_env(container)
  │     └─ has_iptables() → apply_container_network_rules(container)
  │
  └─ 6. Return SessionHandle(agent_id="a1", session_id=..., status=READY)
```

### Request Flow: `destroy_session()` End-to-End

```
caller
  │
  ▼
provider.destroy_session(agent_id="a1", session_id="abc12345")
  │
  ├─ 1. iptables cleanup
  │     └─ has_iptables() → remove_container_network_rules(container)
  │
  ├─ 2. Network proxy unregister
  │     ├─ _network_proxy.unregister(container_ip)
  │     └─ _network_proxy.is_empty() → stop + set None
  │
  ├─ 3. Tool proxy unregister
  │     ├─ _tool_proxy.unregister(container_ip)
  │     └─ _tool_proxy.is_empty() → stop + set None
  │
  ├─ 4. container.stop(timeout=5)          ──→ POST /containers/{id}/stop?t=5
  │
  ├─ 5. container.remove(force=True)       ──→ DELETE /containers/{id}?force=true
  │
  └─ 6. Clean up: _containers, _evaluators .pop(key)
```

## Security Model

### Container Hardening

Every container created by `create_session` is provisioned with:

| Setting | Value | Purpose |
|---------|-------|---------|
| `security_opt` | `["no-new-privileges"]` | Prevent privilege escalation |
| `cap_drop` | `["ALL"]` | Drop all Linux capabilities |
| `read_only` | `True` (default) | Read-only root filesystem |
| `tmpfs` | `/workspace:128m`, `/tmp:64m` | Writable spaces for agent work |
| `network_disabled` | `True` (default) | No network unless policy allows |
| `mem_limit` | From `SandboxConfig` | Hard memory cap |
| `nano_cpus` | From `SandboxConfig` | CPU throttling |
| `user` | `65534:65534` (nobody) | Non-root — cannot modify system files |
| `working_dir` | `/workspace` | All agent commands run here |
| `pids_limit` | `256` | Prevent fork bombs |

### Filesystem Isolation

Agents can only read and write within their own container and within explicitly
mounted host directories. No other host paths are accessible.

#### Writable areas

| Path | Type | Purpose |
|------|------|---------|
| `/workspace` | tmpfs (128 MB) | Agent working directory — scripts, temp data, tool stubs |
| `/tmp` | tmpfs (64 MB) | Temporary files (present when `read_only_fs=True`) |
| `/output` | bind mount (rw) | Host `output_dir` — only if specified in policy `sandbox_mounts:` section |

#### Read-only areas

| Path | Type | Purpose |
|------|------|---------|
| `/` (root) | image FS | Read-only when `read_only_fs=True` (default) |
| `/input` | bind mount (ro) | Host `input_dir` — only if specified in policy `sandbox_mounts:` section |

#### What the agent cannot do

| Action | Why it's blocked |
|--------|------------------|
| Write to `/etc`, `/usr`, `/bin` | `read_only=True` (root FS is read-only) |
| Escalate to root | `user=65534:65534` + `no-new-privileges` + `cap_drop=ALL` |
| Mount new volumes | No `CAP_SYS_ADMIN` capability |
| Access `/proc/sys` | Default Docker seccomp profile + no capabilities |
| Spawn unlimited processes | `pids_limit=256` |
| Read arbitrary host files | Docker namespace isolation — host FS not visible |
| Access other containers' files | Separate mount namespaces per container |

#### Host path validation

When `input_dir` or `output_dir` is specified in the policy's `sandbox_mounts:` section,
`create_session` validates the path against a blocklist of system directories before
mounting. Attempting to mount `/`, `/etc`, `/proc`, `/sys`, `/usr`, `/var`, or
similar protected paths raises a `ValueError` during `create_session`:

```yaml
# These will be rejected at container creation:
sandbox_mounts:
  input_dir: /           # ValueError: protected system directory
  output_dir: /etc       # ValueError: protected system directory

# These are fine:
sandbox_mounts:
  input_dir: /home/user/agent-data
  output_dir: /tmp/agent-results
```

#### Why non-root matters

Running as `nobody` (uid 65534) inside the container means:

* Even if `read_only_fs=False`, the agent cannot modify files owned by root
  (most of the container image: `/usr/bin`, `/etc`, `/lib`).
* If a container escape occurs, the attacker lands on the host as an
  unprivileged user — not root.
* Combined with `no-new-privileges`, `setuid` binaries cannot be used to
  escalate.

### Threat Model

Each threat below maps to a specific `DockerSandboxProvider` method that enforces the mitigation:

| Threat | Mitigation | Enforced by |
|--------|------------|-------------|
| Container escape | Capabilities dropped, no-new-privileges, non-root user. gVisor/Kata provide kernel-level isolation. | `create_session` (container hardening flags) |
| Kernel exploit | With gVisor: syscalls intercepted by Sentry (user-space kernel). With Kata: guest runs its own kernel in a VM. | `create_session` (`runtime` parameter) |
| Resource exhaustion | Memory and CPU limits enforced by Docker cgroups. `pids_limit=256` prevents fork bombs. | `create_session` (policy → `SandboxConfig` limits) |
| Network exfiltration | Network disabled by default; proxy + iptables enforce domain allowlist. | `create_session` (starts `NetworkProxy`, applies iptables) |
| Unauthorized tool calls | Tool proxy enforces per-session `tool_allowlist`. | `create_session` (starts/registers `ToolCallProxy`) |
| Policy-denied execution | `PolicyEvaluator` stored during session creation checks allow/deny on every call. | `execute_code` (evaluator gate) |
| Filesystem tampering | Read-only root FS; non-root user; writable only in tmpfs `/workspace` and `/tmp`. | `create_session` (`read_only`, `user`, `tmpfs`) |
| Host filesystem access | No host paths visible except explicitly mounted `input_dir` (ro) and `output_dir` (rw). Mount paths validated against blocklist. | `create_session` (blocklist validation) |
| Cross-agent leakage | Each `create_session` call creates a separate container with no shared volumes. | `create_session` (per-session container) |
| Stale state | Checkpoints are immutable images; `restore_state` calls `destroy_session` + re-creates from image. | `destroy_session` + `restore_state` |

### Comparison with Other Providers

| Feature | Docker (runc) | Docker + gVisor | Docker + Kata |
|---------|---------------|-----------------|---------------|
| Isolation | Container (shared kernel) | User-kernel (syscall filter) | VM-backed kernel |
| Kernel shared | Yes | No (app-kernel) | No (guest kernel) |
| State persistence | `save_state`/`restore_state` | `save_state`/`restore_state` | `save_state`/`restore_state` |
| Setup complexity | Docker daemon | Docker + runsc | Docker + kata-runtime |
| Ring 3 eligible | Dev/CI only | Yes | Yes |
| Resource limits | CPU, memory, network, FS | CPU, memory, network, FS | CPU, memory, network, FS |

### Platform Compatibility

The `agent-sandbox` package runs on Linux, macOS, and Windows.  Not all
features are available on every platform — the table below summarizes
what is supported and what degrades gracefully.

#### DockerSandboxProvider

| Feature | Linux | macOS (Docker Desktop) | Windows (Docker Desktop) |
|---------|-------|------------------------|--------------------------|
| Core container isolation (runc) | Native | Via Linux VM | Via Linux VM |
| Container hardening (`cap_drop`, `no-new-privileges`, `read_only`, `pids_limit`, non-root user) | Native | Enforced inside the Linux VM | Enforced inside the Linux VM |
| Resource limits (CPU, memory) | Native cgroups | Cgroups inside the Linux VM | Cgroups inside the Linux VM |
| gVisor kernel isolation (`runsc`) | Supported | Not available | Not available |
| Kata kernel isolation (`kata-runtime`) | Supported | Not available | Not available |
| Network proxy (`NetworkProxy`) | Supported | Supported | Supported |
| iptables network enforcement | `create_session` applies natively | Not available — proxy-only fallback | Not available — proxy-only fallback |
| Tool proxy (`ToolCallProxy`) | Supported | Supported | Supported |
| `host.docker.internal` resolution | Via `extra_hosts` flag | Automatic (Docker Desktop) | Automatic (Docker Desktop) |
| State checkpoints (`save_state`/`restore_state`) | Supported | Supported | Supported |
| Session cleanup (SIGTERM handler) | `destroy_session` via signal handler | `destroy_session` via signal handler | SIGINT only (`SIGTERM` not delivered on Windows) |
| Host path validation | Blocks `/`, `/etc`, `/proc`, `/sys`, `/usr`, `/var` | Same | Blocks `C:\`, `D:\`, and drive roots |

#### Security implications of proxy-only mode (macOS / Windows)

On macOS and Windows, `iptables` is not available, so network domain
enforcement relies solely on the HTTP proxy.  This means:

* An agent that **unsets `HTTP_PROXY`** or uses **raw sockets** (e.g.
  `socket.connect()`) can bypass the proxy and reach arbitrary hosts.
* The risk only applies when the policy grants *some* network access
  via `network_allowlist`.  If `network_disabled=True` (the default
  when no allowlist is present), there is **zero network** — no bypass
  is possible.
* All other hardening (`cap_drop`, `no-new-privileges`, `read_only`,
  `pids_limit`, non-root user, resource limits) applied by `create_session`
  remains fully enforced because these are applied inside the Docker Desktop Linux VM.

**Recommendation:** For untrusted (Ring 3) agents on macOS or Windows,
consider a micro-VM-based provider where network enforcement is applied
at the sandbox boundary and cannot be bypassed from guest code.

```

## Kernel-Level Isolation

### Overview

Standard Docker containers share the host kernel via Linux namespaces and cgroups. This is sufficient for resource isolation but does not protect against kernel exploits. For high-risk or untrusted agents, `agent-sandbox` supports two kernel-isolation runtimes that run as drop-in OCI replacements:

| Runtime | How It Works | Isolation Level |
|---------|-------------|-----------------|
| **gVisor (`runsc`)** | Implements a user-space application kernel (Sentry) that intercepts syscalls. The container never touches the host kernel directly. | Syscall-level isolation |
| **Kata Containers** | Each container runs inside a lightweight VM with its own Linux guest kernel via QEMU/Cloud Hypervisor. | Full VM-backed kernel isolation |

### `IsolationRuntime` Enum

```python
from agent_sandbox import IsolationRuntime

class IsolationRuntime(str, Enum):
    RUNC   = "runc"          # Standard Docker (shared kernel)
    GVISOR = "runsc"         # gVisor user-space kernel
    KATA   = "kata-runtime"  # Kata lightweight VM
    AUTO   = "auto"          # Auto-detect strongest available
```

### Auto-Detection

When `runtime=IsolationRuntime.AUTO` (the default), the provider queries `docker info` for registered OCI runtimes and selects the strongest one:

```
Kata > gVisor > runc
```

If neither gVisor nor Kata is installed, it falls back to `runc` with a log message.

### Usage

The runtime can be set at **two levels**:

1. **Provider level** (constructor) — sets the default runtime for all sessions on that provider.
2. **Session level** (`SandboxConfig.runtime`) — overrides the provider default for a specific `create_session` call. If not set, the session inherits the provider's runtime.

**Provider-level runtime (default for all sessions):**

```python
from agent_sandbox import DockerSandboxProvider, IsolationRuntime

# Auto-detect (default) — picks the strongest available runtime
provider = DockerSandboxProvider()
print(provider.runtime)          # e.g. IsolationRuntime.GVISOR
print(provider.kernel_isolated)  # True

# Explicitly require gVisor — raises RuntimeError if not installed
provider = DockerSandboxProvider(runtime=IsolationRuntime.GVISOR)

# Explicitly require Kata — raises RuntimeError if not installed
provider = DockerSandboxProvider(runtime=IsolationRuntime.KATA)

# Force standard runc (no kernel isolation)
provider = DockerSandboxProvider(runtime=IsolationRuntime.RUNC)
```

**Per-session runtime override via `create_session`:**

```python
from agent_sandbox import DockerSandboxProvider, IsolationRuntime
from agent_os.sandbox_provider import SandboxConfig

# Provider defaults to runc
provider = DockerSandboxProvider(runtime=IsolationRuntime.RUNC)

# Trusted agent — uses the provider's default runtime (runc)
handle1 = provider.create_session("trusted-agent")

# Untrusted agent — override to gVisor for this session only
handle2 = provider.create_session(
    "untrusted-agent",
    config=SandboxConfig(runtime=IsolationRuntime.GVISOR),
)

# High-risk agent — override to Kata VM isolation
handle3 = provider.create_session(
    "high-risk-agent",
    config=SandboxConfig(runtime=IsolationRuntime.KATA),
)
```

When `SandboxConfig.runtime` is set, `_create_container` uses that value instead of `self._runtime`. If the requested runtime is not installed, `create_session` raises `RuntimeError`.


### Runtime Installation

#### gVisor (runsc)

```bash
# Install runsc
curl -fsSL https://gvisor.dev/archive.key | sudo gpg --dearmor -o /usr/share/keyrings/gvisor-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/gvisor-archive-keyring.gpg] https://storage.googleapis.com/gvisor/releases release main" | sudo tee /etc/apt/sources.list.d/gvisor.list
sudo apt-get update && sudo apt-get install -y runsc

# Register with Docker
sudo runsc install
sudo systemctl restart docker
```

#### Kata Containers

```bash
# Install Kata (Ubuntu/Debian)
sudo apt-get install -y kata-containers

# Register with Docker — add to /etc/docker/daemon.json:
# {
#   "runtimes": {
#     "kata-runtime": { "path": "/usr/bin/kata-runtime" }
#   }
# }
sudo systemctl restart docker
```

### Isolation Boundary Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                        Host Machine                          │
│                                                              │
│  ┌─── runc ────────┐  ┌─── runsc (gVisor) ──┐  ┌── Kata ──┐│
│  │                  │  │                     │  │           ││
│  │  ┌────────────┐  │  │  ┌──────────────┐   │  │  ┌─────┐ ││
│  │  │ Container  │  │  │  │  Container   │   │  │  │Guest│ ││
│  │  │            │  │  │  │              │   │  │  │ VM  │ ││
│  │  │  agent-1   │  │  │  │   agent-2    │   │  │  │     │ ││
│  │  └────────────┘  │  │  └──────┬───────┘   │  │  │agent│ ││
│  │        │         │  │         │            │  │  │ -3  │ ││
│  │   ─────┼─────    │  │    ┌────┴─────┐     │  │  └──┬──┘ ││
│  │   Host Kernel    │  │    │  Sentry   │     │  │  Guest   ││
│  │   (shared)       │  │    │ (app-kern)│     │  │  Kernel  ││
│  │                  │  │    └────┬──────┘     │  │  (own)   ││
│  └──────────────────┘  │   limited syscalls   │  └─────────┘│
│                        │         │            │       │      │
│  ════════════════════  │    ─────┼─────       │  ─────┼───── │
│     Host Kernel        │    Host Kernel       │  Host Kernel │
│                        └─────────────────────┘       (KVM)   │
└──────────────────────────────────────────────────────────────┘
```

## Future Work

### Cloud Sandbox Providers

- **Azure Container Apps (ACA)** — async-first provider using ACA dynamic sessions for serverless sandboxes with auto-scaling. `create_session` provisions a session pool; `execute_code` submits code via REST API. No Docker daemon required. Supports both long-running and ephemeral container modes, the latter giving sub-second cold starts for short-lived agent tasks.
- **Azure Container Instances (ACI)** — on-demand container groups for longer-running agent workloads. Supports GPU-backed sessions for ML agents.
- **Azure Kubernetes Service (AKS)** — pod-per-session model with namespace isolation. `create_session` creates a pod; `destroy_session` deletes it. Supports network policies for domain-level enforcement without iptables.
- **Amazon EKS** — same pod-per-session model as AKS, targeting AWS-hosted deployments.

All cloud providers implement the `SandboxProvider` ABC with native async overrides (`create_session_async`, `execute_code_async`, `destroy_session_async`). Execution polling via `get_execution_status` enables long-running cloud tasks. Checkpoint methods (`save_state`/`restore_state`) are optional — providers that support persistent storage can implement them; stateless providers skip them.

### HyperLightSandboxProvider

- **Full implementation** — complete the `HyperLightSandboxProvider` with Hyperlight micro-VM provisioning via KVM (Linux), MSHV (Azure), or Hyper-V (Windows). Each `create_session` call spins up a micro-VM with its own guest kernel; `destroy_session` tears it down.
- **Sub-millisecond cold starts** — Hyperlight micro-VMs boot in <1 ms, making per-call VM creation feasible for latency-sensitive workloads.
- **Hardware-level isolation** — the guest runs its own kernel, so kernel exploits in agent code cannot reach the host. No gVisor/Kata dependency required.
- **WASM guest support** — Hyperlight supports WebAssembly guests alongside native Linux guests, enabling language-agnostic sandboxing for non-Python agents.
- **Checkpoint support** — investigate micro-VM snapshotting (QEMU migration, Firecracker snapshots) as an alternative to `docker commit` for `save_state`/`restore_state`.

