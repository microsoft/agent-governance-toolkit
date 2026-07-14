# Agent Sandbox

Public Preview — execution isolation for AI agents with explicit host
configuration, optional native ACS governance, and filesystem checkpointing.
Ships five interchangeable backends behind the same
`SandboxProvider` ABC.

Part of the [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit).

## Providers at a glance

| Provider | Isolation primitive | Best for | Extra |
|----------|--------------------|----------|-------|
| `DockerSandboxProvider` | Hardened OCI container (runc, auto-upgrades to gVisor / Kata) | Local dev, CI, self-hosted runners | `agt-sandbox[docker]` |
| `HyperLightSandboxProvider` | KVM / mshv / WHP micro-VM via [hyperlight-sandbox](https://github.com/hyperlight-dev/hyperlight-sandbox) | Sub-millisecond cold start, per-call VM isolation | `agt-sandbox[hyperlight]` |
| `ACASandboxProvider` | [Azure Container Apps sandbox](https://github.com/microsoft/azure-container-apps) (managed) | Production, multi-tenant, no infra to run | `agt-sandbox[azure]` + the [early-access SDK wheel](https://github.com/microsoft/azure-container-apps/releases) |
| `MxcSandboxProvider` | OS-native containment via the [MXC](https://github.com/microsoft/mxc) binary (bubblewrap / AppContainer / Seatbelt / micro-VM) | No daemon, hypervisor SDK, or cloud account; CI and laptops | native MXC binary (no Python dep) — see [tutorial](tutorials/mxc-quickstart/README.md) |
| `NonoSandboxProvider` | OS-native kernel sandbox via [nono](https://github.com/always-further/nono) (Landlock on Linux, Seatbelt on macOS) with a filtering network proxy | Kernel-enforced isolation with a pure-Python install; CI and laptops (**Linux/macOS only**) | `agt-sandbox[nono]` |

All five implement the same async + sync API (`create_session`,
`execute_code`, `destroy_session`, plus `*_async` variants). Host controls use
`SandboxConfig`. Policy decisions use an optional native `AgtRuntime`.

## Installation

```bash
# Everything (Docker + Hyperlight + native governance support):
pip install "agt-sandbox[full]"

# Pick what you need:
pip install "agt-sandbox[docker]"
pip install "agt-sandbox[hyperlight]"
pip install "agt-sandbox[azure,policy]"
pip install "agt-sandbox[nono]"   # Linux/macOS only
```

The Azure data-plane SDK ships as an early-access wheel — pin the URL:

```bash
pip install https://github.com/microsoft/azure-container-apps/releases/download/python-sdk-v0.1.0b1-early-access/azure_containerapps_sandbox-0.1.0b1-py3-none-any.whl
```

## Quick start (all five providers)

```python
from agent_sandbox import (
    DockerSandboxProvider,
    HyperLightSandboxProvider,
    ACASandboxProvider,
    MxcSandboxProvider,
    NonoSandboxProvider,
)

# Pick one:
provider = DockerSandboxProvider()
# provider = HyperLightSandboxProvider(backend="wasm")
# provider = MxcSandboxProvider(backend="bubblewrap")
# provider = NonoSandboxProvider()  # Linux/macOS, kernel-enforced
# provider = ACASandboxProvider(
#     resource_group="my-rg", sandbox_group="agents",
#     region="eastus2", disk="python-3.13",
#     ensure_group_location="eastus2",
# )

handle = provider.create_session("agent-1")
out = provider.execute_code("agent-1", handle.session_id, "print('hello')")
print(out.result.stdout)
provider.destroy_session("agent-1", handle.session_id)
```

---

## 1. `DockerSandboxProvider` — local hardened containers

Each agent session runs in its own container with capabilities dropped,
no privilege escalation, a read-only root filesystem, a non-root user,
and no network by default.

```python
import asyncio
from agent_sandbox import (
    DockerSandboxProvider,
    IsolationRuntime,
    SandboxConfig,
)

async def run_agent_task():
    provider = DockerSandboxProvider(
        image="python:3.12-slim",
        runtime=IsolationRuntime.AUTO,   # auto-upgrade to gVisor / Kata
    )
    config = SandboxConfig(
        timeout_seconds=30,
        memory_mb=256,
        cpu_limit=0.5,
        network_enabled=False,
        read_only_fs=True,
    )

    session = await provider.create_session_async("research-agent", config=config)
    try:
        execution = await provider.execute_code_async(
            "research-agent", session.session_id,
            "import json, math; print(json.dumps([math.sqrt(x) for x in range(5)]))",
        )
        print(execution.result.stdout)

        checkpoint = provider.save_state(
            "research-agent", session.session_id, "after-step-1",
        )
        print(f"Checkpoint saved: {checkpoint.image_tag}")
    finally:
        await provider.destroy_session_async("research-agent", session.session_id)

asyncio.run(run_agent_task())
```

### What the Docker sandbox enforces

| Control | Default |
|---------|---------|
| Linux capabilities | All dropped (`--cap-drop=ALL`) |
| Privilege escalation | Blocked (`--security-opt=no-new-privileges`) |
| Root filesystem | Read-only |
| Container user | `nobody` (UID 65534) |
| PID limit | 256 |
| Network | Disabled unless explicitly allowed |
| Runtime | `runc` (auto-upgrades to gVisor or Kata when available) |
| State | `save_state` / `restore_state` via image commit |

Filesystem mounts come from `SandboxConfig.input_dir` and
`SandboxConfig.output_dir`.

---

## 2. `HyperLightSandboxProvider` — micro-VM isolation

Backed by the upstream [hyperlight-sandbox](https://github.com/hyperlight-dev/hyperlight-sandbox)
runtime. Each session is a fresh micro-VM on KVM (Linux), mshv (Azure
HCL), or WHP (Windows) — typical cold start is well under a millisecond.
Tools are registered as host functions and invoked synchronously from
the guest, gated by `SandboxConfig.tool_allowlist`.

```python
from agent_sandbox import HyperLightSandboxProvider, SandboxConfig

def fetch_arxiv(query: str) -> str:
    return f"<results for {query}>"

provider = HyperLightSandboxProvider(
    backend="wasm",                 # or "hyperlightjs" / "nanvix"
    module="python_guest",          # only meaningful for backend="wasm"
    tools={"fetch_arxiv": fetch_arxiv},
)

if not provider.is_available():
    raise SystemExit(f"Hyperlight unavailable: {provider.unavailable_reason}")

config = SandboxConfig(tool_allowlist=["fetch_arxiv"])
handle = provider.create_session("agent-1", config=config)
out = provider.execute_code(
    "agent-1", handle.session_id,
    "print(fetch_arxiv('cs.CL'))",
)
print(out.result.stdout)
provider.destroy_session("agent-1", handle.session_id)
```

Notes:
- Each session owns one OS thread that is the sole code path touching
  its `Sandbox` — required by the upstream runtime.
- `provider.is_available()` probes for a hypervisor and returns
  `unavailable_reason` if none is present (e.g. on macOS hosts without
  WHP / KVM passthrough).
- Only tools listed in a session's `SandboxConfig.tool_allowlist` are exposed
  to that session's guest; the rest stay host-side.
- Filesystem mounts come from `SandboxConfig.input_dir` and
  `SandboxConfig.output_dir`.

---

## 3. `ACASandboxProvider` — Azure Container Apps

Runs each session inside a managed Azure Container Apps sandbox via the
early-access `azure-containerapps-sandbox` Python SDK
([complete reference](https://github.com/microsoft/azure-container-apps/blob/main/docs/early/python-sdk/complete-reference.md)).
Same API as the other providers; the rest of your code is unchanged.

```bash
pip install "agt-sandbox[azure,policy]"
pip install https://github.com/microsoft/azure-container-apps/releases/download/python-sdk-v0.1.0b1-early-access/azure_containerapps_sandbox-0.1.0b1-py3-none-any.whl

az login   # or use managed identity in hosted compute
```

```python
from agent_sandbox import ACASandboxProvider

provider = ACASandboxProvider(
    resource_group="my-rg",          # must already exist
    sandbox_group="agents",          # auto-created if ensure_group_location is set
    region="eastus2",                # selects the data-plane endpoint
    subscription_id=None,            # falls back to AZURE_SUBSCRIPTION_ID env var
    disk="python-3.13",              # public disk image with python3 preinstalled
    ensure_group_location="eastus2", # create the sandbox group on first use
)

if not provider.is_available():
    raise SystemExit(f"ACA unavailable: {provider.unavailable_reason}")

handle = provider.create_session("agent-1")
out = provider.execute_code(
    "agent-1", handle.session_id, "print('hello azure')"
)
print(out.result.stdout)
provider.destroy_session("agent-1", handle.session_id)
provider.close()
```

The provider holds one `SandboxGroupClient` per `(resource_group,
sandbox_group)` pair and caches the per-sandbox `SandboxClient` returned
by `begin_create_sandbox().result()`. When
`SandboxConfig.network_allowlist` is supplied, it becomes a fail-closed egress
policy (`defaultAction: Deny` + per-host `Allow` rules) and applied via
`SandboxClient.set_egress_policy`. Set `network_default="allow"` with
`network_enabled=True` only when unrestricted egress is intentional.

---

## 4. `MxcSandboxProvider` — OS-native containment via MXC

Runs each execution behind whichever OS-native primitive the host
provides, driven by the [MXC](https://github.com/microsoft/mxc)
(Microsoft eXecution Container) native binary — bubblewrap / LXC on
Linux, AppContainer on Windows, Seatbelt on macOS, plus experimental
micro-VM backends. No daemon, hypervisor SDK, or cloud account, and
**no new Python dependency**: MXC ships as a native binary you build
from source and place on `PATH` (or point to with `MXC_BINARY`).

```python
from agent_sandbox import MxcSandboxProvider, SandboxConfig

provider = MxcSandboxProvider(backend="bubblewrap")  # None = platform default
if not provider.is_available():
    raise SystemExit("MXC binary not found; set MXC_BINARY or add it to PATH")

# One-shot: create + execute + destroy in a single call (no session_id
# to track), since the MXC sandbox self-destructs after each run.
execution = provider.run_once(
    "agent-1",
    "print('hello from mxc')",
    config=SandboxConfig(timeout_seconds=20, network_enabled=False),
)
print(execution.result.stdout)
```

For repeated executions that share the persistent `output/` directory,
use the full `create_session` + `execute_code` lifecycle instead.
Because the MXC schema has no tool or resource-cap concept, a non-empty
`tool_allowlist` is rejected. CPU and memory settings are not rendered into
the MXC config. See
the [MXC quickstart tutorial](tutorials/mxc-quickstart/README.md) and the
[design doc](../../docs/proposals/MXC-SANDBOX-PROVIDER.md) for details.

---

## 5. `NonoSandboxProvider` — OS-native kernel sandbox via nono

Runs each execution behind a capability set enforced by **OS-native
kernel primitives** — [Landlock](https://docs.kernel.org/userspace-api/landlock.html)
on Linux (kernel 5.13+) and Seatbelt on macOS — using the
[nono](https://github.com/always-further/nono) library's `nono-py`
bindings. No daemon, hypervisor SDK, or cloud account; install with
`agt-sandbox[nono]` (prebuilt wheels). Network egress is mediated by a
built-in filtering proxy restricted to `SandboxConfig.network_allowlist`.
**Linux/macOS only** — there are no Windows wheels.

```python
from agent_sandbox import NonoSandboxProvider, SandboxConfig

provider = NonoSandboxProvider()
if not provider.is_available():
    raise SystemExit("nono not supported here (needs Linux+Landlock or macOS)")

# One-shot: create + execute + destroy in a single call, since each nono
# sandbox is a fresh forked child that exits after the run.
execution = provider.run_once(
    "agent-1",
    "print('hello from nono')",
    config=SandboxConfig(timeout_seconds=20, network_enabled=False),
)
print(execution.result.stdout)
```

For repeated executions that share the persistent `output/` directory (and
a long-lived network proxy), use the full `create_session` + `execute_code`
lifecycle. nono has no in-sandbox tool channel, so a non-empty
`tool_allowlist` is **refused** at session creation
rather than silently ignored, and `max_cpu` / `max_memory_mb` are delegated
to the OS. See the
[design doc](../../docs/proposals/NONO-SANDBOX-PROVIDER.md) for details.

> **Production readiness.** `nono-py` is PyPI-classified **Alpha**
> (upstream [always-further/nono](https://github.com/always-further/nono)).
> Kernel enforcement (Landlock / Seatbelt) is structurally stronger than
> in-process guards, but the project is still maturing — use for
> defense-in-depth, dev, and CI first; run your own security review
> before treating it as a production hard boundary. On Windows or kernels
> without Landlock, use `DockerSandboxProvider` or another backend.

---

## Host configuration and native governance

Resource limits, mounts, network controls, environment variables, and
provider capabilities use `SandboxConfig`.

| Provider | Filtered network allowlist | Tool allowlist |
|----------|----------------------------|----------------|
| `DockerSandboxProvider` | Not supported, rejected | Not supported, rejected |
| `HyperLightSandboxProvider` | `allow_domain` | In-sandbox registration |
| `ACASandboxProvider` | Azure egress policy | Not supported, rejected |
| `MxcSandboxProvider` | MXC `allowedHosts` | Not supported, rejected |
| `NonoSandboxProvider` | Filtering proxy | Not supported, rejected |

```python
from agt.policies.runtime import AgtRuntime
from agent_sandbox import SandboxConfig

runtime = AgtRuntime.from_manifest("manifest.yaml")
config = SandboxConfig(
    timeout_seconds=90,
    memory_mb=2048,
    cpu_limit=1.0,
    input_dir="/data/agent-input",
    output_dir="/data/agent-output",
    network_enabled=True,
    network_allowlist=["api.openai.com", "*.github.com"],
)

handle = await provider.create_session_async(
    "agent-1",
    runtime=runtime,
    config=config,
)
```

## Hardened sandbox image (minimal-PATH)

`docker/Dockerfile.sandbox` is an opt-in hardened variant of the default
`python:3.11-slim` base. It pins `PATH` to a single explicit directory
(`/usr/local/sandbox-bin`) containing only the binaries sandboxed code is
allowed to invoke, and strips the execute bit off well-known network and
infra CLIs (`curl`, `wget`, `ssh`, `git`, `az`, `aws`, `gcloud`, `kubectl`,
`terraform`, `helm`, `ansible`, `apt`, `dpkg`, …) as a second-layer guarantee
in case a caller goes through an absolute path.

This closes the gap that issue [#2662](https://github.com/microsoft/agent-governance-toolkit/issues/2662)
identifies: without a pinned PATH, a tool can shell out to `az account list`
inside the sandbox and the attempt is not blocked or logged by AGT even though
the network-egress policy would later refuse the call.

### Logging denial shim (#2662 option 2)

The pinned PATH and execute-bit stripping *prevent* denied commands, but a bare
"command not found" / `EACCES` is silent — and for compliance, detecting the
attempt matters as much as preventing it. The image therefore routes the denied
network/infra CLIs (`curl`, `az`, `kubectl`, `terraform`, …) to a small Python
logging shim (`docker/agt-deny-shim.py`), installed both at each binary's real
path (so absolute-path calls are caught) and under its name in the pinned PATH
dir (so by-name calls are caught). Any attempt:

- writes a structured `command_denied` JSON record to stderr (captured in
  `SandboxResult.stderr`), e.g. `{"argv":["account","list"],"binary":"az",...}`;
- optionally appends the same record to `$AGT_DENIED_LOG` when that path is set
  and writable;
- exits `126`, so the real command never runs.

The shim is Python (not shell) because the image strips the execute bit off
every shell; `python3` is an allowed interpreter. Shells, interpreters, and
encoders stay execute-bit-stripped — disabled but not logged.

**Behavior change vs. the bare minimal-PATH image.** Routing a denied binary
through the shim makes it *executable again* (the shim itself runs), so an
absolute-path call now exits `126` with a logged record instead of raising
`EACCES`/`PermissionError`. The denial signal is the non-zero exit plus the
`command_denied` record, not an OS-level permission error. (No in-tree caller
relies on the `PermissionError` form; sandboxed code is still denied either
way.)

**Customizing the routed set.** The `DENIED_LOGGED_BIN_NAMES` build-arg
*replaces* the default set rather than extending it — pass the full list you
want logged, not just additions, or the image will silently under-restrict.
The allow-list wins: a name present in both `ALLOWED_BIN_NAMES` and
`DENIED_LOGGED_BIN_NAMES` is left allowed (not shimmed), so do not list the same
binary in both.

```bash
# Build with the default allow-list (python3, cat, echo, ls, sleep).
docker build \
  -f agent-sandbox/docker/Dockerfile.sandbox \
  -t agt-sandbox/python-minimal-path:3.11 \
  agent-sandbox/docker

# Build with a custom allow-list — add only what the sandboxed workload
# actually needs. The full allow-list IS the new PATH; any binary not listed
# here is unreachable.
docker build \
  --build-arg ALLOWED_BIN_NAMES="python3 cat echo ls sleep grep sort uniq" \
  -f agent-sandbox/docker/Dockerfile.sandbox \
  -t agt-sandbox/python-minimal-path:3.11 \
  agent-sandbox/docker
```

Wire the image into `DockerSandboxProvider` via the existing `image` argument:

```python
provider = DockerSandboxProvider(image="agt-sandbox/python-minimal-path:3.11")
```

For security-sensitive deployments, require the hardened image so the
provider fails instead of silently falling back to `python:3.11-slim` when
the local image is unavailable:

```python
provider = DockerSandboxProvider(require_hardened_image=True)
```

Build the image before creating the provider. `require_hardened_image=True`
cannot be combined with a custom `image=`.

To extend the allow-list permanently (rather than at `docker build` time),
edit the `ARG ALLOWED_BIN_NAMES=` line in `Dockerfile.sandbox` and rebuild.
The `tests/test_docker_sandbox.py::TestMinimalPathSandboxImage` smoke tests
assert that the default allow-list cannot accidentally regress to include
network or infra CLIs.

## License

MIT
