# Agent Sandbox

Public Preview — execution isolation for AI agents with policy-driven
resource limits, tool proxies, network enforcement, and filesystem
checkpointing. Ships five interchangeable backends behind the same
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
`execute_code`, `destroy_session`, plus `*_async` variants) and consume
the same `PolicyDocument` for resource caps, network allowlists, and
tool allowlists.

## Installation

```bash
# Everything (Docker + Hyperlight + policy engine):
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

Filesystem mounts come from the policy: `sandbox_mounts.input_dir` is
bind-mounted read-only and `sandbox_mounts.output_dir` read-write
(see [Policy-driven configuration](#policy-driven-configuration)).

---

## 2. `HyperLightSandboxProvider` — micro-VM isolation

Backed by the upstream [hyperlight-sandbox](https://github.com/hyperlight-dev/hyperlight-sandbox)
runtime. Each session is a fresh micro-VM on KVM (Linux), mshv (Azure
HCL), or WHP (Windows) — typical cold start is well under a millisecond.
Tools are registered as host functions and invoked synchronously from
the guest, gated by the session's `policy.tool_allowlist`.

```python
from agent_sandbox import HyperLightSandboxProvider

def fetch_arxiv(query: str) -> str:
    return f"<results for {query}>"

provider = HyperLightSandboxProvider(
    backend="wasm",                 # or "hyperlightjs" / "nanvix"
    module="python_guest",          # only meaningful for backend="wasm"
    tools={"fetch_arxiv": fetch_arxiv},
)

if not provider.is_available():
    raise SystemExit(f"Hyperlight unavailable: {provider.unavailable_reason}")

handle = provider.create_session("agent-1")
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
- Only tools listed in a session's `policy.tool_allowlist` are exposed
  to that session's guest; the rest stay host-side.
- Filesystem mounts come from the policy: `sandbox_mounts.input_dir`
  is mounted into the guest as read-only `/input` and
  `sandbox_mounts.output_dir` as writable `/output`.

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
by `begin_create_sandbox().result()`. When a `PolicyDocument` is
supplied, `network_allowlist` is translated into a fail-closed egress
policy (`defaultAction: Deny` + per-host `Allow` rules) and applied via
`SandboxClient.set_egress_policy`. Set `defaults.network_default: allow`
in the policy if you explicitly want the SDK's default-allow behaviour.

A complete worked example (8 verified branches against live Azure —
allow / policy-deny / egress-block / sanity / tool-allowed /
tool-denied / remote-execution proof / egress audit) lives at
[`examples/quickstart/aca_sandbox_test.py`](../../examples/quickstart/aca_sandbox_test.py)
and reads its policy from
[`examples/quickstart/policies/aca_research_agent.yaml`](../../examples/quickstart/policies/aca_research_agent.yaml).

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
Because the MXC schema has no tool or resource-cap concept,
`tool_allowlist` is enforced host-side before spawn and `max_cpu` /
`max_memory_mb` are carried but not rendered into the MXC config. See
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
built-in filtering proxy restricted to the policy's `network_allowlist`.
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

## Policy-driven configuration

All five providers consume the same `agent_os.policies.PolicyDocument`.
Sandbox resource caps, network allowlists, tool allowlists, and
filesystem mounts (`sandbox_mounts`) are native fields on the schema, so
policies live in YAML and load directly with `PolicyDocument.from_yaml`.

**Provider-specific notes:**

| Provider | `tool_allowlist` | Platform |
|----------|------------------|----------|
| `DockerSandboxProvider` | host-side enforcement | Linux, macOS, Windows |
| `HyperLightSandboxProvider` | in-sandbox tool registration | Linux, macOS, Windows |
| `ACASandboxProvider` | host-side enforcement | cloud (Azure) |
| `MxcSandboxProvider` | host-side enforcement | Linux, macOS, Windows |
| `NonoSandboxProvider` | **refused** if non-empty — use a `tool_name` rule instead | Linux, macOS only |

See `examples/quickstart/nono_sandbox_test.py` and
`examples/quickstart/policies/nono_research_agent.yaml` for a full
governed nono walkthrough (policy gate → AST scan → kernel isolation).

```yaml
name: research-agent
version: "2"

defaults:
  action: allow
  max_cpu: 1.0
  max_memory_mb: 2048
  timeout_seconds: 90
  network_default: deny

network_allowlist:
  - api.openai.com
  - "*.github.com"

tool_allowlist:
  - fetch_arxiv

sandbox_mounts:
  input_dir: /data/agent-input    # mounted read-only
  output_dir: /data/agent-output  # mounted read-write

rules:
  - name: deny-shell-out
    condition: { field: code, operator: contains, value: subprocess }
    action: deny
    priority: 100
    message: "shell-out blocked by research-agent policy"
```

```python
from agent_os.policies import PolicyDocument

policy = PolicyDocument.from_yaml("policies/aca_research_agent.yaml")
handle = await provider.create_session_async("agent-1", policy=policy)
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
identifies: without a pinned PATH, a tool can invoke `os.system('az account list')`
inside the sandbox and the attempt is not blocked or logged by AGT even though
the network-egress policy would later refuse the call. The hardened image makes
the attempt itself fail with "command not found".

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
