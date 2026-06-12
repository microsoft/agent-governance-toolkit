# Tutorial: Sandboxing Agent Code with the MXC Provider

This tutorial walks through running untrusted, model-generated code inside an
OS-native [MXC](https://github.com/microsoft/mxc) sandbox using
`MxcSandboxProvider` from `agt-sandbox`. By the end you will:

1. Install and discover the MXC native binary.
2. Run code in a one-shot sandbox.
3. Drive the sandbox from a governance **policy** (mounts, egress, timeout).
4. Convert a policy YAML straight into the MXC JSON config.
5. Understand what MXC enforces vs. what the host enforces.

> **Design reference:** [MXC-SANDBOX-PROVIDER.md](../../../../docs/proposals/MXC-SANDBOX-PROVIDER.md).
> **Security note:** MXC is an early preview — treat it as defense-in-depth,
> not a hard security boundary, until it stabilizes.

## Prerequisites

Install `agt-sandbox` (`pip install agt-sandbox`).
You also need the MXC native binary on your machine. MXC ships **no Python
package** — build the binary from source per the
[MXC README](https://github.com/microsoft/mxc#building), then make it
discoverable:

```bash
# Linux  -> lxc-exec   (serves both LXC and Bubblewrap)
# Windows-> wxc-exec.exe
# macOS  -> mxc-exec-mac
export MXC_BINARY=/path/to/lxc-exec        # or put it on PATH
```

The provider resolves the binary in this order: explicit `binary_path=` →
`MXC_BINARY` env var → `PATH`.

## Step 1 — Check availability

The provider never raises just because MXC is missing; it reports availability
so you can fall back gracefully.

```python
from agent_sandbox import MxcSandboxProvider

provider = MxcSandboxProvider(backend="bubblewrap")  # Linux default

if not provider.is_available():
    raise RuntimeError(
        "MXC binary not found. Build it per the MXC README and set MXC_BINARY."
    )
print("MXC ready:", provider.binary_path)
```

`backend=None` lets MXC pick the platform default (`processcontainer` on
Windows, `bubblewrap` on Linux, `seatbelt` on macOS). Experimental backends
(e.g. `hyperlight`, `microvm`) automatically set the `--experimental` flag.

## Step 2 — Run code (one-shot)

Since the MXC sandbox self-destructs after each run, the simplest path is
`run_once`: it spins up a fresh, fully isolated sandbox, runs your code, and
cleans up — no session to manage.

```python
from agent_sandbox import MxcSandboxProvider, SandboxConfig

provider = MxcSandboxProvider(backend="bubblewrap")

execution = provider.run_once(
    "tutorial-agent",
    "print('hello from the MXC sandbox')",
    config=SandboxConfig(timeout_seconds=20, network_enabled=False),
)
result = execution.result
print("exit:", result.exit_code, "ok:", result.success)
print(result.stdout)
# async: await provider.run_once_async("tutorial-agent", code)
```

**Key behaviors to know:**

- **Fully isolated per call.** Each `run_once` is a fresh sandbox with no
  shared state — in-memory variables and writes outside the read-write
  workspace are discarded when the run exits.
- **Errors, not crashes.** A blocked syscall, non-zero exit, or timeout surfaces
  as `result.success == False` (with `stderr` / `kill_reason`), never as host
  damage.

> **Need state across calls?** `run_once` is the right tool when each
> execution is independent. If you need a persistent read-write `output/`
> directory shared across multiple executions, use the full
> `create_session` → `execute_code` → `destroy_session` lifecycle instead
> (the `SandboxProvider` ABC that every backend implements). For one-shot
> agent work, `run_once` is all you need.


## Step 3 — Drive the sandbox from a policy

Instead of hand-building config, pass a governance policy. The provider reads
well-known attributes — `defaults.timeout_seconds`, `sandbox_mounts`,
`network_allowlist` — and translates them into MXC's filesystem/network policy.

```yaml
# sandbox_policy.yaml
version: "1.0"
name: pdf-summarizer-sandbox
defaults:
  timeout_seconds: 30
  network_default: deny        # fail-closed egress
network_allowlist:
  - pypi.org
  - "*.github.com"
sandbox_mounts:
  input_dir: /data/user-pdf    # mounted read-only
  output_dir: /data/agent-out  # mounted read-write
```

> **Tool allowlists are not supported by MXC.** The native binary has no
> tool-registration channel, so MXC cannot enforce a `tool_allowlist`.
> Rather than silently ignore the control, the provider **fails closed**:
> passing a policy whose `tool_allowlist` is non-empty raises at
> `create_session` / `run_once`. Use the Docker or Hyperlight backend when
> you need tool gating.

> **Egress is fail-closed.** Outbound networking stays off unless you opt in.
> A non-empty `network_allowlist` enables egress restricted to those hosts;
> to allow unrestricted egress you must set `defaults.network_default: allow`
> explicitly. Enabling outbound with no host filter and no explicit opt-in is
> rejected.

```python
from agent_os.policies.schema import PolicyDocument
from agent_sandbox import MxcSandboxProvider

# `sandbox_mounts` (input_dir / output_dir) is a native PolicyDocument
# field, so the YAML block loads directly — no subclass needed.
policy = PolicyDocument.from_yaml("sandbox_policy.yaml")

provider = MxcSandboxProvider(backend="bubblewrap")
execution = provider.run_once("pdf-agent", code, policy=policy)
```

## Step 4 — Convert a policy straight to MXC JSON

If you just want to see (or persist) the exact JSON MXC will consume, use the
converters — no provider or sandbox required:

```python
from agent_sandbox.mxc_sandbox_provider import policy_yaml_to_mxc_json
import json

doc = policy_yaml_to_mxc_json("sandbox_policy.yaml", "python /scripts/run.py")
print(json.dumps(doc, indent=2))
```

Output:

```json
{
  "version": "0.6.0-alpha",
  "process": { "commandLine": "python /scripts/run.py" },
  "filesystem": {
    "readonlyPaths": ["/data/user-pdf"],
    "readwritePaths": ["/data/agent-out"]
  },
  "network": {
    "allowOutbound": true,
    "allowedHosts": ["pypi.org", "*.github.com"]
  },
  "timeoutMs": 30000
}
```

There is also `policy_to_mxc_json(policy_obj, command_line)` for an in-memory
policy object.

## Step 5 — Understand the enforcement split

Notice what is — and is **not** — in that JSON:

| Constraint | Enforced by | In MXC JSON? |
|------------|-------------|--------------|
| Filesystem mounts | MXC (bubblewrap binds) | ✅ `filesystem.*` |
| Egress allowlist | MXC (network policy) | ✅ `network.*` |
| Timeout | MXC | ✅ `timeoutMs` |
| **Tool allowlist** | **Unsupported** — rejected fail-closed at session creation | ❌ — MXC has no tool concept |
| **CPU / memory** | Other backends (Docker/Hyperlight) | ❌ — not in `0.6.0-alpha` schema |

`tool_allowlist`, CPU, and memory are intentionally omitted from the JSON so it
never claims enforcement MXC does not provide. Because MXC cannot gate tools at
all, a policy that carries a non-empty `tool_allowlist` is **rejected** at
`create_session` / `run_once` rather than silently ignored — use Docker or
Hyperlight when tool gating is required.

## Defense-in-depth recap

For each execution, the provider applies four layers in order:

1. **Host policy gate** — `PolicyEvaluator` can deny before any sandbox spawns.
2. **Static code scan** — `enforce_no_subprocess_execution` rejects obvious
   process-spawning APIs.
3. **MXC containment** — filesystem/network policy enforced by the OS backend.
4. **Process isolation** — only `PATH` + explicitly configured env reach the
   child; host secrets are not inherited.

## Running the companion script

A runnable version of this tutorial lives next to it:

```bash
export MXC_BINARY=/path/to/lxc-exec
python agent-governance-python/agent-sandbox/tutorials/mxc-quickstart/quickstart.py
```

It prints the MXC availability, the rendered config JSON, and (if a binary is
present) the result of executing a small script in the sandbox.

## Where to go next

- Swap the backend: `MxcSandboxProvider(backend="hyperlight")` for micro-VM
  isolation (auto-enables `--experimental`).
- Compose with the governance stack: an untrusted (Ring 3) agent's code is the
  prime candidate for MXC containment.
- Read the full [design doc](../../../../docs/proposals/MXC-SANDBOX-PROVIDER.md)
  for the session model, schema mapping, and limitations.
