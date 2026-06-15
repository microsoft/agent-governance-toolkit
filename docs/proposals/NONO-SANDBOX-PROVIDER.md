# nono Sandbox Provider Design

| Field        | Value                                                       |
|--------------|-------------------------------------------------------------|
| **Status**   | Draft                                                       |
| **Author**   | AGT Core Team                                               |
| **Reviewer** | AGT Core Team                                               |
| **Date**     | 2026-06-15                                                  |
| **Package**  | `agent-sandbox`                                             |
| **Upstream** | [`always-further/nono`](https://github.com/always-further/nono) (Apache-2.0), Python bindings [`nono-py`](https://github.com/always-further/nono-py) |

## Motivation

`agent-sandbox` ships multiple backends behind the `SandboxProvider` ABC —
among them `DockerSandboxProvider` (hardened containers),
`HyperLightSandboxProvider` (micro-VMs), and `ACASandboxProvider` (managed
cloud sessions). Each carries an external dependency: a Docker daemon, a
hypervisor plus the `hyperlight-sandbox` SDK, or an Azure subscription.

[nono](https://github.com/always-further/nono) is a capability-based
sandboxing library that enforces isolation with **OS-native kernel primitives**
— Landlock on Linux (kernel 5.13+) and Seatbelt on macOS. Once a capability set
is applied, unauthorized filesystem and network operations are *structurally*
blocked by the kernel; there is no daemon, hypervisor, cloud account, or
external binary to install.

nono ships a first-party **Python package** (`nono-py`, PyO3 bindings over the
Rust crate) with prebuilt wheels. That makes it a natural fit for
`agent-sandbox`'s optional-dependency model: it installs like `docker` or
`hyperlight-sandbox` as a lazy extra rather than requiring separate host
infrastructure.

### Why the Python bindings and not the Rust crate

`agent-sandbox` is a pure-Python package. Depending on the `nono` Rust crate
directly would force a Rust toolchain and a `maturin`/`cffi` build step into the
wheel and break the "lazy optional extra" pattern every other backend follows.
`nono-py` already wraps the crate via PyO3 and publishes platform wheels (Linux
x86_64/aarch64, macOS x86_64/arm64, CPython 3.10–3.14), so the provider can
`import nono_py` lazily exactly like the other backends import their SDKs.

## Integration Approach

`NonoSandboxProvider` implements the same `SandboxProvider` ABC as the other
backends, so application code can swap to nono without changes. The integration
point is the `nono_py.sandboxed_exec` primitive:

1. The provider builds a `nono_py.CapabilitySet` from the resolved
   `NonoConfig` — read-only and read-write filesystem grants plus a network
   mode.
2. For network egress it starts a `nono_py` filtering proxy
   (`start_proxy`) restricted to the policy's `network_allowlist`, and binds the
   sandbox to it with `caps.proxy_only(proxy)`. With no egress the caps call
   `block_network()`.
3. `sandboxed_exec(caps, command, cwd=..., timeout_secs=..., env=...,
   inherit_env=False)` forks a child, applies the sandbox in the child, and
   `exec`s the command. The parent stays unsandboxed and captures stdout/stderr.
4. The `ExecResult` (`stdout`, `stderr`, `exit_code`) is mapped into a
   `SandboxResult`. A `124` exit code (nono's timeout convention) is surfaced as
   `killed=True`.

`NonoConfig` performs the same policy → config translation as
`docker_config_from_policy` and the other provider helpers, so a single
`PolicyDocument` (or duck-typed equivalent) drives any backend. The shared
`code_scanner` (AST pre-scan) and `_hardening` (env sanitisation, protected
mount rejection) utilities are reused unchanged.

## Session Model

nono's `sandboxed_exec` is **one-shot**: it forks, sandboxes, runs the command,
and the child exits. There is no long-lived guest the way a Docker container or
Hyperlight micro-VM persists across calls. To satisfy the session-based
`SandboxProvider` contract, a *session* is a durable **bundle** — the resolved `NonoConfig`, the policy
evaluator, a per-session workspace directory (`scripts/` read-only, `output/`
read-write), and an optional long-lived network proxy. Each `execute_code` (or
`run`) call forks a fresh one-shot sandbox using that bundle.

Consequently **guest state does not persist across executions** other than
through the read-write `output/` directory, which lives on the host and is
preserved between calls. In-memory state and writes elsewhere are discarded when
each invocation exits. The proxy *is* shared across executions in a session and
is shut down on `destroy_session`.

## Policy Mapping

| AGT policy / `SandboxConfig` field | nono equivalent |
|------------------------------------|-----------------|
| `sandbox_mounts.input_dir` / `input_dir` | `caps.allow_path(..., READ)` |
| `sandbox_mounts.output_dir` / `output_dir` | `caps.allow_path(..., READ_WRITE)` |
| `network_allowlist` | `start_proxy(ProxyConfig(allowed_hosts=...))` + `caps.proxy_only(proxy)` |
| `network_enabled=False` (default) | `caps.block_network()` |
| `defaults.network_default: allow` | unrestricted egress (`ProxyConfig(allow_all_hosts=True)`) — explicit opt-in |
| `defaults.timeout_seconds` | `sandboxed_exec(timeout_secs=...)` |
| `defaults.max_memory_mb` / `max_cpu` | not expressible in nono; warned and delegated to the OS |
| `tool_allowlist` | **fail-closed**: nono has no in-sandbox tool-registration channel, so a non-empty allowlist is refused |

Egress is **fail-closed**, consistent with the other sandbox providers: outbound is
only enabled by a non-empty `network_allowlist` (restricted to those hosts) or
an explicit `network_default: allow` (unrestricted). Enabling outbound with no
host list and no explicit unrestricted opt-in raises.

Guest environment variables are sanitised through the shared
`sanitize_env_vars` (stripping `LD_PRELOAD`, `PYTHONSTARTUP`, `NODE_OPTIONS`,
…), and nono independently rejects dynamic-loader variables in
`sandboxed_exec`. Filesystem mount requests are screened with the shared
`validate_mount_path` so protected system directories are never granted.

## Platform Support

| Platform | Backend | Status |
|----------|---------|--------|
| Linux (kernel 5.13+) | Landlock (+ seccomp for proxy-only) | Supported |
| macOS (11+) | Seatbelt | Supported |
| Windows (WSL2) | Landlock | Supported |
| Windows (native) | — | **Not supported** (no native wheels; NT has no Landlock) |

`is_available()` returns `False` when `nono_py` is not installed or
`nono_py.is_supported()` reports the host cannot enforce a sandbox (e.g.
Windows, or a Linux kernel without Landlock). Callers that need Windows or a
no-Landlock fallback should use a provider that supports those platforms (e.g.
Docker).

> **Security note.** `nono-py` is published with an *Alpha* development
> classifier. It should be used for defense-in-depth and developer ergonomics,
> and evaluated against your production isolation bar before being relied on as a
> hard boundary. The kernel-enforced model is stronger than the in-process
> `agent_os.sandbox` guard, but the project is still maturing.

## Out of Scope (future enhancements)

The first PR is deliberately a self-contained provider. Each item below is its
own follow-up; some need maintainer sign-off (cross-cutting / compliance per
`AGENTS.md`):

- **Sink `PolicyEvaluator.audit_entry`** — cross-provider (no backend forwards
  it today); belongs in its own PR.
- **Credential injection (`RouteConfig`)** — best fit; extends the
  `ProxyConfig` we already build so sandboxed code never holds the token.
- **Snapshot/rollback (`SnapshotManager`)** — mirror Docker's
  `save_state`/`restore_state` + `CHECKPOINT_CREATED`.
- **Audit trail** — translate nono events into AGT's existing Merkle chain,
  don't run a second ledger. Note nono's rich events come from its supervisor,
  not the `sandboxed_exec` primitive we call.

## Known caveats (conscious, inherited from other providers)

- **Policy gate fails open without `agent-os-kernel`** — no evaluator means
  rules aren't enforced (only AST scan + kernel isolation). `[nono]` doesn't
  pull in `[policy]`.
- **`SandboxConfig(network_enabled=True)` grants unrestricted egress** (matches
  MXC) — host-restricted egress only applies on the policy `network_allowlist`
  path.
- **Default read isolation is coarse** — `include_system_paths=True` grants
  broad read-only system access; strength is in blocking writes/egress.
- **Shared-kernel boundary** — for hostile code attempting kernel escape,
  prefer Hyperlight/ACA.

## Documentation follow-up

- Reflect **WSL2** as supported (provider already handles it). The accurate
  caveat is "no *native* Windows wheels."

## Testing

- **Unit** (`tests/test_nono_sandbox.py`): hermetic — `nono_py` is replaced with
  a fake module so config validation, policy translation, capability/proxy
  wiring, the session lifecycle, env isolation, timeout mapping, and the
  fail-closed guards are exercised without a real kernel sandbox.
- **Integration** (`tests/test_nono_integration.py`): skipped unless
  `AGT_NONO_INTEGRATION=1` is set and `nono_py.is_supported()` is true. Runs real
  pure-Python code through an actual Landlock/Seatbelt sandbox on Linux/macOS.
