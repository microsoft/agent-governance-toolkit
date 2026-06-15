# 2026-06-11 — Sandbox Mounts Policy Field

PR: [microsoft/agent-governance-toolkit#2951](https://github.com/microsoft/agent-governance-toolkit/pull/2951)

## What changed and why

This PR adds a **`sandbox_mounts` extension field** to the canonical
`PolicyDocument` schema in
[`agent-governance-python/agent-os/src/agent_os/policies/schema.py`](../../../agent-governance-python/agent-os/src/agent_os/policies/schema.py)
so the new MXC (`MxcSandboxProvider`) backend — and the existing Docker,
Hyperlight, and ACA providers — can read filesystem mount configuration
from a single canonical policy document instead of from out-of-band
`SimpleNamespace` wrappers.

New model `SandboxMounts`:

| Field | Type | Default | Consumer |
|---|---|---|---|
| `input_dir` | `str \| None` | `None` (no mount) | Sandbox providers (mounted read-only) |
| `output_dir` | `str \| None` | `None` (no mount) | Sandbox providers (mounted read-write) |

New field on `PolicyDocument`:

| Field | Type | Default | Consumer |
|---|---|---|---|
| `sandbox_mounts` | `SandboxMounts` | `SandboxMounts()` (both paths `None`) | Sandbox providers (Docker / Hyperlight / MXC) |

The rule engine itself **ignores** these fields. They are read
exclusively by sandbox providers when constructing a sandbox session.
The field is modelled natively (rather than left as a duck-typed block)
because Pydantic drops unknown keys, so a free-form mapping would
otherwise be silently lost on load.

## Threat model impact

This change is **additive and fail-closed**. It does not add any new
capability or weaken any existing check.

| Dimension | Direction |
|---|---|
| Filesystem reach from a sandbox | **Unchanged by default; reduced/validated when set.** Both mount paths default to `None` (no mount). When a path *is* configured, every consuming provider validates it against a shared protected-path denylist (see below), so a policy can never mount a system root. |
| Egress / network reach | **Unchanged.** This PR adds no network field; the MXC provider reuses the existing `network_allowlist` / `network_default` contract (fail-closed deny). |
| Information leakage in error text | **Unchanged.** The new fields are pure data carriers; the only error text they produce is a deterministic "protected system directory" rejection that echoes the offending path the caller already supplied. |
| Policy bypass surface | **Unchanged.** No existing check is removed, weakened, or made conditional. Rule-engine evaluation paths are byte-identical. |
| Authentication / identity / trust handshake | **Unchanged.** No identity, signing, or trust code is modified. |
| Privilege boundaries | **Unchanged.** Execution rings, kill switch, approval gates, and Cedar evaluation are all untouched. |
| Tool-invocation surface | **Reduced for MXC.** MXC cannot enforce a `tool_allowlist`, so the provider **rejects** any policy with a non-empty `tool_allowlist` at session creation rather than silently ignoring the control. |
| Backward compatibility | **Preserved.** `sandbox_mounts` is optional with a safe default (both paths `None`). Existing YAML/JSON policy documents load unchanged. |

### Specific mitigations applied

- **Both mount paths default to `None`.** An unconfigured policy mounts
  nothing. Providers never fall through to a permissive default mount.
- **Protected-path validation is shared and fail-closed.** Mount paths
  (`input_dir` / `output_dir`, plus any provider session paths) are
  validated against a single
  [`agent-governance-python/agent-sandbox/src/agent_sandbox/_hardening.py`](../../../agent-governance-python/agent-sandbox/src/agent_sandbox/_hardening.py)
  denylist of system roots (`/`, `/etc`, `/usr`, `C:\Windows`, every
  user's profile root, …). A policy requesting a read-write mount of a
  system directory raises `ValueError` before any sandbox is spawned.
  The MXC provider reuses the exact logic the Docker provider already
  used, so all backends share one definition.
- **`input_dir` is read-only; `output_dir` is read-write.** The
  read/write split is fixed by the schema semantics, not caller-supplied,
  so a policy cannot request a writable mount of an input directory.
- **MXC `extra_config` cannot weaken security keys.** The verbatim
  `extra_config` deep-merge is followed by a re-assertion of the
  security-critical keys (`network.allowOutbound`, resolved filesystem
  mounts, `timeoutMs`), so an operator fragment can never flip egress
  on or swap the mount layout.
- **Guest environment is sanitised.** Guest env vars are filtered
  through the shared `sanitize_env_vars` denylist (`LD_PRELOAD`,
  `PYTHONSTARTUP`, `NODE_OPTIONS`, …) before reaching the sandbox
  config, and guest/policy env is never mixed into the trusted runner
  process environment.
- **Egress stays fail-closed for MXC.** Outbound networking is only
  enabled by a non-empty `network_allowlist` (restricted to those
  hosts) or an explicit `defaults.network_default: allow` opt-in;
  enabling outbound with no host filter and no opt-in is rejected.

### Surfaces not yet converted (out of scope for this PR)

- Mount-path matching is exact-path based; there is no globbing or
  per-provider mount aliasing. A future PR may add normalised mount
  specs at the schema layer.
- Host-side enforcement of resource caps (`max_cpu` / `max_memory_mb`)
  remains delegated to each provider. MXC's `0.6.0-alpha` schema cannot
  express these, so the provider logs a warning when a policy sets them
  rather than silently dropping the cap. There is no host-side
  double-check.

## Test coverage

| File | Purpose |
|---|---|
| [`agent-sandbox/tests/test_mxc_sandbox.py`](../../../agent-governance-python/agent-sandbox/tests/test_mxc_sandbox.py) | `TestFailClosedHardening` pins the new guarantees: `extra_config` cannot flip `allowOutbound` or swap mounts/timeout, dangerous guest env vars are stripped, `tool_allowlist` fails closed, protected mount paths are rejected (`input_dir` / `output_dir` / policy mounts), caller context / policy env does not leak into the runner env, and the egress contract (`network_default`, unrestricted opt-in) is enforced. |
| [`agent-sandbox/tests/test_docker_sandbox.py`](../../../agent-governance-python/agent-sandbox/tests/test_docker_sandbox.py) | Protected-path and env-sanitisation tests retargeted to the shared `agent_sandbox._hardening` module so both providers exercise one definition. |

Full `pytest` run on `agent-governance-python/agent-sandbox/` is green
(459 passed, 62 skipped); `ruff check --select E,F,W --ignore E501` is
clean on all changed source files.

## Reviewer focus

Concentrate review on:

1. **Default is no mount.** `SandboxMounts.input_dir` and `output_dir`
   must default to `None`. Any change to a non-`None` default is a
   security regression and must be flagged.
2. **Protected-path validation runs on every mount path.** Confirm
   `validate_mount_path` is applied to `input_dir`, `output_dir`, and
   policy-supplied mounts in both `MxcConfig.from_sandbox_config` and
   `mxc_config_from_policy`, and that the shared `_hardening` denylist is
   the single source of truth.
3. **`extra_config` cannot weaken security keys.** Inspect
   `MxcConfig._reassert_security_keys`: after the verbatim merge, network
   egress, filesystem mounts, and timeout must be pinned back to the
   modelled values.
4. **MXC fail-closed posture.** Verify `tool_allowlist` rejection at
   session creation, guest-env sanitisation, runner/guest env separation,
   and the egress contract (deny by default; unrestricted egress requires
   an explicit opt-in).
5. **YAML/JSON backward compatibility.** Old policy documents that omit
   `sandbox_mounts` must load with both paths `None`.
