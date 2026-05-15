# 2026-05-14 — Sandbox Policy Extension Fields

PR: [microsoft/agent-governance-toolkit#2236](https://github.com/microsoft/agent-governance-toolkit/pull/2236)

## What changed and why

This PR adds **sandbox-provider extension fields** to the canonical
`PolicyDocument` / `PolicyDefaults` schema in
[`agent-governance-python/agent-os/src/agent_os/policies/schema.py`](../../agent-governance-python/agent-os/src/agent_os/policies/schema.py)
so the new Azure Container Apps (`ACASandboxProvider`) backend — and the
existing Docker and Hyperlight providers — can read resource and egress
controls from a single canonical policy document instead of from
out-of-band `SimpleNamespace` wrappers.

New fields on `PolicyDefaults`:

| Field | Type | Default | Consumer |
|---|---|---|---|
| `max_cpu` | `float \| None` | `None` (provider default) | Sandbox providers |
| `max_memory_mb` | `int \| None` | `None` (provider default) | Sandbox providers |
| `timeout_seconds` | `int \| None` | `None` (provider default) | Sandbox providers |
| `network_default` | `Literal["allow", "deny"]` | **`"deny"`** | Sandbox providers |

New fields on `PolicyDocument`:

| Field | Type | Default | Consumer |
|---|---|---|---|
| `network_allowlist` | `list[str]` | `[]` | Sandbox providers (egress proxy) |
| `tool_allowlist` | `list[str]` | `[]` | `PolicyEvaluator` (host-side, before any sandbox call) |

The rule engine itself **ignores** all of these fields. They are read
exclusively by sandbox providers (and, for `tool_allowlist`, by the
existing host-side `PolicyEvaluator`).

## Threat model impact

This change is **additive and fail-closed**. It does not add any new
capability or weaken any existing check.

| Dimension | Direction |
|---|---|
| Egress / network reach from a sandbox | **Reduced (fail-closed by default).** `network_default` defaults to `"deny"`, so any caller who upgrades and re-uses an existing policy document with no `network_allowlist` gets *less* network reach than they had before, never more. |
| Information leakage in error text | **Unchanged.** The new fields are pure data carriers; no error-text formatter consumes them. |
| Policy bypass surface | **Unchanged.** No existing check is removed, weakened, or made conditional. Rule-engine evaluation paths are byte-identical. |
| Authentication / identity / trust handshake | **Unchanged.** No identity, signing, or trust code is modified. |
| Privilege boundaries | **Unchanged.** Execution rings, kill switch, approval gates, and Cedar evaluation are all untouched. |
| Tool-invocation surface | **Reduced when set.** `tool_allowlist` is host-side enforced by `PolicyEvaluator` *before* any sandbox call. An empty list (the default) preserves current behavior; a non-empty list narrows the allowed tools. |
| Backward compatibility | **Preserved.** All new fields are optional with safe defaults. Existing YAML policy documents load unchanged (regression-tested — see below). |

### Specific mitigations applied

- **`network_default` defaults to `"deny"`.** The provider-side egress
  proxy treats an unconfigured policy as *deny all egress*, not *allow
  all*. Operators who genuinely need open egress for dev/research must
  opt in explicitly. This matches the existing fail-closed posture of
  the rule engine.
- **`network_allowlist` and `tool_allowlist` default to empty lists,
  not `None`.** Provider code never has to disambiguate
  *"no allowlist configured"* from *"empty allowlist"*. An empty list is
  the strictest possible configuration; providers cannot accidentally
  fall through to permissive defaults.
- **`Literal["allow", "deny"]`** for `network_default` is a closed enum
  enforced by Pydantic at parse time. Misspelled or attacker-controlled
  values fail validation rather than silently falling back to a
  permissive setting.
- **Schema fields live on the canonical `PolicyDocument` / `PolicyDefaults`
  models.** Providers no longer need ad-hoc `SimpleNamespace` wrappers
  or duck-typed `getattr(policy, "network_allowlist", [])` lookups,
  which previously could silently swallow typos in field names.
- **Tool-allowlist enforcement remains host-side.** `tool_allowlist`
  is checked by the existing `PolicyEvaluator` **before** any sandbox
  call is dispatched, so an untrusted sandbox cannot bypass it by
  ignoring the field.

### Surfaces not yet converted (out of scope for this PR)

- Host-side enforcement of `max_cpu` / `max_memory_mb` / `timeout_seconds`
  is delegated to each provider. The Docker, Hyperlight, and ACA
  providers all honor these limits today; future BYO providers must
  implement them. There is no host-side double-check.
- `network_allowlist` matching semantics (exact host vs. glob suffix)
  are provider-defined. The ACA provider treats entries as exact hosts
  with `*.example.com` suffix-glob support; the Docker provider mirrors
  this. A future PR will lift the matching rule to the schema layer.

## Test coverage

All new tests live in `agent-governance-python/agent-os/tests/` and
`agent-governance-python/agent-sandbox/tests/`:

| File | Purpose |
|---|---|
| [`agent-os/tests/test_policy_sandbox_fields.py`](../../agent-governance-python/agent-os/tests/test_policy_sandbox_fields.py) | Pins the contract for the new schema fields: defaults, allowed `Literal` values, YAML round-trip, and backward compatibility with older YAML files that omit every new field. |
| [`agent-sandbox/tests/test_azure_sandbox.py`](../../agent-governance-python/agent-sandbox/tests/test_azure_sandbox.py) | Module-level helpers `_network_allowlist`, `_network_default`, and `aca_config_from_policy` are exercised against the new schema fields — including the fail-closed default, the `allow` opt-in path, and empty-allowlist behavior. |
| [`agent-sandbox/tests/test_azure_sandbox_integration.py`](../../agent-governance-python/agent-sandbox/tests/test_azure_sandbox_integration.py) | End-to-end test `test_empty_allowlist_plus_deny_is_total_lockdown` verifies that the default policy produces zero egress decisions, and `test_network_default_allow_lets_everything_through` verifies the opt-in path. |
| [`agent-sandbox/tests/test_docker_sandbox.py`](../../agent-governance-python/agent-sandbox/tests/test_docker_sandbox.py) | Existing Docker provider tests updated to use the new `network_allowlist` field directly, replacing the previous `SimpleNamespace` shim. Includes `test_network_allowlist_enables_network`, `test_no_network_allowlist`, and `test_empty_network_allowlist_keeps_network_disabled`. |

Full `pytest` run on `agent-governance-python/agent-os/` and
`agent-governance-python/agent-sandbox/` is green; no existing test
required modification beyond removing the `SimpleNamespace` shim in
favor of the new native fields.

## Reviewer focus

Concentrate review on:

1. **Fail-closed default.** `PolicyDefaults.network_default` must
   default to `"deny"`. Any change to this default is a security
   regression and must be flagged.
2. **Provider-side allowlist construction.** Inspect
   `aca_config_from_policy`, `_network_allowlist`, and the equivalent
   Docker-provider helper. Each must:
   - reject unknown `network_default` values (Pydantic enforces this
     at parse time, but providers should not re-introduce a permissive
     fallback if the field is unset),
   - treat an empty `network_allowlist` as *strictest*, not *unconfigured*,
   - never read `network_*` fields through duck-typed `getattr` with a
     permissive default.
3. **Host-side `tool_allowlist` enforcement.** Confirm that
   `PolicyEvaluator` consults `tool_allowlist` *before* dispatching to
   any sandbox provider. An empty list must preserve current behavior
   (no filtering); a non-empty list must deny any tool not on the list.
4. **YAML backward compatibility.** Old policy YAML files (which omit
   every new field) must continue to load with the documented defaults.
   The round-trip tests in `test_policy_sandbox_fields.py` pin this.
