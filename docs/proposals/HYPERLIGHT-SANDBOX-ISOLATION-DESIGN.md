---
title: Hyperlight Sandbox Isolation Design
last_reviewed: 2026-07-11
owner: agent-governance
---

# Hyperlight Sandbox Isolation Design

`HyperLightSandboxProvider` uses the upstream Hyperlight runtime to create a
micro-VM session for each agent. One worker thread owns each upstream sandbox
because the SDK is thread-affine.

## Host configuration

`HyperlightConfig.from_sandbox_config` maps memory, timeout, mounts, and
environment settings. `SandboxConfig.tool_allowlist` selects registered host
functions. `SandboxConfig.network_allowlist` selects domains passed to
`allow_domain`.

Unknown tools and capability-registration failures fail session creation.
Nanvix sessions reject unsupported tools and networking.

## Native governance

An optional `AgtRuntime` is wrapped in `AdapterRuntimeSession`. Denials occur
before guest execution. Runtime transforms and audit data remain native.

## Snapshots

Supported backends may capture and restore in-memory snapshots. Snapshot state
does not replace the native governance session or host configuration.

## Related implementation

- [`HyperLightSandboxProvider`](../../agent-governance-python/agent-sandbox/src/agent_sandbox/hyperlight_provider/provider.py)
- [Agent Sandbox README](../../agent-governance-python/agent-sandbox/README.md)
