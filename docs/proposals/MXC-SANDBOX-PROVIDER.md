---
title: MXC Sandbox Provider Design
last_reviewed: 2026-07-11
owner: agent-governance
---

# MXC Sandbox Provider Design

`MxcSandboxProvider` drives the native MXC executable and keeps no long-lived
sandbox process. A session owns a workspace whose scripts are mounted
read-only and whose output directory is mounted read-write.

## Configuration

`MxcConfig.from_sandbox_config` maps timeout, mounts, environment, and network
controls into MXC JSON. Filtered egress uses `network.allowedHosts`.
Unrestricted egress requires explicit default allow. Protected mount paths are
rejected.

MXC has no tool-registration channel. A non-empty `tool_allowlist` fails
session creation. CPU and memory limits are not represented by the stable MXC
schema and must be enforced by the selected containment backend.

## Native governance

`create_session(..., runtime=runtime, config=config)` stores an
`AdapterRuntimeSession`. Every `execute_code` call evaluates before the static
scan and before MXC is spawned.

## One-shot execution

`run_once` creates a session, executes once, and destroys the workspace. Use
the full lifecycle when multiple calls must share output files.

## Related implementation

- [`MxcSandboxProvider`](../../agent-governance-python/agent-sandbox/src/agent_sandbox/mxc_sandbox_provider/provider.py)
- [MXC quickstart](../../agent-governance-python/agent-sandbox/tutorials/mxc-quickstart/README.md)
