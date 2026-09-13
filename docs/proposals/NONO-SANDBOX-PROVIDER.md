---
title: Nono Sandbox Provider Design
last_reviewed: 2026-07-11
owner: agent-governance
---

# Nono Sandbox Provider Design

`NonoSandboxProvider` uses Landlock on Linux and Seatbelt on macOS through
`nono-py`. Each execution runs in a fresh child process with an explicit
capability set.

## Configuration

`NonoConfig.from_sandbox_config` maps timeout, mounts, environment, and
network controls. Network access is blocked by default. Filtered egress starts
a proxy with `allowed_hosts`. Unrestricted egress requires explicit default
allow.

Nono has no tool-registration channel, so a non-empty `tool_allowlist` is
rejected. CPU and memory controls remain the operating system's
responsibility.

## Native governance

An optional `AgentControl` is wrapped in `HostSession`. Runtime and
static-scan denials occur before `sandboxed_exec`.

## Related implementation

- [`NonoSandboxProvider`](https://github.com/microsoft/agent-governance-toolkit/blob/main/agent-governance-python/agent-sandbox/src/agent_sandbox/nono_sandbox_provider/provider.py)
- [Agent Sandbox README](https://github.com/microsoft/agent-governance-toolkit/blob/main/agent-governance-python/agent-sandbox/README.md)
