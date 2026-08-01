---
title: Docker Sandbox Isolation Design
last_reviewed: 2026-07-11
owner: agent-governance
---

# Docker Sandbox Isolation Design

`DockerSandboxProvider` runs each session in a hardened container with dropped
capabilities, no privilege escalation, a read-only root filesystem, a non-root
user, and bounded process and output resources.

## Current contract

Host controls use `SandboxConfig`. Optional governance uses `runtime=`.
Resource values and mount paths are never inferred from a policy object.

```python
config = SandboxConfig(
    timeout_seconds=30,
    memory_mb=256,
    cpu_limit=0.5,
    read_only_fs=True,
)
handle = provider.create_session(
    "agent-1",
    runtime=runtime,
    config=config,
)
```

Docker does not provide the filtered host or tool channel required to enforce
`network_allowlist` or `tool_allowlist`. The provider rejects those settings
instead of widening access. Unrestricted container networking requires
`network_enabled=True` and `network_default="allow"`.

## Execution order

1. Validate session identity and runtime decision.
2. Run the static subprocess scan.
3. Check execution-ring constraints.
4. Execute inside the container.
5. Capture bounded output and audit state.

## Related implementation

- [`DockerSandboxProvider`](../../agent-governance-python/agent-sandbox/src/agent_sandbox/docker_provider/provider.py)
- [Agent Sandbox README](../../agent-governance-python/agent-sandbox/README.md)
