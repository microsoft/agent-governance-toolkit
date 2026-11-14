---
title: Azure Sandbox Isolation Design
last_reviewed: 2026-07-11
owner: agent-governance
---

# Azure Sandbox Isolation Design

`ACASandboxProvider` maps each agent session to an Azure Container Apps
sandbox. The provider owns provisioning, execution, egress configuration,
status, cancellation, and cleanup.

## Current contract

```python
handle = provider.create_session(
    "agent-1",
    runtime=runtime,
    config=config,
)
```

`SandboxConfig` owns CPU, memory, timeout, environment, mounts, and network
settings. `AgentControl` is optional and owns every governance decision. The
provider wraps it in `HostSession` and evaluates before Azure
execution.

## Egress

Every session receives an explicit Azure egress policy. The default denies all
outbound traffic. A non-empty `network_allowlist` creates host allow rules.
Unrestricted egress requires `network_enabled=True` and
`network_default="allow"`.

## Failure behavior

Invalid agent IDs, unavailable SDKs, provisioning failures, missing sandbox
IDs, runtime denials, and static code-scan denials fail before execution. An
Azure egress API failure also fails session creation: the sandbox already
exists at that point with Azure's default-allow egress, so the provider deletes
it and raises instead of returning a session whose requested deny policy was
never applied. If that delete fails too, the sandbox ID is logged at error
level so it can be removed manually. Sessions that opt in to unrestricted
egress (`network_default="allow"`) make no egress API call and are unaffected.

## Related implementation

- [`ACASandboxProvider`](https://github.com/microsoft/agent-governance-toolkit/blob/main/agent-governance-python/agent-sandbox/src/agent_sandbox/aca_sandbox_provider/aca_sandbox_provider.py)
- [`SandboxProvider`](https://github.com/microsoft/agent-governance-toolkit/blob/main/agent-governance-python/agent-sandbox/src/agent_sandbox/sandbox_provider.py)
- [Agent Sandbox README](https://github.com/microsoft/agent-governance-toolkit/blob/main/agent-governance-python/agent-sandbox/README.md)
