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
settings. `AgtRuntime` is optional and owns every governance decision. The
provider wraps it in `AdapterRuntimeSession` and evaluates before Azure
execution.

## Egress

Every session receives an explicit Azure egress policy. The default denies all
outbound traffic. A non-empty `network_allowlist` creates host allow rules.
Unrestricted egress requires `network_enabled=True` and
`network_default="allow"`.

## Failure behavior

Invalid agent IDs, unavailable SDKs, provisioning failures, missing sandbox
IDs, runtime denials, and static code-scan denials fail before execution. Azure
egress API failures are logged because the sandbox may already exist, while
the default requested state remains deny.

## Related implementation

- [`ACASandboxProvider`](../../agent-governance-python/agent-sandbox/src/agent_sandbox/aca_sandbox_provider/aca_sandbox_provider.py)
- [`SandboxProvider`](../../agent-governance-python/agent-sandbox/src/agent_sandbox/sandbox_provider.py)
- [Agent Sandbox README](../../agent-governance-python/agent-sandbox/README.md)
