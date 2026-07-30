---
title: Azure Container Apps Sandbox Walkthrough
last_reviewed: 2026-07-11
owner: agent-governance
---

# Azure Container Apps Sandbox Walkthrough

This page summarizes the Azure deployment flow for `ACASandboxProvider`.
Detailed API behavior lives in
[Azure Sandbox Isolation Design](AZURE-SANDBOX-ISOLATION-DESIGN.md).

## Prerequisites

- An Azure resource group
- An Azure Container Apps sandbox group
- The early-access Azure sandbox SDK
- A credential supported by `DefaultAzureCredential` or an explicit
  credential object

## Session flow

1. Build `SandboxConfig` with explicit resource and egress settings.
2. Build `AgtRuntime` from a native manifest when governance is required.
3. Call `create_session` with `runtime=` and `config=`.
4. Call `execute_code`.
5. Destroy the session and close the provider.

```python
from agt.policies.runtime import AgtRuntime
from agent_sandbox import ACASandboxProvider, SandboxConfig

runtime = AgtRuntime.from_manifest("manifest.yaml")
config = SandboxConfig(
    timeout_seconds=30,
    memory_mb=512,
    cpu_limit=0.5,
    network_enabled=True,
    network_allowlist=["pypi.org"],
)

provider = ACASandboxProvider(
    resource_group="my-rg",
    sandbox_group="agents",
    region="eastus2",
)
handle = provider.create_session(
    "agent-1",
    runtime=runtime,
    config=config,
)
```

The provider applies a deny-by-default Azure egress policy for every session.
Runtime denials and static scan failures occur before Azure executes code.
