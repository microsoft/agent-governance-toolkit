# Agent Sandbox

Public Preview — Docker-based execution isolation for AI agents with
policy-driven resource limits, tool proxies, network enforcement, and
filesystem checkpointing.

Part of the [Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit).

## Installation

```bash
pip install agent-sandbox[full]
```

## Quick Start

```python
from agent_sandbox import DockerSandboxProvider

provider = DockerSandboxProvider()
handle = provider.create_session("agent-1")
result = provider.execute_code("agent-1", handle.session_id, "print('hello')")
print(result.result.stdout)
provider.destroy_session("agent-1", handle.session_id)
```

## Running Agent Code in a Docker Sandbox

The example below shows how to run AI-generated code inside an isolated Docker
sandbox using the Microsoft Agent Governance Toolkit. Each agent session gets its
own hardened container with dropped capabilities, read-only root filesystem,
non-root execution, and optional policy-based gating.

```python
import asyncio
from agent_sandbox import (
    DockerSandboxProvider,
    IsolationRuntime,
    SandboxConfig,
)

async def run_agent_task():
    # 1. Create a provider — auto-detects gVisor / Kata if available
    provider = DockerSandboxProvider(
        image="python:3.12-slim",
        runtime=IsolationRuntime.AUTO,
    )

    # 2. Configure resource limits for the agent session
    config = SandboxConfig(
        timeout_seconds=30,
        memory_mb=256,
        cpu_limit=0.5,
        network_enabled=False,   # no outbound access
        read_only_fs=True,       # immutable root filesystem
    )

    # 3. Create an isolated session for the agent
    session = await provider.create_session_async(
        agent_id="research-agent",
        config=config,
    )
    print(f"Session created: {session.session_id}")

    try:
        # 4. Execute agent-generated code inside the sandbox
        agent_code = """
import json, math

data = [math.sqrt(x) for x in range(1, 11)]
result = {"roots": [round(v, 4) for v in data]}
print(json.dumps(result))
"""
        execution = await provider.execute_code_async(
            agent_id="research-agent",
            session_id=session.session_id,
            code=agent_code,
        )

        if execution.result.success:
            print(f"Output: {execution.result.stdout}")
        else:
            print(f"Error: {execution.result.stderr}")

        # 5. Checkpoint the session state for later resumption
        checkpoint = provider.save_state(
            "research-agent", session.session_id, "after-step-1",
        )
        print(f"Checkpoint saved: {checkpoint.image_tag}")

    finally:
        # 6. Tear down the container
        await provider.destroy_session_async(
            "research-agent", session.session_id,
        )
        print("Session destroyed")

asyncio.run(run_agent_task())
```

### What the sandbox enforces

| Control | Default |
|---------|---------|
| Linux capabilities | All dropped (`--cap-drop=ALL`) |
| Privilege escalation | Blocked (`--security-opt=no-new-privileges`) |
| Root filesystem | Read-only |
| Container user | `nobody` (UID 65534) |
| PID limit | 256 |
| Network | Disabled unless explicitly allowed |
| Runtime | runc (auto-upgrades to gVisor or Kata when available) |

## License

MIT
