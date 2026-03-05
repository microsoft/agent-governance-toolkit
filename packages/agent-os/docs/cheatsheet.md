# Agent OS Cheatsheet

Quick reference for Agent OS.

## Installation

```bash
pip install agent-os-kernel              # Core
pip install agent-os-kernel[cmvk]        # + Verification
pip install agent-os-kernel[observability] # + Prometheus/OpenTelemetry
pip install agent-os-kernel[full]        # Everything
```

## Basic Usage

```python
from agent_os import KernelSpace

kernel = KernelSpace(policy="strict")

@kernel.register
async def my_agent(task: str) -> str:
    return f"Processed: {task}"

result = await kernel.execute(my_agent, "analyze data")
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `agentos init <name>` | Create new project |
| `agentos run` | Run with kernel |
| `agentos check <path>` | Check for violations |
| `agentos check --staged` | Check staged git files |
| `agentos audit` | Audit policies |
| `agentos review <path> --cmvk` | Multi-model review |
| `agentos install-hooks` | Install git hooks |

## Policy Modes

```python
kernel = KernelSpace(policy="strict")      # Blocks writes, shell, PII
kernel = KernelSpace(policy="permissive")  # Logs only
kernel = KernelSpace(policy_file="custom.yaml")  # Custom rules
```

## Signals

```python
from agent_os import AgentSignal, SignalDispatcher

dispatcher = SignalDispatcher()
dispatcher.signal(agent_id, AgentSignal.SIGSTOP)  # Pause
dispatcher.signal(agent_id, AgentSignal.SIGCONT)  # Resume
dispatcher.signal(agent_id, AgentSignal.SIGKILL)  # Terminate
```

## Message Bus Adapters

```python
# Redis
from amb_core.adapters import RedisBroker
broker = RedisBroker(url="redis://localhost:6379")

# Kafka
from amb_core.adapters import KafkaBroker
broker = KafkaBroker(bootstrap_servers="localhost:9092")

# NATS
from amb_core.adapters import NATSBroker
broker = NATSBroker(servers=["nats://localhost:4222"])

# Azure Service Bus
from amb_core.adapters import AzureServiceBusBroker
broker = AzureServiceBusBroker(connection_string="...")

# AWS SQS
from amb_core.adapters import AWSSQSBroker
broker = AWSSQSBroker(region_name="us-east-1")
```

## Safe Tools

```python
from atr.tools.safe import create_safe_toolkit

toolkit = create_safe_toolkit("standard")

http = toolkit["http"]        # Rate-limited HTTP
files = toolkit["files"]      # Sandboxed file reader
calc = toolkit["calculator"]  # Safe math
json = toolkit["json"]        # Safe JSON/YAML
dt = toolkit["datetime"]      # Timezone-aware datetime
text = toolkit["text"]        # Text processing
```

## Framework Integrations

```python
# LangChain
from agent_os.integrations import LangChainKernel
governed = LangChainKernel().wrap(my_chain)

# OpenAI Assistants
from agent_os.integrations import OpenAIKernel
governed = OpenAIKernel().wrap_assistant(assistant, client)

# CrewAI
from agent_os.integrations import CrewAIKernel
governed = CrewAIKernel().wrap(my_crew)
```

## VFS (Virtual File System)

```python
from agent_os import AgentVFS

vfs = AgentVFS(agent_id="agent-001")
vfs.write("/mem/working/task.txt", "Current task")
content = vfs.read("/mem/working/task.txt")
```

## Observability

```python
from agent_os.observability import metrics

@metrics.track(name="my_operation")
async def my_function():
    with metrics.timer("sub_operation"):
        pass
    metrics.increment("counter_name")
```

## Policy File Format

```yaml
kernel:
  version: "1.0"
  mode: strict

policies:
  - name: read_only
    deny:
      - action: file_write
      - action: file_delete
  
  - name: sandboxed_reads
    allow:
      - action: file_read
        paths: ["./data/**"]
    deny:
      - action: file_read
        paths: ["/**"]

audit:
  enabled: true
  log_path: "./logs/audit.log"
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `AGENTOS_POLICY` | Default policy mode |
| `AGENTOS_AUDIT_LOG` | Audit log path |
| `OPENAI_API_KEY` | OpenAI API key |
| `REDIS_URL` | Redis connection URL |
| `KAFKA_SERVERS` | Kafka bootstrap servers |

## Quick Examples

### Hello World
```python
from agent_os import KernelSpace

kernel = KernelSpace(policy="strict")

@kernel.register
async def hello(name: str):
    return f"Hello, {name}!"

import asyncio
print(asyncio.run(kernel.execute(hello, "World")))
```

### With Tools
```python
from atr.tools.safe import CalculatorTool

calc = CalculatorTool()
result = calc.evaluate("sqrt(16) + 2 * 3")
print(result["result"])  # 10.0
```

### With Message Bus
```python
from amb_core import AgentMessageBus, Message
from amb_core.adapters import RedisBroker

bus = AgentMessageBus(broker=RedisBroker())
await bus.connect()

await bus.publish(Message(topic="tasks", payload={"task": "analyze"}))

async def handler(msg):
    print(f"Received: {msg.payload}")

await bus.subscribe("tasks", handler)
```

## Links

- [Documentation](docs/)
- [Examples](examples/)
- [GitHub](https://github.com/microsoft/agent-governance-toolkit)
