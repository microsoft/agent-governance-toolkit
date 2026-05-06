# 30-Minute Deep Dive

> **Master Agent OS: policies, signals, memory, and verification.**

## Prerequisites

- Completed [5-Minute Quickstart](5-minute-quickstart.md)
- Python 3.10+
- `pip install agent-os-kernel[full]`

---

## Part 1: Understanding the Kernel (5 min)

### The Core Idea

Traditional agent safety relies on **prompts**: "Please don't do dangerous things."

Agent OS uses **kernel enforcement**: Actions are checked before execution. The agent doesn't decide—the kernel does.

```
┌─────────────────────────────────────────────────────────┐
│              USER SPACE                                 │
│   Your agent code runs here.                            │
│   It can try anything—but the kernel intercepts first.  │
├─────────────────────────────────────────────────────────┤
│              KERNEL SPACE                               │
│   ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│   │Policy Engine│  │Flight Recorder│ │Signal Dispatch│   │
│   └─────────────┘  └─────────────┘  └─────────────┘    │
│   Actions are checked, logged, and controlled here.     │
└─────────────────────────────────────────────────────────┘
```

### POSIX-Inspired Design

Agent OS borrows from operating systems:

| POSIX | Agent OS | Purpose |
|-------|----------|---------|
| `SIGKILL` | `AgentSignal.SIGKILL` | Terminate immediately |
| `SIGSTOP` | `AgentSignal.SIGSTOP` | Pause execution |
| `SIGCONT` | `AgentSignal.SIGCONT` | Resume execution |
| `/proc` | `/mem/working` | Agent state |
| `open()`, `read()` | `kernel.execute()` | System calls |

---

## Part 2: Policies (10 min)

### Creating Policies

Policies define what agents can and cannot do:

```python
from agent_os import KernelSpace, Policy

# Define a custom policy
policy = Policy(
    name="data-analyst",
    allowed_actions=["read_file", "query_database", "generate_report"],
    blocked_actions=["write_file", "delete_file", "send_email"],
    blocked_patterns=[
        r"\bpassword\b",
        r"\bssn\b",
        r"\bcredit.card\b"
    ]
)

kernel = KernelSpace(policy=policy)
```

### Policy Templates

Agent OS includes pre-built templates:

```python
# Strict: Read-only, no network, no shell
kernel = KernelSpace(policy="strict")

# Permissive: Logging only, no blocking
kernel = KernelSpace(policy="permissive")

# Audit: Full logging, selective blocking
kernel = KernelSpace(policy="audit")
```

### Policy Files (YAML)

Store policies in `.agents/security.yaml`:

```yaml
kernel:
  version: "1.0"
  mode: strict

policies:
  - name: read_only
    blocked_actions:
      - file_write
      - database_write
      - send_email
  
  - name: no_pii
    blocked_patterns:
      - "\\bssn\\b"
      - "\\bcredit.card\\b"
      - "\\bpassword\\b"

signals:
  on_violation: SIGKILL
  on_warning: SIGSTOP
```

Load from file:

```python
kernel = KernelSpace(policy_file=".agents/security.yaml")
```

---

## Part 3: Signals (5 min)

Signals control agent execution state:

```python
from agent_os import SignalDispatcher, AgentSignal

dispatcher = SignalDispatcher()

# Pause an agent
dispatcher.signal(agent_id="agent-001", signal=AgentSignal.SIGSTOP)

# Resume an agent
dispatcher.signal(agent_id="agent-001", signal=AgentSignal.SIGCONT)

# Terminate an agent (non-catchable)
dispatcher.signal(agent_id="agent-001", signal=AgentSignal.SIGKILL)
```

### Signal Handlers

Register handlers for custom behavior:

```python
@kernel.on_signal(AgentSignal.SIGSTOP)
async def handle_stop(agent_id: str, context: dict):
    print(f"Agent {agent_id} paused for review")
    # Log to audit system, notify humans, etc.

@kernel.on_signal(AgentSignal.SIGKILL)
async def handle_kill(agent_id: str, context: dict):
    print(f"Agent {agent_id} terminated: {context.get('reason')}")
    # Cleanup resources, send alerts, etc.
```

---

## Part 4: Virtual File System (5 min)

Agents have isolated, structured memory via VFS:

```python
from agent_os import AgentVFS

vfs = AgentVFS(agent_id="agent-001")

# Write to working memory
vfs.write("/mem/working/current_task.txt", "Analyze Q4 sales")
vfs.write("/mem/working/progress.json", '{"step": 2, "total": 5}')

# Read from memory
task = vfs.read("/mem/working/current_task.txt")

# List memory contents
files = vfs.listdir("/mem/working/")

# Episodic memory (read-only from agent, write via kernel)
history = vfs.read("/mem/episodic/2024-01-15.jsonl")
```

### VFS Structure

```
/
├── mem/
│   ├── working/     # Agent's scratch space (read/write)
│   ├── episodic/    # Historical episodes (read-only)
│   └── semantic/    # Long-term knowledge (read-only)
├── policy/          # Active policies (read-only)
│   └── rules.yaml
├── tools/           # Available tools (read-only)
│   └── registry.json
└── proc/            # Agent process info (read-only)
    └── status
```

---

## Part 5: Episodic Memory (5 min)

Record agent experiences for learning:

```python
from emk import Episode, FileAdapter

# Initialize storage
store = FileAdapter("agent_memory.jsonl")

# Record an episode
episode = Episode(
    goal="Query sales data",
    action="SELECT * FROM sales WHERE quarter='Q4'",
    result="Retrieved 1,523 rows",
    reflection="Query was efficient, no optimization needed"
)
store.store(episode)

# Retrieve similar episodes
similar = store.retrieve(query="sales query optimization", k=5)
for ep in similar:
    print(f"Goal: {ep.goal}, Result: {ep.result}")
```

### Memory Features

```python
from emk import MemoryCompressor

# Compress old episodes (sleep cycle)
compressor = MemoryCompressor(store, age_threshold_days=30)
result = compressor.compress_old_episodes()
# 1000 episodes → 20 semantic rules

# Track failures (negative memory)
failed = episode.mark_as_failure(reason="Timeout after 30s")
store.store(failed)
```

**See:** [Jupyter Notebook: Episodic Memory](../../notebooks/02-episodic-memory-demo.ipynb)

---

## Part 6: Verification (5 min)

Detect drift between model outputs:

```python
from cmvk import verify

# Compare two outputs
score = verify(
    "The capital of France is Paris.",
    "Paris is the capital city of France."
)

print(f"Drift: {score.drift_score:.3f}")      # 0.0 = identical
print(f"Confidence: {score.confidence:.3f}")  # 0.0-1.0
print(f"Type: {score.drift_type}")            # SEMANTIC, STRUCTURAL, etc.
```

### Multi-Model Consensus

```python
from cmvk import ConsensusVerifier

verifier = ConsensusVerifier(models=["gpt-4", "claude-3", "gemini-pro"])

result = await verifier.verify_consensus(
    prompt="What is the capital of France?",
    threshold=0.8  # Require 80% agreement
)

if result.consensus:
    print(f"Agreed answer: {result.answer}")
else:
    print(f"Disagreement detected: {result.drift_scores}")
```

**See:** [Jupyter Notebook: Verification](../../notebooks/04-cross-model-verification.ipynb)

---

## Putting It All Together

Complete example with all features:

```python
from agent_os import KernelSpace, AgentVFS, SignalDispatcher, AgentSignal
from emk import Episode, FileAdapter
from cmvk import verify

# Initialize kernel with strict policy
kernel = KernelSpace(policy="strict")
vfs = AgentVFS(agent_id="analyst-001")
memory = FileAdapter("analyst_memory.jsonl")

@kernel.register
async def data_analyst(task: str):
    # Check episodic memory for similar tasks
    similar = memory.retrieve(query=task, k=3)
    context = "\n".join([f"- {ep.goal}: {ep.result}" for ep in similar])
    
    # Store current task in working memory
    vfs.write("/mem/working/task.txt", task)
    
    # Your LLM logic here
    result = f"Analysis of: {task}"
    
    # Record episode
    episode = Episode(goal=task, action="analyze", result=result)
    memory.store(episode)
    
    return result

# Run with governance
if __name__ == "__main__":
    import asyncio
    result = asyncio.run(kernel.execute(data_analyst, "Q4 revenue trends"))
    print(result)
```

---

## Next Steps

| Resource | Description |
|----------|-------------|
| [Time-Travel Debugging](../../notebooks/03-time-travel-debugging.ipynb) | Replay and debug agent decisions |
| [Multi-Agent Coordination](../../notebooks/05-multi-agent-coordination.ipynb) | IATP trust protocol |
| [Production Examples](../../examples/) | Carbon Auditor, Grid Balancing, DeFi Sentinel |
| [Architecture Guide](../architecture.md) | Deep dive into system design |
| [API Reference](../api-reference/) | Full API documentation |

---

## Cheat Sheet

```python
# Kernel
kernel = KernelSpace(policy="strict")

# Register agent
@kernel.register
async def my_agent(task): ...

# Execute with governance
await kernel.execute(my_agent, "task")

# Signals
dispatcher.signal(agent_id, AgentSignal.SIGKILL)

# VFS
vfs = AgentVFS(agent_id="agent-001")
vfs.write("/mem/working/file.txt", "content")

# Memory
store = FileAdapter("memory.jsonl")
store.store(Episode(goal="...", action="...", result="..."))

# Verification
score = verify("text a", "text b")
```
