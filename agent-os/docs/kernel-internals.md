# Kernel Internals

> Deep dive into Agent OS kernel architecture for AAIF reviewers.

## Table of Contents

- [Design Philosophy](#design-philosophy)
- [Execution Model](#execution-model)
- [Policy Engine](#policy-engine)
- [Signal Dispatch](#signal-dispatch)
- [Virtual File System](#virtual-file-system)
- [Stateless Architecture](#stateless-architecture)
- [Integration Points](#integration-points)

---

## Design Philosophy

### Why a Kernel?

Traditional agent frameworks (LangChain, CrewAI) are libraries—they provide tools, not governance. When an agent misbehaves, the framework can only suggest; it cannot enforce.

Agent OS inverts this: **the kernel owns execution**. Every agent action passes through kernel space, where policies are enforced deterministically before execution reaches user space.

```
┌────────────────────────────────────────────────────────────────┐
│                        Traditional Framework                    │
│                                                                │
│    Agent → Action → Maybe Validation? → Execution              │
│                     (library call)      (uncontrolled)         │
└────────────────────────────────────────────────────────────────┘

┌────────────────────────────────────────────────────────────────┐
│                           Agent OS                              │
│                                                                │
│    Agent → Syscall → Kernel Space → Policy Check → SIGKILL?   │
│              │                            │                    │
│              │        ┌───────────────────┘                    │
│              │        │ PASS                                   │
│              │        ▼                                        │
│              └───── Execution (governed)                       │
└────────────────────────────────────────────────────────────────┘
```

### Core Invariants

1. **No Bypass**: All agent I/O goes through syscalls
2. **Fail Closed**: Unknown actions are denied
3. **Audit Everything**: Flight Recorder logs all decisions
4. **Crash Isolation**: User space crash ≠ kernel crash

---

## Execution Model

### Request Lifecycle

```
1. Agent code makes syscall (SYS_EXEC, SYS_WRITE, etc.)
         │
         ▼
2. Kernel receives ExecutionRequest
   ┌─────────────────────────────────────────┐
   │ ExecutionRequest                        │
   │   agent_id: "carbon-auditor"           │
   │   action: "database_query"             │
   │   params: {"query": "SELECT..."}       │
   │   context:                             │
   │     policies: ["read_only", "no_pii"]  │
   │     history: [...]                     │
   └─────────────────────────────────────────┘
         │
         ▼
3. Policy Engine evaluates each policy
   ┌─────────────────────────────────────────┐
   │ For each policy in context.policies:   │
   │   - Check blocked_actions              │
   │   - Check blocked_patterns             │
   │   - Check constraints                  │
   │                                        │
   │ If ANY check fails → SIGKILL           │
   └─────────────────────────────────────────┘
         │
    ┌────┴────┐
    │ DENIED  │───▶ ExecutionResult(signal=SIGKILL)
    └─────────┘
         │
    ┌────┴────┐
    │ ALLOWED │───▶ Execute action
    └─────────┘
         │
         ▼
4. Update context with history entry
         │
         ▼
5. Return ExecutionResult
   ┌─────────────────────────────────────────┐
   │ ExecutionResult                        │
   │   success: True                        │
   │   data: {"rows": [...]}               │
   │   trace_id: "abc123"                  │
   │   updated_context: ExecutionContext   │
   └─────────────────────────────────────────┘
```

### Stateless Execution

Every request is independent. The kernel maintains no session state.

```python
from agent_os import StatelessKernel, ExecutionContext

kernel = StatelessKernel()

# Each call is independent
result1 = await kernel.execute(
    action="database_query",
    params={"query": "SELECT * FROM users"},
    context=ExecutionContext(
        agent_id="agent-1",
        policies=["read_only"],
        history=[]  # Empty history
    )
)

# Pass updated context back for next call
result2 = await kernel.execute(
    action="api_call",
    params={"url": "https://api.example.com"},
    context=result1.updated_context  # Contains history
)
```

**Why Stateless?**

- Horizontal scaling (any kernel instance handles any request)
- MCP compatibility (June 2026 stateless requirement)
- Easier testing (no hidden state)
- Cloud-native (works with Lambda, Cloud Run)

---

## Policy Engine

### Policy Definition

Policies are declarative rules that define allowed/blocked actions:

```python
DEFAULT_POLICIES = {
    "read_only": {
        "blocked_actions": [
            "file_write", "database_write", "send_email",
            "api_call_write", "delete"
        ],
        "blocked_patterns": []
    },
    "no_pii": {
        "blocked_actions": [],
        "blocked_patterns": [
            r"\bssn\b", r"\bsocial.security\b",
            r"\bcredit.card\b", r"\bpassword\b"
        ]
    },
    "strict": {
        "blocked_actions": ["shell_exec", "eval", "raw_sql"],
        "blocked_patterns": [
            r"\bdrop\s+table\b", r"\bdelete\s+from\b",
            r";\s*--", r"'\s*or\s*'1'\s*=\s*'1"
        ]
    },
    "audit": {
        "blocked_actions": [],
        "blocked_patterns": [],
        "audit_all": True  # Log everything, block nothing
    }
}
```

### Policy Checking Flow

```python
def _check_policies(self, request: ExecutionRequest) -> Optional[str]:
    """
    Check all policies against the request.
    Returns error message if blocked, None if allowed.
    """
    for policy_name in request.context.policies:
        policy = self.policies.get(policy_name)
        if not policy:
            continue
        
        # Check blocked actions
        if request.action in policy.get("blocked_actions", []):
            return f"Action '{request.action}' blocked by '{policy_name}'"
        
        # Check blocked patterns in params
        params_str = json.dumps(request.params).lower()
        for pattern in policy.get("blocked_patterns", []):
            if re.search(pattern, params_str, re.IGNORECASE):
                return f"Pattern '{pattern}' blocked by '{policy_name}'"
    
    return None  # All checks passed
```

### Custom Policies

```python
kernel = StatelessKernel(policies={
    "banking": {
        "blocked_actions": ["transfer_funds", "create_account"],
        "blocked_patterns": [r"\$\d{6,}"],  # Block amounts > $99,999
        "max_calls_per_minute": 10
    }
})
```

---

## Signal Dispatch

### POSIX-Inspired Signals

| Signal | Value | Description | Maskable | Recovery |
|--------|-------|-------------|----------|----------|
| `SIGSTOP` | 1 | Pause execution | Yes | `SIGCONT` |
| `SIGCONT` | 2 | Resume execution | Yes | - |
| `SIGINT` | 3 | Graceful interrupt | Yes | Restart |
| `SIGKILL` | 4 | Immediate termination | **No** | New agent |
| `SIGTERM` | 5 | Request shutdown | Yes | Cleanup |
| `SIGPOLICY` | 8 | Policy violation | **No** | None |
| `SIGTRUST` | 9 | Trust violation | **No** | None |

### Signal Handling Code

```python
class SignalDispatcher:
    """Dispatch signals to agents."""
    
    def __init__(self):
        self._handlers: Dict[str, Dict[Signal, Callable]] = {}
        self._history: List[Dict] = []
    
    def send(self, agent_id: str, signal: Signal, reason: str = ""):
        """Send signal to agent."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "agent_id": agent_id,
            "signal": signal.name,
            "reason": reason
        }
        self._history.append(entry)
        
        # Non-maskable signals
        if signal in (Signal.SIGKILL, Signal.SIGPOLICY, Signal.SIGTRUST):
            self._terminate(agent_id, signal, reason)
            return
        
        # Maskable signals - call handler if registered
        handlers = self._handlers.get(agent_id, {})
        handler = handlers.get(signal)
        if handler:
            handler(signal, reason)
```

### Policy Violation → SIGKILL

When a policy check fails:

```python
# In StatelessKernel.execute()
error = self._check_policies(request)
if error:
    # Record metrics
    self.metrics.record_violation(
        agent_id=request.context.agent_id,
        action=request.action,
        policy=error.split("'")[1]
    )
    self.metrics.record_blocked(request.context.agent_id, request.action)
    
    # Emit signal (for Flight Recorder)
    self.signals.send(
        request.context.agent_id,
        Signal.SIGKILL,
        reason=error
    )
    
    return ExecutionResult(
        success=False,
        error=error,
        signal="SIGKILL"
    )
```

---

## Virtual File System

### Mount Points

```
/agent/{agent_id}/
├── mem/
│   ├── working/      # Ephemeral (cleared on restart)
│   ├── episodic/     # Experience logs
│   └── semantic/     # Long-term knowledge
├── state/
│   └── checkpoints/  # SIGUSR1 snapshots
├── policy/           # Read-only from user space
│   ├── active.json   # Current policies
│   └── history.json  # Policy changes
├── ipc/              # Inter-process pipes
│   ├── inbox/
│   └── outbox/
└── audit/            # Flight Recorder logs
    └── events.jsonl
```

### VFS Operations

```python
class AgentVFS:
    """Virtual File System for agent memory and state."""
    
    def __init__(self, agent_id: str, backend: StorageBackend = None):
        self.agent_id = agent_id
        self.backend = backend or MemoryBackend()
        self._readonly_paths = {"/policy", "/audit"}
    
    def write(self, path: str, data: Any) -> bool:
        """Write to VFS path."""
        full_path = f"/agent/{self.agent_id}{path}"
        
        # Check read-only
        for ro_path in self._readonly_paths:
            if path.startswith(ro_path):
                raise PermissionError(f"Path {path} is read-only")
        
        self.backend.set(full_path, data)
        return True
    
    def read(self, path: str) -> Any:
        """Read from VFS path."""
        full_path = f"/agent/{self.agent_id}{path}"
        return self.backend.get(full_path)
```

### MCP Resource Mapping

VFS paths are exposed as MCP resources:

```
VFS Path                          MCP Resource URI
/agent/foo/mem/working/data  →   vfs://foo/mem/working/data
/agent/foo/mem/episodic/*    →   vfs://foo/mem/episodic/*
```

---

## Stateless Architecture

### State Externalization

All state lives in pluggable backends:

```python
class StateBackend(Protocol):
    """Protocol for external state storage."""
    
    async def get(self, key: str) -> Optional[Dict[str, Any]]: ...
    async def set(self, key: str, value: Dict[str, Any], ttl: int = None): ...
    async def delete(self, key: str): ...

# Implementations
class MemoryBackend(StateBackend):
    """In-memory (for testing, single-instance)."""
    
class RedisBackend(StateBackend):
    """Redis (for production, distributed)."""
    
class DynamoDBBackend(StateBackend):
    """DynamoDB (for serverless)."""
```

### Context Passing

Every execution carries its own context:

```python
@dataclass
class ExecutionContext:
    """All state needed for a single execution."""
    agent_id: str
    policies: List[str] = field(default_factory=list)
    history: List[Dict] = field(default_factory=list)
    state_ref: Optional[str] = None  # External state key
    metadata: Dict[str, Any] = field(default_factory=dict)
```

### Horizontal Scaling

```
                    Load Balancer
                         │
        ┌────────────────┼────────────────┐
        │                │                │
        ▼                ▼                ▼
   ┌─────────┐     ┌─────────┐     ┌─────────┐
   │ Kernel  │     │ Kernel  │     │ Kernel  │
   │ Pod #1  │     │ Pod #2  │     │ Pod #3  │
   └────┬────┘     └────┬────┘     └────┬────┘
        │                │                │
        └────────────────┼────────────────┘
                         │
                    ┌────┴────┐
                    │  Redis  │  (shared state)
                    │ Cluster │
                    └─────────┘
```

Any kernel instance can handle any request because state is external.

---

## Integration Points

### MCP Integration

```python
# MCP tool calls go through kernel
@mcp_tool
async def kernel_execute(agent_id: str, action: str, params: dict, context: dict):
    kernel = StatelessKernel()
    result = await kernel.execute(
        action=action,
        params=params,
        context=ExecutionContext(**context)
    )
    return result.to_dict()
```

### AGENTS.md Integration

```python
# Parse AGENTS.md and convert to policies
parser = AgentsParser()
config = parser.parse_directory(".agents/")
policies = parser.to_kernel_policies(config)

# Use with kernel
kernel = StatelessKernel()
context = ExecutionContext(
    agent_id=config.name,
    policies=list(policies["rules"])
)
```

### Observability Integration

```python
# Kernel automatically emits metrics and traces
kernel = StatelessKernel(
    metrics=KernelMetrics(),
    tracer=KernelTracer("agent-os")
)

# Start metrics server
server = MetricsServer(port=9090, metrics=kernel.metrics)
server.start()

# Prometheus scrapes localhost:9090/metrics
# Grafana displays dashboards
```

---

## Appendix: Code Locations

| Component | Location |
|-----------|----------|
| Stateless Kernel | `src/agent_os/stateless.py` |
| Policy Engine | `src/agent_os/stateless.py` (in StatelessKernel) |
| Signal Dispatch | `packages/control-plane/src/agent_control_plane/signals.py` |
| VFS | `packages/control-plane/src/agent_control_plane/vfs.py` |
| MCP Server | `packages/mcp-kernel-server/src/mcp_kernel_server/server.py` |
| AGENTS.md Parser | `src/agent_os/agents_compat.py` |
| Metrics | `packages/observability/src/agent_os_observability/metrics.py` |
| Tracer | `packages/observability/src/agent_os_observability/tracer.py` |
| CLI | `src/agent_os/cli.py` |
