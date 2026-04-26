# Running GitHub Copilot Under Agent-OS Governance

This guide shows how to run AI coding assistants (like GitHub Copilot) under Agent-OS governance, allowing file operations without prompts while maintaining a complete audit trail.

## Quick Start

```python
import asyncio
from agent_control_plane.kernel_space import KernelSpace, SyscallRequest, SyscallType
from agent_control_plane.policy_engine import PolicyEngine
from agent_control_plane.flight_recorder import FlightRecorder

# 1. Create policy - allow all file operations for copilot
policy = PolicyEngine()
policy.add_constraint("github-copilot", [
    "file_read", "file_write", "file_delete", "file_list"
])

# 2. Create audit logger
recorder = FlightRecorder("copilot_audit.db")

# 3. Create governed kernel
kernel = KernelSpace(
    policy_engine=policy,
    flight_recorder=recorder,
)

# 4. Register REAL file operations (not mocks!)
kernel.register_tool("file_read", lambda path: open(path).read())
kernel.register_tool("file_write", lambda path, content: open(path, 'w').write(content))

# 5. Create agent context
ctx = kernel.create_agent_context("github-copilot")

# 6. Execute governed operations
async def main():
    request = SyscallRequest(
        syscall=SyscallType.SYS_EXEC,
        args={"tool": "file_read", "args": {"path": "README.md"}},
    )
    result = await kernel.syscall(request, ctx)
    print(result.return_value)

asyncio.run(main())
```

## What Happens Under the Hood

```
┌─────────────────────────────────────────────────────────────┐
│                    COPILOT (User Space)                      │
│   Requests: file_read, file_write, etc.                      │
│   Cannot bypass kernel - all operations go through syscalls  │
├─────────────────────────────────────────────────────────────┤
│                    KERNEL SPACE                              │
│                                                              │
│   1. PolicyEngine checks allow-list                          │
│      ├─ github-copilot → [file_read, file_write, ...]       │
│      └─ If not in list → SIGKILL (agent terminated)         │
│                                                              │
│   2. FlightRecorder logs the action                         │
│      ├─ Hash-chained for tamper detection                 │
│      └─ SQLite WAL mode for performance                     │
│                                                              │
│   3. Tool Registry executes the real operation              │
│      └─ YOUR code runs (actual file I/O)                    │
│                                                              │
│   4. Result returned to agent                               │
└─────────────────────────────────────────────────────────────┘
```

## Policy Configuration

### Allow All File Operations (Permissive)

```python
policy = PolicyEngine()
policy.add_constraint("github-copilot", [
    "file_read",
    "file_write",
    "file_delete",
    "file_list",
    "file_mkdir",
    "file_exists",
])
```

### Read-Only Mode

```python
policy = PolicyEngine()
policy.add_constraint("github-copilot", [
    "file_read",
    "file_list",
    "file_exists",
])
# file_write and file_delete are NOT in the list → blocked
```

### Workspace-Restricted

```python
from agent_control_plane.policy_engine import Condition, ConditionalPermission

policy = PolicyEngine()

# Basic allow-list
policy.add_constraint("github-copilot", ["file_read", "file_write"])

# Add condition: only allow writes in /workspace/
policy.add_conditional_permission("github-copilot", ConditionalPermission(
    tool_name="file_write",
    conditions=[
        Condition(
            attribute_path="args.path",
            operator="starts_with",
            value="/workspace/"
        ),
    ]
))
```

## Registering Real Executors

**IMPORTANT**: The default Agent-OS executors are mocks for testing. For real use, register your own:

```python
import os
from pathlib import Path

# Real file operations
def real_file_read(path: str) -> str:
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()

def real_file_write(path: str, content: str) -> int:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        return f.write(content)

def real_file_delete(path: str) -> bool:
    if os.path.exists(path):
        os.remove(path)
        return True
    return False

def real_file_list(path: str) -> list:
    return os.listdir(path) if os.path.isdir(path) else []

# Register them
kernel.register_tool("file_read", real_file_read)
kernel.register_tool("file_write", real_file_write)
kernel.register_tool("file_delete", real_file_delete)
kernel.register_tool("file_list", real_file_list)
```

## Audit Trail

Every operation is logged with:

- **Timestamp** - When it happened
- **Agent ID** - Which agent did it
- **Tool Name** - What operation
- **Arguments** - Full details
- **Policy Verdict** - allowed/blocked
- **Entry Hash** - hash chain for tamper detection

### Query the Audit Log

```python
# Get recent operations
logs = recorder.query_logs(agent_id="github-copilot", limit=100)

for log in logs:
    print(f"{log['timestamp']} | {log['tool_name']} | {log['policy_verdict']}")

# Verify integrity (detect tampering)
integrity = recorder.verify_integrity()
assert integrity["valid"], "Audit log has been tampered with!"
```

### Export for Compliance

```python
# Get all logs
all_logs = recorder.get_log()

# Export to JSON
import json
with open("audit_export.json", "w") as f:
    json.dump(all_logs, f, indent=2)
```

## Error Handling

When a policy violation occurs, the agent is terminated with `AgentKernelPanic`:

```python
from agent_control_plane.signals import AgentKernelPanic

try:
    result = await kernel.syscall(request, ctx)
except AgentKernelPanic as e:
    print(f"Agent terminated: {e}")
    # Log the violation, alert admins, etc.
```

## Running the Demo

```bash
cd agent-os
python examples/copilot_governed.py
```

Expected output:

```
============================================================
GitHub Copilot under Agent-OS Governance - LIVE DEMO
============================================================

✓ Governance initialized for workspace: /tmp/copilot_governed_xxx
✓ Audit log: /tmp/copilot_governed_xxx/audit.db
✓ Registered tools: ['file_read', 'file_write', 'file_delete', ...]

--- Starting Copilot Session ---

1. Writing hello.py...
   ✓ Wrote 234 bytes

2. Reading hello.py...
   ✓ Read 234 characters

--- Audit Log (FlightRecorder) ---

   ✓ [allowed] file_write
   ✓ [allowed] file_read

--- Integrity Check (Hash Chain) ---

   ✓ Audit log integrity verified (8 entries)

--- Kernel Metrics ---

   Syscalls: 4
   Policy checks: 8
   Policy violations: 0

============================================================
Demo complete! All operations were governed and logged.
============================================================
```

## Testing Policy Enforcement

```bash
python examples/test_policy_enforcement.py
```

This verifies:
1. Unauthorized operations are blocked with `AgentKernelPanic`
2. Authorized operations execute successfully
3. Policies are **actually enforced**, not just logged

## Key Takeaways

1. **Policy Enforcement is REAL** - Unauthorized operations throw exceptions
2. **Audit Logging is REAL** - SQLite with hash chains
3. **You Must Register Real Executors** - Default ones are mocks
4. **All Operations Go Through Kernel** - No bypass possible

## See Also

- [Policy Schema Reference](../docs/policy-schema.md)
- [Kernel Internals](../docs/kernel-internals.md)
- [Security Specification](../docs/security-spec.md)
