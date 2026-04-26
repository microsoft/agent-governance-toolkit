# Agent OS Quickstart

> **60 seconds to your first governed agent.**

## Prerequisites

- Python 3.9+
- pip

## Installation

```bash
pip install agent-os-kernel
```

Or install all Agent-OS packages:

```bash
pip install agent-os-kernel[full]
```

## Your First Governed Agent

### Step 1: Basic Setup

```python
# governed_agent.py
from agent_control_plane.kernel_space import KernelSpace, SyscallRequest, SyscallType
from agent_control_plane.policy_engine import PolicyEngine
from agent_control_plane.flight_recorder import FlightRecorder
import asyncio

# 1. Create policy engine with allow-list
policy = PolicyEngine()
policy.add_constraint("my-agent", [
    "echo",           # Our custom tool
    "file_read",      # For reading files
])

# 2. Create flight recorder for audit logging
recorder = FlightRecorder("audit.db")

# 3. Initialize kernel with governance
kernel = KernelSpace(
    policy_engine=policy,
    flight_recorder=recorder,
)

# 4. Register your tools
def echo_tool(message: str) -> str:
    """A simple echo tool."""
    return f"Echo: {message}"

kernel.register_tool("echo", echo_tool)

# 5. Create agent context
ctx = kernel.create_agent_context("my-agent")

# 6. Execute tools through the kernel
async def main():
    # This will be ALLOWED (echo is in the allow-list)
    request = SyscallRequest(
        syscall=SyscallType.SYS_EXEC,
        args={"tool": "echo", "args": {"message": "Hello, World!"}},
    )
    result = await kernel.syscall(request, ctx)
    print(f"Result: {result.return_value}")
    
asyncio.run(main())
```

Run it:

```bash
python governed_agent.py
# Output: Result: Echo: Hello, World!
```

### What Just Happened?

1. **PolicyEngine** defines which tools each agent can use (allow-list)
2. **FlightRecorder** logs every action with tamper-proof audit trail
3. **KernelSpace** enforces policies and executes tools
4. All tool execution goes through `SYS_EXEC` syscalls

```
┌─────────────────────────────────────────────────────────┐
│              USER SPACE (Your Agent)                    │
│   Agent makes syscalls. Can crash, hallucinate, etc.   │
├─────────────────────────────────────────────────────────┤
│              KERNEL SPACE (Agent OS)                    │
│   Policy Engine checks every action before execution    │
│   If policy violated → SIGKILL (non-catchable)         │
│   Flight Recorder logs everything for audit            │
└─────────────────────────────────────────────────────────┘
```

---

## Try a Blocked Action

```python
# This will be BLOCKED (file_write is not in the allow-list)
async def try_blocked():
    kernel.register_tool("file_write", lambda path, data: open(path, "w").write(data))
    
    request = SyscallRequest(
        syscall=SyscallType.SYS_EXEC,
        args={"tool": "file_write", "args": {"path": "/tmp/test.txt", "data": "danger"}},
    )
    
    try:
        result = await kernel.syscall(request, ctx)
    except Exception as e:
        print(f"Blocked: {e}")

asyncio.run(try_blocked())
# Output: Blocked: Agent terminated: Policy violation...
```

---

## Using the Higher-Level AgentKernel

For simpler use cases, use `AgentKernel` with tool interception:

```python
from agent_control_plane.agent_kernel import AgentKernel
from agent_control_plane.policy_engine import PolicyEngine
from agent_control_plane.flight_recorder import FlightRecorder

# Setup
policy = PolicyEngine()
policy.add_constraint("my-agent", ["search", "calculate"])

recorder = FlightRecorder("audit.db")

kernel = AgentKernel(
    policy_engine=policy,
    audit_logger=recorder,
)

# Intercept tool calls before execution
def my_tool_executor(tool_name: str, args: dict):
    """Your actual tool execution logic."""
    if tool_name == "search":
        return f"Search results for: {args.get('query')}"
    return "Unknown tool"

# Before calling any tool, check with kernel
result = kernel.intercept_tool_execution(
    agent_id="my-agent",
    tool_name="search",
    tool_args={"query": "Agent OS documentation"},
)

if result is None:
    # ALLOWED - proceed with execution
    output = my_tool_executor("search", {"query": "Agent OS documentation"})
    print(output)
elif result.get("status") == "blocked":
    # BLOCKED - policy violation
    print(f"Blocked: {result.get('error')}")
```

---

## Adding Conditional Permissions (ABAC)

For fine-grained access control based on context:

```python
from agent_control_plane.policy_engine import PolicyEngine, Condition, ConditionalPermission

policy = PolicyEngine()

# Basic allow-list
policy.add_constraint("support-agent", ["refund", "lookup_order"])

# Add conditional permission: refunds only for verified users, max $500
policy.add_conditional_permission("support-agent", ConditionalPermission(
    tool_name="refund",
    conditions=[
        Condition(attribute_path="context.user_verified", operator="eq", value=True),
        Condition(attribute_path="args.amount", operator="lte", value=500),
    ],
    require_all=True,  # Both conditions must pass
))

# Set context for this agent
policy.set_agent_context("support-agent", {
    "user_verified": True,
    "department": "customer-service",
})

# Check if action is allowed
violation = policy.check_violation(
    agent_role="support-agent",
    tool_name="refund",
    args={"amount": 100, "order_id": "12345"},
)

if violation:
    print(f"Denied: {violation}")
else:
    print("Allowed!")
```

---

## CLI Commands

| Command | Description |
|---------|-------------|
| `agentos init <name>` | Initialize new agent project |
| `agentos run` | Run agent with kernel governance |
| `agentos audit [--json]` | Query flight recorder audit logs |
| `agentos status [--json]` | Show kernel metrics |

> **Tip**: All monitoring and audit commands now support the `--json` flag for easy integration with CI/CD pipelines.

---

## Next Steps

| Guide | Description |
|-------|-------------|
| [Policy Schema](policy-schema.md) | Complete policy definition reference |
| [Kernel Internals](kernel-internals.md) | Deep dive into syscalls and signals |
| [Security Spec](security-spec.md) | YAML policy format for `.agents/security.md` |
| [Architecture](architecture.md) | Full system overview |

---

## Common Issues

### "Module not found: agent_control_plane"

```bash
pip install agent-os-kernel
```

### "Policy violation but I expected it to pass"

Check your allow-list:

```python
# Ensure the tool is in the allow-list
policy.add_constraint("my-agent", ["the_tool_name"])
```

### "Agent runs but nothing happens"

Ensure you're executing through the kernel:

```python
# ✗ Wrong - bypasses governance
result = my_tool()

# ✓ Correct - goes through kernel
result = await kernel.syscall(
    SyscallRequest(syscall=SyscallType.SYS_EXEC, args={"tool": "my_tool", "args": {}}),
    ctx
)
```

---

## Get Help

- [GitHub Issues](https://github.com/microsoft/agent-governance-toolkit/issues)
- [Documentation](https://github.com/microsoft/agent-governance-toolkit/tree/main/docs)
- [Policy Schema Reference](policy-schema.md)
