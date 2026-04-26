# Migration Guide: From Prompt-Based Safety to Kernel-Based Enforcement

This guide helps you migrate from prompt-based AI safety to Agent OS kernel-based enforcement.

## Why Migrate?

| Prompt-Based Safety | Kernel-Based Enforcement |
|---------------------|-------------------------|
| LLM decides whether to comply | Kernel enforces before execution |
| Can be bypassed with jailbreaks | Cannot be bypassed (deterministic) |
| Non-deterministic results | 100% consistent enforcement |
| Difficult to audit | Complete audit trail |
| Hope-based security | Guarantee-based security |

## Migration Steps

### Step 1: Identify Your Current Safety Controls

List all prompt-based safety instructions you're currently using:

```python
# BEFORE: Prompt-based safety
system_prompt = """
You are a helpful assistant. 
IMPORTANT: 
- Never reveal API keys or passwords
- Do not access files outside /workspace
- Do not run destructive SQL commands like DROP or DELETE
- Always ask for confirmation before making changes
"""
```

### Step 2: Map Prompts to Policies

Convert each prompt instruction to an Agent OS policy:

| Prompt Instruction | Agent OS Policy |
|-------------------|-----------------|
| "Never reveal API keys" | `Policy.no_secrets()` |
| "Do not access files outside /workspace" | `Policy.file_access("/workspace")` |
| "No destructive SQL" | `Policy.no_destructive_sql()` |
| "Ask for confirmation" | `Policy.require_approval()` |

### Step 3: Install Agent OS

```bash
pip install agent-control-plane
```

### Step 4: Create Your Policy Configuration

```python
# AFTER: Kernel-based enforcement
from agent_control_plane import ControlPlane, PolicyEngine

# Create control plane with policies
plane = ControlPlane()

# Add policies (equivalent to your prompt instructions)
plane.policy_engine.add_constraint("agent", [
    "read_file",
    "write_file", 
    "query_database",
])

# Configure file access restriction
plane.policy_engine.protected_paths = [
    "/etc/",
    "/sys/",
    "C:\\Windows\\",
]

# Configure SQL protection
# (Built-in: blocks DROP, DELETE without WHERE, TRUNCATE)
```

### Step 5: Wrap Your Agent

**Before (LangChain example):**
```python
from langchain.agents import AgentExecutor

agent = AgentExecutor(
    agent=my_agent,
    tools=tools,
)

# Run with prompt-based safety only
result = agent.invoke({"input": user_query})
```

**After (with Agent OS):**
```python
from langchain.agents import AgentExecutor
from agent_control_plane.langchain_adapter import GovernedAgentExecutor

# Wrap with Agent OS governance
governed_agent = GovernedAgentExecutor(
    agent=my_agent,
    tools=tools,
    control_plane=plane,
)

# Run with kernel-based enforcement
result = governed_agent.invoke({"input": user_query})
# All tool calls pass through policy engine BEFORE execution
```

### Step 6: Test Your Migration

Run your existing test cases and verify:

1. **Safe actions still work:**
```python
# Should succeed
result = governed_agent.invoke({"input": "Read the config file"})
assert result["success"]
```

2. **Dangerous actions are blocked:**
```python
# Should be blocked by policy, not by hoping the LLM refuses
result = governed_agent.invoke({"input": "Delete all user data"})
assert not result["success"]
assert "Policy" in result.get("error", "")
```

3. **Check audit logs:**
```python
# All actions are logged
logs = plane.flight_recorder.get_recent_entries(100)
for log in logs:
    print(f"{log['action']}: {log['verdict']}")
```

### Step 7: Remove Prompt-Based Safety

Once kernel-based enforcement is verified, you can simplify your prompts:

```python
# BEFORE: Long safety-focused prompt
system_prompt = """
You are a helpful assistant. 
IMPORTANT: 
- Never reveal API keys or passwords
- Do not access files outside /workspace
- Do not run destructive SQL commands
- Always ask for confirmation
- Never execute code that could harm the system
- Do not access sensitive user data without permission
...
"""

# AFTER: Focus on task, not safety
system_prompt = """
You are a helpful assistant for data analysis tasks.
"""
# Safety is enforced by the kernel, not by prompts
```

## Framework-Specific Guides

### LangChain

```python
from agent_control_plane.langchain_adapter import GovernedAgentExecutor

governed = GovernedAgentExecutor(
    agent=agent,
    tools=tools,
    control_plane=plane,
    shadow_mode=False,  # Set True for testing without blocking
)
```

### CrewAI

```python
from agent_control_plane.crewai_adapter import GovernedCrew

crew = GovernedCrew(
    agents=[agent1, agent2],
    tasks=[task1, task2],
    control_plane=plane,
)
```

### OpenAI Assistants

```python
from agent_control_plane.openai_adapter import GovernedAssistant

assistant = GovernedAssistant(
    assistant_id="asst_xxx",
    control_plane=plane,
)
```

### Raw Tool Calls

```python
# Direct kernel integration
@plane.kernel.register
def my_tool(query: str) -> str:
    # This function is governed by the kernel
    return execute_query(query)

# Calls are validated before execution
result = plane.kernel.execute(my_tool, "SELECT * FROM users")
```

## Shadow Mode: Safe Migration

Test your policies without blocking actions:

```python
# Enable shadow mode
plane.shadow_mode = True

# Run your agent - actions execute but violations are logged
result = governed_agent.invoke({"input": "user request"})

# Review what WOULD have been blocked
violations = plane.get_shadow_violations()
for v in violations:
    print(f"Would block: {v['action']} - {v['reason']}")

# Tune policies until satisfied, then disable shadow mode
plane.shadow_mode = False
```

## Keeping Prompts for UX

You can keep prompts for **user experience** while relying on kernel for **security**:

```python
# Prompts for UX (optional, not for security)
system_prompt = """
You are a helpful assistant. When you can't perform an action,
explain why in a friendly way.
"""

# Kernel for actual enforcement (required)
plane = ControlPlane(policies=[...])
```

## Rollback Plan

If issues arise, you can temporarily disable enforcement:

```python
# Emergency: disable enforcement (NOT RECOMMENDED for production)
plane.enforcement_enabled = False

# Better: Use shadow mode to log without blocking
plane.shadow_mode = True
```

## Verification Checklist

- [ ] All prompt safety instructions converted to policies
- [ ] Agent wrapped with appropriate adapter
- [ ] Safe actions verified to work
- [ ] Dangerous actions verified to be blocked
- [ ] Audit logs capturing all actions
- [ ] Shadow mode testing completed
- [ ] Prompts simplified (safety removed)
- [ ] Team trained on new architecture

## Common Issues

### "My agent is being blocked unexpectedly"

Check the audit log for the exact policy that blocked:
```python
logs = plane.flight_recorder.get_recent_entries(10)
for log in logs:
    if log["verdict"] == "blocked":
        print(f"Blocked by: {log['policy']} - {log['reason']}")
```

### "How do I allow a specific action?"

Add it to the constraint graph:
```python
plane.policy_engine.add_constraint("agent_role", [
    "existing_tool",
    "new_tool_to_allow",  # Add here
])
```

### "Can I have different policies for different users?"

Yes, use ABAC (Attribute-Based Access Control):
```python
plane.policy_engine.set_agent_context("agent_id", {
    "user_role": "admin",
    "department": "finance",
})
```

## Next Steps

1. Read [Architecture Overview](architecture.md)
2. Explore [Policy Templates](../templates/policies/)
3. Review [Security Specification](security-spec.md)
