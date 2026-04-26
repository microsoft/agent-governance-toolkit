# Framework Integrations

Agent OS provides one-line integrations with popular AI agent frameworks.

## Philosophy

**Don't rewrite your code. Just wrap it.**

Every integration follows the same pattern:
1. Create a kernel with your policy
2. Wrap your existing agent
3. Continue using your agent as normal

All operations now go through Agent OS governance.

## Supported Frameworks

| Framework | Adapter | Status |
|-----------|---------|--------|
| LangChain | `LangChainKernel` | ✅ Stable |
| LlamaIndex | `LlamaIndexKernel` | ✅ Stable |
| CrewAI | `CrewAIKernel` | ✅ Stable |
| AutoGen | `AutoGenKernel` | ✅ Stable |
| OpenAI Assistants | `OpenAIKernel` | ✅ Stable |
| OpenAI Agents SDK | `OpenAIAgentsKernel` | ✅ Stable |
| Semantic Kernel | `SemanticKernelWrapper` | ✅ Stable |

---

## LangChain

```python
from langchain.chat_models import ChatOpenAI
from langchain.agents import create_openai_functions_agent
from agent_os.integrations import LangChainKernel, GovernancePolicy

# Create your LangChain agent
llm = ChatOpenAI(model="gpt-4")
agent = create_openai_functions_agent(llm, tools, prompt)

# Wrap with Agent OS
kernel = LangChainKernel(policy=GovernancePolicy(
    max_tool_calls=10,
    blocked_patterns=["password", "secret"]
))
governed_agent = kernel.wrap(agent)

# Use as normal - now governed!
result = governed_agent.invoke({"input": "Analyze this data"})
```

**Supported methods:**
- `invoke()` / `ainvoke()` - Single execution
- `run()` / `arun()` - Agent execution
- `batch()` / `abatch()` - Batch execution
- `stream()` / `astream()` - Streaming

---

## LlamaIndex

```python
from llama_index.core import VectorStoreIndex
from agent_os.integrations import LlamaIndexKernel, GovernancePolicy

# Create your LlamaIndex query engine
index = VectorStoreIndex.from_documents(documents)
query_engine = index.as_query_engine()

# Wrap with Agent OS
kernel = LlamaIndexKernel(policy=GovernancePolicy(
    max_tool_calls=20,
    blocked_patterns=["password", "secret"]
))
governed_engine = kernel.wrap(query_engine)

# Use as normal - now governed!
result = governed_engine.query("What are the key findings?")
```

**Supported methods:**
- `query()` / `aquery()` - Query execution
- `chat()` / `achat()` - Chat engine
- `stream_chat()` - Streaming chat
- `retrieve()` - Retriever

**Signal handling:**
```python
kernel.signal("llamaindex-engine-id", "SIGSTOP")   # Pause
kernel.signal("llamaindex-engine-id", "SIGCONT")   # Resume
kernel.signal("llamaindex-engine-id", "SIGKILL")   # Terminate
```

---

## OpenAI Assistants

```python
from openai import OpenAI
from agent_os.integrations import OpenAIKernel, GovernancePolicy

client = OpenAI()

# Create your assistant
assistant = client.beta.assistants.create(
    name="Trading Bot",
    instructions="You analyze market data",
    model="gpt-4-turbo",
    tools=[{"type": "code_interpreter"}]
)

# Wrap with Agent OS
kernel = OpenAIKernel(policy=GovernancePolicy(
    max_tokens=10000,
    allowed_tools=["code_interpreter"],  # Only allow code interpreter
    max_tool_calls=5
))
governed = kernel.wrap_assistant(assistant, client)

# Create thread and run - now governed!
thread = governed.create_thread()
governed.add_message(thread.id, "Analyze AAPL stock")
run = governed.run(thread.id)
```

**Features:**
- Token limit enforcement
- Tool call validation
- Real-time run monitoring
- SIGKILL support (cancel run)
- Full audit trail

**Signal handling:**
```python
# Cancel a run (SIGKILL)
governed.sigkill(thread.id, run.id)
```

---

## Microsoft Semantic Kernel

```python
from semantic_kernel import Kernel
from agent_os.integrations import SemanticKernelWrapper, GovernancePolicy

# Create your Semantic Kernel
sk = Kernel()
sk.add_plugin(MyPlugin(), "my_plugin")

# Wrap with Agent OS
wrapper = SemanticKernelWrapper(policy=GovernancePolicy(
    allowed_tools=["my_plugin.*"],  # Allow all functions in plugin
    blocked_patterns=["password"]
))
governed = wrapper.wrap(sk)

# Use as normal - now governed!
result = await governed.invoke("my_plugin", "analyze", input="data")
```

**Supported operations:**
- `invoke()` - Function invocation
- `add_plugin()` - Plugin management
- `memory_save()` / `memory_search()` - Memory operations
- `invoke_prompt()` - Direct chat completion
- `create_plan()` - Planner with step validation

**Signal handling:**
```python
# Pause execution
governed.sigstop()

# Resume execution
governed.sigcont()

# Terminate
governed.sigkill()
```

---

## CrewAI

```python
from crewai import Crew, Agent, Task
from agent_os.integrations import CrewAIKernel, GovernancePolicy

# Create your crew
agent = Agent(role="Analyst", goal="Analyze data")
task = Task(description="Analyze market trends", agent=agent)
crew = Crew(agents=[agent], tasks=[task])

# Wrap with Agent OS
kernel = CrewAIKernel(policy=GovernancePolicy(
    timeout_seconds=600,
    max_tool_calls=50
))
governed_crew = kernel.wrap(crew)

# Kickoff - now governed!
result = governed_crew.kickoff()
```

---

## AutoGen

```python
from autogen import AssistantAgent, UserProxyAgent
from agent_os.integrations import AutoGenKernel, GovernancePolicy

# Create your agents
assistant = AssistantAgent("assistant", llm_config={"model": "gpt-4"})
user_proxy = UserProxyAgent("user_proxy", human_input_mode="NEVER")

# Wrap with Agent OS
kernel = AutoGenKernel(policy=GovernancePolicy(
    max_tokens=50000,
    confidence_threshold=0.9
))
kernel.govern(assistant, user_proxy)

# Chat - now governed!
user_proxy.initiate_chat(assistant, message="Solve this problem")
```

**Signal handling:**
```python
kernel.signal("assistant", "SIGSTOP")   # Pause agent
kernel.signal("assistant", "SIGCONT")   # Resume agent
kernel.signal("assistant", "SIGKILL")   # Unwrap agent

# Restore original ungoverned agent
kernel.unwrap(assistant)
```

---

## OpenAI Agents SDK

```python
from agents import Agent, Runner
from agent_os.integrations.openai_agents_sdk import OpenAIAgentsKernel

# Create your OpenAI Agent
agent = Agent(name="analyst", instructions="You analyze data")

# Wrap with Agent OS governance
kernel = OpenAIAgentsKernel(policy={
    "blocked_patterns": ["password", "secret"],
    "allowed_tools": ["file_search", "code_interpreter"],
    "max_tool_calls": 10,
})

# Add tool guards
@kernel.tool_guard
async def safe_query(sql: str):
    return db.execute(sql)

# Use GovernedRunner for automatic governance
governed = kernel.wrap_runner(Runner)
result = await governed.run(agent, "Analyze Q4 revenue")

# Access audit log
for entry in kernel.get_audit_log():
    print(f"{entry['event']}: {entry['timestamp']}")
```

---

## Governance Policy

All integrations use the same `GovernancePolicy` class:

```python
from agent_os.integrations import GovernancePolicy

policy = GovernancePolicy(
    # Limits
    max_tokens=10000,           # Token limit
    max_tool_calls=20,          # Tool call limit
    timeout_seconds=300,        # Timeout
    
    # Permissions
    allowed_tools=["safe_tool"],  # Whitelist tools
    blocked_patterns=["secret"],   # Block content
    require_human_approval=False,  # Human-in-loop
    
    # Thresholds
    confidence_threshold=0.8,   # Min confidence
    drift_threshold=0.15,       # CMVK drift
    
    # Audit
    log_all_calls=True,         # Full logging
    checkpoint_frequency=5      # Checkpoint every N calls
)
```

---

## Common Patterns

### Policy Presets

```python
# Strict policy (production)
strict = GovernancePolicy(
    max_tokens=5000,
    max_tool_calls=5,
    blocked_patterns=["password", "secret", "api_key", "token"],
    confidence_threshold=0.95
)

# Permissive policy (development)
permissive = GovernancePolicy(
    max_tokens=100000,
    max_tool_calls=100,
    confidence_threshold=0.5
)
```

### Error Handling

```python
from agent_os.integrations.langchain_adapter import PolicyViolationError

try:
    result = governed_agent.invoke(input_data)
except PolicyViolationError as e:
    print(f"Policy blocked: {e}")
    # Handle violation (log, alert, fallback)
```

### Audit Access

```python
# Get execution context
ctx = governed.get_context()
print(f"Tool calls: {ctx.call_count}")
print(f"Checkpoints: {ctx.checkpoints}")

# For OpenAI Assistants
usage = governed.get_token_usage()
print(f"Tokens used: {usage['total_tokens']}")

# For Semantic Kernel
audit = governed.get_audit_log()
print(f"Functions invoked: {audit['functions_invoked']}")
```

---

## What Gets Governed

| Operation | Pre-Check | Post-Check | Signals |
|-----------|-----------|------------|---------|
| LLM call | ✅ | ✅ | ✅ |
| Tool use | ✅ | ✅ | ✅ |
| Memory access | ✅ | - | ✅ |
| File operations | ✅ | - | ✅ |
| Network calls | ✅ | ✅ | ✅ |

Pre-Check:
- Blocked patterns in input
- Tool allowlist
- Call count limit
- Timeout check

Post-Check:
- Output validation
- Checkpoint creation
- Audit logging

Signals:
- SIGSTOP - Pause execution
- SIGCONT - Resume execution
- SIGKILL - Terminate immediately
