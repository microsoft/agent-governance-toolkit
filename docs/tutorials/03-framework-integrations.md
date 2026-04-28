# Tutorial 03 — Wrapping AI Frameworks with Governance

> **Package:** `agent-os-kernel` · **Time:** 25 minutes · **Prerequisites:** Python 3.10+

---

## What You'll Learn

- Govern LangChain agents with policy-aware wrappers
- Govern CrewAI multi-agent workflows
- Govern AutoGen conversational agents
- Govern OpenAI Agents and Google ADK pipelines

---

Every adapter in Agent OS follows the same pattern: **create a policy, create a
kernel, wrap the framework object, use the governed object as normal**.The
kernel sits between your code and the LLM framework—intercepting calls,
enforcing limits, blocking disallowed tools, and logging everything.

```
┌─────────────┐     ┌──────────────┐     ┌───────────────┐
│  Your Code   │ ──► │  Kernel      │ ──► │  Framework    │
│              │ ◄── │  (governance │ ◄── │  (OpenAI,     │
│              │     │   layer)     │     │   LangChain…) │
└─────────────┘     └──────────────┘     └───────────────┘
                     pre_execute()
                     tool interception
                     post_execute()
                     drift detection
                     audit log
```

All adapters live in `agent-governance-python/agent-os/src/agent_os/integrations/` and inherit
from `BaseIntegration` (defined in `base.py`).  Every kernel exposes:

| Hook | When it fires | What it does |
|---|---|---|
| `pre_execute()` | Before the LLM call | Enforces token limits, timeout, blocked patterns |
| Tool interception | On each tool/function call | Validates against `allowed_tools` / `blocked_patterns` |
| `post_execute()` | After the LLM response | Drift detection, output scanning, audit entry |

Violations raise `PolicyViolationError`.

---

## Prerequisites

```bash
pip install agent-os-kernel
```

Then install the framework package you need:

```bash
pip install openai              # for OpenAIKernel
pip install langchain-core      # for LangChainKernel
pip install crewai              # for CrewAIKernel
pip install anthropic           # for AnthropicKernel
pip install google-generativeai # for GeminiKernel
pip install pyautogen           # for AutoGenKernel
```

---

## 1. Quick Start — OpenAI in 5 Lines

```python
from openai import OpenAI
from agent_os.integrations import OpenAIKernel, GovernancePolicy

client = OpenAI()
assistant = client.beta.assistants.create(
    name="analyst",
    model="gpt-4o",
    tools=[{"type": "code_interpreter"}],
)

# 1. Define policy
policy = GovernancePolicy(
    max_tokens=4096,
    max_tool_calls=5,
    allowed_tools=["code_interpreter"],
    blocked_patterns=["rm -rf", "DROP TABLE"],
    log_all_calls=True,
)

# 2. Create kernel
kernel = OpenAIKernel(policy=policy)

# 3. Wrap — returns a GovernedAssistant
governed = kernel.wrap(assistant, client)

# 4. Use exactly like before
thread = client.beta.threads.create()
client.beta.threads.messages.create(thread.id, role="user", content="Summarize Q3 revenue")
run = governed.run(thread.id)
```

The `GovernedAssistant` proxies every run through the governance layer.
If the assistant tries to exceed `max_tool_calls` or matches a blocked pattern,
the kernel raises `PolicyViolationError` and logs the violation.

### Inspecting execution state

```python
ctx = governed.get_context()
print(ctx.call_count)       # number of LLM round-trips
print(ctx.total_tokens)     # cumulative token usage
print(ctx.tool_calls)       # list of intercepted tool calls
```

---

## 2. LangChain Integration

`LangChainKernel` wraps chains, agents, and runnables.  It intercepts
`invoke()`, `ainvoke()`, `stream()`, `batch()`, and provides deep hooks into
the tool registry, memory writes, and sub-agent delegation.

```python
from langchain_openai import ChatOpenAI
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from agent_os.integrations import LangChainKernel, GovernancePolicy

llm = ChatOpenAI(model="gpt-4o")
chain = ChatPromptTemplate.from_template("Explain {topic}") | llm | StrOutputParser()

policy = GovernancePolicy(
    max_tokens=2048,
    timeout_seconds=30,
    blocked_patterns=[
        ("\\b\\d{3}-\\d{2}-\\d{4}\\b", "regex"),   # block SSN patterns
        ("password", "substring"),
    ],
    log_all_calls=True,
)

kernel = LangChainKernel(policy=policy)
governed_chain = kernel.wrap(chain)

# invoke() is now governed
result = governed_chain.invoke({"topic": "zero-trust architecture"})
```

### Deep hooks

LangChain's kernel intercepts more than just top-level calls:

| Hook | What it catches |
|---|---|
| Tool registry | Every tool invocation is validated against `allowed_tools` |
| Memory writes | Detects and logs writes to conversation memory |
| Sub-agent spawning | Tracks when an agent delegates to another agent |
| PII detection | Built-in patterns catch SSNs, emails, secrets in output |

### Async and streaming

```python
# Async — same governance, async execution
result = await governed_chain.ainvoke({"topic": "mTLS"})

# Streaming — each chunk passes through post_execute
async for chunk in governed_chain.astream({"topic": "RBAC"}):
    print(chunk, end="", flush=True)
```

### Wrapping an agent with tools

```python
from langchain_core.tools import tool

@tool
def query_database(sql: str) -> str:
    """Run a read-only SQL query."""
    # ...

policy = GovernancePolicy(
    allowed_tools=["query_database"],
    blocked_patterns=[
        ("DROP", "substring"),
        ("DELETE", "substring"),
        ("INSERT", "substring"),
    ],
    max_tool_calls=10,
)

kernel = LangChainKernel(policy=policy)
governed_agent = kernel.wrap(agent_executor)
governed_agent.invoke({"input": "How many users signed up last week?"})
```

---

## 3. CrewAI Integration

`CrewAIKernel` wraps an entire crew, governing both `kickoff()` and
`kickoff_async()`.  It also intercepts individual agent execution and tool
calls within the crew.

```python
from crewai import Agent, Task, Crew
from agent_os.integrations import CrewAIKernel, GovernancePolicy

researcher = Agent(
    role="Researcher",
    goal="Find accurate information",
    tools=[search_tool, scrape_tool],
)
writer = Agent(role="Writer", goal="Write clear reports")

task = Task(
    description="Research and summarize recent AI governance frameworks",
    agent=researcher,
    expected_output="A 500-word summary",
)

crew = Crew(agents=[researcher, writer], tasks=[task])

policy = GovernancePolicy(
    allowed_tools=["search_tool", "scrape_tool"],
    max_tool_calls=20,
    timeout_seconds=600,
    drift_threshold=0.15,
    log_all_calls=True,
)

kernel = CrewAIKernel(policy=policy)
governed_crew = kernel.wrap(crew)

# kickoff() is now governed
result = governed_crew.kickoff()
```

### What the kernel intercepts

- **kickoff() / kickoff_async()** — pre/post execution checks on the entire run
- **Individual agent steps** — each agent's step is validated
- **Tool calls** — every tool invocation checked against `allowed_tools`
- **Memory writes** — crew memory interactions are logged
- **Delegation** — when one agent delegates to another, the chain is tracked

### Async crews

```python
result = await governed_crew.kickoff_async()
```

---

## 4. Anthropic and Gemini

### Anthropic — wrapping the client

`AnthropicKernel` wraps the Anthropic client and intercepts every
`messages.create()` call.

```python
from anthropic import Anthropic
from agent_os.integrations import AnthropicKernel, GovernancePolicy

client = Anthropic()

policy = GovernancePolicy(
    max_tokens=4096,
    blocked_patterns=["IGNORE PREVIOUS INSTRUCTIONS"],
    allowed_tools=["get_weather"],
    log_all_calls=True,
)

kernel = AnthropicKernel(policy=policy, max_retries=3, timeout_seconds=120.0)
governed_client = kernel.wrap(client)  # returns GovernedAnthropicClient

# messages.create() is now governed
response = governed_client.messages.create(
    model="claude-sonnet-4-20250514",
    max_tokens=1024,
    messages=[{"role": "user", "content": "Explain governance patterns"}],
)
```

Under the hood, `governed_client.messages` is a `_GovernedMessages` proxy that:
1. Runs `pre_execute()` — validates message content and tools
2. Calls the real `messages.create()`
3. Runs `post_execute()` — checks tool_use blocks, tracks tokens
4. Logs the full request/response to the audit trail

```python
# Token tracking
usage = governed_client.get_token_usage()
print(usage)  # {"input_tokens": 42, "output_tokens": 128, ...}

# Cancel a long-running request
governed_client.sigkill(request_id="req_abc123")
```

There is also a convenience function:

```python
from agent_os.integrations.anthropic_adapter import wrap_client

governed = wrap_client(client, policy=policy)
```

### Gemini — wrapping a GenerativeModel

`GeminiKernel` wraps Google's `GenerativeModel` and intercepts
`generate_content()`.

```python
import google.generativeai as genai
from agent_os.integrations import GeminiKernel, GovernancePolicy

genai.configure(api_key="...")
model = genai.GenerativeModel("gemini-1.5-pro")

policy = GovernancePolicy(
    max_tokens=8192,
    blocked_patterns=["execute_code"],
    log_all_calls=True,
)

kernel = GeminiKernel(policy=policy)
governed_model = kernel.wrap(model)  # returns GovernedGeminiModel

response = governed_model.generate_content("Explain AI safety principles")
```

The kernel intercepts function calls in Gemini responses and validates them
against `allowed_tools` and `blocked_patterns`.  Token usage is extracted from
the response's `usage_metadata`.

```python
from agent_os.integrations.gemini_adapter import wrap_model

governed = wrap_model(model, policy=policy)
```

---

## 5. AutoGen — Multi-Agent Governance

AutoGen is different: you have multiple agents chatting with each other.
`AutoGenKernel` uses `govern()` to patch multiple agents at once via
monkey-patching.

```python
from autogen import AssistantAgent, UserProxyAgent
from agent_os.integrations import AutoGenKernel, GovernancePolicy

assistant = AssistantAgent("assistant", llm_config={"model": "gpt-4o"})
user_proxy = UserProxyAgent("user_proxy", code_execution_config={"use_docker": True})

policy = GovernancePolicy(
    blocked_patterns=[
        ("password", "substring"),
        ("\\b\\d{3}-\\d{2}-\\d{4}\\b", "regex"),  # SSN
    ],
    max_tool_calls=10,
    timeout_seconds=300,
    log_all_calls=True,
)

kernel = AutoGenKernel(
    policy=policy,
    deep_hooks_enabled=True,
    on_error=lambda exc, agent_id: print(f"[{agent_id}] Error: {exc}"),
)

# govern() patches agents in-place and returns them
kernel.govern(assistant, user_proxy)

# Initiate chat — all messages pass through governance
user_proxy.initiate_chat(assistant, message="Analyze this dataset")
```

### What govern() patches

| Method | Behavior on violation |
|---|---|
| `initiate_chat()` | Raises `PolicyViolationError` |
| `generate_reply()` | Returns `[BLOCKED: reason]` string (keeps conversation flowing) |
| `receive()` | Guards inbound messages |
| Function call pipeline | Validates each function call (when `deep_hooks_enabled=True`) |
| GroupChat routing | Intercepts multi-agent message routing |
| State changes | Tracks and logs agent state transitions |

### Unwrapping

```python
# Remove governance from all agents
kernel.unwrap(assistant)
kernel.unwrap(user_proxy)
```

---

## 6. Microsoft Agent Framework (MAF) Middleware

For MAF-based agents, Agent OS provides composable async middleware instead of a
kernel wrapper.

```python
from agent_os.integrations import (
    MAFGovernancePolicyMiddleware,
    MAFCapabilityGuardMiddleware,
    MAFAuditTrailMiddleware,
    maf_create_governance_middleware,
)
```

### Quick setup with the factory

```python
middlewares = maf_create_governance_middleware(
    policy_directory="./policies",
    allowed_tools=["search", "calculator"],
    denied_tools=["shell_exec", "file_write"],
    agent_id="my-agent",
    enable_rogue_detection=True,
    audit_log=my_audit_log,
)

# Register with your MAF agent
for mw in middlewares:
    agent.add_middleware(mw)
```

The factory assembles middleware in order:
1. `AuditTrailMiddleware` — tamper-proof pre/post execution logging
2. `GovernancePolicyMiddleware` — declarative policy evaluation
3. `CapabilityGuardMiddleware` — tool allow/deny enforcement
4. `RogueDetectionMiddleware` — anomaly-based rogue agent detection

### Manual middleware composition

```python
from agent_os.integrations import (
    MAFGovernancePolicyMiddleware,
    MAFCapabilityGuardMiddleware,
)

# Policy middleware — evaluates governance rules
policy_mw = MAFGovernancePolicyMiddleware(
    evaluator=my_policy_evaluator,
    audit_log=audit_log,
)

# Capability guard — tool allow/deny lists
capability_mw = MAFCapabilityGuardMiddleware(
    allowed_tools=["search", "summarize"],
    denied_tools=["delete_record"],
    audit_log=audit_log,
)

# Each middleware follows the process(context, call_next) pattern
# On violation: sets error response, logs, raises MiddlewareTermination
# On allow: calls call_next() to continue the chain
```

---

## 7. Common GovernancePolicy Patterns

`GovernancePolicy` is a dataclass with sensible defaults.  Here are
battle-tested configurations for common scenarios.

### Read-only agent

```python
readonly_policy = GovernancePolicy(
    name="read-only",
    max_tokens=4096,
    max_tool_calls=10,
    allowed_tools=["search", "retrieve", "summarize"],
    blocked_patterns=[
        ("DELETE", "substring"),
        ("DROP", "substring"),
        ("INSERT", "substring"),
        ("UPDATE", "substring"),
        ("rm ", "substring"),
        ("write_file", "substring"),
    ],
    require_human_approval=False,
    log_all_calls=True,
)
```

### Production-strict

```python
production_policy = GovernancePolicy(
    name="production-strict",
    max_tokens=2048,
    max_tool_calls=5,
    timeout_seconds=60,
    allowed_tools=["approved_api_call", "read_database"],
    blocked_patterns=[
        ("\\b\\d{3}-\\d{2}-\\d{4}\\b", "regex"),             # SSN
        ("\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b", "regex"),  # email
        ("(?i)password\\s*[:=]\\s*\\S+", "regex"),            # credentials
        ("IGNORE PREVIOUS", "substring"),                       # prompt injection
    ],
    require_human_approval=True,
    confidence_threshold=0.9,
    drift_threshold=0.10,
    max_concurrent=5,
    backpressure_threshold=4,
    checkpoint_frequency=3,
    log_all_calls=True,
    version="1.0.0",
)
```

### Dev-permissive

```python
dev_policy = GovernancePolicy(
    name="dev-permissive",
    max_tokens=16384,
    max_tool_calls=50,
    timeout_seconds=600,
    allowed_tools=[],  # empty = allow all
    blocked_patterns=[
        ("rm -rf /", "substring"),  # just the truly dangerous stuff
    ],
    require_human_approval=False,
    confidence_threshold=0.5,
    drift_threshold=0.5,
    log_all_calls=True,
)
```

### Serialization

Policies serialize to YAML for version-controlled policy-as-code:

```python
# Save
production_policy.to_yaml("policies/production.yaml")

# Load
policy = GovernancePolicy.from_yaml("policies/production.yaml")

# Compare
if dev_policy.is_stricter_than(production_policy):
    print("Dev policy is stricter — unusual!")

# Diff two policies
changes = production_policy.diff(dev_policy)
for field, (prod_val, dev_val) in changes.items():
    print(f"  {field}: {prod_val} → {dev_val}")
```

---

## 8. Building a Custom Adapter

When your framework isn't covered by the 22 built-in adapters, extend
`BaseIntegration`.

### Minimal adapter

```python
from agent_os.integrations.base import (
    BaseIntegration,
    GovernancePolicy,
    ExecutionContext,
    PolicyViolationError,
)


class MyFrameworkKernel(BaseIntegration):
    """Governance adapter for MyFramework."""

    def __init__(self, policy: GovernancePolicy | None = None) -> None:
        super().__init__(policy)

    def wrap(self, agent):
        """Wrap a MyFramework agent with governance."""
        ctx = self.create_context(agent_id=getattr(agent, "name", "unknown"))
        return GovernedMyAgent(agent, self, ctx)

    def unwrap(self, governed_agent):
        """Remove governance wrapper, return original agent."""
        return governed_agent._original
```

### The governed wrapper

```python
class GovernedMyAgent:
    """Transparent proxy that routes calls through governance."""

    def __init__(self, original, kernel: MyFrameworkKernel, ctx: ExecutionContext):
        self._original = original
        self._kernel = kernel
        self._ctx = ctx

    def run(self, prompt: str, **kwargs):
        # Pre-execution check
        allowed, reason = self._kernel.pre_execute(self._ctx, prompt)
        if not allowed:
            raise PolicyViolationError(reason)

        # Execute the real framework call
        result = self._original.run(prompt, **kwargs)

        # Post-execution: drift detection and checkpointing.
        # post_execute() always returns (True, None) — it records drift
        # scores on ctx but does not block.  Check scores explicitly:
        self._kernel.post_execute(self._ctx, result)

        if self._ctx._drift_scores:
            latest = self._ctx._drift_scores[-1]
            if latest > self._kernel.policy.drift_threshold:
                raise PolicyViolationError(
                    f"Drift {latest:.2f} exceeds threshold "
                    f"{self._kernel.policy.drift_threshold}"
                )

        return result

    def get_context(self) -> ExecutionContext:
        return self._ctx
```

### Adding tool call interception

```python
from agent_os.integrations.base import ToolCallRequest, ToolCallResult, PolicyInterceptor


class GovernedMyAgent:
    # ... (same as above)

    def call_tool(self, tool_name: str, arguments: dict):
        request = ToolCallRequest(
            tool_name=tool_name,
            arguments=arguments,
            agent_id=self._ctx.agent_id,
        )

        interceptor = PolicyInterceptor(self._kernel.policy)
        result: ToolCallResult = interceptor.intercept(request)

        if not result.allowed:
            raise PolicyViolationError(
                f"Tool '{tool_name}' blocked: {result.reason}"
            )

        # Use modified arguments if the interceptor rewrote them
        final_args = result.modified_arguments or arguments
        return self._original.call_tool(tool_name, final_args)
```

### Adding event hooks

```python
from agent_os.integrations.base import GovernanceEventType


class MyFrameworkKernel(BaseIntegration):
    # ... (same as above)

    def wrap(self, agent):
        ctx = self.create_context(agent_id=agent.name)

        # Emit event on wrap
        self.emit(GovernanceEventType.POLICY_CHECK, {
            "agent_id": agent.name,
            "policy": self.policy.name,
            "action": "wrap",
        })

        return GovernedMyAgent(agent, self, ctx)


# Usage — register listeners before wrapping
kernel = MyFrameworkKernel(policy=my_policy)

kernel.on(GovernanceEventType.POLICY_VIOLATION, lambda data: (
    alert_ops_team(data)
))

kernel.on(GovernanceEventType.TOOL_CALL_BLOCKED, lambda data: (
    log_blocked_tool(data["tool_name"], data["reason"])
))

# Note: event listeners are observational only (logging, alerting,
# metrics).  emit() wraps callbacks in try/except, so exceptions
# raised inside a listener are silently swallowed.

governed = kernel.wrap(my_agent)
```

### Composing multiple interceptors

```python
from agent_os.integrations.base import (
    CompositeInterceptor,
    PolicyInterceptor,
    ToolCallInterceptor,
)


class CustomRateLimitInterceptor:
    """Example: rate-limit tool calls per minute."""

    def intercept(self, request: ToolCallRequest) -> ToolCallResult:
        if self._over_limit(request.agent_id):
            return ToolCallResult(allowed=False, reason="Rate limit exceeded")
        return ToolCallResult(allowed=True)


# Chain interceptors — all must allow the call
composite = CompositeInterceptor([
    PolicyInterceptor(policy),
    CustomRateLimitInterceptor(),
])

result = composite.intercept(tool_request)
```

---

## Putting It All Together

A real-world pattern: same policy, multiple frameworks, centralized audit.

```python
from agent_os.integrations import (
    GovernancePolicy,
    OpenAIKernel,
    LangChainKernel,
    AnthropicKernel,
    GovernanceEventType,
)

# One policy for the whole system
policy = GovernancePolicy.from_yaml("policies/production.yaml")

# Centralized violation handler
def on_violation(data):
    send_to_siem(data)
    page_on_call(data["agent_id"], data["reason"])

# OpenAI assistant
oai_kernel = OpenAIKernel(policy=policy)
oai_kernel.on(GovernanceEventType.POLICY_VIOLATION, on_violation)
governed_assistant = oai_kernel.wrap(assistant, client)

# LangChain RAG chain
lc_kernel = LangChainKernel(policy=policy)
lc_kernel.on(GovernanceEventType.POLICY_VIOLATION, on_violation)
governed_chain = lc_kernel.wrap(rag_chain)

# Anthropic summarizer
anth_kernel = AnthropicKernel(policy=policy)
anth_kernel.on(GovernanceEventType.POLICY_VIOLATION, on_violation)
governed_claude = anth_kernel.wrap(anthropic_client)
```

Every call across all three frameworks is now governed by the same policy,
violations route to the same handler, and the audit trail is unified.

---

## Next Steps

- [Tutorial 01 — Policy Engine](./01-policy-engine.md)
- [Tutorial 02 — Trust & Identity](./02-trust-and-identity.md)
- [OWASP Compliance Mapping](../OWASP-COMPLIANCE.md)
- [API Reference — `BaseIntegration`](../../agent-governance-python/agent-os/src/agent_os/integrations/base.py)
- [All 22+ adapters](../../agent-governance-python/agent-os/src/agent_os/integrations/)
