# Agent OS vs Alternatives

A comparison of AI agent safety and governance tools to help you choose the right approach.

## Quick Comparison

| Tool | Primary Focus | When It Acts | Architecture | Best For |
|------|--------------|--------------|--------------|----------|
| **Agent OS** | Action interception | During execution | Middleware wrapper | Runtime governance |
| Guardrails AI | Input/output validation | Before/after LLM | Validators | Response quality |
| NeMo Guardrails | Conversational safety | Before/after LLM | Dialog rails | Chatbot safety |
| LlamaGuard | Content classification | Before/after LLM | Classification model | Content moderation |
| LangChain Callbacks | Event observation | Before/after steps | Callback handlers | Monitoring |

## Detailed Comparison

### Agent OS

**What it does:** Intercepts agent actions at execution time. Wraps frameworks like LangChain, CrewAI, and OpenAI Assistants with governance checks.

**Key differentiator:** Policies are enforced by code, not by hoping the LLM complies. If a policy says "no destructive SQL," the action is blocked even if the LLM generates it.

```python
from agent_os import KernelSpace, Policy

kernel = KernelSpace(policies=[
    Policy.no_destructive_sql(),
    Policy.rate_limit(100, "1m"),
])

@kernel.govern
def my_agent(task):
    return llm.generate(task)  # Dangerous actions blocked at execution
```

**Pros:**
- Deterministic enforcement (not probabilistic)
- Works with any LLM framework
- POSIX-inspired primitives (signals, VFS)
- Comprehensive audit logging

**Cons:**
- Application-level only (bypass possible with direct stdlib calls)
- Requires wrapping existing code
- Adds latency (typically 1-5ms per action)

**Best for:** Production deployments where you need deterministic safety guarantees and audit trails.

---

### Guardrails AI

**What it does:** Validates LLM inputs and outputs against schemas. Ensures responses match expected formats and constraints.

```python
from guardrails import Guard
from guardrails.hub import DetectPII

guard = Guard().use(DetectPII())
result = guard(llm.complete, prompt="...")
```

**Key differentiator:** Schema-based validation with automatic retries. Great for ensuring structured output.

**Pros:**
- Rich validator ecosystem (Guardrails Hub)
- Automatic retry with corrective prompts
- Schema enforcement (JSON, XML, etc.)
- Strong community

**Cons:**
- Focuses on I/O, not action interception
- Validators are pattern-based (can miss edge cases)
- Retry loops can increase costs

**Best for:** Applications where output format and quality are critical.

---

### NeMo Guardrails

**What it does:** Defines conversational "rails" that guide chatbot behavior. Uses a Colang DSL to define allowed conversation flows.

```colang
define user ask about competitors
  "What can you tell me about [competitor]?"
  "How do you compare to [competitor]?"

define flow
  user ask about competitors
  bot refuse to discuss competitors
```

**Key differentiator:** Domain-specific language for conversational safety. Designed for enterprise chatbots.

**Pros:**
- Colang DSL is intuitive for non-developers
- Built-in topical rails, moderation, fact-checking
- Good for customer-facing chatbots
- NVIDIA backing

**Cons:**
- Focused on conversational AI (less suitable for agents)
- Colang learning curve
- Less flexible than code-based solutions

**Best for:** Enterprise chatbots with complex conversational requirements.

---

### LlamaGuard

**What it does:** Classifies prompts and responses for safety. Uses a fine-tuned Llama model to detect harmful content.

```python
from transformers import pipeline

classifier = pipeline("text-classification", model="meta-llama/LlamaGuard-7b")
result = classifier("Is this content safe?")
```

**Key differentiator:** Model-based classification rather than rule-based. Can catch nuanced unsafe content.

**Pros:**
- Catches nuanced content issues
- Multi-category safety taxonomy
- Open weights (self-hostable)
- Good for content moderation

**Cons:**
- Requires GPU for inference
- Adds latency (model inference)
- Classification can have false positives/negatives
- Focused on content, not actions

**Best for:** Content moderation in applications with user-generated input.

---

### LangChain Callbacks/Tracing

**What it does:** Observes agent execution via callback handlers. Logs events, traces execution, integrates with observability tools.

```python
from langchain.callbacks import StdOutCallbackHandler

chain.invoke({"input": "..."}, callbacks=[StdOutCallbackHandler()])
```

**Key differentiator:** Native to LangChain ecosystem. Great for observability but doesn't block actions.

**Pros:**
- Zero additional dependencies
- Integrates with LangSmith, Weights & Biases
- Minimal latency impact
- Good debugging tool

**Cons:**
- Observability only (doesn't block/modify)
- LangChain-specific
- Not designed for enforcement

**Best for:** Development and debugging, not production governance.

---

## When to Use Each

| Scenario | Recommended Tool |
|----------|------------------|
| Production agent with strict safety requirements | **Agent OS** |
| Ensuring JSON/structured output from LLM | **Guardrails AI** |
| Enterprise customer service chatbot | **NeMo Guardrails** |
| Content moderation for user input | **LlamaGuard** |
| Debugging LangChain applications | **LangChain Callbacks** |
| Multi-tenant SaaS with isolation needs | **Agent OS** |
| Cost control and rate limiting | **Agent OS** |

## Using Multiple Tools Together

These tools are complementary. A robust production setup might use:

```python
from agent_os import KernelSpace
from guardrails import Guard
from langchain.callbacks import TracingCallbackHandler

# 1. Agent OS for action governance
kernel = KernelSpace(policy="strict")

# 2. Guardrails for output validation
guard = Guard().use(DetectPII())

# 3. LangChain callbacks for observability
callbacks = [TracingCallbackHandler()]

@kernel.govern
def my_agent(task):
    result = chain.invoke({"input": task}, callbacks=callbacks)
    return guard.validate(result)
```

## Feature Matrix

| Feature | Agent OS | Guardrails AI | NeMo Guardrails | LlamaGuard |
|---------|----------|---------------|-----------------|------------|
| Action blocking | ✅ | ⚪ | ⚪ | ⚪ |
| Input validation | ⚪ | ✅ | ✅ | ✅ |
| Output validation | ⚪ | ✅ | ✅ | ✅ |
| Rate limiting | ✅ | ⚪ | ⚪ | ⚪ |
| Audit logging | ✅ | ⚪ | ⚪ | ⚪ |
| Cost controls | ✅ | ⚪ | ⚪ | ⚪ |
| Multi-tenant isolation | ✅ | ⚪ | ⚪ | ⚪ |
| Schema enforcement | ⚪ | ✅ | ⚪ | ⚪ |
| Conversational rails | ⚪ | ⚪ | ✅ | ⚪ |
| Content classification | ⚪ | ⚪ | ⚪ | ✅ |
| POSIX signals | ✅ | ⚪ | ⚪ | ⚪ |
| Framework agnostic | ✅ | ✅ | ⚪ | ✅ |
| Self-hosted | ✅ | ✅ | ✅ | ✅ |
| Automatic retries | ⚪ | ✅ | ⚪ | ⚪ |

## Performance Comparison

Approximate latency overhead (varies by workload):

| Tool | Typical Latency | Notes |
|------|-----------------|-------|
| Agent OS | 1-5ms | Policy evaluation |
| Guardrails AI | 5-50ms | Depends on validators |
| NeMo Guardrails | 10-100ms | Depends on rail complexity |
| LlamaGuard | 100-500ms | Model inference |
| LangChain Callbacks | <1ms | Observability only |

## Migration Path

### From prompt-based safety to Agent OS

```python
# Before: Prompt-based (unreliable)
prompt = """You are a helpful assistant.
IMPORTANT: Never execute DROP TABLE or DELETE without WHERE.
IMPORTANT: Never access files outside /workspace."""

# After: Kernel-based (deterministic)
from agent_os import KernelSpace, Policy

kernel = KernelSpace(policies=[
    Policy.no_destructive_sql(),
    Policy.file_access("/workspace"),
])
```

### From Guardrails to Agent OS + Guardrails

Keep Guardrails for output validation, add Agent OS for action governance:

```python
from agent_os import KernelSpace
from guardrails import Guard

kernel = KernelSpace(policy="strict")
guard = Guard().use(ValidJSON())

@kernel.govern
def my_agent(task):
    result = llm.generate(task)
    return guard.validate(result)  # Output validation
    # Actions are governed by kernel
```

---

## Summary

- **Agent OS** = Action interception (what the agent *does*)
- **Guardrails AI** = Output validation (what the agent *returns*)
- **NeMo Guardrails** = Conversation flows (what the agent *says*)
- **LlamaGuard** = Content classification (what's *appropriate*)

Choose based on your primary concern, and consider combining tools for defense in depth.
