# FAQ

## What is Agent OS?
Agent OS is a kernel-style architecture for governing autonomous AI agents.  
It applies operating system concepts—such as policies, signals, and controlled execution—to intercept and validate agent actions deterministically before they execute.

Agent OS focuses on *governance*, not agent creation.

---

## How is Agent OS different from LangChain or CrewAI?
LangChain and CrewAI are **agent frameworks** used to build agents.  
Agent OS is **governance infrastructure** that wraps those frameworks.

You can use Agent OS *alongside* LangChain, CrewAI, Semantic Kernel, or OpenAI Assistants to enforce safety, policies, and auditability during execution.

---

## Do I need to change my existing agent code?
No.  
Agent OS provides adapters that wrap existing agent code with minimal changes.

Most integrations involve wrapping your current agent or executor with a KernelSpace instance and defining policies.

---

## What LLM providers are supported?
Agent OS is model-agnostic.

It works with:
- OpenAI
- Anthropic
- Local models (Ollama, llama.cpp)
- Any provider supported by LangChain, CrewAI, or Semantic Kernel

Agent OS governs *actions*, not model outputs.

---

## How do I write custom policies?
Policies are defined declaratively using rule-based configurations or helper APIs.

Policies match known action patterns (e.g., file writes, SQL operations, API calls) and block or allow execution deterministically.

Custom policies can be added by extending the policy engine or writing new rule definitions.

---

## Is Agent OS production-ready?
The **core kernel components** (policy engine, signal handling, audit logging) are production-ready for controlled environments.

Advanced modules—such as multi-agent trust, verification, and observability—are experimental and evolving.

For strong isolation guarantees, Agent OS should be paired with container or sandbox-level isolation.

---

## What does “deterministic enforcement” mean?
Deterministic enforcement means actions are blocked or allowed by the policy engine, not by prompting or relying on LLM behavior.

If a rule matches an action, the action is stopped immediately—without asking the model to comply.

---

## Does Agent OS replace safety tools like Guardrails or LlamaGuard?
No.  
Those tools perform input/output filtering.

Agent OS operates *during execution* by intercepting actions.  
They can be used together for defense in depth.

---

## Can Agent OS be used with local models?
Yes.  
Agent OS does not depend on cloud APIs and works with local inference stacks.

Governance logic runs at the application layer, independent of the model runtime.

---

## How can I contribute?
Contributions are welcome.

You can:
- Improve documentation
- Add integrations or examples
- Propose RFCs
- Fix bugs or improve tests

See the Contributing Guide and GitHub issues labeled `good first issue`.
