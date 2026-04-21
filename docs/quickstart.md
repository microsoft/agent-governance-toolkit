# 🚀 10-Minute Quick Start Guide

Get from zero to governed AI agents in under 10 minutes.

> **Prerequisites:** Python 3.10+ / Node.js 18+ / .NET 8.0+ (any one or more).

## Architecture Overview

The governance layer intercepts every agent action before execution:

```mermaid
graph LR
    A[AI Agent] -->|Tool Call| B{Governance Layer}
    B -->|Policy Check| C{PolicyEngine}
    C -->|Allowed| D[Execute Tool]
    C -->|Blocked| E[Security Block]
    D --> F[Audit Log]
    E --> F
    F --> G[OTEL / Structured Logs]
```

## 1. Installation

Install the governance toolkit:

```bash
pip install agent-governance-toolkit[full]
```

Or install individual packages:

```bash
pip install agent-os-kernel        # Policy enforcement + framework integrations
pip install agentmesh-platform     # Zero-trust identity + trust cards
pip install agent-governance-toolkit    # OWASP ASI verification + integrity CLI
pip install agent-sre              # SLOs, error budgets, chaos testing
pip install agentmesh-runtime       # Execution supervisor + privilege rings
pip install agentmesh-marketplace      # Plugin lifecycle management
pip install agentmesh-lightning        # RL training governance
```

### TypeScript / Node.js

```bash
npm install @microsoft/agentmesh-sdk
```

### .NET

```bash
dotnet add package Microsoft.AgentGovernance
```

## 2. Verify Your Installation

Run the included verification script:

```bash
python scripts/check_gov.py
```

Or use the governance CLI directly:

```bash
agent-governance verify
agent-governance verify --badge
```

## 3. Your First Governed Agent

Create a file called `governed_agent.py`:

```python
from agent_os.policies import PolicyEvaluator, PolicyDecision
from agent_os.policies.schema import (
    PolicyDocument, PolicyRule, PolicyCondition,
    PolicyAction, PolicyOperator, PolicyDefaults,
)

# Define governance rules inline (or load from YAML — see below)
policy = PolicyDocument(
    name="agent-safety",
    version="1.0",
    description="Sample safety policy",
    defaults=PolicyDefaults(action=PolicyAction.ALLOW),
    rules=[
        PolicyRule(
            name="block-dangerous-tools",
            condition=PolicyCondition(
                field="tool_name",
                operator=PolicyOperator.IN,
                value=["execute_code", "delete_file", "shell_exec"],
            ),
            action=PolicyAction.DENY,
            message="Tool is blocked by policy",
            priority=100,
        ),
        PolicyRule(
            name="block-ssn-patterns",
            condition=PolicyCondition(
                field="input_text",
                operator=PolicyOperator.MATCHES,
                value=r"\b\d{3}-\d{2}-\d{4}\b",
            ),
            action=PolicyAction.DENY,
            message="SSN pattern detected in input",
            priority=90,
        ),
    ],
)

evaluator = PolicyEvaluator(policies=[policy])

# Allowed
result = evaluator.evaluate({"tool_name": "web_search", "input_text": "latest AI news"})
print(f"Action allowed: {result.allowed}")   # True
print(f"Reason: {result.reason}")

# Blocked — deterministically
result = evaluator.evaluate({"tool_name": "delete_file", "input_text": "/etc/passwd"})
print(f"Action allowed: {result.allowed}")   # False
print(f"Reason: {result.reason}")            # "Tool is blocked by policy"
```

Or load policies from YAML:

```python
from agent_os.policies import PolicyEvaluator

evaluator = PolicyEvaluator()
evaluator.load_policies("policies/")   # loads all *.yaml files

result = evaluator.evaluate({"tool_name": "web_search", "agent_id": "analyst-1"})
print(f"Allowed: {result.allowed}")
```

Run it:

```bash
python governed_agent.py
```

### Your First Governed Agent — TypeScript

Create a file called `governed_agent.ts`:

```typescript
import { PolicyEngine, AgentIdentity, AuditLogger } from "@microsoft/agentmesh-sdk";

const identity = AgentIdentity.generate("my-agent", ["web_search", "read_file"]);

const engine = new PolicyEngine([
  { action: "web_search", effect: "allow" },
  { action: "delete_file", effect: "deny" },
]);

console.log(engine.evaluate("web_search"));  // "allow"
console.log(engine.evaluate("delete_file")); // "deny"
```

### Your First Governed Agent — .NET

Create a file called `GovernedAgent.cs`:

```csharp
using AgentGovernance;
using AgentGovernance.Policy;

var kernel = new GovernanceKernel(new GovernanceOptions
{
    PolicyPaths = new() { "policies/default.yaml" },
    EnablePromptInjectionDetection = true,
});

var result = kernel.EvaluateToolCall("did:mesh:agent-1", "web_search", new() { ["query"] = "AI news" });
Console.WriteLine($"Allowed: {result.Allowed}");  // True (if policy permits)

result = kernel.EvaluateToolCall("did:mesh:agent-1", "delete_file", new() { ["path"] = "/etc/passwd" });
Console.WriteLine($"Allowed: {result.Allowed}");  // False
```

## 4. Wrap an Existing Framework

The toolkit integrates with all major agent frameworks. Here's a LangChain example:

```python
from agent_os.policies import PolicyEvaluator

# Load your governance policies
evaluator = PolicyEvaluator()
evaluator.load_policies("policies/")

# Evaluate before every tool call in your framework
decision = evaluator.evaluate({
    "agent_id": "langchain-agent-1",
    "tool_name": "web_search",
    "action": "tool_call",
})

if decision.allowed:
    # proceed with LangChain tool call
    result = your_langchain_agent.run(...)
else:
    print(f"Blocked: {decision.reason}")
```

For deeper integration, use framework-specific adapters:

```bash
pip install langchain-agentmesh      # LangChain adapter
pip install llamaindex-agentmesh     # LlamaIndex adapter
pip install crewai-agentmesh         # CrewAI adapter
```

Supported frameworks: **LangChain**, **OpenAI Agents SDK**, **AutoGen**, **CrewAI**,
**Google ADK**, **Semantic Kernel**, **LlamaIndex**, **Anthropic**, **Mistral**, **Gemini**, and more.

## 5. Check OWASP ASI 2026 Coverage

Verify your deployment covers the OWASP Agentic Security Threats:

```bash
# Text summary
agent-governance verify

# JSON for CI/CD pipelines
agent-governance verify --json

# Badge for your README
agent-governance verify --badge
```

### Secure Error Handling

All CLI tools in the toolkit are hardened to prevent internal information disclosure. If a command fails in JSON mode, it returns a sanitized schema:

```json
{
  "status": "error",
  "message": "An internal error occurred during verification",
  "type": "InternalError"
}
```

Known errors (e.g., "File not found") will include the specific error message, while unexpected system errors are masked to ensure security integrity.

## 6. Verify Module Integrity

Ensure no governance modules have been tampered with:

```bash
# Generate a baseline integrity manifest
agent-governance integrity --generate integrity.json

# Verify against the manifest later
agent-governance integrity --manifest integrity.json
```

## Next Steps

| What | Where |
|------|-------|
| Full API reference (Python) | [packages/agent-os/README.md](packages/agent-os/README.md) |
| TypeScript SDK docs | [packages/agent-mesh/sdks/typescript/README.md](packages/agent-mesh/sdks/typescript/README.md) |
| .NET SDK docs | [packages/agent-governance-dotnet/README.md](packages/agent-governance-dotnet/README.md) |
| OWASP coverage map | [docs/OWASP-COMPLIANCE.md](docs/OWASP-COMPLIANCE.md) |
| Framework integrations | [packages/agent-os/src/agent_os/integrations/](packages/agent-os/src/agent_os/integrations/) |
| Example applications | [packages/agent-os/examples/](packages/agent-os/examples/) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |

---

*Based on the initial quickstart contribution by [@davidequarracino](https://github.com/davidequarracino) ([#106](https://github.com/microsoft/agent-governance-toolkit/pull/106), [#108](https://github.com/microsoft/agent-governance-toolkit/pull/108)).*
