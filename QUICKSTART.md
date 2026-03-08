# 🚀 10-Minute Quick Start Guide

Get from zero to governed AI agents in under 10 minutes.

> **Prerequisites:** Python 3.10+ and pip installed.

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
pip install ai-agent-compliance[full]
```

Or install individual packages:

```bash
pip install agent-os-kernel        # Policy enforcement + framework integrations
pip install agentmesh-platform     # Zero-trust identity + trust cards
pip install ai-agent-compliance    # OWASP ASI verification + integrity CLI
pip install agent-sre              # SLOs, error budgets, chaos testing
pip install agent-hypervisor       # Execution sandboxing + privilege rings
```

## 2. Verify Your Installation

Run the included verification script:

```bash
python scripts/check_gov.py
```

Or use the governance CLI directly:

```bash
agent-compliance verify
agent-compliance verify --badge
```

## 3. Your First Governed Agent

Create a file called `governed_agent.py`:

```python
from agent_os.policy import PolicyEngine, CapabilityModel, PolicyScope

# Define what your agent is allowed to do
capabilities = CapabilityModel(
    allowed_tools=["web_search", "read_file", "send_email"],
    blocked_tools=["execute_code", "delete_file"],
    blocked_patterns=[r"\b\d{3}-\d{2}-\d{4}\b"],  # Block SSN patterns
    require_human_approval=True,
    max_tool_calls=10,
)

# Create a policy engine
engine = PolicyEngine(capabilities=capabilities)

# Every agent action goes through the policy engine
result = engine.evaluate(action="web_search", input_text="latest AI news")
print(f"Action allowed: {result.allowed}")
print(f"Reason: {result.reason}")

# This will be blocked
result = engine.evaluate(action="delete_file", input_text="/etc/passwd")
print(f"Action allowed: {result.allowed}")  # False
print(f"Reason: {result.reason}")           # "Tool 'delete_file' is blocked"
```

Run it:

```bash
python governed_agent.py
```

## 4. Wrap an Existing Framework

The toolkit integrates with all major agent frameworks. Here's a LangChain example:

```python
from agent_os import KernelSpace
from agent_os.policy import CapabilityModel

# Initialize with governance
kernel = KernelSpace(
    capabilities=CapabilityModel(
        allowed_tools=["web_search", "calculator"],
        max_tool_calls=5,
    )
)

# Wrap your LangChain agent — every tool call is now governed
governed_agent = kernel.wrap(your_langchain_agent)
```

Supported frameworks: **LangChain**, **OpenAI Agents SDK**, **AutoGen**, **CrewAI**,
**Google ADK**, **Semantic Kernel**, **LlamaIndex**, **Anthropic**, **Mistral**, **Gemini**, and more.

## 5. Check OWASP ASI 2026 Coverage

Verify your deployment covers the OWASP Agentic Security Threats:

```bash
# Text summary
agent-compliance verify

# JSON for CI/CD pipelines
agent-compliance verify --json

# Badge for your README
agent-compliance verify --badge
```

## 6. Verify Module Integrity

Ensure no governance modules have been tampered with:

```bash
# Generate a baseline integrity manifest
agent-compliance integrity --generate integrity.json

# Verify against the manifest later
agent-compliance integrity --manifest integrity.json
```

## Next Steps

| What | Where |
|------|-------|
| Full API reference | [packages/agent-os/README.md](packages/agent-os/README.md) |
| OWASP coverage map | [docs/OWASP-COMPLIANCE.md](docs/OWASP-COMPLIANCE.md) |
| Framework integrations | [packages/agent-os/src/agent_os/integrations/](packages/agent-os/src/agent_os/integrations/) |
| Example applications | [packages/agent-os/examples/](packages/agent-os/examples/) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) |
| Changelog | [CHANGELOG.md](CHANGELOG.md) |

---

*Based on the initial quickstart contribution by [@davidequarracino](https://github.com/davidequarracino) ([#106](https://github.com/microsoft/agent-governance-toolkit/pull/106), [#108](https://github.com/microsoft/agent-governance-toolkit/pull/108)).*
