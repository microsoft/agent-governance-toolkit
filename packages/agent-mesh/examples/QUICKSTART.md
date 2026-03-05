# Quick Start Guide

Get started with AgentMesh examples in 5 minutes.

## Prerequisites

- Python 3.11 or higher
- pip package manager

## Installation

```bash
# Install AgentMesh
pip install agentmesh-platform

# Verify installation
python -c "import agentmesh; print(agentmesh.__version__)"
```

## Your First Governed Agent (3 Minutes)

### 1. Initialize an Agent

```bash
# Create a new governed agent
agentmesh init --name my-first-agent --sponsor your-email@company.com
```

This creates:
- `agentmesh.yaml` - Agent configuration
- `policies/` - Policy files
- `src/main.py` - Agent code

### 2. Explore the Configuration

```bash
cd my-first-agent
cat agentmesh.yaml
```

You'll see:
- **Identity settings:** TTL, auto-rotation
- **Trust settings:** Minimum peer scores, protocols
- **Governance:** Policies directory, audit settings
- **Reward dimensions:** How trust score is calculated

### 3. Run the Agent

```bash
# Install dependencies
pip install -e .

# Run the agent
python src/main.py
```

Output:
```
Agent DID: did:agentmesh:my-first-agent
Loaded 1 policies
Agent my-first-agent is running with trust score: 800
```

### 4. Check Status

```bash
# View agent status and trust score
agentmesh status .
```

You'll see:
- Agent identity (DID)
- Trust score breakdown (5 dimensions)
- Registration status

## Next: Try the Examples

### Option 1: MCP Tool Server (Recommended for MCP users)

```bash
cd examples/01-mcp-tool-server
pip install -r requirements.txt
python main.py
```

**What you'll see:**
- Governed tool invocations
- Policy enforcement (rate limiting, output sanitization)
- Audit logs for every tool call
- Trust score updates

### Option 2: Multi-Agent Customer Service

```bash
cd examples/02-customer-service
pip install -r requirements.txt
python main.py
```

**What you'll see:**
- Supervisor agent creating sub-agents
- Trust handshakes before delegation
- Collaborative trust scoring
- Cross-agent audit trail

### Option 3: Healthcare HIPAA Compliance

```bash
cd examples/03-healthcare-hipaa
pip install -r requirements.txt
python main.py
```

**What you'll see:**
- PHI detection in data
- HIPAA policy enforcement
- hash-chained audit logs
- Compliance report generation

## Key Concepts in 2 Minutes

### 1. Identity

Every agent gets a cryptographic identity:

```python
from agentmesh import AgentIdentity

identity = AgentIdentity.create(
    name="my-agent",
    sponsor="human@company.com",
    capabilities=["read:data", "write:reports"]
)

print(identity.did)  # did:agentmesh:my-agent
```

### 2. Policies

Declare governance rules in YAML:

```yaml
policies:
  - name: "rate-limit"
    rules:
      - condition: "action == 'api_call'"
        limit: "100/hour"
        action: "block"
```

### 3. Delegation

Create sub-agents with narrowed capabilities:

```python
# Parent agent
parent = AgentIdentity.create(
    name="parent",
    capabilities=["read:data", "write:data"]
)

# Child has subset of parent's capabilities
child = parent.delegate(
    name="child",
    capabilities=["read:data"]  # Can't write
)
```

### 4. Trust Scoring

Agents start at 800/1000 and adapt:
- Good behavior → score increases
- Policy violations → score decreases
- Score < 500 → credentials revoked

## Common Tasks

### View Audit Logs

```bash
agentmesh audit --agent did:agentmesh:my-agent --limit 50
```

### Validate a Policy

```bash
agentmesh policy policies/my-policy.yaml --validate
```

### Generate Compliance Report

```python
from agentmesh import ComplianceEngine

compliance = ComplianceEngine(frameworks=["soc2"])
report = compliance.generate_report(
    agent_id="did:agentmesh:my-agent",
    period="2026-01"
)
```

## Integration with Your Framework

### LangChain

```python
from langchain.tools import Tool
from agentmesh import AgentIdentity, PolicyEngine

identity = AgentIdentity.create(name="langchain-agent")
policy_engine = PolicyEngine.from_file("policies/default.yaml")

# Wrap LangChain tools with governance
@governed_tool
def my_tool(input):
    # Policy check happens automatically
    return "result"
```

### CrewAI

```python
from crewai import Agent
from agentmesh import ScopeChain

supervisor = AgentIdentity.create(name="supervisor")
scope_chain = ScopeChain(root=supervisor)

# Create crew member with narrowed capabilities
worker = Agent(
    role="Worker",
    agentmesh_identity=scope_chain.delegate(
        name="worker",
        capabilities=["task:execute"]
    )
)
```

## Troubleshooting

**Issue:** `ModuleNotFoundError: No module named 'agentmesh'`

**Solution:**
```bash
pip install agentmesh-platform
```

---

**Issue:** Policy keeps blocking my actions

**Solution:** Check `policies/*.yaml` and adjust rules to match your use case. Use `shadow_mode: true` to test without blocking.

---

**Issue:** Trust score keeps dropping

**Solution:** Check audit logs with `agentmesh audit` to see what's causing policy violations.

## What's Next?

1. **Explore Examples:** Try all 5 examples to see different use cases
2. **Read Documentation:** Check out the main [README](../README.md)
3. **Build Your Use Case:** Adapt examples to your specific needs
4. **Join Community:** Star the repo, open issues, contribute!

## Resources

- **Examples:** [All examples](./README.md)
- **Main Docs:** [README](../README.md)
- **Issues:** [GitHub Issues](https://github.com/microsoft/agent-governance-toolkit/issues)
- **LangChain Guide:** [Integration guide](./integrations/langchain.md)
- **CrewAI Guide:** [Integration guide](./integrations/crewai.md)

---

**Remember:** AgentMesh is in alpha. APIs may change. Not recommended for production without consulting maintainers.

**Need help?** Open an issue or start a discussion!
