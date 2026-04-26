# AgentMesh Examples

Real-world examples and integrations showcasing how to secure AI agents with AgentMesh.

## 🚀 [Quick Start Guide](./QUICKSTART.md)

**New to AgentMesh?** Start here for a 5-minute tutorial to create your first governed agent.

---

## Quick Start

Each example is self-contained with its own README and dependencies. Navigate to any example directory and follow the instructions.

## Examples

### 1. [MCP Tool Server with Governance](./01-mcp-tool-server/)
**Use Case:** Secure an MCP (Model Context Protocol) tool server with identity and policy enforcement.

**What you'll learn:**
- Register MCP tools with AgentMesh
- Enforce rate limiting and access policies
- Audit tool invocations
- Automatically revoke access on policy violations

**Best for:** Anyone building MCP servers or tool-based agents

---

### 2. [Multi-Agent Customer Service](./02-customer-service/)
**Use Case:** Build a governed multi-agent customer service system with ticket routing, escalation, and knowledge base access.

**What you'll learn:**
- Agent-to-agent (A2A) trust handshakes
- Scope chains (supervisor → specialist agents)
- Cross-agent capability scoping
- Collaborative trust scoring

**Best for:** Enterprise customer service automation

---

### 3. [Healthcare Data Analysis](./03-healthcare-hipaa/)
**Use Case:** Deploy a HIPAA-compliant agent for healthcare data analysis with automated compliance reporting.

**What you'll learn:**
- HIPAA compliance automation
- PHI (Protected Health Information) handling policies
- hash-chained audit logs for compliance
- Automated compliance report generation

**Best for:** Healthcare organizations, compliance teams

---

### 4. [DevOps Automation Agent](./04-devops-automation/)
**Use Case:** Secure a DevOps agent that deploys infrastructure, manages secrets, and executes privileged operations.

**What you'll learn:**
- Narrow delegation for sub-agents (deploy, secrets, DB)
- Just-in-time credential issuance (15-min TTL)
- Approval workflows for production deployments
- Risk-based adaptive scoring

**Best for:** Platform engineers, SRE teams, DevOps automation

---

### 5. [GitHub PR Review Agent](./05-github-integration/)
**Use Case:** An agent that reviews pull requests with governance, preventing malicious code suggestions.

**What you'll learn:**
- Real-world GitHub integration
- Output sanitization policies
- Shadow mode for testing
- Trust score decay on bad suggestions

**Best for:** DevRel teams, open source maintainers

---

## Integration Guides

Quick-start guides for integrating AgentMesh with popular agent frameworks:

- [LangChain Integration](./integrations/langchain.md) - Secure LangChain agents
- [AutoGPT Integration](./integrations/autogpt.md) - Govern AutoGPT instances
- [CrewAI Integration](./integrations/crewai.md) - Multi-agent crew governance

---

## Running Examples

### Prerequisites

```bash
# Install AgentMesh
pip install agentmesh-platform

# Or install from source
git clone https://github.com/microsoft/agent-governance-toolkit.git
cd agent-mesh
pip install -e .
```

### Running an Example

```bash
# Navigate to example
cd examples/01-mcp-tool-server

# Install dependencies
pip install -r requirements.txt

# Run the example
python main.py
```

---

## Contributing Examples

Have a great use case? We'd love to see it!

1. Fork the repository
2. Create a new example directory: `examples/0X-your-example/`
3. Include:
   - `README.md` - Clear explanation and instructions
   - `main.py` - Working example code
   - `requirements.txt` - Dependencies
   - `agentmesh.yaml` - Agent configuration
   - `policies/` - Example policies
4. Submit a pull request

---

## Getting Help

- **Documentation:** [README](../README.md)
- **Issues:** [GitHub Issues](https://github.com/microsoft/agent-governance-toolkit/issues)
- **Discussions:** [GitHub Discussions](https://github.com/microsoft/agent-governance-toolkit/discussions)

---

**Remember:** These examples demonstrate AgentMesh's capabilities. Always adapt them to your specific security and compliance requirements before deploying to production.
