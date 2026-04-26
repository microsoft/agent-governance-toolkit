# langchain-agentmesh

**AgentMesh Trust Layer for LangChain** - Cryptographic identity and trust verification for AI agents.

[![PyPI version](https://badge.fury.io/py/langchain-agentmesh.svg)](https://pypi.org/project/langchain-agentmesh/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

## Overview

`langchain-agentmesh` adds a trust layer to LangChain agents, enabling:

- **Cryptographic Identity** - Ed25519-based agent identities with DIDs
- **Trust Verification** - Verify agent identity before tool execution
- **Trust-Gated Tools** - Tools that require minimum trust scores
- **Audit Logging** - Track all trust decisions via callbacks

## Installation

```bash
pip install langchain-agentmesh
```

## Quick Start

### 1. Create Agent Identity

```python
from langchain_agentmesh import CMVKIdentity

# Generate a new identity for your agent
identity = CMVKIdentity.generate(
    agent_name="research-assistant",
    capabilities=["search", "summarize", "write"]
)

print(f"Agent DID: {identity.did}")
# did:cmvk:a1b2c3d4...
```

### 2. Trust-Gated Tools

Wrap tools to require trust verification:

```python
from langchain_agentmesh import TrustGatedTool, TrustedToolExecutor
from langchain_core.tools import tool

@tool
def search_database(query: str) -> str:
    """Search the internal database."""
    return f"Results for: {query}"

# Wrap with trust requirements
trusted_search = TrustGatedTool(
    tool=search_database,
    required_capabilities=["search"],
    min_trust_score=0.7,
)

# Create executor that verifies identity
executor = TrustedToolExecutor(
    tools=[trusted_search],
    identity=identity,
)

# Execute with trust verification
result = executor.execute("search_database", {"query": "AI safety"})
```

### 3. Trust Callbacks for Monitoring

```python
from langchain_agentmesh import TrustCallbackHandler

# Add to your LangChain callbacks
trust_handler = TrustCallbackHandler(identity=identity)

# Use with any LangChain component
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    model="gpt-4",
    callbacks=[trust_handler]
)

# All LLM calls now logged with identity context
response = llm.invoke("Hello!")

# Check trust metrics
print(trust_handler.get_metrics())
# {"total_calls": 1, "trust_score": 0.85, ...}
```

### 4. Peer Verification

Verify other agents before interaction:

```python
from langchain_agentmesh import TrustHandshake

handshake = TrustHandshake(identity=identity)

# Verify a peer agent
peer_card = {
    "did": "did:cmvk:peer123",
    "public_key": "...",
    "capabilities": ["analyze"],
}

result = handshake.verify_peer(
    peer_card,
    required_capabilities=["analyze"],
    min_trust_score=0.6
)

if result.verified:
    print(f"Peer verified! Trust score: {result.trust_score}")
else:
    print(f"Verification failed: {result.reason}")
```

## Integration with LangChain Agents

```python
from langchain.agents import AgentExecutor, create_openai_functions_agent
from langchain_openai import ChatOpenAI
from langchain_agentmesh import (
    CMVKIdentity,
    TrustGatedTool,
    TrustCallbackHandler,
)

# 1. Create identity
identity = CMVKIdentity.generate("my-agent", ["search", "calculate"])

# 2. Create trust-gated tools
tools = [
    TrustGatedTool(tool=my_search_tool, required_capabilities=["search"]),
    TrustGatedTool(tool=my_calc_tool, required_capabilities=["calculate"]),
]

# 3. Create agent with trust callbacks
llm = ChatOpenAI(model="gpt-4")
trust_handler = TrustCallbackHandler(identity=identity)

agent = create_openai_functions_agent(llm, tools, prompt)
executor = AgentExecutor(
    agent=agent,
    tools=tools,
    callbacks=[trust_handler],
)

# 4. Run with full trust tracking
result = executor.invoke({"input": "Search for AI papers"})
```

## API Reference

### CMVKIdentity

```python
class CMVKIdentity:
    did: str                    # Decentralized identifier
    agent_name: str             # Human-readable name
    public_key: str             # Ed25519 public key (base64)
    private_key: str            # Ed25519 private key (base64)
    capabilities: List[str]     # Allowed capabilities
    
    @classmethod
    def generate(cls, agent_name: str, capabilities: List[str]) -> "CMVKIdentity"
    
    def sign(self, data: str) -> CMVKSignature
    def verify_signature(self, data: str, signature: CMVKSignature) -> bool
    def to_dict(self) -> Dict[str, Any]
```

### TrustGatedTool

```python
class TrustGatedTool:
    def __init__(
        self,
        tool: BaseTool,
        required_capabilities: List[str] = None,
        min_trust_score: float = 0.5,
    )
```

### TrustCallbackHandler

```python
class TrustCallbackHandler(BaseCallbackHandler):
    def __init__(self, identity: CMVKIdentity)
    def get_metrics(self) -> Dict[str, Any]
    def get_audit_log(self) -> List[Dict[str, Any]]
```

## Security Considerations

- **Real Cryptography**: Uses Ed25519 signatures via the `cryptography` library
- **Key Management**: Private keys should be stored securely (e.g., environment variables, vaults)
- **Trust Scores**: Based on behavioral metrics, not self-reported
- **Audit Trail**: All trust decisions are logged for compliance

## Related Projects

- [AgentMesh](https://github.com/microsoft/agent-governance-toolkit) - Full trust mesh platform
- [Agent-OS](https://github.com/microsoft/agent-governance-toolkit) - Governance kernel for AI agents

## License

Apache 2.0 - See [LICENSE](LICENSE) for details.
