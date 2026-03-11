# LangChain AgentMesh Integration

Cryptographic identity verification and trust-gated tool execution for LangChain agents.

## Installation

```bash
pip install langchain-agentmesh
```

## Features

- **VerificationIdentity**: Ed25519-based cryptographic identity for agents
- **TrustGatedTool**: Wrap any tool with trust requirements
- **TrustedToolExecutor**: Execute tools with automatic verification
- **TrustCallbackHandler**: Monitor trust events during chain execution
- **TrustHandshake**: Verify peer agents before collaboration
- **DelegationChain**: Hierarchical capability delegation

## Quick Start

```python
from langchain_agentmesh import VerificationIdentity, TrustGatedTool, TrustedToolExecutor

# Generate agent identity
identity = VerificationIdentity.generate('research-agent', capabilities=['search', 'summarize'])

# Wrap a tool with trust requirements
gated_tool = TrustGatedTool(
    tool=search_tool,
    required_capabilities=['search'],
    min_trust_score=0.8
)

# Execute with verification
executor = TrustedToolExecutor(identity=identity)
result = executor.invoke(gated_tool, 'query')
```

## Use Cases

### Multi-Agent Trust Verification

```python
from langchain_agentmesh import TrustHandshake

# Create handshake for peer verification
handshake = TrustHandshake(my_identity)

# Verify peer before collaboration
result = await handshake.verify_peer(peer_identity)
if result.trusted:
    # Safe to delegate task
    response = await peer_agent.invoke(task)
```

### Trust-Gated Tool Execution

```python
from langchain_agentmesh import TrustGatedTool

# Sensitive tool requiring high trust
code_execution_tool = TrustGatedTool(
    tool=python_repl,
    required_capabilities=['code:execute'],
    min_trust_score=0.9,
    audit_logging=True
)

# Only trusted agents can use this tool
result = executor.invoke(code_execution_tool, code)
```

### Callback Integration

```python
from langchain_agentmesh import TrustCallbackHandler

# Monitor trust events
callback = TrustCallbackHandler(
    on_verification=lambda r: print(f"Verified: {r.peer_did}"),
    on_violation=lambda v: alert(f"Violation: {v}")
)

agent = create_agent(callbacks=[callback])
```

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `min_trust_score` | 0.5 | Minimum trust score required |
| `required_capabilities` | [] | Required capability list |
| `audit_logging` | False | Enable audit trail |
| `cache_ttl` | 900 | Verification cache TTL (seconds) |

## Related

- [AgentMesh](https://github.com/imran-siddique/agent-mesh) - Core trust mesh platform
- [Agent-OS](https://github.com/imran-siddique/agent-os) - Governance kernel

## License

MIT
