# Examples

This directory contains example scripts demonstrating how to use Agent Control Plane.

## Available Examples

### Basic Usage (`basic_usage.py`)
Demonstrates fundamental concepts and basic usage patterns:
- Creating the control plane
- Creating agents with different permission levels
- Executing actions
- Handling permissions and errors

Run:
```bash
python examples/basic_usage.py
```

### Advanced Features (`advanced_features.py`)
Showcases advanced capabilities:
- Mute Agent - Capability-based execution
- Shadow Mode - Simulation without execution
- Constraint Graphs - Multi-dimensional context
- Supervisor Agents - Recursive governance
- Reasoning Telemetry - Tracking agent decisions

Run:
```bash
python examples/advanced_features.py
```

### Configuration (`configuration.py`)
Shows different configuration patterns and agent profiles:
- Development/Testing agent configuration
- Production agent configuration
- Read-only agent configuration
- Multi-tenant configurations

Run:
```bash
python examples/configuration.py
```

### Framework Integrations

#### LangChain Integration (`langchain_demo.py`)
Demonstrates governance for LangChain agents:
- Basic LangChain adapter setup
- Custom tool mappings for company-specific tools
- Blocked action callbacks for monitoring
- Real-world integration patterns
- Statistics and audit trails

Run:
```bash
python examples/langchain_demo.py
```

#### MCP Protocol Integration (`mcp_demo.py`)
Shows how to create governed MCP servers:
- Basic MCP server with governance
- MCP protocol message handling (JSON-RPC)
- Tool and resource registration
- Error handling for blocked actions
- Integration patterns for MCP clients

Run:
```bash
python examples/mcp_demo.py
```

#### A2A Protocol Integration (`a2a_demo.py`)
Demonstrates agent-to-agent communication:
- Creating A2A agents with governance
- Agent Cards for discovery
- Task requests and delegation
- Multi-agent coordination
- Secure inter-agent communication

Run:
```bash
python examples/a2a_demo.py
```

### OpenAI Adapter (`adapter_demo.py`)
Complete demonstration of the OpenAI SDK adapter:
- Drop-in middleware for OpenAI client
- Tool call interception and governance
- Custom tool mappings
- Production deployment patterns

Run:
```bash
python examples/adapter_demo.py
```

## Creating Your Own Examples

When creating examples:
1. Import from `agent_control_plane` package
2. Include clear comments explaining each step
3. Use descriptive variable names
4. Show both success and error cases
5. Keep examples focused on specific features

Example template:
```python
"""
Example: Your Feature Name

This example demonstrates how to use [feature name].
"""

from agent_control_plane import AgentControlPlane, create_standard_agent
from agent_control_plane.agent_kernel import ActionType

def example_function():
    """Demonstrates [specific functionality]"""
    # Create control plane
    control_plane = AgentControlPlane()
    
    # Your example code here
    pass

if __name__ == "__main__":
    example_function()
```

## Supported Frameworks and Protocols

The Agent Control Plane supports multiple frameworks and protocols:

- **OpenAI SDK**: Drop-in adapter for OpenAI client
- **LangChain**: Governance for LangChain agents and tools
- **MCP (Model Context Protocol)**: Anthropic's standard for tool/resource access
- **A2A (Agent-to-Agent)**: Google/Linux Foundation protocol for agent coordination

All adapters provide the same governance approach with consistent security and audit capabilities.
