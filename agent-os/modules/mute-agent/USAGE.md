# Usage Guide

## Getting Started

### Installation

```bash
# Clone the repository
git clone https://github.com/microsoft/agent-governance-toolkit.git
cd mute-agent

# Install in development mode
pip install -e .

# Or install with dev dependencies
pip install -e ".[dev]"
```

### Quick Start

The simplest way to use Mute Agent is to follow these steps:

1. **Create a Knowledge Graph**
2. **Define Dimensions**
3. **Add Actions and Constraints**
4. **Initialize Agents**
5. **Execute Actions**

## Basic Usage

### Step 1: Create a Knowledge Graph

```python
from mute_agent import MultidimensionalKnowledgeGraph
from mute_agent.knowledge_graph.subgraph import Dimension

kg = MultidimensionalKnowledgeGraph()

# Add dimensions
security_dim = Dimension(
    name="security",
    description="Security constraints",
    priority=10  # Higher priority dimensions are checked first
)
kg.add_dimension(security_dim)
```

### Step 2: Add Nodes (Actions and Constraints)

```python
from mute_agent.knowledge_graph.graph_elements import Node, Edge, NodeType, EdgeType

# Create an action node
read_action = Node(
    id="read_file",
    node_type=NodeType.ACTION,
    attributes={"operation": "read", "resource": "file"},
    metadata={"description": "Read a file from the system"}
)

# Create a constraint node
auth_constraint = Node(
    id="requires_auth",
    node_type=NodeType.CONSTRAINT,
    attributes={"type": "authentication", "level": "user"},
    metadata={"description": "User must be authenticated"}
)

# Add nodes to dimension
kg.add_node_to_dimension("security", read_action)
kg.add_node_to_dimension("security", auth_constraint)
```

### Step 3: Add Edges (Relationships)

```python
# Create edge requiring authentication for read action
auth_edge = Edge(
    source_id="read_file",
    target_id="requires_auth",
    edge_type=EdgeType.REQUIRES,
    weight=1.0
)

kg.add_edge_to_dimension("security", auth_edge)
```

### Step 4: Initialize Components

```python
from mute_agent import (
    SuperSystemRouter,
    HandshakeProtocol,
    ReasoningAgent,
    ExecutionAgent
)

# Create router
router = SuperSystemRouter(kg)

# Create protocol
protocol = HandshakeProtocol()

# Create agents
reasoning_agent = ReasoningAgent(kg, router, protocol)
execution_agent = ExecutionAgent(protocol)
```

### Step 5: Register Action Handlers

```python
def read_file_handler(parameters):
    """Handler that performs the actual file read."""
    file_path = parameters.get("file_path")
    # Perform actual file read here
    return {
        "content": f"Content of {file_path}",
        "size": 1024
    }

execution_agent.register_action_handler("read_file", read_file_handler)
```

### Step 6: Reason and Execute

```python
# Define context
context = {
    "user": "alice",
    "authenticated": True,
    "resource": "file"
}

# Reason about available actions
routing_result = reasoning_agent.reason(context)
print(f"Available actions: {len(routing_result.pruned_action_space)}")

# Propose an action
session = reasoning_agent.propose_action(
    action_id="read_file",
    parameters={"file_path": "/data/example.txt"},
    context=context,
    justification="User requested file read"
)

# Check if valid
if session.validation_result.is_valid:
    # Accept the proposal
    protocol.accept_proposal(session.session_id)
    
    # Execute
    result = execution_agent.execute(session.session_id)
    
    print(f"Result: {result.execution_result}")
else:
    print(f"Validation failed: {session.validation_result.errors}")
```

## Advanced Usage

### Multiple Dimensions

```python
# Create multiple dimensions
dimensions = {
    "security": Dimension("security", "Security constraints", priority=10),
    "resource": Dimension("resource", "Resource limits", priority=8),
    "workflow": Dimension("workflow", "Business workflow", priority=6),
}

for dim in dimensions.values():
    kg.add_dimension(dim)

# Add same action to multiple dimensions
for dim_name in dimensions.keys():
    kg.add_node_to_dimension(dim_name, read_action)
```

### Context-Based Routing

The router automatically selects relevant dimensions based on context:

```python
# Security-focused context
security_context = {
    "security_level": "high",
    "user_role": "admin"
}

# Resource-focused context
resource_context = {
    "available_memory": 512,
    "cpu_usage": 45
}

# Different contexts may activate different dimensions
routing1 = router.route(security_context)
routing2 = router.route(resource_context)
```

### Action Selection with Criteria

```python
# Define selection criteria
criteria = {
    "operation": "read",
    "impact": "low",
    "risk": "low"
}

# Let the reasoning agent select the best action
best_action = reasoning_agent.select_best_action(context, criteria)

if best_action:
    session = reasoning_agent.propose_action(
        action_id=best_action.id,
        parameters={},
        context=context,
        justification="Auto-selected based on criteria"
    )
```

### Handling Validation Errors

```python
session = reasoning_agent.propose_action(
    action_id="delete_data",
    parameters={"table": "users"},
    context={"user_role": "guest"},
    justification="Attempting deletion"
)

if not session.validation_result.is_valid:
    print("Validation failed!")
    print(f"Errors: {session.validation_result.errors}")
    print(f"Warnings: {session.validation_result.warnings}")
    print(f"Violated constraints: {session.validation_result.constraints_violated}")
```

### Tracking Statistics

```python
# Get routing statistics
routing_stats = router.get_routing_statistics()
print(f"Total routings: {routing_stats['total_routings']}")
print(f"Dimension usage: {routing_stats['dimension_usage']}")

# Get execution statistics
exec_stats = execution_agent.get_execution_statistics()
print(f"Success rate: {exec_stats['success_rate']:.1%}")
print(f"Actions executed: {exec_stats['actions_executed']}")
```

## Node Types

### ACTION
Represents an executable action in the system.

```python
action = Node(
    id="send_email",
    node_type=NodeType.ACTION,
    attributes={"operation": "send", "medium": "email"},
    metadata={"description": "Send an email"}
)
```

### CONSTRAINT
Represents a constraint that must be satisfied.

```python
constraint = Node(
    id="rate_limit",
    node_type=NodeType.CONSTRAINT,
    attributes={"type": "rate", "max_per_hour": 100},
    metadata={"description": "Rate limit constraint"}
)
```

### PRECONDITION
Represents a condition that must be true before an action.

```python
precondition = Node(
    id="user_verified",
    node_type=NodeType.PRECONDITION,
    attributes={"required": True},
    metadata={"description": "User must be verified"}
)
```

### POSTCONDITION
Represents a condition that will be true after an action.

```python
postcondition = Node(
    id="notification_sent",
    node_type=NodeType.POSTCONDITION,
    attributes={"guaranteed": True},
    metadata={"description": "Notification will be sent"}
)
```

## Edge Types

### REQUIRES
Action requires a constraint to be satisfied.

```python
edge = Edge("action_id", "constraint_id", EdgeType.REQUIRES)
```

### ENABLES
Satisfying one node enables another.

```python
edge = Edge("precondition_id", "action_id", EdgeType.ENABLES)
```

### CONFLICTS_WITH
Two nodes conflict with each other.

```python
edge = Edge("action1_id", "action2_id", EdgeType.CONFLICTS_WITH)
```

### DEPENDS_ON
One node depends on another.

```python
edge = Edge("action_id", "resource_id", EdgeType.DEPENDS_ON)
```

### PRODUCES
Action produces a resource or postcondition.

```python
edge = Edge("action_id", "postcondition_id", EdgeType.PRODUCES)
```

### CONSUMES
Action consumes a resource.

```python
edge = Edge("action_id", "resource_id", EdgeType.CONSUMES)
```

## Session States

The handshake protocol manages sessions through these states:

1. **INITIATED**: Session created with proposal
2. **NEGOTIATING**: (Reserved for future use)
3. **VALIDATED**: Proposal validated against graph
4. **ACCEPTED**: Proposal accepted for execution
5. **REJECTED**: Proposal rejected due to validation failure
6. **EXECUTING**: Action currently being executed
7. **COMPLETED**: Execution completed successfully
8. **FAILED**: Execution failed with error

## Best Practices

### 1. Design Clear Dimensions

```python
# Good: Specific, focused dimensions
security_dim = Dimension("security", "Security and auth", priority=10)
compliance_dim = Dimension("compliance", "Regulatory compliance", priority=9)

# Avoid: Overly broad dimensions
everything_dim = Dimension("everything", "All constraints", priority=5)
```

### 2. Use Appropriate Priorities

Higher priority dimensions are considered first during routing:
- Security: 10
- Compliance: 9
- Resources: 8
- Performance: 6
- Workflow: 5

### 3. Provide Clear Justifications

```python
# Good: Clear justification
session = reasoning_agent.propose_action(
    action_id="delete_user",
    parameters={"user_id": "123"},
    context=context,
    justification="User requested account deletion per GDPR Article 17"
)

# Avoid: Vague justification
session = reasoning_agent.propose_action(
    action_id="delete_user",
    parameters={"user_id": "123"},
    context=context,
    justification="Delete user"
)
```

### 4. Handle Validation Results

Always check validation results before accepting proposals:

```python
if session.validation_result.is_valid:
    if session.validation_result.warnings:
        # Log warnings but proceed
        logger.warning(f"Warnings: {session.validation_result.warnings}")
    
    protocol.accept_proposal(session.session_id)
    result = execution_agent.execute(session.session_id)
else:
    # Handle errors appropriately
    logger.error(f"Validation failed: {session.validation_result.errors}")
```

### 5. Use Context Effectively

```python
# Good: Rich, specific context
context = {
    "user_id": "alice",
    "user_role": "admin",
    "authenticated": True,
    "session_id": "sess_123",
    "ip_address": "192.168.1.1",
    "timestamp": "2024-01-09T12:00:00Z"
}

# Avoid: Minimal context
context = {"user": "alice"}
```

## Troubleshooting

### Action Not Available

If an action is not in the pruned action space:

1. Check if it exists in relevant dimensions
2. Verify context matches dimension metadata
3. Check if constraints can be satisfied

```python
# Debug routing
routing_result = router.route(context)
print(f"Selected dimensions: {routing_result.selected_dimensions}")
print(f"Available actions: {[a.id for a in routing_result.pruned_action_space]}")
```

### Validation Failures

If validation always fails:

1. Check edge relationships in knowledge graph
2. Verify constraint nodes exist
3. Check parameter matching

```python
# Debug validation
if not session.validation_result.is_valid:
    print(f"Errors: {session.validation_result.errors}")
    print(f"Violated: {session.validation_result.constraints_violated}")
```

### Execution Errors

If execution fails:

1. Verify action handler is registered
2. Check handler implementation
3. Review execution error messages

```python
# Check handler registration
print(f"Registered handlers: {list(execution_agent.execution_handlers.keys())}")
```

## Examples

See the `examples/` directory for complete working examples:

- `simple_example.py`: Basic usage demonstration
- `advanced_example.py`: Complex scenarios with multiple dimensions

Run examples:

```bash
cd mute-agent
PYTHONPATH=. python examples/simple_example.py
PYTHONPATH=. python examples/advanced_example.py
```

## API Reference

For detailed API documentation, see the docstrings in each module:

- `mute_agent.core.reasoning_agent`: ReasoningAgent API
- `mute_agent.core.execution_agent`: ExecutionAgent API
- `mute_agent.core.handshake_protocol`: HandshakeProtocol API
- `mute_agent.knowledge_graph.multidimensional_graph`: Knowledge Graph API
- `mute_agent.super_system.router`: Router API
