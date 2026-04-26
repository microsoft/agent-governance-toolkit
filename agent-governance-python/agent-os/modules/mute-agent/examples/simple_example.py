# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example demonstrating the Mute Agent system with a simple task execution scenario.
"""

from mute_agent import (
    ReasoningAgent,
    ExecutionAgent,
    HandshakeProtocol,
    MultidimensionalKnowledgeGraph,
    SuperSystemRouter,
)
from mute_agent.knowledge_graph.graph_elements import Node, Edge, NodeType, EdgeType
from mute_agent.knowledge_graph.subgraph import Dimension


def create_example_knowledge_graph():
    """Create an example knowledge graph with multiple dimensions."""
    kg = MultidimensionalKnowledgeGraph()
    
    # Define dimensions
    security_dim = Dimension(
        name="security",
        description="Security constraints and requirements",
        priority=10,
        metadata={"category": "security"}
    )
    
    resource_dim = Dimension(
        name="resource",
        description="Resource availability and management",
        priority=5,
        metadata={"category": "resource"}
    )
    
    workflow_dim = Dimension(
        name="workflow",
        description="Workflow and process constraints",
        priority=3,
        metadata={"category": "workflow"}
    )
    
    # Add dimensions to knowledge graph
    kg.add_dimension(security_dim)
    kg.add_dimension(resource_dim)
    kg.add_dimension(workflow_dim)
    
    # Add nodes to security dimension
    read_action = Node(
        id="read_file",
        node_type=NodeType.ACTION,
        attributes={"operation": "read", "resource": "file"},
        metadata={"description": "Read a file"}
    )
    
    write_action = Node(
        id="write_file",
        node_type=NodeType.ACTION,
        attributes={"operation": "write", "resource": "file"},
        metadata={"description": "Write to a file"}
    )
    
    auth_constraint = Node(
        id="requires_auth",
        node_type=NodeType.CONSTRAINT,
        attributes={"type": "authentication"},
        metadata={"description": "Requires authentication"}
    )
    
    kg.add_node_to_dimension("security", read_action)
    kg.add_node_to_dimension("security", write_action)
    kg.add_node_to_dimension("security", auth_constraint)
    
    # Add edges in security dimension
    read_requires_auth = Edge(
        source_id="read_file",
        target_id="requires_auth",
        edge_type=EdgeType.REQUIRES
    )
    
    write_requires_auth = Edge(
        source_id="write_file",
        target_id="requires_auth",
        edge_type=EdgeType.REQUIRES
    )
    
    kg.add_edge_to_dimension("security", read_requires_auth)
    kg.add_edge_to_dimension("security", write_requires_auth)
    
    # Add nodes to resource dimension
    kg.add_node_to_dimension("resource", read_action)
    kg.add_node_to_dimension("resource", write_action)
    
    memory_constraint = Node(
        id="memory_available",
        node_type=NodeType.CONSTRAINT,
        attributes={"type": "resource", "resource": "memory"},
        metadata={"description": "Memory must be available"}
    )
    
    kg.add_node_to_dimension("resource", memory_constraint)
    
    # Add nodes to workflow dimension
    kg.add_node_to_dimension("workflow", read_action)
    kg.add_node_to_dimension("workflow", write_action)
    
    return kg


def example_read_handler(parameters):
    """Example handler for read_file action."""
    file_path = parameters.get("file_path", "unknown")
    return {
        "content": f"Content of {file_path}",
        "size": 1024
    }


def example_write_handler(parameters):
    """Example handler for write_file action."""
    file_path = parameters.get("file_path", "unknown")
    content = parameters.get("content", "")
    return {
        "written": True,
        "path": file_path,
        "bytes_written": len(content)
    }


def main():
    """Main example demonstrating the Mute Agent system."""
    print("=" * 60)
    print("Mute Agent Example: Dynamic Semantic Handshake Protocol")
    print("=" * 60)
    print()
    
    # Step 1: Create the knowledge graph
    print("Step 1: Creating Multidimensional Knowledge Graph...")
    kg = create_example_knowledge_graph()
    print(f"  - Created {len(kg.dimensions)} dimensions")
    print(f"  - Dimensions: {', '.join(kg.dimensions.keys())}")
    print()
    
    # Step 2: Create the Super System Router
    print("Step 2: Initializing Super System Router...")
    router = SuperSystemRouter(kg)
    print("  - Router initialized with knowledge graph")
    print()
    
    # Step 3: Create the Handshake Protocol
    print("Step 3: Initializing Handshake Protocol...")
    protocol = HandshakeProtocol()
    print("  - Protocol ready for negotiation")
    print()
    
    # Step 4: Create the Reasoning Agent (The Face)
    print("Step 4: Creating Reasoning Agent (The Face)...")
    reasoning_agent = ReasoningAgent(kg, router, protocol)
    print("  - The Face is ready to reason about actions")
    print()
    
    # Step 5: Create the Execution Agent (The Hands)
    print("Step 5: Creating Execution Agent (The Hands)...")
    execution_agent = ExecutionAgent(protocol)
    execution_agent.register_action_handler("read_file", example_read_handler)
    execution_agent.register_action_handler("write_file", example_write_handler)
    print("  - The Hands are ready to execute")
    print("  - Registered handlers for: read_file, write_file")
    print()
    
    # Step 6: Reasoning and Action Proposal
    print("Step 6: The Face reasons about available actions...")
    context = {
        "user": "admin",
        "authenticated": True,
        "resource": "file"
    }
    print(f"  - Context: {context}")
    
    routing_result = reasoning_agent.reason(context)
    print(f"  - Selected dimensions: {routing_result.selected_dimensions}")
    print(f"  - Available actions: {len(routing_result.pruned_action_space)}")
    for action in routing_result.pruned_action_space:
        print(f"    * {action.id}: {action.metadata.get('description', 'No description')}")
    print()
    
    # Step 7: Propose an action
    print("Step 7: The Face proposes an action...")
    session = reasoning_agent.propose_action(
        action_id="read_file",
        parameters={"file_path": "/data/example.txt"},
        context=context,
        justification="User requested to read the file"
    )
    print(f"  - Session ID: {session.session_id}")
    print(f"  - State: {session.state.value}")
    print(f"  - Valid: {session.validation_result.is_valid if session.validation_result else 'N/A'}")
    
    if session.validation_result:
        print(f"  - Constraints met: {session.validation_result.constraints_met}")
        if session.validation_result.errors:
            print(f"  - Errors: {session.validation_result.errors}")
        if session.validation_result.warnings:
            print(f"  - Warnings: {session.validation_result.warnings}")
    print()
    
    # Step 8: Accept and execute
    if session.validation_result and session.validation_result.is_valid:
        print("Step 8: Accepting proposal and executing...")
        protocol.accept_proposal(session.session_id)
        execution_result = execution_agent.execute(session.session_id)
        
        print(f"  - Execution state: {execution_result.state.value}")
        if execution_result.execution_result:
            print(f"  - Result: {execution_result.execution_result}")
        print()
    
    # Step 9: Statistics
    print("Step 9: System Statistics")
    print("-" * 60)
    
    routing_stats = router.get_routing_statistics()
    print("Routing Statistics:")
    print(f"  - Total routings: {routing_stats['total_routings']}")
    print(f"  - Avg dimensions per routing: {routing_stats['avg_dimensions_per_routing']:.2f}")
    print(f"  - Avg actions per routing: {routing_stats['avg_actions_per_routing']:.2f}")
    print()
    
    exec_stats = execution_agent.get_execution_statistics()
    print("Execution Statistics:")
    print(f"  - Total executions: {exec_stats['total_executions']}")
    print(f"  - Successful: {exec_stats['successful_executions']}")
    print(f"  - Failed: {exec_stats['failed_executions']}")
    print(f"  - Success rate: {exec_stats['success_rate']:.1%}")
    print()
    
    print("=" * 60)
    print("Example completed successfully!")
    print("=" * 60)


if __name__ == "__main__":
    main()
