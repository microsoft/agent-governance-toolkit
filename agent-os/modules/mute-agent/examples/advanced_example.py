# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Advanced example demonstrating complex scenarios in the Mute Agent system.
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


def create_comprehensive_knowledge_graph():
    """Create a comprehensive knowledge graph with multiple dimensions and constraints."""
    kg = MultidimensionalKnowledgeGraph()
    
    # Define multiple dimensions with different priorities
    dimensions = [
        Dimension(
            name="security",
            description="Security and authorization constraints",
            priority=10,
            metadata={"category": "security", "required": True}
        ),
        Dimension(
            name="resource",
            description="Resource availability and limits",
            priority=8,
            metadata={"category": "resource", "required": True}
        ),
        Dimension(
            name="workflow",
            description="Business workflow and process constraints",
            priority=6,
            metadata={"category": "workflow", "required": False}
        ),
        Dimension(
            name="compliance",
            description="Regulatory compliance requirements",
            priority=9,
            metadata={"category": "compliance", "required": True}
        ),
    ]
    
    for dim in dimensions:
        kg.add_dimension(dim)
    
    # Define a rich set of actions
    actions = [
        Node(
            id="read_sensitive_data",
            node_type=NodeType.ACTION,
            attributes={"operation": "read", "data_type": "sensitive", "impact": "low"},
            metadata={"description": "Read sensitive data from database", "risk": "medium"}
        ),
        Node(
            id="write_sensitive_data",
            node_type=NodeType.ACTION,
            attributes={"operation": "write", "data_type": "sensitive", "impact": "high"},
            metadata={"description": "Write sensitive data to database", "risk": "high"}
        ),
        Node(
            id="delete_data",
            node_type=NodeType.ACTION,
            attributes={"operation": "delete", "data_type": "any", "impact": "high"},
            metadata={"description": "Delete data from system", "risk": "critical"}
        ),
        Node(
            id="send_notification",
            node_type=NodeType.ACTION,
            attributes={"operation": "notify", "data_type": "public", "impact": "low"},
            metadata={"description": "Send notification to users", "risk": "low"}
        ),
        Node(
            id="generate_report",
            node_type=NodeType.ACTION,
            attributes={"operation": "read", "data_type": "aggregated", "impact": "low"},
            metadata={"description": "Generate analytics report", "risk": "low"}
        ),
    ]
    
    # Define constraints for security dimension
    security_constraints = [
        Node(
            id="require_admin_auth",
            node_type=NodeType.CONSTRAINT,
            attributes={"type": "authentication", "level": "admin"},
            metadata={"description": "Requires admin-level authentication"}
        ),
        Node(
            id="require_user_auth",
            node_type=NodeType.CONSTRAINT,
            attributes={"type": "authentication", "level": "user"},
            metadata={"description": "Requires user-level authentication"}
        ),
        Node(
            id="require_audit_log",
            node_type=NodeType.CONSTRAINT,
            attributes={"type": "audit", "required": True},
            metadata={"description": "Requires audit logging"}
        ),
    ]
    
    # Add nodes to security dimension
    for action in actions:
        kg.add_node_to_dimension("security", action)
    for constraint in security_constraints:
        kg.add_node_to_dimension("security", constraint)
    
    # Add edges in security dimension
    security_edges = [
        Edge("read_sensitive_data", "require_user_auth", EdgeType.REQUIRES, weight=1.0),
        Edge("read_sensitive_data", "require_audit_log", EdgeType.REQUIRES, weight=1.0),
        Edge("write_sensitive_data", "require_admin_auth", EdgeType.REQUIRES, weight=1.0),
        Edge("write_sensitive_data", "require_audit_log", EdgeType.REQUIRES, weight=1.0),
        Edge("delete_data", "require_admin_auth", EdgeType.REQUIRES, weight=1.0),
        Edge("delete_data", "require_audit_log", EdgeType.REQUIRES, weight=1.0),
        Edge("send_notification", "require_user_auth", EdgeType.REQUIRES, weight=0.5),
    ]
    
    for edge in security_edges:
        kg.add_edge_to_dimension("security", edge)
    
    # Define constraints for resource dimension
    resource_constraints = [
        Node(
            id="memory_available",
            node_type=NodeType.CONSTRAINT,
            attributes={"type": "resource", "resource": "memory", "min_available": 100},
            metadata={"description": "Sufficient memory must be available"}
        ),
        Node(
            id="db_connection_available",
            node_type=NodeType.CONSTRAINT,
            attributes={"type": "resource", "resource": "database", "max_connections": 10},
            metadata={"description": "Database connection must be available"}
        ),
    ]
    
    # Add to resource dimension
    for action in actions:
        kg.add_node_to_dimension("resource", action)
    for constraint in resource_constraints:
        kg.add_node_to_dimension("resource", constraint)
    
    resource_edges = [
        Edge("read_sensitive_data", "db_connection_available", EdgeType.REQUIRES),
        Edge("write_sensitive_data", "db_connection_available", EdgeType.REQUIRES),
        Edge("delete_data", "db_connection_available", EdgeType.REQUIRES),
        Edge("generate_report", "memory_available", EdgeType.REQUIRES),
    ]
    
    for edge in resource_edges:
        kg.add_edge_to_dimension("resource", edge)
    
    # Add to workflow dimension
    for action in actions:
        kg.add_node_to_dimension("workflow", action)
    
    # Add to compliance dimension
    compliance_actions = [actions[0], actions[1], actions[2]]  # Only sensitive operations
    for action in compliance_actions:
        kg.add_node_to_dimension("compliance", action)
    
    compliance_constraint = Node(
        id="gdpr_compliant",
        node_type=NodeType.CONSTRAINT,
        attributes={"type": "compliance", "regulation": "GDPR"},
        metadata={"description": "Must be GDPR compliant"}
    )
    kg.add_node_to_dimension("compliance", compliance_constraint)
    
    for action in compliance_actions:
        edge = Edge(action.id, "gdpr_compliant", EdgeType.REQUIRES)
        kg.add_edge_to_dimension("compliance", edge)
    
    return kg


def setup_action_handlers(execution_agent):
    """Register handlers for all actions."""
    
    def read_handler(params):
        return {
            "data": f"Sensitive data from {params.get('source', 'database')}",
            "records_read": 42
        }
    
    def write_handler(params):
        return {
            "written": True,
            "records_written": params.get("record_count", 1),
            "transaction_id": "txn_12345"
        }
    
    def delete_handler(params):
        return {
            "deleted": True,
            "records_deleted": params.get("record_count", 0),
            "backup_created": True
        }
    
    def notify_handler(params):
        return {
            "sent": True,
            "recipients": params.get("recipients", []),
            "message_id": "msg_67890"
        }
    
    def report_handler(params):
        return {
            "report_generated": True,
            "format": params.get("format", "pdf"),
            "size_kb": 156
        }
    
    execution_agent.register_action_handler("read_sensitive_data", read_handler)
    execution_agent.register_action_handler("write_sensitive_data", write_handler)
    execution_agent.register_action_handler("delete_data", delete_handler)
    execution_agent.register_action_handler("send_notification", notify_handler)
    execution_agent.register_action_handler("generate_report", report_handler)


def scenario_1_valid_action(reasoning_agent, execution_agent, protocol):
    """Scenario 1: Valid action that passes all constraints."""
    print("\n" + "=" * 70)
    print("SCENARIO 1: Valid Action - Admin Reading Sensitive Data")
    print("=" * 70)
    
    context = {
        "user_role": "admin",
        "authenticated": True,
        "data_type": "sensitive",
        "operation": "read"
    }
    
    print(f"Context: {context}")
    
    # Reason about available actions
    routing_result = reasoning_agent.reason(context)
    print(f"\nRouting Result:")
    print(f"  - Selected Dimensions: {routing_result.selected_dimensions}")
    print(f"  - Available Actions: {len(routing_result.pruned_action_space)}")
    
    # Propose action
    session = reasoning_agent.propose_action(
        action_id="read_sensitive_data",
        parameters={"source": "customer_database"},
        context=context,
        justification="Admin needs to review customer data for support ticket"
    )
    
    print(f"\nProposal:")
    print(f"  - Session ID: {session.session_id}")
    print(f"  - State: {session.state.value}")
    print(f"  - Valid: {session.validation_result.is_valid}")
    print(f"  - Constraints Met: {session.validation_result.constraints_met}")
    
    if session.validation_result.is_valid:
        protocol.accept_proposal(session.session_id)
        result = execution_agent.execute(session.session_id)
        print(f"\nExecution:")
        print(f"  - State: {result.state.value}")
        print(f"  - Result: {result.execution_result}")
    
    return session


def scenario_2_rejected_action(reasoning_agent):
    """Scenario 2: Action that fails validation due to missing constraints."""
    print("\n" + "=" * 70)
    print("SCENARIO 2: Rejected Action - Unauthorized Delete")
    print("=" * 70)
    
    context = {
        "user_role": "user",  # Not admin
        "authenticated": True,
        "operation": "delete"
    }
    
    print(f"Context: {context}")
    
    # Propose action
    session = reasoning_agent.propose_action(
        action_id="delete_data",
        parameters={"table": "customer_data", "record_count": 10},
        context=context,
        justification="User wants to delete data"
    )
    
    print(f"\nProposal:")
    print(f"  - Session ID: {session.session_id}")
    print(f"  - State: {session.state.value}")
    print(f"  - Valid: {session.validation_result.is_valid}")
    print(f"  - Errors: {session.validation_result.errors}")
    print(f"  - Violated Constraints: {session.validation_result.constraints_violated}")
    
    return session


def scenario_3_action_selection(reasoning_agent):
    """Scenario 3: Automatic action selection based on criteria."""
    print("\n" + "=" * 70)
    print("SCENARIO 3: Action Selection - Best Action for Context")
    print("=" * 70)
    
    context = {
        "user_role": "user",
        "authenticated": True,
        "operation": "read"
    }
    
    print(f"Context: {context}")
    
    routing_result = reasoning_agent.reason(context)
    print(f"\nAvailable Actions ({len(routing_result.pruned_action_space)}):")
    for action in routing_result.pruned_action_space:
        print(f"  - {action.id}: {action.attributes}")
    
    # Select best action with criteria
    criteria = {"operation": "read", "impact": "low"}
    best_action = reasoning_agent.select_best_action(context, criteria)
    
    if best_action:
        print(f"\nSelected Action:")
        print(f"  - ID: {best_action.id}")
        print(f"  - Description: {best_action.metadata.get('description')}")
        print(f"  - Risk Level: {best_action.metadata.get('risk')}")
    
    return best_action


def main():
    """Run all advanced scenarios."""
    print("=" * 70)
    print("MUTE AGENT - ADVANCED SCENARIOS")
    print("=" * 70)
    
    # Setup
    print("\nInitializing system...")
    kg = create_comprehensive_knowledge_graph()
    router = SuperSystemRouter(kg)
    protocol = HandshakeProtocol()
    reasoning_agent = ReasoningAgent(kg, router, protocol)
    execution_agent = ExecutionAgent(protocol)
    setup_action_handlers(execution_agent)
    
    print(f"  ✓ Created {len(kg.dimensions)} dimensions")
    print(f"  ✓ Registered {len(execution_agent.execution_handlers)} action handlers")
    
    # Run scenarios
    scenario_1_valid_action(reasoning_agent, execution_agent, protocol)
    scenario_2_rejected_action(reasoning_agent)
    scenario_3_action_selection(reasoning_agent)
    
    # Final statistics
    print("\n" + "=" * 70)
    print("SYSTEM STATISTICS")
    print("=" * 70)
    
    routing_stats = router.get_routing_statistics()
    print("\nRouting Statistics:")
    print(f"  - Total Routings: {routing_stats['total_routings']}")
    print(f"  - Avg Dimensions/Routing: {routing_stats['avg_dimensions_per_routing']:.2f}")
    print(f"  - Avg Actions/Routing: {routing_stats['avg_actions_per_routing']:.2f}")
    print(f"  - Dimension Usage: {routing_stats['dimension_usage']}")
    
    exec_stats = execution_agent.get_execution_statistics()
    print("\nExecution Statistics:")
    print(f"  - Total Executions: {exec_stats['total_executions']}")
    print(f"  - Successful: {exec_stats['successful_executions']}")
    print(f"  - Failed: {exec_stats['failed_executions']}")
    print(f"  - Success Rate: {exec_stats['success_rate']:.1%}")
    
    print("\n" + "=" * 70)
    print("All scenarios completed!")
    print("=" * 70)


if __name__ == "__main__":
    main()
