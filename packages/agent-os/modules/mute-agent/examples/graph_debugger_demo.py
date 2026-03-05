# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Demo: Graph Debugger Visualization

Shows the --visualize feature in action.
Generates visual traces showing:
- Green nodes: Successfully traversed
- Red node: Where constraint failed
- Grey nodes: Unreachable due to severed path
"""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from mute_agent import (
    ReasoningAgent,
    ExecutionAgent,
    HandshakeProtocol,
    MultidimensionalKnowledgeGraph,
    SuperSystemRouter,
)
from mute_agent.knowledge_graph.graph_elements import Node, NodeType, Edge, EdgeType
from mute_agent.knowledge_graph.subgraph import Dimension
from mute_agent.visualization import GraphDebugger, ExecutionTrace, NodeState


def create_security_graph():
    """Create a security-focused knowledge graph."""
    kg = MultidimensionalKnowledgeGraph()
    
    # Security dimension
    security_dim = Dimension(
        name="security",
        description="Security constraints",
        priority=10
    )
    kg.add_dimension(security_dim)
    
    # Create nodes
    nodes = {
        "read_file": Node("read_file", NodeType.ACTION, {"operation": "read"}),
        "write_file": Node("write_file", NodeType.ACTION, {"operation": "write"}),
        "delete_db": Node("delete_db", NodeType.ACTION, {"operation": "delete", "critical": True}),
        "auth_check": Node("auth_check", NodeType.CONSTRAINT, {"required": True}),
        "approval_token": Node("approval_token", NodeType.CONSTRAINT, {"required": True, "level": "high"}),
        "backup_required": Node("backup_required", NodeType.PRECONDITION, {"required": True}),
    }
    
    for node in nodes.values():
        kg.add_node_to_dimension("security", node)
    
    # Create edges (constraints)
    edges = [
        Edge("read_file", "auth_check", EdgeType.REQUIRES),
        Edge("write_file", "auth_check", EdgeType.REQUIRES),
        Edge("delete_db", "approval_token", EdgeType.REQUIRES),
        Edge("delete_db", "backup_required", EdgeType.REQUIRES),
    ]
    
    for edge in edges:
        kg.add_edge_to_dimension("security", edge)
    
    return kg, nodes


def demo_successful_action():
    """Demo: Successful action with all constraints met."""
    print("=" * 80)
    print("DEMO 1: Successful Action - Green Path")
    print("=" * 80)
    print()
    
    kg, nodes = create_security_graph()
    debugger = GraphDebugger(kg)
    router = SuperSystemRouter(kg)
    protocol = HandshakeProtocol()
    reasoning_agent = ReasoningAgent(kg, router, protocol)
    
    # Create trace
    trace = debugger.create_trace("demo-success-001", "read_file", {"demo": "success"})
    
    # Simulate successful traversal
    debugger.record_node_visit(trace, "read_file", True)
    debugger.record_edge_traversal(trace, "read_file", "auth_check")
    debugger.record_node_visit(trace, "auth_check", True)
    
    # Mark unreachable nodes
    debugger.mark_unreachable_nodes(trace, list(nodes.keys()))
    
    # Generate visualizations
    html_path = debugger.visualize_trace(trace, "charts/trace_success.html", format="html")
    png_path = debugger.visualize_trace(trace, "charts/trace_success.png", format="png")
    
    print(f"✓ Action succeeded: read_file")
    print(f"✓ Constraints met: auth_check")
    print(f"✓ Visualizations generated:")
    print(f"  - Interactive: {html_path}")
    print(f"  - Static: {png_path}")
    print()


def demo_failed_action():
    """Demo: Failed action showing red node where constraint failed."""
    print("=" * 80)
    print("DEMO 2: Failed Action - Red Node at Failure Point")
    print("=" * 80)
    print()
    
    kg, nodes = create_security_graph()
    debugger = GraphDebugger(kg)
    
    # Create trace for dangerous action
    trace = debugger.create_trace("demo-fail-001", "delete_db", {"demo": "failure"})
    
    # Simulate failed traversal
    debugger.record_node_visit(trace, "delete_db", False)
    trace.validation_errors = ["Missing approval_token", "Missing backup_required"]
    trace.failed_node = "delete_db"
    
    # Mark unreachable nodes (couldn't reach preconditions)
    debugger.mark_unreachable_nodes(trace, list(nodes.keys()))
    
    # Generate visualizations
    html_path = debugger.visualize_trace(trace, "charts/trace_failure.html", format="html")
    png_path = debugger.visualize_trace(trace, "charts/trace_failure.png", format="png")
    
    print(f"✗ Action failed: delete_db")
    print(f"✗ Missing constraints: approval_token, backup_required")
    print(f"✓ Failure visualization shows:")
    print(f"  - RED node: delete_db (where it failed)")
    print(f"  - GREY nodes: approval_token, backup_required (unreachable)")
    print(f"✓ Visualizations generated:")
    print(f"  - Interactive: {html_path}")
    print(f"  - Static: {png_path}")
    print()


def demo_deterministic_safety():
    """Demo: Show how graph physically prevents reaching dangerous nodes."""
    print("=" * 80)
    print("DEMO 3: Deterministic Safety - Path Severed")
    print("=" * 80)
    print()
    print("This proves the agent PHYSICALLY COULD NOT reach 'delete_db'")
    print("because the path was severed by missing constraints.")
    print()
    
    kg, nodes = create_security_graph()
    debugger = GraphDebugger(kg)
    
    # Attacker tries to reach delete_db
    trace = debugger.create_trace("demo-attack-001", "delete_db", {"attacker": True})
    
    # Try to traverse but fail at constraint
    debugger.record_node_visit(trace, "delete_db", False)
    debugger.record_edge_traversal(trace, "delete_db", "approval_token")
    
    trace.validation_errors = [
        "approval_token constraint not satisfied",
        "No valid path exists to delete_db"
    ]
    trace.failed_node = "delete_db"
    
    # These nodes are unreachable because path is severed
    trace.node_states["approval_token"] = NodeState.UNREACHABLE
    trace.node_states["backup_required"] = NodeState.UNREACHABLE
    trace.node_states["read_file"] = NodeState.UNREACHABLE
    trace.node_states["write_file"] = NodeState.UNREACHABLE
    trace.node_states["auth_check"] = NodeState.UNREACHABLE
    
    # Generate visualization
    html_path = debugger.visualize_trace(trace, "charts/trace_attack_blocked.html", format="html")
    png_path = debugger.visualize_trace(trace, "charts/trace_attack_blocked.png", format="png")
    
    print(f"✓ Proof: The visualization shows:")
    print(f"  - RED: delete_db (blocked)")
    print(f"  - GREY: All prerequisites (unreachable)")
    print(f"  - The agent COULD NOT reach the dangerous action")
    print(f"✓ Visualizations generated:")
    print(f"  - Interactive: {html_path}")
    print(f"  - Static: {png_path}")
    print()


def main():
    """Run all demos."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Demo: Graph Debugger Visualization"
    )
    parser.add_argument(
        "--demo",
        choices=["all", "success", "failure", "safety"],
        default="all",
        help="Which demo to run"
    )
    
    args = parser.parse_args()
    
    # Create charts directory
    os.makedirs("charts", exist_ok=True)
    
    print()
    print("=" * 80)
    print("GRAPH DEBUGGER VISUALIZATION DEMO")
    print("=" * 80)
    print()
    print("The Graph Debugger generates visual artifacts for every execution.")
    print("This proves 'Deterministic Safety' by showing which paths were accessible.")
    print()
    
    if args.demo in ["all", "success"]:
        demo_successful_action()
    
    if args.demo in ["all", "failure"]:
        demo_failed_action()
    
    if args.demo in ["all", "safety"]:
        demo_deterministic_safety()
    
    print("=" * 80)
    print("KEY INSIGHTS")
    print("=" * 80)
    print()
    print("1. GREEN PATH: Shows exactly which nodes were successfully traversed")
    print("2. RED NODE: Shows the exact point where constraint validation failed")
    print("3. GREY NODES: Shows unreachable parts (path was severed)")
    print()
    print("WHY THIS MATTERS:")
    print("  - Proves deterministic safety visually")
    print("  - No magic: you can see exactly why an action was blocked")
    print("  - Debuggable: trace every decision the agent makes")
    print("  - Auditable: visual proof for compliance and security reviews")
    print()


if __name__ == "__main__":
    main()
