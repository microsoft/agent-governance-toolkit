# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Advanced Examples - Demonstrating new Agent Control Plane features

This module demonstrates:
1. The Mute Agent - capability-based execution
2. Shadow Mode - simulation without execution
3. Constraint Graphs - multi-dimensional context
4. Supervisor Agents - recursive governance
5. Reasoning Telemetry - tracking agent decisions
"""

from datetime import time
from agent_control_plane import AgentControlPlane, create_standard_agent
from agent_control_plane.agent_kernel import ActionType, PermissionLevel
from agent_control_plane.mute_agent import create_mute_sql_agent, create_mute_data_analyst
from agent_control_plane.shadow_mode import add_reasoning_step
from agent_control_plane.supervisor_agents import create_default_supervisor


def example_mute_agent():
    """
    Example 1: The Mute Agent - Scale by Subtraction
    
    The Mute Agent knows when to shut up. It only executes actions within
    its defined capabilities and returns NULL for out-of-scope requests.
    """
    print("=== Example 1: The Mute Agent ===\n")
    
    # Create control plane
    control_plane = AgentControlPlane()
    
    # Create a SQL agent with strict capabilities
    sql_agent_config = create_mute_sql_agent("sql-agent-001")
    
    # Create agent in control plane
    permissions = {ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY}
    agent_context = control_plane.create_agent("sql-agent-001", permissions)
    
    # Enable mute agent mode
    control_plane.enable_mute_agent("sql-agent-001", sql_agent_config)
    
    print("✓ Created Mute SQL Agent with strict capabilities")
    print("  Capabilities: Only SELECT queries\n")
    
    # Valid request: SELECT query
    result1 = control_plane.execute_action(
        agent_context,
        ActionType.DATABASE_QUERY,
        {"query": "SELECT * FROM users WHERE id = 1"}
    )
    print(f"Test 1 - Valid SELECT query:")
    print(f"  Success: {result1['success']}")
    if result1['success']:
        print(f"  Result: {result1['result']}\n")
    
    # Invalid request: DROP TABLE (destructive operation)
    result2 = control_plane.execute_action(
        agent_context,
        ActionType.DATABASE_QUERY,
        {"query": "DROP TABLE users"}
    )
    print(f"Test 2 - Invalid DROP TABLE query:")
    print(f"  Success: {result2['success']}")
    print(f"  Error: {result2.get('error', 'N/A')}")
    print(f"  ➜ Agent returns NULL instead of hallucinating!\n")
    
    # Out of scope request: File operations
    result3 = control_plane.execute_action(
        agent_context,
        ActionType.FILE_READ,
        {"path": "/data/file.txt"}
    )
    print(f"Test 3 - Out of scope (file read):")
    print(f"  Success: {result3['success']}")
    print(f"  Error: {result3.get('error', 'N/A')}")
    print(f"  ➜ Agent knows it can't do this, returns NULL!\n")
    
    print("-" * 60 + "\n")


def example_shadow_mode():
    """
    Example 2: Shadow Mode - The Matrix for Agents
    
    Agents think they're executing, but we're just simulating and logging
    their intent. Perfect for testing before production.
    """
    print("=== Example 2: Shadow Mode - Simulation ===\n")
    
    # Create control plane with shadow mode enabled
    control_plane = AgentControlPlane(enable_shadow_mode=True)
    
    print("✓ Shadow Mode ENABLED - All executions will be simulated\n")
    
    # Create a standard agent
    agent_context = create_standard_agent(control_plane, "test-agent")
    
    # Build a reasoning chain (showing what the agent was thinking)
    reasoning_chain = []
    add_reasoning_step(
        reasoning_chain,
        "User asked to read customer data",
        ActionType.FILE_READ,
        {"path": "/data/customers.csv"},
        "File read is safe and within permissions"
    )
    add_reasoning_step(
        reasoning_chain,
        "Need to process the data",
        ActionType.CODE_EXECUTION,
        {"code": "process_csv(data)", "language": "python"},
        "Processing is required to answer the question"
    )
    
    # Execute with reasoning chain
    result = control_plane.execute_action(
        agent_context,
        ActionType.FILE_READ,
        {"path": "/data/customers.csv"},
        reasoning_chain=reasoning_chain
    )
    
    print("Execution Result:")
    print(f"  Success: {result['success']}")
    print(f"  Status: {result.get('status')}")
    print(f"  Outcome: {result.get('outcome')}")
    print(f"  Note: {result.get('note')}")
    print(f"  Result: {result.get('result')}")
    
    # Get shadow mode statistics
    stats = control_plane.get_shadow_statistics()
    print(f"\nShadow Mode Statistics:")
    print(f"  Total simulations: {stats['total_simulations']}")
    print(f"  Success rate: {stats['success_rate']:.1%}")
    print(f"  Outcome distribution: {stats['outcome_distribution']}")
    
    print("\n" + "-" * 60 + "\n")


def example_constraint_graphs():
    """
    Example 3: Constraint Graphs - Multi-Dimensional Context
    
    Context isn't flat; it's a graph. We define what data exists (Data Graph),
    what's allowed (Policy Graph), and what's true right now (Temporal Graph).
    """
    print("=== Example 3: Constraint Graphs ===\n")
    
    # Create control plane with constraint graphs enabled
    control_plane = AgentControlPlane(enable_constraint_graphs=True)
    
    print("✓ Constraint Graphs ENABLED\n")
    
    # 1. Build Data Graph - What data exists
    print("Building Data Graph...")
    control_plane.add_data_table(
        "users",
        schema={"id": "int", "name": "string", "email": "string"},
        metadata={"classification": "internal"}
    )
    control_plane.add_data_table(
        "financial_data",
        schema={"id": "int", "amount": "decimal", "account": "string"},
        metadata={"classification": "sensitive"}
    )
    control_plane.add_data_path("/data/", access_level="read")
    control_plane.add_data_path("/reports/", access_level="read")
    print("  ✓ Added tables: users, financial_data")
    print("  ✓ Added paths: /data/, /reports/\n")
    
    # 2. Build Policy Graph - What rules apply
    print("Building Policy Graph...")
    control_plane.add_policy_constraint(
        "pii_protection",
        "No PII in output",
        applies_to=["table:users"],
        rule_type="deny"
    )
    control_plane.add_policy_constraint(
        "finance_approval",
        "Requires CFO approval",
        applies_to=["table:financial_data"],
        rule_type="require_approval"
    )
    print("  ✓ Added PII protection for users table")
    print("  ✓ Added approval requirement for financial_data\n")
    
    # 3. Build Temporal Graph - What's true RIGHT NOW
    print("Building Temporal Graph...")
    control_plane.add_maintenance_window(
        "nightly_maintenance",
        start_time=time(2, 0),  # 2 AM
        end_time=time(4, 0),    # 4 AM
        blocked_actions=[ActionType.DATABASE_WRITE, ActionType.FILE_WRITE]
    )
    print("  ✓ Added maintenance window: 2 AM - 4 AM (blocks writes)\n")
    
    # Create an agent
    agent_context = create_standard_agent(control_plane, "data-agent")
    
    # Test 1: Query accessible table
    print("Test 1 - Query users table (in Data Graph):")
    result1 = control_plane.execute_action(
        agent_context,
        ActionType.DATABASE_QUERY,
        {"table": "users", "query": "SELECT * FROM users"}
    )
    print(f"  Success: {result1['success']}")
    if not result1['success']:
        print(f"  Violations: {result1.get('violations', [])}\n")
    
    # Test 2: Query non-existent table
    print("Test 2 - Query unknown table (NOT in Data Graph):")
    result2 = control_plane.execute_action(
        agent_context,
        ActionType.DATABASE_QUERY,
        {"table": "secrets", "query": "SELECT * FROM secrets"}
    )
    print(f"  Success: {result2['success']}")
    if not result2['success']:
        print(f"  Error: {result2['error']}")
        print(f"  ➜ Constraint Graph blocked access!\n")
    
    # Test 3: Access file outside allowed paths
    print("Test 3 - Access file outside Data Graph:")
    result3 = control_plane.execute_action(
        agent_context,
        ActionType.FILE_READ,
        {"path": "/etc/passwd"}
    )
    print(f"  Success: {result3['success']}")
    if not result3['success']:
        print(f"  Error: {result3['error']}")
        print(f"  ➜ Path not in accessible data graph!\n")
    
    print("-" * 60 + "\n")


def example_supervisor_agents():
    """
    Example 4: Supervisor Agents - Agents Watching Agents
    
    Supervisor agents are highly constrained agents that watch worker agents
    and flag violations. This is recursive governance.
    """
    print("=== Example 4: Supervisor Agents - Recursive Governance ===\n")
    
    # Create control plane
    control_plane = AgentControlPlane()
    
    # Create worker agents
    agent1 = create_standard_agent(control_plane, "worker-agent-1")
    agent2 = create_standard_agent(control_plane, "worker-agent-2")
    
    print("✓ Created 2 worker agents\n")
    
    # Create a supervisor to watch them
    supervisor = create_default_supervisor(["worker-agent-1", "worker-agent-2"])
    control_plane.add_supervisor(supervisor)
    
    print("✓ Created supervisor agent")
    print(f"  Watching: {supervisor.config.watches}")
    print(f"  Detection rules: {len(supervisor.config.detection_rules)}\n")
    
    # Simulate some agent activity
    print("Simulating agent activity...")
    for i in range(3):
        control_plane.execute_action(
            agent1,
            ActionType.FILE_READ,
            {"path": f"/data/file{i}.txt"}
        )
    
    # Try some actions that fail
    for i in range(6):
        control_plane.execute_action(
            agent1,
            ActionType.CODE_EXECUTION,
            {"code": f"raise Exception('Test error {i}')", "language": "python"}
        )
    
    print("  ✓ Executed 3 file reads")
    print("  ✓ Executed 6 code executions (some may fail)\n")
    
    # Run supervision
    print("Running supervision cycle...")
    violations = control_plane.run_supervision()
    
    print(f"✓ Supervision complete\n")
    
    # Display violations
    for supervisor_id, viols in violations.items():
        print(f"Violations detected by {supervisor_id}:")
        for v in viols:
            print(f"  - [{v.severity.upper()}] {v.violation_type.value}")
            print(f"    {v.description}")
    
    if not any(violations.values()):
        print("  No violations detected (all agents behaving normally)")
    
    print("\n" + "-" * 60 + "\n")


def example_integrated_workflow():
    """
    Example 5: Integrated Workflow - All Features Together
    
    Demonstrates how all features work together for comprehensive governance.
    """
    print("=== Example 5: Integrated Workflow - Everything Together ===\n")
    
    # Create control plane with all features
    control_plane = AgentControlPlane(
        enable_default_policies=True,
        enable_shadow_mode=True,  # Start in shadow mode
        enable_constraint_graphs=True
    )
    
    print("✓ Control Plane initialized with:")
    print("  - Default security policies")
    print("  - Shadow mode (for safe testing)")
    print("  - Constraint graphs (multi-dimensional context)\n")
    
    # Setup constraint graphs
    control_plane.add_data_table("customers", {"id": "int", "name": "string"})
    control_plane.add_data_path("/data/")
    
    # Create a mute SQL agent
    sql_config = create_mute_sql_agent("sql-bot")
    permissions = {ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY}
    agent = control_plane.create_agent("sql-bot", permissions)
    control_plane.enable_mute_agent("sql-bot", sql_config)
    
    # Create supervisor
    supervisor = create_default_supervisor(["sql-bot"])
    control_plane.add_supervisor(supervisor)
    
    print("✓ Created SQL agent with:")
    print("  - Mute Agent capabilities (only SELECT queries)")
    print("  - Supervisor monitoring\n")
    
    # Test in shadow mode
    print("Testing in Shadow Mode...")
    result = control_plane.execute_action(
        agent,
        ActionType.DATABASE_QUERY,
        {"table": "customers", "query": "SELECT * FROM customers"}
    )
    print(f"  Success: {result['success']}")
    print(f"  Status: {result.get('status')}")
    print(f"  Note: {result.get('note', 'N/A')}\n")
    
    # Switch to production mode
    print("Switching to Production Mode...")
    control_plane.enable_shadow_mode(False)
    
    result2 = control_plane.execute_action(
        agent,
        ActionType.DATABASE_QUERY,
        {"table": "customers", "query": "SELECT * FROM customers"}
    )
    print(f"  Success: {result2['success']}")
    print(f"  Status: Production execution\n")
    
    # Run supervision
    print("Running supervision...")
    violations = control_plane.run_supervision()
    print(f"  Violations: {sum(len(v) for v in violations.values())}\n")
    
    # Get comprehensive status
    print("System Status:")
    shadow_stats = control_plane.get_shadow_statistics()
    print(f"  Shadow simulations: {shadow_stats['total_simulations']}")
    
    supervisor_summary = control_plane.get_supervisor_summary()
    print(f"  Supervisors active: {supervisor_summary['total_supervisors']}")
    
    agent_status = control_plane.get_agent_status("sql-bot")
    print(f"  Agent executions: {len(agent_status['execution_history'])}")
    
    print("\n" + "-" * 60 + "\n")


def main():
    """Run all advanced examples"""
    print("=" * 60)
    print("  AGENT CONTROL PLANE - ADVANCED FEATURES")
    print("=" * 60)
    print()
    
    example_mute_agent()
    example_shadow_mode()
    example_constraint_graphs()
    example_supervisor_agents()
    example_integrated_workflow()
    
    print("=" * 60)
    print("  All advanced examples completed!")
    print("=" * 60)


if __name__ == "__main__":
    main()
