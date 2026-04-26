# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Real-World Use Cases for Agent Control Plane

This example demonstrates practical, production-ready scenarios.
"""

from datetime import time, datetime
from agent_control_plane import AgentControlPlane, create_standard_agent
from agent_control_plane.agent_kernel import ActionType, PermissionLevel
from agent_control_plane.policy_engine import ResourceQuota
from agent_control_plane.shadow_mode import ShadowModeConfig
from agent_control_plane.constraint_graphs import (
    DataGraph, TemporalGraph, GraphNode, GraphNodeType
)


def use_case_1_data_analysis_pipeline():
    """
    Use Case 1: Data Analysis Pipeline
    
    An AI agent that analyzes customer data but must:
    - Only read from approved data sources
    - Never write to production databases
    - Respect PII restrictions
    - Stay within rate limits
    """
    print("=" * 70)
    print("USE CASE 1: Data Analysis Pipeline")
    print("=" * 70)
    print()
    
    control_plane = AgentControlPlane()
    
    # Create a data analyst agent with restricted permissions
    permissions = {
        ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY,
        ActionType.API_CALL: PermissionLevel.READ_ONLY,
    }
    
    agent = control_plane.create_agent("data-analyst", permissions)
    
    # Set conservative rate limits
    quota = ResourceQuota(
        agent_id="data-analyst",
        max_requests_per_minute=30,
        max_requests_per_hour=500
    )
    control_plane.policy_engine.set_quota("data-analyst", quota)
    
    # Set up data graph for allowed data sources
    data_graph = DataGraph()
    data_graph.add_node(GraphNode(
        id="customer_analytics",
        node_type=GraphNodeType.TABLE,
        metadata={"database": "analytics", "table": "customer_summary"}
    ))
    data_graph.add_node(GraphNode(
        id="sales_reports",
        node_type=GraphNodeType.FILE,
        metadata={"path": "/data/reports/sales/"}
    ))
    
    control_plane.set_data_graph("data-analyst", data_graph)
    
    print("✓ Data analyst agent configured")
    print("  - Read-only access to approved data sources")
    print("  - Rate limited to 30 req/min")
    print("  - Cannot modify any data")
    print()
    
    # Simulate analysis workflow
    print("Executing analysis workflow...")
    
    # Step 1: Read customer data
    result1 = control_plane.execute_action(
        agent,
        ActionType.DATABASE_QUERY,
        {"query": "SELECT customer_segment, AVG(purchase_value) FROM customer_summary GROUP BY customer_segment"}
    )
    print(f"  1. Query customer segments: {result1['success']}")
    
    # Step 2: Read sales report
    result2 = control_plane.execute_action(
        agent,
        ActionType.FILE_READ,
        {"path": "/data/reports/sales/monthly.csv"}
    )
    print(f"  2. Read sales report: {result2['success']}")
    
    # Step 3: Try to write (should be denied)
    result3 = control_plane.execute_action(
        agent,
        ActionType.FILE_WRITE,
        {"path": "/data/reports/output.csv", "content": "analysis results"}
    )
    print(f"  3. Attempt to write output: {result3['success']} (correctly denied)")
    
    print()
    print("✓ Analysis pipeline completed safely")
    print()


def use_case_2_content_moderation():
    """
    Use Case 2: Content Moderation Agent
    
    An AI agent that moderates user-generated content:
    - Can read content submissions
    - Can flag content for review
    - Cannot delete content directly
    - Must operate within business hours
    """
    print("=" * 70)
    print("USE CASE 2: Content Moderation Agent")
    print("=" * 70)
    print()
    
    control_plane = AgentControlPlane()
    
    # Create moderation agent
    permissions = {
        ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY,
        ActionType.API_CALL: PermissionLevel.READ_WRITE,  # Can call moderation API
    }
    
    agent = control_plane.create_agent("content-moderator", permissions)
    
    # Set temporal constraints - only operate during business hours
    temporal_graph = TemporalGraph()
    temporal_graph.set_business_hours(
        time(9, 0),   # 9 AM
        time(17, 0)   # 5 PM
    )
    
    control_plane.set_temporal_graph("content-moderator", temporal_graph)
    
    print("✓ Content moderation agent configured")
    print("  - Can read and analyze content")
    print("  - Can flag for human review")
    print("  - Cannot delete content")
    print("  - Only operates 9 AM - 5 PM")
    print()
    
    print("Moderating content submissions...")
    
    # Analyze content
    result1 = control_plane.execute_action(
        agent,
        ActionType.FILE_READ,
        {"path": "/content/submissions/post_12345.json"}
    )
    print(f"  1. Read submission: {result1['success']}")
    
    # Flag for review via API
    result2 = control_plane.execute_action(
        agent,
        ActionType.API_CALL,
        {
            "url": "https://api.example.com/content/flag",
            "method": "POST",
            "data": {"post_id": "12345", "reason": "possible_violation"}
        }
    )
    print(f"  2. Flag for review: {result2['success']}")
    
    print()
    print("✓ Content moderation completed")
    print()


def use_case_3_testing_in_shadow_mode():
    """
    Use Case 3: Testing New Agent in Shadow Mode
    
    Test a new autonomous agent in shadow mode before production:
    - Agent thinks it's executing real actions
    - Control plane intercepts everything
    - Validate behavior without side effects
    - Analyze decision patterns
    """
    print("=" * 70)
    print("USE CASE 3: Testing in Shadow Mode")
    print("=" * 70)
    print()
    
    control_plane = AgentControlPlane()
    
    # Create experimental agent
    agent = create_standard_agent(control_plane, "experimental-agent")
    
    # Enable shadow mode for safe testing
    shadow_config = ShadowModeConfig(
        enabled=True,
        log_reasoning=True
    )
    control_plane.enable_shadow_mode("experimental-agent", shadow_config)
    
    print("✓ Experimental agent in shadow mode")
    print("  - All actions are simulated")
    print("  - No real side effects")
    print("  - Full reasoning telemetry")
    print()
    
    print("Testing agent behavior in shadow mode...")
    
    # Execute various actions (all simulated)
    actions = [
        (ActionType.FILE_READ, {"path": "/data/config.json"}),
        (ActionType.API_CALL, {"url": "https://api.example.com/data"}),
        (ActionType.DATABASE_QUERY, {"query": "SELECT * FROM users LIMIT 10"}),
        (ActionType.FILE_WRITE, {"path": "/tmp/output.txt", "content": "test"}),
    ]
    
    for i, (action_type, params) in enumerate(actions, 1):
        result = control_plane.execute_action(agent, action_type, params)
        print(f"  {i}. {action_type.value}: Simulated (would have {'succeeded' if result['success'] else 'failed'})")
    
    print()
    
    # Get shadow mode statistics
    shadow_logs = control_plane.get_shadow_mode_log("experimental-agent")
    print(f"✓ Shadow mode test complete")
    print(f"  - {len(shadow_logs)} actions simulated")
    print(f"  - No real side effects occurred")
    print(f"  - Ready to analyze agent behavior")
    print()


def use_case_4_multi_tenant_saas():
    """
    Use Case 4: Multi-Tenant SaaS Application
    
    Multiple customer tenants, each with their own agent:
    - Isolated permissions per tenant
    - Individual rate limits
    - Tenant-specific data access
    - Cost tracking per tenant
    """
    print("=" * 70)
    print("USE CASE 4: Multi-Tenant SaaS Application")
    print("=" * 70)
    print()
    
    control_plane = AgentControlPlane()
    
    # Create agents for different tenants
    tenants = ["acme-corp", "globex-inc", "initech-llc"]
    
    for tenant in tenants:
        # Each tenant gets their own agent
        agent = create_standard_agent(control_plane, f"{tenant}-agent")
        
        # Tenant-specific quotas (different tiers)
        if tenant == "acme-corp":
            # Premium tier
            quota = ResourceQuota(
                agent_id=f"{tenant}-agent",
                max_requests_per_minute=100,
                max_requests_per_hour=5000
            )
        else:
            # Standard tier
            quota = ResourceQuota(
                agent_id=f"{tenant}-agent",
                max_requests_per_minute=30,
                max_requests_per_hour=1000
            )
        
        control_plane.policy_engine.set_quota(f"{tenant}-agent", quota)
        
        # Tenant-specific data isolation
        data_graph = DataGraph()
        data_graph.add_node(GraphNode(
            id=f"{tenant}_data",
            node_type=GraphNodeType.DIRECTORY,
            metadata={"path": f"/data/tenants/{tenant}/"}
        ))
        control_plane.set_data_graph(f"{tenant}-agent", data_graph)
    
    print("✓ Multi-tenant environment configured")
    print(f"  - {len(tenants)} tenant agents created")
    print("  - Each with isolated data access")
    print("  - Individual rate limits per tier")
    print()
    
    # Simulate tenant activity
    for tenant in tenants:
        agent = control_plane.kernel.get_agent_context(f"{tenant}-agent")
        if agent:
            result = control_plane.execute_action(
                agent,
                ActionType.FILE_READ,
                {"path": f"/data/tenants/{tenant}/config.json"}
            )
            quota_status = control_plane.policy_engine.get_quota_status(f"{tenant}-agent")
            print(f"  {tenant}: Action {'succeeded' if result['success'] else 'failed'}, "
                  f"{quota_status['requests_this_minute']}/{quota_status['max_requests_per_minute']} requests")
    
    print()
    print("✓ Multi-tenant operations completed")
    print()


def main():
    """Run all use case examples"""
    print()
    print("=" * 70)
    print("AGENT CONTROL PLANE - REAL-WORLD USE CASES")
    print("=" * 70)
    print()
    
    use_case_1_data_analysis_pipeline()
    input("Press Enter for next use case...")
    print()
    
    use_case_2_content_moderation()
    input("Press Enter for next use case...")
    print()
    
    use_case_3_testing_in_shadow_mode()
    input("Press Enter for next use case...")
    print()
    
    use_case_4_multi_tenant_saas()
    
    print()
    print("=" * 70)
    print("ALL USE CASES COMPLETED")
    print("=" * 70)
    print()


if __name__ == "__main__":
    main()
