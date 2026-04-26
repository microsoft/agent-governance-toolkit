# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Demo: Agent Kernel Tool Interceptor Pattern

This demonstrates the "Hypervisor" pattern where the Agent Kernel
intercepts tool calls BEFORE they execute, enforcing constraints
at the kernel level.
"""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.agent_control_plane.agent_kernel import AgentKernel
from src.agent_control_plane.policy_engine import PolicyEngine


def demo_basic_interception():
    """Demonstrate basic tool interception without policy engine"""
    print("\n" + "="*70)
    print("DEMO 1: Basic Tool Interception (Shadow Mode)")
    print("="*70)
    
    # Create kernel in shadow mode
    kernel = AgentKernel(shadow_mode=True)
    
    # Attempt to execute a tool
    result = kernel.intercept_tool_execution(
        agent_id="test-agent",
        tool_name="write_file",
        tool_args={"path": "/data/test.txt", "content": "Hello"}
    )
    
    print(f"\nTool: write_file")
    print(f"Result: {result}")
    print(f"Status: {result['status']}")
    print(f"Note: In shadow mode, NO actual execution happens!")


def demo_constraint_graph():
    """Demonstrate constraint graph enforcement (Scale by Subtraction)"""
    print("\n" + "="*70)
    print("DEMO 2: Constraint Graph Enforcement (Allow-List)")
    print("="*70)
    
    # Create policy engine and define constraints
    policy = PolicyEngine()
    
    # Define the "Physics" of a finance agent
    # By NOT listing tools, they are implicitly BLOCKED
    policy.add_constraint(
        role="finance_agent",
        allowed_tools=["read_balance", "calculate_tax"]
    )
    
    # Create kernel with policy enforcement
    kernel = AgentKernel(policy_engine=policy, shadow_mode=False)
    
    # Test 1: Allowed action
    print("\n--- Test 1: ALLOWED Action ---")
    result = kernel.intercept_tool_execution(
        agent_id="finance_agent",
        tool_name="read_balance",
        tool_args={"account_id": "12345"}
    )
    print(f"Tool: read_balance")
    print(f"Result: {result}")
    print(f"Status: {'ALLOWED (None = proceed)' if result is None else 'BLOCKED'}")
    
    # Test 2: Blocked action (not in allow-list)
    print("\n--- Test 2: BLOCKED Action (Not in Allow-List) ---")
    result = kernel.intercept_tool_execution(
        agent_id="finance_agent",
        tool_name="transfer_funds",
        tool_args={"amount": 1000000, "to": "offshore"}
    )
    print(f"Tool: transfer_funds")
    print(f"Result: {result}")
    print(f"Status: {result['status']}")
    print(f"Error: {result['error']}")
    print(f"Mute: {result['mute']} (Returns NULL, not verbose refusal)")


def demo_argument_validation():
    """Demonstrate argument-based validation"""
    print("\n" + "="*70)
    print("DEMO 3: Argument-Based Validation")
    print("="*70)
    
    # Create policy engine
    policy = PolicyEngine()
    
    # Allow write_file, but restrict paths
    policy.add_constraint(
        role="data_agent",
        allowed_tools=["write_file", "read_file"]
    )
    
    kernel = AgentKernel(policy_engine=policy, shadow_mode=False)
    
    # Test 1: Safe path (should be allowed)
    print("\n--- Test 1: Safe Path ---")
    result = kernel.intercept_tool_execution(
        agent_id="data_agent",
        tool_name="write_file",
        tool_args={"path": "/data/report.txt", "content": "Report"}
    )
    print(f"Tool: write_file (path=/data/report.txt)")
    print(f"Result: {result}")
    print(f"Status: {'ALLOWED' if result is None else 'BLOCKED'}")
    
    # Test 2: Dangerous path (should be blocked)
    print("\n--- Test 2: Dangerous Path (/etc/) ---")
    result = kernel.intercept_tool_execution(
        agent_id="data_agent",
        tool_name="write_file",
        tool_args={"path": "/etc/passwd", "content": "evil"}
    )
    print(f"Tool: write_file (path=/etc/passwd)")
    print(f"Result: {result}")
    print(f"Status: {result['status']}")
    print(f"Error: {result['error']}")


def demo_scale_by_subtraction():
    """Demonstrate Scale by Subtraction philosophy"""
    print("\n" + "="*70)
    print("DEMO 4: Scale by Subtraction (The Killer Feature)")
    print("="*70)
    
    policy = PolicyEngine()
    
    # Create TWO agents with DIFFERENT constraints
    # SQL Agent: ONLY read queries
    policy.add_constraint(
        role="sql_agent",
        allowed_tools=["execute_query"]
    )
    
    # Admin Agent: Full access
    policy.add_constraint(
        role="admin_agent",
        allowed_tools=["execute_query", "execute_update", "execute_delete", "backup_database"]
    )
    
    kernel = AgentKernel(policy_engine=policy, shadow_mode=False)
    
    # SQL Agent tries to DELETE (BLOCKED)
    print("\n--- SQL Agent (Read-Only) tries DELETE ---")
    result = kernel.intercept_tool_execution(
        agent_id="sql_agent",
        tool_name="execute_delete",
        tool_args={"query": "DELETE FROM users"}
    )
    print(f"Result: {result['status'] if result else 'ALLOWED'}")
    if result:
        print(f"Reason: {result['error']}")
    
    # Admin Agent tries DELETE (ALLOWED)
    print("\n--- Admin Agent tries DELETE ---")
    result = kernel.intercept_tool_execution(
        agent_id="admin_agent",
        tool_name="execute_delete",
        tool_args={"query": "DELETE FROM temp_cache"}
    )
    print(f"Result: {'ALLOWED' if result is None else result['status']}")
    
    # SQL Agent tries to use backup (BLOCKED)
    print("\n--- SQL Agent tries BACKUP ---")
    result = kernel.intercept_tool_execution(
        agent_id="sql_agent",
        tool_name="backup_database",
        tool_args={}
    )
    print(f"Result: {result['status'] if result else 'ALLOWED'}")
    if result:
        print(f"Reason: {result['error']}")
    
    print("\n" + "="*70)
    print("KEY INSIGHT: Scale by Subtraction")
    print("="*70)
    print("By defining ONLY what's allowed, everything else is blocked.")
    print("No need to enumerate all possible dangerous actions.")
    print("This is the 'Physics' of the agent's world.")


if __name__ == "__main__":
    demo_basic_interception()
    demo_constraint_graph()
    demo_argument_validation()
    demo_scale_by_subtraction()
    
    print("\n" + "="*70)
    print("SUMMARY: The Kernel as Hypervisor")
    print("="*70)
    print("✓ Tool calls are intercepted BEFORE execution")
    print("✓ Constraint graphs define what's possible (allow-list)")
    print("✓ Violations return NULL (Mute Protocol), not verbose refusals")
    print("✓ Shadow mode lets you test without side effects")
    print("✓ Scale by Subtraction: Define allowed, block everything else")
    print()
