# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Getting Started with Agent Control Plane

This beginner-friendly example walks through the basics step-by-step.
"""

from agent_control_plane import AgentControlPlane, create_standard_agent
from agent_control_plane.agent_kernel import ActionType


def step1_create_control_plane():
    """Step 1: Create the Control Plane"""
    print("=" * 60)
    print("STEP 1: Creating the Control Plane")
    print("=" * 60)
    print()
    
    # The control plane is the main interface for managing agents
    control_plane = AgentControlPlane()
    
    print("✓ Control plane created successfully!")
    print("  The control plane will manage all agent operations")
    print()
    
    return control_plane


def step2_create_agent(control_plane):
    """Step 2: Create an Agent"""
    print("=" * 60)
    print("STEP 2: Creating an Agent")
    print("=" * 60)
    print()
    
    # Create a standard agent with typical permissions
    agent = create_standard_agent(control_plane, "my-first-agent")
    
    print(f"✓ Agent created: {agent.agent_id}")
    print(f"  Session ID: {agent.session_id}")
    print(f"  Number of permissions: {len(agent.permissions)}")
    print()
    
    return agent


def step3_execute_simple_action(control_plane, agent):
    """Step 3: Execute a Simple Action"""
    print("=" * 60)
    print("STEP 3: Executing a Simple File Read")
    print("=" * 60)
    print()
    
    # Execute a simple file read action
    result = control_plane.execute_action(
        agent,
        ActionType.FILE_READ,
        {"path": "/data/example.txt"}
    )
    
    print(f"✓ Action executed")
    print(f"  Success: {result['success']}")
    print(f"  Risk Score: {result.get('risk_score', 'N/A')}")
    
    if result['success']:
        print(f"  Result preview: {str(result['result'])[:100]}...")
    else:
        print(f"  Error: {result.get('error', 'Unknown')}")
    
    print()
    return result


def step4_check_audit_log(control_plane, agent):
    """Step 4: Check the Audit Log"""
    print("=" * 60)
    print("STEP 4: Viewing Audit Logs")
    print("=" * 60)
    print()
    
    # Get audit log for our agent
    logs = control_plane.get_audit_log(agent.agent_id)
    
    print(f"✓ Found {len(logs)} audit entries")
    print()
    
    if logs:
        print("  Most recent entry:")
        latest = logs[-1]
        print(f"  - Action: {latest.get('action_type', 'N/A')}")
        print(f"  - Status: {latest.get('status', 'N/A')}")
        print(f"  - Timestamp: {latest.get('timestamp', 'N/A')}")
    
    print()


def step5_try_denied_action(control_plane, agent):
    """Step 5: Try an Action Without Permission"""
    print("=" * 60)
    print("STEP 5: Testing Permission Denial")
    print("=" * 60)
    print()
    
    # Standard agents don't have ADMIN permissions
    # Try to execute a high-risk operation
    result = control_plane.execute_action(
        agent,
        ActionType.DATABASE_WRITE,
        {"query": "DELETE FROM users"}
    )
    
    print(f"  Action attempted: Database Write")
    print(f"  Success: {result['success']}")
    
    if not result['success']:
        print(f"  ✓ Correctly denied")
        print(f"  Reason: {result.get('error', 'Unknown')}")
    else:
        print(f"  Note: Action was allowed (check permissions)")
    
    print()


def main():
    """Main function - Run all steps"""
    print()
    print("*" * 60)
    print("*" + " " * 58 + "*")
    print("*" + "  GETTING STARTED WITH AGENT CONTROL PLANE".center(58) + "*")
    print("*" + " " * 58 + "*")
    print("*" * 60)
    print()
    print("This tutorial will walk you through:")
    print("1. Creating a control plane")
    print("2. Creating an agent")
    print("3. Executing actions")
    print("4. Viewing audit logs")
    print("5. Testing permissions")
    print()
    input("Press Enter to continue...")
    print()
    
    # Step 1: Create control plane
    control_plane = step1_create_control_plane()
    input("Press Enter to continue to Step 2...")
    print()
    
    # Step 2: Create agent
    agent = step2_create_agent(control_plane)
    input("Press Enter to continue to Step 3...")
    print()
    
    # Step 3: Execute action
    step3_execute_simple_action(control_plane, agent)
    input("Press Enter to continue to Step 4...")
    print()
    
    # Step 4: Check audit log
    step4_check_audit_log(control_plane, agent)
    input("Press Enter to continue to Step 5...")
    print()
    
    # Step 5: Try denied action
    step5_try_denied_action(control_plane, agent)
    
    print()
    print("=" * 60)
    print("TUTORIAL COMPLETE!")
    print("=" * 60)
    print()
    print("Next steps:")
    print("- Try basic_usage.py for more examples")
    print("- Try advanced_features.py for advanced capabilities")
    print("- Read the documentation in docs/")
    print()


if __name__ == "__main__":
    main()
