# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example usage of the Agent Control Plane

This demonstrates how to use the control plane to govern autonomous agents.
"""

from agent_control_plane import (
    AgentControlPlane,
    create_read_only_agent,
    create_standard_agent,
    create_admin_agent
)
from agent_control_plane.agent_kernel import ActionType, PermissionLevel
from agent_control_plane.policy_engine import ResourceQuota, RiskPolicy


def example_basic_usage():
    """Basic usage example"""
    print("=== Basic Usage Example ===\n")
    
    # Create the control plane
    control_plane = AgentControlPlane()
    
    # Create an agent with standard permissions
    agent_context = create_standard_agent(control_plane, "agent-001")
    print(f"✓ Created agent: {agent_context.agent_id}")
    print(f"  Session ID: {agent_context.session_id}")
    print(f"  Permissions: {list(agent_context.permissions.keys())}\n")
    
    # Execute a file read action
    result = control_plane.execute_action(
        agent_context,
        ActionType.FILE_READ,
        {"path": "/data/sample.txt"}
    )
    
    print(f"✓ File read result:")
    print(f"  Success: {result['success']}")
    print(f"  Risk score: {result.get('risk_score', 'N/A')}")
    if result['success']:
        print(f"  Result: {result['result']}\n")
    else:
        print(f"  Error: {result.get('error', 'Unknown')}\n")
    
    # Try to execute code
    result = control_plane.execute_action(
        agent_context,
        ActionType.CODE_EXECUTION,
        {"code": "print('Hello from agent!')", "language": "python"}
    )
    
    print(f"✓ Code execution result:")
    print(f"  Success: {result['success']}")
    print(f"  Risk score: {result.get('risk_score', 'N/A')}")
    if result['success']:
        print(f"  Result: {result['result']}\n")
    else:
        print(f"  Error: {result.get('error', 'Unknown')}\n")


def example_permission_control():
    """Example showing permission control"""
    print("=== Permission Control Example ===\n")
    
    control_plane = AgentControlPlane()
    
    # Create a read-only agent
    agent_context = create_read_only_agent(control_plane, "read-only-agent")
    print(f"✓ Created read-only agent: {agent_context.agent_id}\n")
    
    # This should succeed
    result = control_plane.execute_action(
        agent_context,
        ActionType.FILE_READ,
        {"path": "/data/public.txt"}
    )
    print(f"✓ File read (allowed): {result['success']}")
    
    # This should fail due to insufficient permissions
    result = control_plane.execute_action(
        agent_context,
        ActionType.FILE_WRITE,
        {"path": "/data/output.txt", "content": "test"}
    )
    print(f"✗ File write (denied): {result['success']}")
    print(f"  Reason: {result.get('error', 'Unknown')}\n")


def example_rate_limiting():
    """Example showing rate limiting"""
    print("=== Rate Limiting Example ===\n")
    
    control_plane = AgentControlPlane()
    
    # Create agent with strict rate limits
    custom_quota = ResourceQuota(
        agent_id="rate-limited-agent",
        max_requests_per_minute=3,
        max_requests_per_hour=10,
        allowed_action_types=[ActionType.FILE_READ]
    )
    
    agent_context = control_plane.create_agent(
        "rate-limited-agent",
        {ActionType.FILE_READ: PermissionLevel.READ_ONLY},
        custom_quota
    )
    
    print(f"✓ Created rate-limited agent")
    print(f"  Max requests per minute: {custom_quota.max_requests_per_minute}\n")
    
    # Make several requests
    for i in range(5):
        result = control_plane.execute_action(
            agent_context,
            ActionType.FILE_READ,
            {"path": f"/data/file{i}.txt"}
        )
        
        status = "✓" if result['success'] else "✗"
        print(f"{status} Request {i+1}: {result['success']}")
        if not result['success']:
            print(f"   Reason: {result.get('error', 'Unknown')}")
    
    # Check quota status
    status = control_plane.get_agent_status("rate-limited-agent")
    print(f"\n✓ Quota status:")
    print(f"  Requests this minute: {status['quota_status']['requests_this_minute']}")
    print(f"  Limit: {status['quota_status']['max_requests_per_minute']}\n")


def example_policy_enforcement():
    """Example showing policy enforcement"""
    print("=== Policy Enforcement Example ===\n")
    
    control_plane = AgentControlPlane()
    agent_context = create_standard_agent(control_plane, "policy-test-agent")
    
    print(f"✓ Created agent with default security policies\n")
    
    # Try to access system files (should be blocked by policy)
    result = control_plane.execute_action(
        agent_context,
        ActionType.FILE_READ,
        {"path": "/etc/passwd"}
    )
    print(f"✗ System file access: {result['success']}")
    print(f"  Reason: {result.get('error', 'Unknown')}\n")
    
    # Try safe file access (should succeed)
    result = control_plane.execute_action(
        agent_context,
        ActionType.FILE_READ,
        {"path": "/data/user_file.txt"}
    )
    print(f"✓ User file access: {result['success']}\n")


def example_audit_logging():
    """Example showing audit logging"""
    print("=== Audit Logging Example ===\n")
    
    control_plane = AgentControlPlane()
    agent_context = create_standard_agent(control_plane, "audited-agent")
    
    # Perform several actions
    control_plane.execute_action(
        agent_context,
        ActionType.FILE_READ,
        {"path": "/data/file1.txt"}
    )
    
    control_plane.execute_action(
        agent_context,
        ActionType.CODE_EXECUTION,
        {"code": "print('test')", "language": "python"}
    )
    
    # Retrieve audit log
    audit_log = control_plane.get_audit_log(limit=10)
    
    print(f"✓ Audit log entries (last 10):")
    for entry in audit_log[-5:]:  # Show last 5
        print(f"  [{entry['timestamp']}] {entry['event_type']}")
        if entry.get('details'):
            print(f"    Details: {entry['details']}")
    print()


def example_risk_management():
    """Example showing risk management"""
    print("=== Risk Management Example ===\n")
    
    control_plane = AgentControlPlane()
    
    # Set a strict risk policy
    risk_policy = RiskPolicy(
        max_risk_score=0.5,
        deny_above=0.8,
        blocked_domains=["malicious.com", "dangerous.net"]
    )
    control_plane.set_risk_policy("strict-policy", risk_policy)
    
    agent_context = create_standard_agent(control_plane, "risk-managed-agent")
    
    print(f"✓ Created agent with strict risk policy")
    print(f"  Max risk score: {risk_policy.max_risk_score}")
    print(f"  Deny above: {risk_policy.deny_above}\n")
    
    # Low risk action (file read)
    result = control_plane.execute_action(
        agent_context,
        ActionType.FILE_READ,
        {"path": "/data/safe.txt"}
    )
    print(f"✓ Low risk action (file read):")
    print(f"  Success: {result['success']}")
    print(f"  Risk score: {result.get('risk_score', 'N/A')}\n")
    
    # Higher risk action (code execution)
    result = control_plane.execute_action(
        agent_context,
        ActionType.CODE_EXECUTION,
        {"code": "import os; os.listdir('/')", "language": "python"}
    )
    print(f"✓ Higher risk action (code execution):")
    print(f"  Success: {result['success']}")
    print(f"  Risk score: {result.get('risk_score', 'N/A')}\n")


def main():
    """Run all examples"""
    print("\n" + "="*60)
    print("  AGENT CONTROL PLANE - EXAMPLES")
    print("="*60 + "\n")
    
    example_basic_usage()
    print("-" * 60 + "\n")
    
    example_permission_control()
    print("-" * 60 + "\n")
    
    example_rate_limiting()
    print("-" * 60 + "\n")
    
    example_policy_enforcement()
    print("-" * 60 + "\n")
    
    example_audit_logging()
    print("-" * 60 + "\n")
    
    example_risk_management()
    print("-" * 60 + "\n")
    
    print("="*60)
    print("  Examples completed!")
    print("="*60 + "\n")


if __name__ == "__main__":
    main()
