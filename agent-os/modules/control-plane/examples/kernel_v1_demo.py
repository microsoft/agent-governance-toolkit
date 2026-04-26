# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Demo: Agent Control Plane v1.0 - The "Kernel" Release

This demo showcases the three main features:
1. Async Support for non-blocking agent operations
2. ABAC (Attribute-Based Access Control) with conditional permissions
3. Flight Recorder for audit logging

Example scenario: A financial agent with context-aware permissions
"""

import asyncio
from agent_control_plane import (
    AgentKernel,
    PolicyEngine,
    Condition,
    ConditionalPermission,
    FlightRecorder,
)


def print_section(title):
    """Print a formatted section header"""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80)


async def demo_async_support():
    """Demo 1: Async Support"""
    print_section("DEMO 1: Async Support")

    policy = PolicyEngine()
    policy.add_constraint(role="agent-1", allowed_tools=["read_data", "analyze"])
    policy.add_constraint(role="agent-2", allowed_tools=["write_report"])

    kernel = AgentKernel(policy_engine=policy)

    # Multiple agents can operate concurrently
    print("\n🚀 Testing concurrent agent operations...")

    results = await asyncio.gather(
        kernel.intercept_tool_execution_async("agent-1", "read_data", {}),
        kernel.intercept_tool_execution_async("agent-2", "write_report", {}),
        kernel.intercept_tool_execution_async("agent-1", "analyze", {}),
    )

    for i, result in enumerate(results, 1):
        status = "✅ ALLOWED" if result.get("allowed") else "❌ BLOCKED"
        print(f"  Operation {i}: {status}")


def demo_abac_conditions():
    """Demo 2: ABAC with Conditional Permissions"""
    print_section("DEMO 2: ABAC (Attribute-Based Access Control)")

    policy = PolicyEngine()

    # Setup: Finance agent can refund IF:
    # 1. User is verified, AND
    # 2. Amount is under $1000
    conditions = [Condition("user_status", "eq", "verified"), Condition("args.amount", "lt", 1000)]
    permission = ConditionalPermission("refund_user", conditions, require_all=True)
    policy.add_conditional_permission("finance-agent", permission)

    kernel = AgentKernel(policy_engine=policy)

    print("\n📋 Policy Rule:")
    print("   'refund_user' allowed IF user_status=='verified' AND amount<1000")

    # Test Case 1: Verified user, low amount (SHOULD ALLOW)
    print("\n🧪 Test 1: Verified user, $500 refund")
    policy.set_agent_context("finance-agent", {"user_status": "verified"})
    result = kernel.intercept_tool_execution("finance-agent", "refund_user", {"amount": 500})
    print(f"   Result: {'✅ ALLOWED' if result is None else '❌ BLOCKED'}")

    # Test Case 2: Verified user, high amount (SHOULD BLOCK)
    print("\n🧪 Test 2: Verified user, $1500 refund")
    policy.set_agent_context("finance-agent", {"user_status": "verified"})
    result = kernel.intercept_tool_execution("finance-agent", "refund_user", {"amount": 1500})
    print(f"   Result: {'✅ ALLOWED' if result is None else '❌ BLOCKED'}")
    if result:
        print(f"   Reason: {result.get('error', 'Unknown')}")

    # Test Case 3: Unverified user, low amount (SHOULD BLOCK)
    print("\n🧪 Test 3: Unverified user, $500 refund")
    policy.set_agent_context("finance-agent", {"user_status": "unverified"})
    result = kernel.intercept_tool_execution("finance-agent", "refund_user", {"amount": 500})
    print(f"   Result: {'✅ ALLOWED' if result is None else '❌ BLOCKED'}")
    if result:
        print(f"   Reason: {result.get('error', 'Unknown')}")


def demo_flight_recorder():
    """Demo 3: Flight Recorder (Black Box Audit Logging)"""
    print_section("DEMO 3: Flight Recorder (Audit Logging)")

    # Create flight recorder
    recorder = FlightRecorder("demo_flight_recorder.db")

    policy = PolicyEngine()
    policy.add_constraint(role="audit-agent", allowed_tools=["read_file", "write_file"])

    # Protect system paths
    policy.protected_paths = ["/etc/", "/sys/"]

    kernel = AgentKernel(policy_engine=policy, audit_logger=recorder)

    print("\n📝 Recording agent actions to flight_recorder.db...")

    # Action 1: Allowed read
    print("\n  Action 1: Read /data/report.txt")
    kernel.intercept_tool_execution(
        "audit-agent",
        "read_file",
        {"path": "/data/report.txt"},
        input_prompt="User: Please read the report",
    )
    print("    ✅ Logged as ALLOWED")

    # Action 2: Blocked write (protected path)
    print("\n  Action 2: Write /etc/passwd")
    kernel.intercept_tool_execution(
        "audit-agent",
        "write_file",
        {"path": "/etc/passwd"},
        input_prompt="User: Update system file",
    )
    print("    ❌ Logged as BLOCKED")

    # Action 3: Blocked (unauthorized tool)
    print("\n  Action 3: Delete file (unauthorized)")
    kernel.intercept_tool_execution(
        "audit-agent",
        "delete_file",
        {"path": "/data/temp.txt"},
        input_prompt="User: Clean up temp files",
    )
    print("    ❌ Logged as BLOCKED")

    # Query the logs
    print("\n📊 Flight Recorder Statistics:")
    stats = recorder.get_statistics()
    print(f"    Total actions: {stats['total_actions']}")
    print(f"    Allowed: {stats['by_verdict'].get('allowed', 0)}")
    print(f"    Blocked: {stats['by_verdict'].get('blocked', 0)}")

    # Show detailed logs
    print("\n📋 Detailed Audit Log:")
    logs = recorder.query_logs(limit=10)
    for log in logs:
        verdict = log["policy_verdict"].upper()
        icon = "✅" if verdict == "ALLOWED" else "❌"
        print(f"    {icon} {log['tool_name']} - {verdict}")
        if log["violation_reason"]:
            print(f"       Reason: {log['violation_reason']}")

    # Cleanup
    recorder.close()
    import os

    if os.path.exists("demo_flight_recorder.db"):
        os.remove("demo_flight_recorder.db")
        print("\n🧹 Cleaned up demo database")


def demo_real_world_scenario():
    """Demo 4: Real-world scenario combining all features"""
    print_section("DEMO 4: Real-World Scenario - E-commerce Agent")

    print("\n🏪 Scenario: E-commerce customer service agent with context-aware permissions")
    print("   - Can process refunds up to $1000 for verified customers")
    print("   - Can only access customer data, not system files")
    print("   - All actions are logged for compliance")

    # Setup
    recorder = FlightRecorder("ecommerce_audit.db")
    policy = PolicyEngine()

    # Define conditional permissions
    refund_conditions = [
        Condition("customer_verified", "eq", True),
        Condition("args.amount", "lte", 1000),
    ]
    refund_permission = ConditionalPermission("process_refund", refund_conditions)
    policy.add_conditional_permission("cs-agent", refund_permission)

    # Also allow basic operations
    policy.add_constraint("cs-agent", ["lookup_order", "process_refund"])

    kernel = AgentKernel(policy_engine=policy, audit_logger=recorder)

    # Scenario: Customer service interactions
    print("\n📞 Customer Service Interactions:")

    # Interaction 1: Lookup order (always allowed)
    print("\n  1. CS Agent: Looking up order #12345...")
    result = kernel.intercept_tool_execution(
        "cs-agent",
        "lookup_order",
        {"order_id": "12345"},
        input_prompt="Customer: What's the status of my order #12345?",
    )
    print(f"     {'✅ SUCCESS' if result is None else '❌ FAILED'}")

    # Interaction 2: Process small refund for verified customer
    print("\n  2. CS Agent: Processing $50 refund for verified customer...")
    policy.set_agent_context("cs-agent", {"customer_verified": True})
    result = kernel.intercept_tool_execution(
        "cs-agent",
        "process_refund",
        {"order_id": "12345", "amount": 50},
        input_prompt="Customer: I'd like a refund for this order",
    )
    print(f"     {'✅ APPROVED - Refund processed' if result is None else '❌ DENIED'}")

    # Interaction 3: Try to process large refund (should require approval)
    print("\n  3. CS Agent: Processing $1500 refund for verified customer...")
    result = kernel.intercept_tool_execution(
        "cs-agent",
        "process_refund",
        {"order_id": "67890", "amount": 1500},
        input_prompt="Customer: I need a refund for this expensive item",
    )
    print(f"     {'✅ APPROVED' if result is None else '❌ DENIED - Amount exceeds limit'}")

    # Show audit trail
    print("\n📊 Compliance Audit Trail:")
    stats = recorder.get_statistics()
    print(f"    Total transactions: {stats['total_actions']}")
    print(f"    Approved: {stats['by_verdict'].get('allowed', 0)}")
    print(f"    Blocked: {stats['by_verdict'].get('blocked', 0)}")

    # Cleanup
    recorder.close()
    import os

    if os.path.exists("ecommerce_audit.db"):
        os.remove("ecommerce_audit.db")


def main():
    """Run all demos"""
    print("\n" + "█" * 80)
    print("█" + " " * 78 + "█")
    print("█" + "  Agent Control Plane v1.0 - The 'Kernel' Release".center(78) + "█")
    print("█" + "  Production-Ready AI Agent Governance".center(78) + "█")
    print("█" + " " * 78 + "█")
    print("█" * 80)

    # Run async demo
    asyncio.run(demo_async_support())

    # Run ABAC demo
    demo_abac_conditions()

    # Run Flight Recorder demo
    demo_flight_recorder()

    # Run real-world scenario
    demo_real_world_scenario()

    print_section("Demo Complete! 🎉")
    print("\nKey Takeaways:")
    print("  ✅ Async support enables concurrent agent operations")
    print("  ✅ ABAC provides context-aware, fine-grained access control")
    print("  ✅ Flight Recorder ensures complete audit trail for compliance")
    print("  ✅ All features work together seamlessly in production scenarios")
    print("\n" + "█" * 80 + "\n")


if __name__ == "__main__":
    main()
