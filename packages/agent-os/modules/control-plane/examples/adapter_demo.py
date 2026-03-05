# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
OpenAI Adapter Demo - Drop-In Middleware for Agent Control Plane

This example demonstrates the "zero-friction" integration pattern
where developers can continue using the OpenAI SDK while benefiting
from Agent Control Plane governance.

The key insight: No need to change agent code. Just wrap the client.
"""

from agent_control_plane import (
    AgentControlPlane,
    ControlPlaneAdapter,
    create_governed_client,
    ActionType,
    PermissionLevel,
)


class MockOpenAIClient:
    """
    Mock OpenAI client for demonstration purposes.
    
    In production, this would be: from openai import OpenAI
    """
    
    class MockFunction:
        def __init__(self, name, arguments):
            self.name = name
            self.arguments = arguments
    
    class MockToolCall:
        def __init__(self, name, arguments):
            self.id = f"call_{name}"
            self.type = "function"
            self.function = MockOpenAIClient.MockFunction(name, arguments)
    
    class MockMessage:
        def __init__(self, tool_calls=None):
            self.role = "assistant"
            self.content = None
            self.tool_calls = tool_calls or []
    
    class MockChoice:
        def __init__(self, message):
            self.index = 0
            self.message = message
            self.finish_reason = "tool_calls"
    
    class MockResponse:
        def __init__(self, choices):
            self.id = "chatcmpl-mock"
            self.object = "chat.completion"
            self.model = "gpt-4"
            self.choices = choices
    
    class MockCompletions:
        def create(self, **kwargs):
            """Simulate OpenAI API response with tool calls"""
            import json
            
            # Simulate LLM deciding to call a tool
            # In real usage, this would be the actual OpenAI API call
            tool_calls = [
                MockOpenAIClient.MockToolCall(
                    "database_query",
                    json.dumps({"query": "SELECT * FROM users WHERE role='admin'"})
                ),
                MockOpenAIClient.MockToolCall(
                    "write_file",
                    json.dumps({"path": "/data/output.txt", "content": "Results"})
                ),
            ]
            
            message = MockOpenAIClient.MockMessage(tool_calls=tool_calls)
            choice = MockOpenAIClient.MockChoice(message)
            return MockOpenAIClient.MockResponse([choice])
    
    class MockChat:
        def __init__(self):
            self.completions = MockOpenAIClient.MockCompletions()
    
    def __init__(self):
        self.chat = MockOpenAIClient.MockChat()


def example_1_basic_usage():
    """Example 1: Basic adapter usage with manual setup"""
    print("="*70)
    print("EXAMPLE 1: Basic Adapter Usage")
    print("="*70 + "\n")
    
    # Setup control plane
    control_plane = AgentControlPlane()
    
    # Create agent with specific permissions
    permissions = {
        ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY,
        ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        ActionType.FILE_WRITE: PermissionLevel.NONE,  # Blocked!
    }
    agent_context = control_plane.create_agent("demo-agent-1", permissions)
    
    print(f"✓ Created agent: {agent_context.agent_id}")
    print(f"  Permissions: DATABASE_QUERY (read), FILE_READ (read), FILE_WRITE (none)\n")
    
    # Create OpenAI client (in production, use: from openai import OpenAI)
    original_client = MockOpenAIClient()
    
    # Wrap with adapter - THIS IS THE KEY STEP
    governed_client = ControlPlaneAdapter(
        control_plane=control_plane,
        agent_context=agent_context,
        original_client=original_client
    )
    
    print("✓ Wrapped OpenAI client with ControlPlaneAdapter\n")
    
    # Use the client EXACTLY as you would use OpenAI
    print("Calling: governed_client.chat.completions.create(...)")
    print("  LLM will try to call: database_query (allowed) and write_file (blocked)\n")
    
    response = governed_client.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Get admin users and save to file"}],
        tools=[
            {"type": "function", "function": {"name": "database_query"}},
            {"type": "function", "function": {"name": "write_file"}},
        ]
    )
    
    # Check results
    print("Response received. Tool calls:")
    for i, tool_call in enumerate(response.choices[0].message.tool_calls, 1):
        print(f"  {i}. {tool_call.function.name}")
        print(f"     Arguments: {tool_call.function.arguments}")
        
        if tool_call.function.name == "blocked_action":
            print(f"     ⚠️  THIS ACTION WAS BLOCKED BY THE CONTROL PLANE")
        else:
            print(f"     ✓ This action was allowed")
        print()


def example_2_convenience_function():
    """Example 2: Using the convenience function for one-liner setup"""
    print("\n" + "="*70)
    print("EXAMPLE 2: One-Liner Setup with create_governed_client()")
    print("="*70 + "\n")
    
    control_plane = AgentControlPlane()
    original_client = MockOpenAIClient()
    
    # ONE LINE to create governed client!
    governed = create_governed_client(
        control_plane=control_plane,
        agent_id="demo-agent-2",
        openai_client=original_client,
        permissions={
            ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY,
            ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        }
    )
    
    print("✓ Created governed client in ONE LINE")
    print("  Agent ID: demo-agent-2")
    print("  Permissions: DATABASE_QUERY (read), FILE_READ (read)")
    print("  FILE_WRITE is implicitly DENIED (not in permissions)\n")
    
    print("Now using the client like normal OpenAI SDK...")
    response = governed.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Query database and save results"}],
        tools=[
            {"type": "function", "function": {"name": "database_query"}},
            {"type": "function", "function": {"name": "write_file"}},
        ]
    )
    
    print("\nTool calls in response:")
    for tool_call in response.choices[0].message.tool_calls:
        status = "❌ BLOCKED" if tool_call.function.name == "blocked_action" else "✅ ALLOWED"
        print(f"  {status}: {tool_call.function.name}")


def example_3_custom_tool_mapping():
    """Example 3: Custom tool name mapping"""
    print("\n" + "="*70)
    print("EXAMPLE 3: Custom Tool Name Mapping")
    print("="*70 + "\n")
    
    control_plane = AgentControlPlane()
    original_client = MockOpenAIClient()
    
    # Your company might have custom tool names
    custom_mapping = {
        "company_db_reader": ActionType.DATABASE_QUERY,
        "company_db_writer": ActionType.DATABASE_WRITE,
        "company_file_store": ActionType.FILE_WRITE,
    }
    
    governed = create_governed_client(
        control_plane=control_plane,
        agent_id="demo-agent-3",
        openai_client=original_client,
        permissions={
            ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY,
        },
        tool_mapping=custom_mapping
    )
    
    print("✓ Created client with custom tool mappings:")
    print("  company_db_reader -> DATABASE_QUERY")
    print("  company_db_writer -> DATABASE_WRITE")
    print("  company_file_store -> FILE_WRITE")
    print("\nAgent only has DATABASE_QUERY permission (read-only)\n")
    
    # The adapter will now recognize your custom tool names
    print("The adapter automatically recognizes and governs custom tool names!")


def example_4_callback_on_block():
    """Example 4: Using callbacks to handle blocked actions"""
    print("\n" + "="*70)
    print("EXAMPLE 4: Callbacks for Blocked Actions")
    print("="*70 + "\n")
    
    # Define a callback to handle blocks
    blocked_actions = []
    
    def on_action_blocked(tool_name, tool_args, result):
        """Called whenever an action is blocked"""
        print(f"  🚨 ALERT: {tool_name} was blocked!")
        print(f"     Reason: {result.get('error', 'Unknown')}")
        blocked_actions.append({
            "tool": tool_name,
            "args": tool_args,
            "reason": result.get('error')
        })
    
    control_plane = AgentControlPlane()
    agent_context = control_plane.create_agent(
        "demo-agent-4",
        {ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY}
    )
    
    governed = ControlPlaneAdapter(
        control_plane=control_plane,
        agent_context=agent_context,
        original_client=MockOpenAIClient(),
        on_block=on_action_blocked  # Register callback
    )
    
    print("✓ Adapter configured with on_block callback")
    print("  Callback will fire whenever an action is blocked\n")
    
    print("Making API call...")
    response = governed.chat.completions.create(
        model="gpt-4",
        messages=[{"role": "user", "content": "Query and write"}],
        tools=[
            {"type": "function", "function": {"name": "database_query"}},
            {"type": "function", "function": {"name": "write_file"}},
        ]
    )
    
    print(f"\nBlocked actions summary: {len(blocked_actions)} actions blocked")
    for action in blocked_actions:
        print(f"  - {action['tool']}: {action['reason']}")


def example_5_audit_trail():
    """Example 5: Accessing audit trail and statistics"""
    print("\n" + "="*70)
    print("EXAMPLE 5: Audit Trail and Statistics")
    print("="*70 + "\n")
    
    control_plane = AgentControlPlane()
    governed = create_governed_client(
        control_plane=control_plane,
        agent_id="demo-agent-5",
        openai_client=MockOpenAIClient(),
        permissions={ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY}
    )
    
    # Make some API calls
    print("Making 2 API calls with governed client...")
    for i in range(2):
        governed.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": f"Request {i+1}"}],
            tools=[
                {"type": "function", "function": {"name": "database_query"}},
                {"type": "function", "function": {"name": "write_file"}},
            ]
        )
    
    # Get statistics
    stats = governed.get_statistics()
    
    print(f"\n✓ Statistics for agent: {stats['agent_id']}")
    print(f"  Session: {stats['session_id']}")
    print(f"  Audit log entries: {len(stats['control_plane_audit'])}")
    print(f"  Execution history: {len(stats['execution_history'])}")
    
    # Show recent audit entries
    print("\n  Recent audit entries:")
    for entry in stats['control_plane_audit'][:5]:
        print(f"    - {entry['event_type']}: {entry['timestamp']}")


def main():
    """Run all examples"""
    print("\n" + "█"*70)
    print("█" + " "*68 + "█")
    print("█" + "  OpenAI Adapter Demo - Drop-In Middleware".center(68) + "█")
    print("█" + " "*68 + "█")
    print("█"*70 + "\n")
    
    example_1_basic_usage()
    example_2_convenience_function()
    example_3_custom_tool_mapping()
    example_4_callback_on_block()
    example_5_audit_trail()
    
    print("\n" + "="*70)
    print("KEY TAKEAWAYS")
    print("="*70)
    print("""
1. ZERO FRICTION: Developers use the standard OpenAI SDK
2. INVISIBLE GOVERNANCE: The control plane works behind the scenes
3. DROP-IN REPLACEMENT: Just wrap the client, no code changes needed
4. PRODUCTION READY: Full audit trail and callback support
5. CUSTOMIZABLE: Support for custom tool names and mappings

To use with real OpenAI:
    from openai import OpenAI
    client = OpenAI(api_key="...")
    governed = create_governed_client(control_plane, "agent-1", client, permissions)
    
    # Use exactly like normal OpenAI client!
    response = governed.chat.completions.create(...)
    """)


if __name__ == "__main__":
    main()
