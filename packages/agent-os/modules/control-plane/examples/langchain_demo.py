# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
LangChain Integration Demo - Agent Control Plane

This example demonstrates how to use the Agent Control Plane with LangChain
to govern tool calls made by LangChain agents.

The LangChain adapter provides the same zero-friction governance as the OpenAI
adapter, but for LangChain's agent framework.
"""

import sys
import os

# Add the src directory to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from agent_control_plane import (
    AgentControlPlane,
    LangChainAdapter,
    create_governed_langchain_client,
    ActionType,
    PermissionLevel,
)


def print_section(title):
    """Print a formatted section header"""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80 + "\n")


def demo_basic_langchain_governance():
    """Demonstrate basic LangChain governance"""
    print_section("Demo 1: Basic LangChain Governance")
    
    # Create control plane
    control_plane = AgentControlPlane()
    
    # Create a mock LangChain client for demonstration
    # In real usage, you would use: from langchain.chat_models import ChatOpenAI
    class MockLangChainLLM:
        """Mock LangChain LLM for demonstration"""
        def __init__(self):
            self.model_name = "gpt-3.5-turbo"
        
        def __call__(self, prompt):
            return f"Response to: {prompt}"
        
        def invoke(self, messages):
            return {"content": "Mock response", "tool_calls": []}
    
    llm = MockLangChainLLM()
    
    # Define permissions - read-only access
    permissions = {
        ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY,
        ActionType.FILE_WRITE: PermissionLevel.NONE,  # Blocked!
    }
    
    # Create governed LangChain client
    governed_llm = create_governed_langchain_client(
        control_plane=control_plane,
        agent_id="langchain-demo-agent",
        langchain_client=llm,
        permissions=permissions
    )
    
    print("✓ Created governed LangChain client")
    print(f"✓ Agent ID: langchain-demo-agent")
    print(f"✓ Permissions: READ_ONLY for files and database")
    print(f"✓ File writes: BLOCKED\n")
    
    # The governed_llm can now be used in place of the original LLM
    # All tool calls will be automatically checked against the control plane
    print("✓ LangChain client is now governed!")
    print("✓ Use it with LangChain agents and all tool calls will be governed")


def demo_custom_tool_mapping():
    """Demonstrate custom tool mapping"""
    print_section("Demo 2: Custom Tool Mapping")
    
    control_plane = AgentControlPlane()
    
    class MockLLM:
        def __call__(self, prompt):
            return f"Response to: {prompt}"
    
    llm = MockLLM()
    
    # Create agent context
    permissions = {
        ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        ActionType.API_CALL: PermissionLevel.READ_WRITE,
    }
    agent_context = control_plane.create_agent("custom-tool-agent", permissions)
    
    # Custom tool mappings for company-specific tools
    custom_mapping = {
        "company_database_tool": ActionType.DATABASE_QUERY,
        "company_file_reader": ActionType.FILE_READ,
        "company_api_caller": ActionType.API_CALL,
    }
    
    # Create adapter with custom mapping
    governed_llm = LangChainAdapter(
        control_plane=control_plane,
        agent_context=agent_context,
        langchain_client=llm,
        tool_mapping=custom_mapping
    )
    
    print("✓ Created LangChain adapter with custom tool mappings:")
    print("  - company_database_tool → DATABASE_QUERY")
    print("  - company_file_reader → FILE_READ")
    print("  - company_api_caller → API_CALL")
    print("\n✓ Company-specific tools are now mapped to standard ActionTypes")
    print("✓ Governance rules apply to your custom tools!")


def demo_blocked_action_callback():
    """Demonstrate callback for blocked actions"""
    print_section("Demo 3: Blocked Action Callback")
    
    control_plane = AgentControlPlane()
    
    # Track blocked actions
    blocked_actions = []
    
    def on_action_blocked(tool_name, tool_args, result):
        """Callback when an action is blocked"""
        blocked_actions.append({
            "tool": tool_name,
            "args": tool_args,
            "reason": result.get("error", "Unknown"),
        })
        print(f"\n⚠️  ALERT: Action blocked!")
        print(f"   Tool: {tool_name}")
        print(f"   Reason: {result.get('error', 'Unknown')}")
    
    class MockLLM:
        def __call__(self, prompt):
            return f"Response to: {prompt}"
    
    llm = MockLLM()
    
    # Restrictive permissions
    permissions = {
        ActionType.FILE_READ: PermissionLevel.READ_ONLY,
        ActionType.FILE_WRITE: PermissionLevel.NONE,  # All writes blocked
    }
    agent_context = control_plane.create_agent("monitored-agent", permissions)
    
    # Create adapter with callback
    governed_llm = LangChainAdapter(
        control_plane=control_plane,
        agent_context=agent_context,
        langchain_client=llm,
        on_block=on_action_blocked
    )
    
    print("✓ Created LangChain adapter with blocked action callback")
    print("✓ Callback will be invoked whenever an action is blocked")
    print("✓ Use this for alerting, logging, or security monitoring")
    print("\nExample uses:")
    print("  - Send alerts to PagerDuty")
    print("  - Log to SIEM system")
    print("  - Notify security team")
    print("  - Track repeated violations")


def demo_integration_pattern():
    """Demonstrate real-world integration pattern"""
    print_section("Demo 4: Real-World Integration Pattern")
    
    print("Real-world LangChain integration pattern:\n")
    
    print("1. Setup (one-time):")
    print("   ```python")
    print("   from langchain.chat_models import ChatOpenAI")
    print("   from langchain.agents import initialize_agent, load_tools")
    print("   from agent_control_plane import create_governed_langchain_client")
    print("   ")
    print("   # Create base LLM")
    print("   llm = ChatOpenAI(temperature=0, model='gpt-4')")
    print("   ")
    print("   # Wrap with governance")
    print("   governed_llm = create_governed_langchain_client(")
    print("       control_plane, 'my-agent', llm, permissions)")
    print("   ```\n")
    
    print("2. Use in agents:")
    print("   ```python")
    print("   # Load LangChain tools")
    print("   tools = load_tools(['python_repl', 'requests', 'wikipedia'])")
    print("   ")
    print("   # Create agent with governed LLM")
    print("   agent = initialize_agent(")
    print("       tools, governed_llm, agent='zero-shot-react-description')")
    print("   ")
    print("   # Run tasks - all tool calls are governed!")
    print("   agent.run('Search Wikipedia and save results to file')")
    print("   ```\n")
    
    print("3. Benefits:")
    print("   ✓ Zero code changes to existing LangChain agents")
    print("   ✓ All tool calls automatically governed")
    print("   ✓ Complete audit trail in control plane")
    print("   ✓ Policy enforcement at kernel level")
    print("   ✓ Works with all LangChain agent types")


def demo_statistics():
    """Demonstrate statistics and audit trail"""
    print_section("Demo 5: Statistics and Audit Trail")
    
    control_plane = AgentControlPlane()
    
    class MockLLM:
        def __call__(self, prompt):
            return f"Response to: {prompt}"
    
    llm = MockLLM()
    
    permissions = {
        ActionType.FILE_READ: PermissionLevel.READ_ONLY,
    }
    agent_context = control_plane.create_agent("audit-demo-agent", permissions)
    
    governed_llm = LangChainAdapter(
        control_plane=control_plane,
        agent_context=agent_context,
        langchain_client=llm
    )
    
    # Get statistics
    stats = governed_llm.get_statistics()
    
    print("✓ Access adapter statistics:")
    print(f"  - Agent ID: {stats['agent_id']}")
    print(f"  - Session ID: {stats['session_id']}")
    print(f"  - Audit log entries: {len(stats['control_plane_audit'])}")
    print(f"  - Execution history: {len(stats['execution_history'])}")
    print("\n✓ Complete audit trail available")
    print("✓ Track all actions, decisions, and violations")
    print("✓ Essential for compliance and debugging")


def main():
    """Run all demos"""
    print("\n" + "=" * 80)
    print("  LangChain Integration Demo - Agent Control Plane")
    print("=" * 80)
    
    try:
        demo_basic_langchain_governance()
        demo_custom_tool_mapping()
        demo_blocked_action_callback()
        demo_integration_pattern()
        demo_statistics()
        
        print_section("Summary")
        print("✓ LangChain adapter provides zero-friction governance")
        print("✓ Works with all LangChain agent types and tools")
        print("✓ Custom tool mappings for company-specific tools")
        print("✓ Callbacks for monitoring and alerting")
        print("✓ Complete audit trail and statistics")
        print("\n✓ Same governance approach as OpenAI adapter")
        print("✓ Use the right adapter for your framework!")
        print("\n" + "=" * 80 + "\n")
        
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
