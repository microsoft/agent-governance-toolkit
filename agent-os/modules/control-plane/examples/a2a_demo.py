# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
A2A (Agent-to-Agent) Protocol Integration Demo - Agent Control Plane

This example demonstrates how to use the Agent Control Plane with A2A
to govern inter-agent communications.

A2A is an open standard (from Google/Linux Foundation) that enables
secure interoperability between AI agents from different frameworks.
"""

import sys
import os
import json
from datetime import datetime

# Add the src directory to the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from agent_control_plane import (
    AgentControlPlane,
    A2AAdapter,
    A2AAgent,
    create_governed_a2a_agent,
    ActionType,
    PermissionLevel,
)


def print_section(title):
    """Print a formatted section header"""
    print("\n" + "=" * 80)
    print(f"  {title}")
    print("=" * 80 + "\n")


def demo_basic_a2a_agent():
    """Demonstrate basic A2A agent with governance"""
    print_section("Demo 1: Basic A2A Agent with Governance")
    
    # Create control plane
    control_plane = AgentControlPlane()
    
    # Define permissions
    permissions = {
        ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY,
        ActionType.API_CALL: PermissionLevel.READ_WRITE,
        ActionType.WORKFLOW_TRIGGER: PermissionLevel.READ_WRITE,
    }
    
    # Create governed A2A agent
    a2a_agent = create_governed_a2a_agent(
        control_plane=control_plane,
        agent_id="data-processor-agent",
        agent_card={
            "name": "Data Processor",
            "description": "Processes and analyzes data",
            "version": "1.0.0",
            "capabilities": []
        },
        permissions=permissions
    )
    
    print("✓ Created governed A2A agent")
    print(f"✓ Agent ID: data-processor-agent")
    print(f"✓ Name: Data Processor")
    print(f"✓ Permissions: READ_ONLY for database, READ_WRITE for API and workflows\n")
    
    # Register capabilities
    def handle_data_processing(params):
        data = params.get("data", [])
        return {"processed": len(data), "status": "completed"}
    
    a2a_agent.register_capability("data_processing", handle_data_processing)
    
    print("✓ Registered capability: data_processing")
    print("✓ All inter-agent communications will be governed!")


def demo_agent_card():
    """Demonstrate Agent Card for discovery"""
    print_section("Demo 2: Agent Card for Discovery")
    
    control_plane = AgentControlPlane()
    permissions = {
        ActionType.FILE_READ: PermissionLevel.READ_ONLY,
    }
    
    # Create A2A agent with detailed Agent Card
    agent_card = {
        "name": "File Analyzer",
        "description": "Analyzes files and extracts metadata",
        "version": "1.0.0",
        "vendor": "Your Company",
        "capabilities": ["file_analysis", "metadata_extraction"],
        "supported_formats": ["pdf", "docx", "txt"],
        "max_file_size": "10MB"
    }
    
    a2a_agent = create_governed_a2a_agent(
        control_plane=control_plane,
        agent_id="file-analyzer",
        agent_card=agent_card,
        permissions=permissions
    )
    
    # Get the Agent Card
    card = a2a_agent.get_agent_card()
    
    print("✓ Created A2A agent with Agent Card")
    print(f"\nAgent Card:")
    print(json.dumps(card, indent=2))
    print("\n✓ Agent Card enables discovery")
    print("✓ Other agents can find and understand capabilities")
    print("✓ Essential for multi-agent coordination")


def demo_task_request():
    """Demonstrate task request handling"""
    print_section("Demo 3: Task Request Handling")
    
    control_plane = AgentControlPlane()
    
    # Create agent 1 (data processor)
    permissions1 = {
        ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY,
        ActionType.WORKFLOW_TRIGGER: PermissionLevel.READ_WRITE,
    }
    agent_context1 = control_plane.create_agent("processor-agent", permissions1)
    
    # Create adapter for agent 1
    adapter1 = A2AAdapter(
        control_plane=control_plane,
        agent_context=agent_context1,
        agent_card={"name": "Data Processor", "capabilities": ["data_processing"]}
    )
    
    # Register capability
    def handle_data_processing(params):
        return {"result": "Data processed successfully", "count": params.get("count", 0)}
    
    adapter1.register_capability("data_processing", handle_data_processing)
    
    print("✓ Created agent: processor-agent")
    print("✓ Registered capability: data_processing\n")
    
    # Simulate task request from another agent
    print("Example: Task request from another agent")
    task_request = {
        "id": "task-123",
        "type": "task_request",
        "from": "client-agent",
        "to": "processor-agent",
        "timestamp": datetime.now().isoformat(),
        "payload": {
            "task_type": "data_processing",
            "parameters": {
                "data": [1, 2, 3, 4, 5],
                "count": 5
            }
        }
    }
    
    print(f"Request: {json.dumps(task_request, indent=2)}\n")
    
    # Handle the request
    response = adapter1.handle_message(task_request, "client-agent")
    
    print(f"Response: {json.dumps(response, indent=2)}\n")
    
    print("✓ Task request handled with governance")
    print("✓ Capability executed only if permitted")
    print("✓ Response includes result and status")


def demo_task_delegation():
    """Demonstrate task delegation between agents"""
    print_section("Demo 4: Task Delegation Between Agents")
    
    control_plane = AgentControlPlane()
    
    # Create orchestrator agent
    orchestrator_permissions = {
        ActionType.WORKFLOW_TRIGGER: PermissionLevel.READ_WRITE,
    }
    orchestrator_context = control_plane.create_agent("orchestrator", orchestrator_permissions)
    
    orchestrator = A2AAdapter(
        control_plane=control_plane,
        agent_context=orchestrator_context,
        agent_card={"name": "Orchestrator", "capabilities": ["task_delegation"]}
    )
    
    print("✓ Created orchestrator agent")
    print("✓ Can delegate tasks to specialized agents\n")
    
    # Simulate delegation request
    print("Example: Orchestrator delegates task to specialist")
    delegation_request = {
        "id": "delegation-456",
        "type": "task_delegation",
        "from": "orchestrator",
        "to": "orchestrator",
        "timestamp": datetime.now().isoformat(),
        "payload": {
            "target_agent": "specialist-agent",
            "task_type": "complex_analysis",
            "parameters": {
                "data_source": "database",
                "analysis_type": "deep"
            }
        }
    }
    
    print(f"Request: {json.dumps(delegation_request, indent=2)}\n")
    
    # Handle delegation
    response = orchestrator.handle_message(delegation_request, "client")
    
    print(f"Response: {json.dumps(response, indent=2)}\n")
    
    print("✓ Task delegation governed by control plane")
    print("✓ Orchestrator needs WORKFLOW_TRIGGER permission")
    print("✓ Enables multi-agent workflows")


def demo_agent_discovery():
    """Demonstrate agent discovery"""
    print_section("Demo 5: Agent Discovery")
    
    control_plane = AgentControlPlane()
    
    # Create multiple agents
    agents = []
    
    # Agent 1: Data Processor
    agent1 = create_governed_a2a_agent(
        control_plane=control_plane,
        agent_id="data-processor",
        agent_card={
            "name": "Data Processor",
            "capabilities": ["data_processing", "data_validation"]
        },
        permissions={ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY}
    )
    agents.append(agent1)
    
    # Agent 2: File Handler
    agent2 = create_governed_a2a_agent(
        control_plane=control_plane,
        agent_id="file-handler",
        agent_card={
            "name": "File Handler",
            "capabilities": ["file_reading", "file_analysis"]
        },
        permissions={ActionType.FILE_READ: PermissionLevel.READ_ONLY}
    )
    agents.append(agent2)
    
    # Agent 3: API Connector
    agent3 = create_governed_a2a_agent(
        control_plane=control_plane,
        agent_id="api-connector",
        agent_card={
            "name": "API Connector",
            "capabilities": ["api_calls", "data_fetching"]
        },
        permissions={ActionType.API_CALL: PermissionLevel.READ_WRITE}
    )
    agents.append(agent3)
    
    print("✓ Created 3 specialized agents:\n")
    
    for agent in agents:
        card = agent.get_agent_card()
        print(f"  Agent: {card['name']}")
        print(f"  ID: {card['agent_id']}")
        print(f"  Capabilities: {', '.join(card['capabilities'])}\n")
    
    print("✓ Agents can discover each other via Agent Cards")
    print("✓ Each agent knows what others can do")
    print("✓ Enables dynamic task routing and coordination")


def demo_integration_pattern():
    """Demonstrate real-world A2A integration"""
    print_section("Demo 6: Real-World A2A Integration Pattern")
    
    print("Real-world A2A multi-agent system pattern:\n")
    
    print("1. Agent Setup:")
    print("   ```python")
    print("   from agent_control_plane import create_governed_a2a_agent")
    print("   ")
    print("   # Create specialized agents")
    print("   data_agent = create_governed_a2a_agent(")
    print("       control_plane, 'data-agent',")
    print("       agent_card={'name': 'Data Agent', 'capabilities': ['query']},")
    print("       permissions={ActionType.DATABASE_QUERY: PermissionLevel.READ_ONLY}")
    print("   )")
    print("   ")
    print("   analytics_agent = create_governed_a2a_agent(")
    print("       control_plane, 'analytics-agent',")
    print("       agent_card={'name': 'Analytics', 'capabilities': ['analyze']},")
    print("       permissions={ActionType.CODE_EXECUTION: PermissionLevel.READ_ONLY}")
    print("   )")
    print("   ```\n")
    
    print("2. Register Capabilities:")
    print("   ```python")
    print("   # Register what each agent can do")
    print("   data_agent.register_capability('query', handle_query)")
    print("   analytics_agent.register_capability('analyze', handle_analysis)")
    print("   ```\n")
    
    print("3. Orchestration:")
    print("   ```python")
    print("   # Orchestrator coordinates multiple agents")
    print("   # 1. Request data from data agent")
    print("   data_request = data_agent.send_task_request(")
    print("       to_agent='data-agent',")
    print("       task_type='query',")
    print("       parameters={'table': 'sales'})")
    print("   ")
    print("   # 2. Send data to analytics agent")
    print("   analysis_request = analytics_agent.send_task_request(")
    print("       to_agent='analytics-agent',")
    print("       task_type='analyze',")
    print("       parameters={'data': data_result})")
    print("   ```\n")
    
    print("4. Benefits:")
    print("   ✓ Specialized agents for different tasks")
    print("   ✓ Secure inter-agent communication")
    print("   ✓ Each agent independently governed")
    print("   ✓ Complete audit trail across all agents")
    print("   ✓ Works across different frameworks/vendors")


def demo_a2a_features():
    """Demonstrate A2A protocol features"""
    print_section("Demo 7: A2A Protocol Features")
    
    print("A2A (Agent-to-Agent) Protocol Features:\n")
    
    print("1. Agent Discovery:")
    print("   - Agent Cards describe capabilities")
    print("   - Dynamic discovery of available agents")
    print("   - Understanding of what each agent can do\n")
    
    print("2. Task Coordination:")
    print("   - Task requests between agents")
    print("   - Task delegation to specialists")
    print("   - Multi-step workflows\n")
    
    print("3. Secure Communication:")
    print("   - No sharing of internal memory")
    print("   - Proprietary logic stays private")
    print("   - Governed message passing\n")
    
    print("4. Interoperability:")
    print("   - Works across different frameworks")
    print("   - Vendor-neutral protocol")
    print("   - Standard message formats\n")
    
    print("5. Message Types:")
    print("   - task_request: Request a task")
    print("   - task_delegation: Delegate to another agent")
    print("   - query: Ask for information")
    print("   - discovery: Find available agents")
    print("   - handshake: Establish connection")
    print("   - negotiate: Discuss parameters\n")
    
    print("✓ Agent Control Plane governs all A2A communications")
    print("✓ Each agent has its own permissions")
    print("✓ Complete audit trail of inter-agent interactions")


def main():
    """Run all demos"""
    print("\n" + "=" * 80)
    print("  A2A (Agent-to-Agent) Protocol Integration Demo")
    print("=" * 80)
    
    try:
        demo_basic_a2a_agent()
        demo_agent_card()
        demo_task_request()
        demo_task_delegation()
        demo_agent_discovery()
        demo_integration_pattern()
        demo_a2a_features()
        
        print_section("Summary")
        print("✓ A2A adapter enables secure inter-agent communication")
        print("✓ Agent Cards for discovery and capability description")
        print("✓ Task requests and delegation with governance")
        print("✓ Works across different frameworks and vendors")
        print("✓ Complete audit trail of all interactions")
        print("\n✓ Build multi-agent systems with confidence")
        print("✓ Agent Control Plane ensures safe coordination!")
        print("\n" + "=" * 80 + "\n")
        
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
