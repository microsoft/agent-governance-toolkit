# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example: OpenAgent Definition (OAD) - The "USB Port" for AI Agents

This example demonstrates the OpenAgent Definition metadata system,
which provides a standard interface definition language for AI agents.

Think of it as Swagger/OpenAPI for AI agents - a way to discover,
understand, and compose agents in a marketplace.

The Key Insight: "This is the USB Port moment for AI. The startup that
defines the Standard Agent Protocol wins the platform war."
"""

import json
import sys
import os

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agent_metadata import (
    AgentMetadata,
    AgentMetadataManager,
    create_default_manifest
)


def example_1_basic_manifest():
    """Example 1: Creating a basic agent metadata manifest."""
    print("="*60)
    print("Example 1: Creating a Basic Agent Metadata Manifest")
    print("="*60)
    print()
    
    # Create a metadata manifest for a specialized agent
    metadata = AgentMetadata(
        agent_id="github-coder",
        name="GitHub Coder Agent",
        version="2.3.1",
        description="Specialized agent for reading and writing code in GitHub repositories"
    )
    
    # Define capabilities (The "Can-Do")
    metadata.add_capability(
        name="python_code_generation",
        description="Can generate Python 3.9+ code following PEP 8 standards",
        tags=["python", "code-generation", "pep8"],
        version="2.0"
    )
    
    metadata.add_capability(
        name="git_operations",
        description="Can perform git operations: clone, commit, push, pull, merge",
        tags=["git", "version-control"],
        version="1.5"
    )
    
    metadata.add_capability(
        name="code_review",
        description="Can review code and suggest improvements",
        tags=["code-review", "quality"],
        version="1.0"
    )
    
    # Define constraints (The "Won't-Do")
    metadata.add_constraint(
        type="access",
        description="No internet access outside of GitHub API",
        severity="high"
    )
    
    metadata.add_constraint(
        type="resource",
        description="4k token context window limit",
        severity="medium"
    )
    
    metadata.add_constraint(
        type="security",
        description="Cannot execute arbitrary shell commands",
        severity="high"
    )
    
    # Define IO contract
    metadata.set_io_contract(
        input_schema={
            "type": "object",
            "properties": {
                "repository": {"type": "string", "description": "GitHub repository URL"},
                "task": {"type": "string", "description": "Coding task description"},
                "language": {"type": "string", "enum": ["python", "javascript", "go"]}
            },
            "required": ["repository", "task"]
        },
        output_schema={
            "type": "object",
            "properties": {
                "code": {"type": "string", "description": "Generated code"},
                "files_modified": {"type": "array", "items": {"type": "string"}},
                "commit_sha": {"type": "string", "description": "Git commit SHA"}
            }
        },
        examples=[
            {
                "input": {
                    "repository": "github.com/user/repo",
                    "task": "Add user authentication",
                    "language": "python"
                },
                "output": {
                    "code": "...",
                    "files_modified": ["auth.py", "models.py"],
                    "commit_sha": "abc123"
                }
            }
        ]
    )
    
    # Define trust score
    metadata.set_trust_score(
        success_rate=0.93,
        avg_latency_ms=2400.0,
        total_executions=1547,
        metrics={
            "code_compilation_rate": 0.95,
            "test_pass_rate": 0.87,
            "review_approval_rate": 0.91
        }
    )
    
    print("✓ Agent metadata manifest created!")
    print()
    print("Agent ID:", metadata.agent_id)
    print("Name:", metadata.name)
    print("Version:", metadata.version)
    print()
    print("Capabilities:")
    for cap in metadata.capabilities:
        print(f"  - {cap.name}: {cap.description}")
    print()
    print("Constraints:")
    for con in metadata.constraints:
        print(f"  - [{con.severity.upper()}] {con.description}")
    print()
    print("Trust Score:")
    if metadata.trust_score:
        print(f"  Success Rate: {metadata.trust_score.success_rate:.1%}")
        print(f"  Avg Latency: {metadata.trust_score.avg_latency_ms:.0f}ms")
        print(f"  Total Executions: {metadata.trust_score.total_executions}")
    print()


def example_2_marketplace_discovery():
    """Example 2: Agent marketplace discovery scenario."""
    print("="*60)
    print("Example 2: Agent Marketplace Discovery")
    print("="*60)
    print()
    
    print("Scenario: You need an agent that can write Python code")
    print("The marketplace uses OAD manifests to find compatible agents")
    print()
    
    # Simulate a marketplace with multiple agents
    agents = [
        {
            "agent_id": "github-coder",
            "name": "GitHub Coder",
            "capabilities": ["python_code_generation", "git_operations"],
            "trust_score": 0.93
        },
        {
            "agent_id": "openai-analyst",
            "name": "OpenAI Data Analyst",
            "capabilities": ["data_analysis", "visualization", "python_scripting"],
            "trust_score": 0.87
        },
        {
            "agent_id": "general-assistant",
            "name": "General Assistant",
            "capabilities": ["conversation", "basic_math", "time_queries"],
            "trust_score": 0.78
        }
    ]
    
    # Search for agents with Python capabilities
    print("Searching marketplace for agents with 'python' capabilities...")
    print()
    
    matching_agents = []
    for agent in agents:
        for cap in agent["capabilities"]:
            if "python" in cap.lower():
                matching_agents.append(agent)
                break
    
    print(f"Found {len(matching_agents)} matching agents:")
    print()
    
    for agent in matching_agents:
        print(f"  {agent['name']} (ID: {agent['agent_id']})")
        print(f"    Trust Score: {agent['trust_score']:.1%}")
        print(f"    Capabilities: {', '.join(agent['capabilities'])}")
        print()
    
    print("You can now select and use the best agent for your needs!")
    print()


def example_3_agent_composition():
    """Example 3: Composing multiple agents with compatible IO contracts."""
    print("="*60)
    print("Example 3: Agent Composition with IO Contracts")
    print("="*60)
    print()
    
    print("Scenario: Build a pipeline by composing multiple agents")
    print("OAD IO contracts ensure compatibility between agents")
    print()
    
    # Agent 1: Data Fetcher
    fetcher = AgentMetadata(
        agent_id="data-fetcher",
        name="Data Fetcher",
        version="1.0.0",
        description="Fetches data from APIs"
    )
    fetcher.set_io_contract(
        input_schema={
            "type": "object",
            "properties": {
                "api_url": {"type": "string"}
            }
        },
        output_schema={
            "type": "object",
            "properties": {
                "data": {"type": "array"},
                "format": {"type": "string", "enum": ["json", "csv"]}
            }
        }
    )
    
    # Agent 2: Data Transformer
    transformer = AgentMetadata(
        agent_id="data-transformer",
        name="Data Transformer",
        version="1.0.0",
        description="Transforms and cleans data"
    )
    transformer.set_io_contract(
        input_schema={
            "type": "object",
            "properties": {
                "data": {"type": "array"},
                "format": {"type": "string"}
            }
        },
        output_schema={
            "type": "object",
            "properties": {
                "cleaned_data": {"type": "array"},
                "summary": {"type": "object"}
            }
        }
    )
    
    # Agent 3: Report Generator
    reporter = AgentMetadata(
        agent_id="report-generator",
        name="Report Generator",
        version="1.0.0",
        description="Generates reports from data"
    )
    reporter.set_io_contract(
        input_schema={
            "type": "object",
            "properties": {
                "cleaned_data": {"type": "array"},
                "summary": {"type": "object"}
            }
        },
        output_schema={
            "type": "object",
            "properties": {
                "report": {"type": "string"},
                "format": {"type": "string", "enum": ["pdf", "html"]}
            }
        }
    )
    
    print("Agent Pipeline:")
    print()
    print(f"1. {fetcher.name}")
    print(f"   Input: API URL")
    print(f"   Output: Data array")
    print()
    print("       ↓")
    print()
    print(f"2. {transformer.name}")
    print(f"   Input: Data array")
    print(f"   Output: Cleaned data + summary")
    print()
    print("       ↓")
    print()
    print(f"3. {reporter.name}")
    print(f"   Input: Cleaned data + summary")
    print(f"   Output: Report (PDF/HTML)")
    print()
    
    # Validate compatibility
    print("Validating IO contract compatibility...")
    
    # Check if fetcher output matches transformer input
    fetcher_output = set(fetcher.io_contract.output_schema["properties"].keys())
    transformer_input = set(transformer.io_contract.input_schema["properties"].keys())
    
    if fetcher_output & transformer_input:
        print("  ✓ Fetcher → Transformer: Compatible")
    else:
        print("  ✗ Fetcher → Transformer: Incompatible")
    
    # Check if transformer output matches reporter input
    transformer_output = set(transformer.io_contract.output_schema["properties"].keys())
    reporter_input = set(reporter.io_contract.input_schema["properties"].keys())
    
    if transformer_output & reporter_input:
        print("  ✓ Transformer → Reporter: Compatible")
    else:
        print("  ✗ Transformer → Reporter: Incompatible")
    
    print()
    print("Pipeline validated! Agents can be composed together.")
    print()


def example_4_trust_score_updates():
    """Example 4: Updating trust scores based on executions."""
    print("="*60)
    print("Example 4: Dynamic Trust Score Updates")
    print("="*60)
    print()
    
    print("Scenario: Agent executes tasks and updates trust score in real-time")
    print()
    
    # Create agent with initial trust score
    metadata = AgentMetadata(
        agent_id="test-agent",
        name="Test Agent",
        version="1.0.0",
        description="Test agent"
    )
    
    metadata.set_trust_score(
        success_rate=0.80,
        avg_latency_ms=1000.0,
        total_executions=100
    )
    
    print(f"Initial Trust Score:")
    print(f"  Success Rate: {metadata.trust_score.success_rate:.1%}")
    print(f"  Avg Latency: {metadata.trust_score.avg_latency_ms:.0f}ms")
    print(f"  Total Executions: {metadata.trust_score.total_executions}")
    print()
    
    # Simulate successful executions
    print("Executing 5 successful tasks...")
    for i in range(5):
        metadata.update_trust_score(success=True, latency_ms=900.0)
    
    print(f"After 5 successes:")
    print(f"  Success Rate: {metadata.trust_score.success_rate:.1%} (↑)")
    print(f"  Avg Latency: {metadata.trust_score.avg_latency_ms:.0f}ms (↓)")
    print(f"  Total Executions: {metadata.trust_score.total_executions}")
    print()
    
    # Simulate failed executions
    print("Executing 2 failed tasks...")
    for i in range(2):
        metadata.update_trust_score(success=False, latency_ms=1500.0)
    
    print(f"After 2 failures:")
    print(f"  Success Rate: {metadata.trust_score.success_rate:.1%} (↓)")
    print(f"  Avg Latency: {metadata.trust_score.avg_latency_ms:.0f}ms (↑)")
    print(f"  Total Executions: {metadata.trust_score.total_executions}")
    print()
    
    print("Trust scores update dynamically based on real performance!")
    print()


def example_5_saving_and_loading():
    """Example 5: Saving and loading manifests."""
    print("="*60)
    print("Example 5: Persisting Agent Manifests")
    print("="*60)
    print()
    
    # Create manager
    manager = AgentMetadataManager("demo_manifest.json")
    
    # Create manifest
    metadata = create_default_manifest()
    
    print(f"Creating manifest for: {metadata.name}")
    print(f"Agent ID: {metadata.agent_id}")
    print(f"Version: {metadata.version}")
    print()
    
    # Save to file
    print("Saving manifest to 'demo_manifest.json'...")
    success = manager.save_manifest(metadata)
    
    if success:
        print("✓ Manifest saved successfully!")
        print()
        
        # Show JSON preview
        print("Manifest JSON (preview):")
        print(json.dumps(metadata.to_dict(), indent=2)[:500] + "...")
        print()
        
        # Simulate loading in a different context
        print("Simulating agent discovery (loading manifest)...")
        manager2 = AgentMetadataManager("demo_manifest.json")
        loaded_metadata = manager2.load_manifest()
        
        if loaded_metadata:
            print(f"✓ Loaded manifest: {loaded_metadata.name} v{loaded_metadata.version}")
            print(f"  Capabilities: {len(loaded_metadata.capabilities)}")
            print(f"  Constraints: {len(loaded_metadata.constraints)}")
            print()
    
    # Cleanup
    import os
    if os.path.exists("demo_manifest.json"):
        os.remove("demo_manifest.json")
        print("(Demo manifest file cleaned up)")
        print()


def main():
    """Run all examples."""
    print()
    print("#"*60)
    print("# OpenAgent Definition (OAD) - The USB Port for AI")
    print("#"*60)
    print()
    print("The Old World:")
    print('  "Just read the system prompt to figure out what the agent does."')
    print()
    print("The Engineering Reality:")
    print("  That is unscalable. If we want to pull specialized agents from")
    print("  a marketplace, we cannot guess how to talk to them.")
    print()
    print("The Solution:")
    print("  OpenAgent Definition (OAD) - A standard interface definition")
    print("  language for AI agents, similar to Swagger/OpenAPI for REST APIs.")
    print()
    print("The Lesson:")
    print('  This is the "USB Port" moment for AI. The startup that defines')
    print("  the Standard Agent Protocol wins the platform war.")
    print()
    print("#"*60)
    print()
    
    input("Press Enter to start examples...")
    print()
    
    example_1_basic_manifest()
    input("Press Enter for next example...")
    print()
    
    example_2_marketplace_discovery()
    input("Press Enter for next example...")
    print()
    
    example_3_agent_composition()
    input("Press Enter for next example...")
    print()
    
    example_4_trust_score_updates()
    input("Press Enter for next example...")
    print()
    
    example_5_saving_and_loading()
    
    print("="*60)
    print("All examples completed!")
    print()
    print("Key Takeaways:")
    print("  1. Capabilities: What the agent CAN do")
    print("  2. Constraints: What the agent WON'T/CAN'T do")
    print("  3. IO Contract: Standard input/output specification")
    print("  4. Trust Score: Real performance metrics")
    print()
    print("This is how we build the agent marketplace of the future!")
    print("="*60)


if __name__ == "__main__":
    main()
