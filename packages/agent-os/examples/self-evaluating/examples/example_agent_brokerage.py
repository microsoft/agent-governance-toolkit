# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Example: Agent Brokerage Layer - The API Economy

This example demonstrates the future of specialized agents:
- Agents compete on UTILITY (price, speed, quality)
- Users pay per API call, not monthly subscriptions
- The Orchestrator micro-bids for the best agent for each task
- Real-time cost tracking and optimization

The Old World: "Subscribe to my Agent for $20/month"
The New World: "Pay $0.01 for 10 seconds of specialized work"
"""

from typing import Dict
import sys
import os

# Add parent directory to path to allow imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.agent_brokerage import (
    AgentMarketplace,
    AgentBroker,
    AgentListing,
    AgentPricing,
    PricingModel,
    create_sample_agents
)


def demo_agent_discovery():
    """Demonstrate agent discovery in the marketplace."""
    print("\n" + "="*60)
    print("DEMO 1: Agent Discovery")
    print("="*60)
    
    # Create marketplace
    marketplace = AgentMarketplace()
    
    # Register sample agents
    for agent in create_sample_agents():
        marketplace.register_agent(agent)
    
    # Discover all agents
    print("\n[MARKETPLACE] All Available Agents:")
    for agent in marketplace.list_all_agents():
        print(f"\n  • {agent.name}")
        print(f"    ID: {agent.agent_id}")
        print(f"    Price: ${agent.pricing.base_price:.4f} per execution")
        print(f"    Speed: {agent.avg_latency_ms:.0f}ms average")
        print(f"    Success Rate: {agent.success_rate:.1%}")
        print(f"    Capabilities: {', '.join(agent.capabilities)}")
    
    # Discover agents by capability
    print("\n[DISCOVERY] Agents with 'pdf_ocr' capability:")
    ocr_agents = marketplace.discover_agents(capability_filter="pdf_ocr")
    for agent in ocr_agents:
        print(f"  • {agent.name} - ${agent.pricing.base_price:.4f}")
    
    # Discover budget agents
    print("\n[DISCOVERY] Budget Agents (< $0.03):")
    budget_agents = marketplace.discover_agents(max_price=0.03)
    for agent in budget_agents:
        print(f"  • {agent.name} - ${agent.pricing.base_price:.4f}")


def demo_agent_bidding():
    """Demonstrate agent bidding for tasks."""
    print("\n" + "="*60)
    print("DEMO 2: Agent Bidding")
    print("="*60)
    
    # Setup
    marketplace = AgentMarketplace()
    for agent in create_sample_agents():
        marketplace.register_agent(agent)
    
    broker = AgentBroker(marketplace)
    
    # Task: Extract text from PDF
    task = "Extract text from invoice.pdf"
    
    print(f"\n[TASK] {task}")
    print("\n[BIDDING PROCESS] Requesting bids from all agents...")
    
    bids = broker.request_bids(task)
    
    print(f"\nReceived {len(bids)} bids:\n")
    for i, bid in enumerate(bids, 1):
        print(f"{i}. {bid.agent_name}")
        print(f"   Cost: ${bid.estimated_cost:.4f}")
        print(f"   Latency: {bid.estimated_latency_ms:.0f}ms")
        print(f"   Confidence: {bid.confidence_score:.1%}")
        print(f"   Overall Score: {bid.bid_score:.2f}/1.00")
        print()


def demo_task_execution():
    """Demonstrate task execution with agent selection."""
    print("\n" + "="*60)
    print("DEMO 3: Task Execution with Best Value Selection")
    print("="*60)
    
    # Setup
    marketplace = AgentMarketplace()
    for agent in create_sample_agents():
        marketplace.register_agent(agent)
    
    broker = AgentBroker(marketplace)
    
    # Execute task with best value strategy
    task = "Summarize this PDF document"
    result = broker.execute_task(
        task=task,
        selection_strategy="best_value",
        verbose=True
    )
    
    print(f"\n[RESULT]")
    print(f"  Success: {result['success']}")
    print(f"  Agent Used: {result['agent_name']}")
    print(f"  Response: {result['response']}")


def demo_cost_optimization():
    """Demonstrate different selection strategies."""
    print("\n" + "="*60)
    print("DEMO 4: Cost Optimization Strategies")
    print("="*60)
    
    # Setup
    marketplace = AgentMarketplace()
    for agent in create_sample_agents():
        marketplace.register_agent(agent)
    
    broker = AgentBroker(marketplace)
    
    task = "Extract text from document.pdf"
    
    strategies = ["best_value", "cheapest", "fastest", "most_reliable"]
    
    for strategy in strategies:
        print(f"\n[STRATEGY: {strategy.upper()}]")
        result = broker.execute_task(
            task=task,
            selection_strategy=strategy,
            verbose=False
        )
        print(f"  Agent: {result['agent_name']}")
        print(f"  Cost: ${result['actual_cost']:.4f}")
        print(f"  Latency: {result['actual_latency_ms']:.0f}ms")


def demo_user_constraints():
    """Demonstrate execution with user constraints."""
    print("\n" + "="*60)
    print("DEMO 5: User Constraints")
    print("="*60)
    
    # Setup
    marketplace = AgentMarketplace()
    for agent in create_sample_agents():
        marketplace.register_agent(agent)
    
    broker = AgentBroker(marketplace)
    
    task = "Process this PDF document"
    
    # Constraint 1: Budget conscious (max $0.02)
    print("\n[SCENARIO 1] Budget Conscious User (max $0.02)")
    result = broker.execute_task(
        task=task,
        user_constraints={"max_budget": 0.02},
        verbose=True
    )
    
    # Constraint 2: Speed critical (max 1000ms)
    print("\n[SCENARIO 2] Speed Critical User (max 1000ms)")
    result = broker.execute_task(
        task=task,
        user_constraints={"max_latency_ms": 1000},
        verbose=True
    )


def demo_usage_tracking():
    """Demonstrate usage and cost tracking."""
    print("\n" + "="*60)
    print("DEMO 6: Usage Tracking & Micro-Payments")
    print("="*60)
    
    # Setup
    marketplace = AgentMarketplace()
    for agent in create_sample_agents():
        marketplace.register_agent(agent)
    
    broker = AgentBroker(marketplace)
    
    # Execute multiple tasks
    tasks = [
        "Extract text from invoice1.pdf",
        "Summarize quarterly_report.pdf",
        "Extract text from receipt.pdf",
        "Summarize meeting_notes.pdf",
        "Extract text from contract.pdf"
    ]
    
    print("\n[EXECUTION] Running 5 tasks...")
    for i, task in enumerate(tasks, 1):
        print(f"\nTask {i}/{len(tasks)}: {task}")
        result = broker.execute_task(task, verbose=False)
        print(f"  ✓ Agent: {result['agent_name']}, Cost: ${result['actual_cost']:.4f}")
    
    # Get usage report
    print("\n" + "="*60)
    print("USAGE REPORT")
    print("="*60)
    
    report = broker.get_usage_report()
    
    print(f"\n[SUMMARY]")
    print(f"  Total Spent: ${report['total_spent']:.4f}")
    print(f"  Total Executions: {report['total_executions']}")
    print(f"  Success Rate: {report['success_rate']:.1%}")
    
    print(f"\n[BREAKDOWN BY AGENT]")
    for agent_id, stats in report['agent_breakdown'].items():
        agent = marketplace.get_agent(agent_id)
        print(f"\n  {agent.name if agent else agent_id}:")
        print(f"    Executions: {stats['executions']}")
        print(f"    Total Cost: ${stats['total_cost']:.4f}")
        print(f"    Avg Latency: {stats['avg_latency_ms']:.0f}ms")
        print(f"    Success Rate: {stats['success_rate']:.1%}")


def demo_api_economy_comparison():
    """Compare subscription vs. utility-based pricing."""
    print("\n" + "="*60)
    print("DEMO 7: The Economics - Subscription vs. Utility")
    print("="*60)
    
    # Setup
    marketplace = AgentMarketplace()
    for agent in create_sample_agents():
        marketplace.register_agent(agent)
    
    broker = AgentBroker(marketplace)
    
    # Simulate one day of usage (10 tasks)
    num_tasks = 10
    print(f"\n[SCENARIO] User needs to process {num_tasks} PDFs in one day")
    
    print("\n[EXECUTING TASKS...]")
    for i in range(num_tasks):
        broker.execute_task(
            f"Process document_{i}.pdf",
            selection_strategy="best_value",
            verbose=False
        )
    
    report = broker.get_usage_report()
    
    print(f"\n[OLD WORLD: Subscription Model]")
    print(f"  Monthly Cost: $20.00")
    print(f"  Cost Per Day: $0.67 (assuming 30 days)")
    print(f"  Cost for {num_tasks} tasks: $0.67")
    print(f"  → User pays even if they don't use the agent!")
    
    print(f"\n[NEW WORLD: Utility Model (Pay-Per-Use)]")
    print(f"  Cost for {num_tasks} tasks: ${report['total_spent']:.4f}")
    print(f"  Cost Per Task: ${report['total_spent'] / num_tasks:.4f}")
    print(f"  → User pays ONLY for what they use!")
    
    savings = 0.67 - report['total_spent']
    savings_pct = (savings / 0.67) * 100
    
    print(f"\n[SAVINGS]")
    print(f"  Amount Saved: ${savings:.4f}")
    print(f"  Savings Percentage: {savings_pct:.1f}%")
    print(f"\n  💡 Key Insight: For occasional use, utility pricing is FAR cheaper!")


def demo_agent_integration_with_doer():
    """Demonstrate integration with DoerAgent."""
    print("\n" + "="*60)
    print("DEMO 8: Integration with Existing Agent System")
    print("="*60)
    
    try:
        from agent import DoerAgent
    except ImportError:
        print("\n⚠️  Skipping DoerAgent integration demo (openai module not installed)")
        print("Install with: pip install openai")
        return
    
    # Setup marketplace
    marketplace = AgentMarketplace()
    
    # Register DoerAgent as a worker in the marketplace
    def doer_executor(task: str, metadata: Dict) -> str:
        doer = DoerAgent(enable_telemetry=False)
        result = doer.run(task, verbose=False)
        return result["response"]
    
    doer_listing = AgentListing(
        agent_id="doer_agent",
        name="Self-Evolving Doer Agent",
        description="General-purpose self-improving AI agent",
        capabilities=["calculations", "time_queries", "string_operations", "general_tasks"],
        pricing=AgentPricing(
            model=PricingModel.PER_EXECUTION,
            base_price=0.03  # $0.03 per execution
        ),
        executor=doer_executor,
        avg_latency_ms=1200.0,
        success_rate=0.92
    )
    
    marketplace.register_agent(doer_listing)
    
    # Also register specialized agents
    for agent in create_sample_agents():
        marketplace.register_agent(agent)
    
    broker = AgentBroker(marketplace)
    
    # Test with a calculation task (DoerAgent's specialty)
    print("\n[TASK 1] Mathematical Calculation")
    result = broker.execute_task(
        "What is 25 * 47 + 100?",
        verbose=True
    )
    
    # Test with a PDF task (specialized agents' specialty)
    print("\n[TASK 2] PDF Processing")
    result = broker.execute_task(
        "Extract text from invoice.pdf",
        verbose=True
    )


def main():
    """Run all demos."""
    print("\n" + "="*70)
    print("AGENT BROKERAGE LAYER DEMONSTRATION")
    print("The Future: API Economy for Specialized Agents")
    print("="*70)
    print("\nThe Old World: Subscribe to my Agent for $20/month")
    print("The New World: Pay $0.01 for 10 seconds of work")
    print("\nKey Innovation: Micro-payments for Micro-tasks")
    
    try:
        demo_agent_discovery()
        demo_agent_bidding()
        demo_task_execution()
        demo_cost_optimization()
        demo_user_constraints()
        demo_usage_tracking()
        demo_api_economy_comparison()
        demo_agent_integration_with_doer()
        
        print("\n" + "="*70)
        print("THE LESSON")
        print("="*70)
        print("\nThe future is an API Economy.")
        print("Specialized agent developers won't sell subscriptions;")
        print("they will sell UTILITY and get paid by the API call.")
        print("\nThis is the shift from:")
        print("  • Rent (subscriptions) → Own (utility)")
        print("  • Monthly commitments → Per-use payments")
        print("  • Platform lock-in → Open marketplace")
        print("="*70)
        
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
