# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Brokerage Layer - The API Economy for Specialized Agents

This module implements an agent marketplace and brokerage system where:
1. Agents publish their capabilities and pricing (utility-based, not subscriptions)
2. Orchestrators can discover and select agents based on task requirements
3. Micro-payments are made per API call, not monthly subscriptions
4. Agents compete on price, speed, and quality

The Lesson:
The future is an API Economy. Specialized agent developers won't sell subscriptions;
they will sell Utility and get paid by the API call.

Key Components:
- AgentListing: Agent with pricing and capabilities
- AgentMarketplace: Registry of available agents
- AgentBroker: Selects best agent for a task based on bidding
- MicroPaymentTracker: Tracks usage and costs
"""

from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json
import time


class PricingModel(Enum):
    """Pricing models for agents."""
    PER_EXECUTION = "per_execution"  # Flat fee per execution
    PER_TOKEN = "per_token"  # Price per token processed
    PER_SECOND = "per_second"  # Price per second of computation
    TIERED = "tiered"  # Different prices for different request volumes


@dataclass
class AgentPricing:
    """
    Pricing information for an agent.
    
    Example:
        - PDF OCR Agent: $0.01 per execution, ~2s latency
        - Advanced OCR Agent: $0.05 per execution, ~0.5s latency (faster)
    """
    model: PricingModel
    base_price: float  # Base price in dollars
    per_token_price: Optional[float] = None  # Price per 1000 tokens if applicable
    per_second_price: Optional[float] = None  # Price per second if applicable
    currency: str = "USD"
    free_tier_limit: int = 0  # Number of free executions
    
    def calculate_cost(self, tokens: int = 0, seconds: float = 0.0) -> float:
        """
        Calculate cost based on usage.
        
        Note: This implementation allows for hybrid pricing models where
        base_price is always charged and additional costs are added based
        on the model type. For pure per-token or per-second pricing,
        set base_price to 0.0.
        
        Examples:
        - Pure per-execution: base_price=0.01, model=PER_EXECUTION
        - Pure per-token: base_price=0.0, per_token_price=0.002, model=PER_TOKEN
        - Hybrid: base_price=0.01, per_token_price=0.001, model=PER_TOKEN
        
        Args:
            tokens: Number of tokens processed
            seconds: Execution time in seconds
        
        Returns:
            Total cost in dollars
        """
        cost = self.base_price
        
        if self.model == PricingModel.PER_TOKEN and self.per_token_price:
            cost += (tokens / 1000.0) * self.per_token_price
        
        if self.model == PricingModel.PER_SECOND and self.per_second_price:
            cost += seconds * self.per_second_price
        
        return cost
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "model": self.model.value,
            "base_price": self.base_price,
            "per_token_price": self.per_token_price,
            "per_second_price": self.per_second_price,
            "currency": self.currency,
            "free_tier_limit": self.free_tier_limit
        }


@dataclass
class AgentListing:
    """
    An agent listing in the marketplace.
    
    Includes agent metadata, pricing, and executor function.
    """
    agent_id: str
    name: str
    description: str
    capabilities: List[str]
    pricing: AgentPricing
    executor: Callable[[str, Dict[str, Any]], str]  # Function to execute the agent
    avg_latency_ms: float = 1000.0
    success_rate: float = 0.95
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def calculate_score(self, task: str, user_constraints: Optional[Dict[str, Any]] = None) -> float:
        """
        Calculate a score for this agent for a given task.
        
        Scoring is based on:
        - Success rate: 30% weight (reliability)
        - Speed (latency): 30% weight (performance)
        - Pricing: 40% weight (cost)
        
        User constraints act as hard filters:
        - max_budget: Eliminates agents exceeding budget
        - max_latency_ms: Eliminates agents too slow
        
        Note: Capability matching is done during agent discovery/bidding,
        not in scoring. Only agents with relevant capabilities receive bids.
        
        Returns:
            Score between 0 and 1 (higher is better)
        """
        score = 0.0
        
        # Base score from success rate (0-30 points)
        score += self.success_rate * 30
        
        # Speed score - faster is better (0-30 points)
        # Normalize latency (assuming 0-5000ms range)
        speed_score = max(0, 1 - (self.avg_latency_ms / 5000.0)) * 30
        score += speed_score
        
        # Pricing score - cheaper is better (0-40 points)
        # Normalize price (assuming $0-$1 range)
        price_score = max(0, 1 - (self.pricing.base_price / 1.0)) * 40
        score += price_score
        
        # Apply user constraints
        if user_constraints:
            max_budget = user_constraints.get("max_budget")
            if max_budget and self.pricing.base_price > max_budget:
                return 0.0  # Exceeds budget, eliminate
            
            max_latency = user_constraints.get("max_latency_ms")
            if max_latency and self.avg_latency_ms > max_latency:
                return 0.0  # Too slow, eliminate
        
        return score / 100.0  # Normalize to 0-1
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary (excluding executor)."""
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "description": self.description,
            "capabilities": self.capabilities,
            "pricing": self.pricing.to_dict(),
            "avg_latency_ms": self.avg_latency_ms,
            "success_rate": self.success_rate,
            "metadata": self.metadata
        }


@dataclass
class AgentBid:
    """
    A bid from an agent for a task.
    """
    agent_id: str
    agent_name: str
    estimated_cost: float
    estimated_latency_ms: float
    confidence_score: float  # 0-1, how confident the agent is it can handle this
    bid_score: float  # Overall score for selection
    details: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "estimated_cost": self.estimated_cost,
            "estimated_latency_ms": self.estimated_latency_ms,
            "confidence_score": self.confidence_score,
            "bid_score": self.bid_score,
            "details": self.details
        }


@dataclass
class TaskExecution:
    """
    Record of a task execution through the brokerage.
    """
    task_id: str
    task_description: str
    selected_agent_id: str
    actual_cost: float
    actual_latency_ms: float
    success: bool
    timestamp: str
    bids_received: List[AgentBid] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "task_id": self.task_id,
            "task_description": self.task_description,
            "selected_agent_id": self.selected_agent_id,
            "actual_cost": self.actual_cost,
            "actual_latency_ms": self.actual_latency_ms,
            "success": self.success,
            "timestamp": self.timestamp,
            "bids_received": [bid.to_dict() for bid in self.bids_received]
        }


class AgentMarketplace:
    """
    Registry of available agents.
    
    This is where agents publish their capabilities and pricing.
    Think of it like an "App Store" for AI agents.
    """
    
    def __init__(self):
        self.agents: Dict[str, AgentListing] = {}
    
    def register_agent(self, agent: AgentListing) -> None:
        """Register an agent in the marketplace."""
        self.agents[agent.agent_id] = agent
    
    def unregister_agent(self, agent_id: str) -> bool:
        """Remove an agent from the marketplace."""
        if agent_id in self.agents:
            del self.agents[agent_id]
            return True
        return False
    
    def discover_agents(self, capability_filter: Optional[str] = None,
                       max_price: Optional[float] = None,
                       min_success_rate: Optional[float] = None) -> List[AgentListing]:
        """
        Discover agents matching criteria.
        
        Args:
            capability_filter: Filter by capability (e.g., "pdf_ocr")
            max_price: Maximum price per execution
            min_success_rate: Minimum success rate (0-1)
        
        Returns:
            List of matching agents
        """
        results = []
        
        for agent in self.agents.values():
            # Filter by capability
            if capability_filter:
                if not any(capability_filter.lower() in cap.lower() 
                          for cap in agent.capabilities):
                    continue
            
            # Filter by price
            if max_price and agent.pricing.base_price > max_price:
                continue
            
            # Filter by success rate
            if min_success_rate and agent.success_rate < min_success_rate:
                continue
            
            results.append(agent)
        
        return results
    
    def get_agent(self, agent_id: str) -> Optional[AgentListing]:
        """Get an agent by ID."""
        return self.agents.get(agent_id)
    
    def list_all_agents(self) -> List[AgentListing]:
        """List all registered agents."""
        return list(self.agents.values())


class AgentBroker:
    """
    The Agent Broker - Selects the best agent for a task.
    
    This is the "Orchestrator" that:
    1. Receives a task from the user
    2. Requests bids from available agents
    3. Selects the best agent based on cost, speed, and quality
    4. Executes the task with the selected agent
    5. Tracks costs (micro-payments)
    
    The User pays the Orchestrator, and the Orchestrator pays the Agent.
    """
    
    def __init__(self, marketplace: AgentMarketplace):
        self.marketplace = marketplace
        self.execution_history: List[TaskExecution] = []
        self.total_spent = 0.0
    
    def request_bids(self, task: str, task_metadata: Optional[Dict[str, Any]] = None,
                    user_constraints: Optional[Dict[str, Any]] = None) -> List[AgentBid]:
        """
        Request bids from all capable agents.
        
        Args:
            task: Description of the task
            task_metadata: Additional task information
            user_constraints: User constraints (max budget, max latency, etc.)
        
        Returns:
            List of bids from agents
        """
        bids = []
        
        # Get relevant agents
        agents = self.marketplace.list_all_agents()
        
        for agent in agents:
            # Calculate bid score
            bid_score = agent.calculate_score(task, user_constraints)
            
            if bid_score > 0:
                bid = AgentBid(
                    agent_id=agent.agent_id,
                    agent_name=agent.name,
                    estimated_cost=agent.pricing.base_price,
                    estimated_latency_ms=agent.avg_latency_ms,
                    confidence_score=agent.success_rate,
                    bid_score=bid_score,
                    details={
                        "capabilities": agent.capabilities,
                        "pricing_model": agent.pricing.model.value
                    }
                )
                bids.append(bid)
        
        # Sort bids by score (highest first)
        bids.sort(key=lambda b: b.bid_score, reverse=True)
        
        return bids
    
    def select_agent(self, bids: List[AgentBid], 
                    selection_strategy: str = "best_value") -> Optional[AgentBid]:
        """
        Select the best agent based on strategy.
        
        Args:
            bids: List of bids from agents
            selection_strategy: Strategy for selection
                - "best_value": Best overall score (default)
                - "cheapest": Lowest cost
                - "fastest": Lowest latency
                - "most_reliable": Highest success rate
        
        Returns:
            Selected bid, or None if no bids
        """
        if not bids:
            return None
        
        if selection_strategy == "cheapest":
            return min(bids, key=lambda b: b.estimated_cost)
        elif selection_strategy == "fastest":
            return min(bids, key=lambda b: b.estimated_latency_ms)
        elif selection_strategy == "most_reliable":
            return max(bids, key=lambda b: b.confidence_score)
        else:  # best_value (default)
            return bids[0]  # Already sorted by bid_score
    
    def execute_task(self, task: str, task_metadata: Optional[Dict[str, Any]] = None,
                    user_constraints: Optional[Dict[str, Any]] = None,
                    selection_strategy: str = "best_value",
                    verbose: bool = True) -> Dict[str, Any]:
        """
        Execute a task by selecting and running the best agent.
        
        Args:
            task: Description of the task
            task_metadata: Additional task information
            user_constraints: User constraints (max budget, max latency)
            selection_strategy: Strategy for agent selection
            verbose: Print execution details
        
        Returns:
            Execution result with agent response, cost, and metadata
        """
        if verbose:
            print("="*60)
            print("AGENT BROKERAGE: Executing Task")
            print("="*60)
            print(f"Task: {task}")
            if user_constraints:
                print(f"Constraints: {user_constraints}")
        
        # Request bids from agents
        bids = self.request_bids(task, task_metadata, user_constraints)
        
        if verbose:
            print(f"\n[BIDDING] Received {len(bids)} bids")
            for i, bid in enumerate(bids[:3], 1):  # Show top 3
                print(f"  {i}. {bid.agent_name}: ${bid.estimated_cost:.4f}, "
                      f"{bid.estimated_latency_ms:.0f}ms, "
                      f"score={bid.bid_score:.2f}")
        
        # Select best agent
        selected_bid = self.select_agent(bids, selection_strategy)
        
        if not selected_bid:
            return {
                "success": False,
                "error": "No agents available for this task",
                "bids_received": []
            }
        
        if verbose:
            print(f"\n[SELECTION] Selected: {selected_bid.agent_name}")
            print(f"  Strategy: {selection_strategy}")
            print(f"  Estimated Cost: ${selected_bid.estimated_cost:.4f}")
            print(f"  Estimated Latency: {selected_bid.estimated_latency_ms:.0f}ms")
        
        # Get the agent
        agent = self.marketplace.get_agent(selected_bid.agent_id)
        if not agent:
            return {
                "success": False,
                "error": f"Agent {selected_bid.agent_id} not found in marketplace",
                "bids_received": [b.to_dict() for b in bids]
            }
        
        # Execute the task
        start_time = time.time()
        
        try:
            response = agent.executor(task, task_metadata or {})
            success = True
        except Exception as e:
            response = f"Error: {str(e)}"
            success = False
        
        actual_latency_ms = (time.time() - start_time) * 1000
        
        # Calculate actual cost
        # Note: Token counting is a placeholder (set to 0)
        # In production, this would use a token counter library
        # to calculate actual tokens from request/response
        actual_cost = agent.pricing.calculate_cost(
            tokens=0,  # TODO: Calculate actual token usage
            seconds=actual_latency_ms / 1000.0
        )
        
        if verbose:
            print(f"\n[EXECUTION] {'✓ Success' if success else '✗ Failed'}")
            print(f"  Actual Cost: ${actual_cost:.4f}")
            print(f"  Actual Latency: {actual_latency_ms:.0f}ms")
            print(f"  Response: {str(response)[:100]}...")
        
        # Record execution
        execution = TaskExecution(
            task_id=f"task_{len(self.execution_history) + 1}",
            task_description=task,
            selected_agent_id=selected_bid.agent_id,
            actual_cost=actual_cost,
            actual_latency_ms=actual_latency_ms,
            success=success,
            timestamp=datetime.now().isoformat(),
            bids_received=bids
        )
        self.execution_history.append(execution)
        self.total_spent += actual_cost
        
        if verbose:
            print(f"\n[PAYMENT] Micro-payment processed: ${actual_cost:.4f}")
            print(f"  Total Spent: ${self.total_spent:.4f}")
            print("="*60)
        
        return {
            "success": success,
            "response": response,
            "agent_id": selected_bid.agent_id,
            "agent_name": selected_bid.agent_name,
            "actual_cost": actual_cost,
            "estimated_cost": selected_bid.estimated_cost,
            "actual_latency_ms": actual_latency_ms,
            "estimated_latency_ms": selected_bid.estimated_latency_ms,
            "bids_received": [b.to_dict() for b in bids],
            "total_spent": self.total_spent
        }
    
    def get_usage_report(self) -> Dict[str, Any]:
        """
        Get a usage and cost report.
        
        Returns:
            Report with total cost, executions, and breakdown by agent
        """
        agent_breakdown = {}
        total_executions = len(self.execution_history)
        successful_executions = sum(1 for e in self.execution_history if e.success)
        
        for execution in self.execution_history:
            agent_id = execution.selected_agent_id
            if agent_id not in agent_breakdown:
                agent_breakdown[agent_id] = {
                    "executions": 0,
                    "total_cost": 0.0,
                    "avg_latency_ms": 0.0,
                    "success_count": 0
                }
            
            agent_breakdown[agent_id]["executions"] += 1
            agent_breakdown[agent_id]["total_cost"] += execution.actual_cost
            agent_breakdown[agent_id]["avg_latency_ms"] += execution.actual_latency_ms
            if execution.success:
                agent_breakdown[agent_id]["success_count"] += 1
        
        # Calculate averages
        for agent_data in agent_breakdown.values():
            if agent_data["executions"] > 0:
                agent_data["avg_latency_ms"] /= agent_data["executions"]
                agent_data["success_rate"] = agent_data["success_count"] / agent_data["executions"]
        
        return {
            "total_spent": self.total_spent,
            "total_executions": total_executions,
            "successful_executions": successful_executions,
            "success_rate": successful_executions / total_executions if total_executions > 0 else 0.0,
            "agent_breakdown": agent_breakdown
        }


def create_sample_agents() -> List[AgentListing]:
    """
    Create sample agents for demonstration.
    
    Returns:
        List of sample agent listings
    """
    agents = []
    
    # Budget PDF OCR Agent - Cheap but slower
    agents.append(AgentListing(
        agent_id="pdf_ocr_basic",
        name="Budget PDF OCR Agent",
        description="Basic PDF OCR with good accuracy, economical pricing",
        capabilities=["pdf_ocr", "text_extraction", "document_processing"],
        pricing=AgentPricing(
            model=PricingModel.PER_EXECUTION,
            base_price=0.01  # $0.01 per execution
        ),
        executor=lambda task, metadata: f"[Budget OCR] Extracted text from PDF: {task}",
        avg_latency_ms=2000.0,  # 2 seconds
        success_rate=0.90
    ))
    
    # Premium PDF OCR Agent - Expensive but faster
    agents.append(AgentListing(
        agent_id="pdf_ocr_premium",
        name="Premium PDF OCR Agent",
        description="Advanced PDF OCR with high accuracy and speed",
        capabilities=["pdf_ocr", "text_extraction", "document_processing", "handwriting_recognition"],
        pricing=AgentPricing(
            model=PricingModel.PER_EXECUTION,
            base_price=0.05  # $0.05 per execution
        ),
        executor=lambda task, metadata: f"[Premium OCR] High-quality text extraction: {task}",
        avg_latency_ms=500.0,  # 0.5 seconds
        success_rate=0.98
    ))
    
    # Text Summarization Agent
    agents.append(AgentListing(
        agent_id="text_summarizer",
        name="Text Summarization Agent",
        description="Summarizes long documents into concise summaries",
        capabilities=["summarization", "text_processing", "analysis"],
        pricing=AgentPricing(
            model=PricingModel.PER_EXECUTION,
            base_price=0.02  # $0.02 per execution
        ),
        executor=lambda task, metadata: f"[Summarizer] Summary: {task[:50]}...",
        avg_latency_ms=1500.0,
        success_rate=0.95
    ))
    
    return agents
