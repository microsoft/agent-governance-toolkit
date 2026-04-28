# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
OpenAgent Definition (OAD) - Metadata Manifest System

This module implements an Interface Definition Language (IDL) for AI Agents,
similar to Swagger/OpenAPI for REST APIs.

Every agent publishes a metadata manifest that includes:
1. Capabilities: What the agent can do
2. Constraints: What the agent won't/can't do
3. IO Contract: Input/output specifications
4. Trust Score: Performance and reliability metrics

This is the "USB Port" moment for AI - standardizing agent interfaces.
"""

import json
import os
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from datetime import datetime


@dataclass
class Capability:
    """
    Represents a single capability of the agent.
    
    Example:
        - "I can write Python 3.9 code"
        - "I can parse CSV files"
        - "I can execute SQL queries"
    """
    name: str
    description: str
    tags: List[str] = field(default_factory=list)
    version: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class Constraint:
    """
    Represents a constraint or limitation of the agent.
    
    Example:
        - "I have no internet access"
        - "I have a 4k token limit"
        - "I cannot execute shell commands"
    """
    type: str  # e.g., "access", "resource", "security"
    description: str
    severity: str = "high"  # "low", "medium", "high"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class IOContract:
    """
    Defines the input/output contract for the agent.
    
    Similar to API specifications in OpenAPI/Swagger.
    """
    input_schema: Dict[str, Any]
    output_schema: Dict[str, Any]
    examples: List[Dict[str, Any]] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class TrustScore:
    """
    Performance and reliability metrics for the agent.
    
    Example:
        - "My code compiles 95% of the time"
        - "Average response time: 1.2s"
        - "Task completion rate: 87%"
    """
    success_rate: float  # 0.0 to 1.0
    avg_latency_ms: Optional[float] = None
    total_executions: int = 0
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())
    metrics: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class AgentMetadata:
    """
    Complete metadata manifest for an AI agent.
    
    This is the "OpenAgent Definition" (OAD) - a standard interface
    definition language for AI agents, analogous to OpenAPI for REST APIs.
    """
    agent_id: str
    name: str
    version: str
    description: str
    capabilities: List[Capability] = field(default_factory=list)
    constraints: List[Constraint] = field(default_factory=list)
    io_contract: Optional[IOContract] = None
    trust_score: Optional[TrustScore] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now().isoformat())
    
    def add_capability(self, name: str, description: str, 
                      tags: Optional[List[str]] = None, 
                      version: Optional[str] = None) -> None:
        """Add a capability to the agent."""
        capability = Capability(
            name=name,
            description=description,
            tags=tags or [],
            version=version
        )
        self.capabilities.append(capability)
        self.updated_at = datetime.now().isoformat()
    
    def add_constraint(self, type: str, description: str, 
                      severity: str = "high") -> None:
        """Add a constraint to the agent."""
        constraint = Constraint(
            type=type,
            description=description,
            severity=severity
        )
        self.constraints.append(constraint)
        self.updated_at = datetime.now().isoformat()
    
    def set_io_contract(self, input_schema: Dict[str, Any], 
                       output_schema: Dict[str, Any],
                       examples: Optional[List[Dict[str, Any]]] = None) -> None:
        """Set the input/output contract for the agent."""
        self.io_contract = IOContract(
            input_schema=input_schema,
            output_schema=output_schema,
            examples=examples or []
        )
        self.updated_at = datetime.now().isoformat()
    
    def set_trust_score(self, success_rate: float, 
                       avg_latency_ms: Optional[float] = None,
                       total_executions: int = 0,
                       metrics: Optional[Dict[str, Any]] = None) -> None:
        """Set the trust score for the agent."""
        self.trust_score = TrustScore(
            success_rate=success_rate,
            avg_latency_ms=avg_latency_ms,
            total_executions=total_executions,
            metrics=metrics or {}
        )
        self.updated_at = datetime.now().isoformat()
    
    def update_trust_score(self, success: bool, latency_ms: Optional[float] = None) -> None:
        """
        Update trust score based on a new execution.
        
        Args:
            success: Whether the execution was successful
            latency_ms: Latency in milliseconds
        """
        if self.trust_score is None:
            self.trust_score = TrustScore(success_rate=0.0, total_executions=0)
        
        # Update success rate using running average
        total = self.trust_score.total_executions
        current_rate = self.trust_score.success_rate
        new_success_value = 1.0 if success else 0.0
        
        self.trust_score.success_rate = (current_rate * total + new_success_value) / (total + 1)
        self.trust_score.total_executions += 1
        
        # Update average latency
        if latency_ms is not None:
            if self.trust_score.avg_latency_ms is None:
                self.trust_score.avg_latency_ms = latency_ms
            else:
                current_avg = self.trust_score.avg_latency_ms
                self.trust_score.avg_latency_ms = (current_avg * total + latency_ms) / (total + 1)
        
        self.trust_score.last_updated = datetime.now().isoformat()
        self.updated_at = datetime.now().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = {
            "agent_id": self.agent_id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "capabilities": [cap.to_dict() for cap in self.capabilities],
            "constraints": [con.to_dict() for con in self.constraints],
            "io_contract": self.io_contract.to_dict() if self.io_contract else None,
            "trust_score": self.trust_score.to_dict() if self.trust_score else None,
            "metadata": self.metadata,
            "created_at": self.created_at,
            "updated_at": self.updated_at
        }
        return data
    
    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'AgentMetadata':
        """Create from dictionary."""
        # Parse capabilities
        capabilities = [
            Capability(**cap) for cap in data.get("capabilities", [])
        ]
        
        # Parse constraints
        constraints = [
            Constraint(**con) for con in data.get("constraints", [])
        ]
        
        # Parse IO contract
        io_contract = None
        if data.get("io_contract"):
            io_contract = IOContract(**data["io_contract"])
        
        # Parse trust score
        trust_score = None
        if data.get("trust_score"):
            trust_score = TrustScore(**data["trust_score"])
        
        return cls(
            agent_id=data["agent_id"],
            name=data["name"],
            version=data["version"],
            description=data["description"],
            capabilities=capabilities,
            constraints=constraints,
            io_contract=io_contract,
            trust_score=trust_score,
            metadata=data.get("metadata", {}),
            created_at=data.get("created_at", datetime.now().isoformat()),
            updated_at=data.get("updated_at", datetime.now().isoformat())
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> 'AgentMetadata':
        """Create from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)


class AgentMetadataManager:
    """
    Manages loading, saving, and publishing agent metadata manifests.
    
    This is the "Standard Agent Protocol" that enables agent marketplaces
    and interoperability between different AI agents.
    """
    
    def __init__(self, manifest_file: str = "agent_manifest.json"):
        self.manifest_file = manifest_file
        self.metadata: Optional[AgentMetadata] = None
    
    def load_manifest(self) -> Optional[AgentMetadata]:
        """Load metadata manifest from file."""
        if not os.path.exists(self.manifest_file):
            return None
        
        try:
            with open(self.manifest_file, 'r') as f:
                data = json.load(f)
            self.metadata = AgentMetadata.from_dict(data)
            return self.metadata
        except (json.JSONDecodeError, IOError, KeyError) as e:
            print(f"Error loading manifest: {e}")
            return None
    
    def save_manifest(self, metadata: AgentMetadata) -> bool:
        """Save metadata manifest to file."""
        try:
            with open(self.manifest_file, 'w') as f:
                json.dump(metadata.to_dict(), f, indent=2)
            self.metadata = metadata
            return True
        except IOError as e:
            print(f"Error saving manifest: {e}")
            return False
    
    def create_manifest(self, agent_id: str, name: str, version: str, 
                       description: str) -> AgentMetadata:
        """Create a new metadata manifest."""
        metadata = AgentMetadata(
            agent_id=agent_id,
            name=name,
            version=version,
            description=description
        )
        self.metadata = metadata
        return metadata
    
    def get_manifest(self) -> Optional[AgentMetadata]:
        """Get the current metadata manifest."""
        if self.metadata is None:
            self.load_manifest()
        return self.metadata
    
    def publish_manifest(self) -> Dict[str, Any]:
        """
        Publish the metadata manifest.
        
        In a real system, this would publish to a marketplace or registry.
        For now, it returns the manifest in a publishable format.
        """
        if self.metadata is None:
            raise ValueError("No manifest to publish. Create or load a manifest first.")
        
        return {
            "status": "published",
            "manifest": self.metadata.to_dict(),
            "published_at": datetime.now().isoformat()
        }
    
    def discover_agents(self, capability_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Discover agents with specific capabilities.
        
        In a real system, this would query a marketplace or registry.
        For now, it returns a mock discovery result.
        """
        # Mock implementation - would query a real registry in production
        return [
            {
                "agent_id": self.metadata.agent_id if self.metadata else "unknown",
                "name": self.metadata.name if self.metadata else "Unknown Agent",
                "version": self.metadata.version if self.metadata else "0.0.0",
                "capabilities": [cap.name for cap in (self.metadata.capabilities if self.metadata else [])]
            }
        ]
    
    def validate_compatibility(self, other_manifest: AgentMetadata) -> Dict[str, Any]:
        """
        Validate compatibility between this agent and another agent.
        
        Checks if this agent can work with another agent based on their
        IO contracts and capabilities.
        """
        if self.metadata is None:
            return {"compatible": False, "reason": "No local manifest loaded"}
        
        compatibility_report = {
            "compatible": True,
            "warnings": [],
            "errors": []
        }
        
        # Check IO contract compatibility
        if self.metadata.io_contract and other_manifest.io_contract:
            # Simple check - in production would do deep schema validation
            if self.metadata.io_contract.output_schema != other_manifest.io_contract.input_schema:
                compatibility_report["warnings"].append(
                    "Output schema may not match input schema of target agent"
                )
        
        # Check constraint compatibility
        for constraint in self.metadata.constraints:
            if constraint.severity == "high":
                compatibility_report["warnings"].append(
                    f"Agent has high-severity constraint: {constraint.description}"
                )
        
        return compatibility_report


def create_default_manifest(agent_id: str = "self-evolving-agent",
                           name: str = "Self-Evolving Agent",
                           version: str = "1.0.0") -> AgentMetadata:
    """
    Create a default metadata manifest for the self-evolving agent.
    
    This demonstrates the standard format that all agents should publish.
    """
    metadata = AgentMetadata(
        agent_id=agent_id,
        name=name,
        version=version,
        description="A self-evolving AI agent that improves its own system instructions based on performance feedback"
    )
    
    # Add capabilities
    metadata.add_capability(
        name="mathematical_calculations",
        description="Can evaluate mathematical expressions safely using AST parsing",
        tags=["math", "calculations", "computation"],
        version="1.0"
    )
    
    metadata.add_capability(
        name="time_queries",
        description="Can retrieve current date and time information",
        tags=["time", "datetime", "timestamp"],
        version="1.0"
    )
    
    metadata.add_capability(
        name="string_operations",
        description="Can perform string operations like length calculation",
        tags=["strings", "text", "processing"],
        version="1.0"
    )
    
    metadata.add_capability(
        name="self_improvement",
        description="Can reflect on its own performance and evolve system instructions",
        tags=["meta-learning", "self-improvement", "evolution"],
        version="1.0"
    )
    
    # Add constraints
    metadata.add_constraint(
        type="resource",
        description="No direct internet access - operates in sandboxed environment",
        severity="high"
    )
    
    metadata.add_constraint(
        type="resource",
        description="Token limit of 4096 tokens per request",
        severity="medium"
    )
    
    metadata.add_constraint(
        type="security",
        description="Cannot execute arbitrary shell commands",
        severity="high"
    )
    
    metadata.add_constraint(
        type="access",
        description="Read-only file system access during execution",
        severity="medium"
    )
    
    # Set IO contract
    metadata.set_io_contract(
        input_schema={
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "The user's query to process"
                },
                "user_id": {
                    "type": "string",
                    "description": "Optional user identifier",
                    "required": False
                },
                "conversation_id": {
                    "type": "string",
                    "description": "Optional conversation identifier",
                    "required": False
                }
            },
            "required": ["query"]
        },
        output_schema={
            "type": "object",
            "properties": {
                "response": {
                    "type": "string",
                    "description": "The agent's response to the query"
                },
                "instructions_version": {
                    "type": "integer",
                    "description": "Version of system instructions used"
                },
                "telemetry_emitted": {
                    "type": "boolean",
                    "description": "Whether telemetry was emitted"
                }
            }
        },
        examples=[
            {
                "input": {"query": "What is 10 + 20?"},
                "output": {
                    "response": "Result: 30",
                    "instructions_version": 1,
                    "telemetry_emitted": True
                }
            },
            {
                "input": {"query": "What time is it?"},
                "output": {
                    "response": "Current time: 2024-01-01 12:00:00",
                    "instructions_version": 1,
                    "telemetry_emitted": True
                }
            }
        ]
    )
    
    # Set initial trust score
    metadata.set_trust_score(
        success_rate=0.95,
        avg_latency_ms=1200.0,
        total_executions=0,
        metrics={
            "code_compilation_rate": 0.95,
            "task_completion_rate": 0.87,
            "user_satisfaction": 0.92
        }
    )
    
    return metadata
