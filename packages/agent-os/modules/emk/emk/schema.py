# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
# Public Preview — basic context/memory management
"""
Episode Schema — core data structures for episodic memory.

Defines mutable Episode and SemanticRule models.
"""

from datetime import datetime, timezone
from typing import Any, Dict, Optional, List
from pydantic import BaseModel, Field, model_validator
import hashlib
import json


class Episode(BaseModel):
    """
    An immutable episode representing a single agent experience.
    
    Episodes follow the pattern: Goal -> Action -> Result -> Reflection
    and are stored in an append-only manner with no modifications allowed.
    
    Attributes:
        goal: The agent's intended objective
        action: The action taken to achieve the goal
        result: The outcome of the action
        reflection: Agent's analysis or learning from the experience
        timestamp: When the episode was created (auto-generated)
        metadata: Additional context or tags for indexing
        episode_id: Unique hash-based identifier (auto-generated)
    """
    
    goal: str = Field(..., description="The agent's intended objective")
    action: str = Field(..., description="The action taken to achieve the goal")
    result: str = Field(..., description="The outcome of the action")
    reflection: str = Field(..., description="Agent's analysis or learning from the experience")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc), 
        description="When the episode was created"
    )
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional context or tags")
    episode_id: str = Field(default="", description="Unique hash-based identifier")
    
    # Public Preview — basic context/memory management
    model_config = {
        "json_schema_extra": {
            "example": {
                "goal": "Retrieve user preferences",
                "action": "Query database for user_id=123",
                "result": "Successfully retrieved preferences",
                "reflection": "Database query was efficient and returned expected data",
                "metadata": {"user_id": "123", "query_time_ms": 45}
            }
        }
    }
    
    @model_validator(mode='before')
    @classmethod
    def generate_episode_id(cls, data: Any) -> Any:
        """Generate episode_id if not provided."""
        if isinstance(data, dict):
            if not data.get('episode_id'):
                content = {
                    "goal": data.get('goal', ''),
                    "action": data.get('action', ''),
                    "result": data.get('result', ''),
                    "reflection": data.get('reflection', ''),
                    "timestamp": data.get('timestamp', datetime.now(timezone.utc)).isoformat() 
                                if isinstance(data.get('timestamp'), datetime) 
                                else data.get('timestamp', datetime.now(timezone.utc).isoformat()),
                }
                content_str = json.dumps(content, sort_keys=True)
                data['episode_id'] = hashlib.sha256(content_str.encode()).hexdigest()
        return data
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert episode to dictionary format."""
        return self.model_dump()
    
    def to_json(self) -> str:
        """Convert episode to JSON string."""
        return self.model_dump_json()
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Episode":
        """Create episode from dictionary."""
        return cls(**data)
    
    @classmethod
    def from_json(cls, json_str: str) -> "Episode":
        """Create episode from JSON string."""
        return cls.model_validate_json(json_str)
    
    def is_failure(self) -> bool:
        """
        Check if this episode represents a failure/anti-pattern.
        
        Returns:
            True if the episode is marked as a failure
        """
        return self.metadata.get("is_failure", False)
    
    def mark_as_failure(self, reason: Optional[str] = None) -> "Episode":
        """
        Create a new episode marked as a failure (immutable pattern).
        
        Args:
            reason: Optional reason for the failure
            
        Returns:
            A new Episode instance with failure metadata
        """
        new_metadata = {**self.metadata, "is_failure": True}
        if reason:
            new_metadata["failure_reason"] = reason
        
        return Episode(
            goal=self.goal,
            action=self.action,
            result=self.result,
            reflection=self.reflection,
            timestamp=self.timestamp,
            metadata=new_metadata
        )


class SemanticRule(BaseModel):
    """
    A compressed semantic rule derived from multiple episodes.
    
    Semantic rules represent distilled knowledge from the "sleep cycle"
    where old episodes are summarized and compressed to reduce memory overhead.
    
    Attributes:
        rule: The compressed semantic knowledge
        source_episode_ids: IDs of episodes that contributed to this rule
        created_at: When the rule was created
        context: Optional context about when/how this rule applies
        confidence: Confidence score for the rule (0.0 to 1.0)
        metadata: Additional context or tags
        rule_id: Unique hash-based identifier (auto-generated)
    """
    
    rule: str = Field(..., description="The compressed semantic knowledge")
    source_episode_ids: List[str] = Field(
        default_factory=list,
        description="IDs of episodes that contributed to this rule"
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the rule was created"
    )
    context: Optional[str] = Field(None, description="Context about when/how this rule applies")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence score")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional context or tags")
    rule_id: str = Field(default="", description="Unique hash-based identifier")
    
    # Public Preview — basic context/memory management
    model_config = {
        "json_schema_extra": {
            "example": {
                "rule": "When querying user preferences, use indexed user_id for optimal performance",
                "source_episode_ids": ["abc123", "def456", "ghi789"],
                "context": "Database query optimization",
                "confidence": 0.95,
                "metadata": {"pattern_type": "optimization", "frequency": 15}
            }
        }
    }
    
    @model_validator(mode='before')
    @classmethod
    def generate_rule_id(cls, data: Any) -> Any:
        """Generate rule_id if not provided."""
        if isinstance(data, dict):
            if not data.get('rule_id'):
                content = {
                    "rule": data.get('rule', ''),
                    "created_at": data.get('created_at', datetime.now(timezone.utc)).isoformat()
                                 if isinstance(data.get('created_at'), datetime)
                                 else data.get('created_at', datetime.now(timezone.utc).isoformat()),
                }
                content_str = json.dumps(content, sort_keys=True)
                data['rule_id'] = hashlib.sha256(content_str.encode()).hexdigest()
        return data
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary format."""
        return self.model_dump()
    
    def to_json(self) -> str:
        """Convert rule to JSON string."""
        return self.model_dump_json()
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SemanticRule":
        """Create rule from dictionary."""
        return cls(**data)
    
    @classmethod
    def from_json(cls, json_str: str) -> "SemanticRule":
        """Create rule from JSON string."""
        return cls.model_validate_json(json_str)
