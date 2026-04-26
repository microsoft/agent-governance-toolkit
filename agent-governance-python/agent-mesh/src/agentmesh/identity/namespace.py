# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Agent Namespaces

Scoped trust boundaries for agent groups. Agents within the same namespace
communicate freely; cross-namespace interaction requires explicit rules.
Supports nested namespaces (e.g. "finance.trading" is a child of "finance").
"""

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field

from agentmesh.governance.trust_policy import TrustPolicy


class AgentNamespace(BaseModel):
    """A logical grouping of agents with shared trust boundaries.

    Attributes:
        name: Dot-separated namespace name (e.g. "finance.trading").
        description: Human-readable description of the namespace's purpose.
        parent: Parent namespace name for nesting (e.g. "finance").
        trust_policy: Optional trust policy governing this namespace.
        members: Set of agent DIDs belonging to this namespace.
        created_at: Timestamp when the namespace was created.
    """

    name: str = Field(..., description="Namespace name (e.g. 'finance.trading')")
    description: str = Field(..., description="Human-readable description")
    parent: Optional[str] = Field(
        None, description="Parent namespace name for nesting (e.g. 'finance')"
    )
    trust_policy: Optional[TrustPolicy] = Field(
        None, description="Optional trust policy governing this namespace"
    )
    members: set[str] = Field(default_factory=set, description="Agent DIDs in this namespace")
    created_at: datetime = Field(default_factory=datetime.utcnow)


class NamespaceRule(BaseModel):
    """Rule governing cross-namespace communication or delegation.

    Attributes:
        source_namespace: Originating namespace name.
        target_namespace: Destination namespace name.
        allowed: Whether communication is permitted.
        min_trust_score: Minimum trust score required (0–1000), or None.
        require_approval: Whether human approval is required for this rule.
    """

    source_namespace: str = Field(..., description="Originating namespace")
    target_namespace: str = Field(..., description="Destination namespace")
    allowed: bool = Field(..., description="Whether communication is allowed")
    min_trust_score: Optional[int] = Field(
        None, description="Minimum trust score required (0-1000)"
    )
    require_approval: bool = Field(
        default=False, description="Whether human approval is required"
    )
