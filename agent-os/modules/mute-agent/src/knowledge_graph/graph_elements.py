# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Knowledge Graph Node and Edge definitions.
"""

from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum


class NodeType(Enum):
    """Types of nodes in the knowledge graph."""
    ACTION = "action"
    CONSTRAINT = "constraint"
    PRECONDITION = "precondition"
    POSTCONDITION = "postcondition"
    CONTEXT = "context"
    RESOURCE = "resource"


class EdgeType(Enum):
    """Types of edges in the knowledge graph."""
    REQUIRES = "requires"
    ENABLES = "enables"
    CONFLICTS_WITH = "conflicts_with"
    DEPENDS_ON = "depends_on"
    PRODUCES = "produces"
    CONSUMES = "consumes"


@dataclass
class Node:
    """A node in the knowledge graph."""
    id: str
    node_type: NodeType
    attributes: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def matches_constraint(self, constraint: Dict[str, Any]) -> bool:
        """Check if node matches given constraints."""
        for key, value in constraint.items():
            if key in self.attributes:
                if self.attributes[key] != value:
                    return False
            elif key in self.metadata:
                if self.metadata[key] != value:
                    return False
            else:
                return False
        return True


@dataclass
class Edge:
    """An edge in the knowledge graph."""
    source_id: str
    target_id: str
    edge_type: EdgeType
    weight: float = 1.0
    attributes: Dict[str, Any] = field(default_factory=dict)
    
    def is_valid(self) -> bool:
        """Check if edge is valid."""
        return self.weight > 0 and self.source_id and self.target_id
