# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Dimensional subgraph implementation.
"""

from typing import Dict, List, Set, Optional, Any
from dataclasses import dataclass, field
from .graph_elements import Node, Edge, NodeType, EdgeType


# Wildcard constant for matching any value in context
WILDCARD_VALUE = "*"


@dataclass
class Dimension:
    """A dimension in the multidimensional knowledge graph."""
    name: str
    description: str
    priority: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class Subgraph:
    """A subgraph representing a specific dimensional view of the knowledge graph."""
    
    def __init__(self, dimension: Dimension):
        self.dimension = dimension
        self.nodes: Dict[str, Node] = {}
        self.edges: List[Edge] = []
        self._adjacency_list: Dict[str, List[Edge]] = {}
    
    def add_node(self, node: Node) -> None:
        """Add a node to the subgraph."""
        self.nodes[node.id] = node
        if node.id not in self._adjacency_list:
            self._adjacency_list[node.id] = []
    
    def add_edge(self, edge: Edge) -> None:
        """Add an edge to the subgraph."""
        if edge.is_valid():
            self.edges.append(edge)
            if edge.source_id not in self._adjacency_list:
                self._adjacency_list[edge.source_id] = []
            self._adjacency_list[edge.source_id].append(edge)
    
    def get_node(self, node_id: str) -> Optional[Node]:
        """Get a node by ID."""
        return self.nodes.get(node_id)
    
    def get_neighbors(self, node_id: str) -> List[Node]:
        """Get neighboring nodes."""
        neighbors = []
        for edge in self._adjacency_list.get(node_id, []):
            if edge.target_id in self.nodes:
                neighbors.append(self.nodes[edge.target_id])
        return neighbors
    
    def find_nodes_by_type(self, node_type: NodeType) -> List[Node]:
        """Find all nodes of a specific type."""
        return [node for node in self.nodes.values() if node.node_type == node_type]
    
    def find_nodes_by_constraint(self, constraint: Dict[str, Any]) -> List[Node]:
        """Find nodes matching specific constraints."""
        return [node for node in self.nodes.values() if node.matches_constraint(constraint)]
    
    def get_action_space(self) -> List[Node]:
        """Get all available actions in this subgraph."""
        return self.find_nodes_by_type(NodeType.ACTION)
    
    def validate_action(self, action_id: str, context: Optional[Dict[str, Any]] = None) -> bool:
        """Validate if an action can be executed based on graph constraints."""
        if action_id not in self.nodes:
            return False
        
        action_node = self.nodes[action_id]
        if action_node.node_type != NodeType.ACTION:
            return False
        
        # Check preconditions
        for edge in self._adjacency_list.get(action_id, []):
            if edge.edge_type == EdgeType.REQUIRES:
                target_node = self.nodes.get(edge.target_id)
                if not target_node:
                    return False
                # If context provided, check if requirement is satisfied
                if context:
                    if not self._is_requirement_satisfied(target_node, context):
                        return False
        
        return True
    
    def _is_requirement_satisfied(self, requirement_node: Node, context: Dict[str, Any]) -> bool:
        """Check if a requirement node is satisfied by the context."""
        # Check if the requirement exists in context
        req_id = requirement_node.id
        
        # Check if context explicitly marks this requirement as satisfied
        if f"{req_id}_satisfied" in context:
            return context[f"{req_id}_satisfied"]
        
        # Check if requirement attributes are present in context
        for key, expected_value in requirement_node.attributes.items():
            if key in context:
                if context[key] == expected_value:
                    return True
        
        return False
    
    def find_missing_dependencies(self, action_id: str, context: Dict[str, Any]) -> List[str]:
        """
        Find all missing dependencies for an action (deep traversal).
        Returns a list of missing dependency IDs in order from root to leaf.
        Handles circular dependencies gracefully.
        """
        if action_id not in self.nodes:
            return [f"Action '{action_id}' not found"]
        
        visited = set()
        in_progress = set()  # Track nodes currently being processed for cycle detection
        missing_deps = []
        
        def traverse_dependencies(node_id: str, path: List[str]) -> None:
            """Recursively traverse dependencies to find missing ones."""
            if node_id in visited:
                return
            
            # Cycle detection: if we're currently processing this node, we have a cycle
            if node_id in in_progress:
                return  # Skip circular dependency
            
            in_progress.add(node_id)
            
            # Get all requirements for this node
            for edge in self._adjacency_list.get(node_id, []):
                if edge.edge_type == EdgeType.REQUIRES:
                    target_node = self.nodes.get(edge.target_id)
                    if target_node:
                        # Check if this requirement is satisfied
                        if not self._is_requirement_satisfied(target_node, context):
                            # This dependency is missing, check its dependencies first
                            traverse_dependencies(edge.target_id, path + [node_id])
                            # Add to missing list if not already there
                            if edge.target_id not in missing_deps:
                                missing_deps.append(edge.target_id)
            
            in_progress.remove(node_id)
            visited.add(node_id)
        
        traverse_dependencies(action_id, [])
        return missing_deps
    
    def get_dependency_chain(self, action_id: str) -> List[List[str]]:
        """
        Get all dependency chains for an action.
        Returns a list of chains, where each chain is a list of node IDs.
        Handles circular dependencies by detecting and skipping cycles.
        """
        if action_id not in self.nodes:
            return []
        
        chains = []
        visited_in_chain = set()  # Track nodes in current chain for cycle detection
        
        def traverse_chain(node_id: str, current_chain: List[str]) -> None:
            """Recursively build dependency chains with cycle detection."""
            # Cycle detection: if node is already in current chain, we have a cycle
            if node_id in visited_in_chain:
                return
            
            visited_in_chain.add(node_id)
            
            # Get all requirements for this node
            requirements = []
            for edge in self._adjacency_list.get(node_id, []):
                if edge.edge_type == EdgeType.REQUIRES:
                    requirements.append(edge.target_id)
            
            if not requirements:
                # End of chain
                chains.append(current_chain[:])
            else:
                # Continue traversing
                for req_id in requirements:
                    if req_id in self.nodes:
                        traverse_chain(req_id, current_chain + [req_id])
            
            visited_in_chain.remove(node_id)
        
        traverse_chain(action_id, [action_id])
        return chains
    
    def prune_by_context(self, context: Dict[str, Any]) -> "Subgraph":
        """Create a pruned version of this subgraph based on context."""
        pruned = Subgraph(self.dimension)
        
        # Add nodes that match the context
        for node in self.nodes.values():
            if self._node_matches_context(node, context):
                pruned.add_node(node)
        
        # Add edges between matching nodes
        for edge in self.edges:
            if edge.source_id in pruned.nodes and edge.target_id in pruned.nodes:
                pruned.add_edge(edge)
        
        return pruned
    
    def _node_matches_context(self, node: Node, context: Dict[str, Any]) -> bool:
        """Check if a node is relevant to the given context."""
        if not context:
            return True
        
        # Check if any context attributes match node attributes
        for key, value in context.items():
            if key in node.attributes:
                if node.attributes[key] == value or value == WILDCARD_VALUE:
                    return True
            if key in node.metadata:
                if node.metadata[key] == value or value == WILDCARD_VALUE:
                    return True
        
        return False
