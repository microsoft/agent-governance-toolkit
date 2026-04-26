# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Multidimensional Knowledge Graph implementation.
"""

from typing import Dict, List, Optional, Any, Set
from .graph_elements import Node, Edge, NodeType, EdgeType
from .subgraph import Subgraph, Dimension


class MultidimensionalKnowledgeGraph:
    """
    A multidimensional knowledge graph that manages multiple dimensional subgraphs.
    This implements the "Forest of Trees" approach where each dimension represents
    a different view or constraint layer on the action space.
    """
    
    def __init__(self):
        self.dimensions: Dict[str, Dimension] = {}
        self.subgraphs: Dict[str, Subgraph] = {}
        self._global_nodes: Dict[str, Node] = {}
        self._global_edges: List[Edge] = []
    
    def add_dimension(self, dimension: Dimension) -> None:
        """Add a new dimension to the knowledge graph."""
        self.dimensions[dimension.name] = dimension
        self.subgraphs[dimension.name] = Subgraph(dimension)
    
    def add_node_to_dimension(self, dimension_name: str, node: Node) -> None:
        """Add a node to a specific dimensional subgraph."""
        if dimension_name in self.subgraphs:
            self.subgraphs[dimension_name].add_node(node)
            self._global_nodes[node.id] = node
    
    def add_edge_to_dimension(self, dimension_name: str, edge: Edge) -> None:
        """Add an edge to a specific dimensional subgraph."""
        if dimension_name in self.subgraphs:
            self.subgraphs[dimension_name].add_edge(edge)
            self._global_edges.append(edge)
    
    def get_dimension(self, dimension_name: str) -> Optional[Dimension]:
        """Get a dimension by name."""
        return self.dimensions.get(dimension_name)
    
    def get_subgraph(self, dimension_name: str) -> Optional[Subgraph]:
        """Get a subgraph for a specific dimension."""
        return self.subgraphs.get(dimension_name)
    
    def get_all_dimensions(self) -> List[Dimension]:
        """Get all dimensions, sorted by priority."""
        return sorted(self.dimensions.values(), key=lambda d: d.priority, reverse=True)
    
    def find_relevant_dimensions(self, context: Dict[str, Any]) -> List[str]:
        """
        Find dimensions that are relevant to the given context.
        Returns dimension names sorted by priority.
        """
        relevant_dimensions = []
        
        for dim_name, dimension in self.dimensions.items():
            # Check if context matches dimension metadata
            if self._dimension_matches_context(dimension, context):
                relevant_dimensions.append(dim_name)
        
        # Sort by priority
        relevant_dimensions.sort(
            key=lambda d: self.dimensions[d].priority,
            reverse=True
        )
        
        return relevant_dimensions
    
    def _dimension_matches_context(self, dimension: Dimension, context: Dict[str, Any]) -> bool:
        """Check if a dimension is relevant to the given context."""
        if not context:
            return True
        
        # Check if any context keys match dimension metadata
        for key in context.keys():
            if key in dimension.metadata:
                return True
        
        # If no specific metadata match, dimension is potentially relevant
        return True
    
    def get_pruned_action_space(
        self,
        dimension_name: str,
        context: Dict[str, Any]
    ) -> List[Node]:
        """
        Get the pruned action space for a specific dimension and context.
        This is the core of the action space pruning mechanism.
        """
        subgraph = self.subgraphs.get(dimension_name)
        if not subgraph:
            return []
        
        # Prune the subgraph based on context
        pruned_subgraph = subgraph.prune_by_context(context)
        
        # Return available actions
        return pruned_subgraph.get_action_space()
    
    def validate_action_across_dimensions(
        self,
        action_id: str,
        dimension_names: List[str],
        context: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Validate an action across multiple dimensions.
        The action must be valid in all specified dimensions.
        """
        for dim_name in dimension_names:
            subgraph = self.subgraphs.get(dim_name)
            if not subgraph:
                continue
            
            if not subgraph.validate_action(action_id, context):
                return False
        
        return True
    
    def find_all_missing_dependencies(
        self,
        action_id: str,
        dimension_names: List[str],
        context: Dict[str, Any]
    ) -> Dict[str, List[str]]:
        """
        Find all missing dependencies for an action across all dimensions.
        Returns a dictionary mapping dimension names to lists of missing dependencies.
        """
        all_missing = {}
        
        for dim_name in dimension_names:
            subgraph = self.subgraphs.get(dim_name)
            if not subgraph:
                continue
            
            missing = subgraph.find_missing_dependencies(action_id, context)
            if missing:
                all_missing[dim_name] = missing
        
        return all_missing
    
    def get_action_constraints(
        self,
        action_id: str,
        dimension_name: str
    ) -> List[Node]:
        """Get all constraints associated with an action in a dimension."""
        subgraph = self.subgraphs.get(dimension_name)
        if not subgraph:
            return []
        
        action_node = subgraph.get_node(action_id)
        if not action_node:
            return []
        
        constraints = []
        for edge in subgraph._adjacency_list.get(action_id, []):
            if edge.edge_type == EdgeType.REQUIRES:
                target_node = subgraph.get_node(edge.target_id)
                if target_node and target_node.node_type == NodeType.CONSTRAINT:
                    constraints.append(target_node)
        
        return constraints
