# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
SCAK Adapter - Intelligence/Knowledge Layer Integration

This adapter provides integration with the SCAK (Structured Contextual
Agent Knowledge) layer for knowledge graph operations.

In the Listener context, this adapter is used to:
1. Query graph state for observation
2. Delegate constraint validation
3. Access dimensional routing logic

The adapter delegates all intelligence to SCAK - no logic is reimplemented.
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass

from .base_adapter import BaseLayerAdapter


@dataclass
class GraphQueryResult:
    """Result from a SCAK graph query."""
    
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]
    dimensions: List[str]
    metadata: Dict[str, Any]


@dataclass
class ValidationResult:
    """Result from SCAK constraint validation."""
    
    valid: bool
    constraints_checked: int
    constraints_passed: int
    violations: List[str]
    suggestions: List[str]


class MockSCAKClient:
    """Mock SCAK client for testing without the actual dependency."""
    
    def __init__(self):
        self._graphs: Dict[str, Dict] = {}
    
    def query(self, graph_id: str, query: Dict[str, Any]) -> GraphQueryResult:
        """Mock graph query."""
        return GraphQueryResult(
            nodes=[],
            edges=[],
            dimensions=["default"],
            metadata={"mock": True},
        )
    
    def validate(
        self,
        graph_id: str,
        action_id: str,
        context: Dict[str, Any]
    ) -> ValidationResult:
        """Mock validation."""
        return ValidationResult(
            valid=True,
            constraints_checked=0,
            constraints_passed=0,
            violations=[],
            suggestions=[],
        )
    
    def get_action_space(
        self,
        graph_id: str,
        dimensions: List[str]
    ) -> List[str]:
        """Mock action space retrieval."""
        return []
    
    def close(self) -> None:
        """Close mock client."""
        pass


class IntelligenceAdapter(BaseLayerAdapter):
    """
    Adapter for SCAK (Intelligence/Knowledge) layer.
    
    Provides a clean interface for the Listener to access knowledge
    graph operations without reimplementing any SCAK logic.
    
    Usage:
        ```python
        adapter = IntelligenceAdapter(mock_mode=True)
        adapter.connect()
        
        # Query graph state
        result = adapter.query_graph("my_graph", {"action": "restart"})
        
        # Validate an action
        validation = adapter.validate_action(
            "my_graph",
            "restart_service",
            {"service_id": "api-gateway"}
        )
        ```
    """
    
    def get_layer_name(self) -> str:
        return "scak"
    
    def _create_client(self) -> Any:
        """
        Create the SCAK client.
        
        In production, this would import and instantiate the actual
        scak library client. For now, returns mock.
        """
        try:
            # Attempt to import real SCAK client
            # from scak import Client as SCAKClient
            # return SCAKClient(self.config)
            
            # Fall back to mock if not available
            return self._mock_client()
        except ImportError:
            return self._mock_client()
    
    def _mock_client(self) -> Any:
        """Create mock client for testing."""
        return MockSCAKClient()
    
    def _health_ping(self) -> None:
        """Verify SCAK connection."""
        if self._client:
            # In production: self._client.ping()
            pass
    
    def _get_version(self) -> Optional[str]:
        """Get SCAK version."""
        if self._client and hasattr(self._client, 'version'):
            return self._client.version
        return "mock-1.0.0" if self.mock_mode else None
    
    # === SCAK-specific operations ===
    
    def query_graph(
        self,
        graph_id: str,
        query: Dict[str, Any]
    ) -> GraphQueryResult:
        """
        Query a knowledge graph.
        
        Delegates entirely to SCAK - no query logic here.
        
        Args:
            graph_id: Identifier of the graph to query
            query: Query parameters (SCAK-specific format)
            
        Returns:
            GraphQueryResult with matching nodes and edges
        """
        self.ensure_connected()
        return self._client.query(graph_id, query)
    
    def validate_action(
        self,
        graph_id: str,
        action_id: str,
        context: Dict[str, Any]
    ) -> ValidationResult:
        """
        Validate an action against graph constraints.
        
        Delegates entirely to SCAK constraint validation.
        
        Args:
            graph_id: Graph to validate against
            action_id: Action to validate
            context: Context for validation
            
        Returns:
            ValidationResult with validation outcome
        """
        self.ensure_connected()
        return self._client.validate(graph_id, action_id, context)
    
    def get_pruned_action_space(
        self,
        graph_id: str,
        dimensions: List[str],
        context: Optional[Dict[str, Any]] = None
    ) -> List[str]:
        """
        Get the pruned action space for given dimensions.
        
        Delegates to SCAK's action space pruning logic.
        
        Args:
            graph_id: Graph to query
            dimensions: Active dimensions
            context: Optional context for further pruning
            
        Returns:
            List of valid action IDs
        """
        self.ensure_connected()
        return self._client.get_action_space(graph_id, dimensions)
    
    def get_dimension_metadata(
        self,
        graph_id: str,
        dimension_name: str
    ) -> Dict[str, Any]:
        """
        Get metadata for a dimension.
        
        Args:
            graph_id: Graph containing the dimension
            dimension_name: Name of the dimension
            
        Returns:
            Dimension metadata dictionary
        """
        self.ensure_connected()
        if hasattr(self._client, 'get_dimension_metadata'):
            return self._client.get_dimension_metadata(graph_id, dimension_name)
        return {}
    
    def find_constraints(
        self,
        graph_id: str,
        action_id: str
    ) -> List[Dict[str, Any]]:
        """
        Find all constraints for an action.
        
        Args:
            graph_id: Graph to search
            action_id: Action to find constraints for
            
        Returns:
            List of constraint definitions
        """
        self.ensure_connected()
        if hasattr(self._client, 'find_constraints'):
            return self._client.find_constraints(graph_id, action_id)
        return []
