# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
CAAS Adapter - Context-as-a-Service Layer Integration

This adapter provides integration with the CAAS (Context-as-a-Service)
layer for context management operations.

In the Listener context, this adapter is used to:
1. Monitor context freshness
2. Detect context drift
3. Resolve ambiguity in context
4. Track context updates

The adapter delegates all context logic to CAAS - no reimplementation.
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime, timedelta

from .base_adapter import BaseLayerAdapter


@dataclass
class ContextSnapshot:
    """A snapshot of context from CAAS."""
    
    context_id: str
    data: Dict[str, Any]
    timestamp: datetime
    source: str
    confidence: float
    ttl_seconds: Optional[float] = None


@dataclass
class ContextDriftAnalysis:
    """Analysis of context drift from CAAS."""
    
    current_context: Dict[str, Any]
    previous_context: Dict[str, Any]
    drift_score: float  # 0.0 = identical, 1.0 = completely different
    changed_fields: List[str]
    drift_direction: str  # "stable", "expanding", "contracting", "shifting"


@dataclass
class AmbiguityAnalysis:
    """Analysis of context ambiguity from CAAS."""
    
    ambiguity_score: float  # 0.0 = clear, 1.0 = highly ambiguous
    ambiguous_fields: List[str]
    suggested_clarifications: List[str]
    confidence_per_field: Dict[str, float]


class MockCAASClient:
    """Mock CAAS client for testing without the actual dependency."""
    
    def __init__(self):
        self._contexts: Dict[str, ContextSnapshot] = {}
        self._history: List[ContextSnapshot] = []
    
    def get_context(self, context_id: str) -> Optional[ContextSnapshot]:
        """Mock context retrieval."""
        return self._contexts.get(context_id)
    
    def store_context(self, snapshot: ContextSnapshot) -> str:
        """Mock context storage."""
        self._contexts[snapshot.context_id] = snapshot
        self._history.append(snapshot)
        return snapshot.context_id
    
    def analyze_drift(
        self,
        current: Dict[str, Any],
        previous: Dict[str, Any]
    ) -> ContextDriftAnalysis:
        """Mock drift analysis."""
        return ContextDriftAnalysis(
            current_context=current,
            previous_context=previous,
            drift_score=0.0,
            changed_fields=[],
            drift_direction="stable",
        )
    
    def analyze_ambiguity(self, context: Dict[str, Any]) -> AmbiguityAnalysis:
        """Mock ambiguity analysis."""
        return AmbiguityAnalysis(
            ambiguity_score=0.0,
            ambiguous_fields=[],
            suggested_clarifications=[],
            confidence_per_field={k: 1.0 for k in context.keys()},
        )
    
    def get_context_age_seconds(self, context_id: str) -> float:
        """Get age of a context in seconds."""
        snapshot = self._contexts.get(context_id)
        if snapshot:
            return (datetime.now() - snapshot.timestamp).total_seconds()
        return float('inf')
    
    def close(self) -> None:
        """Close mock client."""
        pass


class ContextAdapter(BaseLayerAdapter):
    """
    Adapter for CAAS (Context-as-a-Service) layer.
    
    Provides a clean interface for the Listener to access context
    operations without reimplementing any CAAS logic.
    
    Usage:
        ```python
        adapter = ContextAdapter(mock_mode=True)
        adapter.connect()
        
        # Store context
        context_id = adapter.store_context(
            context_id="session_123",
            data={"user_id": "user_1", "focus": "api-gateway"},
            source="user_input"
        )
        
        # Check context freshness
        age = adapter.get_context_age("session_123")
        if age > 300:
            print("Context is stale!")
        
        # Analyze ambiguity
        analysis = adapter.analyze_ambiguity({"target": "the service"})
        ```
    """
    
    def get_layer_name(self) -> str:
        return "caas"
    
    def _create_client(self) -> Any:
        """
        Create the CAAS client.
        
        In production, this would import and instantiate the actual
        caas library client. For now, returns mock.
        """
        try:
            # Attempt to import real CAAS client
            # from caas import Client as CAASClient
            # return CAASClient(self.config)
            
            # Fall back to mock if not available
            return self._mock_client()
        except ImportError:
            return self._mock_client()
    
    def _mock_client(self) -> Any:
        """Create mock client for testing."""
        return MockCAASClient()
    
    def _health_ping(self) -> None:
        """Verify CAAS connection."""
        if self._client:
            # In production: self._client.ping()
            pass
    
    def _get_version(self) -> Optional[str]:
        """Get CAAS version."""
        if self._client and hasattr(self._client, 'version'):
            return self._client.version
        return "mock-1.0.0" if self.mock_mode else None
    
    # === CAAS-specific operations ===
    
    def get_context(self, context_id: str) -> Optional[ContextSnapshot]:
        """
        Retrieve a context by ID.
        
        Delegates to CAAS context retrieval.
        
        Args:
            context_id: Identifier of the context
            
        Returns:
            ContextSnapshot if found, None otherwise
        """
        self.ensure_connected()
        return self._client.get_context(context_id)
    
    def store_context(
        self,
        context_id: str,
        data: Dict[str, Any],
        source: str,
        confidence: float = 1.0,
        ttl_seconds: Optional[float] = None
    ) -> str:
        """
        Store a context snapshot.
        
        Args:
            context_id: Identifier for the context
            data: Context data
            source: Source of the context (e.g., "user_input", "system")
            confidence: Confidence in the context (0.0 to 1.0)
            ttl_seconds: Optional time-to-live
            
        Returns:
            Context ID
        """
        self.ensure_connected()
        
        snapshot = ContextSnapshot(
            context_id=context_id,
            data=data,
            timestamp=datetime.now(),
            source=source,
            confidence=confidence,
            ttl_seconds=ttl_seconds,
        )
        
        return self._client.store_context(snapshot)
    
    def analyze_drift(
        self,
        current_context: Dict[str, Any],
        previous_context: Dict[str, Any]
    ) -> ContextDriftAnalysis:
        """
        Analyze drift between two contexts.
        
        Delegates to CAAS drift analysis.
        
        Args:
            current_context: The current context
            previous_context: The previous context to compare against
            
        Returns:
            ContextDriftAnalysis with drift metrics
        """
        self.ensure_connected()
        return self._client.analyze_drift(current_context, previous_context)
    
    def analyze_ambiguity(self, context: Dict[str, Any]) -> AmbiguityAnalysis:
        """
        Analyze ambiguity in a context.
        
        Delegates to CAAS ambiguity detection.
        
        Args:
            context: Context to analyze
            
        Returns:
            AmbiguityAnalysis with ambiguity metrics
        """
        self.ensure_connected()
        return self._client.analyze_ambiguity(context)
    
    def get_context_age(self, context_id: str) -> float:
        """
        Get the age of a context in seconds.
        
        Args:
            context_id: Context to check
            
        Returns:
            Age in seconds (float('inf') if context not found)
        """
        self.ensure_connected()
        return self._client.get_context_age_seconds(context_id)
    
    def is_context_stale(
        self,
        context_id: str,
        max_age_seconds: float = 300.0
    ) -> bool:
        """
        Check if a context is stale.
        
        Args:
            context_id: Context to check
            max_age_seconds: Maximum acceptable age
            
        Returns:
            True if context is stale or not found
        """
        age = self.get_context_age(context_id)
        return age > max_age_seconds
    
    def get_drift_score(
        self,
        context_id: str,
        new_data: Dict[str, Any]
    ) -> float:
        """
        Get drift score between stored context and new data.
        
        Convenience method combining retrieval and drift analysis.
        
        Args:
            context_id: ID of stored context
            new_data: New context data to compare
            
        Returns:
            Drift score (0.0 to 1.0)
        """
        self.ensure_connected()
        
        stored = self.get_context(context_id)
        if not stored:
            return 1.0  # Maximum drift if no previous context
        
        analysis = self.analyze_drift(new_data, stored.data)
        return analysis.drift_score
    
    def get_ambiguity_score(self, context: Dict[str, Any]) -> float:
        """
        Get ambiguity score for a context.
        
        Convenience method extracting just the score.
        
        Args:
            context: Context to analyze
            
        Returns:
            Ambiguity score (0.0 to 1.0)
        """
        analysis = self.analyze_ambiguity(context)
        return analysis.ambiguity_score
    
    def suggest_clarifications(self, context: Dict[str, Any]) -> List[str]:
        """
        Get suggested clarifications for ambiguous context.
        
        Args:
            context: Context to analyze
            
        Returns:
            List of suggested clarification prompts
        """
        analysis = self.analyze_ambiguity(context)
        return analysis.suggested_clarifications
