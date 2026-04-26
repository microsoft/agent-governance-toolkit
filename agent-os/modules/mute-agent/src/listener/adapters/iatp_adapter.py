# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
IATP Adapter - Security/Trust Layer Integration

This adapter provides integration with the IATP (Inter-Agent Trust
Protocol) layer for security and trust operations.

In the Listener context, this adapter is used to:
1. Validate trust scores for actors
2. Check permission escalation attempts
3. Report security anomalies
4. Trigger emergency security responses

The adapter delegates all security logic to IATP - no reimplementation.
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime

from .base_adapter import BaseLayerAdapter


@dataclass
class TrustAssessment:
    """Result of a trust assessment from IATP."""
    
    actor_id: str
    trust_score: float  # 0.0 to 1.0
    confidence: float  # 0.0 to 1.0
    factors: Dict[str, float]
    timestamp: datetime
    warnings: List[str]


@dataclass
class SecurityEvent:
    """A security event detected or reported via IATP."""
    
    event_id: str
    event_type: str
    severity: str  # "low", "medium", "high", "critical"
    actor_id: Optional[str]
    description: str
    timestamp: datetime
    metadata: Dict[str, Any]


@dataclass
class PermissionCheck:
    """Result of a permission check from IATP."""
    
    allowed: bool
    actor_id: str
    permission: str
    reason: str
    escalation_detected: bool


class MockIATPClient:
    """Mock IATP client for testing without the actual dependency."""
    
    def __init__(self):
        self._trust_scores: Dict[str, float] = {}
        self._events: List[SecurityEvent] = []
    
    def assess_trust(self, actor_id: str) -> TrustAssessment:
        """Mock trust assessment."""
        return TrustAssessment(
            actor_id=actor_id,
            trust_score=self._trust_scores.get(actor_id, 0.8),
            confidence=0.9,
            factors={"history": 0.8, "behavior": 0.9},
            timestamp=datetime.now(),
            warnings=[],
        )
    
    def check_permission(
        self,
        actor_id: str,
        permission: str,
        resource: Optional[str] = None
    ) -> PermissionCheck:
        """Mock permission check."""
        return PermissionCheck(
            allowed=True,
            actor_id=actor_id,
            permission=permission,
            reason="Mock: all permissions allowed",
            escalation_detected=False,
        )
    
    def report_event(self, event: SecurityEvent) -> str:
        """Mock event reporting."""
        self._events.append(event)
        return event.event_id
    
    def emergency_alert(
        self,
        reason: str,
        triggered_rules: List[str]
    ) -> str:
        """Mock emergency alert."""
        return f"emergency_alert_{datetime.now().timestamp()}"
    
    def get_anomaly_score(self, context: Dict[str, Any]) -> float:
        """Mock anomaly detection."""
        return 0.1
    
    def close(self) -> None:
        """Close mock client."""
        pass


class SecurityAdapter(BaseLayerAdapter):
    """
    Adapter for IATP (Security/Trust) layer.
    
    Provides a clean interface for the Listener to access security
    operations without reimplementing any IATP logic.
    
    Usage:
        ```python
        adapter = SecurityAdapter(mock_mode=True)
        adapter.connect()
        
        # Assess trust for an actor
        assessment = adapter.assess_trust("user_123")
        
        # Check for anomalies
        anomaly_score = adapter.get_anomaly_score({"action": "delete"})
        
        # Report a security event
        adapter.report_security_event(
            event_type="permission_escalation_attempt",
            severity="high",
            description="User attempted admin action without permission"
        )
        ```
    """
    
    def get_layer_name(self) -> str:
        return "iatp"
    
    def _create_client(self) -> Any:
        """
        Create the IATP client.
        
        In production, this would import and instantiate the actual
        iatp library client. For now, returns mock.
        """
        try:
            # Attempt to import real IATP client
            # from iatp import Client as IATPClient
            # return IATPClient(self.config)
            
            # Fall back to mock if not available
            return self._mock_client()
        except ImportError:
            return self._mock_client()
    
    def _mock_client(self) -> Any:
        """Create mock client for testing."""
        return MockIATPClient()
    
    def _health_ping(self) -> None:
        """Verify IATP connection."""
        if self._client:
            # In production: self._client.ping()
            pass
    
    def _get_version(self) -> Optional[str]:
        """Get IATP version."""
        if self._client and hasattr(self._client, 'version'):
            return self._client.version
        return "mock-1.0.0" if self.mock_mode else None
    
    # === IATP-specific operations ===
    
    def assess_trust(self, actor_id: str) -> TrustAssessment:
        """
        Assess trust for an actor.
        
        Delegates entirely to IATP trust assessment.
        
        Args:
            actor_id: Identifier of the actor to assess
            
        Returns:
            TrustAssessment with trust score and factors
        """
        self.ensure_connected()
        return self._client.assess_trust(actor_id)
    
    def check_permission(
        self,
        actor_id: str,
        permission: str,
        resource: Optional[str] = None
    ) -> PermissionCheck:
        """
        Check if an actor has a permission.
        
        Delegates to IATP permission verification.
        
        Args:
            actor_id: Actor requesting permission
            permission: Permission being requested
            resource: Optional resource the permission applies to
            
        Returns:
            PermissionCheck with result and escalation detection
        """
        self.ensure_connected()
        return self._client.check_permission(actor_id, permission, resource)
    
    def report_security_event(
        self,
        event_type: str,
        severity: str,
        description: str,
        actor_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Report a security event to IATP.
        
        Args:
            event_type: Type of security event
            severity: Severity level ("low", "medium", "high", "critical")
            description: Human-readable description
            actor_id: Optional actor involved
            metadata: Optional additional metadata
            
        Returns:
            Event ID from IATP
        """
        self.ensure_connected()
        
        event = SecurityEvent(
            event_id=f"event_{datetime.now().timestamp()}",
            event_type=event_type,
            severity=severity,
            actor_id=actor_id,
            description=description,
            timestamp=datetime.now(),
            metadata=metadata or {},
        )
        
        return self._client.report_event(event)
    
    def emergency_alert(
        self,
        reason: str,
        triggered_rules: List[str],
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Trigger an emergency security alert.
        
        This notifies IATP of a critical security situation requiring
        immediate attention.
        
        Args:
            reason: Reason for the emergency
            triggered_rules: List of rules that triggered the emergency
            context: Optional additional context
            
        Returns:
            Alert ID from IATP
        """
        self.ensure_connected()
        return self._client.emergency_alert(reason, triggered_rules)
    
    def get_anomaly_score(self, context: Dict[str, Any]) -> float:
        """
        Get anomaly score for a context.
        
        Delegates to IATP anomaly detection.
        
        Args:
            context: Context to analyze for anomalies
            
        Returns:
            Anomaly score (0.0 = normal, 1.0 = highly anomalous)
        """
        self.ensure_connected()
        return self._client.get_anomaly_score(context)
    
    def get_trust_score(self, actor_id: str) -> float:
        """
        Get the current trust score for an actor.
        
        Convenience method that extracts just the score.
        
        Args:
            actor_id: Actor to get trust score for
            
        Returns:
            Trust score (0.0 to 1.0)
        """
        assessment = self.assess_trust(actor_id)
        return assessment.trust_score
    
    def detect_permission_escalation(
        self,
        actor_id: str,
        requested_permissions: List[str],
        current_permissions: List[str]
    ) -> bool:
        """
        Detect if a permission escalation is being attempted.
        
        Args:
            actor_id: Actor making the request
            requested_permissions: Permissions being requested
            current_permissions: Actor's current permissions
            
        Returns:
            True if escalation detected
        """
        self.ensure_connected()
        
        # Check each requested permission
        for perm in requested_permissions:
            if perm not in current_permissions:
                check = self.check_permission(actor_id, perm)
                if check.escalation_detected:
                    return True
        
        return False
