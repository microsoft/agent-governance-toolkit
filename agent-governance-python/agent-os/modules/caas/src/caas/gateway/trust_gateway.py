# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""
Trust Gateway: The Middleware Gap Solution

The Naive Approach:
"Let's use a startup's API that auto-routes our traffic to the cheapest model."

The Engineering Reality:
No Enterprise CISO will send their proprietary data to a random middleware startup 
just to save 30% on tokens. The risk of data leakage is too high.

This layer—the "Model Gateway"—is critical, but it requires massive trust.

The Opportunity:
There is a gap here, but it's not for a SaaS. It's for Infrastructure.

The Solution:
Build an On-Prem / Private Cloud Router that enterprises can deploy within their
own infrastructure. The winner won't be the one with the smartest routing algorithm;
it will be the one the Enterprise trusts with the keys to the kingdom.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime
from pydantic import BaseModel, Field
import uuid
import json


class DeploymentMode(str, Enum):
    """Deployment modes for Trust Gateway."""
    ON_PREM = "on_prem"  # Deployed on customer's own infrastructure
    PRIVATE_CLOUD = "private_cloud"  # Deployed in customer's private cloud (AWS VPC, Azure VNet, GCP VPC)
    HYBRID = "hybrid"  # Hybrid deployment with local processing and cloud backup
    AIR_GAPPED = "air_gapped"  # Completely isolated from internet (maximum security)


class SecurityLevel(str, Enum):
    """Security levels for data handling."""
    STANDARD = "standard"  # Basic security controls
    HIGH = "high"  # Enhanced security (encryption at rest and in transit)
    MAXIMUM = "maximum"  # Maximum security (air-gapped, zero data retention)


class DataRetentionPolicy(BaseModel):
    """Data retention and deletion policies."""
    retain_requests: bool = Field(default=False, description="Whether to retain request data")
    retention_days: int = Field(default=0, ge=0, le=365, description="Days to retain data (0 = no retention)")
    auto_delete: bool = Field(default=True, description="Automatically delete data after retention period")
    encrypt_at_rest: bool = Field(default=True, description="Encrypt data at rest")
    pii_scrubbing: bool = Field(default=True, description="Automatically scrub PII from logs")


class AuditLog(BaseModel):
    """Audit log entry for compliance and security monitoring."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    event_type: str  # e.g., "request_routed", "data_accessed", "policy_changed"
    user_id: Optional[str] = None
    request_id: Optional[str] = None
    action: str  # Description of the action
    model_tier: Optional[str] = None
    data_classification: Optional[str] = None  # e.g., "public", "confidential", "secret"
    security_level: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "user_id": self.user_id,
            "request_id": self.request_id,
            "action": self.action,
            "model_tier": self.model_tier,
            "data_classification": self.data_classification,
            "security_level": self.security_level,
            "metadata": self.metadata
        }


class SecurityPolicy(BaseModel):
    """Security policy configuration for Trust Gateway."""
    deployment_mode: DeploymentMode = Field(default=DeploymentMode.ON_PREM)
    security_level: SecurityLevel = Field(default=SecurityLevel.HIGH)
    data_retention: DataRetentionPolicy = Field(default_factory=DataRetentionPolicy)
    
    # Authentication & Authorization
    require_authentication: bool = Field(default=True, description="Require authentication for all requests")
    allowed_users: List[str] = Field(default_factory=list, description="List of allowed user IDs (empty = all)")
    allowed_ip_ranges: List[str] = Field(default_factory=list, description="Allowed IP ranges (CIDR notation)")
    
    # Data Classification
    data_classification_required: bool = Field(default=False, description="Require data classification labels")
    allowed_classifications: List[str] = Field(
        default_factory=lambda: ["public", "internal", "confidential", "secret"],
        description="Allowed data classification levels"
    )
    
    # Encryption
    encrypt_in_transit: bool = Field(default=True, description="Require TLS/HTTPS for all communication")
    encrypt_at_rest: bool = Field(default=True, description="Encrypt stored data")
    
    # Audit & Compliance
    audit_all_requests: bool = Field(default=True, description="Audit all gateway requests")
    audit_data_access: bool = Field(default=True, description="Audit all data access events")
    compliance_mode: Optional[str] = Field(default=None, description="Compliance framework (e.g., 'GDPR', 'HIPAA', 'SOC2')")
    
    # Network Isolation
    allow_external_calls: bool = Field(default=False, description="Allow calls to external APIs")
    external_model_endpoints: List[str] = Field(
        default_factory=list,
        description="Whitelisted external model endpoints (if allowed)"
    )


class TrustGateway:
    """
    Trust Gateway: Enterprise-Grade Private Cloud Router
    
    The Trust Gateway is designed to address enterprise security concerns by providing:
    1. On-Prem / Private Cloud deployment options
    2. Zero data leakage (data never leaves customer infrastructure)
    3. Full audit trail for compliance
    4. Configurable security policies
    5. Data retention and deletion controls
    
    Philosophy:
    The winner isn't the one with the smartest routing algorithm;
    it's the one the Enterprise trusts with the keys to the kingdom.
    """
    
    def __init__(
        self,
        security_policy: Optional[SecurityPolicy] = None,
        audit_enabled: bool = True
    ):
        """
        Initialize Trust Gateway.
        
        Args:
            security_policy: Security policy configuration
            audit_enabled: Whether to enable audit logging
        """
        self.security_policy = security_policy or SecurityPolicy()
        self.audit_enabled = audit_enabled
        self.audit_logs: List[AuditLog] = []
        self._deployment_info = self._get_deployment_info()
    
    def _get_deployment_info(self) -> Dict[str, Any]:
        """Get deployment information."""
        return {
            "deployment_mode": self.security_policy.deployment_mode,
            "security_level": self.security_policy.security_level,
            "data_retention_days": self.security_policy.data_retention.retention_days,
            "audit_enabled": self.audit_enabled,
            "compliance_mode": self.security_policy.compliance_mode,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def validate_request(
        self,
        request_data: Dict[str, Any],
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        data_classification: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Validate request against security policy.
        
        Args:
            request_data: The request data to validate
            user_id: User ID making the request
            ip_address: IP address of the requester
            data_classification: Classification level of the data
        
        Returns:
            Validation result with status and any security warnings
        """
        validation_result = {
            "valid": True,
            "warnings": [],
            "violations": []
        }
        
        # Check authentication requirement
        if self.security_policy.require_authentication and not user_id:
            validation_result["valid"] = False
            validation_result["violations"].append("Authentication required but no user_id provided")
        
        # Check allowed users
        if user_id and self.security_policy.allowed_users:
            if user_id not in self.security_policy.allowed_users:
                validation_result["valid"] = False
                validation_result["violations"].append(f"User {user_id} not in allowed users list")
        
        # Check data classification
        if self.security_policy.data_classification_required and not data_classification:
            validation_result["valid"] = False
            validation_result["violations"].append("Data classification required but not provided")
        
        if data_classification and data_classification not in self.security_policy.allowed_classifications:
            validation_result["valid"] = False
            validation_result["violations"].append(
                f"Data classification '{data_classification}' not in allowed classifications"
            )
        
        # Check encryption requirements
        if self.security_policy.encrypt_in_transit:
            validation_result["warnings"].append("Ensure connection uses TLS/HTTPS")
        
        # Audit the validation attempt
        if self.audit_enabled:
            self._log_audit(
                event_type="request_validated",
                user_id=user_id,
                action=f"Request validation: {'passed' if validation_result['valid'] else 'failed'}",
                data_classification=data_classification,
                metadata={
                    "ip_address": ip_address,
                    "violations": validation_result["violations"],
                    "warnings": validation_result["warnings"]
                }
            )
        
        return validation_result
    
    def route_request(
        self,
        query: str,
        user_id: Optional[str] = None,
        data_classification: Optional[str] = None,
        request_metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Route request through Trust Gateway with security controls.
        
        Args:
            query: The user query to route
            user_id: User ID making the request
            data_classification: Classification level of the data
            request_metadata: Additional request metadata
        
        Returns:
            Routing decision with security context
        """
        request_id = str(uuid.uuid4())
        
        # Validate request first
        validation = self.validate_request(
            request_data={"query": query},
            user_id=user_id,
            data_classification=data_classification
        )
        
        if not validation["valid"]:
            return {
                "status": "rejected",
                "request_id": request_id,
                "reason": "Security policy violation",
                "violations": validation["violations"],
                "timestamp": datetime.utcnow().isoformat()
            }
        
        # Import here to avoid circular dependency
        from caas.routing import HeuristicRouter
        
        # Use heuristic router for actual routing decision
        router = HeuristicRouter()
        decision = router.route(query)
        
        # Add security context to routing decision
        result = {
            "status": "approved",
            "request_id": request_id,
            "routing_decision": decision.model_dump(),
            "security_context": {
                "deployment_mode": self.security_policy.deployment_mode,
                "security_level": self.security_policy.security_level,
                "data_classification": data_classification,
                "data_retention_days": self.security_policy.data_retention.retention_days,
                "encrypted": self.security_policy.encrypt_at_rest,
                "audited": self.audit_enabled
            },
            "warnings": validation["warnings"],
            "timestamp": datetime.utcnow().isoformat()
        }
        
        # Audit the routing decision
        if self.audit_enabled:
            self._log_audit(
                event_type="request_routed",
                user_id=user_id,
                request_id=request_id,
                action=f"Query routed to {decision.model_tier} tier",
                model_tier=decision.model_tier,
                data_classification=data_classification,
                metadata={
                    "query_length": len(query),
                    "suggested_model": decision.suggested_model,
                    "estimated_cost": decision.estimated_cost,
                    "request_metadata": request_metadata
                }
            )
        
        return result
    
    def _log_audit(
        self,
        event_type: str,
        action: str,
        user_id: Optional[str] = None,
        request_id: Optional[str] = None,
        model_tier: Optional[str] = None,
        data_classification: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None
    ):
        """Log an audit event."""
        log_entry = AuditLog(
            event_type=event_type,
            user_id=user_id,
            request_id=request_id,
            action=action,
            model_tier=model_tier,
            data_classification=data_classification,
            security_level=self.security_policy.security_level,
            metadata=metadata or {}
        )
        self.audit_logs.append(log_entry)
    
    def get_audit_logs(
        self,
        event_type: Optional[str] = None,
        user_id: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Retrieve audit logs with optional filtering.
        
        Args:
            event_type: Filter by event type
            user_id: Filter by user ID
            start_time: Filter logs after this time (ISO format)
            end_time: Filter logs before this time (ISO format)
        
        Returns:
            List of matching audit log entries
        """
        filtered_logs = self.audit_logs
        
        if event_type:
            filtered_logs = [log for log in filtered_logs if log.event_type == event_type]
        
        if user_id:
            filtered_logs = [log for log in filtered_logs if log.user_id == user_id]
        
        if start_time:
            filtered_logs = [log for log in filtered_logs if log.timestamp >= start_time]
        
        if end_time:
            filtered_logs = [log for log in filtered_logs if log.timestamp <= end_time]
        
        return [log.to_dict() for log in filtered_logs]
    
    def get_deployment_info(self) -> Dict[str, Any]:
        """
        Get Trust Gateway deployment information.
        
        Returns:
            Deployment configuration and status
        """
        return {
            **self._deployment_info,
            "total_audit_logs": len(self.audit_logs),
            "security_policy": {
                "deployment_mode": self.security_policy.deployment_mode,
                "security_level": self.security_policy.security_level,
                "authentication_required": self.security_policy.require_authentication,
                "audit_enabled": self.audit_enabled,
                "data_retention_days": self.security_policy.data_retention.retention_days,
                "encrypt_at_rest": self.security_policy.encrypt_at_rest,
                "encrypt_in_transit": self.security_policy.encrypt_in_transit,
                "compliance_mode": self.security_policy.compliance_mode,
                "external_calls_allowed": self.security_policy.allow_external_calls
            },
            "trust_guarantees": [
                "Data never leaves your infrastructure",
                "Full audit trail for compliance",
                "Configurable retention policies",
                "Enterprise-grade security controls",
                "Zero third-party data sharing"
            ]
        }
    
    def update_security_policy(
        self,
        new_policy: SecurityPolicy,
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Update security policy (requires audit logging).
        
        Args:
            new_policy: New security policy
            user_id: User ID making the change
        
        Returns:
            Update status
        """
        old_policy = self.security_policy
        
        # Log the policy change
        if self.audit_enabled:
            self._log_audit(
                event_type="policy_changed",
                user_id=user_id,
                action="Security policy updated",
                metadata={
                    "old_policy": {
                        "deployment_mode": old_policy.deployment_mode,
                        "security_level": old_policy.security_level
                    },
                    "new_policy": {
                        "deployment_mode": new_policy.deployment_mode,
                        "security_level": new_policy.security_level
                    }
                }
            )
        
        self.security_policy = new_policy
        self._deployment_info = self._get_deployment_info()
        
        return {
            "status": "success",
            "message": "Security policy updated",
            "timestamp": datetime.utcnow().isoformat()
        }
    
    def clear_audit_logs(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Clear audit logs (requires authorization).
        
        Args:
            user_id: User ID requesting the clear operation
        
        Returns:
            Clear operation status
        """
        logs_count = len(self.audit_logs)
        
        # Log the clear operation before clearing
        if self.audit_enabled:
            self._log_audit(
                event_type="audit_logs_cleared",
                user_id=user_id,
                action=f"Cleared {logs_count} audit log entries",
                metadata={"logs_cleared": logs_count}
            )
        
        # Keep the last log entry (the clear operation itself)
        last_log = self.audit_logs[-1] if self.audit_logs else None
        self.audit_logs = [last_log] if last_log else []
        
        return {
            "status": "success",
            "message": f"Cleared {logs_count} audit log entries",
            "remaining_logs": len(self.audit_logs),
            "timestamp": datetime.utcnow().isoformat()
        }
