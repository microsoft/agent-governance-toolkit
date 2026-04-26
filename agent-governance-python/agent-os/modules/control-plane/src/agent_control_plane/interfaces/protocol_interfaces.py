# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Protocol Interfaces - Integration Points for iatp, cmvk, and caas

This module defines the interfaces for integrating with the allowed
Layer 2 protocols:
- iatp: Inter-Agent Transport Protocol (message security)
- cmvk: Cryptographic Message Verification Kit (verification)
- caas: Context-as-a-Service (context routing)

Layer 3: The Framework
- These interfaces allow optional integration with Layer 2 protocols
- Implementations are injected at runtime, not hard-coded
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


# ============================================================================
# Message Security Interface (for iatp integration)
# ============================================================================

class SecurityLevel(Enum):
    """Security levels for message passing"""
    NONE = "none"
    SIGNED = "signed"
    ENCRYPTED = "encrypted"
    SIGNED_ENCRYPTED = "signed_encrypted"


@dataclass
class SecureMessage:
    """A secured message with optional encryption and signature"""
    message_id: str
    payload: Any
    sender_id: str
    recipient_id: str
    timestamp: datetime
    security_level: SecurityLevel = SecurityLevel.NONE
    signature: Optional[bytes] = None
    encrypted_payload: Optional[bytes] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityValidationResult:
    """Result of security validation"""
    is_valid: bool
    security_level: SecurityLevel
    sender_verified: bool = False
    integrity_verified: bool = False
    decrypted_payload: Optional[Any] = None
    errors: List[str] = field(default_factory=list)


class MessageSecurityInterface(ABC):
    """
    Abstract interface for message security (iatp integration).
    
    This interface defines how to secure inter-agent messages.
    Implementations can use iatp or any other security protocol.
    
    Example Usage:
        ```python
        from agent_control_plane.interfaces import MessageSecurityInterface
        
        class IATPMessageSecurity(MessageSecurityInterface):
            def secure_message(self, message, security_level):
                # Use iatp to secure the message
                ...
        
        control_plane.register_message_security(IATPMessageSecurity())
        ```
    """
    
    @abstractmethod
    def secure_message(
        self, 
        message: Any,
        sender_id: str,
        recipient_id: str,
        security_level: SecurityLevel = SecurityLevel.SIGNED_ENCRYPTED
    ) -> SecureMessage:
        """
        Secure a message for transmission.
        
        Args:
            message: The message payload to secure
            sender_id: ID of the sending agent
            recipient_id: ID of the receiving agent
            security_level: Desired security level
            
        Returns:
            SecureMessage with appropriate security applied
        """
        pass
    
    @abstractmethod
    def validate_message(self, secure_message: SecureMessage) -> SecurityValidationResult:
        """
        Validate a received secure message.
        
        Args:
            secure_message: The message to validate
            
        Returns:
            SecurityValidationResult with validation details
        """
        pass
    
    @abstractmethod
    def register_agent_keys(
        self, 
        agent_id: str, 
        public_key: bytes,
        key_type: str = "ed25519"
    ) -> bool:
        """
        Register an agent's public key for verification.
        
        Args:
            agent_id: ID of the agent
            public_key: Agent's public key
            key_type: Type of key (default: ed25519)
            
        Returns:
            True if registration was successful
        """
        pass
    
    def get_supported_security_levels(self) -> List[SecurityLevel]:
        """Get supported security levels"""
        return list(SecurityLevel)


# ============================================================================
# Verification Interface (for cmvk integration)
# ============================================================================

class VerificationType(Enum):
    """Types of verification"""
    SIGNATURE = "signature"
    HASH = "hash"
    HASH_CHAIN_PROOF = "hash_chain_proof"
    ZERO_KNOWLEDGE = "zero_knowledge"


@dataclass
class VerificationRequest:
    """Request for verification"""
    request_id: str
    data: Any
    verification_type: VerificationType
    expected_proof: Optional[bytes] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class VerificationResult:
    """Result of verification"""
    is_verified: bool
    verification_type: VerificationType
    proof: Optional[bytes] = None
    timestamp: datetime = field(default_factory=datetime.now)
    details: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


class VerificationInterface(ABC):
    """
    Abstract interface for cryptographic verification (cmvk integration).
    
    This interface defines how to verify data integrity and authenticity.
    Implementations can use cmvk or any other verification system.
    
    Example Usage:
        ```python
        from agent_control_plane.interfaces import VerificationInterface
        
        class CMVKVerifier(VerificationInterface):
            def verify(self, request):
                # Use cmvk for verification
                ...
        
        control_plane.register_verifier(CMVKVerifier())
        ```
    """
    
    @abstractmethod
    def create_proof(
        self, 
        data: Any,
        verification_type: VerificationType = VerificationType.SIGNATURE
    ) -> bytes:
        """
        Create a verification proof for data.
        
        Args:
            data: The data to create proof for
            verification_type: Type of verification to use
            
        Returns:
            Proof bytes
        """
        pass
    
    @abstractmethod
    def verify(self, request: VerificationRequest) -> VerificationResult:
        """
        Verify data against a proof.
        
        Args:
            request: The verification request
            
        Returns:
            VerificationResult with verification details
        """
        pass
    
    @abstractmethod
    def verify_chain(
        self, 
        data_chain: List[Any],
        proofs: List[bytes]
    ) -> List[VerificationResult]:
        """
        Verify a chain of data items.
        
        Args:
            data_chain: List of data items
            proofs: List of corresponding proofs
            
        Returns:
            List of verification results
        """
        pass
    
    def get_supported_verification_types(self) -> List[VerificationType]:
        """Get supported verification types"""
        return [VerificationType.SIGNATURE, VerificationType.HASH]


# ============================================================================
# Context Routing Interface (for caas integration)
# ============================================================================

class RoutingStrategy(Enum):
    """Routing strategies for context"""
    ROUND_ROBIN = "round_robin"
    LEAST_LOADED = "least_loaded"
    CONTENT_BASED = "content_based"
    CAPABILITY_BASED = "capability_based"
    PRIORITY_BASED = "priority_based"


@dataclass
class ContextMetadata:
    """Metadata about a context"""
    context_id: str
    content_type: str
    size_bytes: int
    created_at: datetime
    tags: List[str] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RoutingContext:
    """Context for routing decisions"""
    request_id: str
    content: Any
    metadata: ContextMetadata
    constraints: Dict[str, Any] = field(default_factory=dict)
    preferences: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RouteResult:
    """Result of a routing operation"""
    success: bool
    target_id: str
    strategy_used: RoutingStrategy
    latency_ms: float = 0.0
    fallback_targets: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ContextRoutingInterface(ABC):
    """
    Abstract interface for context routing (caas integration).
    
    This interface defines how to route context to appropriate handlers.
    Implementations can use caas or any other context routing system.
    
    Example Usage:
        ```python
        from agent_control_plane.interfaces import ContextRoutingInterface
        
        class CAASRouter(ContextRoutingInterface):
            def route_context(self, context, available_handlers):
                # Use caas for routing
                ...
        
        control_plane.register_context_router(CAASRouter())
        ```
    """
    
    @abstractmethod
    def route_context(
        self, 
        context: RoutingContext,
        available_handlers: List[str],
        strategy: RoutingStrategy = RoutingStrategy.CAPABILITY_BASED
    ) -> RouteResult:
        """
        Route context to an appropriate handler.
        
        Args:
            context: The context to route
            available_handlers: List of available handler IDs
            strategy: Routing strategy to use
            
        Returns:
            RouteResult with target and metadata
        """
        pass
    
    @abstractmethod
    def register_handler(
        self, 
        handler_id: str,
        capabilities: List[str],
        capacity: int = 100,
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Register a context handler.
        
        Args:
            handler_id: ID of the handler
            capabilities: List of content types/tags the handler can process
            capacity: Maximum concurrent contexts
            metadata: Optional handler metadata
            
        Returns:
            True if registration was successful
        """
        pass
    
    @abstractmethod
    def unregister_handler(self, handler_id: str) -> bool:
        """
        Unregister a context handler.
        
        Args:
            handler_id: ID of the handler to unregister
            
        Returns:
            True if unregistration was successful
        """
        pass
    
    @abstractmethod
    def get_handler_status(self, handler_id: str) -> Dict[str, Any]:
        """
        Get status of a registered handler.
        
        Args:
            handler_id: ID of the handler
            
        Returns:
            Handler status dictionary
        """
        pass
    
    def get_routing_statistics(self) -> Dict[str, Any]:
        """Get routing statistics"""
        return {}
    
    def get_supported_strategies(self) -> List[RoutingStrategy]:
        """Get supported routing strategies"""
        return list(RoutingStrategy)
