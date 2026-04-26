# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Schema validation for AMB messages.

This module provides schema registry and validation capabilities
to ensure message payloads conform to expected schemas.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Type, Union, Callable
from pydantic import BaseModel, ValidationError
import json


class SchemaValidationError(Exception):
    """Raised when message schema validation fails."""
    
    def __init__(self, topic: str, errors: list, payload: Dict[str, Any]):
        self.topic = topic
        self.errors = errors
        self.payload = payload
        super().__init__(f"Schema validation failed for topic '{topic}': {errors}")


class Schema(ABC):
    """Abstract base class for message schemas."""
    
    @abstractmethod
    def validate(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate a payload against the schema.
        
        Args:
            payload: The payload to validate
            
        Returns:
            The validated payload (potentially coerced/normalized)
            
        Raises:
            SchemaValidationError: If validation fails
        """
        pass


class PydanticSchema(Schema):
    """Schema backed by a Pydantic model."""
    
    def __init__(self, model: Type[BaseModel]):
        """
        Initialize with a Pydantic model.
        
        Args:
            model: Pydantic model class to use for validation
        """
        self._model = model
    
    def validate(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Validate payload using Pydantic model."""
        try:
            validated = self._model.model_validate(payload)
            return validated.model_dump()
        except ValidationError as e:
            raise SchemaValidationError(
                topic="unknown",
                errors=e.errors(),
                payload=payload
            )


class DictSchema(Schema):
    """Schema based on a dictionary specification with type checking."""
    
    def __init__(self, spec: Dict[str, type], strict: bool = False):
        """
        Initialize with a dictionary specification.
        
        Args:
            spec: Dict mapping field names to expected types
            strict: If True, reject payloads with extra fields
            
        Example:
            schema = DictSchema({
                "user_id": str,
                "amount": float,
                "timestamp": str
            })
        """
        self._spec = spec
        self._strict = strict
    
    def validate(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Validate payload against dictionary specification."""
        errors = []
        
        # Check required fields
        for field, expected_type in self._spec.items():
            if field not in payload:
                errors.append({
                    "type": "missing",
                    "loc": [field],
                    "msg": f"Field '{field}' is required"
                })
            elif not isinstance(payload[field], expected_type):
                errors.append({
                    "type": "type_error",
                    "loc": [field],
                    "msg": f"Expected {expected_type.__name__}, got {type(payload[field]).__name__}"
                })
        
        # Check for extra fields if strict
        if self._strict:
            extra_fields = set(payload.keys()) - set(self._spec.keys())
            for field in extra_fields:
                errors.append({
                    "type": "extra_forbidden",
                    "loc": [field],
                    "msg": f"Extra field '{field}' not allowed"
                })
        
        if errors:
            raise SchemaValidationError(
                topic="unknown",
                errors=errors,
                payload=payload
            )
        
        return payload


class CallableSchema(Schema):
    """Schema using a custom validation function."""
    
    def __init__(self, validator: Callable[[Dict[str, Any]], Dict[str, Any]]):
        """
        Initialize with a validation function.
        
        Args:
            validator: Function that takes payload and returns validated payload,
                      or raises an exception on validation failure
        """
        self._validator = validator
    
    def validate(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Validate using custom function."""
        try:
            return self._validator(payload)
        except Exception as e:
            raise SchemaValidationError(
                topic="unknown",
                errors=[{"type": "validation_error", "msg": str(e)}],
                payload=payload
            )


class SchemaRegistry:
    """
    Registry for message schemas.
    
    Provides centralized schema management for topic validation.
    Supports multiple schema types: Pydantic models, dict specs, and custom validators.
    
    Example:
        from pydantic import BaseModel
        
        class FraudAlertPayload(BaseModel):
            transaction_id: str
            amount: float
            risk_score: float
        
        registry = SchemaRegistry()
        registry.register("fraud.alerts", FraudAlertPayload)
        
        # Or with dict schema
        registry.register("user.events", {
            "user_id": str,
            "event_type": str
        })
    """
    
    def __init__(self, strict: bool = True):
        """
        Initialize the schema registry.
        
        Args:
            strict: If True, require schema for all topics when validating
        """
        self._schemas: Dict[str, Schema] = {}
        self._strict = strict
    
    def register(
        self,
        topic: str,
        schema: Union[Type[BaseModel], Dict[str, type], Schema, Callable]
    ) -> None:
        """
        Register a schema for a topic.
        
        Args:
            topic: Topic pattern to register schema for
            schema: Schema specification (Pydantic model, dict, Schema instance, or callable)
            
        Example:
            # Pydantic model
            registry.register("fraud.alerts", FraudAlertSchema)
            
            # Dict specification
            registry.register("user.events", {"user_id": str, "event": str})
            
            # Custom Schema instance
            registry.register("custom.topic", MyCustomSchema())
            
            # Callable validator
            registry.register("validated.topic", lambda p: p if p.get("valid") else raise_error())
        """
        if isinstance(schema, type) and issubclass(schema, BaseModel):
            self._schemas[topic] = PydanticSchema(schema)
        elif isinstance(schema, dict):
            self._schemas[topic] = DictSchema(schema)
        elif isinstance(schema, Schema):
            self._schemas[topic] = schema
        elif callable(schema):
            self._schemas[topic] = CallableSchema(schema)
        else:
            raise TypeError(
                f"Schema must be a Pydantic model, dict, Schema instance, or callable. "
                f"Got {type(schema)}"
            )
    
    def unregister(self, topic: str) -> bool:
        """
        Unregister a schema for a topic.
        
        Args:
            topic: Topic to unregister
            
        Returns:
            True if schema was removed, False if topic wasn't registered
        """
        if topic in self._schemas:
            del self._schemas[topic]
            return True
        return False
    
    def has_schema(self, topic: str) -> bool:
        """Check if a topic has a registered schema."""
        return topic in self._schemas
    
    def get_schema(self, topic: str) -> Optional[Schema]:
        """Get the schema for a topic."""
        return self._schemas.get(topic)
    
    def validate(self, topic: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate a payload for a given topic.
        
        Args:
            topic: Topic the message is for
            payload: Message payload to validate
            
        Returns:
            Validated payload (potentially normalized)
            
        Raises:
            SchemaValidationError: If validation fails
            ValueError: If strict mode and no schema registered for topic
        """
        schema = self._schemas.get(topic)
        
        if schema is None:
            if self._strict:
                raise ValueError(f"No schema registered for topic '{topic}'")
            return payload
        
        try:
            return schema.validate(payload)
        except SchemaValidationError as e:
            # Update error with correct topic
            raise SchemaValidationError(
                topic=topic,
                errors=e.errors,
                payload=e.payload
            )
    
    def list_topics(self) -> list:
        """Get list of topics with registered schemas."""
        return list(self._schemas.keys())
    
    def __len__(self) -> int:
        """Get number of registered schemas."""
        return len(self._schemas)
    
    def __contains__(self, topic: str) -> bool:
        """Check if topic has a schema registered."""
        return topic in self._schemas
