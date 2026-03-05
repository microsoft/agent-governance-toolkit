# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Schema definitions for Agent Tool Registry.

Defines the rigorous JSON/Pydantic schema for tool specifications,
similar to OpenAI Function Calling spec.
"""

from __future__ import annotations

import asyncio
import time
from enum import Enum
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, field_validator

if TYPE_CHECKING:
    pass


class ParameterType(str, Enum):
    """Supported parameter types for tool inputs/outputs."""

    STRING = "string"
    INTEGER = "integer"
    NUMBER = "number"
    BOOLEAN = "boolean"
    ARRAY = "array"
    OBJECT = "object"


class ParameterSpec(BaseModel):
    """Specification for a single parameter."""

    name: str = Field(..., description="Parameter name")
    type: ParameterType = Field(..., description="Parameter type")
    description: str = Field(..., description="Human-readable description")
    required: bool = Field(default=True, description="Whether parameter is required")
    default: Optional[Any] = Field(default=None, description="Default value if not required")
    enum: Optional[List[Any]] = Field(default=None, description="Allowed values (for enum types)")
    items: Optional[Dict[str, Any]] = Field(
        default=None, description="Array item schema (for array type)"
    )
    properties: Optional[Dict[str, Any]] = Field(
        default=None, description="Object properties (for object type)"
    )

    @field_validator("default")
    @classmethod
    def validate_default(cls, v, info):
        """Ensure default is only set for non-required parameters."""
        if v is not None and info.data.get("required", True):
            raise ValueError("Cannot set default value for required parameter")
        return v


class SideEffect(str, Enum):
    """Types of side effects a tool may have."""

    NONE = "none"
    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    NETWORK = "network"
    FILESYSTEM = "filesystem"


class CostLevel(str, Enum):
    """Cost level for tool execution."""

    FREE = "free"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class ToolMetadata(BaseModel):
    """Metadata about a tool."""

    name: str = Field(..., description="Unique tool identifier")
    description: str = Field(..., description="Human-readable tool description")
    version: str = Field(default="1.0.0", description="Semantic version (e.g., '1.0.0')")
    author: Optional[str] = Field(default=None, description="Tool author")
    cost: CostLevel = Field(default=CostLevel.FREE, description="Estimated execution cost")
    side_effects: List[SideEffect] = Field(
        default_factory=lambda: [SideEffect.NONE], description="Tool side effects"
    )
    tags: List[str] = Field(default_factory=list, description="Searchable tags")

    # New fields for enhanced functionality
    is_async: bool = Field(default=False, description="Whether tool supports async execution")
    permissions: List[str] = Field(
        default_factory=list, description="Required permissions/roles to access"
    )
    rate_limit: Optional[str] = Field(
        default=None, description="Rate limit string (e.g., '10/minute')"
    )
    deprecated: bool = Field(default=False, description="Whether this tool version is deprecated")
    deprecated_message: Optional[str] = Field(
        default=None, description="Deprecation message/migration guide"
    )

    @field_validator("version")
    @classmethod
    def validate_version(cls, v: str) -> str:
        """Validate semantic version format."""
        import re

        # Basic semver pattern
        pattern = r"^\d+\.\d+\.\d+(?:-[\w.]+)?(?:\+[\w.]+)?$"
        if not re.match(pattern, v):
            raise ValueError(f"Invalid version format: {v}. Expected semver (e.g., '1.0.0')")
        return v

    @property
    def version_tuple(self) -> tuple:
        """Get version as a comparable tuple."""
        import re

        # Extract major.minor.patch
        match = re.match(r"^(\d+)\.(\d+)\.(\d+)", self.version)
        if match:
            return (int(match.group(1)), int(match.group(2)), int(match.group(3)))
        return (0, 0, 0)


class ToolSpec(BaseModel):
    """Complete specification for a tool.

    This is the core schema that defines what a tool looks like in the registry.
    It does NOT execute the tool - it just describes it.
    """

    model_config = ConfigDict(arbitrary_types_allowed=True)

    metadata: ToolMetadata = Field(..., description="Tool metadata")
    parameters: List[ParameterSpec] = Field(default_factory=list, description="Input parameters")
    returns: Optional[ParameterSpec] = Field(default=None, description="Return value specification")

    # The actual callable - stored but never executed by the registry
    # Use PrivateAttr for internal state that shouldn't be validated
    _callable_func: Optional[Any] = PrivateAttr(default=None)

    # Enhanced execution configuration
    _retry_policy: Optional[Any] = PrivateAttr(default=None)  # RetryPolicy
    _rate_limit_policy: Optional[Any] = PrivateAttr(default=None)  # RateLimitPolicy
    _health_check: Optional[Any] = PrivateAttr(default=None)  # HealthCheck
    _access_policy: Optional[Any] = PrivateAttr(default=None)  # AccessPolicy

    @property
    def name(self) -> str:
        """Convenience property for tool name."""
        return self.metadata.name

    @property
    def version(self) -> str:
        """Convenience property for tool version."""
        return self.metadata.version

    @property
    def is_async(self) -> bool:
        """Check if tool supports async execution."""
        return self.metadata.is_async

    @property
    def retry_policy(self) -> Optional[Any]:
        """Get the retry policy if set."""
        return self._retry_policy

    @retry_policy.setter
    def retry_policy(self, policy: Any) -> None:
        """Set the retry policy."""
        self._retry_policy = policy

    @property
    def rate_limit_policy(self) -> Optional[Any]:
        """Get the rate limit policy if set."""
        return self._rate_limit_policy

    @rate_limit_policy.setter
    def rate_limit_policy(self, policy: Any) -> None:
        """Set the rate limit policy."""
        self._rate_limit_policy = policy

    @property
    def health_check(self) -> Optional[Any]:
        """Get the health check if set."""
        return self._health_check

    @health_check.setter
    def health_check(self, check: Any) -> None:
        """Set the health check."""
        self._health_check = check

    @property
    def access_policy(self) -> Optional[Any]:
        """Get the access policy if set."""
        return self._access_policy

    @access_policy.setter
    def access_policy(self, policy: Any) -> None:
        """Set the access policy."""
        self._access_policy = policy

    def to_openai_function_schema(self) -> Dict[str, Any]:
        """Convert to OpenAI function calling format.

        Returns:
            Dictionary in OpenAI function calling format
        """
        properties = {}
        required = []

        for param in self.parameters:
            prop_schema = {
                "type": param.type.value,
                "description": param.description,
            }

            if param.enum:
                prop_schema["enum"] = param.enum
            if param.items:
                prop_schema["items"] = param.items
            if param.properties:
                prop_schema["properties"] = param.properties

            properties[param.name] = prop_schema

            if param.required:
                required.append(param.name)

        return {
            "name": self.metadata.name,
            "description": self.metadata.description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        }

    def to_anthropic_tool_schema(self) -> Dict[str, Any]:
        """Convert to Anthropic tool use format.

        Returns:
            Dictionary in Anthropic tool use format.
        """
        return {
            "name": self.metadata.name,
            "description": self.metadata.description,
            "input_schema": {
                "type": "object",
                "properties": {
                    param.name: {
                        "type": param.type.value,
                        "description": param.description,
                        **({"enum": param.enum} if param.enum else {}),
                        **({"items": param.items} if param.items else {}),
                    }
                    for param in self.parameters
                },
                "required": [p.name for p in self.parameters if p.required],
            },
        }


class ToolHandle:
    """Handle for executing a registered tool with all policies applied.

    This is the public interface for tool execution, applying rate limiting,
    retries, metrics collection, and access control automatically.

    Example:
        >>> tool = atr.get_tool("pdf_parser", version=">=1.0.0")
        >>> result = await tool.call_async(file_path="doc.pdf")
        >>> # or synchronously
        >>> result = tool.call(file_path="doc.pdf")
    """

    def __init__(
        self,
        spec: ToolSpec,
        container: Optional[Any] = None,  # DependencyContainer
        metrics_collector: Optional[Any] = None,  # MetricsCollector
        access_manager: Optional[Any] = None,  # AccessControlManager
    ):
        """Initialize tool handle.

        Args:
            spec: The tool specification.
            container: Optional dependency container for injection.
            metrics_collector: Optional metrics collector.
            access_manager: Optional access control manager.
        """
        self._spec = spec
        self._container = container
        self._metrics = metrics_collector
        self._access_manager = access_manager

    @property
    def spec(self) -> ToolSpec:
        """Get the underlying tool specification."""
        return self._spec

    @property
    def name(self) -> str:
        """Get tool name."""
        return self._spec.name

    @property
    def version(self) -> str:
        """Get tool version."""
        return self._spec.version

    @property
    def is_async(self) -> bool:
        """Check if tool supports async."""
        return self._spec.is_async

    def call(self, *args: Any, **kwargs: Any) -> Any:
        """Execute the tool synchronously with all policies.

        Args:
            *args: Positional arguments.
            **kwargs: Keyword arguments.

        Returns:
            The tool's return value.

        Raises:
            ValueError: If tool has no callable.
            RateLimitExceeded: If rate limited.
            RetryExhausted: If all retries fail.
            AccessDeniedError: If access is denied.
        """
        if self._spec._callable_func is None:
            raise ValueError(f"Tool '{self.name}' has no callable function")

        start_time = time.perf_counter()
        error = None
        rate_limited = False

        try:
            # Apply rate limiting
            if self._spec._rate_limit_policy and not self._spec._rate_limit_policy.acquire(
                blocking=True, timeout=30
            ):
                rate_limited = True
                from atr.policies import RateLimitExceeded

                raise RateLimitExceeded(f"Rate limit exceeded for tool '{self.name}'")

            # Inject dependencies if container available
            if self._container:
                from atr.injection import InjectionResolver

                resolver = InjectionResolver(self._container)
                kwargs = resolver.resolve_parameters(self._spec._callable_func, args, kwargs)
                args = ()

            # Execute with retry policy if configured
            if self._spec._retry_policy:
                from atr.policies import with_retry

                result = with_retry(
                    self._spec._retry_policy, self._spec._callable_func, *args, **kwargs
                )
            else:
                result = self._spec._callable_func(*args, **kwargs)

            return result

        except Exception as e:
            error = e
            raise
        finally:
            # Record metrics
            if self._metrics:
                latency_ms = (time.perf_counter() - start_time) * 1000
                self._metrics.record_call(
                    tool_name=self.name,
                    latency_ms=latency_ms,
                    success=(error is None),
                    error=error,
                    rate_limited=rate_limited,
                )

    async def call_async(self, *args: Any, **kwargs: Any) -> Any:
        """Execute the tool asynchronously with all policies.

        Args:
            *args: Positional arguments.
            **kwargs: Keyword arguments.

        Returns:
            The tool's return value.

        Raises:
            ValueError: If tool has no callable.
            RateLimitExceeded: If rate limited.
            RetryExhausted: If all retries fail.
            AccessDeniedError: If access is denied.
        """
        if self._spec._callable_func is None:
            raise ValueError(f"Tool '{self.name}' has no callable function")

        start_time = time.perf_counter()
        error = None
        rate_limited = False

        try:
            # Apply rate limiting
            if (
                self._spec._rate_limit_policy
                and not await self._spec._rate_limit_policy.acquire_async(blocking=True, timeout=30)
            ):
                rate_limited = True
                from atr.policies import RateLimitExceeded

                raise RateLimitExceeded(f"Rate limit exceeded for tool '{self.name}'")

            # Inject dependencies if container available
            if self._container:
                from atr.injection import InjectionResolver

                resolver = InjectionResolver(self._container)
                kwargs = resolver.resolve_parameters(self._spec._callable_func, args, kwargs)
                args = ()

            # Execute with retry policy if configured
            if self._spec._retry_policy:
                from atr.policies import with_retry_async

                result = await with_retry_async(
                    self._spec._retry_policy, self._spec._callable_func, *args, **kwargs
                )
            else:
                func = self._spec._callable_func
                result = func(*args, **kwargs)
                if asyncio.iscoroutine(result):
                    result = await result

            return result

        except Exception as e:
            error = e
            raise
        finally:
            # Record metrics
            if self._metrics:
                latency_ms = (time.perf_counter() - start_time) * 1000
                self._metrics.record_call(
                    tool_name=self.name,
                    latency_ms=latency_ms,
                    success=(error is None),
                    error=error,
                    rate_limited=rate_limited,
                )

    def check_health(self) -> Optional[Any]:
        """Run health check if configured.

        Returns:
            HealthCheckResult or None if no health check configured.
        """
        if self._spec._health_check:
            return self._spec._health_check.check()
        return None

    async def check_health_async(self) -> Optional[Any]:
        """Run health check asynchronously.

        Returns:
            HealthCheckResult or None if no health check configured.
        """
        if self._spec._health_check:
            return await self._spec._health_check.check_async()
        return None
