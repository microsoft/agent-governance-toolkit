# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Decorator for registering tools in the Agent Tool Registry.

Provides @atr.register() decorator to turn Python functions into discoverable tools.
"""

from __future__ import annotations

import asyncio
import inspect
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    List,
    Optional,
    Union,
    get_args,
    get_origin,
    get_type_hints,
)

from .registry import Registry
from .schema import (
    CostLevel,
    ParameterSpec,
    ParameterType,
    SideEffect,
    ToolMetadata,
    ToolSpec,
)

if TYPE_CHECKING:
    pass


def _python_type_to_parameter_type(python_type: Any) -> ParameterType:
    """Convert Python type annotation to ParameterType.

    Args:
        python_type: Python type annotation

    Returns:
        Corresponding ParameterType
    """
    # Handle None type
    if python_type is type(None):
        return ParameterType.STRING

    # Get the origin to check for generic types
    origin = get_origin(python_type)

    # Only unwrap Optional/Union types - don't unwrap List, Dict, etc.
    # Check if it's a Union (which includes Optional)
    if origin is Union:
        args = get_args(python_type)
        if args:
            # For Optional[X] or Union[X, None], get X
            non_none_types = [arg for arg in args if arg is not type(None)]
            if non_none_types:
                # Use the first non-None type and recurse
                return _python_type_to_parameter_type(non_none_types[0])

    # Now check the origin for generic types like List[str], Dict[str, int]
    if origin is list:
        return ParameterType.ARRAY
    elif origin is dict:
        return ParameterType.OBJECT

    # Map basic Python types to ParameterType
    if python_type == str:
        return ParameterType.STRING
    elif python_type == int:
        return ParameterType.INTEGER
    elif python_type == float:
        return ParameterType.NUMBER
    elif python_type == bool:
        return ParameterType.BOOLEAN
    elif python_type == list:
        return ParameterType.ARRAY
    elif python_type == dict:
        return ParameterType.OBJECT
    else:
        # Default to string for unknown types
        return ParameterType.STRING


def _extract_parameters_from_function(func: Callable) -> List[ParameterSpec]:
    """Extract parameter specifications from function signature.

    Args:
        func: The function to analyze

    Returns:
        List of ParameterSpec objects

    Raises:
        ValueError: If function has parameters without type hints
    """
    sig = inspect.signature(func)
    type_hints = get_type_hints(func)
    parameters = []

    for param_name, param in sig.parameters.items():
        # Skip self/cls parameters
        if param_name in ("self", "cls"):
            continue

        # Require type hints - no magic arguments!
        if param_name not in type_hints:
            raise ValueError(
                f"Parameter '{param_name}' in function '{func.__name__}' must have a type hint. "
                "No magic arguments allowed!"
            )

        python_type = type_hints[param_name]
        param_type = _python_type_to_parameter_type(python_type)

        # Determine if required (has no default value)
        required = param.default == inspect.Parameter.empty
        default = None if required else param.default

        # Extract description from docstring if available
        description = f"Parameter {param_name}"
        docstring = inspect.getdoc(func)
        if docstring:
            # Simple extraction - look for "param_name: description" pattern
            for line in docstring.split("\n"):
                if param_name in line and ":" in line:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        description = parts[1].strip()
                        break

        param_spec = ParameterSpec(
            name=param_name,
            type=param_type,
            description=description,
            required=required,
            default=default,
        )
        parameters.append(param_spec)

    return parameters


def _extract_return_spec_from_function(func: Callable) -> Optional[ParameterSpec]:
    """Extract return value specification from function.

    Args:
        func: The function to analyze

    Returns:
        ParameterSpec for return value, or None if no return type
    """
    type_hints = get_type_hints(func)

    if "return" not in type_hints or type_hints["return"] == type(None):
        return None

    return_type = type_hints["return"]
    param_type = _python_type_to_parameter_type(return_type)

    return ParameterSpec(
        name="return_value",
        type=param_type,
        description="Function return value",
        required=True,
    )


class register:
    """Decorator to register a function as a tool in the ATR.

    Usage:
        @atr.register(name="scraper", cost="low", tags=["web", "scraping"])
        def scrape_website(url: str, timeout: int = 30) -> str:
            '''Scrape content from a website.

            Args:
                url: The URL to scrape
                timeout: Timeout in seconds
            '''
            # Implementation here
            pass

    Advanced usage with all features:
        @atr.register(
            name="pdf_parser",
            version="1.0.0",
            async_=True,
            rate_limit="10/minute",
            permissions=["claims-agent"],
            retry_policy=RetryPolicy(max_attempts=3, backoff="exponential"),
            tags=["document", "parsing"]
        )
        async def pdf_parser(file_path: str, config: Config = inject()) -> dict:
            '''Parse a PDF document.'''
            ...

    This decorator:
    1. Extracts function signature and converts to ToolSpec
    2. Validates all parameters have type hints (no magic arguments!)
    3. Registers the tool in the global registry
    4. Returns the original function unchanged (doesn't wrap it)
    """

    def __init__(
        self,
        name: Optional[str] = None,
        description: Optional[str] = None,
        version: str = "1.0.0",
        author: Optional[str] = None,
        cost: str = "free",
        side_effects: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        registry: Optional[Registry] = None,
        # New parameters for enhanced features
        async_: Optional[bool] = None,  # Auto-detected if None
        permissions: Optional[List[str]] = None,
        rate_limit: Optional[str] = None,
        retry_policy: Optional[Any] = None,  # RetryPolicy
        health_check: Optional[Any] = None,  # HealthCheck
        access_policy: Optional[Any] = None,  # AccessPolicy
        deprecated: bool = False,
        deprecated_message: Optional[str] = None,
    ):
        """Initialize the register decorator.

        Args:
            name: Tool name (defaults to function name)
            description: Tool description (defaults to function docstring)
            version: Semantic version string (e.g., "1.0.0")
            author: Tool author
            cost: Cost level (free, low, medium, high)
            side_effects: List of side effects
            tags: Searchable tags
            registry: Registry instance (uses global if not provided)
            async_: Whether tool is async (auto-detected if None)
            permissions: List of roles/agents allowed to access this tool
            rate_limit: Rate limit string (e.g., "10/minute", "100/hour")
            retry_policy: RetryPolicy instance for automatic retries
            health_check: HealthCheck instance for verifying tool availability
            access_policy: AccessPolicy instance for fine-grained access control
            deprecated: Whether this version is deprecated
            deprecated_message: Migration guide for deprecated tools
        """
        self.name = name
        self.description = description
        self.version = version
        self.author = author
        self.cost = cost
        self.side_effects = side_effects or ["none"]
        self.tags = tags or []
        self.registry = registry
        self.async_ = async_
        self.permissions = permissions or []
        self.rate_limit = rate_limit
        self.retry_policy = retry_policy
        self.health_check = health_check
        self.access_policy = access_policy
        self.deprecated = deprecated
        self.deprecated_message = deprecated_message

    def __call__(self, func: Callable) -> Callable:
        """Register the function and return it unchanged.

        Args:
            func: The function to register

        Returns:
            The original function (not wrapped)
        """
        # Get or import global registry
        if self.registry is None:
            from . import _global_registry

            self.registry = _global_registry

        # Extract metadata
        tool_name = self.name or func.__name__
        tool_description = self.description or inspect.getdoc(func) or f"Tool: {tool_name}"

        # Auto-detect async
        is_async = self.async_ if self.async_ is not None else asyncio.iscoroutinefunction(func)

        # Parse cost level
        try:
            cost_level = CostLevel(self.cost.lower())
        except ValueError:
            cost_level = CostLevel.FREE

        # Parse side effects
        parsed_side_effects = []
        for se in self.side_effects:
            try:
                parsed_side_effects.append(SideEffect(se.lower()))
            except ValueError:
                parsed_side_effects.append(SideEffect.NONE)

        # Create metadata
        metadata = ToolMetadata(
            name=tool_name,
            description=tool_description,
            version=self.version,
            author=self.author,
            cost=cost_level,
            side_effects=parsed_side_effects,
            tags=self.tags,
            is_async=is_async,
            permissions=self.permissions,
            rate_limit=self.rate_limit,
            deprecated=self.deprecated,
            deprecated_message=self.deprecated_message,
        )

        # Extract parameters from function signature
        parameters = _extract_parameters_from_function(func)

        # Extract return specification
        returns = _extract_return_spec_from_function(func)

        # Create tool spec
        tool_spec = ToolSpec(
            metadata=metadata,
            parameters=parameters,
            returns=returns,
        )

        # Apply policies
        if self.retry_policy is not None:
            tool_spec._retry_policy = self.retry_policy

        if self.rate_limit is not None:
            from .policies import RateLimitPolicy

            tool_spec._rate_limit_policy = RateLimitPolicy.from_string(self.rate_limit)

        if self.health_check is not None:
            tool_spec._health_check = self.health_check

        if self.access_policy is not None:
            tool_spec._access_policy = self.access_policy
        elif self.permissions:
            # Create access policy from permissions list
            from .access import AccessPolicy

            tool_spec._access_policy = AccessPolicy.roles_only(*self.permissions)

        # Register the tool (store the callable but don't execute it)
        self.registry.register_tool(tool_spec, callable_func=func)

        # Return the original function unchanged - we don't wrap it
        # The registry stores it, but execution happens elsewhere
        return func
