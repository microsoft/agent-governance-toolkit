# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""ATR - Agent Tool Registry.

A decentralized marketplace for agent capabilities. ATR provides a standardized
interface for tool discovery, registration, and schema generation compatible with
OpenAI Function Calling, Anthropic Tool Use, and other LLM function calling formats.

Example:
    Basic usage with the global registry::

        import atr

        @atr.register(name="calculator", cost="free", tags=["math"])
        def add(a: int, b: int) -> int:
            '''Add two numbers together.

            Args:
                a: First number to add.
                b: Second number to add.

            Returns:
                The sum of a and b.
            '''
            return a + b

        # Discover tools
        tools = atr.list_tools(tag="math")

        # Get OpenAI-compatible schema
        schema = atr.get_tool("calculator").to_openai_function_schema()

    Advanced usage with versioning and policies::

        from atr import register, get_tool, RetryPolicy, inject

        @register(
            name="pdf_parser",
            version="1.0.0",
            async_=True,
            rate_limit="10/minute",
            permissions=["claims-agent"],
            retry_policy=RetryPolicy(max_attempts=3, backoff="exponential")
        )
        async def pdf_parser(file_path: str, config: Config = inject()) -> dict:
            '''Parse a PDF document.'''
            ...

        # Get tool handle for execution
        tool = atr.get_tool("pdf_parser", version=">=1.0.0")
        result = await tool.call_async(file_path="doc.pdf")

Note:
    The registry stores tool specifications but does NOT execute them.
    Execution is the responsibility of the Agent Runtime (Control Plane).

Attributes:
    __version__: Package version string.
    __author__: Package author.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable, List, Optional

from atr.access import (
    AccessControlManager,
    AccessDeniedError,
    AccessPolicy,
    Permission,
    Principal,
    get_access_manager,
    set_access_manager,
)
from atr.composition import (
    CompositionError,
    ConditionalStep,
    FallbackStep,
    FunctionStep,
    ParallelExecution,
    Pipeline,
    ToolChain,
    ToolResult,
    ToolStep,
    compose,
)
from atr.decorator import register as register_decorator
from atr.executor import (
    DockerExecutor,
    ExecutionTimeoutError,
    Executor,
    ExecutorError,
    LocalExecutor,
)
from atr.health import (
    CallableHealthCheck,
    HealthCheck,
    HealthCheckRegistry,
    HealthCheckResult,
    HealthStatus,
    HttpHealthCheck,
    TcpHealthCheck,
    get_health_registry,
    set_health_registry,
)
from atr.injection import (
    DependencyContainer,
    InjectionError,
    InjectionMarker,
    InjectionResolver,
    InjectionToken,
    get_container,
    inject,
    set_container,
)
from atr.metrics import (
    MetricsCollector,
    MetricsContext,
    MetricType,
    ToolMetrics,
)
from atr.metrics import (
    get_collector as get_metrics_collector,
)
from atr.metrics import (
    set_collector as set_metrics_collector,
)

# Import new modules
from atr.policies import (
    BackoffStrategy,
    RateLimitExceeded,
    RateLimitPolicy,
    RetryExhausted,
    RetryPolicy,
    with_retry,
    with_retry_async,
)
from atr.registry import (
    Registry,
    RegistryError,
    ToolAlreadyExistsError,
    ToolNotFoundError,
    VersionConstraintError,
)
from atr.schema import (
    CostLevel,
    ParameterSpec,
    ParameterType,
    SideEffect,
    ToolHandle,
    ToolMetadata,
    ToolSpec,
)

if TYPE_CHECKING:
    from typing import Any

__version__ = "3.1.1"
__author__ = "Microsoft Corporation"

__all__ = [
    # Core classes
    "ToolSpec",
    "ToolMetadata",
    "ToolHandle",
    "ParameterSpec",
    "ParameterType",
    # Enums
    "CostLevel",
    "SideEffect",
    # Registry
    "Registry",
    "RegistryError",
    "ToolNotFoundError",
    "ToolAlreadyExistsError",
    "VersionConstraintError",
    # Executors
    "Executor",
    "LocalExecutor",
    "DockerExecutor",
    "ExecutorError",
    "ExecutionTimeoutError",
    # Functions
    "register",
    "get_tool",
    "get_tool_handle",
    "list_tools",
    "search_tools",
    "get_callable",
    "execute_tool",
    "get_all_versions",
    "deprecate_tool",
    # Policies
    "RetryPolicy",
    "RateLimitPolicy",
    "BackoffStrategy",
    "RateLimitExceeded",
    "RetryExhausted",
    "with_retry",
    "with_retry_async",
    # Dependency Injection
    "inject",
    "InjectionToken",
    "InjectionMarker",
    "DependencyContainer",
    "InjectionResolver",
    "InjectionError",
    "get_container",
    "set_container",
    # Metrics
    "MetricsCollector",
    "ToolMetrics",
    "MetricType",
    "MetricsContext",
    "get_metrics_collector",
    "set_metrics_collector",
    # Health Checks
    "HealthCheck",
    "HealthCheckResult",
    "HealthStatus",
    "HttpHealthCheck",
    "TcpHealthCheck",
    "CallableHealthCheck",
    "HealthCheckRegistry",
    "get_health_registry",
    "set_health_registry",
    # Access Control
    "Principal",
    "AccessPolicy",
    "AccessDeniedError",
    "AccessControlManager",
    "Permission",
    "get_access_manager",
    "set_access_manager",
    # Composition
    "ToolResult",
    "ToolStep",
    "FunctionStep",
    "Pipeline",
    "ParallelExecution",
    "ConditionalStep",
    "FallbackStep",
    "ToolChain",
    "compose",
    "CompositionError",
    "configure_registry",
    "get_registry",
    # Module info
    "__version__",
    "__author__",
]

# ---------------------------------------------------------------------------
# Global Registry Instance
# ---------------------------------------------------------------------------

_global_registry: Registry = Registry(
    container=get_container(),
    metrics_collector=get_metrics_collector(),
    access_manager=get_access_manager(),
)


def register(
    name: Optional[str] = None,
    description: Optional[str] = None,
    version: str = "1.0.0",
    author: Optional[str] = None,
    cost: str = "free",
    side_effects: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
    registry: Optional[Registry] = None,
    # New parameters for enhanced features
    async_: Optional[bool] = None,
    permissions: Optional[List[str]] = None,
    rate_limit: Optional[str] = None,
    retry_policy: Optional[RetryPolicy] = None,
    health_check: Optional[HealthCheck] = None,
    access_policy: Optional[AccessPolicy] = None,
    deprecated: bool = False,
    deprecated_message: Optional[str] = None,
) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
    """Register a function as a tool in the Agent Tool Registry.

    This decorator transforms a Python function into a discoverable tool by:
    1. Extracting the function signature and type hints
    2. Converting to a standardized ToolSpec schema
    3. Registering in the specified registry (defaults to global)

    Args:
        name: Unique tool identifier. Defaults to function name if not provided.
        description: Human-readable description. Defaults to function docstring.
        version: Semantic version string for the tool (e.g., "1.0.0").
        author: Tool author name.
        cost: Execution cost level. One of "free", "low", "medium", "high".
        side_effects: List of side effects. Options: "none", "read", "write",
            "delete", "network", "filesystem".
        tags: Searchable tags for tool discovery.
        registry: Custom registry instance. Uses global registry if None.
        async_: Whether tool is async (auto-detected if None).
        permissions: List of roles/agents allowed to access this tool.
        rate_limit: Rate limit string (e.g., "10/minute", "100/hour").
        retry_policy: RetryPolicy instance for automatic retries.
        health_check: HealthCheck instance for verifying tool availability.
        access_policy: AccessPolicy instance for fine-grained access control.
        deprecated: Whether this version is deprecated.
        deprecated_message: Migration guide for deprecated tools.

    Returns:
        A decorator that registers the function and returns it unchanged.

    Raises:
        ValueError: If function parameters lack type hints.
        ToolAlreadyExistsError: If tool with same name/version already exists.

    Example:
        Basic usage::

            @register(name="web_scraper", cost="low", tags=["web"])
            def scrape(url: str, timeout: int = 30) -> str:
                '''Scrape content from a URL.'''
                return requests.get(url, timeout=timeout).text

        Advanced usage with versioning and policies::

            @register(
                name="pdf_parser",
                version="1.0.0",
                async_=True,
                rate_limit="10/minute",
                permissions=["claims-agent"],
                retry_policy=RetryPolicy(max_attempts=3, backoff="exponential")
            )
            async def pdf_parser(file_path: str) -> dict:
                '''Parse a PDF document.'''
                ...
    """
    target_registry = registry if registry is not None else _global_registry

    return register_decorator(
        name=name,
        description=description,
        version=version,
        author=author,
        cost=cost,
        side_effects=side_effects,
        tags=tags,
        registry=target_registry,
        async_=async_,
        permissions=permissions,
        rate_limit=rate_limit,
        retry_policy=retry_policy,
        health_check=health_check,
        access_policy=access_policy,
        deprecated=deprecated,
        deprecated_message=deprecated_message,
    )


def get_tool(
    name: str, version: Optional[str] = None, include_deprecated: bool = False
) -> ToolSpec:
    """Retrieve a tool specification from the global registry.

    Args:
        name: The unique tool identifier.
        version: Version constraint (e.g., ">=1.0.0", "^1.0.0", "1.2.3").
                If None, returns the latest version.
        include_deprecated: Whether to include deprecated versions.

    Returns:
        The complete tool specification including metadata and parameters.

    Raises:
        ToolNotFoundError: If no tool with the given name exists.
        VersionConstraintError: If no version matches the constraint.

    Example:
        >>> spec = get_tool("calculator")
        >>> print(spec.metadata.description)
        >>>
        >>> # Get specific version
        >>> spec = get_tool("pdf_parser", version=">=1.0.0")
    """
    return _global_registry.get_tool(name, version, include_deprecated)


def get_tool_handle(
    name: str, version: Optional[str] = None, include_deprecated: bool = False
) -> ToolHandle:
    """Get a ToolHandle for executing a tool with all policies applied.

    The ToolHandle provides a convenient interface for executing tools
    with automatic rate limiting, retries, metrics collection, and
    dependency injection.

    Args:
        name: The unique tool identifier.
        version: Version constraint (e.g., ">=1.0.0", "^1.0.0", "1.2.3").
        include_deprecated: Whether to include deprecated versions.

    Returns:
        ToolHandle ready for execution.

    Raises:
        ToolNotFoundError: If no tool with the given name exists.
        VersionConstraintError: If no version matches the constraint.

    Example:
        >>> tool = get_tool_handle("pdf_parser", version=">=1.0.0")
        >>> result = await tool.call_async(file_path="doc.pdf")
        >>> # or synchronously
        >>> result = tool.call(file_path="doc.pdf")
    """
    return _global_registry.get_tool_handle(name, version, include_deprecated)


def get_all_versions(name: str) -> List[str]:
    """Get all registered versions of a tool.

    Args:
        name: The unique tool identifier.

    Returns:
        List of version strings, sorted newest first.

    Raises:
        ToolNotFoundError: If no tool with the given name exists.

    Example:
        >>> versions = get_all_versions("pdf_parser")
        >>> print(versions)  # ["2.0.0", "1.1.0", "1.0.0"]
    """
    return _global_registry.get_all_versions(name)


def deprecate_tool(name: str, version: str, message: Optional[str] = None) -> None:
    """Mark a tool version as deprecated.

    Args:
        name: Tool name.
        version: Version to deprecate.
        message: Optional deprecation message/migration guide.

    Raises:
        ToolNotFoundError: If tool/version not found.

    Example:
        >>> deprecate_tool(
        ...     "pdf_parser",
        ...     "1.0.0",
        ...     "Use version 2.0.0 instead. See migration guide at ..."
        ... )
    """
    _global_registry.deprecate_tool(name, version, message)


def list_tools(
    tag: Optional[str] = None,
    cost: Optional[CostLevel] = None,
    side_effect: Optional[SideEffect] = None,
    include_all_versions: bool = False,
    include_deprecated: bool = False,
) -> List[ToolSpec]:
    """List all registered tools with optional filtering.

    Args:
        tag: Filter by tag (e.g., "math", "web", "file").
        cost: Filter by cost level enum.
        side_effect: Filter by side effect type.
        include_all_versions: If True, return all versions. If False, only latest.
        include_deprecated: Whether to include deprecated tools.

    Returns:
        List of tool specifications matching the filters.

    Example:
        >>> # Get all low-cost tools
        >>> cheap_tools = list_tools(cost=CostLevel.LOW)
        >>> # Get all tools tagged "math"
        >>> math_tools = list_tools(tag="math")
        >>> # Get all versions of all tools
        >>> all_tools = list_tools(include_all_versions=True)
    """
    return _global_registry.list_tools(
        tag=tag,
        cost=cost,
        side_effect=side_effect,
        include_all_versions=include_all_versions,
        include_deprecated=include_deprecated,
    )


def search_tools(query: str, include_all_versions: bool = False) -> List[ToolSpec]:
    """Search tools by name, description, or tags.

    Performs a case-insensitive search across tool metadata.

    Args:
        query: Search query string.
        include_all_versions: Whether to search all versions.

    Returns:
        List of matching tool specifications.

    Example:
        >>> results = search_tools("scrape")
        >>> for tool in results:
        ...     print(tool.metadata.name)
    """
    return _global_registry.search_tools(query, include_all_versions)


def get_callable(name: str, version: Optional[str] = None) -> Callable[..., Any]:
    """Get the callable function for a registered tool.

    This returns the function object but does NOT execute it.
    The caller (Agent Runtime) is responsible for execution.

    For most use cases, prefer get_tool_handle() which provides
    automatic rate limiting, retries, and metrics collection.

    Args:
        name: The unique tool identifier.
        version: Optional version constraint.

    Returns:
        The original callable function.

    Raises:
        ToolNotFoundError: If no tool with the given name exists.
        ValueError: If the tool has no associated callable.

    Example:
        >>> func = get_callable("calculator")
        >>> result = func(a=1, b=2)  # Caller executes
    """
    return _global_registry.get_callable(name, version)


def execute_tool(
    name: str,
    args: Optional[dict] = None,
    executor: Optional[Executor] = None,
    timeout: Optional[int] = None,
) -> Any:
    """Execute a registered tool with optional sandboxing.

    This is a convenience function that retrieves a tool and executes it
    using the specified executor. If no executor is provided, uses LocalExecutor
    (direct execution on host - not sandboxed).

    For production use with untrusted code, always provide a DockerExecutor
    to ensure sandboxed execution.

    Args:
        name: The unique tool identifier.
        args: Dictionary of arguments to pass to the tool.
        executor: Executor instance to use. Defaults to LocalExecutor if None.
        timeout: Execution timeout in seconds (only applicable for DockerExecutor).

    Returns:
        The result of the tool execution.

    Raises:
        ToolNotFoundError: If no tool with the given name exists.
        ValueError: If the tool has no associated callable.
        ExecutorError: If execution fails.
        ExecutionTimeoutError: If execution exceeds timeout.

    Example:
        >>> # Direct execution (not sandboxed - use only with trusted code)
        >>> result = execute_tool("calculator", {"a": 5, "b": 3})

        >>> # Sandboxed execution (recommended for untrusted code)
        >>> from atr import DockerExecutor
        >>> docker_exec = DockerExecutor()
        >>> result = execute_tool("calculator", {"a": 5, "b": 3}, executor=docker_exec)
    """
    if args is None:
        args = {}

    # Get the callable function
    func = get_callable(name)

    # Use LocalExecutor if no executor provided
    if executor is None:
        executor = LocalExecutor()

    # Execute with the specified executor
    return executor.execute(func, args=args, timeout=timeout)


# ---------------------------------------------------------------------------
# Registry Configuration
# ---------------------------------------------------------------------------


def configure_registry(
    container: Optional[DependencyContainer] = None,
    metrics_collector: Optional[MetricsCollector] = None,
    access_manager: Optional[AccessControlManager] = None,
) -> None:
    """Configure the global registry with custom components.

    Args:
        container: Dependency container for injection.
        metrics_collector: Metrics collector for tracking.
        access_manager: Access control manager.

    Example:
        >>> container = DependencyContainer()
        >>> container.register(Config, Config(api_key="secret"))
        >>> configure_registry(container=container)
    """
    global _global_registry

    if container is not None:
        _global_registry._container = container
    if metrics_collector is not None:
        _global_registry._metrics = metrics_collector
    if access_manager is not None:
        _global_registry._access_manager = access_manager


def get_registry() -> Registry:
    """Get the global registry instance.

    This is the preferred way to access the registry instead of
    using the private _global_registry directly.

    Returns:
        The global Registry instance.

    Example:
        >>> registry = get_registry()
        >>> print(f"Registered tools: {len(registry)}")
    """
    return _global_registry
