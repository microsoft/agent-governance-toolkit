# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Dependency Injection for ATR tools.

Provides a mechanism for injecting configuration, credentials, and other
dependencies into tool functions at execution time.
"""

from __future__ import annotations

import inspect
import threading
from dataclasses import dataclass
from typing import (
    Any,
    Callable,
    Dict,
    Generic,
    Optional,
    Type,
    TypeVar,
    Union,
    get_type_hints,
)

T = TypeVar("T")


class InjectionToken(Generic[T]):
    """Token for identifying injectable dependencies.

    Example:
        >>> CONFIG_TOKEN = InjectionToken[Config]("config")
        >>> @atr.register()
        ... def my_tool(config: Config = inject(CONFIG_TOKEN)) -> str:
        ...     return config.api_key
    """

    def __init__(self, name: str, default: Optional[T] = None):
        """Initialize injection token.

        Args:
            name: Unique name for this token.
            default: Default value if not provided.
        """
        self.name = name
        self.default = default

    def __repr__(self) -> str:
        return f"InjectionToken({self.name!r})"

    def __hash__(self) -> int:
        return hash(self.name)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, InjectionToken):
            return self.name == other.name
        return False


@dataclass
class InjectionMarker:
    """Marker class to identify parameters that need injection.

    Used as a default value for parameters that should be injected.
    """

    token: Optional[Union[InjectionToken, str, Type]] = None
    optional: bool = False
    default: Any = None

    def __repr__(self) -> str:
        if self.token:
            return f"inject({self.token!r})"
        return "inject()"


def inject(
    token: Optional[Union[InjectionToken, str, Type]] = None,
    *,
    optional: bool = False,
    default: Any = None,
) -> Any:
    """Mark a parameter for dependency injection.

    Use this as a default value for parameters that should be injected
    by the runtime when the tool is executed.

    Args:
        token: Optional injection token, type, or name string.
               If None, uses the parameter's type annotation.
        optional: If True, allow None when dependency isn't available.
        default: Default value if dependency isn't available.

    Returns:
        InjectionMarker instance (used as parameter default).

    Example:
        >>> @atr.register()
        ... def pdf_parser(
        ...     file_path: str,
        ...     config: Config = inject(),  # Inject by type
        ...     api_key: str = inject("api_key"),  # Inject by name
        ... ) -> dict:
        ...     ...
    """
    return InjectionMarker(token=token, optional=optional, default=default)


class DependencyContainer:
    """Container for managing injectable dependencies.

    Provides a thread-safe container for registering and resolving
    dependencies used by tools.

    Example:
        >>> container = DependencyContainer()
        >>> container.register(Config, Config(api_key="secret"))
        >>> container.register("database", db_connection)
        >>>
        >>> config = container.resolve(Config)
        >>> db = container.resolve("database")
    """

    def __init__(self):
        """Initialize empty container."""
        self._by_type: Dict[Type, Any] = {}
        self._by_name: Dict[str, Any] = {}
        self._by_token: Dict[InjectionToken, Any] = {}
        self._factories: Dict[Any, Callable[[], Any]] = {}
        self._lock = threading.RLock()

    def register(
        self,
        key: Union[Type, str, InjectionToken],
        value: Any = None,
        *,
        factory: Optional[Callable[[], Any]] = None,
        singleton: bool = True,
    ) -> "DependencyContainer":
        """Register a dependency.

        Args:
            key: Type, name string, or InjectionToken.
            value: The value to inject (mutually exclusive with factory).
            factory: Factory function to create the value.
            singleton: If using factory, whether to cache the result.

        Returns:
            Self for chaining.

        Raises:
            ValueError: If both value and factory are provided.
        """
        if value is not None and factory is not None:
            raise ValueError("Cannot provide both value and factory")

        with self._lock:
            if factory is not None:
                if singleton:
                    # Wrap factory to cache result
                    _cached = {}

                    def cached_factory():
                        if "value" not in _cached:
                            _cached["value"] = factory()
                        return _cached["value"]

                    self._factories[key] = cached_factory
                else:
                    self._factories[key] = factory
            elif isinstance(key, type):
                self._by_type[key] = value
            elif isinstance(key, str):
                self._by_name[key] = value
            elif isinstance(key, InjectionToken):
                self._by_token[key] = value
            else:
                raise TypeError(f"Unsupported key type: {type(key)}")

        return self

    def register_instance(self, instance: Any) -> "DependencyContainer":
        """Register an instance by its type.

        Convenience method that registers the instance using its type as key.

        Args:
            instance: The instance to register.

        Returns:
            Self for chaining.
        """
        return self.register(type(instance), instance)

    def resolve(
        self, key: Union[Type[T], str, InjectionToken[T]], default: Any = None
    ) -> Optional[T]:
        """Resolve a dependency.

        Args:
            key: Type, name string, or InjectionToken to resolve.
            default: Default value if not found.

        Returns:
            The resolved dependency or default.
        """
        with self._lock:
            # Check factories first
            if key in self._factories:
                return self._factories[key]()

            # Then check direct registrations
            if isinstance(key, type):
                if key in self._by_type:
                    return self._by_type[key]
                # Check subclasses
                for _registered_type, value in self._by_type.items():
                    if isinstance(value, key):
                        return value
            elif isinstance(key, str):
                if key in self._by_name:
                    return self._by_name[key]
            elif isinstance(key, InjectionToken):
                if key in self._by_token:
                    return self._by_token[key]
                # Fall back to token's default
                if key.default is not None:
                    return key.default

            return default

    def has(self, key: Union[Type, str, InjectionToken]) -> bool:
        """Check if a dependency is registered.

        Args:
            key: The key to check.

        Returns:
            True if registered, False otherwise.
        """
        with self._lock:
            if key in self._factories:
                return True
            if isinstance(key, type):
                return key in self._by_type
            elif isinstance(key, str):
                return key in self._by_name
            elif isinstance(key, InjectionToken):
                return key in self._by_token
            return False

    def unregister(self, key: Union[Type, str, InjectionToken]) -> bool:
        """Unregister a dependency.

        Args:
            key: The key to unregister.

        Returns:
            True if was registered, False otherwise.
        """
        with self._lock:
            if key in self._factories:
                del self._factories[key]
                return True
            if isinstance(key, type) and key in self._by_type:
                del self._by_type[key]
                return True
            elif isinstance(key, str) and key in self._by_name:
                del self._by_name[key]
                return True
            elif isinstance(key, InjectionToken) and key in self._by_token:
                del self._by_token[key]
                return True
            return False

    def clear(self) -> None:
        """Clear all registered dependencies."""
        with self._lock:
            self._by_type.clear()
            self._by_name.clear()
            self._by_token.clear()
            self._factories.clear()

    def create_child(self) -> "DependencyContainer":
        """Create a child container that inherits from this one.

        The child can override dependencies without affecting the parent.

        Returns:
            New child container.
        """
        child = ChildContainer(self)
        return child


class ChildContainer(DependencyContainer):
    """Child container that inherits from a parent."""

    def __init__(self, parent: DependencyContainer):
        super().__init__()
        self._parent = parent

    def resolve(
        self, key: Union[Type[T], str, InjectionToken[T]], default: Any = None
    ) -> Optional[T]:
        """Resolve from self first, then parent."""
        # Try self first
        result = super().resolve(key, None)
        if result is not None:
            return result

        # Fall back to parent
        return self._parent.resolve(key, default)

    def has(self, key: Union[Type, str, InjectionToken]) -> bool:
        """Check self and parent."""
        return super().has(key) or self._parent.has(key)


class InjectionResolver:
    """Resolves injection markers in function calls.

    Used by the runtime to inject dependencies into tool functions.
    """

    def __init__(self, container: DependencyContainer):
        """Initialize resolver with a container.

        Args:
            container: The dependency container to use.
        """
        self.container = container

    def resolve_parameters(
        self, func: Callable, args: tuple, kwargs: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Resolve injection markers in function parameters.

        Args:
            func: The function being called.
            args: Positional arguments provided.
            kwargs: Keyword arguments provided.

        Returns:
            Updated kwargs with injected values.

        Raises:
            InjectionError: If a required dependency cannot be resolved.
        """
        sig = inspect.signature(func)
        type_hints = get_type_hints(func) if hasattr(func, "__annotations__") else {}

        resolved_kwargs = dict(kwargs)

        # Convert positional args to kwargs
        params = list(sig.parameters.items())
        for i, arg in enumerate(args):
            if i < len(params):
                param_name = params[i][0]
                resolved_kwargs[param_name] = arg

        # Check each parameter for injection markers
        for param_name, param in sig.parameters.items():
            # Skip if already provided
            if param_name in resolved_kwargs:
                continue

            # Check if default is an injection marker
            if isinstance(param.default, InjectionMarker):
                marker = param.default

                # Determine the key to use
                if marker.token is not None:
                    key = marker.token
                elif param_name in type_hints:
                    key = type_hints[param_name]
                else:
                    key = param_name

                # Resolve the dependency
                value = self.container.resolve(key, marker.default)

                if value is None and not marker.optional:
                    raise InjectionError(
                        f"Cannot resolve dependency for parameter '{param_name}' "
                        f"with key {key!r}"
                    )

                resolved_kwargs[param_name] = value

        return resolved_kwargs


class InjectionError(Exception):
    """Raised when dependency injection fails."""

    pass


# Global container instance
_global_container: DependencyContainer = DependencyContainer()


def get_container() -> DependencyContainer:
    """Get the global dependency container.

    Returns:
        The global DependencyContainer instance.
    """
    return _global_container


def set_container(container: DependencyContainer) -> None:
    """Set the global dependency container.

    Args:
        container: The container to use globally.
    """
    global _global_container
    _global_container = container
