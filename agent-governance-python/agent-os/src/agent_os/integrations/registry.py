# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Adapter Registry with Auto-Discovery

Provides a central registry for framework adapters, with support for
manual registration, decorator-based registration, and automatic
discovery of BaseIntegration subclasses.
"""

import importlib
import inspect
import logging
import pkgutil

logger = logging.getLogger(__name__)

from .base import BaseIntegration


class AdapterRegistry:
    """Singleton registry for framework adapters."""

    _instance: "AdapterRegistry | None" = None
    _adapters: dict[str, type[BaseIntegration]]

    def __new__(cls) -> "AdapterRegistry":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._adapters = {}
        return cls._instance

    def register(self, name: str, adapter_class: type[BaseIntegration]) -> None:
        """Register an adapter class under the given name.

        Raises:
            ValueError: If *name* is already registered.
            TypeError: If *adapter_class* is not a BaseIntegration subclass.
        """
        if not (isinstance(adapter_class, type) and issubclass(adapter_class, BaseIntegration)):
            raise TypeError(
                f"adapter_class must be a subclass of BaseIntegration, "
                f"got {adapter_class!r}"
            )
        if name in self._adapters:
            raise ValueError(f"Adapter '{name}' is already registered")
        self._adapters[name] = adapter_class

    def get(self, name: str) -> type[BaseIntegration]:
        """Return the adapter class registered under *name*.

        Raises:
            KeyError: If no adapter is registered with that name.
        """
        try:
            return self._adapters[name]
        except KeyError:
            raise KeyError(f"No adapter registered with name '{name}'") from None

    def list_adapters(self) -> list[str]:
        """Return sorted list of registered adapter names."""
        return sorted(self._adapters)

    def clear(self) -> None:
        """Remove all registered adapters (useful for testing)."""
        self._adapters.clear()

    @classmethod
    def auto_discover(cls) -> "AdapterRegistry":
        """Scan the integrations package and register all BaseIntegration subclasses.

        Each subclass is registered under its class name.  Returns the
        (singleton) registry instance.
        """
        registry = cls()
        package = importlib.import_module("agent_os.integrations")
        package_path = package.__path__

        for _importer, modname, _ispkg in pkgutil.iter_modules(package_path):
            if modname.startswith("_"):
                continue
            full_name = f"agent_os.integrations.{modname}"
            try:
                mod = importlib.import_module(full_name)
            except Exception:  # noqa: BLE001 — optional adapter may not be installed
                logger.debug("Failed to import adapter module %s", full_name, exc_info=True)
                continue
            for _attr_name, obj in inspect.getmembers(mod, inspect.isclass):
                if (
                    issubclass(obj, BaseIntegration)
                    and obj is not BaseIntegration
                    and obj.__name__ not in registry._adapters
                ):
                    registry._adapters[obj.__name__] = obj

        return registry


def register_adapter(name: str):
    """Class decorator that registers an adapter in the global registry.

    Usage::

        @register_adapter("my_framework")
        class MyAdapter(BaseIntegration):
            ...
    """

    def decorator(cls: type[BaseIntegration]) -> type[BaseIntegration]:
        AdapterRegistry().register(name, cls)
        return cls

    return decorator
