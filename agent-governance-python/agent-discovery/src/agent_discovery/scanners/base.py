# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Abstract base scanner and scanner registry."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..models import ScanResult


class BaseScanner(ABC):
    """Abstract base class for all agent discovery scanners.

    Scanners are stateless, read-only, and passive by default.
    They must never modify the target environment.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Unique scanner identifier."""

    @property
    def description(self) -> str:
        """Human-readable description."""
        return ""

    @abstractmethod
    async def scan(self, **kwargs: Any) -> ScanResult:
        """Execute the scan and return discovered agents.

        All scanners must be:
        - Read-only: never modify the target environment
        - Safe: redact secrets, respect rate limits
        - Scoped: only scan what's explicitly requested
        """

    def validate_config(self, **kwargs: Any) -> list[str]:
        """Validate scanner configuration. Returns list of error messages."""
        return []


class ScannerRegistry:
    """Registry of available scanners.

    Provides a central place to discover and instantiate scanners.
    """

    def __init__(self) -> None:
        self._scanners: dict[str, type[BaseScanner]] = {}

    def register(self, scanner_cls: type[BaseScanner]) -> type[BaseScanner]:
        """Register a scanner class. Can be used as a decorator."""
        instance = scanner_cls()
        self._scanners[instance.name] = scanner_cls
        return scanner_cls

    def get(self, name: str) -> BaseScanner | None:
        """Get a scanner instance by name."""
        cls = self._scanners.get(name)
        return cls() if cls else None

    def list_scanners(self) -> list[str]:
        """List all registered scanner names."""
        return sorted(self._scanners.keys())

    def get_all(self) -> list[BaseScanner]:
        """Instantiate and return all registered scanners."""
        return [cls() for cls in self._scanners.values()]


# Global registry — scanners auto-register on import
registry = ScannerRegistry()
