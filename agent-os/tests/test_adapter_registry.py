# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the adapter registry with auto-discovery."""

import pytest
from typing import Any, Optional

from agent_os.integrations.base import BaseIntegration, GovernancePolicy
from agent_os.integrations.registry import AdapterRegistry, register_adapter


# ── Helpers ──────────────────────────────────────────────────


class _DummyAdapter(BaseIntegration):
    """Minimal concrete adapter for testing."""

    def wrap(self, agent: Any) -> Any:
        return agent

    def unwrap(self, governed_agent: Any) -> Any:
        return governed_agent


class _AnotherAdapter(BaseIntegration):
    """Second concrete adapter for testing."""

    def wrap(self, agent: Any) -> Any:
        return agent

    def unwrap(self, governed_agent: Any) -> Any:
        return governed_agent


# ── Fixtures ─────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _reset_registry():
    """Ensure a clean registry for every test."""
    registry = AdapterRegistry()
    registry.clear()
    yield
    registry.clear()
    # Reset singleton so other test modules aren't affected
    AdapterRegistry._instance = None


# ── Tests ────────────────────────────────────────────────────


class TestRegisterAndGet:
    def test_register_and_retrieve(self):
        reg = AdapterRegistry()
        reg.register("dummy", _DummyAdapter)
        assert reg.get("dummy") is _DummyAdapter

    def test_get_missing_raises_key_error(self):
        reg = AdapterRegistry()
        with pytest.raises(KeyError, match="No adapter registered"):
            reg.get("nonexistent")

    def test_duplicate_register_raises_value_error(self):
        reg = AdapterRegistry()
        reg.register("dummy", _DummyAdapter)
        with pytest.raises(ValueError, match="already registered"):
            reg.register("dummy", _AnotherAdapter)

    def test_register_non_subclass_raises_type_error(self):
        reg = AdapterRegistry()
        with pytest.raises(TypeError, match="subclass of BaseIntegration"):
            reg.register("bad", object)  # type: ignore[arg-type]


class TestListAdapters:
    def test_empty_registry(self):
        assert AdapterRegistry().list_adapters() == []

    def test_lists_registered_names_sorted(self):
        reg = AdapterRegistry()
        reg.register("zeta", _DummyAdapter)
        reg.register("alpha", _AnotherAdapter)
        assert reg.list_adapters() == ["alpha", "zeta"]


class TestSingleton:
    def test_same_instance(self):
        assert AdapterRegistry() is AdapterRegistry()


class TestDecoratorRegistration:
    def test_decorator_registers_class(self):
        @register_adapter("decorated")
        class _DecoratedAdapter(BaseIntegration):
            def wrap(self, agent: Any) -> Any:
                return agent

            def unwrap(self, governed_agent: Any) -> Any:
                return governed_agent

        reg = AdapterRegistry()
        assert reg.get("decorated") is _DecoratedAdapter


class TestAutoDiscover:
    def test_discovers_known_adapters(self):
        registry = AdapterRegistry.auto_discover()
        names = registry.list_adapters()

        # Should find the six adapters that subclass BaseIntegration
        for expected in (
            "LangChainKernel",
            "LlamaIndexKernel",
            "CrewAIKernel",
            "AutoGenKernel",
            "OpenAIKernel",
            "SemanticKernelWrapper",
        ):
            assert expected in names, f"{expected} not discovered"

    def test_auto_discover_returns_registry(self):
        result = AdapterRegistry.auto_discover()
        assert isinstance(result, AdapterRegistry)

    def test_discovered_classes_are_base_integration_subclasses(self):
        registry = AdapterRegistry.auto_discover()
        for name in registry.list_adapters():
            cls = registry.get(name)
            assert issubclass(cls, BaseIntegration)
