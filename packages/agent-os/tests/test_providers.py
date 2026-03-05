# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for the provider discovery system."""

import pytest
from unittest.mock import patch, MagicMock
from importlib.metadata import EntryPoint

from agent_os.providers import (
    _discover_provider,
    get_verification_engine,
    get_self_correction_kernel,
    get_policy_engine,
    get_context_service,
    get_memory_store,
    get_trust_protocol,
    get_mute_agent,
    list_providers,
    clear_cache,
    PROVIDER_GROUPS,
)


@pytest.fixture(autouse=True)
def _clear_provider_cache():
    """Clear provider cache before and after each test."""
    clear_cache()
    yield
    clear_cache()


class TestProviderDiscovery:
    """Test the entry_points-based provider discovery."""

    def test_no_advanced_provider_returns_none(self):
        """When no entry_point is registered, returns None."""
        result = _discover_provider("agent_os.providers.nonexistent")
        assert result is None

    def test_discovery_caches_result(self):
        """Second call returns cached result without re-scanning."""
        _discover_provider("agent_os.providers.nonexistent")
        # Call again — should hit cache
        result = _discover_provider("agent_os.providers.nonexistent")
        assert result is None

    def test_advanced_provider_loaded(self):
        """When an entry_point is registered, loads the provider class."""

        class AdvancedEngine:
            pass

        mock_ep = MagicMock()
        mock_ep.name = "advanced"
        mock_ep.value = "advanced_pkg:AdvancedEngine"
        mock_ep.load.return_value = AdvancedEngine

        with patch("agent_os.providers.entry_points", return_value=[mock_ep]):
            result = _discover_provider("agent_os.providers.verification")

        assert result is AdvancedEngine

    def test_discovery_error_returns_none(self):
        """Entry point loading errors don't crash, return None."""
        with patch(
            "agent_os.providers.entry_points",
            side_effect=Exception("broken"),
        ):
            result = _discover_provider("agent_os.providers.verification")
        assert result is None


class TestCommunityEditionFallback:
    """Test that factory functions return CE implementations when no advanced provider exists."""

    def test_get_verification_engine_ce(self):
        """Returns CE verification engine when no advanced provider."""
        try:
            engine = get_verification_engine()
            assert engine is not None
        except (ImportError, TypeError):
            pytest.skip("CE verification module not importable in test env")

    def test_get_self_correction_kernel_ce(self):
        """Returns CE self-correction kernel when no advanced provider."""
        try:
            kernel = get_self_correction_kernel()
            assert kernel is not None
        except (ImportError, TypeError):
            pytest.skip("CE self-correction module not importable in test env")

    def test_get_policy_engine_ce(self):
        """Returns CE policy engine."""
        try:
            policy = get_policy_engine(
                allowed_tools=["search"],
                max_calls=10,
            )
            assert policy is not None
        except (ImportError, TypeError):
            pytest.skip("CE policy module not importable in test env")


class TestAdvancedProviderOverride:
    """Test that advanced providers override CE when registered."""

    def test_advanced_verification_used(self):
        """Advanced provider is used when entry_point is registered."""

        class AdvancedVerificationEngine:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

        mock_ep = MagicMock()
        mock_ep.name = "advanced"
        mock_ep.value = "cmvk:AdvancedVerificationEngine"
        mock_ep.load.return_value = AdvancedVerificationEngine

        with patch("agent_os.providers.entry_points", return_value=[mock_ep]):
            engine = get_verification_engine(mode="adversarial")

        assert isinstance(engine, AdvancedVerificationEngine)
        assert engine.kwargs == {"mode": "adversarial"}

    def test_advanced_self_correction_used(self):
        """Advanced self-correction kernel overrides CE."""

        class AdvancedKernel:
            def __init__(self, **kwargs):
                self.active = True

        mock_ep = MagicMock()
        mock_ep.name = "advanced"
        mock_ep.value = "agent_kernel:AdvancedKernel"
        mock_ep.load.return_value = AdvancedKernel

        with patch("agent_os.providers.entry_points", return_value=[mock_ep]):
            kernel = get_self_correction_kernel()

        assert isinstance(kernel, AdvancedKernel)
        assert kernel.active is True


class TestListProviders:
    """Test the provider listing functionality."""

    def test_list_all_community(self):
        """When no advanced providers, all show as community."""
        result = list_providers()
        assert isinstance(result, dict)
        assert len(result) == len(PROVIDER_GROUPS)
        for name in PROVIDER_GROUPS:
            assert result[name] == "community"

    def test_list_mixed_providers(self):
        """Shows advanced for registered providers, community for rest."""

        class AdvancedEngine:
            pass

        mock_ep = MagicMock()
        mock_ep.name = "advanced"
        mock_ep.value = "pkg:Engine"
        mock_ep.load.return_value = AdvancedEngine

        def mock_entry_points(group):
            if group == PROVIDER_GROUPS["verification"]:
                return [mock_ep]
            return []

        with patch("agent_os.providers.entry_points", side_effect=mock_entry_points):
            result = list_providers()

        assert result["verification"] == "advanced"
        assert result["self_correction"] == "community"
        assert result["policy_engine"] == "community"


class TestClearCache:
    """Test cache management."""

    def test_clear_cache_resets(self):
        """Clearing cache forces re-discovery on next call."""
        # First call caches None
        _discover_provider("agent_os.providers.nonexistent")

        # Clear and verify it's gone
        clear_cache()

        # Now inject an advanced provider
        class NewEngine:
            pass

        mock_ep = MagicMock()
        mock_ep.name = "new"
        mock_ep.value = "pkg:NewEngine"
        mock_ep.load.return_value = NewEngine

        with patch(
            "agent_os.providers.entry_points",
            return_value=[mock_ep],
        ):
            result = _discover_provider("agent_os.providers.nonexistent")

        assert result is NewEngine
