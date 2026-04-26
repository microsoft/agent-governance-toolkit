# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for plugin trust tiers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from agent_marketplace.manifest import PluginManifest, PluginType
from agent_marketplace.trust_tiers import (
    DEFAULT_TIER_CONFIGS,
    TRUST_TIERS,
    PluginTrustConfig,
    PluginTrustStore,
    compute_initial_score,
    filter_capabilities,
    get_tier_config,
    get_trust_tier,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_manifest(**overrides) -> PluginManifest:
    """Create a PluginManifest with sensible defaults."""
    defaults = {
        "name": "test-plugin",
        "version": "1.0.0",
        "description": "A test plugin for evaluation",
        "author": "test@example.com",
        "plugin_type": PluginType.INTEGRATION,
    }
    defaults.update(overrides)
    return PluginManifest(**defaults)


# ---------------------------------------------------------------------------
# Trust tier resolution
# ---------------------------------------------------------------------------


class TestGetTrustTier:
    """Tests for get_trust_tier()."""

    def test_revoked_lower_bound(self) -> None:
        assert get_trust_tier(0) == "revoked"

    def test_revoked_upper_bound(self) -> None:
        assert get_trust_tier(299) == "revoked"

    def test_probationary_lower_bound(self) -> None:
        assert get_trust_tier(300) == "probationary"

    def test_probationary_upper_bound(self) -> None:
        assert get_trust_tier(499) == "probationary"

    def test_standard_lower_bound(self) -> None:
        assert get_trust_tier(500) == "standard"

    def test_standard_upper_bound(self) -> None:
        assert get_trust_tier(699) == "standard"

    def test_trusted_lower_bound(self) -> None:
        assert get_trust_tier(700) == "trusted"

    def test_trusted_upper_bound(self) -> None:
        assert get_trust_tier(899) == "trusted"

    def test_verified_lower_bound(self) -> None:
        assert get_trust_tier(900) == "verified"

    def test_verified_upper_bound(self) -> None:
        assert get_trust_tier(1000) == "verified"

    def test_negative_score_raises(self) -> None:
        with pytest.raises(ValueError, match="between 0 and 1000"):
            get_trust_tier(-1)

    def test_over_max_score_raises(self) -> None:
        with pytest.raises(ValueError, match="between 0 and 1000"):
            get_trust_tier(1001)


# ---------------------------------------------------------------------------
# Tier config
# ---------------------------------------------------------------------------


class TestGetTierConfig:
    """Tests for get_tier_config()."""

    def test_all_tiers_have_configs(self) -> None:
        for tier in TRUST_TIERS:
            config = get_tier_config(tier)
            assert isinstance(config, PluginTrustConfig)

    def test_revoked_has_zero_budget(self) -> None:
        config = get_tier_config("revoked")
        assert config.max_token_budget == 0
        assert config.max_tool_calls == 0
        assert config.allowed_tool_access == "read-only"

    def test_verified_has_full_access(self) -> None:
        config = get_tier_config("verified")
        assert config.allowed_tool_access == "full"
        assert config.max_token_budget > 0

    def test_budget_increases_with_tier(self) -> None:
        budgets = [get_tier_config(t).max_token_budget for t in TRUST_TIERS]
        assert budgets == sorted(budgets)

    def test_unknown_tier_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown trust tier"):
            get_tier_config("nonexistent")


# ---------------------------------------------------------------------------
# Capability filtering
# ---------------------------------------------------------------------------


class TestFilterCapabilities:
    """Tests for filter_capabilities()."""

    def test_standard_allows_network(self) -> None:
        caps = filter_capabilities(["network", "admin"], "standard")
        assert "network" in caps
        assert "admin" not in caps

    def test_verified_allows_all(self) -> None:
        caps = filter_capabilities(["network", "filesystem", "execute", "admin"], "verified")
        assert caps == ["network", "filesystem", "execute", "admin"]

    def test_revoked_strips_restricted(self) -> None:
        caps = filter_capabilities(["network", "execute"], "revoked")
        assert caps == []

    def test_unknown_capabilities_pass_through(self) -> None:
        caps = filter_capabilities(["custom-cap", "another"], "probationary")
        assert caps == ["custom-cap", "another"]

    def test_empty_capabilities(self) -> None:
        assert filter_capabilities([], "trusted") == []

    def test_unknown_tier_raises(self) -> None:
        with pytest.raises(ValueError, match="Unknown trust tier"):
            filter_capabilities(["network"], "bogus")


# ---------------------------------------------------------------------------
# Initial score computation
# ---------------------------------------------------------------------------


class TestComputeInitialScore:
    """Tests for compute_initial_score()."""

    def test_base_score_unsigned_no_caps(self) -> None:
        manifest = _make_manifest()
        score = compute_initial_score(manifest)
        assert score == 500

    def test_signed_plugin_bonus(self) -> None:
        manifest = _make_manifest(signature="abc123")
        score = compute_initial_score(manifest)
        assert score == 600  # 500 + 100

    def test_capabilities_bonus(self) -> None:
        manifest = _make_manifest(capabilities=["cap-a"])
        score = compute_initial_score(manifest)
        assert score == 550  # 500 + 50

    def test_short_description_penalty(self) -> None:
        manifest = _make_manifest(description="Hi")
        score = compute_initial_score(manifest)
        assert score == 450  # 500 - 50

    def test_all_bonuses_combined(self) -> None:
        manifest = _make_manifest(
            signature="sig",
            capabilities=["cap-a", "cap-b"],
            description="A well-described plugin for governance",
        )
        score = compute_initial_score(manifest)
        assert score == 650  # 500 + 100 + 50

    def test_score_clamped_to_max(self) -> None:
        # Even with all bonuses, score should not exceed 1000
        manifest = _make_manifest(
            signature="sig",
            capabilities=["cap"],
        )
        score = compute_initial_score(manifest)
        assert 0 <= score <= 1000


# ---------------------------------------------------------------------------
# PluginTrustStore
# ---------------------------------------------------------------------------


class TestPluginTrustStore:
    """Tests for PluginTrustStore."""

    def test_default_score(self, tmp_path: Path) -> None:
        store = PluginTrustStore(store_path=tmp_path / "trust.json")
        assert store.get_score("unknown-plugin") == 500

    def test_set_and_get_score(self, tmp_path: Path) -> None:
        store = PluginTrustStore(store_path=tmp_path / "trust.json")
        store.set_score("my-plugin", 750)
        assert store.get_score("my-plugin") == 750

    def test_score_clamped_low(self, tmp_path: Path) -> None:
        store = PluginTrustStore(store_path=tmp_path / "trust.json")
        store.set_score("my-plugin", -100)
        assert store.get_score("my-plugin") == 0

    def test_score_clamped_high(self, tmp_path: Path) -> None:
        store = PluginTrustStore(store_path=tmp_path / "trust.json")
        store.set_score("my-plugin", 9999)
        assert store.get_score("my-plugin") == 1000

    def test_record_event_adjusts_score(self, tmp_path: Path) -> None:
        store = PluginTrustStore(store_path=tmp_path / "trust.json")
        store.set_score("my-plugin", 600)
        store.record_event("my-plugin", "policy_violation", -50)
        assert store.get_score("my-plugin") == 550

    def test_record_event_positive_delta(self, tmp_path: Path) -> None:
        store = PluginTrustStore(store_path=tmp_path / "trust.json")
        store.set_score("my-plugin", 400)
        store.record_event("my-plugin", "successful_audit", 100)
        assert store.get_score("my-plugin") == 500

    def test_record_event_clamps(self, tmp_path: Path) -> None:
        store = PluginTrustStore(store_path=tmp_path / "trust.json")
        store.set_score("my-plugin", 50)
        store.record_event("my-plugin", "critical_failure", -200)
        assert store.get_score("my-plugin") == 0

    def test_get_tier(self, tmp_path: Path) -> None:
        store = PluginTrustStore(store_path=tmp_path / "trust.json")
        store.set_score("my-plugin", 750)
        assert store.get_tier("my-plugin") == "trusted"

    def test_persistence_survives_reload(self, tmp_path: Path) -> None:
        path = tmp_path / "trust.json"
        store = PluginTrustStore(store_path=path)
        store.set_score("my-plugin", 800)
        store.record_event("my-plugin", "audit", 50)

        # Reload from disk
        store2 = PluginTrustStore(store_path=path)
        assert store2.get_score("my-plugin") == 850
        assert store2.get_tier("my-plugin") == "trusted"

    def test_corrupt_store_resets(self, tmp_path: Path) -> None:
        path = tmp_path / "trust.json"
        path.write_text("NOT VALID JSON", encoding="utf-8")

        store = PluginTrustStore(store_path=path)
        assert store.get_score("any") == 500

    def test_events_recorded_in_store(self, tmp_path: Path) -> None:
        path = tmp_path / "trust.json"
        store = PluginTrustStore(store_path=path)
        store.record_event("my-plugin", "install_success", 10)

        with open(path) as f:
            data = json.load(f)
        events = data["events"]["my-plugin"]
        assert len(events) == 1
        assert events[0]["event"] == "install_success"
        assert events[0]["delta"] == 10


# ---------------------------------------------------------------------------
# CLI trust command
# ---------------------------------------------------------------------------


class TestTrustCLICommand:
    """Tests for the 'plugin trust' CLI command."""

    def test_trust_command_default_score(self, tmp_path: Path) -> None:
        """Trust command shows default score for unknown plugin."""
        from agent_marketplace.cli_commands import plugin

        runner = CliRunner()
        result = runner.invoke(
            plugin,
            ["trust", "unknown-plugin", "--store", str(tmp_path / "trust.json")],
        )

        assert result.exit_code == 0
        assert "unknown-plugin" in result.output
        assert "500" in result.output
        assert "standard" in result.output

    def test_trust_command_with_existing_score(self, tmp_path: Path) -> None:
        """Trust command shows correct tier for a stored score."""
        store_path = tmp_path / "trust.json"
        store = PluginTrustStore(store_path=store_path)
        store.set_score("my-plugin", 900)

        from agent_marketplace.cli_commands import plugin

        runner = CliRunner()
        result = runner.invoke(
            plugin,
            ["trust", "my-plugin", "--store", str(store_path)],
        )

        assert result.exit_code == 0
        assert "my-plugin" in result.output
        assert "900" in result.output
        assert "verified" in result.output


# ---------------------------------------------------------------------------
# Top-level import smoke test
# ---------------------------------------------------------------------------


def test_trust_tier_imports():
    """Trust tier symbols are importable from the top-level package."""
    from agent_marketplace import (
        DEFAULT_TIER_CONFIGS,
        TRUST_TIERS,
        PluginTrustConfig,
        PluginTrustStore,
        compute_initial_score,
        filter_capabilities,
        get_tier_config,
        get_trust_tier,
    )

    assert TRUST_TIERS is not None
    assert DEFAULT_TIER_CONFIGS is not None
    assert PluginTrustConfig is not None
    assert PluginTrustStore is not None
    assert callable(compute_initial_score)
    assert callable(filter_capabilities)
    assert callable(get_tier_config)
    assert callable(get_trust_tier)
