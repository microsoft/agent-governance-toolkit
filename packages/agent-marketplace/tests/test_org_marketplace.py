# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for org-scoped marketplace, quality scoring, and per-org MCP policies.

Covers:
  - Issue #733: Org-scoped plugin listing (see global + org plugins, not other orgs)
  - Issue #736: Quality scoring (record scores, badges, overall score)
  - Issue #737: Per-org MCP policy resolution (inherit, merge, cannot un-block)
"""

from __future__ import annotations

import pytest

from agent_marketplace.manifest import PluginManifest, PluginType
from agent_marketplace.marketplace_policy import (
    MCPServerPolicy,
    MarketplacePolicy,
    OrgMarketplacePolicy,
    evaluate_plugin_compliance,
)
from agent_marketplace.quality_scoring import (
    PluginQualityProfile,
    QualityBadge,
    QualityDimension,
    QualityScore,
    QualityStore,
)
from agent_marketplace.registry import PluginRegistry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_manifest(**overrides) -> PluginManifest:
    """Create a PluginManifest with sensible defaults."""
    defaults = {
        "name": "test-plugin",
        "version": "1.0.0",
        "description": "A test plugin",
        "author": "test@example.com",
        "plugin_type": PluginType.INTEGRATION,
    }
    defaults.update(overrides)
    return PluginManifest(**defaults)


# ===========================================================================
# Issue #733 — Org-scoped plugin listing
# ===========================================================================


class TestPluginManifestOrganizationField:
    """PluginManifest.organization field basics."""

    def test_default_organization_is_none(self) -> None:
        manifest = _make_manifest()
        assert manifest.organization is None

    def test_set_organization(self) -> None:
        manifest = _make_manifest(organization="contoso")
        assert manifest.organization == "contoso"

    def test_backward_compatible_serialization(self) -> None:
        """Existing manifests without organization still load fine."""
        data = {
            "name": "legacy-plugin",
            "version": "1.0.0",
            "description": "Legacy",
            "author": "dev@example.com",
            "plugin_type": "integration",
        }
        manifest = PluginManifest(**data)
        assert manifest.organization is None


class TestRegistryListForOrganization:
    """PluginRegistry.list_for_organization visibility rules."""

    def _build_registry(self) -> PluginRegistry:
        registry = PluginRegistry()
        # Global plugins (organization=None)
        registry.register(_make_manifest(name="global-plugin", version="1.0.0"))
        registry.register(_make_manifest(name="global-plugin", version="2.0.0"))
        # Contoso-specific plugins
        registry.register(
            _make_manifest(name="contoso-tool", version="1.0.0", organization="contoso")
        )
        # Fabrikam-specific plugins
        registry.register(
            _make_manifest(name="fabrikam-tool", version="1.0.0", organization="fabrikam")
        )
        return registry

    def test_org_sees_global_and_own_plugins(self) -> None:
        registry = self._build_registry()
        visible = registry.list_for_organization("contoso")
        names = {m.name for m in visible}
        assert "global-plugin" in names
        assert "contoso-tool" in names

    def test_org_does_not_see_other_org_plugins(self) -> None:
        registry = self._build_registry()
        visible = registry.list_for_organization("contoso")
        names = {m.name for m in visible}
        assert "fabrikam-tool" not in names

    def test_all_versions_of_global_plugin_visible(self) -> None:
        registry = self._build_registry()
        visible = registry.list_for_organization("contoso")
        global_versions = [m.version for m in visible if m.name == "global-plugin"]
        assert sorted(global_versions) == ["1.0.0", "2.0.0"]

    def test_unknown_org_sees_only_global(self) -> None:
        registry = self._build_registry()
        visible = registry.list_for_organization("unknown-org")
        names = {m.name for m in visible}
        assert names == {"global-plugin"}


# ===========================================================================
# Issue #733 — OrgMarketplacePolicy & get_effective_policy
# ===========================================================================


class TestOrgMarketplacePolicy:
    """OrgMarketplacePolicy dataclass and MarketplacePolicy.get_effective_policy."""

    def test_org_policy_defaults(self) -> None:
        org = OrgMarketplacePolicy(organization="contoso")
        assert org.organization == "contoso"
        assert org.additional_allowed_plugin_types == []
        assert org.additional_blocked_plugins == []
        assert org.mcp_server_overrides is None

    def test_get_effective_policy_no_org(self) -> None:
        policy = MarketplacePolicy(allowed_plugin_types=["integration"])
        effective = policy.get_effective_policy(None)
        assert effective is policy  # identity — no merge needed

    def test_get_effective_policy_unknown_org(self) -> None:
        policy = MarketplacePolicy(allowed_plugin_types=["integration"])
        effective = policy.get_effective_policy("unknown")
        assert effective is policy

    def test_get_effective_policy_merges_plugin_types(self) -> None:
        policy = MarketplacePolicy(
            allowed_plugin_types=["integration"],
            org_policies={
                "contoso": OrgMarketplacePolicy(
                    organization="contoso",
                    additional_allowed_plugin_types=["agent"],
                ),
            },
        )
        effective = policy.get_effective_policy("contoso")
        assert set(effective.allowed_plugin_types) == {"integration", "agent"}

    def test_get_effective_policy_preserves_signature_requirement(self) -> None:
        policy = MarketplacePolicy(
            require_signature=True,
            org_policies={
                "contoso": OrgMarketplacePolicy(organization="contoso"),
            },
        )
        effective = policy.get_effective_policy("contoso")
        assert effective.require_signature is True


# ===========================================================================
# Issue #736 — Plugin quality scoring
# ===========================================================================


class TestQualityScore:
    """QualityScore dataclass."""

    def test_basic_construction(self) -> None:
        score = QualityScore(
            dimension=QualityDimension.DOCUMENTATION,
            score=0.85,
            evidence="README present",
        )
        assert score.dimension == QualityDimension.DOCUMENTATION
        assert score.score == 0.85
        assert score.evidence == "README present"

    def test_defaults(self) -> None:
        score = QualityScore(dimension=QualityDimension.RELIABILITY, score=0.5)
        assert score.evidence == ""
        assert score.assessed_at == ""


class TestPluginQualityProfile:
    """PluginQualityProfile aggregation."""

    def _make_profile(self, scores: list[tuple[QualityDimension, float]]) -> PluginQualityProfile:
        return PluginQualityProfile(
            plugin_name="test",
            plugin_version="1.0.0",
            scores=[QualityScore(dimension=d, score=s) for d, s in scores],
        )

    def test_overall_score_empty(self) -> None:
        profile = PluginQualityProfile(plugin_name="x", plugin_version="1.0.0")
        assert profile.overall_score == 0.0

    def test_overall_score_average(self) -> None:
        profile = self._make_profile([
            (QualityDimension.DOCUMENTATION, 0.8),
            (QualityDimension.RELIABILITY, 0.6),
        ])
        assert profile.overall_score == pytest.approx(0.7)

    def test_badge_platinum(self) -> None:
        profile = self._make_profile([(QualityDimension.DOCUMENTATION, 0.95)])
        assert profile.badge == QualityBadge.PLATINUM

    def test_badge_gold(self) -> None:
        profile = self._make_profile([(QualityDimension.DOCUMENTATION, 0.80)])
        assert profile.badge == QualityBadge.GOLD

    def test_badge_silver(self) -> None:
        profile = self._make_profile([(QualityDimension.DOCUMENTATION, 0.65)])
        assert profile.badge == QualityBadge.SILVER

    def test_badge_bronze(self) -> None:
        profile = self._make_profile([(QualityDimension.DOCUMENTATION, 0.45)])
        assert profile.badge == QualityBadge.BRONZE

    def test_badge_unrated(self) -> None:
        profile = self._make_profile([(QualityDimension.DOCUMENTATION, 0.2)])
        assert profile.badge == QualityBadge.UNRATED

    def test_badge_unrated_no_scores(self) -> None:
        profile = PluginQualityProfile(plugin_name="x", plugin_version="1.0.0")
        assert profile.badge == QualityBadge.UNRATED

    def test_get_score_existing(self) -> None:
        profile = self._make_profile([(QualityDimension.PERFORMANCE, 0.9)])
        assert profile.get_score(QualityDimension.PERFORMANCE) == 0.9

    def test_get_score_missing(self) -> None:
        profile = self._make_profile([(QualityDimension.PERFORMANCE, 0.9)])
        assert profile.get_score(QualityDimension.TEST_COVERAGE) is None


class TestQualityStore:
    """QualityStore record/retrieve operations."""

    def test_record_and_retrieve(self) -> None:
        store = QualityStore()
        score = QualityScore(dimension=QualityDimension.DOCUMENTATION, score=0.8)
        store.record_score("my-plugin", "1.0.0", score)

        profile = store.get_profile("my-plugin", "1.0.0")
        assert profile is not None
        assert profile.plugin_name == "my-plugin"
        assert len(profile.scores) == 1
        assert profile.scores[0].score == 0.8

    def test_record_updates_existing_dimension(self) -> None:
        store = QualityStore()
        store.record_score(
            "my-plugin", "1.0.0",
            QualityScore(dimension=QualityDimension.DOCUMENTATION, score=0.5),
        )
        store.record_score(
            "my-plugin", "1.0.0",
            QualityScore(dimension=QualityDimension.DOCUMENTATION, score=0.9),
        )
        profile = store.get_profile("my-plugin", "1.0.0")
        assert len(profile.scores) == 1
        assert profile.scores[0].score == 0.9

    def test_record_multiple_dimensions(self) -> None:
        store = QualityStore()
        store.record_score(
            "p", "1.0.0",
            QualityScore(dimension=QualityDimension.DOCUMENTATION, score=0.8),
        )
        store.record_score(
            "p", "1.0.0",
            QualityScore(dimension=QualityDimension.RELIABILITY, score=0.6),
        )
        profile = store.get_profile("p", "1.0.0")
        assert len(profile.scores) == 2
        assert profile.overall_score == pytest.approx(0.7)

    def test_get_badge_unknown_plugin(self) -> None:
        store = QualityStore()
        assert store.get_badge("missing", "1.0.0") == QualityBadge.UNRATED

    def test_get_badge_known_plugin(self) -> None:
        store = QualityStore()
        store.record_score(
            "good-plugin", "1.0.0",
            QualityScore(dimension=QualityDimension.OUTPUT_ACCURACY, score=0.92),
        )
        assert store.get_badge("good-plugin", "1.0.0") == QualityBadge.PLATINUM

    def test_separate_versions_have_separate_profiles(self) -> None:
        store = QualityStore()
        store.record_score(
            "p", "1.0.0",
            QualityScore(dimension=QualityDimension.RELIABILITY, score=0.4),
        )
        store.record_score(
            "p", "2.0.0",
            QualityScore(dimension=QualityDimension.RELIABILITY, score=0.95),
        )
        assert store.get_badge("p", "1.0.0") == QualityBadge.BRONZE
        assert store.get_badge("p", "2.0.0") == QualityBadge.PLATINUM


# ===========================================================================
# Issue #737 — Per-org MCP policy resolution
# ===========================================================================


class TestGetEffectiveMCPPolicy:
    """MarketplacePolicy.get_effective_mcp_policy merge logic."""

    def test_no_org_returns_base(self) -> None:
        base_mcp = MCPServerPolicy(mode="allowlist", allowed=["server-a"])
        policy = MarketplacePolicy(mcp_servers=base_mcp)
        effective = policy.get_effective_mcp_policy(None)
        assert effective is base_mcp

    def test_unknown_org_returns_base(self) -> None:
        base_mcp = MCPServerPolicy(mode="allowlist", allowed=["server-a"])
        policy = MarketplacePolicy(mcp_servers=base_mcp)
        effective = policy.get_effective_mcp_policy("unknown-org")
        assert effective is base_mcp

    # -- Blocklist mode -------------------------------------------------------

    def test_blocklist_org_cannot_unblock_enterprise_blocked(self) -> None:
        """Org-level policy cannot remove servers blocked at enterprise level."""
        policy = MarketplacePolicy(
            mcp_servers=MCPServerPolicy(
                mode="blocklist",
                blocked=["evil-server"],
            ),
            org_mcp_policies={
                "contoso": MCPServerPolicy(
                    mode="blocklist",
                    blocked=[],  # org tries to have no blocks
                    allowed=["evil-server"],  # org tries to allow a blocked server
                ),
            },
        )
        effective = policy.get_effective_mcp_policy("contoso")
        assert "evil-server" in effective.blocked
        assert "evil-server" not in effective.allowed

    def test_blocklist_org_adds_own_blocks(self) -> None:
        """Org can add additional blocked servers."""
        policy = MarketplacePolicy(
            mcp_servers=MCPServerPolicy(mode="blocklist", blocked=["enterprise-bad"]),
            org_mcp_policies={
                "contoso": MCPServerPolicy(
                    mode="blocklist",
                    blocked=["org-bad"],
                ),
            },
        )
        effective = policy.get_effective_mcp_policy("contoso")
        assert "enterprise-bad" in effective.blocked
        assert "org-bad" in effective.blocked

    def test_blocklist_require_declaration_inherits(self) -> None:
        """If base requires declaration, org inherits it."""
        policy = MarketplacePolicy(
            mcp_servers=MCPServerPolicy(
                mode="blocklist", require_declaration=True
            ),
            org_mcp_policies={
                "contoso": MCPServerPolicy(
                    mode="blocklist", require_declaration=False
                ),
            },
        )
        effective = policy.get_effective_mcp_policy("contoso")
        assert effective.require_declaration is True

    # -- Allowlist mode -------------------------------------------------------

    def test_allowlist_org_only_allows_enterprise_approved(self) -> None:
        """Org cannot allow servers not in the enterprise allowlist."""
        policy = MarketplacePolicy(
            mcp_servers=MCPServerPolicy(
                mode="allowlist",
                allowed=["approved-a", "approved-b"],
            ),
            org_mcp_policies={
                "contoso": MCPServerPolicy(
                    mode="allowlist",
                    allowed=["approved-a", "rogue-server"],
                ),
            },
        )
        effective = policy.get_effective_mcp_policy("contoso")
        assert "approved-a" in effective.allowed
        assert "rogue-server" not in effective.allowed

    def test_allowlist_org_inherits_base_when_no_overlap(self) -> None:
        """When org's allowed list has no overlap, fall back to base."""
        policy = MarketplacePolicy(
            mcp_servers=MCPServerPolicy(
                mode="allowlist",
                allowed=["server-a"],
            ),
            org_mcp_policies={
                "contoso": MCPServerPolicy(
                    mode="allowlist",
                    allowed=["server-z"],  # not in base
                ),
            },
        )
        effective = policy.get_effective_mcp_policy("contoso")
        # Falls back to base.allowed since intersection is empty
        assert "server-a" in effective.allowed

    def test_allowlist_org_adds_blocks(self) -> None:
        """Org can add blocked servers even in allowlist mode."""
        policy = MarketplacePolicy(
            mcp_servers=MCPServerPolicy(mode="allowlist", allowed=["server-a"]),
            org_mcp_policies={
                "contoso": MCPServerPolicy(
                    mode="allowlist",
                    blocked=["org-blocked"],
                ),
            },
        )
        effective = policy.get_effective_mcp_policy("contoso")
        assert "org-blocked" in effective.blocked


# ===========================================================================
# Issue #737 — evaluate_plugin_compliance with organization
# ===========================================================================


class TestEvaluatePluginComplianceWithOrg:
    """evaluate_plugin_compliance respects per-org MCP policies."""

    def test_org_blocked_server_rejected(self) -> None:
        manifest = _make_manifest()
        policy = MarketplacePolicy(
            mcp_servers=MCPServerPolicy(mode="blocklist", blocked=["enterprise-bad"]),
            org_mcp_policies={
                "contoso": MCPServerPolicy(mode="blocklist", blocked=["org-bad"]),
            },
        )
        result = evaluate_plugin_compliance(
            manifest, policy, mcp_servers=["org-bad"], organization="contoso"
        )
        assert result.compliant is False
        assert any("blocked" in v for v in result.violations)

    def test_base_blocked_server_rejected_via_org(self) -> None:
        manifest = _make_manifest()
        policy = MarketplacePolicy(
            mcp_servers=MCPServerPolicy(mode="blocklist", blocked=["enterprise-bad"]),
            org_mcp_policies={
                "contoso": MCPServerPolicy(mode="blocklist", blocked=[]),
            },
        )
        result = evaluate_plugin_compliance(
            manifest, policy, mcp_servers=["enterprise-bad"], organization="contoso"
        )
        assert result.compliant is False

    def test_compliant_server_with_org(self) -> None:
        manifest = _make_manifest()
        policy = MarketplacePolicy(
            mcp_servers=MCPServerPolicy(mode="blocklist", blocked=["enterprise-bad"]),
            org_mcp_policies={
                "contoso": MCPServerPolicy(mode="blocklist", blocked=["org-bad"]),
            },
        )
        result = evaluate_plugin_compliance(
            manifest, policy, mcp_servers=["good-server"], organization="contoso"
        )
        assert result.compliant is True

    def test_without_org_uses_base_policy(self) -> None:
        manifest = _make_manifest()
        policy = MarketplacePolicy(
            mcp_servers=MCPServerPolicy(
                mode="allowlist", allowed=["approved"]
            ),
        )
        result = evaluate_plugin_compliance(
            manifest, policy, mcp_servers=["approved"], organization=None
        )
        assert result.compliant is True


# ===========================================================================
# Top-level import smoke test
# ===========================================================================


def test_new_symbols_importable():
    """New public symbols are importable from the top-level package."""
    from agent_marketplace import (
        OrgMarketplacePolicy,
        PluginQualityProfile,
        QualityBadge,
        QualityDimension,
        QualityScore,
        QualityStore,
    )

    assert OrgMarketplacePolicy is not None
    assert PluginQualityProfile is not None
    assert QualityBadge is not None
    assert QualityDimension is not None
    assert QualityScore is not None
    assert QualityStore is not None
