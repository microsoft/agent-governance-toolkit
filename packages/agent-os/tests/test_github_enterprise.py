# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Tests for GitHub Enterprise managed policy and ruleset integration (issue #735)."""

from __future__ import annotations

import pytest

from agent_os.github_enterprise import (
    EnterpriseGovernanceManager,
    EnterpriseGovernancePolicy,
    GovernanceTier,
    RulesetConfig,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_policy(
    name: str,
    tiers: list[GovernanceTier],
    ruleset_names: list[str] | None = None,
) -> EnterpriseGovernancePolicy:
    """Create a policy with optional rulesets for testing."""
    rulesets = [RulesetConfig(name=n) for n in (ruleset_names or [])]
    return EnterpriseGovernancePolicy(
        name=name,
        applicable_tiers=tiers,
        rulesets=rulesets,
    )


# ---------------------------------------------------------------------------
# Issue #735: GitHub Enterprise governance integration
# ---------------------------------------------------------------------------


class TestSetGetRepoTier:
    """Tests for setting and getting repo governance tiers."""

    def test_set_and_get_tier(self) -> None:
        mgr = EnterpriseGovernanceManager()
        mgr.set_repo_tier("org/repo-a", GovernanceTier.CRITICAL)
        assert mgr.get_repo_tier("org/repo-a") == GovernanceTier.CRITICAL

    def test_default_tier_is_unclassified(self) -> None:
        mgr = EnterpriseGovernanceManager()
        assert mgr.get_repo_tier("org/unknown") == GovernanceTier.UNCLASSIFIED

    def test_update_tier(self) -> None:
        mgr = EnterpriseGovernanceManager()
        mgr.set_repo_tier("org/repo-b", GovernanceTier.BASIC)
        mgr.set_repo_tier("org/repo-b", GovernanceTier.ELEVATED)
        assert mgr.get_repo_tier("org/repo-b") == GovernanceTier.ELEVATED

    def test_multiple_repos_independent(self) -> None:
        mgr = EnterpriseGovernanceManager()
        mgr.set_repo_tier("org/alpha", GovernanceTier.STANDARD)
        mgr.set_repo_tier("org/beta", GovernanceTier.CRITICAL)
        assert mgr.get_repo_tier("org/alpha") == GovernanceTier.STANDARD
        assert mgr.get_repo_tier("org/beta") == GovernanceTier.CRITICAL


class TestApplicablePoliciesByTier:
    """Tests for getting applicable policies based on repo tier."""

    def test_policy_matches_tier(self) -> None:
        mgr = EnterpriseGovernanceManager()
        policy = _make_policy("p1", [GovernanceTier.CRITICAL])
        mgr.add_policy(policy)
        mgr.set_repo_tier("org/repo", GovernanceTier.CRITICAL)
        assert mgr.get_applicable_policies("org/repo") == [policy]

    def test_policy_does_not_match_other_tier(self) -> None:
        mgr = EnterpriseGovernanceManager()
        policy = _make_policy("p1", [GovernanceTier.CRITICAL])
        mgr.add_policy(policy)
        mgr.set_repo_tier("org/repo", GovernanceTier.BASIC)
        assert mgr.get_applicable_policies("org/repo") == []

    def test_multiple_policies_same_tier(self) -> None:
        mgr = EnterpriseGovernanceManager()
        p1 = _make_policy("p1", [GovernanceTier.ELEVATED])
        p2 = _make_policy("p2", [GovernanceTier.ELEVATED])
        mgr.add_policy(p1)
        mgr.add_policy(p2)
        mgr.set_repo_tier("org/repo", GovernanceTier.ELEVATED)
        result = mgr.get_applicable_policies("org/repo")
        assert len(result) == 2
        assert p1 in result
        assert p2 in result

    def test_policy_applicable_to_multiple_tiers(self) -> None:
        mgr = EnterpriseGovernanceManager()
        policy = _make_policy(
            "wide-policy",
            [GovernanceTier.STANDARD, GovernanceTier.ELEVATED, GovernanceTier.CRITICAL],
        )
        mgr.add_policy(policy)
        mgr.set_repo_tier("org/std", GovernanceTier.STANDARD)
        mgr.set_repo_tier("org/elev", GovernanceTier.ELEVATED)
        mgr.set_repo_tier("org/basic", GovernanceTier.BASIC)
        assert mgr.get_applicable_policies("org/std") == [policy]
        assert mgr.get_applicable_policies("org/elev") == [policy]
        assert mgr.get_applicable_policies("org/basic") == []


class TestRequiredRulesets:
    """Tests for required rulesets aggregation."""

    def test_rulesets_from_single_policy(self) -> None:
        mgr = EnterpriseGovernanceManager()
        mgr.add_policy(_make_policy(
            "p1",
            [GovernanceTier.CRITICAL],
            ruleset_names=["branch-protection", "code-review"],
        ))
        mgr.set_repo_tier("org/repo", GovernanceTier.CRITICAL)
        rulesets = mgr.get_required_rulesets("org/repo")
        names = [r.name for r in rulesets]
        assert "branch-protection" in names
        assert "code-review" in names

    def test_rulesets_aggregated_across_policies(self) -> None:
        mgr = EnterpriseGovernanceManager()
        mgr.add_policy(_make_policy(
            "p1", [GovernanceTier.ELEVATED], ruleset_names=["signed-commits"],
        ))
        mgr.add_policy(_make_policy(
            "p2", [GovernanceTier.ELEVATED], ruleset_names=["status-checks"],
        ))
        mgr.set_repo_tier("org/repo", GovernanceTier.ELEVATED)
        rulesets = mgr.get_required_rulesets("org/repo")
        names = [r.name for r in rulesets]
        assert "signed-commits" in names
        assert "status-checks" in names

    def test_no_rulesets_for_non_matching_tier(self) -> None:
        mgr = EnterpriseGovernanceManager()
        mgr.add_policy(_make_policy(
            "p1", [GovernanceTier.CRITICAL], ruleset_names=["branch-protection"],
        ))
        mgr.set_repo_tier("org/repo", GovernanceTier.BASIC)
        assert mgr.get_required_rulesets("org/repo") == []


class TestAuditCompliance:
    """Tests for audit_repo_compliance (compliant + non-compliant)."""

    def test_compliant_when_all_rulesets_active(self) -> None:
        mgr = EnterpriseGovernanceManager()
        mgr.add_policy(_make_policy(
            "p1", [GovernanceTier.CRITICAL],
            ruleset_names=["branch-protection", "code-review"],
        ))
        mgr.set_repo_tier("org/repo", GovernanceTier.CRITICAL)
        result = mgr.audit_repo_compliance(
            "org/repo",
            active_rulesets=["branch-protection", "code-review"],
        )
        assert result["compliant"] is True
        assert result["missing_rulesets"] == []
        assert result["tier"] == "critical"

    def test_non_compliant_when_ruleset_missing(self) -> None:
        mgr = EnterpriseGovernanceManager()
        mgr.add_policy(_make_policy(
            "p1", [GovernanceTier.CRITICAL],
            ruleset_names=["branch-protection", "code-review"],
        ))
        mgr.set_repo_tier("org/repo", GovernanceTier.CRITICAL)
        result = mgr.audit_repo_compliance(
            "org/repo",
            active_rulesets=["branch-protection"],
        )
        assert result["compliant"] is False
        assert "code-review" in result["missing_rulesets"]

    def test_extra_rulesets_reported(self) -> None:
        mgr = EnterpriseGovernanceManager()
        mgr.add_policy(_make_policy(
            "p1", [GovernanceTier.STANDARD], ruleset_names=["status-checks"],
        ))
        mgr.set_repo_tier("org/repo", GovernanceTier.STANDARD)
        result = mgr.audit_repo_compliance(
            "org/repo",
            active_rulesets=["status-checks", "custom-lint"],
        )
        assert result["compliant"] is True
        assert "custom-lint" in result["extra_rulesets"]

    def test_compliance_with_no_active_rulesets(self) -> None:
        mgr = EnterpriseGovernanceManager()
        mgr.add_policy(_make_policy(
            "p1", [GovernanceTier.ELEVATED], ruleset_names=["signed-commits"],
        ))
        mgr.set_repo_tier("org/repo", GovernanceTier.ELEVATED)
        result = mgr.audit_repo_compliance("org/repo", active_rulesets=[])
        assert result["compliant"] is False
        assert "signed-commits" in result["missing_rulesets"]

    def test_audit_result_structure(self) -> None:
        mgr = EnterpriseGovernanceManager()
        mgr.add_policy(_make_policy(
            "p1", [GovernanceTier.BASIC], ruleset_names=["r1"],
        ))
        mgr.set_repo_tier("org/repo", GovernanceTier.BASIC)
        result = mgr.audit_repo_compliance("org/repo", active_rulesets=["r1"])
        expected_keys = {
            "repo", "tier", "compliant",
            "required_rulesets", "active_rulesets",
            "missing_rulesets", "extra_rulesets",
        }
        assert set(result.keys()) == expected_keys
        assert result["repo"] == "org/repo"
        assert result["tier"] == "basic"


class TestUnclassifiedRepos:
    """Tests that unclassified repos get no policies."""

    def test_unclassified_repo_no_policies(self) -> None:
        mgr = EnterpriseGovernanceManager()
        mgr.add_policy(_make_policy("p1", [GovernanceTier.CRITICAL]))
        mgr.add_policy(_make_policy("p2", [GovernanceTier.STANDARD]))
        mgr.add_policy(_make_policy("p3", [GovernanceTier.BASIC]))
        # repo not set — defaults to UNCLASSIFIED
        assert mgr.get_applicable_policies("org/new-repo") == []
        assert mgr.get_required_rulesets("org/new-repo") == []

    def test_unclassified_repo_is_compliant_with_no_requirements(self) -> None:
        mgr = EnterpriseGovernanceManager()
        mgr.add_policy(_make_policy(
            "p1", [GovernanceTier.CRITICAL], ruleset_names=["r1"],
        ))
        result = mgr.audit_repo_compliance("org/new-repo", active_rulesets=[])
        assert result["compliant"] is True
        assert result["tier"] == "unclassified"
        assert result["required_rulesets"] == []

    def test_policy_explicitly_targeting_unclassified(self) -> None:
        mgr = EnterpriseGovernanceManager()
        policy = _make_policy(
            "catch-all", [GovernanceTier.UNCLASSIFIED],
            ruleset_names=["basic-protection"],
        )
        mgr.add_policy(policy)
        result = mgr.get_applicable_policies("org/new-repo")
        assert result == [policy]
