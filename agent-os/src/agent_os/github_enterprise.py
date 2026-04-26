# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""GitHub Enterprise managed policy and ruleset integration.

Provides integration points for GitHub Enterprise features:
- Repository rulesets for governance enforcement
- Custom properties for repo governance tier tagging
- Enterprise-level policy templates
"""
from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class GovernanceTier(str, Enum):
    """Repository governance tier assigned via GitHub custom properties."""
    UNCLASSIFIED = "unclassified"
    BASIC = "basic"
    STANDARD = "standard"
    ELEVATED = "elevated"
    CRITICAL = "critical"


@dataclass
class RulesetConfig:
    """Configuration for a GitHub repository ruleset."""
    name: str
    enforcement: str = "active"  # active, evaluate, disabled
    target: str = "branch"  # branch, tag, push
    conditions: dict[str, Any] = field(default_factory=dict)
    rules: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class EnterpriseGovernancePolicy:
    """Enterprise-level governance policy template.

    Defines rulesets and custom properties that should be applied
    to repositories based on their governance tier.
    """
    name: str
    description: str = ""
    applicable_tiers: list[GovernanceTier] = field(default_factory=list)
    rulesets: list[RulesetConfig] = field(default_factory=list)
    required_custom_properties: dict[str, str] = field(default_factory=dict)


class EnterpriseGovernanceManager:
    """Manages GitHub Enterprise governance policies and rulesets.

    Maps governance tiers to repository rulesets and enforces
    enterprise-level policy templates across org repos.
    """

    def __init__(self) -> None:
        self._policies: list[EnterpriseGovernancePolicy] = []
        self._repo_tiers: dict[str, GovernanceTier] = {}

    def add_policy(self, policy: EnterpriseGovernancePolicy) -> None:
        self._policies.append(policy)

    def set_repo_tier(self, repo: str, tier: GovernanceTier) -> None:
        self._repo_tiers[repo] = tier

    def get_repo_tier(self, repo: str) -> GovernanceTier:
        return self._repo_tiers.get(repo, GovernanceTier.UNCLASSIFIED)

    def get_applicable_policies(self, repo: str) -> list[EnterpriseGovernancePolicy]:
        """Get all policies applicable to a repo based on its tier."""
        tier = self.get_repo_tier(repo)
        return [p for p in self._policies if tier in p.applicable_tiers]

    def get_required_rulesets(self, repo: str) -> list[RulesetConfig]:
        """Get all rulesets that should be applied to a repo."""
        rulesets = []
        for policy in self.get_applicable_policies(repo):
            rulesets.extend(policy.rulesets)
        return rulesets

    def audit_repo_compliance(self, repo: str, active_rulesets: list[str]) -> dict[str, Any]:
        """Audit a repo's compliance with its governance tier requirements."""
        required = self.get_required_rulesets(repo)
        required_names = {r.name for r in required}
        active_set = set(active_rulesets)
        missing = required_names - active_set
        extra = active_set - required_names
        return {
            "repo": repo,
            "tier": self.get_repo_tier(repo).value,
            "compliant": len(missing) == 0,
            "required_rulesets": sorted(required_names),
            "active_rulesets": sorted(active_set),
            "missing_rulesets": sorted(missing),
            "extra_rulesets": sorted(extra),
        }
