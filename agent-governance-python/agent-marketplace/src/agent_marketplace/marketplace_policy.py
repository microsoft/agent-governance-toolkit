# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Marketplace Policy Enforcement

Defines marketplace-level policies for MCP server allowlist/blocklist
enforcement, plugin type restrictions, and signature requirements.
Operators can declare which MCP servers are permitted for plugins.
Supports organization-scoped policy overrides (Issues #733, #737).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, Field, field_validator

from agent_marketplace.exceptions import MarketplaceError
from agent_marketplace.manifest import PluginManifest

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Policy models
# ---------------------------------------------------------------------------


class MCPServerPolicy(BaseModel):
    """Controls which MCP servers plugins are allowed to use."""

    mode: str = Field(
        "allowlist",
        description="Enforcement mode: 'allowlist' or 'blocklist'",
    )
    allowed: list[str] = Field(
        default_factory=list,
        description="Allowed MCP server names (when mode=allowlist)",
    )
    blocked: list[str] = Field(
        default_factory=list,
        description="Blocked MCP server names (when mode=blocklist)",
    )
    require_declaration: bool = Field(
        False,
        description="Plugins must declare all MCP servers they use",
    )

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        if v not in ("allowlist", "blocklist"):
            raise MarketplaceError(
                f"Invalid MCP server policy mode: {v} (expected 'allowlist' or 'blocklist')"
            )
        return v


@dataclass
class OrgMarketplacePolicy:
    """Organization-scoped marketplace policy that inherits from enterprise base."""

    organization: str
    additional_allowed_plugin_types: list[str] = field(default_factory=list)
    additional_blocked_plugins: list[str] = field(default_factory=list)
    mcp_server_overrides: MCPServerPolicy | None = None


class MarketplacePolicy(BaseModel):
    """Top-level marketplace policy controlling plugin admission."""

    mcp_servers: MCPServerPolicy = Field(
        default_factory=MCPServerPolicy,
        description="MCP server allowlist/blocklist policy",
    )
    allowed_plugin_types: Optional[list[str]] = Field(
        None,
        description="Restrict which plugin types may be registered",
    )
    require_signature: bool = Field(
        False,
        description="Require Ed25519 signatures on all plugins",
    )
    org_policies: dict[str, OrgMarketplacePolicy] = Field(
        default_factory=dict,
        description="Organization-scoped policy overrides keyed by org name",
    )
    org_mcp_policies: dict[str, MCPServerPolicy] = Field(
        default_factory=dict,
        description="Per-organization MCP server policy overrides",
    )

    def get_effective_policy(self, organization: str | None = None) -> MarketplacePolicy:
        """Resolve effective policy for an organization (base + org overrides).

        When *organization* is ``None`` or the org has no overrides, the base
        enterprise policy is returned unchanged.  Otherwise the base policy is
        merged with the org-specific additions.
        """
        if organization is None or organization not in self.org_policies:
            return self

        org = self.org_policies[organization]

        # Merge allowed plugin types: base + org additions
        merged_types = self.allowed_plugin_types
        if merged_types is not None and org.additional_allowed_plugin_types:
            merged_types = list(set(merged_types + org.additional_allowed_plugin_types))

        # Merge MCP server policy if org has overrides
        merged_mcp = org.mcp_server_overrides if org.mcp_server_overrides else self.mcp_servers

        return MarketplacePolicy(
            mcp_servers=merged_mcp,
            allowed_plugin_types=merged_types,
            require_signature=self.require_signature,
        )

    def get_effective_mcp_policy(self, organization: str | None = None) -> MCPServerPolicy:
        """Get effective MCP server policy for an organization.

        Org policies inherit from the base (enterprise) MCP policy.
        Org can add to allowlist but cannot remove base restrictions.
        """
        base = self.mcp_servers
        if organization is None or organization not in self.org_mcp_policies:
            return base
        org = self.org_mcp_policies[organization]
        # Merge: org inherits base restrictions, can add more allowed servers
        if base.mode == "blocklist":
            # Org cannot un-block servers blocked at enterprise level
            merged_blocked = list(set(base.blocked + org.blocked))
            merged_allowed = [s for s in org.allowed if s not in base.blocked]
            return MCPServerPolicy(
                mode=base.mode,
                blocked=merged_blocked,
                allowed=merged_allowed,
                require_declaration=base.require_declaration or org.require_declaration,
            )
        else:  # allowlist
            # Org can only allow servers already in the enterprise allowlist
            merged_allowed = (
                [s for s in org.allowed if s in base.allowed] if base.allowed else org.allowed
            )
            return MCPServerPolicy(
                mode=base.mode,
                allowed=merged_allowed or base.allowed,
                blocked=list(set(base.blocked + org.blocked)),
                require_declaration=base.require_declaration or org.require_declaration,
            )


class ComplianceResult(BaseModel):
    """Result of evaluating a plugin against a marketplace policy."""

    compliant: bool = Field(..., description="Whether the plugin is compliant")
    violations: list[str] = Field(
        default_factory=list,
        description="Human-readable violation descriptions",
    )


# ---------------------------------------------------------------------------
# Policy loading
# ---------------------------------------------------------------------------


def load_marketplace_policy(path: Path) -> MarketplacePolicy:
    """Load a marketplace policy from a YAML file.

    Args:
        path: Path to the policy YAML file.

    Returns:
        Parsed MarketplacePolicy.

    Raises:
        MarketplaceError: If the file is missing or invalid.
    """
    if not path.exists():
        raise MarketplaceError(f"Marketplace policy file not found: {path}")
    try:
        with open(path) as f:
            data = yaml.safe_load(f)
        if not isinstance(data, dict):
            raise MarketplaceError("Marketplace policy must be a YAML mapping")
        return MarketplacePolicy(**data)
    except MarketplaceError:
        raise
    except Exception as exc:
        raise MarketplaceError(f"Failed to load marketplace policy: {exc}") from exc


# ---------------------------------------------------------------------------
# Compliance evaluation
# ---------------------------------------------------------------------------


def evaluate_plugin_compliance(
    manifest: PluginManifest,
    policy: MarketplacePolicy,
    mcp_servers: list[str] | None = None,
    organization: str | None = None,
) -> ComplianceResult:
    """Check whether a plugin manifest complies with a marketplace policy.

    Args:
        manifest: The plugin manifest to evaluate.
        policy: The marketplace policy to enforce.
        mcp_servers: Optional list of MCP server names declared by the plugin.
            When ``None``, MCP declaration checks that require a server list
            will flag a violation if ``require_declaration`` is enabled.
        organization: Optional organization name.  When provided the
            effective MCP policy is resolved via
            :meth:`MarketplacePolicy.get_effective_mcp_policy`.

    Returns:
        A :class:`ComplianceResult` indicating compliance status and any
        violations.
    """
    violations: list[str] = []

    # -- Signature requirement ------------------------------------------------
    if policy.require_signature and not manifest.signature:
        violations.append(
            f"Plugin '{manifest.name}' must be signed (Ed25519 signature required)"
        )

    # -- Plugin type restriction ----------------------------------------------
    if policy.allowed_plugin_types is not None:
        if manifest.plugin_type.value not in policy.allowed_plugin_types:
            violations.append(
                f"Plugin type '{manifest.plugin_type.value}' is not allowed "
                f"(allowed: {', '.join(policy.allowed_plugin_types)})"
            )

    # -- MCP server policy (org-aware) ----------------------------------------
    mcp_policy = policy.get_effective_mcp_policy(organization)

    if mcp_policy.require_declaration and mcp_servers is None:
        violations.append(
            f"Plugin '{manifest.name}' must declare its MCP servers"
        )

    if mcp_servers is not None:
        if mcp_policy.mode == "allowlist" and mcp_policy.allowed:
            disallowed = [s for s in mcp_servers if s not in mcp_policy.allowed]
            if disallowed:
                violations.append(
                    f"MCP servers not in allowlist: {', '.join(disallowed)}"
                )

        if mcp_policy.mode == "blocklist" and mcp_policy.blocked:
            blocked_found = [s for s in mcp_servers if s in mcp_policy.blocked]
            if blocked_found:
                violations.append(
                    f"MCP servers are blocked: {', '.join(blocked_found)}"
                )

    return ComplianceResult(
        compliant=len(violations) == 0,
        violations=violations,
    )
