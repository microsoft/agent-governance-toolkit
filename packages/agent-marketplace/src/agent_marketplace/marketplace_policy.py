# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Marketplace Policy Enforcement

Defines marketplace-level policies for MCP server allowlist/blocklist
enforcement, plugin type restrictions, and signature requirements.
Operators can declare which MCP servers are permitted for plugins.
"""

from __future__ import annotations

import logging
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
) -> ComplianceResult:
    """Check whether a plugin manifest complies with a marketplace policy.

    Args:
        manifest: The plugin manifest to evaluate.
        policy: The marketplace policy to enforce.
        mcp_servers: Optional list of MCP server names declared by the plugin.
            When ``None``, MCP declaration checks that require a server list
            will flag a violation if ``require_declaration`` is enabled.

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

    # -- MCP server policy ----------------------------------------------------
    mcp_policy = policy.mcp_servers

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
