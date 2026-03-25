# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Copilot / Claude Plugin Manifest Schema Adapters

Detects and converts Copilot-style and Claude-style plugin manifests
(plugin.json with skills, agents, mcps fields) into the canonical
PluginManifest used by the marketplace validator.
"""

from __future__ import annotations

import logging
from typing import Optional

from pydantic import BaseModel, Field, model_validator

from agent_marketplace.exceptions import MarketplaceError
from agent_marketplace.manifest import PluginManifest, PluginType

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Sub-models shared by Copilot and Claude manifests
# ---------------------------------------------------------------------------


class SkillDef(BaseModel):
    """A skill declaration inside a plugin manifest."""

    name: str = Field(..., description="Skill identifier")
    description: str = Field("", description="Human-readable description")


class AgentDef(BaseModel):
    """An agent declaration inside a plugin manifest."""

    name: str = Field(..., description="Agent identifier")
    model: str = Field("", description="Model backing this agent")
    instructions: str = Field("", description="System instructions for the agent")


class MCPServerDef(BaseModel):
    """An MCP server registration inside a plugin manifest."""

    name: str = Field(..., description="Server identifier")
    url: Optional[str] = Field(None, description="HTTP endpoint for the server")
    command: Optional[str] = Field(None, description="Local command to launch the server")
    tools: list[str] = Field(default_factory=list, description="Tools exposed by the server")

    @model_validator(mode="after")
    def require_url_or_command(self) -> MCPServerDef:
        if not self.url and not self.command:
            raise MarketplaceError(
                f"MCP server '{self.name}' must declare either 'url' or 'command'"
            )
        return self


# ---------------------------------------------------------------------------
# Copilot plugin manifest
# ---------------------------------------------------------------------------


class CopilotPluginManifest(BaseModel):
    """Schema for a GitHub Copilot-style plugin manifest (plugin.json)."""

    name: str = Field(..., description="Plugin name")
    description: str = Field("", description="Plugin description")
    version: str = Field("1.0.0", description="Semver version string")
    skills: list[SkillDef] = Field(default_factory=list, description="Skill definitions")
    agents: list[AgentDef] = Field(default_factory=list, description="Agent definitions")
    mcps: list[MCPServerDef] = Field(default_factory=list, description="MCP server registrations")


# ---------------------------------------------------------------------------
# Claude plugin manifest
# ---------------------------------------------------------------------------


class ClaudePluginManifest(BaseModel):
    """Schema for an Anthropic Claude-style plugin manifest (plugin.json)."""

    name: str = Field(..., description="Plugin name")
    description: str = Field("", description="Plugin description")
    version: str = Field("1.0.0", description="Semver version string")
    permissions: list[str] = Field(
        default_factory=list, description="Permissions requested by the plugin"
    )
    allowed_tools: list[str] = Field(
        default_factory=list, description="Tools the plugin is allowed to invoke"
    )
    skills: list[SkillDef] = Field(default_factory=list, description="Skill definitions")
    agents: list[AgentDef] = Field(default_factory=list, description="Agent definitions")
    mcps: list[MCPServerDef] = Field(default_factory=list, description="MCP server registrations")


# ---------------------------------------------------------------------------
# Detection and adaptation helpers
# ---------------------------------------------------------------------------

# Fields that distinguish each format
_COPILOT_SIGNALS = {"skills", "agents", "mcps"}
_CLAUDE_SIGNALS = {"permissions", "allowed_tools"}


def detect_manifest_format(data: dict) -> str:
    """Detect whether *data* represents a Copilot, Claude, or generic manifest.

    Returns:
        ``"copilot"``, ``"claude"``, or ``"generic"``.
    """
    keys = set(data.keys())
    has_claude = bool(keys & _CLAUDE_SIGNALS)
    has_copilot = bool(keys & _COPILOT_SIGNALS)

    if has_claude:
        return "claude"
    if has_copilot:
        return "copilot"
    return "generic"


def adapt_to_canonical(data: dict, format: str) -> PluginManifest:
    """Convert a Copilot or Claude manifest dict into a canonical :class:`PluginManifest`.

    For ``"generic"`` format the data is passed straight through.

    Args:
        data: Raw manifest dictionary.
        format: One of ``"copilot"``, ``"claude"``, or ``"generic"``.

    Returns:
        A validated :class:`PluginManifest`.

    Raises:
        MarketplaceError: On validation failure.
    """
    if format == "generic":
        try:
            return PluginManifest(**data)
        except Exception as exc:
            raise MarketplaceError(f"Invalid generic manifest: {exc}") from exc

    # Validate through the format-specific model first
    try:
        if format == "copilot":
            parsed = CopilotPluginManifest(**data)
        elif format == "claude":
            parsed = ClaudePluginManifest(**data)
        else:
            raise MarketplaceError(f"Unknown manifest format: {format}")
    except MarketplaceError:
        raise
    except Exception as exc:
        raise MarketplaceError(f"Invalid {format} manifest: {exc}") from exc

    capabilities = extract_capabilities(data, format)

    return PluginManifest(
        name=parsed.name,
        version=parsed.version,
        description=parsed.description,
        author=data.get("author", "unknown"),
        plugin_type=PluginType.AGENT,
        capabilities=capabilities,
    )


def extract_capabilities(data: dict, format: str) -> list[str]:
    """Extract declared capabilities from a manifest dict.

    Capabilities are derived from skill names and MCP server tool lists.

    Args:
        data: Raw manifest dictionary.
        format: ``"copilot"``, ``"claude"``, or ``"generic"``.

    Returns:
        Sorted, deduplicated list of capability strings.
    """
    if format == "generic":
        return sorted(set(data.get("capabilities", [])))

    caps: set[str] = set()
    for skill in data.get("skills", []):
        if isinstance(skill, dict) and skill.get("name"):
            caps.add(skill["name"])
    for mcp in data.get("mcps", []):
        if isinstance(mcp, dict):
            for tool in mcp.get("tools", []):
                caps.add(tool)
    if format == "claude":
        for tool in data.get("allowed_tools", []):
            caps.add(tool)
    return sorted(caps)


def extract_mcp_servers(data: dict) -> list[str]:
    """Extract MCP server names from any manifest format.

    Args:
        data: Raw manifest dictionary.

    Returns:
        List of MCP server name strings.
    """
    servers: list[str] = []
    for mcp in data.get("mcps", []):
        if isinstance(mcp, dict) and mcp.get("name"):
            servers.append(mcp["name"])
    return servers
