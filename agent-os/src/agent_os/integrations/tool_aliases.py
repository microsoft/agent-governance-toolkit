# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Tool Alias Registry for Capability Canonicalization.

Maps tool name variants to canonical capability identifiers so that
policy allowlists/blocklists cannot be bypassed by renaming tools.

Usage:
    from agent_os.integrations.tool_aliases import ToolAliasRegistry

    registry = ToolAliasRegistry()
    registry.register_alias("bing_search", "web_search")
    registry.register_alias("search_web", "web_search")
    registry.register_alias("google_search", "web_search")

    assert registry.canonicalize("bing_search") == "web_search"
    assert registry.canonicalize("unknown_tool") == "unknown_tool"
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# Default canonical mappings for common tool families.
# Keys are alias patterns, values are canonical names.
DEFAULT_ALIASES: dict[str, str] = {
    # Search tools
    "bing_search": "web_search",
    "google_search": "web_search",
    "search_web": "web_search",
    "internet_search": "web_search",
    "duckduckgo_search": "web_search",
    # File operations
    "read_file": "file_read",
    "file_read": "file_read",
    "get_file": "file_read",
    "load_file": "file_read",
    "write_file": "file_write",
    "file_write": "file_write",
    "save_file": "file_write",
    "create_file": "file_write",
    # Shell execution
    "shell_exec": "shell_execute",
    "shell_execute": "shell_execute",
    "run_command": "shell_execute",
    "exec_command": "shell_execute",
    "bash": "shell_execute",
    "terminal": "shell_execute",
    # Code execution
    "python_exec": "code_execute",
    "run_python": "code_execute",
    "execute_code": "code_execute",
    "eval_code": "code_execute",
    # Database operations
    "sql_query": "database_query",
    "run_sql": "database_query",
    "execute_sql": "database_query",
    "db_query": "database_query",
    # HTTP operations
    "http_request": "http_request",
    "api_call": "http_request",
    "fetch_url": "http_request",
    "curl": "http_request",
}


class ToolAliasRegistry:
    """Maps tool name variants to canonical capability identifiers.

    Provides both exact-match aliases and regex pattern-based matching
    for tool name canonicalization. Prevents policy bypass via tool
    renaming.

    Args:
        use_defaults: If True, loads the default alias mappings.
    """

    def __init__(self, use_defaults: bool = True) -> None:
        self._aliases: dict[str, str] = {}
        self._patterns: list[tuple[re.Pattern, str]] = []
        if use_defaults:
            self._aliases.update(DEFAULT_ALIASES)

    def register_alias(self, alias: str, canonical: str) -> None:
        """Register a tool name alias.

        Args:
            alias: The alternative tool name (case-insensitive).
            canonical: The canonical capability name it maps to.
        """
        self._aliases[alias.lower()] = canonical.lower()

    def register_pattern(self, pattern: str, canonical: str) -> None:
        """Register a regex pattern that maps matching tool names.

        Args:
            pattern: Regex pattern to match tool names against.
            canonical: The canonical capability name for matches.
        """
        self._patterns.append((re.compile(pattern, re.IGNORECASE), canonical.lower()))

    def canonicalize(self, tool_name: str) -> str:
        """Resolve a tool name to its canonical form.

        Checks exact aliases first, then regex patterns. Returns the
        original name (lowercased) if no mapping is found.

        Args:
            tool_name: The tool name to canonicalize.

        Returns:
            The canonical capability name.
        """
        lower = tool_name.lower()

        # Exact match first
        if lower in self._aliases:
            return self._aliases[lower]

        # Pattern match
        for pattern, canonical in self._patterns:
            if pattern.search(lower):
                return canonical

        return lower

    def is_allowed(self, tool_name: str, allowed_tools: list[str]) -> bool:
        """Check if a tool is in the allowed list after canonicalization.

        Both the tool name and all entries in the allowed list are
        canonicalized before comparison.

        Args:
            tool_name: Tool name to check.
            allowed_tools: List of allowed tool names/capabilities.

        Returns:
            True if the canonicalized tool is in the canonicalized allowlist.
        """
        if not allowed_tools:
            return True  # Empty allowlist = all allowed
        canonical = self.canonicalize(tool_name)
        allowed_canonical = {self.canonicalize(t) for t in allowed_tools}
        return canonical in allowed_canonical

    def is_blocked(self, tool_name: str, blocked_tools: list[str]) -> bool:
        """Check if a tool is in a block list after canonicalization.

        Args:
            tool_name: Tool name to check.
            blocked_tools: List of blocked tool names/capabilities.

        Returns:
            True if the canonicalized tool is in the canonicalized blocklist.
        """
        if not blocked_tools:
            return False
        canonical = self.canonicalize(tool_name)
        blocked_canonical = {self.canonicalize(t) for t in blocked_tools}
        return canonical in blocked_canonical

    def get_aliases(self, canonical: str) -> list[str]:
        """Get all known aliases for a canonical tool name.

        Args:
            canonical: The canonical capability name.

        Returns:
            List of alias names that map to this canonical name.
        """
        canonical_lower = canonical.lower()
        return [
            alias
            for alias, canon in self._aliases.items()
            if canon == canonical_lower
        ]

    def list_canonical_tools(self) -> list[str]:
        """List all unique canonical tool names."""
        return sorted(set(self._aliases.values()))

    def __len__(self) -> int:
        return len(self._aliases)

    def __contains__(self, tool_name: str) -> bool:
        return tool_name.lower() in self._aliases
