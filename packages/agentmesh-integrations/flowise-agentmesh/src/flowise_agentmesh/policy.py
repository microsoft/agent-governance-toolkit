"""YAML policy loading with deny-by-default semantics and wildcard support."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class Policy:
    """Governance policy with deny-by-default semantics."""

    allowed_tools: list[str] = field(default_factory=list)
    blocked_tools: list[str] = field(default_factory=list)
    blocked_content_patterns: list[str] = field(default_factory=list)
    blocked_argument_patterns: list[str] = field(default_factory=list)
    default_action: str = "deny"
    max_trust_score: float = 1.0
    min_trust_score: float = 0.0

    def is_tool_allowed(self, tool_name: str) -> bool:
        """Check if a tool is allowed by policy. Supports wildcard patterns."""
        # Blocklist takes priority
        for pattern in self.blocked_tools:
            if fnmatch.fnmatch(tool_name, pattern):
                return False
        # If allowlist is defined, tool must match
        if self.allowed_tools:
            return any(
                fnmatch.fnmatch(tool_name, pat) for pat in self.allowed_tools
            )
        # No allowlist defined — fall back to default action
        return self.default_action == "allow"

    def check_content(self, content: str) -> tuple[bool, str | None]:
        """Check content against blocked patterns. Returns (allowed, reason)."""
        for pattern in self.blocked_content_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return False, f"Content matches blocked pattern: {pattern}"
        return True, None

    def check_arguments(self, arguments: dict[str, Any]) -> tuple[bool, str | None]:
        """Scan arguments for blocked patterns. Returns (allowed, reason)."""
        for key, value in arguments.items():
            text = f"{key}={value}"
            for pattern in self.blocked_argument_patterns:
                if re.search(pattern, str(value), re.IGNORECASE):
                    return False, f"Argument '{key}' matches blocked pattern: {pattern}"
                if re.search(pattern, text, re.IGNORECASE):
                    return False, f"Argument '{key}' matches blocked pattern: {pattern}"
        return True, None


def load_policy(source: str | Path | dict) -> Policy:
    """Load a Policy from a YAML file path, YAML string, or dict."""
    if isinstance(source, dict):
        raw = source
    elif isinstance(source, Path) or (
        isinstance(source, str) and not source.strip().startswith("{")
        and "\n" not in source and Path(source).suffix in (".yaml", ".yml")
    ):
        path = Path(source)
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    else:
        raw = yaml.safe_load(source)

    if raw is None:
        raw = {}

    return Policy(
        allowed_tools=raw.get("allowed_tools", []),
        blocked_tools=raw.get("blocked_tools", []),
        blocked_content_patterns=raw.get("blocked_content_patterns", []),
        blocked_argument_patterns=raw.get("blocked_argument_patterns", []),
        default_action=raw.get("default_action", "deny"),
        max_trust_score=float(raw.get("max_trust_score", 1.0)),
        min_trust_score=float(raw.get("min_trust_score", 0.0)),
    )
