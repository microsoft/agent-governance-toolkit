"""Governance policy definitions."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional, Set


@dataclass
class GovernancePolicy:
    """Defines governance constraints for agent execution."""

    name: str = "default"
    max_tokens: int = 10000
    max_tool_calls: int = 50
    blocked_patterns: List[str] = field(default_factory=list)
    allowed_tools: Optional[List[str]] = None
    min_trust_score: float = 0.5
    require_identity: bool = False

    def check_content(self, content: str) -> Optional[str]:
        """Check content against blocked patterns. Returns violation reason or None."""
        for pattern in self.blocked_patterns:
            if re.search(pattern, content, re.IGNORECASE):
                return f"Content matches blocked pattern: {pattern}"
        return None

    def check_tool(self, tool_name: str) -> Optional[str]:
        """Check if a tool is allowed. Returns violation reason or None."""
        if self.allowed_tools is not None and tool_name not in self.allowed_tools:
            return f"Tool '{tool_name}' not in allowed list: {self.allowed_tools}"
        return None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "max_tokens": self.max_tokens,
            "max_tool_calls": self.max_tool_calls,
            "blocked_patterns": self.blocked_patterns,
            "allowed_tools": self.allowed_tools,
            "min_trust_score": self.min_trust_score,
            "require_identity": self.require_identity,
        }
