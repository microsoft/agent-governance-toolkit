"""Governance policy engine with pattern matching and YAML serialization.

Shared policy engine reusable across Langflow governance components.
Compatible with the AgentMesh policy pattern (pydantic-ai-governance).
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


class PatternType(Enum):
    """Pattern matching strategy for blocked content."""

    SUBSTRING = "substring"
    REGEX = "regex"
    GLOB = "glob"


class GovernanceEventType(Enum):
    """Events emitted during governance enforcement."""

    POLICY_CHECK = "policy_check"
    POLICY_VIOLATION = "policy_violation"
    TOOL_CALL_BLOCKED = "tool_call_blocked"
    TOOL_CALL_ALLOWED = "tool_call_allowed"
    TRUST_CHECK = "trust_check"
    COMPLIANCE_CHECK = "compliance_check"
    AUDIT_ENTRY = "audit_entry"


@dataclass
class PolicyCheckResult:
    """Result of a policy check."""

    allowed: bool
    reason: Optional[str] = None
    event_type: GovernanceEventType = GovernanceEventType.POLICY_CHECK
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GovernancePolicy:
    """Governance policy for agent actions in Langflow flows.

    Defines execution limits, blocked/allowed tools, content patterns,
    and argument scanning rules. Serializable to/from YAML.
    """

    allowed_tools: List[str] = field(default_factory=list)
    blocked_tools: List[str] = field(default_factory=list)
    blocked_patterns: List[Tuple[str, PatternType]] = field(default_factory=list)
    max_tool_calls_per_request: int = 10
    max_tokens_per_request: int = 4096
    confidence_threshold: float = 0.8
    require_human_approval: bool = False
    log_all_calls: bool = True
    version: str = "1.0.0"

    _compiled_patterns: Optional[List[Tuple[str, PatternType, "re.Pattern[str]"]]] = field(
        default=None, repr=False, compare=False
    )

    def __post_init__(self) -> None:
        self._compile_patterns()

    def _compile_patterns(self) -> None:
        """Pre-compile regex and glob patterns for performance."""
        self._compiled_patterns = []
        for pattern, ptype in self.blocked_patterns:
            if ptype == PatternType.REGEX:
                compiled = re.compile(pattern, re.IGNORECASE)
            elif ptype == PatternType.GLOB:
                compiled = re.compile(fnmatch.translate(pattern), re.IGNORECASE)
            else:
                compiled = re.compile(re.escape(pattern), re.IGNORECASE)
            self._compiled_patterns.append((pattern, ptype, compiled))

    def check_content(self, text: str) -> PolicyCheckResult:
        """Check text against blocked patterns."""
        if not self._compiled_patterns:
            self._compile_patterns()

        for pattern, ptype, compiled in self._compiled_patterns:  # type: ignore[union-attr]
            if compiled.search(text):
                return PolicyCheckResult(
                    allowed=False,
                    reason=f"Blocked pattern matched: '{pattern}' ({ptype.value})",
                    event_type=GovernanceEventType.POLICY_VIOLATION,
                    metadata={"pattern": pattern, "pattern_type": ptype.value},
                )
        return PolicyCheckResult(allowed=True)

    def check_tool(self, tool_name: str) -> PolicyCheckResult:
        """Check if a tool is allowed by policy."""
        if tool_name in self.blocked_tools:
            return PolicyCheckResult(
                allowed=False,
                reason=f"Tool '{tool_name}' is in blocklist",
                event_type=GovernanceEventType.TOOL_CALL_BLOCKED,
                metadata={"tool_name": tool_name, "blocked_tools": self.blocked_tools},
            )
        if self.allowed_tools and tool_name not in self.allowed_tools:
            return PolicyCheckResult(
                allowed=False,
                reason=f"Tool '{tool_name}' not in allowed list: {self.allowed_tools}",
                event_type=GovernanceEventType.TOOL_CALL_BLOCKED,
                metadata={"tool_name": tool_name, "allowed_tools": self.allowed_tools},
            )
        return PolicyCheckResult(allowed=True)

    def check_arguments(self, arguments: Dict[str, Any]) -> PolicyCheckResult:
        """Scan tool arguments for blocked content patterns."""
        for key, value in arguments.items():
            text = str(value)
            result = self.check_content(text)
            if not result.allowed:
                result.metadata["argument_key"] = key
                return result
        return PolicyCheckResult(allowed=True)

    def check_call_count(self, current_count: int) -> PolicyCheckResult:
        """Check if tool call count exceeds limit."""
        if current_count > self.max_tool_calls_per_request:
            return PolicyCheckResult(
                allowed=False,
                reason=(
                    f"Tool call limit reached: {current_count}"
                    f"/{self.max_tool_calls_per_request}"
                ),
                event_type=GovernanceEventType.POLICY_VIOLATION,
                metadata={
                    "current_count": current_count,
                    "max_calls": self.max_tool_calls_per_request,
                },
            )
        return PolicyCheckResult(allowed=True)

    def enforce(
        self, action: str, parameters: Dict[str, Any], agent_id: Optional[str] = None
    ) -> PolicyCheckResult:
        """Run all policy checks for an action. Returns first violation or allowed."""
        tool_result = self.check_tool(action)
        if not tool_result.allowed:
            tool_result.metadata["agent_id"] = agent_id
            return tool_result

        arg_result = self.check_arguments(parameters)
        if not arg_result.allowed:
            arg_result.metadata["agent_id"] = agent_id
            return arg_result

        content = f"{action} {' '.join(str(v) for v in parameters.values())}"
        content_result = self.check_content(content)
        if not content_result.allowed:
            content_result.metadata["agent_id"] = agent_id
            return content_result

        return PolicyCheckResult(
            allowed=True,
            event_type=GovernanceEventType.TOOL_CALL_ALLOWED,
            metadata={"agent_id": agent_id, "action": action},
        )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize policy to a dictionary."""
        return {
            "allowed_tools": self.allowed_tools,
            "blocked_tools": self.blocked_tools,
            "blocked_patterns": [
                {"pattern": p, "type": t.value} for p, t in self.blocked_patterns
            ],
            "max_tool_calls_per_request": self.max_tool_calls_per_request,
            "max_tokens_per_request": self.max_tokens_per_request,
            "confidence_threshold": self.confidence_threshold,
            "require_human_approval": self.require_human_approval,
            "log_all_calls": self.log_all_calls,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> GovernancePolicy:
        """Deserialize policy from a dictionary."""
        patterns = []
        for p in data.get("blocked_patterns", []):
            if isinstance(p, dict):
                patterns.append((p["pattern"], PatternType(p["type"])))
            elif isinstance(p, (list, tuple)):
                patterns.append((p[0], PatternType(p[1])))
        return cls(
            allowed_tools=data.get("allowed_tools", []),
            blocked_tools=data.get("blocked_tools", []),
            blocked_patterns=patterns,
            max_tool_calls_per_request=data.get("max_tool_calls_per_request", 10),
            max_tokens_per_request=data.get("max_tokens_per_request", 4096),
            confidence_threshold=data.get("confidence_threshold", 0.8),
            require_human_approval=data.get("require_human_approval", False),
            log_all_calls=data.get("log_all_calls", True),
            version=data.get("version", "1.0.0"),
        )

    def to_yaml(self) -> str:
        """Serialize policy to YAML string (no PyYAML dependency)."""
        lines = [
            f"max_tool_calls_per_request: {self.max_tool_calls_per_request}",
            f"max_tokens_per_request: {self.max_tokens_per_request}",
            f"confidence_threshold: {self.confidence_threshold}",
            f"require_human_approval: {str(self.require_human_approval).lower()}",
            f"log_all_calls: {str(self.log_all_calls).lower()}",
            f'version: "{self.version}"',
        ]
        if self.allowed_tools:
            lines.append("allowed_tools:")
            for tool in self.allowed_tools:
                lines.append(f"  - {tool}")
        if self.blocked_tools:
            lines.append("blocked_tools:")
            for tool in self.blocked_tools:
                lines.append(f"  - {tool}")
        if self.blocked_patterns:
            lines.append("blocked_patterns:")
            for pattern, ptype in self.blocked_patterns:
                lines.append(f'  - pattern: "{pattern}"')
                lines.append(f"    type: {ptype.value}")
        return "\n".join(lines) + "\n"

    @classmethod
    def from_yaml(cls, yaml_str: str) -> GovernancePolicy:
        """Deserialize policy from YAML string (minimal parser, no PyYAML dep)."""
        data: Dict[str, Any] = {}
        patterns: List[Dict[str, str]] = []
        allowed_tools: List[str] = []
        blocked_tools: List[str] = []
        current_section: Optional[str] = None
        current_pattern: Dict[str, str] = {}

        for line in yaml_str.strip().splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            if stripped == "blocked_patterns:":
                current_section = "patterns"
                continue
            elif stripped == "allowed_tools:":
                current_section = "allowed_tools"
                continue
            elif stripped == "blocked_tools:":
                current_section = "blocked_tools"
                continue

            if current_section == "patterns":
                if stripped.startswith("- pattern:"):
                    if current_pattern and "pattern" in current_pattern:
                        patterns.append(current_pattern)
                    val = stripped.split(":", 1)[1].strip().strip('"').strip("'")
                    current_pattern = {"pattern": val}
                elif "type:" in stripped:
                    type_val = stripped.split("type:", 1)[1].strip()
                    current_pattern["type"] = type_val
                continue
            elif current_section == "allowed_tools":
                if stripped.startswith("-"):
                    allowed_tools.append(stripped.lstrip("- ").strip())
                else:
                    current_section = None
                continue
            elif current_section == "blocked_tools":
                if stripped.startswith("-"):
                    blocked_tools.append(stripped.lstrip("- ").strip())
                else:
                    current_section = None
                continue

            if ":" in stripped:
                key, val = stripped.split(":", 1)
                key = key.strip()
                val = val.strip().strip('"').strip("'")
                if val.lower() == "true":
                    data[key] = True
                elif val.lower() == "false":
                    data[key] = False
                elif "." in val:
                    try:
                        data[key] = float(val)
                    except ValueError:
                        data[key] = val
                else:
                    try:
                        data[key] = int(val)
                    except ValueError:
                        data[key] = val

        if current_pattern and "pattern" in current_pattern:
            patterns.append(current_pattern)

        data["blocked_patterns"] = patterns
        data["allowed_tools"] = allowed_tools
        data["blocked_tools"] = blocked_tools
        return cls.from_dict(data)

    @classmethod
    def from_yaml_file(cls, path: str) -> GovernancePolicy:
        """Load policy from a YAML file."""
        with open(path, "r") as f:
            return cls.from_yaml(f.read())
