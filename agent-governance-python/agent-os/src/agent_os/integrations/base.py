# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Base Integration Interface

All framework adapters inherit from this base class.
"""

from __future__ import annotations

import asyncio
import copy
import difflib
import fnmatch
import hashlib
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Protocol

logger = logging.getLogger(__name__)


class PatternType(Enum):
    """Type of pattern matching for blocked_patterns."""
    SUBSTRING = "substring"
    REGEX = "regex"
    GLOB = "glob"


class GovernanceEventType(Enum):
    """Event types emitted by the governance layer."""
    POLICY_CHECK = "policy_check"
    POLICY_VIOLATION = "policy_violation"
    TOOL_CALL_BLOCKED = "tool_call_blocked"
    CHECKPOINT_CREATED = "checkpoint_created"
    DRIFT_DETECTED = "drift_detected"


@dataclass
class DriftResult:
    """Result of a drift detection comparison.

    Attributes:
        score: Drift score in [0.0, 1.0]. 0 = identical, 1 = completely different.
        exceeded: Whether the score exceeded the configured threshold.
        threshold: The threshold that was checked against.
        baseline_hash: Hash of the baseline output.
        current_hash: Hash of the current output.
    """
    score: float
    exceeded: bool
    threshold: float
    baseline_hash: str
    current_hash: str

    def __repr__(self) -> str:
        status = "EXCEEDED" if self.exceeded else "OK"
        return f"DriftResult(score={self.score:.4f}, threshold={self.threshold}, {status})"


@dataclass
class GovernancePolicy:
    """Policy configuration for governed AI agents.

    Defines the complete set of constraints, thresholds, and audit settings
    that the governance layer enforces on agent behaviour. Policies are
    validated on construction via ``__post_init__`` and can be serialized
    to/from YAML for version-controlled configuration.

    Policies are **composable**: create a base policy with sensible defaults
    and derive stricter variants for sensitive environments.  Use
    ``is_stricter_than()`` to verify that a derived policy never *loosens*
    constraints relative to the base.

    Attributes:
        name: Human-readable policy name used in audit logs and error
            messages.  Defaults to ``"default"``.
        max_tokens: Maximum number of tokens an agent may consume per
            request.  Must be a positive integer.  Defaults to ``4096``.
        max_tool_calls: Maximum number of tool invocations allowed per
            request.  ``0`` disables tool calls entirely.  Must be a
            non-negative integer.  Defaults to ``10``.
        allowed_tools: Explicit allowlist of tool names the agent may call.
            An empty list means *all* tools are permitted (subject to other
            constraints).  Defaults to ``[]``.
        blocked_patterns: Patterns that must not appear in tool arguments.
            Each entry is either a plain substring string or a
            ``(pattern, PatternType)`` tuple for regex/glob matching.
            Defaults to ``[]``.
        require_human_approval: When ``True``, tool calls require explicit
            human approval before execution.  Defaults to ``False``.
        timeout_seconds: Maximum wall-clock time (in seconds) allowed for
            a single request.  Must be a positive integer.  Defaults to
            ``300``.
        confidence_threshold: Minimum confidence score (0.0–1.0) for an
            agent's action to be accepted without review.  ``0.0``
            effectively disables confidence checking.  Defaults to ``0.8``.
        drift_threshold: Maximum acceptable semantic drift score (0.0–1.0)
            between an agent's stated intent and actual output before a
            ``DRIFT_DETECTED`` event is emitted.  Defaults to ``0.15``.
        log_all_calls: When ``True``, every tool call is recorded in the
            audit log regardless of outcome.  Defaults to ``True``.
        checkpoint_frequency: Create a governance checkpoint every *N* tool
            calls.  Must be a positive integer.  Defaults to ``5``.
        max_concurrent: Maximum number of concurrent agent executions
            allowed under this policy.  Must be a positive integer.
            Defaults to ``10``.
        backpressure_threshold: Number of concurrent executions at which
            the system begins applying backpressure (e.g. throttling new
            requests).  Should be less than ``max_concurrent`` to be
            effective.  Defaults to ``8``.
        version: Semantic version string for the policy, enabling auditable
            policy evolution.  Defaults to ``"1.0.0"``.

    Example:
        Creating a strict read-only policy::

            policy = GovernancePolicy(
                name="read_only_strict",
                max_tokens=2048,
                max_tool_calls=5,
                allowed_tools=["read_file", "web_search"],
                blocked_patterns=[
                    "password",
                    ("rm\\s+-rf", PatternType.REGEX),
                    ("*.exe", PatternType.GLOB),
                ],
                require_human_approval=True,
                confidence_threshold=0.9,
                drift_threshold=0.10,
                version="2.0.0",
            )

        Comparing policies::

            base = GovernancePolicy()
            strict = GovernancePolicy(max_tokens=1024, max_tool_calls=3)
            assert strict.is_stricter_than(base)

        Serialization round-trip::

            yaml_str = policy.to_yaml()
            restored = GovernancePolicy.from_yaml(yaml_str)
    """
    name: str = "default"
    max_tokens: int = 4096
    max_tool_calls: int = 10
    allowed_tools: list[str] = field(default_factory=list)
    blocked_patterns: list[str | tuple[str, PatternType]] = field(default_factory=list)
    require_human_approval: bool = False
    timeout_seconds: int = 300

    # Safety thresholds
    confidence_threshold: float = 0.8
    drift_threshold: float = 0.15

    # Audit settings
    log_all_calls: bool = True
    checkpoint_frequency: int = 5  # Every N calls

    # Concurrency limits
    max_concurrent: int = 10
    backpressure_threshold: int = 8  # Start slowing down at this level

    # Version tracking
    version: str = "1.0.0"

    def __repr__(self) -> str:
        return (
            f"GovernancePolicy(max_tokens={self.max_tokens!r}, "
            f"max_tool_calls={self.max_tool_calls!r}, "
            f"require_human_approval={self.require_human_approval!r}, "
            f"version={self.version!r})"
        )

    def __hash__(self) -> int:
        return hash(
            (
                self.max_tokens,
                self.max_tool_calls,
                tuple(self.allowed_tools),
                tuple(self.blocked_patterns),
                self.require_human_approval,
                self.timeout_seconds,
                self.confidence_threshold,
                self.drift_threshold,
                self.log_all_calls,
                self.checkpoint_frequency,
                self.max_concurrent,
                self.backpressure_threshold,
                self.version,
            )
        )

    def __post_init__(self) -> None:
        """Validate policy fields on construction."""
        self.validate()

    def validate(self) -> None:
        """Validate all policy fields and raise ValueError for invalid inputs."""
        # Validate positive integers (must be > 0)
        for field_name in (
            "max_tokens", "timeout_seconds",
            "max_concurrent", "backpressure_threshold", "checkpoint_frequency",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, int) or value <= 0:
                raise ValueError(
                    f"{field_name} must be a positive integer, got {value!r}"
                )

        # Validate non-negative integers (>= 0 allowed)
        for field_name in ("max_tool_calls",):
            value = getattr(self, field_name)
            if not isinstance(value, int) or value < 0:
                raise ValueError(
                    f"{field_name} must be a non-negative integer, got {value!r}"
                )

        # Validate float thresholds are in [0.0, 1.0]
        for field_name in ("confidence_threshold", "drift_threshold"):
            value = getattr(self, field_name)
            if not isinstance(value, (int, float)) or not (0.0 <= value <= 1.0):
                raise ValueError(
                    f"{field_name} must be a float between 0.0 and 1.0, got {value!r}"
                )

        # Validate allowed_tools entries are strings
        if not isinstance(self.allowed_tools, list):
            raise ValueError(
                f"allowed_tools must be a list, got {type(self.allowed_tools).__name__}"
            )
        for i, tool in enumerate(self.allowed_tools):
            if not isinstance(tool, str):
                raise ValueError(
                    f"allowed_tools[{i}] must be a string, got {type(tool).__name__}: {tool!r}"
                )

        # Validate blocked_patterns entries and precompile regex/glob patterns
        if not isinstance(self.blocked_patterns, list):
            raise ValueError(
                f"blocked_patterns must be a list, got {type(self.blocked_patterns).__name__}"
            )

        # Validate version is a non-empty string
        if not isinstance(self.version, str) or not self.version:
            raise ValueError(
                f"version must be a non-empty string, got {self.version!r}"
            )

        self._compiled_patterns: list[tuple[str, PatternType, re.Pattern | None]] = []
        for i, pattern in enumerate(self.blocked_patterns):
            if isinstance(pattern, str):
                self._compiled_patterns.append((pattern, PatternType.SUBSTRING, None))
            elif isinstance(pattern, tuple) and len(pattern) == 2:
                pat_str, pat_type = pattern
                if not isinstance(pat_str, str):
                    raise ValueError(
                        f"blocked_patterns[{i}][0] must be a string, got {type(pat_str).__name__}: {pat_str!r}"
                    )
                if not isinstance(pat_type, PatternType):
                    raise ValueError(
                        f"blocked_patterns[{i}][1] must be a PatternType, got {type(pat_type).__name__}: {pat_type!r}"
                    )
                compiled = None
                if pat_type == PatternType.REGEX:
                    try:
                        compiled = re.compile(pat_str, re.IGNORECASE)
                    except re.error as e:
                        raise ValueError(
                            f"blocked_patterns[{i}] has invalid regex '{pat_str}': {e}"
                        ) from e
                elif pat_type == PatternType.GLOB:
                    try:
                        compiled = re.compile(fnmatch.translate(pat_str), re.IGNORECASE)
                    except re.error as e:
                        raise ValueError(
                            f"blocked_patterns[{i}] has invalid glob '{pat_str}': {e}"
                        ) from e
                self._compiled_patterns.append((pat_str, pat_type, compiled))
            else:
                raise ValueError(
                    f"blocked_patterns[{i}] must be a string or (string, PatternType) tuple, got {type(pattern).__name__}: {pattern!r}"
                )

    def detect_conflicts(self) -> list[str]:
        """
        Detect conflicting or contradictory policy settings.

        Returns:
            A list of human-readable warning strings describing each conflict.
        """
        warnings: list[str] = []

        # Backpressure will never trigger if threshold is >= max_concurrent
        if self.backpressure_threshold >= self.max_concurrent:
            warnings.append(
                f"backpressure_threshold ({self.backpressure_threshold}) >= "
                f"max_concurrent ({self.max_concurrent}): backpressure will never trigger"
            )

        # Tools are allowed but max_tool_calls blocks any tool calls
        if self.max_tool_calls == 0 and self.allowed_tools:
            warnings.append(
                f"max_tool_calls is 0 but allowed_tools is non-empty "
                f"({self.allowed_tools}): tools are allowed but no calls permitted"
            )

        # Confidence checks effectively disabled
        if self.confidence_threshold == 0.0:
            warnings.append(
                "confidence_threshold is 0.0: effectively disables confidence checking"
            )

        # timeout_seconds is too low for reasonable execution (< 5s warning)
        if self.timeout_seconds < 5:
            warnings.append(
                f"timeout_seconds ({self.timeout_seconds}) is very low (under 5s), "
                f"may not allow reasonable execution time"
            )

        return warnings

    def matches_pattern(self, text: str) -> list[str]:
        """Return all blocked patterns that match the given text."""
        matches = []
        for pat_str, pat_type, compiled in self._compiled_patterns:
            if pat_type == PatternType.SUBSTRING:
                if pat_str.lower() in text.lower():
                    matches.append(pat_str)
            elif compiled is not None and compiled.search(text):
                matches.append(pat_str)
        return matches

    def to_dict(self) -> dict[str, Any]:
        """Serialize policy to a dictionary."""
        return {
            "name": self.name,
            "max_tokens": self.max_tokens,
            "max_tool_calls": self.max_tool_calls,
            "allowed_tools": self.allowed_tools,
            "blocked_patterns": [
                {"pattern": p, "type": t.value} if t != PatternType.SUBSTRING
                else p
                for p, t, _ in self._compiled_patterns
            ],
            "require_human_approval": self.require_human_approval,
            "timeout_seconds": self.timeout_seconds,
            "confidence_threshold": self.confidence_threshold,
            "drift_threshold": self.drift_threshold,
            "log_all_calls": self.log_all_calls,
            "checkpoint_frequency": self.checkpoint_frequency,
            "max_concurrent": self.max_concurrent,
            "backpressure_threshold": self.backpressure_threshold,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GovernancePolicy:
        """Deserialize policy from a dictionary.

        Args:
            data: Dictionary as produced by ``to_dict()``.

        Returns:
            Reconstructed GovernancePolicy instance.
        """
        data = dict(data)  # shallow copy to avoid mutating caller's dict
        # Convert blocked_patterns back to tuples where needed
        raw_patterns = data.get("blocked_patterns", [])
        patterns: list[str | tuple[str, PatternType]] = []
        for p in raw_patterns:
            if isinstance(p, str):
                patterns.append(p)
            elif isinstance(p, dict) and "pattern" in p and "type" in p:
                try:
                    pt = PatternType(p["type"])
                except ValueError:
                    raise ValueError(f"Unknown pattern type: {p['type']!r}") from None
                patterns.append((p["pattern"], pt))
            else:
                raise ValueError(f"Invalid blocked_pattern entry: {p!r}")
        data["blocked_patterns"] = patterns

        valid_fields = {
            "name", "max_tokens", "max_tool_calls", "allowed_tools",
            "blocked_patterns", "require_human_approval", "timeout_seconds",
            "confidence_threshold", "drift_threshold", "log_all_calls",
            "checkpoint_frequency", "max_concurrent", "backpressure_threshold",
            "version",
        }
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)

    def compare_versions(self, other: GovernancePolicy) -> dict[str, Any]:
        """Compare this policy with another, including version info.

        Returns a dict with version details and field-level changes.
        """
        return {
            "old_version": self.version,
            "new_version": other.version,
            "versions_differ": self.version != other.version,
            "changes": self.diff(other),
        }

    def to_yaml(self) -> str:
        """Serialize policy to YAML string."""
        import yaml

        data = {
            "max_tokens": self.max_tokens,
            "max_tool_calls": self.max_tool_calls,
            "allowed_tools": self.allowed_tools,
            "blocked_patterns": [
                {"pattern": p, "type": t.value} if t != PatternType.SUBSTRING
                else p
                for p, t, _ in self._compiled_patterns
            ],
            "require_human_approval": self.require_human_approval,
            "timeout_seconds": self.timeout_seconds,
            "confidence_threshold": self.confidence_threshold,
            "drift_threshold": self.drift_threshold,
            "log_all_calls": self.log_all_calls,
            "checkpoint_frequency": self.checkpoint_frequency,
            "max_concurrent": self.max_concurrent,
            "backpressure_threshold": self.backpressure_threshold,
            "version": self.version,
        }
        return yaml.dump(data, default_flow_style=False, sort_keys=False)

    @classmethod
    def from_yaml(cls, yaml_str: str) -> GovernancePolicy:
        """Deserialize policy from YAML string."""
        import yaml

        data = yaml.safe_load(yaml_str)
        if not isinstance(data, dict):
            raise ValueError(f"Expected a YAML mapping, got {type(data).__name__}")

        # Convert blocked_patterns back to tuples where needed
        raw_patterns = data.get("blocked_patterns", [])
        patterns: list[str | tuple[str, PatternType]] = []
        for p in raw_patterns:
            if isinstance(p, str):
                patterns.append(p)
            elif isinstance(p, dict) and "pattern" in p and "type" in p:
                try:
                    pt = PatternType(p["type"])
                except ValueError:
                    raise ValueError(f"Unknown pattern type: {p['type']!r}") from None
                patterns.append((p["pattern"], pt))
            else:
                raise ValueError(f"Invalid blocked_pattern entry: {p!r}")
        data["blocked_patterns"] = patterns

        # Remove unknown keys
        valid_fields = {
            "max_tokens", "max_tool_calls", "allowed_tools", "blocked_patterns",
            "require_human_approval", "timeout_seconds", "confidence_threshold",
            "drift_threshold", "log_all_calls", "checkpoint_frequency",
            "max_concurrent", "backpressure_threshold", "version",
        }
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        return cls(**filtered)

    def save(self, filepath: str) -> None:
        """Save policy to a YAML file."""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(self.to_yaml())

    @classmethod
    def load(cls, filepath: str) -> GovernancePolicy:
        """Load policy from a YAML file."""
        with open(filepath, encoding="utf-8") as f:
            return cls.from_yaml(f.read())

    def diff(self, other: GovernancePolicy) -> dict[str, tuple[Any, Any]]:
        """Compare this policy with another, returning changed fields.

        Returns a dict mapping field names to (self_value, other_value) tuples
        for fields that differ between the two policies.
        """
        changes: dict[str, tuple[Any, Any]] = {}
        fields = [
            "max_tokens", "max_tool_calls", "allowed_tools", "blocked_patterns",
            "require_human_approval", "timeout_seconds", "confidence_threshold",
            "drift_threshold", "log_all_calls", "checkpoint_frequency",
            "max_concurrent", "backpressure_threshold", "version",
        ]
        for f in fields:
            v_self = getattr(self, f)
            v_other = getattr(other, f)
            if v_self != v_other:
                changes[f] = (v_self, v_other)
        return changes

    def is_stricter_than(self, other: GovernancePolicy) -> bool:
        """Return True if this policy is more restrictive than other.

        Stricter means: lower limits, higher thresholds, more blocked patterns,
        fewer allowed tools, and human approval required.
        """
        checks = [
            self.max_tokens <= other.max_tokens,
            self.max_tool_calls <= other.max_tool_calls,
            self.timeout_seconds <= other.timeout_seconds,
            self.max_concurrent <= other.max_concurrent,
            self.backpressure_threshold <= other.backpressure_threshold,
            self.confidence_threshold >= other.confidence_threshold,
            self.checkpoint_frequency <= other.checkpoint_frequency,
            len(self.blocked_patterns) >= len(other.blocked_patterns),
            (not other.require_human_approval) or self.require_human_approval,
        ]
        # allowed_tools: fewer allowed tools is stricter (unless both empty)
        if self.allowed_tools or other.allowed_tools:
            checks.append(
                len(self.allowed_tools) <= len(other.allowed_tools)
                if other.allowed_tools else True
            )
        # Must be at least one actual difference to be considered stricter
        has_difference = any([
            self.max_tokens < other.max_tokens,
            self.max_tool_calls < other.max_tool_calls,
            self.timeout_seconds < other.timeout_seconds,
            self.confidence_threshold > other.confidence_threshold,
            self.require_human_approval and not other.require_human_approval,
            len(self.blocked_patterns) > len(other.blocked_patterns),
            len(self.allowed_tools) < len(other.allowed_tools) if other.allowed_tools else False,
        ])
        return all(checks) and has_difference

    def format_diff(self, other: GovernancePolicy) -> str:
        """Return a human-readable diff between this policy and other."""
        changes = self.diff(other)
        if not changes:
            return "Policies are identical."
        lines = ["Policy Diff:", "-" * 50]
        for field_name, (old, new) in changes.items():
            lines.append(f"  {field_name}: {old!r} -> {new!r}")
        lines.append("-" * 50)
        return "\n".join(lines)


_AGENT_ID_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


@dataclass
class ExecutionContext:
    """Context passed through the governance layer"""
    agent_id: str
    session_id: str
    policy: GovernancePolicy
    start_time: datetime = field(default_factory=datetime.now)
    call_count: int = 0
    total_tokens: int = 0
    tool_calls: list[dict] = field(default_factory=list)
    checkpoints: list[str] = field(default_factory=list)
    _baseline_hash: str | None = field(default=None, repr=False)
    _baseline_text: str | None = field(default=None, repr=False)
    _drift_scores: list[float] = field(default_factory=list, repr=False)

    def __repr__(self) -> str:
        return f"ExecutionContext(agent_id={self.agent_id!r}, session_id={self.session_id!r})"

    def __post_init__(self) -> None:
        """Validate context fields on construction."""
        self.validate()

    def validate(self) -> None:
        """Validate all context fields and raise ValueError for invalid inputs."""
        # Validate agent_id is a non-empty string matching allowed pattern
        if not isinstance(self.agent_id, str) or not self.agent_id:
            raise ValueError(
                f"agent_id must be a non-empty string, got {self.agent_id!r}"
            )
        if not _AGENT_ID_RE.match(self.agent_id):
            raise ValueError(
                f"agent_id must match ^[a-zA-Z0-9_-]+$, got {self.agent_id!r}"
            )

        # Validate session_id is a non-empty string
        if not isinstance(self.session_id, str) or not self.session_id:
            raise ValueError(
                f"session_id must be a non-empty string, got {self.session_id!r}"
            )

        # Validate policy is a GovernancePolicy instance
        if not isinstance(self.policy, GovernancePolicy):
            raise ValueError(
                f"policy must be a GovernancePolicy instance, got {type(self.policy).__name__}"
            )

        # Validate non-negative integers
        for field_name in ("call_count", "total_tokens"):
            value = getattr(self, field_name)
            if not isinstance(value, int) or value < 0:
                raise ValueError(
                    f"{field_name} must be a non-negative integer, got {value!r}"
                )

        # Validate checkpoints is a list of strings
        if not isinstance(self.checkpoints, list):
            raise ValueError(
                f"checkpoints must be a list, got {type(self.checkpoints).__name__}"
            )
        for i, cp in enumerate(self.checkpoints):
            if not isinstance(cp, str):
                raise ValueError(
                    f"checkpoints[{i}] must be a string, got {type(cp).__name__}: {cp!r}"
                )


# ── Abstract Tool Call Interceptor ────────────────────────────

@dataclass
class ToolCallRequest:
    """Vendor-neutral representation of a tool/function call."""
    tool_name: str
    arguments: dict[str, Any]
    call_id: str = ""
    agent_id: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return f"ToolCallRequest(tool_name={self.tool_name!r}, call_id={self.call_id!r})"


@dataclass
class ToolCallResult:
    """Result of intercepting a tool call."""
    allowed: bool
    reason: str | None = None
    modified_arguments: dict[str, Any] | None = None  # For argument sanitization
    audit_entry: dict[str, Any] | None = None

    def __repr__(self) -> str:
        return f"ToolCallResult(allowed={self.allowed!r}, reason={self.reason!r})"


class ToolCallInterceptor(Protocol):
    """
    Abstract protocol for intercepting tool/function calls.

    Implement this to add custom governance logic across any framework.
    The same interceptor works with OpenAI, LangChain, CrewAI, etc.

    Example:
        class PIIInterceptor:
            def intercept(self, request: ToolCallRequest) -> ToolCallResult:
                if any(p in str(request.arguments) for p in ["ssn", "password"]):
                    return ToolCallResult(allowed=False, reason="PII detected")
                return ToolCallResult(allowed=True)
    """

    def intercept(self, request: ToolCallRequest) -> ToolCallResult:
        """Intercept a tool call and return allow/deny decision."""
        ...


class PolicyInterceptor:
    """
    Default interceptor that enforces GovernancePolicy rules.

    Checks:
    - Human approval requirement (require_human_approval)
    - Tool is in allowed_tools (if specified)
    - Arguments don't contain blocked patterns
    - Call count within limits
    """

    def __init__(self, policy: GovernancePolicy, context: ExecutionContext | None = None):
        self.policy = policy
        self.context = context

    def intercept(self, request: ToolCallRequest) -> ToolCallResult:
        # Check human approval requirement
        if self.policy.require_human_approval:
            return ToolCallResult(
                allowed=False,
                reason=f"Tool '{request.tool_name}' requires human approval per governance policy",
            )

        # Check allowed tools
        if self.policy.allowed_tools and request.tool_name not in self.policy.allowed_tools:
            return ToolCallResult(
                allowed=False,
                reason=f"Tool '{request.tool_name}' not in allowed list: {self.policy.allowed_tools}",
            )

        # Check blocked patterns
        args_str = str(request.arguments)
        matched = self.policy.matches_pattern(args_str)
        if matched:
            return ToolCallResult(
                allowed=False,
                reason=f"Blocked pattern '{matched[0]}' detected in tool arguments",
            )

        # Check call count
        if self.context and self.context.call_count >= self.policy.max_tool_calls:
            return ToolCallResult(
                allowed=False,
                reason=f"Max tool calls exceeded ({self.policy.max_tool_calls})",
            )

        return ToolCallResult(allowed=True)


class ContentHashInterceptor:
    """Interceptor that verifies tool identity via content hashing.

    Instead of relying solely on tool *names* (which can be aliased),
    this interceptor checks that the callable behind a tool name has the
    same SHA-256 source hash that was recorded when the tool was
    registered.  This defeats tool-wrapping and aliasing attacks
    described in the Ona/Veto agent sandbox escape research.

    Requires a ``tool_registry`` that stores content hashes (see
    :class:`~agent_control_plane.tool_registry.ToolRegistry`).

    Args:
        tool_hashes: Mapping of tool name → expected SHA-256 hex digest.
        strict: If ``True`` (default), block tools with no registered
            hash.  If ``False``, allow unknown tools with a warning.
    """

    def __init__(
        self,
        tool_hashes: dict[str, str] | None = None,
        strict: bool = True,
    ) -> None:
        self._tool_hashes: dict[str, str] = dict(tool_hashes or {})
        self._strict = strict

    def register_hash(self, tool_name: str, content_hash: str) -> None:
        """Record the expected content hash for a tool."""
        self._tool_hashes[tool_name] = content_hash

    def intercept(self, request: ToolCallRequest) -> ToolCallResult:
        expected = self._tool_hashes.get(request.tool_name)
        if expected is None:
            if self._strict:
                return ToolCallResult(
                    allowed=False,
                    reason=(
                        f"Tool '{request.tool_name}' has no registered content hash "
                        "(possible alias or wrapper)"
                    ),
                )
            logger.warning(
                "No content hash for tool '%s' — allowing in non-strict mode",
                request.tool_name,
            )
            return ToolCallResult(allowed=True)

        # Verify the hash carried in request metadata (set by the framework adapter)
        actual = request.metadata.get("content_hash", "")
        if not actual:
            return ToolCallResult(
                allowed=False,
                reason=(
                    f"Tool '{request.tool_name}' call is missing content_hash metadata "
                    "— cannot verify integrity"
                ),
            )

        if actual != expected:
            return ToolCallResult(
                allowed=False,
                reason=(
                    f"Tool '{request.tool_name}' content hash mismatch: "
                    f"expected {expected[:12]}… got {actual[:12]}… "
                    "(possible tampering or wrapper)"
                ),
            )

        return ToolCallResult(allowed=True)


class CompositeInterceptor:
    """Chain multiple interceptors. All must allow for the call to proceed."""

    def __init__(self, interceptors: list[Any] | None = None):
        self.interceptors: list[Any] = interceptors or []

    def add(self, interceptor: Any) -> CompositeInterceptor:
        self.interceptors.append(interceptor)
        return self

    def intercept(self, request: ToolCallRequest) -> ToolCallResult:
        for interceptor in self.interceptors:
            result = interceptor.intercept(request)
            if not result.allowed:
                return result
        return ToolCallResult(allowed=True)


# ── Bounded Concurrency ──────────────────────────────────────

class BoundedSemaphore:
    """
    Async-compatible bounded semaphore with backpressure.

    When concurrency exceeds backpressure_threshold, callers must wait.
    When it exceeds max_concurrent, requests are rejected.
    """

    def __init__(self, max_concurrent: int = 10, backpressure_threshold: int = 8):
        self.max_concurrent = max_concurrent
        self.backpressure_threshold = backpressure_threshold
        self._active = 0
        self._total_acquired = 0
        self._total_rejected = 0

    def try_acquire(self) -> tuple[bool, str | None]:
        """
        Try to acquire a slot.

        Returns (acquired, reason).
        """
        if self._active >= self.max_concurrent:
            self._total_rejected += 1
            return False, f"Max concurrency reached ({self.max_concurrent})"
        self._active += 1
        self._total_acquired += 1
        return True, None

    def release(self) -> None:
        """Release a slot."""
        if self._active > 0:
            self._active -= 1

    @property
    def is_under_pressure(self) -> bool:
        """Check if backpressure threshold is reached."""
        return self._active >= self.backpressure_threshold

    @property
    def active(self) -> int:
        return self._active

    @property
    def available(self) -> int:
        return max(0, self.max_concurrent - self._active)

    def stats(self) -> dict[str, Any]:
        return {
            "active": self._active,
            "max_concurrent": self.max_concurrent,
            "available": self.available,
            "under_pressure": self.is_under_pressure,
            "total_acquired": self._total_acquired,
            "total_rejected": self._total_rejected,
        }


class BaseIntegration(ABC):
    """
    Base class for framework integrations.

    Wraps any agent framework with Agent OS governance:
    - Pre-execution policy checks
    - Post-execution validation
    - Flight recording
    - Signal handling
    """

    def __init__(self, policy: GovernancePolicy | None = None) -> None:
        self.policy: GovernancePolicy = policy or GovernancePolicy()
        self.contexts: dict[str, ExecutionContext] = {}
        self._signal_handlers: dict[str, Callable[..., Any]] = {}
        self._event_listeners: dict[GovernanceEventType, list[Callable[..., Any]]] = {}

    @abstractmethod
    def wrap(self, agent: Any) -> Any:
        """
        Wrap an agent with governance.

        Returns a governed version of the agent that:
        - Enforces policy on all operations
        - Records execution to flight recorder
        - Responds to signals (SIGSTOP, SIGKILL, etc.)
        """
        pass

    @abstractmethod
    def unwrap(self, governed_agent: Any) -> Any:
        """Remove governance wrapper and return original agent."""
        pass

    def create_context(self, agent_id: str) -> ExecutionContext:
        """Create execution context for an agent.

        The policy is **deep-copied** so that the session is pinned to
        the policy that was active when the context was created. This
        prevents mid-session mutations from leaking into running sessions.
        """
        from uuid import uuid4
        ctx = ExecutionContext(
            agent_id=agent_id,
            session_id=str(uuid4())[:8],
            policy=copy.deepcopy(self.policy),
        )
        self.contexts[agent_id] = ctx
        return ctx

    def on(self, event_type: GovernanceEventType, callback: Callable[..., Any]) -> None:
        """Register a callback for a governance event type."""
        self._event_listeners.setdefault(event_type, []).append(callback)

    def emit(self, event_type: GovernanceEventType, data: dict[str, Any]) -> None:
        """Fire all registered callbacks for an event type."""
        for cb in self._event_listeners.get(event_type, []):
            try:
                cb(data)
            except Exception as exc:  # noqa: BLE001 — listener errors must not break governance flow
                logger.warning(
                    "Governance event listener error for %s: %s",
                    event_type, exc, exc_info=True,
                )

    def pre_execute(self, ctx: ExecutionContext, input_data: Any) -> tuple[bool, str | None]:
        """
        Pre-execution policy check.

        Returns (allowed, reason) tuple.
        """
        event_base = {"agent_id": ctx.agent_id, "timestamp": datetime.now().isoformat()}

        self.emit(GovernanceEventType.POLICY_CHECK, {**event_base, "phase": "pre_execute"})

        # Check call count
        if ctx.call_count >= self.policy.max_tool_calls:
            reason = f"Max tool calls exceeded ({self.policy.max_tool_calls})"
            self.emit(GovernanceEventType.POLICY_VIOLATION, {**event_base, "reason": reason})
            return False, reason

        # Check timeout
        elapsed = (datetime.now() - ctx.start_time).total_seconds()
        if elapsed > self.policy.timeout_seconds:
            reason = f"Timeout exceeded ({self.policy.timeout_seconds}s)"
            self.emit(GovernanceEventType.POLICY_VIOLATION, {**event_base, "reason": reason})
            return False, reason

        # Check blocked patterns
        input_str = str(input_data)
        matched = self.policy.matches_pattern(input_str)
        if matched:
            reason = f"Blocked pattern detected: {matched[0]}"
            self.emit(GovernanceEventType.TOOL_CALL_BLOCKED, {**event_base, "reason": reason, "pattern": matched[0]})
            return False, reason

        # Check human approval requirement
        if self.policy.require_human_approval:
            reason = "Execution requires human approval per governance policy"
            self.emit(GovernanceEventType.POLICY_VIOLATION, {**event_base, "reason": reason})
            return False, reason

        # Check confidence threshold
        if self.policy.confidence_threshold > 0.0:
            confidence = getattr(input_data, 'confidence', None)
            if isinstance(confidence, (int, float)) and confidence < self.policy.confidence_threshold:
                reason = (
                    f"Confidence {confidence:.2f} below threshold "
                    f"{self.policy.confidence_threshold:.2f}"
                )
                self.emit(GovernanceEventType.POLICY_VIOLATION, {**event_base, "reason": reason})
                return False, reason

        return True, None

    def post_execute(self, ctx: ExecutionContext, output_data: Any) -> tuple[bool, str | None]:
        """
        Post-execution validation including drift detection.

        Computes a similarity score between the serialized output and the
        baseline (first output) using ``SequenceMatcher``.  The drift score
        is ``1.0 - similarity`` (0.0 = identical, 1.0 = completely different).

        When the score exceeds ``policy.drift_threshold`` a
        ``DRIFT_DETECTED`` governance event is emitted and a warning is
        logged.  Callers can register listeners for this event to enforce
        blocking behaviour if desired.

        Returns (valid, reason) tuple.
        """
        ctx.call_count += 1

        # Drift detection: compare output against baseline
        if self.policy.drift_threshold > 0.0:
            drift_result = self.compute_drift(ctx, output_data)
            if drift_result is not None:
                ctx._drift_scores.append(drift_result.score)
                if drift_result.exceeded:
                    reason = (
                        f"Drift score {drift_result.score:.2f} exceeds threshold "
                        f"{self.policy.drift_threshold:.2f}"
                    )
                    logger.warning(
                        "Drift detected agent=%s score=%.4f threshold=%.2f",
                        ctx.agent_id,
                        drift_result.score,
                        drift_result.threshold,
                    )
                    self.emit(GovernanceEventType.DRIFT_DETECTED, {
                        "agent_id": ctx.agent_id,
                        "timestamp": datetime.now().isoformat(),
                        "reason": reason,
                        "drift_score": drift_result.score,
                        "threshold": drift_result.threshold,
                        "baseline_hash": drift_result.baseline_hash,
                        "current_hash": drift_result.current_hash,
                    })
                else:
                    logger.debug(
                        "Drift check agent=%s score=%.4f threshold=%.2f",
                        ctx.agent_id,
                        drift_result.score,
                        drift_result.threshold,
                    )

        # Checkpoint if needed
        if ctx.call_count % self.policy.checkpoint_frequency == 0:
            checkpoint_id = f"checkpoint-{ctx.call_count}"
            ctx.checkpoints.append(checkpoint_id)
            self.emit(GovernanceEventType.CHECKPOINT_CREATED, {
                "agent_id": ctx.agent_id,
                "timestamp": datetime.now().isoformat(),
                "checkpoint_id": checkpoint_id,
                "call_count": ctx.call_count,
            })

        return True, None

    @staticmethod
    def compute_drift(ctx: ExecutionContext, output_data: Any) -> DriftResult | None:
        """Compute drift between *output_data* and the baseline stored in *ctx*.

        On the first call the output is recorded as the baseline and ``None``
        is returned (no comparison possible).  Subsequent calls use
        ``SequenceMatcher`` to compute a similarity ratio between the
        serialised baseline and the current output.  The drift score is
        ``1.0 - similarity`` (0.0 = identical, 1.0 = completely different).
        """
        current_text = str(output_data)
        current_hash = hashlib.sha256(current_text.encode()).hexdigest()

        if ctx._baseline_hash is None:
            ctx._baseline_hash = current_hash
            ctx._baseline_text = current_text
            return None

        # SequenceMatcher ratio: 1.0 = identical, 0.0 = nothing in common
        similarity = difflib.SequenceMatcher(
            None, ctx._baseline_text, current_text
        ).ratio()
        score = 1.0 - similarity

        return DriftResult(
            score=score,
            exceeded=score > ctx.policy.drift_threshold,
            threshold=ctx.policy.drift_threshold,
            baseline_hash=ctx._baseline_hash,
            current_hash=current_hash,
        )

    async def async_pre_execute(self, ctx: ExecutionContext, input_data: Any) -> tuple[bool, str | None]:
        """
        Async pre-execution policy check.

        Defaults to calling the sync version. Override in subclasses
        to add async-specific logic (e.g., async database lookups).
        """
        return self.pre_execute(ctx, input_data)

    async def async_post_execute(self, ctx: ExecutionContext, output_data: Any) -> tuple[bool, str | None]:
        """
        Async post-execution validation.

        Defaults to calling the sync version. Override in subclasses
        to add async-specific logic.
        """
        return self.post_execute(ctx, output_data)

    def on_signal(self, signal: str, handler: Callable[..., Any]) -> None:
        """Register a signal handler."""
        self._signal_handlers[signal] = handler

    def signal(self, agent_id: str, signal: str) -> None:
        """Send signal to agent."""
        if signal in self._signal_handlers:
            self._signal_handlers[signal](agent_id)


class AsyncGovernedWrapper:
    """
    Async wrapper that applies governance around an async callable.

    Uses asyncio.Lock for concurrent access control instead of threading.
    Calls async_pre_execute before and async_post_execute after the wrapped callable.
    """

    def __init__(self, integration: BaseIntegration, fn: Callable[..., Any], agent_id: str = "async-agent") -> None:
        self._integration = integration
        self._fn = fn
        self._ctx = integration.create_context(agent_id)
        self._lock = asyncio.Lock()

    @property
    def context(self) -> ExecutionContext:
        return self._ctx

    async def __call__(self, *args: Any, **kwargs: Any) -> Any:
        async with self._lock:
            # Pre-execution check
            allowed, reason = await self._integration.async_pre_execute(self._ctx, (args, kwargs))
            if not allowed:
                raise PolicyViolationError(reason or "Policy check failed")

            # Execute the wrapped callable
            result = await self._fn(*args, **kwargs)

            # Post-execution validation
            valid, reason = await self._integration.async_post_execute(self._ctx, result)
            if not valid:
                raise PolicyViolationError(reason or "Post-execution validation failed")

            return result


# Backward compatibility: import from the centralized exception hierarchy
from agent_os.exceptions import PolicyViolationError as PolicyViolationError  # noqa: F401
