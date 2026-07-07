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
import json
import logging
import re
import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import TYPE_CHECKING, Any, Callable, Literal, Mapping, Protocol

if TYPE_CHECKING:
    from agent_os.policies.decision import PolicyCheckResult

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Detection module configuration
# ---------------------------------------------------------------------------


class DetectionEnforcementAction(str, Enum):
    """Enforcement action taken when a detection module fires."""

    LOCK = "lock"    # Block the request and raise PolicyViolationError
    WARN = "warn"    # Log a warning but allow the request
    LOG = "log"      # Silently record to audit log only


@dataclass
class DetectionModuleConfig:
    """Per-module on/off and enforcement action.

    Each detection module that ``BaseIntegration`` auto-wires can be
    individually disabled or have its enforcement action overridden.
    Modules are opt-out: all are enabled by default. Set ``<module>_enabled``
    to ``False`` to skip a module entirely.

    Security modules default to ``LOCK`` (fail-closed).
    Advisory modules default to ``WARN``.
    """

    # Per-module enable/disable
    prompt_injection_enabled: bool = True
    token_budget_enabled: bool = True
    rate_limiter_enabled: bool = True
    bounded_semaphore_enabled: bool = True
    scope_guard_enabled: bool = True
    supply_chain_guard_enabled: bool = True
    mcp_security_scanner_enabled: bool = True

    # Per-module enforcement actions
    prompt_injection_action: DetectionEnforcementAction = DetectionEnforcementAction.LOCK
    token_budget_action: DetectionEnforcementAction = DetectionEnforcementAction.LOCK
    rate_limiter_action: DetectionEnforcementAction = DetectionEnforcementAction.LOCK
    scope_guard_action: DetectionEnforcementAction = DetectionEnforcementAction.WARN
    supply_chain_guard_action: DetectionEnforcementAction = DetectionEnforcementAction.LOCK
    mcp_security_action: DetectionEnforcementAction = DetectionEnforcementAction.LOCK


# Shared PII / secrets detection patterns reused by every framework
# adapter (LangChain, AutoGen, CrewAI, Bedrock, ...).
#
# Defined here as the single source of truth so adapters cannot silently
# drift apart when a new sensitive-data class is added or an existing
# pattern is broadened.  Stored as a tuple to prevent accidental
# mutation of a process-wide constant by adapter or test code.
#
# Patterns (in order):
#   0. U.S. Social Security Number.  Covers all common separator
#      variants — dash, space, dot, or none — so that ``123-45-6789``,
#      ``123 45 6789``, ``123.45.6789``, and ``123456789`` all match.
#      Mirrors the broadened SSN pattern used by the YAML policy packs
#      (see PR #2594 and issue #2469).
#   1. Email address (simple RFC-5322-ish match, sufficient for content
#      filtering — not for address validation).
#   2. Visa / Mastercard primary account number (PAN).  Visa: 13 or 16
#      digits with a leading ``4``; Mastercard: 16 digits with a leading
#      ``51``-``55``.  Other card brands (Amex, Discover, JCB) are
#      intentionally out of scope until we add full check-digit
#      validation; expand this entry alongside any such helper rather
#      than adding brittle prefix-only regexes here.
#   3. Inline credential assignment such as ``password=``, ``api_key:``,
#      ``token = ...``.  Case-insensitive, and accepts both ``api_key``
#      and ``api-key`` spellings.
#
# Adapters consume this tuple read-only via ``for pattern in PII_PATTERNS:``;
# new adapters MUST import from here and MUST NOT define a private copy.
# The name follows the repo convention (no leading underscore) for
# constants that are intentionally shared across modules.
PII_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b\d{3}[\s.-]?\d{2}[\s.-]?\d{4}\b"),                       # SSN
    re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),     # email
    re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14})\b"),          # credit card
    re.compile(r"\b(?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*\S+", re.IGNORECASE),  # secrets
)


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

    # Optional runtime module wiring sections (issue #2477)
    prompt_injection: dict[str, Any] = field(default_factory=dict)
    token_budget: dict[str, Any] = field(default_factory=dict)
    rate_limiter: dict[str, Any] = field(default_factory=dict)
    bounded_semaphore: dict[str, Any] = field(default_factory=dict)
    scope_guard: dict[str, Any] = field(default_factory=dict)
    supply_chain: dict[str, Any] = field(default_factory=dict)
    mcp_security: dict[str, Any] = field(default_factory=dict)

    @staticmethod
    def _freeze_mapping(value: Any) -> Any:
        """Recursively convert nested mappings/lists to hashable tuples."""
        if isinstance(value, dict):
            return tuple(
                (k, GovernancePolicy._freeze_mapping(v))
                for k, v in sorted(value.items(), key=lambda item: item[0])
            )
        if isinstance(value, list):
            return tuple(GovernancePolicy._freeze_mapping(v) for v in value)
        return value

    # Detection module configuration (opt-out per module)
    detection: DetectionModuleConfig = field(default_factory=DetectionModuleConfig)

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
                self._freeze_mapping(self.prompt_injection),
                self._freeze_mapping(self.token_budget),
                self._freeze_mapping(self.rate_limiter),
                self._freeze_mapping(self.bounded_semaphore),
                self._freeze_mapping(self.scope_guard),
                self._freeze_mapping(self.supply_chain),
                self._freeze_mapping(self.mcp_security),
            )
        )  # detection excluded from hash intentionally (mutable config object)

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

        # Validate optional module sections.
        for field_name in (
            "prompt_injection",
            "token_budget",
            "rate_limiter",
            "bounded_semaphore",
            "scope_guard",
            "supply_chain",
            "mcp_security",
        ):
            value = getattr(self, field_name)
            if not isinstance(value, dict):
                raise ValueError(
                    f"{field_name} must be a dict, got {type(value).__name__}"
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
            "prompt_injection": self.prompt_injection,
            "token_budget": self.token_budget,
            "rate_limiter": self.rate_limiter,
            "bounded_semaphore": self.bounded_semaphore,
            "scope_guard": self.scope_guard,
            "supply_chain": self.supply_chain,
            "mcp_security": self.mcp_security,
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
            "version", "prompt_injection", "token_budget", "rate_limiter",
            "bounded_semaphore", "scope_guard", "supply_chain", "mcp_security",
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
            "prompt_injection": self.prompt_injection,
            "token_budget": self.token_budget,
            "rate_limiter": self.rate_limiter,
            "bounded_semaphore": self.bounded_semaphore,
            "scope_guard": self.scope_guard,
            "supply_chain": self.supply_chain,
            "mcp_security": self.mcp_security,
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
            "prompt_injection", "token_budget", "rate_limiter",
            "bounded_semaphore", "scope_guard", "supply_chain", "mcp_security",
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
            "prompt_injection", "token_budget", "rate_limiter",
            "bounded_semaphore", "scope_guard", "supply_chain", "mcp_security",
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
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
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


@dataclass(frozen=True)
class SkillAuditMetadata:
    """Normalized skill metadata attached to audit events.

    Fields are additive and nullable so existing integrations can adopt this
    progressively without breaking older payload consumers.
    """

    skill_name: str | None = None
    skill_origin: str | None = None
    provenance_source_trust: Literal["trusted"] | None = None
    context_hash_before: str | None = None
    context_hash_after: str | None = None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "skill_name": self.skill_name,
            "skill_origin": self.skill_origin,
            "provenance_source_trust": self.provenance_source_trust,
            "context_hash_before": self.context_hash_before,
            "context_hash_after": self.context_hash_after,
        }


@dataclass(frozen=True)
class TrustedSkillMetadataSource:
    """Trusted framework-owned skill metadata source.

    Adapters must construct this only from framework metadata surfaces,
    never from user-controlled request payloads or tool arguments.

    Future: extend with verifiable attestations/signatures when framework
    runtimes expose portable trust claims. Tracked in #2907.
    """

    skill_name: str | None = None
    skill_origin: str | None = None


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
    - Call count within limits
    - Human approval requirement (require_human_approval)
    - Tool is in allowed_tools (if specified)
    - Arguments don't contain blocked patterns
    """

    def __init__(
        self,
        policy: GovernancePolicy,
        context: ExecutionContext | None = None,
        policy_bundle_hash: str | None = None,
    ):
        self.policy = policy
        self.context = context
        self.policy_bundle_hash = policy_bundle_hash

    def intercept(self, request: ToolCallRequest) -> ToolCallResult:
        from agent_os.policies.decision_factory import (
            deny_blocked_pattern_tool,
            deny_human_approval,
            deny_max_tool_calls,
            deny_not_allowed_tool,
        )

        # Check call count
        if self.context and self.context.call_count >= self.policy.max_tool_calls:
            result = deny_max_tool_calls(self.policy.max_tool_calls, self.context.call_count)
            return ToolCallResult(
                allowed=False,
                reason=result.reason,
            )

        # Check human approval requirement
        if self.policy.require_human_approval:
            result = deny_human_approval(request.tool_name)
            return ToolCallResult(
                allowed=False,
                reason=result.reason,
            )

        # Check allowed tools
        if self.policy.allowed_tools and request.tool_name not in self.policy.allowed_tools:
            result = deny_not_allowed_tool(request.tool_name, self.policy.allowed_tools)
            return ToolCallResult(
                allowed=False,
                reason=result.reason,
            )

        # Check blocked patterns
        args_str = str(request.arguments)
        matched = self.policy.matches_pattern(args_str)
        if matched:
            result = deny_blocked_pattern_tool(matched[0])
            return ToolCallResult(
                allowed=False,
                reason=result.reason,
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
        self._lock = threading.Lock()

    def try_acquire(self) -> tuple[bool, str | None]:
        """
        Try to acquire a slot.

        Returns (acquired, reason).
        """
        with self._lock:
            if self._active >= self.max_concurrent:
                self._total_rejected += 1
                return False, f"Max concurrency reached ({self.max_concurrent})"
            self._active += 1
            self._total_acquired += 1
            return True, None

    def release(self) -> None:
        """Release a slot."""
        with self._lock:
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
    - Cedar/OPA declarative policy evaluation
    - Flight recording
    - Signal handling
    """

    def __init__(
        self,
        policy: GovernancePolicy | None = None,
        evaluator: Any | None = None,
    ) -> None:
        self.policy: GovernancePolicy = policy or GovernancePolicy()
        self._evaluator: Any | None = evaluator
        self.contexts: dict[str, ExecutionContext] = {}
        self._signal_handlers: dict[str, Callable[..., Any]] = {}
        self._event_listeners: dict[GovernanceEventType, list[Callable[..., Any]]] = {}
        self._semaphore_held_sessions: set[str] = set()
        self._init_runtime_modules()

    @staticmethod
    def _is_module_enabled(config: dict[str, Any]) -> bool:
        """Return whether a runtime module section is enabled."""
        return bool(config.get("enabled"))

    @staticmethod
    def _extract_text_payload(input_data: Any) -> str:
        """Extract a best-effort textual payload for input scanners."""
        if isinstance(input_data, str):
            return input_data
        if isinstance(input_data, dict):
            for key in ("input", "input_text", "content", "message", "prompt"):
                value = input_data.get(key)
                if isinstance(value, str) and value:
                    return value
        return str(input_data)

    @staticmethod
    def _extract_token_usage(input_data: Any) -> tuple[int, int]:
        """Extract ``(prompt_tokens, completion_tokens)`` from common payload shapes."""
        if isinstance(input_data, dict):
            prompt = int(input_data.get("prompt_tokens", input_data.get("token_count", 0)) or 0)
            completion = int(input_data.get("completion_tokens", 0) or 0)
            total = int(input_data.get("total_tokens", 0) or 0)
            if total > 0 and prompt == 0 and completion == 0:
                prompt = total
            return prompt, completion
        return 0, 0

    def _init_runtime_modules(self) -> None:
        """Initialize optional runtime modules declared on the policy."""
        self._prompt_injection_detector: Any | None = None
        self._token_budget_tracker: Any | None = None
        self._rate_limiter: Any | None = None
        self._bounded_semaphore: BoundedSemaphore | None = None
        self._scope_guard: Any | None = None
        self._supply_chain_guard: Any | None = None
        self._mcp_security_scanner: Any | None = None

        if self._is_module_enabled(self.policy.prompt_injection):
            from agent_os.prompt_injection import DetectionConfig, PromptInjectionDetector

            config = DetectionConfig(
                sensitivity=str(self.policy.prompt_injection.get("sensitivity", "balanced")),
                blocklist=list(self.policy.prompt_injection.get("blocklist", [])),
                allowlist=list(self.policy.prompt_injection.get("allowlist", [])),
            )
            self._prompt_injection_detector = PromptInjectionDetector(config=config)

        if self._is_module_enabled(self.policy.token_budget):
            from .token_budget import TokenBudgetTracker

            warning_threshold = float(self.policy.token_budget.get("warning_threshold", 0.8))
            self._token_budget_tracker = TokenBudgetTracker(
                policy=self.policy,
                warning_threshold=warning_threshold,
            )

        if self._is_module_enabled(self.policy.rate_limiter):
            from .rate_limiter import RateLimiter

            self._rate_limiter = RateLimiter(
                max_calls=int(self.policy.rate_limiter.get("max_calls", self.policy.max_tool_calls)),
                time_window=float(self.policy.rate_limiter.get("time_window", 60.0)),
                per_agent=bool(self.policy.rate_limiter.get("per_agent", True)),
            )

        if self._is_module_enabled(self.policy.bounded_semaphore):
            self._bounded_semaphore = BoundedSemaphore(
                max_concurrent=int(
                    self.policy.bounded_semaphore.get("max_concurrent", self.policy.max_concurrent)
                ),
                backpressure_threshold=int(
                    self.policy.bounded_semaphore.get(
                        "backpressure_threshold",
                        self.policy.backpressure_threshold,
                    )
                ),
            )

        if self._is_module_enabled(self.policy.scope_guard):
            from .scope_guard import ScopeGuard

            self._scope_guard = ScopeGuard()

        if self._is_module_enabled(self.policy.supply_chain):
            try:
                from agent_compliance.supply_chain import SupplyChainConfig, SupplyChainGuard
            except ImportError:
                logger.warning(
                    "supply_chain.enabled=true but agent_compliance is unavailable; module disabled"
                )
            else:
                self._supply_chain_guard = SupplyChainGuard(
                    SupplyChainConfig(
                        freshness_days=int(self.policy.supply_chain.get("freshness_days", 7)),
                        allow_ranges=bool(self.policy.supply_chain.get("allow_ranges", False)),
                    )
                )

        if self._is_module_enabled(self.policy.mcp_security):
            from agent_os.mcp_security import MCPSecurityConfig, MCPSecurityScanner

            self._mcp_security_scanner = MCPSecurityScanner(config=MCPSecurityConfig())

        self._detection_modules: list[Any] = []
        self._register_detection_modules()

    def _release_semaphore_if_held(self, ctx: ExecutionContext) -> None:
        """Release a bounded-semaphore slot if this context currently holds one."""
        if self._bounded_semaphore is None:
            return
        if ctx.session_id in self._semaphore_held_sessions:
            self._bounded_semaphore.release()
            self._semaphore_held_sessions.remove(ctx.session_id)

    # ------------------------------------------------------------------
    # Detection module auto-registration  (#2477)
    # ------------------------------------------------------------------

    def _register_detection_modules(self) -> None:
        """Auto-register all installed detection modules based on policy config.

        Modules are opt-out: each is registered unless the corresponding
        detection.<module>_enabled flag is False. Modules whose package is not
        installed are silently skipped. Security modules default to LOCK
        enforcement; advisory modules default to WARN.
        """
        dcfg = self.policy.detection

        if dcfg.prompt_injection_enabled:
            try:
                from agent_os.prompt_injection import PromptInjectionDetector
                self._detection_modules.append((
                    "prompt_injection",
                    PromptInjectionDetector(),
                    dcfg.prompt_injection_action,
                ))
            except ImportError:
                logger.debug("PromptInjectionDetector not available")

        if dcfg.token_budget_enabled:
            try:
                from agent_os.integrations.token_budget import TokenBudgetTracker
                self._detection_modules.append((
                    "token_budget",
                    TokenBudgetTracker(policy=self.policy),
                    dcfg.token_budget_action,
                ))
            except ImportError:
                logger.debug("TokenBudgetTracker not available")

        if dcfg.rate_limiter_enabled:
            try:
                from agent_os.integrations.rate_limiter import RateLimiter
                self._detection_modules.append((
                    "rate_limiter",
                    RateLimiter(policy=self.policy),
                    dcfg.rate_limiter_action,
                ))
            except ImportError:
                logger.debug("RateLimiter not available")

        if dcfg.bounded_semaphore_enabled:
            # BoundedSemaphore is defined in this module; always available.
            self._detection_modules.append((
                "bounded_semaphore",
                BoundedSemaphore(
                    max_concurrent=self.policy.max_concurrent,
                    backpressure_threshold=self.policy.backpressure_threshold,
                ),
                DetectionEnforcementAction.LOCK,
            ))

        if dcfg.scope_guard_enabled:
            try:
                from agent_os.integrations.scope_guard import ScopeGuard
                self._detection_modules.append((
                    "scope_guard",
                    ScopeGuard(),
                    dcfg.scope_guard_action,
                ))
            except ImportError:
                logger.debug("ScopeGuard not available")

        if dcfg.supply_chain_guard_enabled:
            try:
                from agent_compliance.supply_chain import SupplyChainGuard  # type: ignore[import]
                self._detection_modules.append((
                    "supply_chain_guard",
                    SupplyChainGuard(),
                    dcfg.supply_chain_guard_action,
                ))
            except ImportError:
                logger.debug("SupplyChainGuard not available")

        if dcfg.mcp_security_scanner_enabled:
            try:
                from agent_os.mcp_security import MCPSecurityScanner
                self._detection_modules.append((
                    "mcp_security_scanner",
                    MCPSecurityScanner(),
                    dcfg.mcp_security_action,
                ))
            except ImportError:
                logger.debug("MCPSecurityScanner not available")

        logger.debug(
            "BaseIntegration: %d detection module(s) registered: %s",
            len(self._detection_modules),
            [n for n, _, _ in self._detection_modules],
        )

    def _run_detection_modules(
        self,
        ctx: ExecutionContext,
        input_data: Any,
    ) -> tuple[bool, str]:
        """Run all registered detection modules against input_data.

        Returns (allowed, reason). The first LOCK module that fires denies the
        request. WARN and LOG modules are recorded but do not block.

        Fail-closed: if a detection module raises, access is denied.
        """
        input_str = str(input_data)

        for module_name, module, action in self._detection_modules:
            try:
                blocked = False
                reason = ""

                if module_name == "prompt_injection":
                    result = module.detect(input_str, source=ctx.agent_id)
                    if result.is_injection:
                        blocked = True
                        reason = "Prompt injection detected: " + result.explanation

                elif module_name == "token_budget":
                    status = module.check_budget(ctx.agent_id)
                    if status.is_exceeded:
                        blocked = True
                        reason = (
                            "Token budget exceeded: "
                            + str(status.used)
                            + "/"
                            + str(status.limit)
                            + " tokens"
                        )

                elif module_name == "rate_limiter":
                    if not module.allow(ctx.agent_id):
                        blocked = True
                        reason = "Rate limit exceeded for agent " + repr(ctx.agent_id)

                elif module_name == "bounded_semaphore":
                    acquired, sem_reason = module.try_acquire()
                    if not acquired:
                        blocked = True
                        reason = "Concurrency limit: " + (sem_reason or "")
                    else:
                        module.release()

                elif module_name == "mcp_security_scanner":
                    if (
                        isinstance(input_data, dict)
                        and "name" in input_data
                        and "description" in input_data
                    ):
                        threats = module.scan_tool(
                            input_data["name"],
                            input_data["description"],
                            schema=input_data.get("inputSchema"),
                            server_name=input_data.get("server_name", "unknown"),
                        )
                        critical = [
                            t for t in threats if t.severity.value == "critical"
                        ]
                        if critical:
                            blocked = True
                            reason = "MCP security threat: " + critical[0].message

                if blocked:
                    if action == DetectionEnforcementAction.LOCK:
                        logger.warning(
                            "Detection module %r blocked agent=%s: %s",
                            module_name, ctx.agent_id, reason,
                        )
                        return False, reason
                    elif action == DetectionEnforcementAction.WARN:
                        logger.warning(
                            "Detection module %r warned agent=%s: %s",
                            module_name, ctx.agent_id, reason,
                        )
                    else:
                        logger.info(
                            "Detection module %r logged agent=%s: %s",
                            module_name, ctx.agent_id, reason,
                        )

            except Exception as exc:
                logger.error(
                    "Detection module %r raised exception (fail-closed): %s",
                    module_name, exc, exc_info=True,
                )
                return (
                    False,
                    "Detection module " + repr(module_name) + " error (fail-closed): " + str(exc),
                )

        return True, ""


    # ------------------------------------------------------------------
    # Cedar / PolicyEvaluator integration
    # ------------------------------------------------------------------

    def _build_cedar_context(
        self,
        *,
        agent_id: str = "",
        action_type: str = "",
        tool_name: str = "",
        tool_args: dict[str, Any] | None = None,
        **extra: Any,
    ) -> dict[str, Any]:
        """Build a context dict for PolicyEvaluator/CedarBackend.

        Constructs the principal/action/resource triple that Cedar and OPA
        backends expect.  Subclasses should override this method to add
        framework-specific fields (e.g. token budgets, handoff counts).

        Args:
            agent_id: The agent identifier (maps to Cedar principal).
            action_type: ``"tool_call"``, ``"model_call"``, ``"handoff"``.
            tool_name: Name of the tool being invoked.
            tool_args: Tool arguments for context enrichment.
            **extra: Additional framework-specific context fields.

        Returns:
            A context dict consumable by ``PolicyEvaluator.evaluate()``.
        """
        return {
            "agent_id": agent_id,
            "action_type": action_type,
            "tool_name": tool_name,
            "tool_args": tool_args or {},
            **extra,
        }

    def _evaluate_policy(
        self,
        context: dict[str, Any],
    ) -> tuple[bool, str]:
        """Consult the PolicyEvaluator if one is configured.

        Returns ``(allowed, reason)``.  When no evaluator is set, returns
        ``(True, "")`` so callers can fall through to ``GovernancePolicy``
        checks.

        **Fail-closed**: if the evaluator raises an exception, access is
        denied.  This ensures that a misconfigured policy engine never
        silently permits an action.
        """
        if self._evaluator is None:
            return True, ""

        try:
            decision = self._evaluator.evaluate(context)
            if not decision.allowed:
                return False, decision.reason or "Policy denied by evaluator"
            return True, ""
        except Exception as exc:
            logger.error(
                "PolicyEvaluator error — denying access (fail-closed): %s",
                exc,
                exc_info=True,
            )
            return False, f"Policy evaluation error (fail-closed): {exc}"

    @classmethod
    def from_cedar(
        cls,
        policy_path: str | None = None,
        policy_content: str | None = None,
        entities: list[dict[str, Any]] | None = None,
        **kwargs: Any,
    ) -> BaseIntegration:
        """Create an integration with Cedar policy evaluation.

        Convenience factory that configures a ``PolicyEvaluator`` with a
        ``CedarBackend`` and passes it to the constructor.  All standard
        kwargs are forwarded to ``__init__``.

        Example::

            kernel = CrewAIKernel.from_cedar(
                policy_path="policies/governance.cedar",
            )

        Args:
            policy_path: Path to a ``.cedar`` policy file.
            policy_content: Inline Cedar policy string.
            entities: Cedar entities for authorization context.
            **kwargs: Forwarded to ``cls.__init__``.

        Returns:
            A configured integration with Cedar evaluation enabled.
        """
        from agent_os.policies.evaluator import PolicyEvaluator

        evaluator = PolicyEvaluator()
        evaluator.load_cedar(
            policy_path=policy_path,
            policy_content=policy_content,
            entities=entities,
        )
        return cls(evaluator=evaluator, **kwargs)

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

    @staticmethod
    def hash_context(context: Any) -> str | None:
        """Return a deterministic SHA-256 hash for canonically serializable context.

        This is a lightweight, best-effort fingerprint for observability.
        It is not a cryptographic provenance guarantee.
        """
        if context is None:
            return None

        try:
            canonical = json.dumps(
                context,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            )
        except Exception:
            logger.debug(
                "Unable to canonicalize context for hashing (type=%s)",
                type(context).__name__,
                exc_info=True,
            )
            # Fail-safe: non-canonical payloads should not produce hashes.
            return None

        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @staticmethod
    def trusted_skill_metadata_source(
        *,
        skill_name: Any = None,
        skill_origin: Any = None,
    ) -> TrustedSkillMetadataSource | None:
        """Create a trusted metadata source from explicit framework-owned values."""

        def _pick_string(value: Any) -> str | None:
            if isinstance(value, str):
                normalized = value.strip()
                return normalized or None
            return None

        parsed_name = _pick_string(skill_name)
        parsed_origin = _pick_string(skill_origin)
        if parsed_name is None and parsed_origin is None:
            return None

        return TrustedSkillMetadataSource(
            skill_name=parsed_name,
            skill_origin=parsed_origin,
        )

    @staticmethod
    def trusted_skill_metadata_from_mapping(
        metadata: Mapping[str, Any] | None,
        *,
        skill_name_key: str = "skill_name",
        skill_origin_key: str = "skill_origin",
    ) -> TrustedSkillMetadataSource | None:
        """Build trusted metadata from an explicitly designated framework mapping.

        Callers must pass only framework-owned metadata maps.
        Arbitrary request/argument dictionaries are out of scope by design.
        """
        if not isinstance(metadata, Mapping):
            return None
        return BaseIntegration.trusted_skill_metadata_source(
            skill_name=metadata.get(skill_name_key),
            skill_origin=metadata.get(skill_origin_key),
        )

    @staticmethod
    def trusted_sources(
        *sources: TrustedSkillMetadataSource | None,
    ) -> tuple[TrustedSkillMetadataSource, ...]:
        """Return only non-null trusted metadata sources."""
        return tuple(source for source in sources if source is not None)

    @staticmethod
    def trusted_sources_from_attrs(
        *objs: Any,
    ) -> tuple[TrustedSkillMetadataSource, ...]:
        """Extract trusted metadata sources from objects exposing skill attrs."""
        return BaseIntegration.trusted_sources(
            *(
                BaseIntegration.trusted_skill_metadata_source(
                    skill_name=getattr(obj, "skill_name", None),
                    skill_origin=getattr(obj, "skill_origin", None),
                )
                for obj in objs
            )
        )

    @staticmethod
    def extract_skill_metadata(
        *,
        trusted_sources: tuple[TrustedSkillMetadataSource, ...] = (),
        sources: tuple[Any, ...] = (),
        default_origin: str | None = None,
    ) -> SkillAuditMetadata:
        """Extract skill metadata from trusted framework-owned sources only.

        Trust boundary: this method intentionally ignores user-controlled data.
        """

        skill_name: str | None = None
        skill_origin: str | None = None

        # Backward-compatible bridge: only explicitly trusted wrappers from
        # legacy ``sources`` are accepted.
        merged_trusted_sources = list(trusted_sources)
        for source in sources:
            if isinstance(source, TrustedSkillMetadataSource):
                merged_trusted_sources.append(source)

        for source in merged_trusted_sources:
            if skill_name is None and source.skill_name is not None:
                skill_name = source.skill_name
            if skill_origin is None and source.skill_origin is not None:
                skill_origin = source.skill_origin

        if skill_name and not skill_origin and default_origin:
            skill_origin = default_origin

        provenance_source_trust: Literal["trusted"] | None = "trusted" if skill_name else None

        return SkillAuditMetadata(
            skill_name=skill_name,
            skill_origin=skill_origin,
            provenance_source_trust=provenance_source_trust,
        )

    def build_skill_audit_fields(
        self,
        *,
        trusted_sources: tuple[TrustedSkillMetadataSource, ...] = (),
        sources: tuple[Any, ...] = (),
        default_origin: str | None = None,
        context_before: Any | None = None,
        context_after: Any | None = None,
    ) -> dict[str, str | None]:
        """Build normalized skill-audit fields for adapter audit payloads."""
        metadata = self.extract_skill_metadata(
            trusted_sources=trusted_sources,
            sources=sources,
            default_origin=default_origin,
        )
        return SkillAuditMetadata(
            skill_name=metadata.skill_name,
            skill_origin=metadata.skill_origin,
            provenance_source_trust=metadata.provenance_source_trust,
            context_hash_before=self.hash_context(context_before),
            context_hash_after=self.hash_context(context_after),
        ).to_dict()

    def emit_skill_audit_event(
        self,
        event_type: GovernanceEventType,
        *,
        agent_id: str,
        action: str,
        trusted_sources: tuple[TrustedSkillMetadataSource, ...] = (),
        sources: tuple[Any, ...] = (),
        default_origin: str | None = None,
        context_before: Any | None = None,
        context_after: Any | None = None,
        **extra: Any,
    ) -> dict[str, Any]:
        """Emit a centralized skill-aware governance audit payload.

        Emission happens in governance middleware/hooks (outside skill loading
        or execution internals) so malformed skills cannot suppress audit
        generation.
        """
        payload: dict[str, Any] = {
            "agent_id": agent_id,
            "action": action,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            **self.build_skill_audit_fields(
                trusted_sources=trusted_sources,
                sources=sources,
                default_origin=default_origin,
                context_before=context_before,
                context_after=context_after,
            ),
            **extra,
        }
        self.emit(event_type, payload)
        return payload

    def pre_execute_check(self, ctx: ExecutionContext, input_data: Any) -> PolicyCheckResult:
        """Run pre-execution policy checks and return a structured result.

        Args:
            ctx: Execution context for the governed operation.
            input_data: Input payload to validate before execution.

        Returns:
            A structured policy-check result.
        """
        from agent_os.policies.decision import PolicyCheckResult
        from agent_os.policies.decision_factory import (
            deny_blocked_pattern_input,
            deny_confidence_threshold,
            deny_human_approval,
            deny_max_tool_calls,
            deny_policy_error,
            deny_timeout,
        )

        event_base = {"agent_id": ctx.agent_id, "timestamp": datetime.now(timezone.utc).isoformat()}

        self.emit(GovernanceEventType.POLICY_CHECK, {**event_base, "phase": "pre_execute"})

        # ── Cedar / PolicyEvaluator gate (runs first) ──────────────
        if self._evaluator is not None:
            # Extract tool identity from input_data when available so
            # Cedar policies can gate on tool_name / tool_args.
            _tool_name = ""
            _tool_args: dict[str, Any] = {}
            if isinstance(input_data, dict):
                _tool_name = input_data.get("tool_name", "")
                _tool_args = input_data.get("tool_args", {})
            elif hasattr(input_data, "tool_name"):
                _tool_name = getattr(input_data, "tool_name", "")
                _tool_args = getattr(input_data, "tool_args", {}) or {}

            cedar_ctx = self._build_cedar_context(
                agent_id=ctx.agent_id,
                action_type="tool_call",
                tool_name=_tool_name,
                tool_args=_tool_args,
            )
            allowed, reason = self._evaluate_policy(cedar_ctx)
            if not allowed:
                result = deny_policy_error(reason)
                self.emit(
                    GovernanceEventType.TOOL_CALL_BLOCKED,
                    {**event_base, "reason": result.reason, "source": "cedar"},
                )
                return result

        # Check call count.
        #
        # The legacy ``max_tool_calls`` budget runs *before* the detection
        # module gate below.  The auto-wired ``rate_limiter`` detection
        # module governs the same dimension (its bucket size defaults to
        # ``max_tool_calls``), so without this ordering the rate limiter
        # would intercept the over-budget call first and report
        # "Rate limit exceeded" instead of the canonical "Max tool calls"
        # reason that callers and tests depend on.  Running the legacy
        # check first preserves the documented public reason while keeping
        # the rate limiter active for time-window based throttling.
        if ctx.call_count >= ctx.policy.max_tool_calls:
            self._release_semaphore_if_held(ctx)
            result = deny_max_tool_calls(ctx.policy.max_tool_calls, ctx.call_count)
            self.emit(
                GovernanceEventType.POLICY_VIOLATION,
                {**event_base, "reason": result.reason},
            )
            return result

        # Check timeout.
        # Normalize start_time to UTC-aware if it is naive (e.g. set by an external
        # caller before the default factory was made tz-aware) so the subtraction
        # never raises TypeError for mixed-awareness datetimes.
        # astimezone() correctly interprets the naive datetime as local time and
        # converts it to UTC, unlike replace() which would just label it UTC without
        # adjusting the value.
        start = ctx.start_time
        if start.tzinfo is None:
            start = start.astimezone(timezone.utc)
        elapsed = (datetime.now(timezone.utc) - start).total_seconds()
        if elapsed > ctx.policy.timeout_seconds:
            self._release_semaphore_if_held(ctx)
            result = deny_timeout(ctx.policy.timeout_seconds, elapsed)
            self.emit(
                GovernanceEventType.POLICY_VIOLATION,
                {**event_base, "reason": result.reason},
            )
            return result

        # Check blocked patterns
        input_str = str(input_data)
        matched = ctx.policy.matches_pattern(input_str)
        if matched:
            self._release_semaphore_if_held(ctx)
            result = deny_blocked_pattern_input(matched[0], input_str)
            self.emit(
                GovernanceEventType.TOOL_CALL_BLOCKED,
                {**event_base, "reason": result.reason, "pattern": matched[0]},
            )
            return result

        # Check human approval requirement
        if ctx.policy.require_human_approval:
            self._release_semaphore_if_held(ctx)
            result = deny_human_approval()
            self.emit(
                GovernanceEventType.POLICY_VIOLATION,
                {**event_base, "reason": result.reason},
            )
            return result

        # Check confidence threshold
        if ctx.policy.confidence_threshold > 0.0:
            confidence = getattr(input_data, "confidence", None)
            if isinstance(confidence, (int, float)) and confidence < ctx.policy.confidence_threshold:
                self._release_semaphore_if_held(ctx)
                result = deny_confidence_threshold(ctx.policy.confidence_threshold, confidence)
                self.emit(
                    GovernanceEventType.POLICY_VIOLATION,
                    {**event_base, "reason": result.reason},
                )
                return result

        if self._rate_limiter is not None and not self._rate_limiter.allow(ctx.agent_id):
            self._release_semaphore_if_held(ctx)
            result = deny_policy_error("Rate limit exceeded")
            self.emit(
                GovernanceEventType.POLICY_VIOLATION,
                {**event_base, "reason": result.reason},
            )
            return result

        if self._prompt_injection_detector is not None:
            text_payload = self._extract_text_payload(input_data)
            detection = self._prompt_injection_detector.detect(
                text_payload,
                source=f"integration:{ctx.agent_id}",
            )
            if detection.is_injection:
                self._release_semaphore_if_held(ctx)
                result = deny_policy_error(
                    f"Prompt injection detected ({detection.threat_level.value}): "
                    f"{detection.explanation}"
                )
                self.emit(
                    GovernanceEventType.TOOL_CALL_BLOCKED,
                    {
                        **event_base,
                        "reason": result.reason,
                        "source": "prompt_injection",
                    },
                )
                return result

        if self._token_budget_tracker is not None:
            prompt_tokens, completion_tokens = self._extract_token_usage(input_data)
            if prompt_tokens > 0 or completion_tokens > 0:
                budget_status = self._token_budget_tracker.record_usage(
                    ctx.agent_id, prompt_tokens, completion_tokens
                )
                if budget_status.is_exceeded:
                    self._release_semaphore_if_held(ctx)
                    result = deny_policy_error(
                        f"Token budget exceeded ({budget_status.used}/{budget_status.limit})"
                    )
                    self.emit(
                        GovernanceEventType.POLICY_VIOLATION,
                        {**event_base, "reason": result.reason, "source": "token_budget"},
                    )
                    return result

        if self._scope_guard is not None and isinstance(input_data, dict):
            from .scope_guard import ScopeConfig

            changed_files = input_data.get("changed_files")
            insertions = input_data.get("insertions")
            deletions = input_data.get("deletions")
            if (
                isinstance(changed_files, list)
                and isinstance(insertions, int)
                and isinstance(deletions, int)
            ):
                cfg = ScopeConfig(
                    max_files=int(self.policy.scope_guard.get("max_files", 10)),
                    max_lines=int(self.policy.scope_guard.get("max_lines", 500)),
                    mode=str(self.policy.scope_guard.get("mode", "on")),
                    drift_detection=bool(self.policy.scope_guard.get("drift_detection", True)),
                )
                scope_eval = self._scope_guard.evaluate(
                    agent_id=ctx.agent_id,
                    config=cfg,
                    changed_files=changed_files,
                    insertions=insertions,
                    deletions=deletions,
                    drift_indicators=input_data.get("drift_indicators"),
                )
                if scope_eval.decision != "PASS":
                    self._release_semaphore_if_held(ctx)
                    result = deny_policy_error(
                        f"Scope guard {scope_eval.decision}: {scope_eval.reason}"
                    )
                    self.emit(
                        GovernanceEventType.POLICY_VIOLATION,
                        {**event_base, "reason": result.reason, "source": "scope_guard"},
                    )
                    return result

        if self._supply_chain_guard is not None and isinstance(input_data, dict):
            scan_path = input_data.get("supply_chain_path")
            if isinstance(scan_path, str) and scan_path:
                findings = self._supply_chain_guard.scan_directory(scan_path)
                blocking = [f for f in findings if f.severity in {"critical", "high"}]
                if blocking:
                    self._release_semaphore_if_held(ctx)
                    result = deny_policy_error(
                        f"Supply chain guard blocked: {blocking[0].message}"
                    )
                    self.emit(
                        GovernanceEventType.POLICY_VIOLATION,
                        {**event_base, "reason": result.reason, "source": "supply_chain"},
                    )
                    return result

        if self._mcp_security_scanner is not None and isinstance(input_data, dict):
            tool = input_data.get("mcp_tool")
            if isinstance(tool, dict):
                threats = self._mcp_security_scanner.scan_tool(
                    tool_name=str(tool.get("name", "unknown")),
                    description=str(tool.get("description", "")),
                    schema=tool.get("inputSchema"),
                    server_name=str(input_data.get("mcp_server_name", "unknown")),
                )
                if threats:
                    self._release_semaphore_if_held(ctx)
                    result = deny_policy_error(
                        f"MCP security scanner blocked tool: {threats[0].message}"
                    )
                    self.emit(
                        GovernanceEventType.TOOL_CALL_BLOCKED,
                        {**event_base, "reason": result.reason, "source": "mcp_security"},
                    )
                    return result

        # ── Detection module gate (#2477) ──────────────────────────
        #
        # Runs as a backstop *after* the legacy budget and the explicitly
        # configured runtime modules above.  The auto-wired detection
        # modules (prompt_injection, token_budget, rate_limiter,
        # mcp_security_scanner, ...) cover the same dimensions as those
        # legacy checks, so running them last ensures that when a caller
        # opts a legacy module in via the policy, that module's specific
        # reason wins.  Detection modules still catch any dimension not
        # already governed by an enabled legacy module.
        det_allowed, det_reason = self._run_detection_modules(ctx, input_data)
        if not det_allowed:
            self._release_semaphore_if_held(ctx)
            result = deny_policy_error(det_reason)
            self.emit(
                GovernanceEventType.TOOL_CALL_BLOCKED,
                {**event_base, "reason": det_reason, "source": "detection_module"},
            )
            return result

        if self._bounded_semaphore is not None:
            acquired, reason = self._bounded_semaphore.try_acquire()
            if not acquired:
                result = deny_policy_error(reason or "Concurrency guard denied request")
                self.emit(
                    GovernanceEventType.POLICY_VIOLATION,
                    {**event_base, "reason": result.reason, "source": "bounded_semaphore"},
                )
                return result
            self._semaphore_held_sessions.add(ctx.session_id)

        return PolicyCheckResult()

    def pre_execute(self, ctx: ExecutionContext, input_data: Any) -> tuple[bool, str | None]:
        """Run pre-execution policy checks and return the legacy tuple.

        Args:
            ctx: Execution context for the governed operation.
            input_data: Input payload to validate before execution.

        Returns:
            The legacy ``(allowed, reason)`` tuple.
        """

        return self.pre_execute_check(ctx, input_data).to_legacy_tuple()

    def post_execute_check(self, ctx: ExecutionContext, output_data: Any) -> PolicyCheckResult:
        """Run post-execution validation and return a structured result.

        Args:
            ctx: Execution context for the governed operation.
            output_data: Output payload to validate after execution.

        Returns:
            A structured policy-check result.
        """
        from agent_os.policies.decision import PolicyCheckResult

        ctx.call_count += 1
        self._release_semaphore_if_held(ctx)

        if self._token_budget_tracker is not None:
            prompt_tokens, completion_tokens = self._extract_token_usage(output_data)
            if prompt_tokens > 0 or completion_tokens > 0:
                self._token_budget_tracker.record_usage(ctx.agent_id, prompt_tokens, completion_tokens)

        # Drift detection: compare output against baseline
        if ctx.policy.drift_threshold > 0.0:
            drift_result = self.compute_drift(ctx, output_data)
            if drift_result is not None:
                ctx._drift_scores.append(drift_result.score)
                if drift_result.exceeded:
                    reason = (
                        f"Drift score {drift_result.score:.2f} exceeds threshold "
                        f"{ctx.policy.drift_threshold:.2f}"
                    )
                    logger.warning(
                        "Drift detected agent=%s score=%.4f threshold=%.2f",
                        ctx.agent_id,
                        drift_result.score,
                        drift_result.threshold,
                    )
                    self.emit(GovernanceEventType.DRIFT_DETECTED, {
                        "agent_id": ctx.agent_id,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
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
        if ctx.call_count % ctx.policy.checkpoint_frequency == 0:
            checkpoint_id = f"checkpoint-{ctx.call_count}"
            ctx.checkpoints.append(checkpoint_id)
            self.emit(GovernanceEventType.CHECKPOINT_CREATED, {
                "agent_id": ctx.agent_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "checkpoint_id": checkpoint_id,
                "call_count": ctx.call_count,
            })

        return PolicyCheckResult()

    def post_execute(self, ctx: ExecutionContext, output_data: Any) -> tuple[bool, str | None]:
        """Run post-execution validation and return the legacy tuple.

        Args:
            ctx: Execution context for the governed operation.
            output_data: Output payload to validate after execution.

        Returns:
            The legacy ``(valid, reason)`` tuple.
        """

        return self.post_execute_check(ctx, output_data).to_legacy_tuple()

    @staticmethod
    def compute_drift(ctx: ExecutionContext, output_data: Any) -> DriftResult | None:
        """Compute drift between *output_data* and the baseline stored in *ctx*.

        On the first call the output is recorded as the baseline and ``None``
        is returned (no comparison possible). Subsequent calls use
        ``SequenceMatcher`` to compute a similarity ratio between the
        serialised baseline and the current output. The drift score is
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

    async def async_pre_execute_check(
        self,
        ctx: ExecutionContext,
        input_data: Any,
    ) -> PolicyCheckResult:
        """Run async pre-execution policy checks and return a structured result.

        Args:
            ctx: Execution context for the governed operation.
            input_data: Input payload to validate before execution.

        Returns:
            A structured policy-check result.
        """

        return self.pre_execute_check(ctx, input_data)

    async def async_pre_execute(
        self,
        ctx: ExecutionContext,
        input_data: Any,
    ) -> tuple[bool, str | None]:
        """Run async pre-execution policy checks and return the legacy tuple.

        Args:
            ctx: Execution context for the governed operation.
            input_data: Input payload to validate before execution.

        Returns:
            The legacy ``(allowed, reason)`` tuple.
        """

        result = await self.async_pre_execute_check(ctx, input_data)
        return result.to_legacy_tuple()

    async def async_post_execute_check(
        self,
        ctx: ExecutionContext,
        output_data: Any,
    ) -> PolicyCheckResult:
        """Run async post-execution validation and return a structured result.

        Args:
            ctx: Execution context for the governed operation.
            output_data: Output payload to validate after execution.

        Returns:
            A structured policy-check result.
        """

        return self.post_execute_check(ctx, output_data)

    async def async_post_execute(
        self,
        ctx: ExecutionContext,
        output_data: Any,
    ) -> tuple[bool, str | None]:
        """Run async post-execution validation and return the legacy tuple.

        Args:
            ctx: Execution context for the governed operation.
            output_data: Output payload to validate after execution.

        Returns:
            The legacy ``(valid, reason)`` tuple.
        """

        result = await self.async_post_execute_check(ctx, output_data)
        return result.to_legacy_tuple()

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
            pre_result = await self._integration.async_pre_execute_check(self._ctx, (args, kwargs))
            if not pre_result.allowed:
                raise PolicyViolationError(pre_result.reason or "Policy check failed")

            # Execute the wrapped callable. Wrap in try/finally so that a
            # bounded-semaphore slot acquired during pre_execute_check is always
            # released even when the wrapped callable raises. Without this the
            # slot leaks permanently and repeated failures exhaust max_concurrent,
            # deadlocking the integration into denying every subsequent request.
            try:
                result = await self._fn(*args, **kwargs)
            except BaseException:
                self._integration._release_semaphore_if_held(self._ctx)
                raise

            # Post-execution validation (this also releases the semaphore slot).
            post_result = await self._integration.async_post_execute_check(self._ctx, result)
            if not post_result.allowed:
                raise PolicyViolationError(post_result.reason or "Post-execution validation failed")

            return result


# Backward compatibility: import from the centralized exception hierarchy
from agent_os.exceptions import PolicyViolationError as PolicyViolationError  # noqa: E402, F401
