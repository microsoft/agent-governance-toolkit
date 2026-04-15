# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""AGT Lite — Zero-config governance in 3 lines.

The full Agent OS is powerful but heavy (530 files, 42s import).
AGT Lite is the lightweight alternative: single import, inline rules,
no YAML, no external deps beyond pydantic. Designed for the developer
who just wants to add basic governance without learning the full stack.

Usage:
    from agent_os.lite import govern

    # One line to create a governance function
    check = govern(allow=["read_file", "web_search"], deny=["execute_code", "delete_file"])

    # One line to check any action
    check("read_file")      # returns True
    check("execute_code")   # raises GovernanceViolation

    # Or use the non-raising version
    check.is_allowed("execute_code")  # returns False

That's it. No YAML, no PolicyEvaluator, no 42-second import.
Upgrade to the full stack when you need trust mesh, SRE, or compliance.
"""

from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Any


class GovernanceViolation(Exception):
    """Raised when an action is blocked by governance policy."""

    def __init__(self, action: str, reason: str) -> None:
        self.action = action
        self.reason = reason
        super().__init__(f"Governance violation: '{action}' — {reason}")


class GovernanceDecision:
    """Result of a governance check."""

    __slots__ = ("action", "allowed", "reason", "timestamp", "latency_ms")

    def __init__(self, action: str, allowed: bool, reason: str, latency_ms: float) -> None:
        self.action = action
        self.allowed = allowed
        self.reason = reason
        self.timestamp = datetime.now(timezone.utc)
        self.latency_ms = latency_ms


class LiteGovernor:
    """Lightweight, zero-config governance gate.

    Rules:
    1. If action is in `deny` list → BLOCKED
    2. If action matches a `deny_patterns` regex → BLOCKED
    3. If `allow` list is set and action is NOT in it → BLOCKED
    4. If content matches `blocked_content` patterns → BLOCKED
    5. Otherwise → ALLOWED

    Deny takes priority over allow (fail-secure).
    """

    def __init__(
        self,
        allow: list[str] | None = None,
        deny: list[str] | None = None,
        deny_patterns: list[str] | None = None,
        blocked_content: list[str] | None = None,
        escalate: list[str] | None = None,
        max_calls: int = 0,
        log: bool = True,
    ) -> None:
        self._allow = set(allow) if allow else None
        self._deny = set(deny or [])
        self._deny_patterns = [re.compile(p) for p in (deny_patterns or [])]
        self._blocked_content = [re.compile(p) for p in (blocked_content or [])]
        self._escalate = set(escalate or [])
        self._max_calls = max_calls
        self._log = log
        self._call_count = 0
        self._audit: list[GovernanceDecision] = []

    def __call__(self, action: str, content: str = "", **context: Any) -> bool:
        """Check if action is allowed. Raises GovernanceViolation if not."""
        decision = self.evaluate(action, content, **context)
        if not decision.allowed:
            raise GovernanceViolation(action, decision.reason)
        return True

    def is_allowed(self, action: str, content: str = "", **context: Any) -> bool:
        """Check if action is allowed. Returns bool (non-raising)."""
        return self.evaluate(action, content, **context).allowed

    def evaluate(self, action: str, content: str = "", **context: Any) -> GovernanceDecision:
        """Evaluate an action against policy. Returns GovernanceDecision."""
        start = time.perf_counter()

        # Rate limit check
        if self._max_calls > 0:
            self._call_count += 1
            if self._call_count > self._max_calls:
                return self._decide(action, False, f"Rate limit exceeded ({self._max_calls} max)", start)

        # Deny list (highest priority)
        if action in self._deny:
            return self._decide(action, False, f"Action '{action}' is explicitly denied", start)

        # Deny patterns
        for pattern in self._deny_patterns:
            if pattern.search(action):
                return self._decide(action, False, f"Action '{action}' matches deny pattern", start)

        # Content check
        if content:
            for pattern in self._blocked_content:
                if pattern.search(content):
                    return self._decide(action, False, "Content matches blocked pattern", start)

        # Allow list (if set, only listed actions are allowed)
        if self._allow is not None and action not in self._allow:
            return self._decide(action, False, f"Action '{action}' not in allow list", start)

        return self._decide(action, True, "Allowed by policy", start)

    @property
    def audit_trail(self) -> list[GovernanceDecision]:
        """Get all governance decisions made."""
        return list(self._audit)

    @property
    def stats(self) -> dict[str, Any]:
        """Get governance statistics."""
        total = len(self._audit)
        allowed = sum(1 for d in self._audit if d.allowed)
        denied = total - allowed
        avg_latency = (
            sum(d.latency_ms for d in self._audit) / total if total else 0
        )
        return {
            "total": total,
            "allowed": allowed,
            "denied": denied,
            "violation_rate": f"{denied/total*100:.1f}%" if total else "0%",
            "avg_latency_ms": f"{avg_latency:.3f}",
        }

    def _decide(
        self, action: str, allowed: bool, reason: str, start: float
    ) -> GovernanceDecision:
        latency_ms = (time.perf_counter() - start) * 1000
        decision = GovernanceDecision(action, allowed, reason, latency_ms)
        if self._log:
            self._audit.append(decision)
        return decision


def govern(
    allow: list[str] | None = None,
    deny: list[str] | None = None,
    deny_patterns: list[str] | None = None,
    blocked_content: list[str] | None = None,
    escalate: list[str] | None = None,
    max_calls: int = 0,
    log: bool = True,
) -> LiteGovernor:
    """Create a lightweight governance gate.

    Args:
        allow: Actions to allow (allowlist). If set, only these actions pass.
        deny: Actions to explicitly deny (takes priority over allow).
        deny_patterns: Regex patterns to deny.
        blocked_content: Regex patterns to block in content.
        escalate: Actions that require human approval (logged as denied).
        max_calls: Max total calls before rate limiting (0 = unlimited).
        log: Whether to keep audit trail.

    Returns:
        A LiteGovernor callable. Use as: `check("action_name")`

    Examples:
        # Minimal — block dangerous, allow everything else
        check = govern(deny=["execute_code", "delete_file", "ssh_connect"])

        # Allowlist — only permit specific actions
        check = govern(allow=["read_file", "web_search", "api_call"])

        # With content filtering
        check = govern(
            allow=["read_file", "web_search"],
            blocked_content=[r'\\b\\d{3}-\\d{2}-\\d{4}\\b'],  # SSN
        )
    """
    return LiteGovernor(
        allow=allow,
        deny=deny,
        deny_patterns=deny_patterns,
        blocked_content=blocked_content,
        escalate=escalate,
        max_calls=max_calls,
        log=log,
    )
