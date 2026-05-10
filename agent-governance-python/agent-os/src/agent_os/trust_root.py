# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Deterministic Trust Root — Final authority for the supervisor hierarchy.

The trust root is a pure-code (non-LLM) policy checkpoint that sits at
the top of the supervisor chain.  It evaluates actions using
GovernancePolicy rules and cannot be overridden by any agent.

Example:
    >>> from agent_os.trust_root import TrustRoot, TrustDecision
    >>> from agent_os.integrations.base import GovernancePolicy
    >>>
    >>> policy = GovernancePolicy(allowed_tools=["read_file"])
    >>> root = TrustRoot(policies=[policy])
    >>> decision = root.validate_action({"tool": "delete_file", "arguments": {}})
    >>> decision.allowed  # False
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from agent_os.integrations.base import GovernancePolicy


def _iter_string_leaves(value: Any) -> Iterable[str]:
    """Yield every string-like leaf reachable from *value*.

    Walks dicts (keys and values), lists/tuples/sets, and decodes ``bytes``
    via UTF-8 with ``backslashreplace`` so that non-ASCII payloads still
    surface as inspectable text. Primitives (int/float/bool/None) are
    coerced to their ``str()`` form because callers sometimes interpolate
    them into shell or SQL strings downstream.

    The intent is that every byte the receiver of an action might
    eventually interpret should pass through the blocklist.
    """
    if value is None:
        return
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, (bytes, bytearray)):
        yield bytes(value).decode("utf-8", errors="backslashreplace")
        return
    if isinstance(value, Mapping):
        for k, v in value.items():
            yield from _iter_string_leaves(k)
            yield from _iter_string_leaves(v)
        return
    if isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _iter_string_leaves(item)
        return
    # Fallback for primitives and unknown objects — repr() is the same
    # surface ``str(arguments)`` previously exposed, so we never regress
    # detection coverage relative to the pre-fix behavior.
    yield str(value)


@dataclass
class TrustDecision:
    """Result of a deterministic trust-root evaluation."""

    allowed: bool
    reason: str
    policy_name: str
    deterministic: bool = True


class TrustRoot:
    """Deterministic (non-LLM) policy authority at the top of the supervisor hierarchy.

    The trust root is the FINAL authority — it cannot be overridden by any agent.
    All evaluations use pure code logic; no model inference is involved.

    Args:
        policies: List of GovernancePolicy instances to enforce.
        max_escalation_depth: Maximum supervisor levels before forced rejection.
    """

    def __init__(
        self,
        policies: list[GovernancePolicy],
        max_escalation_depth: int = 3,
    ) -> None:
        if not policies:
            raise ValueError("TrustRoot requires at least one policy")
        self.policies = policies
        self.max_escalation_depth = max_escalation_depth

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def validate_action(self, action: dict[str, Any]) -> TrustDecision:
        """Deterministic policy check against all registered policies.

        Args:
            action: Dict with at least ``tool`` (str) and ``arguments`` (dict).

        Returns:
            TrustDecision indicating whether the action is allowed.
        """
        tool = action.get("tool", "")
        arguments = action.get("arguments", {})
        leaves = list(_iter_string_leaves(arguments))

        for policy in self.policies:
            # Check allowed tools
            if policy.allowed_tools and tool not in policy.allowed_tools:
                return TrustDecision(
                    allowed=False,
                    reason=(
                        f"Tool '{tool}' not in allowed list: {policy.allowed_tools}"
                    ),
                    policy_name=policy.name,
                )

            # Check blocked patterns against every string leaf and key — the
            # previous str(arguments) approach silently re-encoded bytes
            # values (`b'\x..'`) and produced a single repr blob whose
            # delimiters could disrupt regex anchors.
            for leaf in leaves:
                matched = policy.matches_pattern(leaf)
                if matched:
                    return TrustDecision(
                        allowed=False,
                        reason=f"Blocked pattern '{matched[0]}' detected in arguments",
                        policy_name=policy.name,
                    )

        return TrustDecision(
            allowed=True,
            reason="All policies passed",
            policy_name="aggregate",
        )

    def validate_supervisor(self, supervisor_config: dict[str, Any]) -> bool:
        """Verify a supervisor agent meets trust requirements.

        A supervisor at any level must declare a ``name`` and ``level``.
        Level-0 supervisors **must not** be agent-based (``is_agent`` must be False).

        Args:
            supervisor_config: Dict with ``name``, ``level``, and optionally ``is_agent``.

        Returns:
            True if the supervisor configuration is acceptable.
        """
        level = supervisor_config.get("level")
        is_agent = supervisor_config.get("is_agent", True)

        if level is None or not supervisor_config.get("name"):
            return False

        # Root level must be deterministic — not an LLM agent
        if level == 0 and is_agent:
            return False

        return True

    def is_deterministic(self) -> bool:
        """Guarantee that this trust root uses only deterministic logic."""
        return True
