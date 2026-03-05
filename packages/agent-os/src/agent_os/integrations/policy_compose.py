# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Policy Inheritance and Composition

Utilities for merging, inheriting, and overriding GovernancePolicy instances.
"""

from __future__ import annotations

from dataclasses import asdict, fields
from typing import Any

from .base import GovernancePolicy

# Fields that use "most restrictive" (min) merging
_MIN_FIELDS = {"max_tokens", "max_tool_calls", "max_concurrent", "timeout_seconds"}

# Fields that use "most restrictive" (truthy wins) merging
_BOOL_RESTRICTIVE = {"require_human_approval", "log_all_calls"}

# List fields with special merge semantics
_UNION_LIST_FIELDS = {"blocked_patterns"}
_INTERSECT_LIST_FIELDS = {"allowed_tools"}


def override_policy(base: GovernancePolicy, **kwargs: Any) -> GovernancePolicy:
    """Create a copy of *base* with the given field overrides applied."""
    data = asdict(base)
    data.update(kwargs)
    return GovernancePolicy(**data)


def compose_policies(*policies: GovernancePolicy) -> GovernancePolicy:
    """Merge multiple policies using most-restrictive-wins semantics.

    - ``max_tokens``, ``max_tool_calls``, ``max_concurrent``, ``timeout_seconds``:
      smallest value wins.
    - ``blocked_patterns``: union of all lists.
    - ``allowed_tools``: intersection when both specify; single list kept as-is.
    - ``version``: highest version string (lexicographic).
    - ``name``: names joined with " + ".
    - ``require_human_approval``, ``log_all_calls``: ``True`` if *any* policy
      sets them.
    """
    if not policies:
        raise ValueError("compose_policies requires at least one policy")
    if len(policies) == 1:
        return override_policy(policies[0])

    result = asdict(policies[0])

    for policy in policies[1:]:
        other = asdict(policy)

        # Name
        result["name"] = result["name"] + " + " + other["name"]

        # Most-restrictive numeric fields
        for f in _MIN_FIELDS:
            result[f] = min(result[f], other[f])

        # Boolean restrictive fields
        for f in _BOOL_RESTRICTIVE:
            result[f] = result[f] or other[f]

        # Union list fields
        for f in _UNION_LIST_FIELDS:
            combined = list(result[f])
            for item in other[f]:
                if item not in combined:
                    combined.append(item)
            result[f] = combined

        # Intersect list fields (allowed_tools)
        for f in _INTERSECT_LIST_FIELDS:
            left = result[f]
            right = other[f]
            if left and right:
                result[f] = [t for t in left if t in right]
            elif right:
                result[f] = list(right)
            # if only left has values, keep them as-is

        # Highest version
        if other["version"] > result["version"]:
            result["version"] = other["version"]

        # Safety thresholds – most restrictive
        result["confidence_threshold"] = max(
            result["confidence_threshold"], other["confidence_threshold"]
        )
        result["drift_threshold"] = min(
            result["drift_threshold"], other["drift_threshold"]
        )

        # Checkpoint frequency – more frequent wins
        result["checkpoint_frequency"] = min(
            result["checkpoint_frequency"], other["checkpoint_frequency"]
        )

        # Backpressure threshold – lower is more restrictive
        result["backpressure_threshold"] = min(
            result["backpressure_threshold"], other["backpressure_threshold"]
        )

    return GovernancePolicy(**result)


class PolicyHierarchy:
    """Tree-structured policy inheritance.

    A hierarchy node wraps a *base* (parent) policy and can produce child
    policies that inherit from it, with optional overrides.
    """

    def __init__(self, base: GovernancePolicy) -> None:
        self._base = base

    @property
    def policy(self) -> GovernancePolicy:
        """The base policy of this hierarchy node."""
        return self._base

    def extend(self, **overrides: Any) -> GovernancePolicy:
        """Return a new policy that inherits from the base with *overrides*."""
        return override_policy(self._base, **overrides)

    def child(self, name: str, **overrides: Any) -> PolicyHierarchy:
        """Create a child hierarchy node inheriting from this one."""
        child_policy = self.extend(name=name, **overrides)
        return PolicyHierarchy(child_policy)

    def chain(self, *policies: GovernancePolicy) -> GovernancePolicy:
        """Apply policies in priority order on top of the base.

        Later policies win for simple scalar fields; list fields are unioned.
        """
        if not policies:
            return override_policy(self._base)

        result = asdict(self._base)

        for policy in policies:
            other = asdict(policy)
            for f in fields(GovernancePolicy):
                key = f.name
                val = other[key]
                if key == "name":
                    continue  # handled separately
                if key in _UNION_LIST_FIELDS:
                    combined = list(result[key])
                    for item in val:
                        if item not in combined:
                            combined.append(item)
                    result[key] = combined
                elif key in _INTERSECT_LIST_FIELDS:
                    left = result[key]
                    right = val
                    if left and right:
                        result[key] = [t for t in left if t in right]
                    elif right:
                        result[key] = list(right)
                else:
                    result[key] = val

        # Build composite name
        names = [self._base.name] + [p.name for p in policies]
        result["name"] = " + ".join(names)

        return GovernancePolicy(**result)
