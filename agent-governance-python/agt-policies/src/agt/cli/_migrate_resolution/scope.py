# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Scope filtering, per AGT-RESOLUTION §2.3.

A governance document MAY declare a ``scope`` glob. Filtering drops
documents whose scope does not match the action path. Documents with
no scope always apply.

The action path is normalised to forward slashes for cross-platform
consistency before matching.
"""

from __future__ import annotations

from fnmatch import fnmatchcase
from pathlib import Path
from typing import Optional

from .errors import ResolutionError


def filter_by_scope(
    policy_path: Path,
    scope_pattern: Optional[str],
    action_path: Path,
    root: Path,
) -> bool:
    """Return True if the policy at ``policy_path`` applies to the action.

    Args:
        policy_path: Path to the governance file (unused today, accepted
            for future per-policy diagnostics).
        scope_pattern: Glob from the document's ``scope`` field, or
            ``None`` (the document always applies).
        action_path: Resolved action path.
        root: Workspace root.

    Returns:
        True when the document applies.

    Raises:
        ResolutionError: ``INVALID_GOVERNANCE`` when ``scope`` is present
            but is not a non-empty string. An empty or blank scope would
            match nothing and silently drop the document (and its deny
            rules); a non-string scope has no defined matching semantics.
            ``PATH_TRAVERSAL`` when ``action_path`` is not under ``root``.
    """
    del policy_path  # reserved for diagnostics

    if scope_pattern is None:
        return True
    if not isinstance(scope_pattern, str) or not scope_pattern.strip():
        raise ResolutionError.invalid_governance(
            "scope must be a non-empty glob string or omitted"
        )

    root = root.resolve()
    action_path = action_path.resolve()
    try:
        action_rel = str(action_path.relative_to(root)).replace("\\", "/")
    except ValueError:
        raise ResolutionError.path_traversal(
            f"action_path {action_path} is not under workspace root {root}"
        ) from None
    normalized_scope = scope_pattern.replace("\\", "/")

    if normalized_scope.endswith("/"):
        scope_dir = normalized_scope.rstrip("/")
        return action_rel == scope_dir or action_rel.startswith(f"{scope_dir}/")

    return fnmatchcase(action_rel, normalized_scope)
