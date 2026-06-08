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

from fnmatch import fnmatch
from pathlib import Path
from typing import Optional


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
    """
    del policy_path  # reserved for diagnostics

    if scope_pattern is None:
        return True

    root = root.resolve()
    action_path = action_path.resolve()
    action_rel = str(action_path.relative_to(root)).replace("\\", "/")
    normalized_scope = scope_pattern.replace("\\", "/")

    if normalized_scope.endswith("/"):
        scope_dir = normalized_scope.rstrip("/")
        return action_rel == scope_dir or action_rel.startswith(f"{scope_dir}/")

    return fnmatch(action_rel, normalized_scope)
