# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""
Folder-level governance policy discovery.

Walks up from an action's path to the repository root, collecting
governance.yaml files for hierarchical policy evaluation.
"""

from __future__ import annotations

import logging
from fnmatch import fnmatch
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

GOVERNANCE_FILENAMES = ("governance.yaml", "governance.yml")


def discover_policies(
    action_path: Path,
    root: Path,
) -> list[Path]:
    """Discover governance policy files from action path up to root.

    Walks the directory tree from ``action_path`` upward to ``root``,
    collecting ``governance.yaml`` (or ``.yml``) files. Returns them
    in **root-first** order (root at index 0, most specific last).

    If a policy declares ``inherit: false``, parent policies above
    that level are excluded.

    Args:
        action_path: Path where the agent action originates.
        root: Repository or workspace root directory.

    Returns:
        List of governance policy file paths, root-first order.
    """
    root = root.resolve()
    action_path = action_path.resolve()

    if action_path.is_file():
        action_path = action_path.parent

    # Collect candidates walking up
    candidates: list[Path] = []
    current = action_path

    while True:
        for name in GOVERNANCE_FILENAMES:
            candidate = current / name
            if candidate.is_file():
                candidates.append(candidate)
                break

        if current == root or current.parent == current:
            break
        current = current.parent

    # Reverse to root-first order
    candidates.reverse()

    if not candidates:
        return []

    # Check for inherit: false — trim the chain
    final = _apply_inheritance(candidates)

    logger.debug(
        "Discovered %d governance policies for %s: %s",
        len(final),
        action_path,
        [str(p) for p in final],
    )
    return final


def _apply_inheritance(candidates: list[Path]) -> list[Path]:
    """Trim the policy chain at the first inherit: false boundary.

    Walks from most specific (last) toward root. The first policy
    with ``inherit: false`` becomes the new root — nothing above
    it is included.
    """
    try:
        import yaml
    except ImportError:
        return candidates

    for i in range(len(candidates) - 1, -1, -1):
        with open(candidates[i], encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        if data.get("inherit") is False:
            return candidates[i:]

    return candidates


def filter_by_scope(
    policy_path: Path,
    scope_pattern: Optional[str],
    action_path: Path,
    root: Path,
) -> bool:
    """Check if an action path matches a policy's scope glob.

    Args:
        policy_path: Path to the governance.yaml file.
        scope_pattern: Glob pattern from the policy's ``scope`` field.
            If None, the policy applies to everything under its directory.
        action_path: Path where the agent action originates.
        root: Repository root.

    Returns:
        True if the action path is within scope.
    """
    if scope_pattern is None:
        return True

    action_rel = str(action_path.resolve().relative_to(root.resolve()))
    # Normalize to forward slashes for consistent matching
    action_rel = action_rel.replace("\\", "/")
    return fnmatch(action_rel, scope_pattern)
