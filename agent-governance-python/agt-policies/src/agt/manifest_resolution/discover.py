# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Folder-level governance discovery, per AGT-RESOLUTION §2.1.

Walks the directory tree from an action path up to a workspace root,
collecting ``governance.yaml`` (preferred) or ``governance.yml`` files.
Returns the candidate list in **root-first** order. A path that
resolves outside the workspace root raises
:class:`ResolutionError(PATH_TRAVERSAL)`.
"""

from __future__ import annotations

from pathlib import Path

from .errors import ResolutionError

GOVERNANCE_FILENAMES: tuple[str, ...] = ("governance.yaml", "governance.yml")


def _is_relative_to(child: Path, root: Path) -> bool:
    """Polyfill of Path.is_relative_to (added in 3.9). Both inputs must
    already be resolved to absolute paths.
    """
    try:
        child.relative_to(root)
        return True
    except ValueError:
        return False


def discover_policies(action_path: Path, root: Path) -> list[Path]:
    """Discover governance.yaml files from ``action_path`` up to ``root``.

    Args:
        action_path: Path where the agent action originates. If it is a
            file, walking starts from its parent directory.
        root: Workspace root that bounds the walk.

    Returns:
        List of discovered governance file paths in root-first order
        (root at index 0, most-specific directory last).

    Raises:
        ResolutionError: ``PATH_TRAVERSAL`` if ``action_path`` resolves
            outside ``root`` (symlinks, ``..`` segments, attacker-supplied
            path fields). The previous v4 behaviour of returning an empty
            list defaulted to allow; v5 fails closed.
    """
    root = root.resolve()
    action_path = action_path.resolve()

    if action_path.is_file():
        action_path = action_path.parent

    if not _is_relative_to(action_path, root):
        raise ResolutionError.path_traversal(
            f"action_path {action_path} is not under workspace root {root}"
        )

    candidates: list[Path] = []
    current = action_path

    while True:
        for name in GOVERNANCE_FILENAMES:
            candidate = current / name
            if candidate.is_file():
                resolved_candidate = candidate.resolve()
                if not _is_relative_to(resolved_candidate, root):
                    raise ResolutionError.path_traversal(
                        f"governance file {candidate} resolves outside workspace root {root}"
                    )
                candidates.append(resolved_candidate)
                break

        if current == root or current.parent == current:
            break
        current = current.parent

    candidates.reverse()
    return candidates
