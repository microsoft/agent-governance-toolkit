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
            file, or a to-be-created file with an existing parent,
            walking starts from its parent directory.
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
    original_action_path = action_path
    try:
        root = root.resolve()
        action_path = action_path.resolve()
    except (OSError, RuntimeError) as exc:
        raise ResolutionError.path_traversal(
            f"failed to resolve action_path under {root}: {exc}"
        ) from exc

    try:
        if action_path.is_file():
            action_path = action_path.parent
        elif action_path.is_dir():
            pass
        elif not action_path.exists():
            if original_action_path.is_symlink():
                raise ResolutionError.path_traversal(
                    f"action_path {action_path} is not a file or directory"
                )
            action_path = action_path.parent
            if not action_path.is_dir():
                raise ResolutionError.path_traversal(
                    f"action_path parent {action_path} is not a directory"
                )
        else:
            raise ResolutionError.path_traversal(
                f"action_path {action_path} is not a file or directory"
            )
    except ResolutionError:
        raise
    except (OSError, RuntimeError) as exc:
        raise ResolutionError.path_traversal(
            f"failed to inspect action_path under {root}: {exc}"
        ) from exc

    if not _is_relative_to(action_path, root):
        raise ResolutionError.path_traversal(
            f"action_path {action_path} is not under workspace root {root}"
        )

    candidates: list[Path] = []
    current = action_path

    while True:
        for name in GOVERNANCE_FILENAMES:
            candidate = current / name
            try:
                if candidate.is_file():
                    resolved_candidate = candidate.resolve()
                    if not _is_relative_to(resolved_candidate, root):
                        raise ResolutionError.path_traversal(
                            f"governance file {candidate} resolves outside workspace root {root}"
                        )
                    candidates.append(resolved_candidate)
                    break
            except ResolutionError:
                raise
            except (OSError, RuntimeError) as exc:
                raise ResolutionError.path_traversal(
                    f"failed to walk governance chain under {root}: {exc}"
                ) from exc

        if current == root or current.parent == current:
            break
        current = current.parent

    candidates.reverse()
    return candidates
