# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""DiffPolicy rule type for git change scope enforcement.

Enforces constraints on agent-authored code changes:
file count limits, line count limits, and path restrictions.

Example::

    policy = DiffPolicy(max_files=20, max_lines=400, blocked_paths=["*.env", "secrets/**"])
    result = policy.evaluate(changed_files)
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field


@dataclass
class DiffFile:
    """A file in a diff."""

    path: str
    additions: int = 0
    deletions: int = 0


@dataclass
class DiffPolicyResult:
    """Result of evaluating a diff against policy."""

    allowed: bool
    violations: list[str] = field(default_factory=list)


@dataclass
class DiffPolicy:
    """Policy rules for git change scope enforcement.

    Attributes:
        max_files: Maximum number of files changed.
        max_lines: Maximum total lines changed (additions + deletions).
        allowed_paths: Glob patterns for allowed file paths. Empty = all allowed.
        blocked_paths: Glob patterns for blocked file paths.
    """

    max_files: int | None = None
    max_lines: int | None = None
    allowed_paths: list[str] = field(default_factory=list)
    blocked_paths: list[str] = field(default_factory=list)

    def evaluate(self, files: list[DiffFile]) -> DiffPolicyResult:
        """Evaluate a set of changed files against this policy.

        Args:
            files: List of DiffFile objects representing the changes.

        Returns:
            DiffPolicyResult with allowed status and any violations.
        """
        violations = []

        # Check file count
        if self.max_files is not None and len(files) > self.max_files:
            violations.append(f"files: {len(files)}/{self.max_files}")

        # Check total lines
        if self.max_lines is not None:
            total_lines = sum(f.additions + f.deletions for f in files)
            if total_lines > self.max_lines:
                violations.append(f"lines: {total_lines}/{self.max_lines}")

        # Check path restrictions
        for f in files:
            # Blocked paths
            for pattern in self.blocked_paths:
                if fnmatch.fnmatch(f.path, pattern):
                    violations.append(f"blocked: {f.path} matches {pattern}")

            # Allowed paths (if set, file must match at least one)
            if self.allowed_paths:
                if not any(fnmatch.fnmatch(f.path, p) for p in self.allowed_paths):
                    violations.append(f"not_allowed: {f.path}")

        return DiffPolicyResult(
            allowed=len(violations) == 0,
            violations=violations,
        )
