# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Shared publication scope for documentation quality checks."""

from __future__ import annotations

import fnmatch
from pathlib import Path


# These files live under docs/ for repository workflows, source history, or
# contributor scaffolding. They are not user-facing MkDocs pages.
DOCS_EXCLUDE_PATTERNS = (
    "AGENTS.md",
    "adr/0000-template.md",
    "adr/README.md",
    "assets/partners/README.md",
    "benchmarks/governance-overhead.md",
    "case-studies/TEMPLATE.md",
    "dependency-audits/**",
    "deployment/README.md",
    "security/tenant-isolation-checklist.md",
    "slo/**",
    "tutorials/README.md",
)


def is_excluded_doc(path: Path, docs_dir: Path) -> bool:
    """Return whether ``path`` is intentionally outside the published site."""
    try:
        relative = path.resolve().relative_to(docs_dir.resolve()).as_posix()
    except ValueError:
        return False
    return any(fnmatch.fnmatchcase(relative, pattern) for pattern in DOCS_EXCLUDE_PATTERNS)
