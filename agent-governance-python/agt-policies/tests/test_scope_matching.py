# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for migration scope matching."""

from __future__ import annotations

import os
from pathlib import Path

from agt.cli._migrate_resolution import filter_by_scope


def test_scope_glob_does_not_inherit_host_normcase(
    tmp_path: Path, monkeypatch
) -> None:
    """Scope matching stays case-sensitive even on Windows-style normcase."""
    root = tmp_path
    action = root / "Src" / "payments" / "wire.py"
    action.parent.mkdir(parents=True)
    action.touch()

    # fnmatch() applies os.path.normcase() before matching. Simulate Windows
    # semantics so this regression is load-bearing on Linux CI as well.
    monkeypatch.setattr(
        os.path,
        "normcase",
        lambda value: value.lower().replace("/", "\\"),
    )

    assert filter_by_scope(root / "p", "src/payments/*", action, root) is False
    assert filter_by_scope(root / "p", "Src/payments/*", action, root) is True
