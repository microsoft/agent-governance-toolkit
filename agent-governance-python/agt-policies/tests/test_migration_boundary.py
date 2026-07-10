# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Import-boundary tests for the private one-way migration translator."""

from __future__ import annotations

import ast
import importlib
import sys
from pathlib import Path

import pytest

PRIVATE_MIGRATOR = "agt.cli._migrate_bridge"


@pytest.mark.parametrize(
    "module",
    [
        "agt.policies",
        "agt.policies.runtime",
        "agt.policies.session",
        "agt.manifest_resolution",
        "agt._harness.opa_runner",
    ],
)
def test_runtime_imports_do_not_load_private_migrator(module: str) -> None:
    sys.modules.pop(PRIVATE_MIGRATOR, None)

    importlib.import_module(module)

    assert PRIVATE_MIGRATOR not in sys.modules


def test_no_non_cli_source_imports_private_migrator() -> None:
    src_root = Path(__file__).resolve().parents[1] / "src" / "agt"
    offenders: list[str] = []
    for path in src_root.rglob("*.py"):
        if path in {
            src_root / "cli" / "migrate.py",
            src_root / "cli" / "_migrate_bridge.py",
        }:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            if any(PRIVATE_MIGRATOR in name for name in names):
                offenders.append(str(path.relative_to(src_root)))

    assert offenders == []
