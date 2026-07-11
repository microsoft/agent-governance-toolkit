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
PRIVATE_RESOLVER = "agt.cli._migrate_resolution"


@pytest.mark.parametrize(
    "module",
    [
        "agt.policies",
        "agt.policies.runtime",
        "agt.policies.session",
        "agt._harness.snapshot",
    ],
)
def test_runtime_imports_do_not_load_private_migrator(module: str) -> None:
    sys.modules.pop(PRIVATE_MIGRATOR, None)
    sys.modules.pop(PRIVATE_RESOLVER, None)

    importlib.import_module(module)

    assert PRIVATE_MIGRATOR not in sys.modules
    assert PRIVATE_RESOLVER not in sys.modules


def test_legacy_resolver_is_not_publicly_importable() -> None:
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("agt." + "manifest_" + "resolution")


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
            if any(
                private in name
                for name in names
                for private in (PRIVATE_MIGRATOR, PRIVATE_RESOLVER)
            ):
                offenders.append(str(path.relative_to(src_root)))

    assert offenders == []
