# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

"""Regression tests for repository version synchronization."""

from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[2] / "scripts" / "sync-version.py"
SPEC = importlib.util.spec_from_file_location("sync_version", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
sync_version = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sync_version)


def test_sync_python_runtime_version_checks_and_updates(
    tmp_path: Path, monkeypatch, capsys
) -> None:
    runtime_init = tmp_path / "runtime" / "__init__.py"
    runtime_init.parent.mkdir()
    runtime_init.write_text('__version__ = "5.0.0"\n', encoding="utf-8")
    monkeypatch.setattr(sync_version, "REPO_ROOT", tmp_path)

    assert not sync_version.sync_python_runtime_version(runtime_init, "5.0.1", check=True)
    assert "DRIFT runtime/__init__.py" in capsys.readouterr().out
    assert runtime_init.read_text(encoding="utf-8") == '__version__ = "5.0.0"\n'

    assert sync_version.sync_python_runtime_version(runtime_init, "5.0.1", check=False)
    assert runtime_init.read_text(encoding="utf-8") == '__version__ = "5.0.1"\n'