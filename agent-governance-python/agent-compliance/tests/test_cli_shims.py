# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Regression tests for the repository CLI compatibility shims."""

# cspell:ignore syspath

from __future__ import annotations

import importlib
import os
import subprocess
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize(
    ("script_name", "package_module"),
    [
        ("contributor_check", "agent_compliance.cli.contributor_check"),
        ("credential_audit", "agent_compliance.cli.credential_audit"),
    ],
)
def test_repository_shim_is_packaged_module(
    monkeypatch: pytest.MonkeyPatch,
    script_name: str,
    package_module: str,
) -> None:
    """Importing a repository script must resolve to the packaged implementation."""
    monkeypatch.syspath_prepend(str(_REPO_ROOT / "scripts"))
    sys.modules.pop(script_name, None)

    shim = importlib.import_module(script_name)
    packaged = importlib.import_module(package_module)

    assert shim is packaged
    sys.modules.pop(script_name, None)


@pytest.mark.parametrize(
    ("script_name", "package_module"),
    [
        ("contributor_check", "agent_compliance.cli.contributor_check"),
        ("credential_audit", "agent_compliance.cli.credential_audit"),
    ],
)
def test_repository_shim_cli_matches_packaged_module(
    script_name: str,
    package_module: str,
) -> None:
    """The repository and package entry points must expose the same CLI."""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(
        _REPO_ROOT / "agent-governance-python" / "agent-compliance" / "src"
    )

    shim = subprocess.run(
        [sys.executable, str(_REPO_ROOT / "scripts" / f"{script_name}.py"), "--help"],
        capture_output=True,
        check=False,
        env=env,
        text=True,
    )
    packaged = subprocess.run(
        [sys.executable, "-m", package_module, "--help"],
        capture_output=True,
        check=False,
        env=env,
        text=True,
    )

    assert (shim.returncode, shim.stdout, shim.stderr) == (
        packaged.returncode,
        packaged.stdout,
        packaged.stderr,
    )
